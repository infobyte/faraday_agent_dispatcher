#!/usr/bin/env python
"""Trend Micro Deep Security REST importer.

Pulls managed computers, anti-malware events and the IPS rule catalogue
from a Trend Micro Deep Security Manager (DSM) instance.  Emits Faraday
bulk-create JSON to stdout.  Each Deep Security computer becomes one
Faraday host (``ip`` = the first non-loopback ``displayName`` /
``hostName`` / ``ip`` address on the computer record, falling back to
synthetic ``0.0.0.0``); per-computer anti-malware events attach as
Faraday vulnerabilities — one per Deep Security AM event id with engine
prefix ``[EDR]``.  Each assigned IPS rule that maps onto a CVE list (the
Deep Security IPS catalogue stamps CVE-* on virtual-patching rules) is
also surfaced as a vulnerability under the matching computer so the
Faraday workspace mirrors the virtual-patch posture the manager
reports.

Endpoints used:
  GET {DSM_HOST}/api/computers?expand=all&overrides=true
      -> paginated managed-computer inventory.  Each entry carries
      ID / hostName / displayName / agentVersion / platform / agentStatus /
      lastAgentCommunication / lastIPUsed / policyID / groupID /
      intrusionPrevention.ruleIDs / antiMalware / firewall / integrity /
      logInspection / applicationControl blocks.  Pagination is the
      id-cursor pattern Deep Security uses: ``searchCriteria.idValue``
      is set to the last item's ID + ``idTest=greater-than`` to walk
      forward through the catalogue (Deep Security caps a single
      response at 5 000 items).
  POST {DSM_HOST}/api/searches/eventsantimalware
      -> paginated anti-malware events.  POST body carries the
      ``searchCriteria`` (id-cursor + optional hostID filter), ``maxItems``
      and ``sortByObjectID=true``.  Response envelope is
      ``{"events": [...]}``; each entry carries
      eventID / hostID / logDate / logTime / detectionTime / malwareName /
      malwareType / scanAction1 / scanAction2 / scanType /
      reason / errorCode / quarantineRecordID / filePath / fileSHA1 /
      fileSHA256 / sourceUser / sourceProcessName / sourceProcessSHA1.
  GET {DSM_HOST}/api/ipsrules
      -> paginated IPS rule catalogue.  Same id-cursor pagination as
      ``/api/computers``.  Each entry carries
      ID / name / description / severity / type / cvssScore / cvssVector /
      CVE / CVSSScore / cveDescription / patternIfStaticType /
      detectOnly / alertEnabled / templateType plus a numeric ``severity``
      enum (1=Low, 2=Medium, 3=High, 4=Critical).  The catalogue is
      fetched up-front so each computer's ``intrusionPrevention.ruleIDs``
      array can be expanded into virtual-patching findings without
      re-walking the catalogue per host.

Auth: Deep Security uses an ``API Key`` header auth flow rooted at
``api-secret-key: <key>``.  The operator creates an API Key in the DSM
console (Administration -> User Management -> API Keys -> New) with a
``Full Access`` role and pastes the returned secret into ``DSM_API_KEY``.
The dispatcher carries that key on every request as
``api-secret-key: <DSM_API_KEY>`` plus ``api-version: v1``.  ``DSM_HOST``
is the manager URL (e.g. ``https://dsm.example.com:4119`` for the
default on-prem port or ``https://workload.deepsecurity.trendmicro.com``
for the Trend Micro Cloud One Workload Security SaaS endpoint).
``DSM_POLICY_ID`` is an optional computer-side filter that narrows the
computer inventory walk to a single policy id (per-policy
``virtualization-policy`` posture).  ``DSM_HOSTNAME_FILTER`` is an
optional client-side substring filter applied to ``hostName`` /
``displayName`` so operators can scope a run to a single business unit
without changing the API key's role.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 5000  # Deep Security caps a single search at 5000 items.

# Deep Security severity numeric enum -> Faraday bucket.  The DSM REST
# surface stamps ipsrule.severity as an integer 1..4 (1=Low ... 4=Critical)
# alongside the string severity label.
DEEP_SECURITY_SEVERITY_NUM = {
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

DEEP_SECURITY_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
}

# Anti-malware ``malwareType`` enum -> Faraday bucket.  Deep Security
# stamps a coarse malware classification on every AM event; we map the
# canonical labels onto Faraday's 5-bucket scale so the dispatcher emits
# a sensible severity even when the manager does not stamp a numeric
# score on the event.
DEEP_SECURITY_MALWARE_SEVERITY = {
    "ransomware": "critical",
    "rootkit": "critical",
    "backdoor": "critical",
    "trojan": "high",
    "worm": "high",
    "virus": "high",
    "exploit": "high",
    "spyware": "high",
    "keylogger": "high",
    "infostealer": "high",
    "downloader": "high",
    "dropper": "high",
    "generic": "high",
    "malware": "high",
    "malicious": "high",
    "pup": "low",
    "potentiallyunwanted": "low",
    "potentially_unwanted": "low",
    "adware": "low",
    "joke": "low",
    "test": "info",
    "eicar": "info",
    "cookie": "info",
    "trackingcookie": "info",
    "unknown": "info",
}

# Anti-malware ``scanAction`` codes that translate onto Faraday status.
# Deep Security uses two scan actions (scanAction1 / scanAction2 — the
# primary and fallback action it tried).  ``Cleaned`` / ``Quarantined``
# / ``Deleted`` / ``Terminated`` mean the manager neutralised the threat
# (Faraday ``closed``).  ``Untouched`` / ``DenyAccess`` mean the manager
# saw it but did not remediate (Faraday ``open``).  ``Allowed`` /
# ``Exception`` mean the operator allow-listed the file (Faraday
# ``risk-accepted``).
DEEP_SECURITY_AM_STATUS = {
    "cleaned": "closed",
    "quarantined": "closed",
    "deleted": "closed",
    "terminated": "closed",
    "passed": "closed",
    "remediated": "closed",
    "untouched": "open",
    "failed": "open",
    "denyaccess": "open",
    "denied": "open",
    "blocked": "closed",
    "active": "open",
    "open": "open",
    "default": "open",
    "allowed": "risk-accepted",
    "exception": "risk-accepted",
    "whitelisted": "risk-accepted",
    "approved": "risk-accepted",
    "excluded": "risk-accepted",
    "ignored": "risk-accepted",
    "muted": "risk-accepted",
    "suppressed": "risk-accepted",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(f"{datetime.utcnow()} - TrendMicro Deep Security: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "info"
    if score <= 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    if score > 10:
        return "info"
    return "critical"


def severity_from_numeric(value):
    """Map a Deep Security 1..4 severity enum to a Faraday bucket."""
    if isinstance(value, bool):
        return None
    try:
        as_int = int(value)
    except (TypeError, ValueError):
        return None
    return DEEP_SECURITY_SEVERITY_NUM.get(as_int)


def severity_from_string(value):
    """Map a Deep Security string severity label to a Faraday bucket."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().lower()
    if text in DEEP_SECURITY_STRING_SEVERITY:
        return DEEP_SECURITY_STRING_SEVERITY[text]
    return None


def severity_from_malware_type(value):
    """Map a Deep Security malware type label onto a Faraday bucket."""
    if not isinstance(value, str) or not value.strip():
        return None
    key = re.sub(r"[^a-z0-9_]", "", value.strip().lower())
    if key in DEEP_SECURITY_MALWARE_SEVERITY:
        return DEEP_SECURITY_MALWARE_SEVERITY[key]
    squashed = key.replace("_", "")
    if squashed in DEEP_SECURITY_MALWARE_SEVERITY:
        return DEEP_SECURITY_MALWARE_SEVERITY[squashed]
    return None


def severity_from_event(item, cvss=None):
    """Map a Deep Security AM event / IPS rule payload to a severity bucket.

    Walks the numeric ``severity`` enum first (the canonical IPS rule
    signal), then the string ``severity`` label, then the AM event's
    ``malwareType`` enum, then a CVSS fallback when nothing else lands.
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            text = item.strip().lower()
            if text in DEEP_SECURITY_STRING_SEVERITY:
                return DEEP_SECURITY_STRING_SEVERITY[text]
            bucket = severity_from_malware_type(item)
            if bucket is not None:
                return bucket
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    for key in ("severity", "Severity", "severityLevel"):
        raw = item.get(key)
        # Numeric path first — Deep Security IPS rules carry severity as int.
        if raw is not None and not isinstance(raw, bool):
            bucket = severity_from_numeric(raw)
            if bucket is not None:
                return bucket
        if isinstance(raw, str):
            bucket = severity_from_string(raw)
            if bucket is not None:
                return bucket

    malware_type = item.get("malwareType") or item.get("malware_type")
    bucket = severity_from_malware_type(malware_type)
    if bucket is not None:
        return bucket

    # Anti-malware events sometimes carry a ``riskLevel`` label.
    risk_level = item.get("riskLevel") or item.get("risk_level")
    bucket = severity_from_string(risk_level)
    if bucket is not None:
        return bucket

    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_event(item):
    """Map a Deep Security AM event payload to a Faraday status.

    Walks ``scanAction1`` first (the canonical primary action), then
    ``scanAction2``, then ``action`` / ``status`` / ``state`` alt-keys.
    Defaults to ``open`` so the dispatcher does not silently drop an
    AM event when the manager reports an unmapped action.
    """
    if not isinstance(item, dict):
        return "open"
    for key in (
        "scanAction1",
        "scan_action_1",
        "scanAction2",
        "scan_action_2",
        "action",
        "Action",
        "status",
        "Status",
        "state",
        "State",
        "result",
        "Result",
        "scanResult",
        "scan_result",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in DEEP_SECURITY_AM_STATUS:
                return DEEP_SECURITY_AM_STATUS[compact]
            if squashed in DEEP_SECURITY_AM_STATUS:
                return DEEP_SECURITY_AM_STATUS[squashed]
    if item.get("quarantined") is True or item.get("isQuarantined") is True:
        return "closed"
    if item.get("cleaned") is True:
        return "closed"
    if item.get("allowed") is True or item.get("isAllowed") is True:
        return "risk-accepted"
    return "open"


def validate_min_severity(value):
    """Validate DSM_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus Deep Security synonyms.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = DEEP_SECURITY_STRING_SEVERITY.get(text)
    if bucket is None:
        # Numeric severity floor (1..4)?
        try:
            bucket = severity_from_numeric(int(float(text)))
        except (TypeError, ValueError):
            bucket = None
    if bucket is None:
        log(f"DSM_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_policy_id(value):
    """Validate DSM_POLICY_ID (computer policy filter).

    None / blank -> None (no filter applied; the executor walks every
    computer).  Numeric / numeric-string is coerced to int because the
    Deep Security ``searchCriteria.policyID`` API expects an integer.
    Non-numeric input is logged and dropped so the executor still runs
    against the unfiltered catalogue.
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        log(f"DSM_POLICY_ID '{value}' is not numeric; ignoring filter")
        return None


def validate_hostname_filter(value):
    """Validate DSM_HOSTNAME_FILTER (client-side hostname substring).

    None / blank -> None (no filter applied).  Whitespace is trimmed;
    case is lowered so the substring match is case-insensitive.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    if not text:
        return None
    return text.lower()


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on the DSM host."""
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def build_computers_url(host):
    base = normalize_base_url(host)
    return f"{base}/api/computers"


def build_am_events_url(host):
    base = normalize_base_url(host)
    return f"{base}/api/searches/eventsantimalware"


def build_ips_rules_url(host):
    base = normalize_base_url(host)
    return f"{base}/api/ipsrules"


def auth_headers(api_key):
    """Deep Security REST surfaces expect ``api-secret-key`` + ``api-version``."""
    return {
        "api-secret-key": str(api_key),
        "api-version": "v1",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def build_search_body(id_cursor=0, max_items=PAGE_SIZE, host_id=None, policy_id=None):
    """Build a Deep Security ``searchCriteria`` body.

    Uses the canonical id-cursor pagination Deep Security exposes —
    ``idValue`` is the last-seen item id and ``idTest=greater-than``
    walks forward through the catalogue.  ``maxItems`` caps a single
    response at 5 000.  ``host_id`` narrows an anti-malware event
    search to one computer; ``policy_id`` narrows a computer search to
    one policy.
    """
    criteria = [
        {
            "fieldName": "ID",
            "idValue": int(id_cursor or 0),
            "idTest": "greater-than",
        }
    ]
    if host_id is not None:
        criteria.append(
            {
                "fieldName": "hostID",
                "numericValue": int(host_id),
                "numericTest": "equal",
            }
        )
    if policy_id is not None:
        criteria.append(
            {
                "fieldName": "policyID",
                "numericValue": int(policy_id),
                "numericTest": "equal",
            }
        )
    return {
        "maxItems": int(max_items),
        "searchCriteria": criteria,
        "sortByObjectID": True,
    }


def extract_items(payload):
    """Pull the result list out of a Deep Security response envelope.

    Deep Security uses different list keys per surface: ``computers``
    for /api/computers, ``events`` for /api/searches/eventsantimalware
    and ``intrusionPreventionRules`` (alias: ``ipsRules``) for
    /api/ipsrules.  Walk every common alias defensively.
    """
    if not isinstance(payload, dict):
        return []
    for key in (
        "computers",
        "events",
        "intrusionPreventionRules",
        "ipsRules",
        "items",
        "results",
        "data",
    ):
        v = payload.get(key)
        if isinstance(v, list):
            return v
    return []


def cvss_score(item):
    """Pull a numeric CVSS score from a Deep Security payload.

    Deep Security stamps CVSS on virtual-patching IPS rules under
    ``cvssScore`` (top-level) and inside the ``cvss`` nested block on
    re-emitted shapes.
    """
    if not isinstance(item, dict):
        return None
    for key in (
        "cvssScore",
        "cvss_score",
        "CVSSScore",
        "baseScore",
        "base_score",
    ):
        v = item.get(key)
        if v is None or isinstance(v, (dict, list, bool)):
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2"):
        nested = item.get(nested_key)
        if isinstance(nested, dict):
            for inner_key in ("3.0", "3.1", "2.0"):
                inner = nested.get(inner_key)
                if isinstance(inner, dict):
                    for k in ("base", "score", "baseScore", "base_score"):
                        v = inner.get(k)
                        if v is None or isinstance(v, (dict, list, bool)):
                            continue
                        try:
                            return float(v)
                        except (TypeError, ValueError):
                            continue
            for k in ("score", "baseScore", "base_score", "base"):
                v = nested.get(k)
                if v is None or isinstance(v, (dict, list, bool)):
                    continue
                try:
                    return float(v)
                except (TypeError, ValueError):
                    continue
        elif isinstance(nested, list):
            for entry in nested:
                if not isinstance(entry, dict):
                    continue
                for k in ("baseScore", "base_score", "score", "base"):
                    v = entry.get(k)
                    if v is None or isinstance(v, (dict, list, bool)):
                        continue
                    try:
                        return float(v)
                    except (TypeError, ValueError):
                        continue
    return None


def cvss_vector(item):
    if not isinstance(item, dict):
        return ""
    for k in ("cvssVector", "cvss_vector", "vector", "vectorString", "vector_string"):
        s = item.get(k)
        if isinstance(s, str) and s.strip():
            return s.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3"):
        nested = item.get(nested_key)
        if isinstance(nested, dict):
            for inner_key in ("3.0", "3.1", "2.0"):
                inner = nested.get(inner_key)
                if isinstance(inner, dict):
                    for k in ("vector", "vectorString", "vector_string"):
                        s = inner.get(k)
                        if isinstance(s, str) and s.strip():
                            return s.strip()
            for k in ("vector", "vectorString", "vector_string"):
                s = nested.get(k)
                if isinstance(s, str) and s.strip():
                    return s.strip()
    return ""


def collect_cves(item):
    """Pull CVE-* ids out of a Deep Security AM event / IPS rule payload.

    Deep Security IPS rules stamp the protected CVEs under ``CVE`` (one
    canonical-cased entry) plus ``cveDescription`` (free text).  AM
    events occasionally reference the CVE in ``malwareName`` /
    ``reason``.  Walk every surface defensively.
    """
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if not CVE_RE.fullmatch(s):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    def scan(text):
        if not isinstance(text, str):
            return
        for m in CVE_RE.findall(text):
            add(m)

    if not isinstance(item, dict):
        return found

    for key in ("cve", "CVE", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)
                elif isinstance(entry, dict):
                    scan(entry.get("id") or entry.get("name") or entry.get("value"))
        elif isinstance(v, dict):
            scan(v.get("id") or v.get("name") or v.get("value"))
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(
                        entry.get("id")
                        or entry.get("name")
                        or entry.get("cve")
                        or entry.get("cveId")
                        or entry.get("value")
                    )

    for key in (
        "name",
        "Name",
        "description",
        "Description",
        "cveDescription",
        "malwareName",
        "malware_name",
        "reason",
        "Reason",
        "title",
        "filePath",
        "file_path",
        "sourceProcessName",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)
                elif isinstance(entry, dict):
                    for sub_key in ("name", "value", "id"):
                        s = entry.get(sub_key)
                        if isinstance(s, str):
                            scan(s)
    return found


def collect_refs(item):
    """Walk a Deep Security AM event / IPS rule for advisory pivots.

    Surfaces Deep Security-side pivots (``DSM-Rule: {ruleID}``,
    ``DSM-RuleName: {name}``, ``DSM-Malware: {malwareName}``,
    ``DSM-MalwareType: {malwareType}``, ``DSM-FileSHA1: {sha1}``,
    ``DSM-FileSHA256: {sha256}``, ``DSM-FilePath: {path}``,
    ``DSM-Policy: {policy}``, ``DSM-ScanAction: {action}``,
    ``DSM-ApplicationType: {appType}``) plus any inline URLs from the
    rule's ``references`` block.
    """
    refs = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(item, dict):
        return refs

    rule_id = item.get("ruleID") or item.get("ID") or item.get("ipsRuleID")
    if rule_id is not None and not isinstance(rule_id, bool):
        s = str(rule_id).strip()
        if s:
            add(f"DSM-Rule: {s}")

    rule_name = item.get("name") or item.get("Name") or item.get("ruleName")
    if isinstance(rule_name, str) and rule_name.strip():
        add(f"DSM-RuleName: {rule_name.strip()}")

    malware_name = item.get("malwareName") or item.get("malware_name")
    if isinstance(malware_name, str) and malware_name.strip():
        add(f"DSM-Malware: {malware_name.strip()}")

    malware_type = item.get("malwareType") or item.get("malware_type")
    if isinstance(malware_type, str) and malware_type.strip():
        add(f"DSM-MalwareType: {malware_type.strip()}")

    sha1 = item.get("fileSHA1") or item.get("fileSha1") or item.get("file_sha1")
    if isinstance(sha1, str) and sha1.strip():
        add(f"DSM-FileSHA1: {sha1.strip()}")

    sha256 = item.get("fileSHA256") or item.get("fileSha256") or item.get("file_sha256")
    if isinstance(sha256, str) and sha256.strip():
        add(f"DSM-FileSHA256: {sha256.strip()}")

    file_path = item.get("filePath") or item.get("file_path")
    if isinstance(file_path, str) and file_path.strip():
        add(f"DSM-FilePath: {file_path.strip()}")

    policy = item.get("policy")
    if isinstance(policy, dict):
        name = policy.get("name") or policy.get("Name")
        if isinstance(name, str) and name.strip():
            add(f"DSM-Policy: {name.strip()}")
        pid = policy.get("id") or policy.get("policyID")
        if pid is not None:
            add(f"DSM-PolicyId: {pid}")
    elif isinstance(policy, str) and policy.strip():
        add(f"DSM-Policy: {policy.strip()}")
    pid = item.get("policyID") or item.get("policy_id")
    if pid is not None and not isinstance(pid, bool):
        add(f"DSM-PolicyId: {pid}")

    scan_action = item.get("scanAction1") or item.get("scan_action_1")
    if isinstance(scan_action, str) and scan_action.strip():
        add(f"DSM-ScanAction: {scan_action.strip()}")

    app_type = item.get("applicationType") or item.get("application_type")
    if isinstance(app_type, str) and app_type.strip():
        add(f"DSM-ApplicationType: {app_type.strip()}")
    elif isinstance(app_type, dict):
        name = app_type.get("name")
        if isinstance(name, str) and name.strip():
            add(f"DSM-ApplicationType: {name.strip()}")

    for key in ("references", "links", "References", "Links"):
        entry = item.get(key) if isinstance(item, dict) else None
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("name") or it.get("value")
                    if href:
                        add(href)
                elif it:
                    add(str(it))
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def computer_label(computer):
    """Build a friendly label for a Deep Security computer record."""
    if not isinstance(computer, dict):
        return ""
    for key in (
        "displayName",
        "display_name",
        "hostName",
        "host_name",
        "name",
        "Name",
        "fqdn",
    ):
        v = computer.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("ID", "id", "Id", "hostID", "host_id"):
        v = computer.get(key)
        if v is not None and not isinstance(v, bool):
            s = str(v).strip()
            if s:
                return s
    return ""


def event_label(item):
    """Build the leading title fragment for a Deep Security AM event."""
    if not isinstance(item, dict):
        return ""
    name = item.get("malwareName") or item.get("malware_name") or item.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    file_path = item.get("filePath") or item.get("file_path")
    if isinstance(file_path, str) and file_path.strip():
        return file_path.strip()
    malware_type = item.get("malwareType") or item.get("malware_type")
    if isinstance(malware_type, str) and malware_type.strip():
        return f"Malware ({malware_type.strip()})"
    return "Deep Security AM event"


def ips_rule_label(item):
    """Build the leading title fragment for a Deep Security IPS rule."""
    if not isinstance(item, dict):
        return ""
    name = item.get("name") or item.get("Name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    rule_id = item.get("ID") or item.get("id") or item.get("ruleID")
    if rule_id is not None and not isinstance(rule_id, bool):
        return f"IPS Rule {rule_id}"
    return "Deep Security IPS rule"


def host_bucket_key(item):
    """Pick a stable bucket key for a Deep Security computer / event record."""
    if not isinstance(item, dict):
        return "__unknown__"
    for key in ("ID", "id", "Id", "hostID", "host_id"):
        v = item.get(key)
        if v is None or isinstance(v, bool):
            continue
        s = str(v).strip()
        if s:
            return s
    for key in ("hostName", "host_name", "displayName", "display_name"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "__unknown__"


def host_ip(item):
    """Pick the host IP from a Deep Security computer record.

    Deep Security surfaces ``lastIPUsed`` on the computer record; older
    shapes carry ``ip`` / ``ipAddress`` scalars.  Falls back to synthetic
    ``0.0.0.0`` because Deep Security agents on VDI / mobile / public
    cloud endpoints sometimes only carry private addresses (loopback
    ``127.0.0.1`` and ``0.0.0.0`` are explicitly skipped).
    """
    if not isinstance(item, dict):
        return "0.0.0.0"
    for key in ("lastIPUsed", "last_ip_used", "ip", "ipAddress", "ip_address"):
        v = item.get(key)
        if isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1"):
            return v.strip()
    for key in ("ipAddresses", "ip_addresses"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip() and entry.strip() not in ("0.0.0.0", "127.0.0.1"):
                    return entry.strip()
    return "0.0.0.0"


def host_mac(item):
    if not isinstance(item, dict):
        return ""
    for key in ("macAddress", "mac_address", "mac"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("macAddresses", "mac_addresses"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    return entry.strip()
    return ""


def host_os(item):
    if not isinstance(item, dict):
        return ""
    platform = item.get("platform") or item.get("Platform")
    if isinstance(platform, str) and platform.strip():
        return platform.strip()
    os_name = item.get("os") or item.get("operatingSystem") or item.get("operating_system") or ""
    return str(os_name).strip()


def _serialise(obj):
    if obj is None:
        return ""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (str, int, float)):
        return str(obj)
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(obj)


def build_am_vulnerability(event, computer_lookup=None):
    """Build a Faraday vulnerability dict from a Deep Security AM event.

    ``computer_lookup`` is an optional ``{computer_id: computer_record}``
    map used to enrich the description with the computer's hostName /
    displayName / platform when the event only carries hostID.
    """
    if not isinstance(event, dict):
        return None

    score = cvss_score(event)
    severity = severity_from_event(event, cvss=score)
    status = status_from_event(event)

    label = event_label(event)
    name = f"[EDR] {label}" if label else "[EDR] Deep Security AM event"

    desc_parts = []
    description = event.get("description") or event.get("Description") or event.get("reason")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    for label_key, key in (
        ("event_id", "eventID"),
        ("host_id", "hostID"),
        ("malware_name", "malwareName"),
        ("malware_type", "malwareType"),
        ("scan_type", "scanType"),
        ("scan_action_1", "scanAction1"),
        ("scan_action_2", "scanAction2"),
        ("scan_result_action_1", "scanResultAction1"),
        ("scan_result_action_2", "scanResultAction2"),
        ("error_code", "errorCode"),
        ("file_path", "filePath"),
        ("file_sha1", "fileSHA1"),
        ("file_sha256", "fileSHA256"),
        ("file_size", "fileSize"),
        ("source_user", "sourceUser"),
        ("source_process_name", "sourceProcessName"),
        ("source_process_sha1", "sourceProcessSHA1"),
        ("source_process_sha256", "sourceProcessSHA256"),
        ("source_ip", "sourceIP"),
        ("target_ip", "targetIP"),
        ("log_date", "logDate"),
        ("log_time", "logTime"),
        ("detection_time", "detectionTime"),
        ("quarantine_record_id", "quarantineRecordID"),
        ("application_type", "applicationType"),
    ):
        v = event.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(event)
    if vector:
        desc_parts.append(f"vector: {vector}")

    if isinstance(computer_lookup, dict):
        host_id = event.get("hostID") or event.get("host_id")
        if host_id is not None:
            comp = computer_lookup.get(str(host_id))
            if isinstance(comp, dict):
                for label_key, key in (
                    ("computer_hostName", "hostName"),
                    ("computer_displayName", "displayName"),
                    ("computer_platform", "platform"),
                    ("computer_agentVersion", "agentVersion"),
                    ("computer_policyID", "policyID"),
                ):
                    v = comp.get(key)
                    if v not in (None, ""):
                        desc_parts.append(f"{label_key}: {v}")

    cves = collect_cves(event)
    refs = collect_refs(event)

    resolution = ""
    rem = event.get("remediation") or event.get("Remediation") or event.get("remediationDescription")
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution:
        scan_action = event.get("scanAction1") or event.get("scan_action_1")
        if isinstance(scan_action, str) and scan_action.strip():
            resolution = (
                f"Deep Security scanAction1: {scan_action.strip()}. "
                "Confirm the disposition in the Deep Security Manager "
                "console (Events & Reports -> Events -> Anti-Malware Events) "
                "and tune the policy / allow-list if the action was incorrect."
            )
    if not resolution:
        resolution = (
            "Investigate the event in the Trend Micro Deep Security Manager "
            "console (Events & Reports -> Events -> Anti-Malware Events -> "
            "select event) and decide a disposition (true positive -> ensure "
            "Quarantine / Delete action; false positive -> add a scan exclusion)."
        )

    external_id = str(
        event.get("eventID")
        or event.get("fileSHA256")
        or event.get("fileSHA1")
        or event.get("quarantineRecordID")
        or (cves[0] if cves else "")
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Deep Security AM event {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["trendmicro_deep_security", "edr", "endpoint-edr"],
    }


def build_ips_vulnerability(rule, computer=None):
    """Build a Faraday vulnerability dict from a Deep Security IPS rule.

    IPS rules are the virtual-patching catalogue Deep Security uses to
    block known CVEs at the network layer; the per-computer surface
    ``intrusionPrevention.ruleIDs`` lists which rules are assigned to
    each computer.  We surface every (computer, IPS rule) pair where
    the rule maps onto a CVE list as a Faraday vulnerability so the
    workspace mirrors the virtual-patch posture the manager reports.
    """
    if not isinstance(rule, dict):
        return None

    score = cvss_score(rule)
    severity = severity_from_event(rule, cvss=score)

    label = ips_rule_label(rule)
    name = f"[EDR] {label}" if label else "[EDR] Deep Security IPS rule"

    desc_parts = []
    description = rule.get("description") or rule.get("Description") or rule.get("cveDescription")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    for label_key, key in (
        ("rule_id", "ID"),
        ("rule_name", "name"),
        ("identifier", "identifier"),
        ("type", "type"),
        ("template_type", "templateType"),
        ("severity_raw", "severity"),
        ("detect_only", "detectOnly"),
        ("alert_enabled", "alertEnabled"),
        ("application_type_id", "applicationTypeID"),
        ("pattern_action", "patternAction"),
        ("pattern_if_static_type", "patternIfStaticType"),
        ("priority", "priority"),
    ):
        v = rule.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(rule)
    if vector:
        desc_parts.append(f"vector: {vector}")

    if isinstance(computer, dict):
        for label_key, key in (
            ("computer_hostName", "hostName"),
            ("computer_displayName", "displayName"),
            ("computer_platform", "platform"),
            ("computer_agentVersion", "agentVersion"),
            ("computer_policyID", "policyID"),
        ):
            v = computer.get(key)
            if v not in (None, ""):
                desc_parts.append(f"{label_key}: {v}")

    cves = collect_cves(rule)
    refs = collect_refs(rule)

    rule_id = rule.get("ID") or rule.get("id") or rule.get("ruleID")
    resolution = (
        f"Trend Micro Deep Security IPS rule {rule_id} ({label}) is "
        "providing virtual-patching coverage for the listed CVEs. Confirm "
        "the rule is set to Prevent (not Detect-Only) in the assigned "
        "policy and patch the underlying software per the vendor advisory "
        "to remove dependency on the IPS shim."
    )

    external_id = str(rule_id or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Deep Security IPS rule {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["trendmicro_deep_security", "edr", "endpoint-edr"],
    }


def build_host(bucket_key, sample_computer, vulns):
    """Build a Faraday host record for the supplied computer bucket."""
    sample = sample_computer if isinstance(sample_computer, dict) else {}
    label = computer_label(sample) if sample else ""
    hostname = ""
    if label:
        hostname = label
    elif bucket_key and bucket_key != "__unknown__":
        hostname = bucket_key

    ip = host_ip(sample) if sample else "0.0.0.0"
    mac = host_mac(sample) if sample else ""
    os_str = host_os(sample) if sample else ""

    desc_parts = []
    if bucket_key and bucket_key != "__unknown__":
        desc_parts.append(f"computer_id={bucket_key}")

    if isinstance(sample, dict):
        for label_key, key in (
            ("hostName", "hostName"),
            ("displayName", "displayName"),
            ("platform", "platform"),
            ("agentVersion", "agentVersion"),
            ("agentStatus", "agentStatus"),
            ("agentStatusMessages", "agentStatusMessages"),
            ("lastAgentCommunication", "lastAgentCommunication"),
            ("lastIPUsed", "lastIPUsed"),
            ("policyID", "policyID"),
            ("groupID", "groupID"),
            ("policyName", "policyName"),
        ):
            v = sample.get(key)
            if v not in (None, ""):
                desc_parts.append(f"{label_key}={v}")

    if vulns:
        desc_parts.append(f"findings={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_computers(requests_module, host, headers, policy_id=None, verify=True):
    """Walk /api/computers with id-cursor pagination."""
    out = []
    cursor = 0
    pages = 0
    url = build_computers_url(host) + "/search"
    # Deep Security computers list expands related blocks (antiMalware,
    # intrusionPrevention.ruleIDs etc.) via the ``expand`` query param.
    params_url = url + "?expand=all&overrides=false"
    while pages < MAX_PAGES:
        body = build_search_body(id_cursor=cursor, max_items=PAGE_SIZE, policy_id=policy_id)
        try:
            resp = requests_module.post(
                params_url,
                headers=headers,
                json=body,
                timeout=TIMEOUT,
                verify=verify,
            )
        except Exception as exc:  # noqa: BLE001
            log(f"POST {params_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Deep Security request rejected (401). Check DSM_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Deep Security request rejected (403). API key role lacks computers read.")
            return out
        if resp.status_code == 404:
            log(f"Deep Security request 404 for {params_url} — endpoint not found")
            return out
        if resp.status_code >= 400:
            log(f"Deep Security request failed ({resp.status_code}) for {params_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Deep Security response was not JSON ({params_url})")
            return out
        items = extract_items(payload)
        if not items:
            break
        last_id = cursor
        for entry in items:
            if isinstance(entry, dict):
                out.append(entry)
                eid = entry.get("ID") or entry.get("id")
                if isinstance(eid, int):
                    if eid > last_id:
                        last_id = eid
        if last_id <= cursor:
            break
        cursor = last_id
        if len(items) < PAGE_SIZE:
            break
        pages += 1
    if pages >= MAX_PAGES:
        log(f"hit MAX_PAGES={MAX_PAGES}; stopping pagination on {params_url}")
    return out


def fetch_am_events(requests_module, host, headers, verify=True):
    """Walk /api/searches/eventsantimalware with id-cursor pagination."""
    out = []
    cursor = 0
    pages = 0
    url = build_am_events_url(host)
    while pages < MAX_PAGES:
        body = build_search_body(id_cursor=cursor, max_items=PAGE_SIZE)
        try:
            resp = requests_module.post(
                url,
                headers=headers,
                json=body,
                timeout=TIMEOUT,
                verify=verify,
            )
        except Exception as exc:  # noqa: BLE001
            log(f"POST {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Deep Security request rejected (401). Check DSM_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Deep Security request rejected (403). API key role lacks AM events read.")
            return out
        if resp.status_code >= 400:
            log(f"Deep Security request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Deep Security response was not JSON ({url})")
            return out
        items = extract_items(payload)
        if not items:
            break
        last_id = cursor
        for entry in items:
            if isinstance(entry, dict):
                out.append(entry)
                eid = entry.get("eventID") or entry.get("ID") or entry.get("id")
                if isinstance(eid, int) and eid > last_id:
                    last_id = eid
        if last_id <= cursor:
            break
        cursor = last_id
        if len(items) < PAGE_SIZE:
            break
        pages += 1
    if pages >= MAX_PAGES:
        log(f"hit MAX_PAGES={MAX_PAGES}; stopping pagination on {url}")
    return out


def fetch_ips_rules(requests_module, host, headers, verify=True):
    """Walk /api/ipsrules with id-cursor pagination."""
    out = []
    cursor = 0
    pages = 0
    base = build_ips_rules_url(host)
    while pages < MAX_PAGES:
        url = f"{base}/search"
        body = build_search_body(id_cursor=cursor, max_items=PAGE_SIZE)
        try:
            resp = requests_module.post(
                url,
                headers=headers,
                json=body,
                timeout=TIMEOUT,
                verify=verify,
            )
        except Exception as exc:  # noqa: BLE001
            log(f"POST {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Deep Security request rejected (401). Check DSM_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Deep Security request rejected (403). API key role lacks IPS rules read.")
            return out
        if resp.status_code >= 400:
            log(f"Deep Security request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Deep Security response was not JSON ({url})")
            return out
        items = extract_items(payload)
        if not items:
            break
        last_id = cursor
        for entry in items:
            if isinstance(entry, dict):
                out.append(entry)
                eid = entry.get("ID") or entry.get("id")
                if isinstance(eid, int) and eid > last_id:
                    last_id = eid
        if last_id <= cursor:
            break
        cursor = last_id
        if len(items) < PAGE_SIZE:
            break
        pages += 1
    if pages >= MAX_PAGES:
        log(f"hit MAX_PAGES={MAX_PAGES}; stopping pagination on {url}")
    return out


def hostname_matches(computer, substring):
    """Return True when ``substring`` matches the computer's hostName / displayName."""
    if not substring:
        return True
    if not isinstance(computer, dict):
        return False
    for key in ("hostName", "host_name", "displayName", "display_name", "name"):
        v = computer.get(key)
        if isinstance(v, str) and substring in v.lower():
            return True
    return False


def extract_assigned_rule_ids(computer):
    """Pull the list of IPS rule IDs assigned to a Deep Security computer.

    The DSM ``intrusionPrevention`` block carries the per-computer
    rule assignment; we walk both the top-level ``ruleIDs`` array and
    the alt-keyed surfaces seen on legacy on-prem stacks.
    """
    if not isinstance(computer, dict):
        return []
    out = []

    def add(v):
        if v is None or isinstance(v, bool):
            return
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            s = str(v).strip()
            if s and s not in [str(x) for x in out]:
                out.append(s)

    ip_block = computer.get("intrusionPrevention") or computer.get("intrusion_prevention")
    if isinstance(ip_block, dict):
        for key in ("ruleIDs", "rule_ids", "ruleIds"):
            v = ip_block.get(key)
            if isinstance(v, list):
                for entry in v:
                    add(entry)
    for key in ("ipsRuleIDs", "ips_rule_ids"):
        v = computer.get(key)
        if isinstance(v, list):
            for entry in v:
                add(entry)
    # Dedup preserving order.
    seen = set()
    dedup = []
    for v in out:
        if v in seen:
            continue
        seen.add(v)
        dedup.append(v)
    return dedup


def main():
    started = time.time()

    host = env("DSM_HOST", required=True)
    api_key = env("DSM_API_KEY", required=True)
    policy_id = validate_policy_id(env("EXECUTOR_CONFIG_DSM_POLICY_ID"))
    hostname_filter = validate_hostname_filter(env("EXECUTOR_CONFIG_DSM_HOSTNAME_FILTER"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_DSM_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    verify_env = (os.getenv("DSM_VERIFY_SSL") or "").strip().lower()
    verify = verify_env not in ("0", "false", "no", "off")

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(api_key)

    computers = fetch_computers(requests, host, headers, policy_id=policy_id, verify=verify)
    am_events = fetch_am_events(requests, host, headers, verify=verify)
    ips_rules = fetch_ips_rules(requests, host, headers, verify=verify)

    log(
        f"Processing {len(computers)} Deep Security computers + {len(am_events)} AM events + "
        f"{len(ips_rules)} IPS rules (policy_id={policy_id}, "
        f"hostname_filter={hostname_filter!r}, min_severity={min_severity})"
    )

    # Apply client-side hostname filter.
    if hostname_filter:
        computers = [c for c in computers if hostname_matches(c, hostname_filter)]

    ips_lookup = {}
    for rule in ips_rules:
        if not isinstance(rule, dict):
            continue
        rid = rule.get("ID") or rule.get("id") or rule.get("ruleID")
        if rid is not None and not isinstance(rid, bool):
            ips_lookup[str(rid)] = rule

    computer_lookup = {}
    for comp in computers:
        if not isinstance(comp, dict):
            continue
        cid = comp.get("ID") or comp.get("id") or comp.get("hostID")
        if cid is not None and not isinstance(cid, bool):
            computer_lookup[str(cid)] = comp

    buckets = {cid: [] for cid in computer_lookup}

    # AM events: fan out per host_id.
    for event in am_events:
        if not isinstance(event, dict):
            continue
        host_id = event.get("hostID") or event.get("host_id")
        bucket_key = str(host_id) if host_id is not None else "__unknown__"
        if bucket_key not in buckets:
            # Skip events for filtered-out computers.
            if hostname_filter and bucket_key in computer_lookup:
                continue
            buckets.setdefault(bucket_key, [])
        vuln = build_am_vulnerability(event, computer_lookup=computer_lookup)
        if vuln is None:
            continue
        if allowed_severities and vuln["severity"] not in allowed_severities:
            continue
        buckets[bucket_key].append(vuln)

    # IPS rules: fan out per (computer, assigned rule) where the rule has CVEs.
    for cid, computer in computer_lookup.items():
        rule_ids = extract_assigned_rule_ids(computer)
        for rid in rule_ids:
            rule = ips_lookup.get(str(rid))
            if not isinstance(rule, dict):
                continue
            cves = collect_cves(rule)
            score = cvss_score(rule)
            severity = severity_from_event(rule, cvss=score)
            if not cves and severity not in ("high", "critical"):
                # Skip low-signal IPS rules without a CVE pivot.
                continue
            vuln = build_ips_vulnerability(rule, computer=computer)
            if vuln is None:
                continue
            if allowed_severities and vuln["severity"] not in allowed_severities:
                continue
            buckets[cid].append(vuln)

    hosts = []
    for key, vulns in buckets.items():
        sample = computer_lookup.get(key) if key != "__unknown__" else {}
        hosts.append(build_host(key, sample, vulns))

    params_bits = []
    if policy_id is not None:
        params_bits.append(f"policy_id={policy_id}")
    if hostname_filter:
        params_bits.append(f"hostname_filter={hostname_filter}")
    params_bits.append(f"min_severity={min_severity}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "trendmicro_deep_security",
            "command": "trendmicro_deep_security",
            "params": ",".join(params_bits),
            "user": os.environ.get("USER", ""),
            "hostname": socket.gethostname(),
            "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
            "duration": int((time.time() - started) * 1000),
            "import_source": "report",
        },
    }
    print(json.dumps(output))


if __name__ == "__main__":
    main()
