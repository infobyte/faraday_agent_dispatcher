#!/usr/bin/env python
"""Tripwire Enterprise compliance / FIM REST importer.

Pulls the managed-node catalogue and the open compliance / file
integrity findings from a Tripwire Enterprise console and emits
Faraday bulk-create JSON to stdout.  Tripwire Enterprise's surface
is node-scoped (one row per managed Windows / Linux / Solaris /
network-device endpoint) and rule-scoped (one finding per element
version that fails a policy rule), so each TE-managed node becomes
one Faraday host (keyed by the TE node identifier; carries the
node's hostname / IP / OS / make-model / tags); each unresolved
finding on that node attaches as a Faraday vulnerability with the
engine prefix ``[CONFIG-MGMT]``.

Endpoints used:
  GET <TRIPWIRE_HOST>/api/v1/computers
      -> paginated managed-node catalogue, optionally narrowed by
      ``nodeGroup=<TRIPWIRE_NODE_GROUP>`` (matches the friendly
      group name; TE node-group names are user-defined per console
      so the executor matches case-insensitively against
      ``nodeGroups[].name`` on each computer record as a defence-
      in-depth fallback when the server's filter does not honour
      the parameter).  Each record carries the node's ``id`` /
      ``name`` / ``ipAddress`` / ``operatingSystem`` / ``make`` /
      ``model`` / ``nodeGroups`` / ``lastCheck`` / ``tags``.
  GET <TRIPWIRE_HOST>/api/v1/elementVersions/findings
      -> paginated finding catalogue, optionally narrowed by
      ``ruleType=<TRIPWIRE_RULE_TYPE>`` (accepted values are
      Tripwire-canonical: ``compliance`` / ``configuration`` /
      ``policy`` / ``file_integrity`` / ``change`` — case-insensitive
      and validated client-side).  Findings are joined back to the
      computer catalogue by ``nodeId`` / ``computerId``; orphaned
      findings (assets present in TE-findings but not in the
      narrowed computer catalogue) attach to a synthetic catch-all
      host so they are not silently dropped.

Pagination is TE-canonical ``start`` + ``count`` cursor
(``PAGE_SIZE=100`` x ``MAX_PAGES=200`` = 20k rows per endpoint)
with ``totalCount`` exhaustion detection.

Auth: HTTP Basic with the ``TRIPWIRE_USER`` / ``TRIPWIRE_PASSWORD``
credentials carried as ``Authorization: Basic <b64(user:password)>``
+ ``Accept: application/json`` on every call.  Built explicitly via
``base64.b64encode`` so the executor stays testable without a live
``requests`` install and the encoded credentials never leak into log
output.
"""

import base64
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Tripwire Enterprise host validation — accept http(s)://host[:port],
# strip trailing slash.  Control chars (newline / tab / null / etc)
# rejected outright so a header-injection attempt can't sneak through.
# Anchored with \A/\Z (not ^/$) so a trailing newline cannot sneak
# past the regex — Python's `$` matches just before a trailing `\n`.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")
# TE node-group name validation — friendly names like
# "DC Tier-1 Windows Servers" are allowed (alphanumeric + spaces +
# `._-` up to 128 chars).
NODE_GROUP_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 ._\-]{0,127}\Z")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# Tripwire Enterprise rule-type validation — accepts the canonical
# Tripwire rule-type families with common synonyms folded onto each.
# Anything outside this set is logged + ignored (rather than fanned
# out into a 400) so a typo can't crash the run.  Mapping value is
# the canonical TE rule-type slug the server expects on the
# ``ruleType`` query parameter.
TE_RULE_TYPES = {
    "compliance": "compliance",
    "config": "configuration",
    "configuration": "configuration",
    "policy": "policy",
    "policy_check": "policy",
    "policycheck": "policy",
    "file_integrity": "file_integrity",
    "fileintegrity": "file_integrity",
    "fim": "file_integrity",
    "integrity": "file_integrity",
    "change": "change",
    "changes": "change",
    "change_audit": "change",
    "changeaudit": "change",
}

# Tripwire Enterprise surfaces ``severity`` as a freeform string
# enum (critical / high / medium / low / info plus TE synonyms
# severe / major / moderate / warning / minor / informational) plus
# a numeric ``severityScore`` / ``score`` 0-10 (CVSS-style on the
# vuln-link findings, internal 0-100 on the compliance findings).
# The string enum buckets onto Faraday tiers; numeric bucketing is
# used as a fallback.
TE_STRING_SEVERITY = {
    "critical": "critical",
    "severe": "critical",
    "very_high": "critical",
    "veryhigh": "critical",
    "high": "high",
    "major": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unknown": "info",
    "unspecified": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Tripwire Enterprise finding lifecycle is exposed through
# ``status`` / ``state`` / ``findingStatus`` / ``resolution``.
# Open / new / detected / unresolved map onto Faraday open;
# resolved / promoted / approved (a TE-specific "the change is now
# the new baseline" lifecycle action) map onto closed;
# acknowledged / accepted / waived / suppressed / dismissed map
# onto risk-accepted.
TE_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "active": "open",
    "detected": "open",
    "unresolved": "open",
    "in_progress": "open",
    "inprogress": "open",
    "investigating": "open",
    "triaging": "open",
    "reopened": "open",
    "pending": "open",
    "remediated": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "patched": "closed",
    "mitigated": "closed",
    "closed": "closed",
    "completed": "closed",
    "promoted": "closed",
    "approved": "closed",
    "baselined": "closed",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "acknowledged": "risk-accepted",
    "deferred": "risk-accepted",
    "waived": "risk-accepted",
    "will_not_fix": "risk-accepted",
    "willnotfix": "risk-accepted",
    "wontfix": "risk-accepted",
    "won't_fix": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "suppressed": "risk-accepted",
    "dismissed": "risk-accepted",
    "ignored": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - TripwireEnterprise: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    # Per-scan EXECUTOR_CONFIG_<name> arg wins; bare env-var is the fallback.
    if name.startswith("EXECUTOR_CONFIG_"):
        value = os.getenv(name, default)
    else:
        value = os.environ.get(f"EXECUTOR_CONFIG_{name}") or os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
    """Bucket a numeric severity (0-10 CVSS-style) onto a Faraday tier."""
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


def severity_from_tripwire(value, numeric=None):
    """Map a Tripwire Enterprise severity string onto a Faraday bucket.

    Accepts the freeform string enum (critical / high / medium / low /
    info), TE synonyms (severe / major / important / moderate /
    warning / minor / informational), numeric inputs (0-10 CVSS-style),
    numeric strings, and falls back to numeric bucketing on
    ``numeric`` when the primary value is missing or unrecognised.
    """
    if isinstance(value, bool):
        if numeric is not None:
            return severity_from_cvss(numeric)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        if text in TE_STRING_SEVERITY:
            return TE_STRING_SEVERITY[text]
        squashed = text.replace("_", "")
        if squashed in TE_STRING_SEVERITY:
            return TE_STRING_SEVERITY[squashed]
        try:
            return severity_from_cvss(float(value.strip()))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def status_from_tripwire(item):
    """Derive Faraday status from a Tripwire Enterprise finding payload."""
    if not isinstance(item, dict):
        return "open"
    for key in (
        "status",
        "state",
        "findingStatus",
        "finding_status",
        "resolution",
        "resolutionStatus",
        "resolution_status",
        "Status",
        "State",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in TE_STATUS_BY_STATE:
                return TE_STATUS_BY_STATE[compact]
            if squashed in TE_STATUS_BY_STATE:
                return TE_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in TE_STATUS_BY_STATE:
                        return TE_STATUS_BY_STATE[compact]
                    if squashed in TE_STATUS_BY_STATE:
                        return TE_STATUS_BY_STATE[squashed]
    return "open"


def validate_min_severity(value):
    """Validate TRIPWIRE_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus TE synonyms (severe ->
    critical, major / important -> high, moderate / warning -> medium,
    minor -> low, informational / information / unspecified -> info)
    plus numeric-string input bucketed via severity_from_cvss.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "info"
    bucket = TE_STRING_SEVERITY.get(text)
    if bucket is None:
        bucket = TE_STRING_SEVERITY.get(text.replace("_", ""))
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(str(value).strip()))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"TRIPWIRE_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_node_group(value):
    """Validate TRIPWIRE_NODE_GROUP.

    None / blank -> ``None`` (no node-group filter applied — every
    computer in the catalogue is walked).  Friendly group names like
    "DC Tier-1 Windows" are allowed.  Control chars rejected on the
    *raw* value before .strip() so a typo ending in \\n / \\r cannot
    sneak past NODE_GROUP_RE.
    """
    if value is None or value == "":
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("TRIPWIRE_NODE_GROUP contains a control char; ignoring filter")
        return None
    text = raw.strip()
    if not text:
        return None
    if not NODE_GROUP_RE.match(text):
        log(
            f"TRIPWIRE_NODE_GROUP '{text}' is not a valid identifier "
            "(alphanumeric + spaces + ._- up to 128 chars); ignoring filter"
        )
        return None
    return text


def validate_rule_type(value):
    """Validate TRIPWIRE_RULE_TYPE.

    None / blank -> ``None`` (no rule-type filter applied).  Accepts
    canonical TE rule-type families (compliance / configuration /
    policy / file_integrity / change) plus common synonyms (config,
    fim, integrity, change_audit, etc.); garbage is logged + ignored
    rather than fanned out into a 400.  Returns the canonical TE
    rule-type slug the server expects on the ``ruleType`` query
    parameter (None when no filter).
    """
    if value is None or value == "":
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("TRIPWIRE_RULE_TYPE contains a control char; ignoring filter")
        return None
    text = raw.strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return None
    canonical = TE_RULE_TYPES.get(text)
    if canonical is None:
        canonical = TE_RULE_TYPES.get(text.replace("_", ""))
    if canonical is None:
        log(
            f"TRIPWIRE_RULE_TYPE '{value}' not recognised "
            "(expected compliance / configuration / policy / file_integrity / change); "
            "ignoring filter"
        )
        return None
    return canonical


def validate_host(value):
    """Validate TRIPWIRE_HOST.

    None / blank -> sys.exit(1).  Must be ``http(s)://host[:port]``;
    trailing slash stripped client-side.  Control chars rejected so a
    header-injection attempt can't sneak through.
    """
    if value is None or value == "":
        log("TRIPWIRE_HOST is required")
        sys.exit(1)
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("TRIPWIRE_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("TRIPWIRE_HOST is required")
        sys.exit(1)
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"TRIPWIRE_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(user, password):
    """Tripwire Enterprise expects HTTP Basic auth.

    Built explicitly via base64.b64encode so the executor stays
    testable without a live ``requests`` install and the encoded
    credentials never leak into log output.
    """
    raw = f"{user or ''}:{password or ''}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return {
        "Authorization": f"Basic {encoded}",
        "Accept": "application/json",
    }


def build_computers_url(host):
    return f"{host}/api/v1/computers"


def build_findings_url(host):
    return f"{host}/api/v1/elementVersions/findings"


def build_computers_params(node_group, start, count):
    """TE computer pagination is ``start`` + ``count`` cursor."""
    params = {"start": int(start), "count": int(count)}
    if node_group:
        # TE accepts ``nodeGroup=<name>`` on /api/v1/computers; on
        # some console versions the parameter is silently ignored
        # which is fine — we re-check ``nodeGroups[].name`` on each
        # record client-side as a defence-in-depth fallback.
        params["nodeGroup"] = node_group
    return params


def build_findings_params(rule_type, start, count):
    """TE finding pagination is ``start`` + ``count`` cursor."""
    params = {"start": int(start), "count": int(count)}
    if rule_type:
        params["ruleType"] = rule_type
    return params


def extract_results(body):
    """Pull the result list out of a TE pagination envelope.

    TE uses ``{"results": [...], "totalCount": N, "start": M,
    "count": K}`` on its v1 endpoints — accept ``data`` / ``items``
    / ``findings`` / ``computers`` / ``entries`` as alt-keys for
    federated stacks.
    """
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for key in ("results", "data", "items", "findings", "computers", "entries"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_count(body):
    """Pull the total record count from a TE envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("totalCount", "total_count", "total", "count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


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


def collect_cves(item):
    """Walk a TE finding payload for CVE-* ids."""
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

    for key in ("cve", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "cve_ids", "cveIds"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    details = item.get("details") if isinstance(item, dict) else None
    if isinstance(details, dict):
        for key in ("cve", "cves", "cve_id", "cve_ids"):
            v = details.get(key)
            if isinstance(v, str):
                add(v)
            elif isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add(entry)

    for key in (
        "description",
        "summary",
        "name",
        "title",
        "details_description",
        "ruleDescription",
        "rule_description",
        "evidence",
        "remediation",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
    if isinstance(details, dict):
        for key in ("description", "evidence", "summary"):
            v = details.get(key)
            if isinstance(v, str):
                scan(v)

    return found


def collect_refs(item):
    """Walk a TE finding payload for advisory URLs and TE pivots."""
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

    finding_id = item.get("id") or item.get("findingId") or item.get("finding_id")
    if finding_id is not None:
        s = str(finding_id).strip()
        if s:
            add(f"Tripwire-Finding: {s}")

    rule_id = item.get("ruleId") or item.get("rule_id") or item.get("ruleName") or item.get("rule_name")
    if rule_id is not None:
        s = str(rule_id).strip()
        if s:
            add(f"Tripwire-Rule: {s}")

    rule_type = item.get("ruleType") or item.get("rule_type")
    if isinstance(rule_type, str) and rule_type.strip():
        add(f"Tripwire-RuleType: {rule_type.strip()}")

    policy = item.get("policy") or item.get("policyName") or item.get("policy_name")
    if isinstance(policy, str) and policy.strip():
        add(f"Tripwire-Policy: {policy.strip()}")
    elif isinstance(policy, dict):
        label = policy.get("name") or policy.get("id")
        if isinstance(label, str) and label.strip():
            add(f"Tripwire-Policy: {label.strip()}")

    test_id = item.get("testId") or item.get("test_id") or item.get("testName") or item.get("test_name")
    if test_id is not None:
        s = str(test_id).strip()
        if s:
            add(f"Tripwire-Test: {s}")

    element = (
        item.get("elementName")
        or item.get("element_name")
        or item.get("elementPath")
        or item.get("element_path")
        or item.get("path")
    )
    if isinstance(element, str) and element.strip():
        add(f"Tripwire-Element: {element.strip()}")

    element_version = item.get("elementVersionId") or item.get("element_version_id") or item.get("elementVersion")
    if element_version is not None:
        s = str(element_version).strip()
        if s:
            add(f"Tripwire-ElementVersion: {s}")

    node_name = item.get("nodeName") or item.get("node_name") or item.get("computerName") or item.get("computer_name")
    if isinstance(node_name, str) and node_name.strip():
        add(f"Tripwire-Node: {node_name.strip()}")

    node_id = item.get("nodeId") or item.get("node_id") or item.get("computerId") or item.get("computer_id")
    if node_id is not None:
        s = str(node_id).strip()
        if s:
            add(f"Tripwire-NodeId: {s}")

    for key in ("references", "links", "advisory_urls", "remediations"):
        entry = item.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("link") or it.get("help_text") or it.get("name")
                    if href:
                        add(href)
                elif isinstance(it, str):
                    add(it)
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def finding_label(item):
    """Build the leading title fragment for a TE finding."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "title",
        "name",
        "ruleName",
        "rule_name",
        "testName",
        "test_name",
        "policyName",
        "policy_name",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("summary", "description", "finding_description"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "Tripwire Enterprise finding"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from a TE finding record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    for key in (
        "severityScore",
        "severity_score",
        "score",
        "cvss",
        "cvssScore",
        "cvss_score",
        "riskScore",
        "risk_score",
    ):
        raw_numeric = item.get(key)
        if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
            severity_numeric = float(raw_numeric)
            break
        if isinstance(raw_numeric, str) and raw_numeric.strip():
            try:
                severity_numeric = float(raw_numeric.strip())
                break
            except ValueError:
                continue

    severity_string = (
        item.get("severity")
        or item.get("severityLabel")
        or item.get("severity_label")
        or item.get("severityName")
        or item.get("severity_name")
        or item.get("risk_level")
        or item.get("riskLevel")
    )
    severity = severity_from_tripwire(severity_string, severity_numeric)
    status = status_from_tripwire(item)

    label = finding_label(item)
    name = f"[CONFIG-MGMT] {label}" if label else "[CONFIG-MGMT] Tripwire Enterprise finding"

    desc_parts = []
    description = (
        item.get("description")
        or item.get("Description")
        or item.get("finding_description")
        or item.get("details_description")
        or item.get("ruleDescription")
        or item.get("rule_description")
    )
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("id", "id"),
        ("finding_id", "finding_id"),
        ("rule_id", "ruleId"),
        ("rule_name", "ruleName"),
        ("rule_type", "ruleType"),
        ("policy", "policyName"),
        ("test_id", "testId"),
        ("test_name", "testName"),
        ("element", "elementName"),
        ("element_version_id", "elementVersionId"),
        ("path", "path"),
        ("first_seen", "firstSeen"),
        ("last_seen", "lastSeen"),
        ("first_detected", "firstDetected"),
        ("last_detected", "lastDetected"),
        ("severity", "severity"),
        ("severity_score", "severityScore"),
        ("status", "status"),
        ("resolution", "resolution"),
        ("node_id", "nodeId"),
        ("node_name", "nodeName"),
        ("change_type", "changeType"),
        ("change_action", "changeAction"),
        ("baseline", "baselineId"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if severity_numeric is not None:
        desc_parts.append(f"severity_score: {severity_numeric}")

    details = item.get("details")
    if isinstance(details, dict):
        for label_key, key in (
            ("evidence", "evidence"),
            ("observed_value", "observed_value"),
            ("expected_value", "expected_value"),
            ("parameter", "parameter"),
            ("location", "location"),
        ):
            v = details.get(key)
            if v in (None, ""):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"details.{label_key}: {_serialise(v)}")
            else:
                desc_parts.append(f"details.{label_key}: {v}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    remediations = item.get("remediations") or item.get("recommendation") or item.get("resolution")
    if isinstance(remediations, list):
        bits = []
        for r in remediations:
            if isinstance(r, dict):
                txt = r.get("help_text") or r.get("description") or r.get("name") or r.get("solution")
                if isinstance(txt, str) and txt.strip():
                    bits.append(txt.strip())
            elif isinstance(r, str) and r.strip():
                bits.append(r.strip())
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(remediations, str) and remediations.strip():
        resolution = remediations.strip()
    if not resolution:
        resolution = (
            "Investigate the finding in the Tripwire Enterprise console "
            "(Findings -> select the element version -> Rule + Evidence "
            "tabs) and drive remediation through the platform owner — "
            "compliance failures usually require a config change to "
            "restore the policy baseline; file-integrity / change "
            "findings require either rollback to the prior version or "
            "promotion of the new version to the baseline via the "
            "Tripwire ``Promote`` action."
        )

    external_id = str(
        item.get("id")
        or item.get("findingId")
        or item.get("finding_id")
        or item.get("elementVersionId")
        or item.get("element_version_id")
        or (cves[0] if cves else "")
    )

    return {
        "name": str(name).strip()[:200] or f"Tripwire Enterprise finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["tripwire", "tripwire-enterprise", "config-mgmt", "compliance"],
    }


def node_hostname(node, fallback):
    """Pick the canonical hostname for a TE computer record."""
    if isinstance(node, dict):
        for key in ("name", "hostname", "host", "fqdn", "dnsName", "dns_name"):
            v = node.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return ""


def node_ip(node):
    """Pick an IP address for the TE node (if surfaced)."""
    if not isinstance(node, dict):
        return "0.0.0.0"
    for key in ("ipAddress", "ip_address", "ip", "primaryIp", "primary_ip"):
        v = node.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "0.0.0.0"


def node_os(node):
    """Build the host.os string from a TE computer record.

    TE surfaces ``operatingSystem`` as a freeform string (e.g.
    ``Microsoft Windows Server 2019``); ``make`` / ``model`` extend
    it on appliance-class records.  Falls back to the literal
    ``Tripwire Enterprise`` if no metadata is present.
    """
    if not isinstance(node, dict):
        return "Tripwire Enterprise"
    os_str = (
        node.get("operatingSystem")
        or node.get("operating_system")
        or node.get("os")
        or node.get("osName")
        or node.get("os_name")
    )
    if isinstance(os_str, str) and os_str.strip():
        return os_str.strip()
    make = node.get("make")
    model = node.get("model")
    parts = []
    if isinstance(make, str) and make.strip():
        parts.append(make.strip())
    if isinstance(model, str) and model.strip():
        parts.append(model.strip())
    if parts:
        return " ".join(parts)
    return "Tripwire Enterprise"


def node_in_group(node, node_group):
    """Check whether a TE computer record claims membership in ``node_group``.

    Defence-in-depth fallback for TE consoles that ignore the
    ``nodeGroup=`` query parameter — re-checks ``nodeGroups[].name``
    on each record client-side and matches case-insensitively.
    """
    if not node_group:
        return True
    if not isinstance(node, dict):
        return False
    target = node_group.strip().lower()
    groups = node.get("nodeGroups") or node.get("node_groups") or node.get("groups")
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, str) and g.strip().lower() == target:
                return True
            if isinstance(g, dict):
                name = g.get("name") or g.get("groupName") or g.get("group_name")
                if isinstance(name, str) and name.strip().lower() == target:
                    return True
    return False


def build_host(node_id, node, vulns):
    """Build a Faraday host record for a TE-managed node."""
    if not isinstance(node, dict):
        node = {}
    hostname = node_hostname(node, node_id)
    os_str = node_os(node)
    ip = node_ip(node)

    desc_parts = [f"node_id={node_id}"]
    for label_key, key in (
        ("name", "name"),
        ("operating_system", "operatingSystem"),
        ("make", "make"),
        ("model", "model"),
        ("last_check", "lastCheck"),
        ("last_audit", "lastAudit"),
        ("agent_version", "agentVersion"),
        ("agent_status", "agentStatus"),
        ("environment", "environment"),
        ("location", "location"),
        ("description", "description"),
    ):
        v = node.get(key)
        if v not in (None, ""):
            desc_parts.append(f"{label_key}={v}")

    groups = node.get("nodeGroups") or node.get("node_groups") or node.get("groups")
    if isinstance(groups, list):
        names = []
        for g in groups:
            if isinstance(g, str) and g.strip():
                names.append(g.strip())
            elif isinstance(g, dict):
                name = g.get("name") or g.get("groupName") or g.get("group_name")
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
        if names:
            desc_parts.append(f"node_groups={','.join(names)}")

    tags = node.get("tags")
    if isinstance(tags, list):
        names = [t.strip() for t in tags if isinstance(t, str) and t.strip()]
        if names:
            desc_parts.append(f"tags={','.join(names)}")

    if vulns:
        desc_parts.append(f"findings={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_paginated(requests_module, url, headers, params_builder, label, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk a TE paginated endpoint via start/count cursor."""
    out = []
    start = 0
    pages_walked = 0
    while pages_walked < max_pages:
        params = params_builder(start, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log(f"Tripwire {label} request rejected (401). Check TRIPWIRE_USER / TRIPWIRE_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"Tripwire {label} request rejected (403). Check the user's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"Tripwire {label} endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"Tripwire {label} request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Tripwire {label} response was not JSON ({url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < page_size:
            break
        total = extract_count(payload)
        if isinstance(total, int) and (start + len(results)) >= total:
            break
        start += page_size
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages} for {label}; stopping pagination")
    return out


def fetch_computers(requests_module, host, node_group, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk the TE /api/v1/computers catalogue via start/count cursor."""
    url = build_computers_url(host)

    def params_builder(start, count):
        return build_computers_params(node_group, start, count)

    rows = fetch_paginated(
        requests_module,
        url,
        headers,
        params_builder,
        label="computers",
        max_pages=max_pages,
        page_size=page_size,
    )
    # Defence-in-depth: TE consoles that ignore the nodeGroup query
    # parameter return the whole catalogue — re-filter client-side.
    if node_group:
        rows = [r for r in rows if node_in_group(r, node_group)]
    return rows


def fetch_findings(requests_module, host, rule_type, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk the TE /api/v1/elementVersions/findings catalogue via start/count cursor."""
    url = build_findings_url(host)

    def params_builder(start, count):
        return build_findings_params(rule_type, start, count)

    return fetch_paginated(
        requests_module,
        url,
        headers,
        params_builder,
        label="findings",
        max_pages=max_pages,
        page_size=page_size,
    )


def finding_node_id(finding):
    """Pull the joining node id out of a TE finding record."""
    if not isinstance(finding, dict):
        return None
    for key in ("nodeId", "node_id", "computerId", "computer_id"):
        v = finding.get(key)
        if v is None or v == "":
            continue
        return str(v).strip()
    # Some federated shapes nest the node id under a sub-dict.
    node = finding.get("node") or finding.get("computer")
    if isinstance(node, dict):
        for key in ("id", "nodeId", "computerId"):
            v = node.get(key)
            if v is None or v == "":
                continue
            return str(v).strip()
    return None


def computer_id(computer):
    """Pull the canonical node id from a TE computer record."""
    if not isinstance(computer, dict):
        return None
    for key in ("id", "nodeId", "computerId", "node_id", "computer_id"):
        v = computer.get(key)
        if v is None or v == "":
            continue
        return str(v).strip()
    return None


def main():
    started = time.time()

    node_group = validate_node_group(env("EXECUTOR_CONFIG_TRIPWIRE_NODE_GROUP"))
    rule_type = validate_rule_type(env("EXECUTOR_CONFIG_TRIPWIRE_RULE_TYPE"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_TRIPWIRE_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = validate_host(env("TRIPWIRE_HOST", required=True))
    user = env("TRIPWIRE_USER", required=True)
    password = env("TRIPWIRE_PASSWORD", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(user, password)
    computers = fetch_computers(requests, host, node_group, headers)
    findings = fetch_findings(requests, host, rule_type, headers)

    log(
        f"Processing {len(findings)} Tripwire Enterprise findings across "
        f"{len(computers)} managed nodes "
        f"(node_group={node_group or '*'}, rule_type={rule_type or '*'}, "
        f"min_severity={min_severity})"
    )

    # Index computers by id for the finding -> host join.
    computer_index = {}
    for c in computers:
        cid = computer_id(c)
        if cid:
            computer_index[cid] = c

    # Bucket findings by node id; orphan findings whose node isn't
    # in the (possibly narrowed) computer catalogue attach to a
    # synthetic catch-all host so they're not silently dropped.
    findings_by_node = {}
    orphan_findings = []
    for f in findings:
        built = build_vulnerability(f)
        if built is None:
            continue
        if allowed_severities and built["severity"] not in allowed_severities:
            continue
        nid = finding_node_id(f)
        if nid and nid in computer_index:
            findings_by_node.setdefault(nid, []).append(built)
        else:
            orphan_findings.append(built)

    hosts = []
    for cid, computer in computer_index.items():
        vulns = findings_by_node.get(cid, [])
        hosts.append(build_host(cid, computer, vulns))

    if orphan_findings:
        synthetic = {
            "name": "tripwire-orphan-findings",
            "description": "Findings whose nodeId did not match the narrowed computer catalogue.",
        }
        hosts.append(build_host("orphan", synthetic, orphan_findings))

    if not hosts:
        # No computers came back at all — emit a synthetic placeholder
        # so the Faraday workspace still records that the TE query
        # was processed.
        placeholder = {
            "name": "tripwire-no-results",
            "description": (f"No computers returned from /api/v1/computers " f"(node_group={node_group or '*'})."),
        }
        hosts.append(build_host("placeholder", placeholder, []))

    params_bits = []
    if node_group:
        params_bits.append(f"node_group={node_group}")
    if rule_type:
        params_bits.append(f"rule_type={rule_type}")
    params_bits.append(f"min_severity={min_severity}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "tripwire_enterprise",
            "command": "tripwire_enterprise",
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
