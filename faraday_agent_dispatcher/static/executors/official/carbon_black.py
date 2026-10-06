#!/usr/bin/env python
"""Carbon Black Cloud (VMware / Broadcom) REST importer.

Pulls alerts and managed devices from Carbon Black Cloud (the SaaS
successor to the on-prem Carbon Black Response / Carbon Black Defense
products) via the v7 alerts search API and the v6 appservices devices
search API. Emits Faraday bulk-create JSON to stdout. Each managed
endpoint becomes one Faraday host (``ip`` = the first non-loopback
entry in ``last_internal_ip_address`` / ``last_external_ip_address``,
falling back to synthetic ``0.0.0.0``); alerts attach as Faraday
vulnerabilities — one per alert id with engine prefix ``[EDR]``.

Endpoints used:
  POST {CB_HOST}/api/alerts/v7/orgs/{org_key}/alerts/_search
      -> paginated alert search. POST body carries the search criteria
      (severity floor + time range + rows / start pagination) and the
      response shape is ``{"num_found": N, "results": [...]}``. The
      v7 alert envelope unifies what older API versions split across
      ``/api/alerts/v6/orgs/{org_key}/alerts``,
      ``/api/alerts/v6/orgs/{org_key}/alerts/cbanalytics`` (CB Defense),
      ``/api/alerts/v6/orgs/{org_key}/alerts/watchlist`` and
      ``/api/alerts/v6/orgs/{org_key}/alerts/devicecontrol`` into a
      single, type-tagged record.
  POST {CB_HOST}/appservices/v6/orgs/{org_key}/devices/_search
      -> paginated device (sensor) inventory. POST body carries the
      search criteria (rows + start pagination); response shape is
      ``{"num_found": N, "results": [...]}``. Surfaces sensor metadata
      (deployment_type, sensor_version, policy_name, os, last_seen_*,
      last_internal_ip_address, last_external_ip_address) used to
      enrich the host record for any device that has open alerts plus
      to surface devices with no alerts as inventory-only hosts.

Auth: Carbon Black Cloud uses a per-API-Key X-Auth-Token header in the
form ``<API_SECRET>/<API_ID>``. The Connector API Key is created in the
Carbon Black Cloud console (Settings -> API Access -> Add API Key) with
the access level granted at the org scope (the "API" access level for
read-only alert + device queries). Credentials are exposed to the
dispatcher as ``CB_API_ID`` (the API ID) and ``CB_API_SECRET`` (the API
Secret); ``CB_HOST`` is the regional API endpoint (e.g.
``https://defense-prod05.conferdeploy.net`` for the US-East prod05
region — Carbon Black has region-pinned endpoints, one per cloud).
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
PAGE_SIZE = 1000  # Carbon Black caps rows per page at 10000; 1000 is a polite default.

# Carbon Black surfaces severity as a 1-10 integer ("severity" field
# on alerts) plus a freeform "severity" / "category" string on some
# legacy shapes. The numeric scale buckets onto Faraday tiers per the
# Carbon Black Cloud severity guidance (1-2 -> low, 3-5 -> medium,
# 6-7 -> high, 8-10 -> critical); Faraday-side synonyms are accepted so
# re-emitted shapes still bucket correctly.
CB_STRING_SEVERITY = {
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

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Carbon Black numeric severity (1-10) -> Faraday severity floor when
# build_min_severity_threshold needs to convert "medium" into the
# CB-side integer threshold (``criteria.minimum_severity``). The
# mapping follows the CB Cloud console — 1 = info, 2 = low, 3-5 =
# medium, 6-7 = high, 8-10 = critical.
CB_NUMERIC_FLOOR = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 6,
    "critical": 8,
}

# Carbon Black workflow / state -> Faraday status. CB Cloud surfaces
# alert lifecycle through ``workflow.state`` (OPEN / IN_PROGRESS /
# CLOSED) plus a ``determination`` (NONE / TRUE_POSITIVE /
# FALSE_POSITIVE) on the legacy /v6 shape. We collapse onto Faraday's
# open / closed / risk-accepted scheme; suppression decisions go to
# risk-accepted.
CB_STATUS_BY_STATE = {
    "open": "open",
    "in_progress": "open",
    "inprogress": "open",
    "new": "open",
    "active": "open",
    "closed": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "remediated": "closed",
    "dismissed": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "wontfix": "risk-accepted",
    "won't_fix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false_positive": "risk-accepted",
}

# Carbon Black ``time_range`` shorthand. The v7 search API accepts a
# ``time_range.range`` token (e.g. ``-1d``, ``-7d``, ``-30d``) or a
# concrete ``{start, end}`` ISO-8601 window. We normalise common
# operator-friendly shorthand (1h / 24h / 7d / 30d / today / yesterday)
# into the CB-canonical ``-Nd`` / ``-Nh`` form so the API accepts it.
TIME_RANGE_ALIASES = {
    "1h": "-1h",
    "24h": "-1d",
    "1d": "-1d",
    "today": "-1d",
    "yesterday": "-2d",
    "2d": "-2d",
    "3d": "-3d",
    "7d": "-7d",
    "week": "-7d",
    "1w": "-7d",
    "14d": "-14d",
    "2w": "-14d",
    "30d": "-30d",
    "month": "-30d",
    "1m": "-30d",
    "60d": "-60d",
    "90d": "-90d",
    "3m": "-90d",
}

VALID_TIME_RANGE_RE = re.compile(r"^-\d+[hdwmy]$", re.IGNORECASE)


def log(msg):
    print(f"{datetime.utcnow()} - CarbonBlack: {msg}", file=sys.stderr, flush=True)


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


def severity_from_cb(value, cvss=None):
    """Map a Carbon Black severity to a Faraday bucket.

    Accepts the numeric 1-10 scale, the freeform string enum
    (Critical / High / Medium / Low / Informational), Faraday-side
    synonyms, and falls back to CVSS bucketing on ``cvss`` when the
    primary value is missing or unrecognised.
    """
    if isinstance(value, bool):
        # Defensive: bool is a subclass of int — skip it entirely.
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"
    if isinstance(value, (int, float)):
        score = float(value)
        if score <= 0:
            return "info"
        if score < 2:
            return "info"
        if score < 3:
            return "low"
        if score < 6:
            return "medium"
        if score < 8:
            return "high"
        if score > 10:
            return "info"
        return "critical"
    if isinstance(value, str) and value.strip():
        text = value.strip().lower()
        if text in CB_STRING_SEVERITY:
            return CB_STRING_SEVERITY[text]
        try:
            return severity_from_cb(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_cb(item):
    """Derive Faraday status from a Carbon Black alert payload.

    Walks ``workflow.state`` first (the v7 alert envelope's lifecycle
    field), then falls back to ``state`` / ``status`` / ``workflow``
    / ``determination`` for re-emitted shapes.
    """
    if not isinstance(item, dict):
        return "open"
    workflow = item.get("workflow")
    if isinstance(workflow, dict):
        for key in ("state", "status", "State", "Status"):
            raw = workflow.get(key)
            if isinstance(raw, str) and raw.strip():
                compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
                squashed = compact.replace("_", "")
                if compact in CB_STATUS_BY_STATE:
                    return CB_STATUS_BY_STATE[compact]
                if squashed in CB_STATUS_BY_STATE:
                    return CB_STATUS_BY_STATE[squashed]
    elif isinstance(workflow, str) and workflow.strip():
        compact = workflow.strip().lower().replace(" ", "_").replace("-", "_")
        if compact in CB_STATUS_BY_STATE:
            return CB_STATUS_BY_STATE[compact]
    for key in ("state", "status", "alertStatus", "alert_status", "State", "Status"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in CB_STATUS_BY_STATE:
                return CB_STATUS_BY_STATE[compact]
            if squashed in CB_STATUS_BY_STATE:
                return CB_STATUS_BY_STATE[squashed]
    determination = item.get("determination")
    if isinstance(determination, dict):
        value = determination.get("value") or determination.get("name")
        if isinstance(value, str) and value.strip():
            compact = value.strip().lower().replace(" ", "_").replace("-", "_")
            if compact == "false_positive":
                return "risk-accepted"
            if compact == "true_positive":
                return "open"
    return "open"


def validate_min_severity(value):
    """Validate CB_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied
    beyond the default). Accepts the canonical Faraday buckets plus
    Carbon Black-side synonyms (informational, important / major,
    moderate, minor, none / unspecified / unknown).
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = CB_STRING_SEVERITY.get(text)
    if bucket is None:
        # Numeric input (1-10) -> bucket via the CB numeric scale.
        try:
            bucket = severity_from_cb(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"CB_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_org_key(value):
    """Validate CB_ORG_KEY (the Carbon Black organisation identifier).

    None / blank -> caller sys.exits with a clear message (the org key
    is mandatory; every CB Cloud API call carries it in the URL path).
    Whitespace is trimmed. Carbon Black org keys are 8-char base-36
    strings — we don't enforce the shape client-side because some
    federated stacks use longer / mixed-case identifiers.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    if not text:
        return None
    return text


def validate_time_range(value):
    """Validate CB_TIME_RANGE.

    Accepts the canonical CB token shape (``-Nd`` / ``-Nh`` / ``-Nw``
    / ``-Nm`` / ``-Ny``) plus operator-friendly aliases (24h, 7d,
    30d, week, month, today, yesterday). None / blank -> None (no
    time filter; the search returns every alert the org can read).
    Garbage -> None with a log line.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    if not text:
        return None
    keyed = text.lower().replace(" ", "")
    if keyed in TIME_RANGE_ALIASES:
        return TIME_RANGE_ALIASES[keyed]
    # If the operator already supplied -Nd / -Nh / -Nw shape, accept it
    # verbatim (case-insensitive on the unit suffix).
    if VALID_TIME_RANGE_RE.match(keyed):
        return keyed
    log(f"CB_TIME_RANGE '{value}' not recognised; dropping filter")
    return None


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def cb_numeric_floor(min_severity):
    """Return the CB 1-10 numeric floor for a Faraday severity bucket.

    Used to populate ``criteria.minimum_severity`` on the v7 search
    body so CB does most of the filtering server-side.
    """
    return CB_NUMERIC_FLOOR.get(min_severity, 1)


def build_alert_search_body(min_severity, time_range, rows, start):
    """Build the POST body for /api/alerts/v7/orgs/{org}/alerts/_search.

    Returns a dict mirroring the v7 search shape — ``criteria`` carries
    the server-side filters, ``time_range`` carries the rolling window,
    and ``rows`` + ``start`` carry pagination. Empty filters are
    omitted so the caller gets every alert the org can read.
    """
    body = {
        "rows": int(rows),
        "start": int(start),
        "sort": [{"field": "backend_timestamp", "order": "DESC"}],
    }
    criteria = {}
    floor = cb_numeric_floor(min_severity)
    if floor > 1:
        criteria["minimum_severity"] = floor
    if criteria:
        body["criteria"] = criteria
    if time_range:
        body["time_range"] = {"range": time_range}
    return body


def build_device_search_body(rows, start):
    """Build the POST body for /appservices/v6/orgs/{org}/devices/_search.

    Returns a dict mirroring the v6 search shape — ``rows`` + ``start``
    pagination, with a stable ``last_contact_time`` DESC sort so
    re-runs see the freshest devices first.
    """
    return {
        "rows": int(rows),
        "start": int(start),
        "sort": [{"field": "last_contact_time", "order": "DESC"}],
    }


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on the CB host."""
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def build_alert_url(host, org_key):
    base = normalize_base_url(host)
    return f"{base}/api/alerts/v7/orgs/{org_key}/alerts/_search"


def build_device_url(host, org_key):
    base = normalize_base_url(host)
    return f"{base}/appservices/v6/orgs/{org_key}/devices/_search"


def auth_headers(api_id, api_secret):
    """Carbon Black Cloud expects ``X-Auth-Token: <SECRET>/<ID>``."""
    return {
        "X-Auth-Token": f"{api_secret}/{api_id}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_items(body, keys=("results", "data", "alerts", "devices")):
    """Pull the result list out of a CB-style search envelope.

    CB Cloud uses ``{"num_found": N, "results": [...]}`` consistently
    on the alerts + devices search endpoints, but the alt keys appear
    on legacy / federated stacks — be defensive.
    """
    if not isinstance(body, dict):
        return []
    for key in keys:
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def cvss_score(item):
    """Pull a numeric CVSS score from a CB alert payload.

    CB alerts surface CVE / CVSS through the threat hashes catalogue
    (``threat.cvss_score`` / ``threat.cvss`` / ``threat.cvss3``) and
    occasionally through ``additionalData.cvss``. Walk those surfaces
    defensively so re-emitted findings still bucket correctly.
    """
    if not isinstance(item, dict):
        return None
    candidates = [item]
    threat = item.get("threat")
    if isinstance(threat, dict):
        candidates.insert(0, threat)
    additional = item.get("additionalData") or item.get("additional_data")
    if isinstance(additional, dict):
        candidates.insert(0, additional)
    for src in candidates:
        if not isinstance(src, dict):
            continue
        for key in ("cvssScore", "cvss_score", "score", "baseScore", "base_score"):
            v = src.get(key)
            if v is None or isinstance(v, (dict, list, bool)):
                continue
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
        for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2"):
            nested = src.get(nested_key)
            if isinstance(nested, dict):
                for inner_key in ("3.0", "3.1", "2.0"):
                    inner = nested.get(inner_key)
                    if isinstance(inner, dict):
                        for k in ("base", "Base", "score", "Score", "baseScore", "base_score"):
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
    candidates = [item]
    threat = item.get("threat")
    if isinstance(threat, dict):
        candidates.insert(0, threat)
    additional = item.get("additionalData") or item.get("additional_data")
    if isinstance(additional, dict):
        candidates.insert(0, additional)
    for src in candidates:
        if not isinstance(src, dict):
            continue
        for k in ("cvssVector", "cvss_vector", "vector", "vectorString", "vector_string"):
            s = src.get(k)
            if isinstance(s, str) and s.strip():
                return s.strip()
        for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3"):
            nested = src.get(nested_key)
            if isinstance(nested, dict):
                for inner_key in ("3.0", "3.1", "2.0"):
                    inner = nested.get(inner_key)
                    if isinstance(inner, dict):
                        for k in ("vector", "Vector", "vectorString", "vector_string"):
                            s = inner.get(k)
                            if isinstance(s, str) and s.strip():
                                return s.strip()
                for k in ("vector", "vectorString", "vector_string"):
                    s = nested.get(k)
                    if isinstance(s, str) and s.strip():
                        return s.strip()
            elif isinstance(nested, list):
                for entry in nested:
                    if not isinstance(entry, dict):
                        continue
                    for k in ("vector", "vectorString", "vector_string"):
                        s = entry.get(k)
                        if isinstance(s, str) and s.strip():
                            return s.strip()
    return ""


def collect_cves(item):
    """Pull CVE-* ids out of a Carbon Black alert payload.

    Walks ``threat.cve`` / ``cves`` / ``aliases`` surfaces and falls
    back to free-form description / reason / threat_cause_actor_name
    scans (defensive for hand-curated alerts that only mention the CVE
    in text).
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

    threat = item.get("threat") if isinstance(item.get("threat"), dict) else {}
    additional = item.get("additionalData") or item.get("additional_data") or {}
    if not isinstance(additional, dict):
        additional = {}

    for src in (item, threat, additional):
        if not isinstance(src, dict):
            continue
        for key in ("cve", "cveId", "cve_id", "Cve", "CveId"):
            v = src.get(key)
            if isinstance(v, str) and v.strip():
                add(v)
            elif isinstance(v, dict):
                add(v.get("id") or v.get("Id") or v.get("name") or v.get("value"))
        for key in ("cves", "cveIds", "cve_ids", "aliases", "Cves"):
            v = src.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add(entry)
                    elif isinstance(entry, dict):
                        add(
                            entry.get("id")
                            or entry.get("Id")
                            or entry.get("name")
                            or entry.get("cve")
                            or entry.get("cveId")
                        )

    for key in (
        "reason",
        "Reason",
        "description",
        "Description",
        "title",
        "Title",
        "alert_description",
        "alertDescription",
        "alert_message",
        "alertMessage",
        "threat_cause_actor_name",
        "threat_cause_reason",
        "threat_indicators",
        "mitre_tactics",
        "mitre_techniques",
        "ttps",
        "tactics",
        "techniques",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)
                elif isinstance(entry, dict):
                    for sub_key in ("name", "value", "id", "label"):
                        s = entry.get(sub_key)
                        if isinstance(s, str):
                            scan(s)

    threat_reason = threat.get("reason") if isinstance(threat, dict) else None
    if isinstance(threat_reason, str):
        scan(threat_reason)
    threat_indicators = threat.get("threat_indicators") if isinstance(threat, dict) else None
    if isinstance(threat_indicators, list):
        for entry in threat_indicators:
            if isinstance(entry, str):
                scan(entry)
            elif isinstance(entry, dict):
                for sub_key in ("name", "value", "id"):
                    s = entry.get(sub_key)
                    if isinstance(s, str):
                        scan(s)

    return found


def collect_refs(item):
    """Walk a CB alert for advisory URLs / pivots.

    Surfaces CB-side pivots (``CB-Alert: {id}``, ``CB-Threat: {id}``,
    ``CB-Process: {process_guid}``, MITRE ATT&CK tactic / technique
    references) plus any inline URLs from the threat catalogue.
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

    def add_cwe(value):
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, (int, float)):
            add(f"CWE-{int(value)}")
            return
        if isinstance(value, str) and value.strip():
            s = value.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
            return
        if isinstance(value, dict):
            cid = value.get("id") or value.get("Id") or value.get("value") or value.get("name")
            if cid is not None:
                add_cwe(cid)

    if not isinstance(item, dict):
        return refs

    threat = item.get("threat") if isinstance(item.get("threat"), dict) else {}
    additional = item.get("additionalData") or item.get("additional_data") or {}
    if not isinstance(additional, dict):
        additional = {}

    for src in (item, threat, additional):
        if not isinstance(src, dict):
            continue
        for source_key in ("cweId", "cwe_id", "cwe", "CWE"):
            add_cwe(src.get(source_key))
        for source_key in ("cwes", "cweIds", "cwe_ids", "CWEs"):
            items = src.get(source_key)
            if isinstance(items, list):
                for it in items:
                    add_cwe(it)

    alert_id = item.get("id") or item.get("alert_id") or item.get("Id")
    if isinstance(alert_id, str) and alert_id.strip():
        add(f"CB-Alert: {alert_id.strip()}")

    threat_id = (
        item.get("threat_id") or item.get("threatId") or (threat.get("id") if isinstance(threat, dict) else None)
    )
    if isinstance(threat_id, str) and threat_id.strip():
        add(f"CB-Threat: {threat_id.strip()}")

    process_guid = item.get("process_guid") or item.get("processGuid")
    if isinstance(process_guid, str) and process_guid.strip():
        add(f"CB-Process: {process_guid.strip()}")

    parent_guid = item.get("parent_guid") or item.get("parentGuid")
    if isinstance(parent_guid, str) and parent_guid.strip():
        add(f"CB-ParentProcess: {parent_guid.strip()}")

    process_hash = item.get("process_sha256") or item.get("processSha256")
    if isinstance(process_hash, str) and process_hash.strip():
        add(f"CB-ProcessSHA256: {process_hash.strip()}")

    parent_hash = item.get("parent_sha256") or item.get("parentSha256")
    if isinstance(parent_hash, str) and parent_hash.strip():
        add(f"CB-ParentSHA256: {parent_hash.strip()}")

    policy_id = item.get("policy_id") or item.get("policyId")
    if policy_id is not None:
        add(f"CB-Policy: {policy_id}")

    policy_name = item.get("policy_name") or item.get("policyName")
    if isinstance(policy_name, str) and policy_name.strip():
        add(f"CB-PolicyName: {policy_name.strip()}")

    alert_type = item.get("type") or item.get("alert_type") or item.get("category")
    if isinstance(alert_type, str) and alert_type.strip():
        add(f"CB-AlertType: {alert_type.strip()}")

    detection_source = item.get("detection_source") or item.get("detectionSource")
    if isinstance(detection_source, str) and detection_source.strip():
        add(f"CB-DetectionSource: {detection_source.strip()}")

    # MITRE ATT&CK tactics / techniques surfaced by CB alerts.
    for key in ("mitre_tactics", "mitreTactics", "tactics"):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, list):
            for tactic in v:
                if isinstance(tactic, str) and tactic.strip():
                    add(f"MITRE-Tactic: {tactic.strip()}")
                elif isinstance(tactic, dict):
                    name = tactic.get("name") or tactic.get("id") or tactic.get("value")
                    if isinstance(name, str) and name.strip():
                        add(f"MITRE-Tactic: {name.strip()}")
    for key in ("mitre_techniques", "mitreTechniques", "techniques"):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, list):
            for tech in v:
                if isinstance(tech, str) and tech.strip():
                    add(f"MITRE-Technique: {tech.strip()}")
                elif isinstance(tech, dict):
                    name = tech.get("name") or tech.get("id") or tech.get("value")
                    if isinstance(name, str) and name.strip():
                        add(f"MITRE-Technique: {name.strip()}")

    # references / links lists shared with other CSPM / EDR shapes.
    for key in ("references", "links", "References", "Links", "ioc_field"):
        entry = item.get(key) if isinstance(item, dict) else None
        if entry is None and isinstance(additional, dict):
            entry = additional.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = (
                        it.get("href")
                        or it.get("Href")
                        or it.get("url")
                        or it.get("Url")
                        or it.get("name")
                        or it.get("value")
                    )
                    if href:
                        add(href)
                elif it:
                    add(str(it))
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def device_label(item):
    """Build a friendly label for a Carbon Black device record."""
    if not isinstance(item, dict):
        return ""
    for key in ("name", "device_name", "deviceName", "hostname", "Hostname"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("email", "user", "userName", "user_name", "last_user"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("id", "Id", "device_id", "deviceId"):
        v = item.get(key)
        if v is not None:
            s = str(v).strip()
            if s:
                return s
    return ""


def vuln_label(item):
    """Build the leading title fragment for a Carbon Black finding."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "reason",
        "Reason",
        "alert_description",
        "alertDescription",
        "title",
        "Title",
        "name",
        "Name",
        "alert_message",
        "alertMessage",
        "threat_cause_reason",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    threat = item.get("threat")
    if isinstance(threat, dict):
        for key in ("reason", "name", "title"):
            v = threat.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    actor = item.get("threat_cause_actor_name") or item.get("threatCauseActorName")
    if isinstance(actor, str) and actor.strip():
        return actor.strip()
    return "Carbon Black finding"


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


def build_vulnerability(item, device_lookup=None):
    """Build a Faraday vulnerability dict from a CB alert record.

    ``device_lookup`` is an optional ``{device_id: device_record}`` map
    used to enrich the alert's host context with device-side metadata
    (sensor_version, policy_name, deployment_type). When present the
    surfaced device data is folded into the description so re-emitted
    shapes still surface every available CB enrichment.
    """
    if not isinstance(item, dict):
        return None

    score = cvss_score(item)
    severity_raw = item.get("severity") if "severity" in item else (item.get("threat", {}) or {}).get("severity")
    severity = severity_from_cb(severity_raw, score)
    status = status_from_cb(item)

    label = vuln_label(item)
    name = f"[EDR] {label}" if label else "[EDR] Carbon Black finding"

    desc_parts = []
    description = item.get("description") or item.get("Description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("alert_id", "id"),
        ("legacy_alert_id", "legacy_alert_id"),
        ("alert_type", "type"),
        ("category", "category"),
        ("reason", "reason"),
        ("reason_code", "reason_code"),
        ("severity_raw", "severity"),
        ("detection_source", "detection_source"),
        ("detection_timestamp", "detection_timestamp"),
        ("backend_timestamp", "backend_timestamp"),
        ("first_event_timestamp", "first_event_timestamp"),
        ("last_event_timestamp", "last_event_timestamp"),
        ("device_id", "device_id"),
        ("device_name", "device_name"),
        ("device_os", "device_os"),
        ("device_os_version", "device_os_version"),
        ("device_username", "device_username"),
        ("device_internal_ip", "device_internal_ip"),
        ("device_external_ip", "device_external_ip"),
        ("device_policy", "device_policy"),
        ("device_policy_id", "device_policy_id"),
        ("policy_applied", "policy_applied"),
        ("threat_id", "threat_id"),
        ("threat_indicators", "threat_indicators"),
        ("threat_cause_actor_name", "threat_cause_actor_name"),
        ("threat_cause_actor_sha256", "threat_cause_actor_sha256"),
        ("threat_cause_reason", "threat_cause_reason"),
        ("threat_cause_threat_category", "threat_cause_threat_category"),
        ("threat_cause_vector", "threat_cause_vector"),
        ("process_guid", "process_guid"),
        ("process_name", "process_name"),
        ("process_sha256", "process_sha256"),
        ("process_pid", "process_pid"),
        ("parent_guid", "parent_guid"),
        ("parent_name", "parent_name"),
        ("parent_sha256", "parent_sha256"),
        ("parent_pid", "parent_pid"),
        ("mitre_tactics", "mitre_tactics"),
        ("mitre_techniques", "mitre_techniques"),
        ("ioc_field", "ioc_field"),
        ("ioc_hit", "ioc_hit"),
        ("workflow_state", "workflow"),
        ("determination", "determination"),
        ("run_state", "run_state"),
        ("sensor_action", "sensor_action"),
        ("count", "count"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(item)
    if vector:
        desc_parts.append(f"vector: {vector}")

    if isinstance(device_lookup, dict):
        device_id = item.get("device_id") or item.get("deviceId")
        if device_id is not None:
            device = device_lookup.get(str(device_id))
            if isinstance(device, dict):
                for sub_key in (
                    "sensor_version",
                    "policy_name",
                    "policy_id",
                    "deployment_type",
                    "deployment_class",
                    "os_version",
                    "av_engine",
                    "av_av_version",
                    "av_status",
                    "av_master",
                    "av_update_servers",
                    "last_contact_time",
                    "last_reported_time",
                    "last_internal_ip_address",
                    "last_external_ip_address",
                    "last_location",
                    "last_reset_time",
                    "registered_time",
                    "scan_status",
                    "uninstalled_time",
                    "vdi_base_device_id",
                    "virtual_machine",
                ):
                    sv = device.get(sub_key)
                    if sv in (None, ""):
                        continue
                    if isinstance(sv, (dict, list)):
                        desc_parts.append(f"device_{sub_key}: {_serialise(sv)}")
                    else:
                        desc_parts.append(f"device_{sub_key}: {sv}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    rem = (
        item.get("remediation")
        or item.get("Remediation")
        or item.get("remediation_description")
        or item.get("remediationDescription")
    )
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution:
        sensor_action = item.get("sensor_action") or item.get("sensorAction")
        if isinstance(sensor_action, str) and sensor_action.strip():
            resolution = (
                f"Carbon Black sensor action: {sensor_action.strip()}. "
                "Investigate the alert in the CB Cloud console and tune the "
                "policy if the action was incorrect."
            )
    if not resolution:
        resolution = (
            "Investigate the alert in the Carbon Black Cloud console "
            "(Alerts -> select alert) and decide a workflow disposition "
            "(true positive -> respond; false positive -> dismiss)."
        )

    external_id = str(
        item.get("id") or item.get("alert_id") or item.get("legacy_alert_id") or (cves[0] if cves else "")
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Carbon Black finding {external_id}",
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
        "tags": ["carbon_black", "edr", "endpoint-edr"],
    }


def host_bucket_key(item):
    """Pick a stable bucket key for a CB alert or device record.

    Alerts have a ``device_id`` GUID; devices have ``id``. Both
    collapse onto the same string key so alerts on the same device
    end up in the same Faraday host bucket.
    """
    if not isinstance(item, dict):
        return "__unknown__"
    for key in ("device_id", "deviceId", "id", "Id"):
        v = item.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    for key in ("device_name", "deviceName", "name"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "__unknown__"


def host_ip(item):
    """Pick the host IP from a CB alert / device record.

    Devices surface ``last_internal_ip_address`` / ``last_external_ip_address``
    (the v6 sensor envelope); alerts surface ``device_internal_ip`` /
    ``device_external_ip`` (the v7 alert envelope). Falls back to
    ``0.0.0.0`` because CB-managed mobile / VDI endpoints often only
    carry private addresses.
    """
    if not isinstance(item, dict):
        return "0.0.0.0"
    for key in (
        "last_internal_ip_address",
        "lastInternalIpAddress",
        "device_internal_ip",
        "deviceInternalIp",
        "last_external_ip_address",
        "lastExternalIpAddress",
        "device_external_ip",
        "deviceExternalIp",
        "ip",
        "ipAddress",
        "ip_address",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1"):
            return v.strip()
    return "0.0.0.0"


def host_mac(item):
    if not isinstance(item, dict):
        return ""
    for key in ("mac_address", "macAddress", "mac"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def host_os(item):
    if not isinstance(item, dict):
        return ""
    os_name = item.get("os") or item.get("device_os") or item.get("deviceOs") or item.get("operating_system") or ""
    os_version = item.get("os_version") or item.get("device_os_version") or item.get("deviceOsVersion") or ""
    if os_name and os_version:
        return f"{os_name} {os_version}".strip()
    return str(os_name or os_version or "").strip()


def build_host(bucket_key, sample_alert, sample_device, vulns):
    """Build a Faraday host record for the supplied device bucket.

    ``sample_alert`` is one alert from the bucket (used to populate
    device_internal_ip / device_external_ip when no device record is
    available); ``sample_device`` is the matching device entry from
    the ``/devices/_search`` catalogue (preferred for the canonical
    sensor metadata).
    """
    sample = sample_device or sample_alert
    label = device_label(sample) if sample else ""
    hostname = ""
    if label:
        hostname = label
    elif bucket_key and bucket_key != "__unknown__":
        hostname = bucket_key

    ip = host_ip(sample_device) if sample_device else (host_ip(sample_alert) if sample_alert else "0.0.0.0")
    mac = host_mac(sample_device) if sample_device else (host_mac(sample_alert) if sample_alert else "")
    os_str = host_os(sample_device) if sample_device else (host_os(sample_alert) if sample_alert else "")

    desc_parts = []
    if bucket_key and bucket_key != "__unknown__":
        desc_parts.append(f"device_id={bucket_key}")

    if isinstance(sample_device, dict):
        for label_key, key in (
            ("device_name", "name"),
            ("os", "os"),
            ("os_version", "os_version"),
            ("policy_name", "policy_name"),
            ("policy_id", "policy_id"),
            ("deployment_type", "deployment_type"),
            ("sensor_version", "sensor_version"),
            ("scan_status", "scan_status"),
            ("av_status", "av_status"),
            ("last_contact_time", "last_contact_time"),
            ("last_reported_time", "last_reported_time"),
            ("last_internal_ip_address", "last_internal_ip_address"),
            ("last_external_ip_address", "last_external_ip_address"),
            ("last_user", "last_user"),
            ("organization_name", "organization_name"),
            ("virtual_machine", "virtual_machine"),
        ):
            v = sample_device.get(key)
            if v not in (None, ""):
                desc_parts.append(f"{label_key}={v}")
    elif isinstance(sample_alert, dict):
        for label_key, key in (
            ("device_name", "device_name"),
            ("device_os", "device_os"),
            ("device_os_version", "device_os_version"),
            ("device_username", "device_username"),
            ("device_internal_ip", "device_internal_ip"),
            ("device_external_ip", "device_external_ip"),
            ("device_policy", "device_policy"),
            ("device_policy_id", "device_policy_id"),
            ("device_location", "device_location"),
        ):
            v = sample_alert.get(key)
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


def fetch_pages(requests_module, url, headers, body_builder, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk a CB-paged ``{"num_found": N, "results": [...]}`` envelope.

    ``body_builder`` is a callable ``(rows, start) -> dict`` that builds
    each POST body. Carbon Black caps ``rows`` at 10000 per page on
    most surfaces; ``PAGE_SIZE=1000`` is a polite default that fits
    well within the cap.
    """
    out = []
    start = 0
    pages = 0
    while pages < max_pages:
        body = body_builder(page_size, start)
        try:
            resp = requests_module.post(url, headers=headers, json=body, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"POST {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Carbon Black request rejected (401). Check CB_API_ID / CB_API_SECRET.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Carbon Black request rejected (403). Check CB_ORG_KEY + API key access level.")
            return out
        if resp.status_code == 404:
            log(f"Carbon Black request 404 for {url} — endpoint not found")
            return out
        if resp.status_code >= 400:
            log(f"Carbon Black request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Carbon Black response was not JSON ({url})")
            return out
        results = extract_items(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < page_size:
            break
        num_found = payload.get("num_found") if isinstance(payload, dict) else None
        start += len(results)
        if isinstance(num_found, int) and start >= num_found:
            break
        pages += 1
    if pages >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    org_key = validate_org_key(env("EXECUTOR_CONFIG_CB_ORG_KEY"))
    if not org_key:
        log("CB_ORG_KEY is required")
        sys.exit(1)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_CB_MIN_SEVERITY"))
    time_range = validate_time_range(env("EXECUTOR_CONFIG_CB_TIME_RANGE"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = env("CB_HOST", required=True)
    api_id = env("CB_API_ID", required=True)
    api_secret = env("CB_API_SECRET", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(api_id, api_secret)
    alert_url = build_alert_url(host, org_key)
    device_url = build_device_url(host, org_key)

    alerts = fetch_pages(
        requests,
        alert_url,
        headers,
        lambda rows, start: build_alert_search_body(min_severity, time_range, rows, start),
    )
    devices = fetch_pages(
        requests,
        device_url,
        headers,
        lambda rows, start: build_device_search_body(rows, start),
    )
    log(
        f"Processing {len(alerts)} Carbon Black alerts + {len(devices)} devices "
        f"(org_key={org_key}, min_severity={min_severity}, time_range={time_range or 'ALL'})"
    )

    device_lookup = {}
    for device in devices:
        if not isinstance(device, dict):
            continue
        did = device.get("id") or device.get("Id") or device.get("device_id")
        if did is not None:
            device_lookup[str(did)] = device

    buckets = {}
    sample_alerts = {}
    for alert in alerts:
        key = host_bucket_key(alert)
        buckets.setdefault(key, []).append(alert)
        sample_alerts.setdefault(key, alert)

    # Devices with no alerts still surface as inventory hosts so the
    # Faraday workspace mirrors the full sensor inventory.
    for did, device in device_lookup.items():
        buckets.setdefault(did, [])
        sample_alerts.setdefault(did, None)

    hosts = []
    for key, alert_items in buckets.items():
        vulns = []
        for alert in alert_items:
            built = build_vulnerability(alert, device_lookup=device_lookup)
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        sample_alert = sample_alerts.get(key)
        sample_device = device_lookup.get(key) if key != "__unknown__" else None
        hosts.append(build_host(key, sample_alert, sample_device, vulns))

    params_bits = [f"org_key={org_key}", f"min_severity={min_severity}"]
    if time_range:
        params_bits.append(f"time_range={time_range}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "carbon_black",
            "command": "carbon_black",
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
