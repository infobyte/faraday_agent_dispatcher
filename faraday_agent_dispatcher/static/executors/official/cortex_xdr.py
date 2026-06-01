#!/usr/bin/env python
"""Palo Alto Cortex XDR REST importer.

Pulls incidents, managed endpoints and multi-event alerts from a
Palo Alto Cortex XDR tenant.  Emits Faraday bulk-create JSON to stdout.
Each Cortex XDR endpoint becomes one Faraday host (``ip`` = the first
non-loopback entry in the endpoint's ``ip`` / ``ip_v6`` arrays, falling
back to synthetic ``0.0.0.0``); per-endpoint incidents and alerts attach
as Faraday vulnerabilities — one per incident_id / alert_id with engine
prefix ``[EDR]``.

Endpoints used:
  POST {CXDR_HOST}/public_api/v1/incidents/get_incidents/
      -> paginated incidents catalogue.  POST body carries
      ``request_data.filters`` (server-side severity floor +
      incident-status filter), ``request_data.search_from`` /
      ``request_data.search_to`` integer cursor pagination and
      ``request_data.sort`` (``creation_time DESC`` keeps the freshest
      incidents at the head).  Response envelope is
      ``{"reply": {"incidents": [...], "total_count": N,
      "result_count": M}}``.
  POST {CXDR_HOST}/public_api/v1/endpoints/get_endpoints/
      -> paginated managed-endpoint inventory.  Same body shape as the
      incidents surface; response envelope is
      ``{"reply": {"endpoints": [...], "total_count": N,
      "result_count": M}}`` (some XDR versions wrap the list at the
      ``reply`` top-level as a plain list rather than the
      ``endpoints`` key, both shapes are tolerated).
  POST {CXDR_HOST}/public_api/v1/alerts/get_alerts_multi_events
      -> paginated alerts with associated raw events.  Same body shape
      as the incidents surface; response envelope is
      ``{"reply": {"alerts": [...], "total_count": N,
      "result_count": M}}``.

Auth: Cortex XDR exposes a Standard API Key auth flow.  The operator
creates an API Key in the Cortex XDR console (Settings -> Configurations
-> Integrations -> API Keys -> New) with Security Level set to
``Standard`` (the recommended posture for read-only data ingestion)
and pastes the returned API Key Id + API Key pair into
``CXDR_API_KEY_ID`` + ``CXDR_API_KEY``.  The dispatcher carries those
values on every request as ``Authorization: <CXDR_API_KEY>`` plus
``x-xdr-auth-id: <CXDR_API_KEY_ID>`` headers (the canonical Standard
auth shape; the Advanced HMAC-signed flow is intentionally not
implemented because the Standard flow is sufficient for read-only data
ingestion).  ``CXDR_HOST`` is the FQDN-style tenant host shown in the
API Key dialog (e.g. ``api-mytenant.xdr.us.paloaltonetworks.com``).
``CXDR_MIN_SEVERITY`` is an optional client-side severity floor that
also drives the ``incidents.get_incidents`` server-side filter so
Cortex XDR does the bulk of the filtering server-side;
``CXDR_INCIDENT_STATUS`` is an optional CSV of incident status enum
values forwarded server-side via the same filter pattern.
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
PAGE_SIZE = 100  # Cortex XDR paginates in 100-row windows on the v1 surfaces.

# Cortex XDR severity numeric enum -> Faraday bucket.  The Cortex XDR
# REST surface stamps both incidents and alerts with severity as an
# integer 1..4 (1=Low ... 4=Critical); some legacy / re-emitted shapes
# carry 5 as a Critical synonym.
CXDR_SEVERITY_NUM = {
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
    5: "critical",
}

CXDR_STRING_SEVERITY = {
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

# Cortex XDR incident.status / alert.resolution_status -> Faraday status.
# ``new`` / ``under_investigation`` map onto Faraday ``open`` (the
# incident is still active).  ``resolved_threat_handled`` /
# ``resolved_known_issue`` / ``resolved_other`` map onto Faraday
# ``closed`` (the analyst neutralised the threat).  ``resolved_false_positive``
# / ``resolved_security_testing`` / ``resolved_duplicate`` / ``resolved_auto``
# map onto Faraday ``risk-accepted`` (the analyst dispositioned the
# alert as a non-issue).
CXDR_STATUS = {
    "new": "open",
    "under_investigation": "open",
    "underinvestigation": "open",
    "open": "open",
    "active": "open",
    "in_progress": "open",
    "inprogress": "open",
    "reopened": "open",
    "todo": "open",
    "resolved_threat_handled": "closed",
    "resolvedthreathandled": "closed",
    "resolved_known_issue": "closed",
    "resolvedknownissue": "closed",
    "resolved_other": "closed",
    "resolvedother": "closed",
    "resolved": "closed",
    "closed": "closed",
    "remediated": "closed",
    "fixed": "closed",
    "mitigated": "closed",
    "resolved_false_positive": "risk-accepted",
    "resolvedfalsepositive": "risk-accepted",
    "resolved_security_testing": "risk-accepted",
    "resolvedsecuritytesting": "risk-accepted",
    "resolved_duplicate": "risk-accepted",
    "resolvedduplicate": "risk-accepted",
    "resolved_auto": "risk-accepted",
    "resolvedauto": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "fp": "risk-accepted",
    "dismissed": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
}

# Canonical Cortex XDR incident status enum (validated against
# CXDR_INCIDENT_STATUS); aliases collapse onto the canonical names so
# operator-friendly inputs like `open` / `closed` are accepted.
CXDR_INCIDENT_STATUS_ENUM = (
    "new",
    "under_investigation",
    "resolved_threat_handled",
    "resolved_known_issue",
    "resolved_duplicate",
    "resolved_false_positive",
    "resolved_auto",
    "resolved_other",
    "resolved_security_testing",
)

CXDR_STATUS_ALIASES = {
    "open": ["new", "under_investigation"],
    "active": ["new", "under_investigation"],
    "inprogress": ["under_investigation"],
    "in_progress": ["under_investigation"],
    "closed": [
        "resolved_threat_handled",
        "resolved_known_issue",
        "resolved_duplicate",
        "resolved_false_positive",
        "resolved_auto",
        "resolved_other",
        "resolved_security_testing",
    ],
    "resolved": [
        "resolved_threat_handled",
        "resolved_known_issue",
        "resolved_duplicate",
        "resolved_false_positive",
        "resolved_auto",
        "resolved_other",
        "resolved_security_testing",
    ],
    "false_positive": ["resolved_false_positive"],
    "falsepositive": ["resolved_false_positive"],
    "fp": ["resolved_false_positive"],
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(f"{datetime.utcnow()} - Cortex XDR: {msg}", file=sys.stderr, flush=True)


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


def severity_from_numeric(value):
    """Map a Cortex XDR 1..5 severity enum to a Faraday bucket."""
    if isinstance(value, bool):
        return None
    try:
        as_int = int(value)
    except (TypeError, ValueError):
        return None
    return CXDR_SEVERITY_NUM.get(as_int)


def severity_from_string(value):
    """Map a Cortex XDR string severity label to a Faraday bucket."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().lower()
    if text in CXDR_STRING_SEVERITY:
        return CXDR_STRING_SEVERITY[text]
    return None


def severity_from_cortex(item, cvss=None):
    """Map a Cortex XDR incident / alert payload to a Faraday severity.

    Walks the numeric ``severity`` enum first (the canonical Cortex
    XDR signal — both incidents and alerts stamp severity as int),
    then the string ``severity`` field, then ``manual_severity``
    (operator-overridden), then a CVSS fallback when nothing else
    lands.
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            bucket = severity_from_string(item)
            if bucket is not None:
                return bucket
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    for key in ("severity", "Severity", "severity_level"):
        raw = item.get(key)
        if raw is not None and not isinstance(raw, bool):
            bucket = severity_from_numeric(raw)
            if bucket is not None:
                return bucket
        if isinstance(raw, str):
            bucket = severity_from_string(raw)
            if bucket is not None:
                return bucket

    for key in ("manual_severity", "manualSeverity"):
        raw = item.get(key)
        if raw is not None and not isinstance(raw, bool):
            bucket = severity_from_numeric(raw)
            if bucket is not None:
                return bucket
        if isinstance(raw, str):
            bucket = severity_from_string(raw)
            if bucket is not None:
                return bucket

    # Aggregated severity on incident shapes that summarise alerts.
    aggregate = item.get("aggregated_score") or item.get("score")
    if aggregate is not None and not isinstance(aggregate, bool):
        bucket = severity_from_numeric(aggregate)
        if bucket is not None:
            return bucket

    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_cortex(item):
    """Map a Cortex XDR incident / alert payload to a Faraday status.

    Walks ``status`` first (canonical incident lifecycle), then
    ``resolution_status`` (alert-side equivalent), then ``state`` /
    ``alert_status`` alt-keys.  Defaults to ``open`` so the dispatcher
    does not silently drop an incident when Cortex XDR reports an
    unmapped status.
    """
    if not isinstance(item, dict):
        return "open"
    for key in (
        "status",
        "Status",
        "resolution_status",
        "resolutionStatus",
        "state",
        "State",
        "alert_status",
        "alertStatus",
        "incident_status",
        "incidentStatus",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in CXDR_STATUS:
                return CXDR_STATUS[compact]
            if squashed in CXDR_STATUS:
                return CXDR_STATUS[squashed]
    return "open"


def validate_min_severity(value):
    """Validate CXDR_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus Cortex XDR-side synonyms
    plus the numeric 1..4 enum.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = CXDR_STRING_SEVERITY.get(text)
    if bucket is None:
        try:
            bucket = severity_from_numeric(int(float(text)))
        except (TypeError, ValueError):
            bucket = None
    if bucket is None:
        log(f"CXDR_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_incident_status(value):
    """Validate CXDR_INCIDENT_STATUS (CSV of incident status enum values).

    None / blank -> ``[]`` (no filter applied).  Accepts the canonical
    Cortex XDR status enum (new / under_investigation /
    resolved_threat_handled / resolved_known_issue / resolved_duplicate
    / resolved_false_positive / resolved_auto / resolved_other /
    resolved_security_testing) plus operator-friendly aliases (open /
    closed / active / resolved / false_positive).  Returns a dedup'd
    list of canonical status enum names preserving input order.
    """
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        raw_parts = [str(p) for p in value]
    else:
        raw_parts = str(value).split(",")
    out = []
    seen = set()
    for part in raw_parts:
        if not isinstance(part, str):
            continue
        text = part.strip().lower().replace(" ", "_").replace("-", "_")
        if not text:
            continue
        canonical = None
        if text in CXDR_INCIDENT_STATUS_ENUM:
            canonical = [text]
        elif text in CXDR_STATUS_ALIASES:
            canonical = list(CXDR_STATUS_ALIASES[text])
        else:
            # Unknown / custom status — accept verbatim and forward to
            # Cortex XDR (some federated tenants register custom status
            # values).  Cortex XDR will error server-side if the value
            # is not valid.
            log(f"CXDR_INCIDENT_STATUS '{part}' is not canonical; forwarding verbatim")
            canonical = [text]
        for status in canonical:
            if status in seen:
                continue
            seen.add(status)
            out.append(status)
    return out


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def severity_numeric_floor(min_severity):
    """Return the Cortex XDR numeric floor for the Faraday min_severity.

    Used to populate the ``request_data.filters`` server-side severity
    floor on the incidents / alerts surfaces so Cortex XDR does the
    bulk of the filtering before the result reaches the dispatcher.
    """
    return {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        min_severity,
        1,
    )


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on the CXDR host."""
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def build_incidents_url(host):
    base = normalize_base_url(host)
    return f"{base}/public_api/v1/incidents/get_incidents/"


def build_endpoints_url(host):
    base = normalize_base_url(host)
    return f"{base}/public_api/v1/endpoints/get_endpoints/"


def build_alerts_url(host):
    base = normalize_base_url(host)
    return f"{base}/public_api/v1/alerts/get_alerts_multi_events"


def auth_headers(api_key_id, api_key):
    """Cortex XDR REST surfaces expect ``Authorization`` + ``x-xdr-auth-id``."""
    return {
        "Authorization": str(api_key),
        "x-xdr-auth-id": str(api_key_id),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def build_request_body(search_from=0, search_to=None, filters=None, sort=None):
    """Build a Cortex XDR ``request_data`` body envelope.

    All three Cortex XDR surfaces (incidents / endpoints / alerts)
    share the same request body shape — ``request_data`` carries the
    ``filters`` array, ``search_from`` / ``search_to`` integer cursor
    pagination and an optional ``sort`` dict.
    """
    if search_to is None:
        search_to = int(search_from) + PAGE_SIZE
    body = {
        "request_data": {
            "search_from": int(search_from),
            "search_to": int(search_to),
        }
    }
    if filters:
        body["request_data"]["filters"] = filters
    if sort:
        body["request_data"]["sort"] = sort
    return body


def build_incidents_filters(min_severity_floor=1, statuses=None):
    """Build the Cortex XDR incidents.get_incidents filters array.

    ``min_severity_floor`` is the Cortex XDR 1..4 numeric floor (see
    ``severity_numeric_floor``).  ``statuses`` is a list of canonical
    Cortex XDR status enum values (see ``validate_incident_status``).
    """
    filters = []
    if isinstance(min_severity_floor, int) and min_severity_floor > 1:
        # Cortex XDR uses string-valued severity filter levels:
        # ``low`` / ``medium`` / ``high`` / ``critical``.
        floor_names = []
        if min_severity_floor <= 1:
            floor_names = ["low", "medium", "high", "critical"]
        elif min_severity_floor == 2:
            floor_names = ["medium", "high", "critical"]
        elif min_severity_floor == 3:
            floor_names = ["high", "critical"]
        else:
            floor_names = ["critical"]
        filters.append(
            {
                "field": "severity",
                "operator": "in",
                "value": floor_names,
            }
        )
    if statuses:
        filters.append(
            {
                "field": "status",
                "operator": "in",
                "value": list(statuses),
            }
        )
    return filters


def extract_items(payload, *keys):
    """Pull the result list out of a Cortex XDR response envelope.

    Cortex XDR wraps everything under ``reply``; the inner list key
    varies per surface (``incidents`` / ``endpoints`` / ``alerts``).
    Walk every supplied key defensively, plus common alt-keys.
    """
    if not isinstance(payload, dict):
        return []
    reply = payload.get("reply")
    candidates = list(keys) + ["incidents", "endpoints", "alerts", "items", "results", "data"]
    if isinstance(reply, dict):
        for key in candidates:
            v = reply.get(key)
            if isinstance(v, list):
                return v
    elif isinstance(reply, list):
        return reply
    for key in candidates:
        v = payload.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_total(payload):
    """Pull total_count / result_count from a Cortex XDR response envelope."""
    if not isinstance(payload, dict):
        return None
    reply = payload.get("reply")
    if isinstance(reply, dict):
        for key in ("total_count", "totalCount", "result_count", "resultCount"):
            v = reply.get(key)
            if isinstance(v, int):
                return v
    for key in ("total_count", "totalCount", "result_count", "resultCount"):
        v = payload.get(key)
        if isinstance(v, int):
            return v
    return None


def cvss_score(item):
    """Pull a numeric CVSS score from a Cortex XDR payload.

    Cortex XDR does not natively stamp CVSS on incidents / alerts but
    re-emitted shapes (e.g. via XSOAR playbook enrichment) sometimes
    fold a CVSS block in; walk every common surface defensively.
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
    """Pull CVE-* ids out of a Cortex XDR incident / alert payload.

    Cortex XDR does not stamp a dedicated CVE list on incidents /
    alerts; the CVE typically appears in the alert description /
    module_id / detection_module_name or in the incident's
    manual_description / description.  Walk every common surface
    defensively.
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
        "manual_description",
        "manualDescription",
        "alert_name",
        "alertName",
        "alert_description",
        "alertDescription",
        "module_id",
        "moduleID",
        "detection_module_name",
        "detectionModuleName",
        "title",
        "reason",
        "source",
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
    """Walk a Cortex XDR incident / alert for advisory pivots.

    Surfaces Cortex XDR-side pivots (``CXDR-Incident: {id}``,
    ``CXDR-Alert: {id}``, ``CXDR-Category: {name}``,
    ``CXDR-AlertCategory: {name}``, ``CXDR-Source: {source}``,
    ``CXDR-AlertSource: {source}``, ``CXDR-DetectionModule: {name}``,
    ``CXDR-Action: {action}``, ``CXDR-Host: {hostname}``,
    ``CXDR-User: {user}``, ``CXDR-CausalityActor: {process}``,
    ``CXDR-Endpoint: {endpoint_id}``, ``CXDR-EndpointGroup: {group}``,
    ``CXDR-OS: {os_type}``) plus MITRE-Tactic / MITRE-Technique
    pivots from the incident's mitre_tactics_ids_and_names /
    mitre_techniques_ids_and_names arrays and any inline URLs.
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

    incident_id = item.get("incident_id") or item.get("incidentId")
    if incident_id is not None and not isinstance(incident_id, bool):
        add(f"CXDR-Incident: {incident_id}")

    alert_id = item.get("alert_id") or item.get("alertId")
    if alert_id is not None and not isinstance(alert_id, bool):
        add(f"CXDR-Alert: {alert_id}")

    for key, label_key in (
        ("category", "CXDR-Category"),
        ("alert_category", "CXDR-AlertCategory"),
        ("alertCategory", "CXDR-AlertCategory"),
        ("source", "CXDR-Source"),
        ("alert_source", "CXDR-AlertSource"),
        ("alertSource", "CXDR-AlertSource"),
        ("detection_module_name", "CXDR-DetectionModule"),
        ("detectionModuleName", "CXDR-DetectionModule"),
        ("module_id", "CXDR-DetectionModule"),
        ("moduleID", "CXDR-DetectionModule"),
        ("action", "CXDR-Action"),
        ("action_pretty", "CXDR-Action"),
        ("actionPretty", "CXDR-Action"),
        ("host_name", "CXDR-Host"),
        ("hostName", "CXDR-Host"),
        ("user_name", "CXDR-User"),
        ("userName", "CXDR-User"),
        ("causality_actor_process_image_name", "CXDR-CausalityActor"),
        ("causalityActorProcessImageName", "CXDR-CausalityActor"),
        ("endpoint_id", "CXDR-Endpoint"),
        ("endpointId", "CXDR-Endpoint"),
        ("group_name", "CXDR-EndpointGroup"),
        ("groupName", "CXDR-EndpointGroup"),
        ("os_type", "CXDR-OS"),
        ("osType", "CXDR-OS"),
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            add(f"{label_key}: {v.strip()}")
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            add(f"{label_key}: {v}")
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    add(f"{label_key}: {entry.strip()}")
                elif isinstance(entry, dict):
                    name = entry.get("name") or entry.get("value") or entry.get("id")
                    if isinstance(name, str) and name.strip():
                        add(f"{label_key}: {name.strip()}")

    # alert_categories is an array on incidents.
    cats = item.get("alert_categories") or item.get("alertCategories")
    if isinstance(cats, list):
        for cat in cats:
            if isinstance(cat, str) and cat.strip():
                add(f"CXDR-AlertCategory: {cat.strip()}")
            elif isinstance(cat, dict):
                name = cat.get("name") or cat.get("value")
                if isinstance(name, str) and name.strip():
                    add(f"CXDR-AlertCategory: {name.strip()}")

    # MITRE tactics / techniques.  Cortex XDR stamps both as either
    # bare-string arrays or as "{tactic_id} - {tactic_name}" composite
    # strings, plus the alert-side carries them as separate id / name
    # arrays.
    for key, label_key in (
        ("mitre_tactics_ids_and_names", "MITRE-Tactic"),
        ("mitreTacticIdsAndNames", "MITRE-Tactic"),
        ("mitre_tactic_ids_and_names", "MITRE-Tactic"),
        ("mitre_tactic_id_and_name", "MITRE-Tactic"),
        ("mitreTacticIdAndName", "MITRE-Tactic"),
        ("mitre_tactics", "MITRE-Tactic"),
        ("mitreTactics", "MITRE-Tactic"),
        ("mitre_techniques_ids_and_names", "MITRE-Technique"),
        ("mitreTechniqueIdsAndNames", "MITRE-Technique"),
        ("mitre_technique_ids_and_names", "MITRE-Technique"),
        ("mitre_technique_id_and_name", "MITRE-Technique"),
        ("mitreTechniqueIdAndName", "MITRE-Technique"),
        ("mitre_techniques", "MITRE-Technique"),
        ("mitreTechniques", "MITRE-Technique"),
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            add(f"{label_key}: {v.strip()}")
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    add(f"{label_key}: {entry.strip()}")
                elif isinstance(entry, dict):
                    name = entry.get("name") or entry.get("value") or entry.get("id")
                    if isinstance(name, str) and name.strip():
                        add(f"{label_key}: {name.strip()}")

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


def endpoint_label(endpoint):
    """Build a friendly label for a Cortex XDR endpoint record."""
    if not isinstance(endpoint, dict):
        return ""
    for key in (
        "endpoint_name",
        "endpointName",
        "host_name",
        "hostName",
        "hostname",
        "name",
        "Name",
        "fqdn",
    ):
        v = endpoint.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("endpoint_id", "endpointId", "id", "Id"):
        v = endpoint.get(key)
        if v is not None and not isinstance(v, bool):
            s = str(v).strip()
            if s:
                return s
    return ""


def incident_label(item):
    """Build the leading title fragment for a Cortex XDR incident."""
    if not isinstance(item, dict):
        return ""
    for key in ("description", "Description", "manual_description", "manualDescription", "name", "Name"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    incident_id = item.get("incident_id") or item.get("incidentId")
    if incident_id is not None and not isinstance(incident_id, bool):
        return f"Incident {incident_id}"
    return "Cortex XDR incident"


def alert_label(item):
    """Build the leading title fragment for a Cortex XDR alert."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "name",
        "Name",
        "alert_name",
        "alertName",
        "description",
        "Description",
        "alert_description",
        "alertDescription",
        "source",
        "Source",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    alert_id = item.get("alert_id") or item.get("alertId")
    if alert_id is not None and not isinstance(alert_id, bool):
        return f"Alert {alert_id}"
    return "Cortex XDR alert"


def host_bucket_key(item):
    """Pick a stable bucket key for a Cortex XDR endpoint / incident / alert."""
    if not isinstance(item, dict):
        return "__unknown__"
    for key in ("endpoint_id", "endpointId", "id", "Id", "agent_id", "agentId"):
        v = item.get(key)
        if v is None or isinstance(v, bool):
            continue
        s = str(v).strip()
        if s:
            return s
    for key in ("host_name", "hostName", "endpoint_name", "endpointName"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "__unknown__"


def host_ip(item):
    """Pick the host IP from a Cortex XDR endpoint record.

    Cortex XDR surfaces ``ip`` as an array (IPv4) plus ``ip_v6`` as an
    array (IPv6).  Falls back to synthetic ``0.0.0.0`` because Cortex
    XDR-managed mobile / VDI endpoints often only carry private
    addresses (loopback ``127.0.0.1`` and ``0.0.0.0`` are explicitly
    skipped).
    """
    if not isinstance(item, dict):
        return "0.0.0.0"
    for key in ("ip", "ip_addresses", "ipAddresses"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip() and entry.strip() not in ("0.0.0.0", "127.0.0.1"):
                    return entry.strip()
        elif isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1"):
            return v.strip()
    for key in ("ip_v6", "ipV6", "ipv6"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip() and entry.strip() not in ("::1", "::"):
                    return entry.strip()
        elif isinstance(v, str) and v.strip() and v.strip() not in ("::1", "::"):
            return v.strip()
    return "0.0.0.0"


def host_mac(item):
    if not isinstance(item, dict):
        return ""
    for key in ("mac_address", "macAddress", "mac"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("mac_addresses", "macAddresses"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    return entry.strip()
    return ""


def host_os(item):
    if not isinstance(item, dict):
        return ""
    os_type = item.get("os_type") or item.get("osType")
    os_version = item.get("os_version") or item.get("osVersion")
    if isinstance(os_type, str) and os_type.strip():
        if isinstance(os_version, str) and os_version.strip():
            return f"{os_type.strip()} {os_version.strip()}"
        return os_type.strip()
    if isinstance(os_version, str) and os_version.strip():
        return os_version.strip()
    return ""


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


def build_incident_vulnerability(incident, endpoint_lookup=None):
    """Build a Faraday vulnerability dict from a Cortex XDR incident."""
    if not isinstance(incident, dict):
        return None

    score = cvss_score(incident)
    severity = severity_from_cortex(incident, cvss=score)
    status = status_from_cortex(incident)

    label = incident_label(incident)
    name = f"[EDR] {label}" if label else "[EDR] Cortex XDR incident"

    desc_parts = []
    description = (
        incident.get("description")
        or incident.get("Description")
        or incident.get("manual_description")
        or incident.get("manualDescription")
    )
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    for label_key, key in (
        ("incident_id", "incident_id"),
        ("incident_name", "incident_name"),
        ("incident_sources", "incident_sources"),
        ("severity_raw", "severity"),
        ("manual_severity", "manual_severity"),
        ("status_raw", "status"),
        ("assigned_user_mail", "assigned_user_mail"),
        ("assigned_user_pretty_name", "assigned_user_pretty_name"),
        ("alert_count", "alert_count"),
        ("low_severity_alert_count", "low_severity_alert_count"),
        ("med_severity_alert_count", "med_severity_alert_count"),
        ("high_severity_alert_count", "high_severity_alert_count"),
        ("critical_severity_alert_count", "critical_severity_alert_count"),
        ("user_count", "user_count"),
        ("host_count", "host_count"),
        ("notes", "notes"),
        ("resolve_comment", "resolve_comment"),
        ("creation_time", "creation_time"),
        ("modification_time", "modification_time"),
        ("detection_time", "detection_time"),
        ("starred", "starred"),
        ("xdr_url", "xdr_url"),
        ("rule_based_score", "rule_based_score"),
        ("predicted_score", "predicted_score"),
        ("aggregated_score", "aggregated_score"),
        ("alerts_grouping_status", "alerts_grouping_status"),
        ("wildfire_hits", "wildfire_hits"),
        ("alert_categories", "alert_categories"),
        ("mitre_tactics_ids_and_names", "mitre_tactics_ids_and_names"),
        ("mitre_techniques_ids_and_names", "mitre_techniques_ids_and_names"),
    ):
        v = incident.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(incident)
    if vector:
        desc_parts.append(f"vector: {vector}")

    # Endpoint enrichment — surface the first 5 affected endpoints from
    # the incident's hosts array (Cortex XDR stamps the affected
    # endpoint ids on incident.hosts).
    if isinstance(endpoint_lookup, dict):
        hosts = incident.get("hosts") or incident.get("host_ids") or []
        if isinstance(hosts, list):
            for host_ref in hosts[:5]:
                ep_id = None
                if isinstance(host_ref, str):
                    ep_id = host_ref.strip()
                elif isinstance(host_ref, dict):
                    ep_id = host_ref.get("endpoint_id") or host_ref.get("id")
                if ep_id:
                    ep = endpoint_lookup.get(str(ep_id))
                    if isinstance(ep, dict):
                        for label_key, key in (
                            ("endpoint_endpoint_name", "endpoint_name"),
                            ("endpoint_endpoint_type", "endpoint_type"),
                            ("endpoint_os_type", "os_type"),
                            ("endpoint_os_version", "os_version"),
                            ("endpoint_agent_version", "agent_version"),
                            ("endpoint_group_name", "group_name"),
                            ("endpoint_isolate_status", "isolate_status"),
                            ("endpoint_scan_status", "scan_status"),
                            ("endpoint_first_seen", "first_seen"),
                            ("endpoint_last_seen", "last_seen"),
                            ("endpoint_users", "users"),
                            ("endpoint_domain", "domain"),
                        ):
                            v = ep.get(key)
                            if v not in (None, ""):
                                desc_parts.append(f"{label_key}: {v}")

    cves = collect_cves(incident)
    refs = collect_refs(incident)

    resolution = ""
    rem = (
        incident.get("remediation")
        or incident.get("Remediation")
        or incident.get("remediationDescription")
        or incident.get("resolve_comment")
    )
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution:
        resolution = (
            "Investigate the incident in the Palo Alto Cortex XDR console "
            "(Incidents -> select incident -> Investigation) and decide a "
            "disposition (true positive -> remediate via the response action "
            "panel and resolve as resolved_threat_handled; false positive -> "
            "resolve as resolved_false_positive and tune the detection rule "
            "if it is a recurring false positive)."
        )

    external_id = str(incident.get("incident_id") or incident.get("incidentId") or "")

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Cortex XDR incident {external_id}",
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
        "tags": ["cortex_xdr", "edr", "endpoint-edr"],
    }


def build_alert_vulnerability(alert, endpoint_lookup=None):
    """Build a Faraday vulnerability dict from a Cortex XDR alert."""
    if not isinstance(alert, dict):
        return None

    score = cvss_score(alert)
    severity = severity_from_cortex(alert, cvss=score)
    status = status_from_cortex(alert)

    label = alert_label(alert)
    name = f"[EDR] {label}" if label else "[EDR] Cortex XDR alert"

    desc_parts = []
    description = (
        alert.get("description")
        or alert.get("Description")
        or alert.get("alert_description")
        or alert.get("alertDescription")
    )
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    for label_key, key in (
        ("alert_id", "alert_id"),
        ("incident_id", "incident_id"),
        ("name", "name"),
        ("category", "category"),
        ("source", "source"),
        ("severity_raw", "severity"),
        ("action", "action"),
        ("action_pretty", "action_pretty"),
        ("action_country", "action_country"),
        ("action_external_hostname", "action_external_hostname"),
        ("action_local_ip", "action_local_ip"),
        ("action_local_port", "action_local_port"),
        ("action_remote_ip", "action_remote_ip"),
        ("action_remote_port", "action_remote_port"),
        ("action_process_image_name", "action_process_image_name"),
        ("action_process_image_command_line", "action_process_image_command_line"),
        ("action_process_image_sha256", "action_process_image_sha256"),
        ("actor_process_image_name", "actor_process_image_name"),
        ("actor_process_command_line", "actor_process_command_line"),
        ("actor_process_image_sha256", "actor_process_image_sha256"),
        ("causality_actor_process_image_name", "causality_actor_process_image_name"),
        ("causality_actor_process_command_line", "causality_actor_process_command_line"),
        ("causality_actor_process_image_sha256", "causality_actor_process_image_sha256"),
        ("os_actor_process_image_name", "os_actor_process_image_name"),
        ("os_actor_process_command_line", "os_actor_process_command_line"),
        ("os_actor_process_image_sha256", "os_actor_process_image_sha256"),
        ("target_process_image_name", "target_process_image_name"),
        ("target_process_command_line", "target_process_command_line"),
        ("host_ip", "host_ip"),
        ("host_name", "host_name"),
        ("user_name", "user_name"),
        ("endpoint_id", "endpoint_id"),
        ("agent_id", "agent_id"),
        ("agent_version", "agent_version"),
        ("agent_os_type", "agent_os_type"),
        ("agent_os_sub_type", "agent_os_sub_type"),
        ("agent_data_collection_status", "agent_data_collection_status"),
        ("module_id", "module_id"),
        ("detection_module_name", "detection_module_name"),
        ("alert_type", "alert_type"),
        ("alert_sub_type", "alert_sub_type"),
        ("matching_status", "matching_status"),
        ("matching_service_rule_id", "matching_service_rule_id"),
        ("event_type", "event_type"),
        ("event_sub_type", "event_sub_type"),
        ("event_timestamp", "event_timestamp"),
        ("detection_timestamp", "detection_timestamp"),
        ("starred", "starred"),
        ("xdr_url", "xdr_url"),
        ("mitre_tactic_id_and_name", "mitre_tactic_id_and_name"),
        ("mitre_technique_id_and_name", "mitre_technique_id_and_name"),
        ("association_strength", "association_strength"),
    ):
        v = alert.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(alert)
    if vector:
        desc_parts.append(f"vector: {vector}")

    if isinstance(endpoint_lookup, dict):
        ep_id = alert.get("endpoint_id") or alert.get("endpointId") or alert.get("agent_id")
        if ep_id is not None:
            ep = endpoint_lookup.get(str(ep_id))
            if isinstance(ep, dict):
                for label_key, key in (
                    ("endpoint_endpoint_name", "endpoint_name"),
                    ("endpoint_endpoint_type", "endpoint_type"),
                    ("endpoint_os_type", "os_type"),
                    ("endpoint_os_version", "os_version"),
                    ("endpoint_agent_version", "agent_version"),
                    ("endpoint_group_name", "group_name"),
                    ("endpoint_isolate_status", "isolate_status"),
                    ("endpoint_scan_status", "scan_status"),
                ):
                    v = ep.get(key)
                    if v not in (None, ""):
                        desc_parts.append(f"{label_key}: {v}")

    cves = collect_cves(alert)
    refs = collect_refs(alert)

    resolution = ""
    rem = alert.get("remediation") or alert.get("Remediation")
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution:
        action = alert.get("action_pretty") or alert.get("action")
        if isinstance(action, str) and action.strip():
            resolution = (
                f"Cortex XDR action: {action.strip()}. "
                "Confirm the disposition in the Cortex XDR console "
                "(Alerts -> select alert -> Investigation) and tune "
                "the detection rule if the action was incorrect."
            )
    if not resolution:
        resolution = (
            "Investigate the alert in the Palo Alto Cortex XDR console "
            "(Alerts -> select alert -> Investigation) and decide a "
            "disposition (true positive -> remediate via the response "
            "action panel; false positive -> resolve and tune the "
            "detection rule)."
        )

    external_id = str(alert.get("alert_id") or alert.get("alertId") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Cortex XDR alert {external_id}",
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
        "tags": ["cortex_xdr", "edr", "endpoint-edr"],
    }


def build_host(bucket_key, sample_endpoint, vulns):
    """Build a Faraday host record for the supplied endpoint bucket."""
    sample = sample_endpoint if isinstance(sample_endpoint, dict) else {}
    label = endpoint_label(sample) if sample else ""
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
        desc_parts.append(f"endpoint_id={bucket_key}")

    if isinstance(sample, dict):
        for label_key, key in (
            ("endpoint_name", "endpoint_name"),
            ("endpoint_type", "endpoint_type"),
            ("endpoint_status", "endpoint_status"),
            ("os_type", "os_type"),
            ("os_version", "os_version"),
            ("agent_version", "agent_version"),
            ("group_name", "group_name"),
            ("first_seen", "first_seen"),
            ("last_seen", "last_seen"),
            ("isolate_status", "isolate_status"),
            ("scan_status", "scan_status"),
            ("domain", "domain"),
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


def fetch_pages(requests_module, url, headers, build_body, list_keys=(), verify=True):
    """Walk a Cortex XDR surface with search_from / search_to pagination.

    ``build_body`` is a callable ``(search_from, search_to) -> body`` so
    each surface can fold its own filters / sort into the request body.
    """
    out = []
    cursor = 0
    pages = 0
    while pages < MAX_PAGES:
        body = build_body(cursor, cursor + PAGE_SIZE)
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
            log("Cortex XDR request rejected (401). Check CXDR_API_KEY_ID + CXDR_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"Cortex XDR request rejected (403). API key role lacks access to {url}")
            return out
        if resp.status_code == 404:
            log(f"Cortex XDR request 404 for {url} — endpoint not found")
            return out
        if resp.status_code >= 400:
            log(f"Cortex XDR request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Cortex XDR response was not JSON ({url})")
            return out
        items = extract_items(payload, *list_keys)
        if not items:
            break
        for entry in items:
            if isinstance(entry, dict):
                out.append(entry)
        if len(items) < PAGE_SIZE:
            break
        cursor += PAGE_SIZE
        pages += 1
        total = extract_total(payload)
        if isinstance(total, int) and cursor >= total:
            break
    if pages >= MAX_PAGES:
        log(f"hit MAX_PAGES={MAX_PAGES}; stopping pagination on {url}")
    return out


def main():
    started = time.time()

    host = env("CXDR_HOST", required=True)
    api_key_id = env("CXDR_API_KEY_ID", required=True)
    api_key = env("CXDR_API_KEY", required=True)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_CXDR_MIN_SEVERITY"))
    incident_statuses = validate_incident_status(env("EXECUTOR_CONFIG_CXDR_INCIDENT_STATUS"))
    allowed_severities = set(severities_at_or_above(min_severity))
    severity_floor = severity_numeric_floor(min_severity)

    verify_env = (os.getenv("CXDR_VERIFY_SSL") or "").strip().lower()
    verify = verify_env not in ("0", "false", "no", "off")

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(api_key_id, api_key)

    incidents_url = build_incidents_url(host)
    endpoints_url = build_endpoints_url(host)
    alerts_url = build_alerts_url(host)

    incident_filters = build_incidents_filters(
        min_severity_floor=severity_floor,
        statuses=incident_statuses,
    )
    incident_sort = {"field": "creation_time", "keyword": "desc"}

    def incidents_body(search_from, search_to):
        return build_request_body(
            search_from=search_from,
            search_to=search_to,
            filters=incident_filters,
            sort=incident_sort,
        )

    def endpoints_body(search_from, search_to):
        return build_request_body(search_from=search_from, search_to=search_to)

    def alerts_body(search_from, search_to):
        return build_request_body(
            search_from=search_from,
            search_to=search_to,
            filters=incident_filters[:1] if incident_filters else None,
            sort={"field": "creation_time", "keyword": "desc"},
        )

    incidents = fetch_pages(
        requests,
        incidents_url,
        headers,
        incidents_body,
        list_keys=("incidents",),
        verify=verify,
    )
    endpoints = fetch_pages(
        requests,
        endpoints_url,
        headers,
        endpoints_body,
        list_keys=("endpoints",),
        verify=verify,
    )
    alerts = fetch_pages(
        requests,
        alerts_url,
        headers,
        alerts_body,
        list_keys=("alerts",),
        verify=verify,
    )

    log(
        f"Processing {len(incidents)} Cortex XDR incidents + {len(endpoints)} endpoints + "
        f"{len(alerts)} alerts (min_severity={min_severity}, "
        f"incident_statuses={incident_statuses or 'all'})"
    )

    endpoint_lookup = {}
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        eid = ep.get("endpoint_id") or ep.get("endpointId") or ep.get("agent_id") or ep.get("id")
        if eid is not None and not isinstance(eid, bool):
            endpoint_lookup[str(eid)] = ep

    buckets = {eid: [] for eid in endpoint_lookup}

    # Incidents: fan out per affected endpoint.  Cortex XDR stamps the
    # affected endpoint ids on incident.hosts (an array).
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        vuln = build_incident_vulnerability(incident, endpoint_lookup=endpoint_lookup)
        if vuln is None:
            continue
        if allowed_severities and vuln["severity"] not in allowed_severities:
            continue
        hosts_ref = incident.get("hosts") or incident.get("host_ids") or []
        ep_ids = []
        if isinstance(hosts_ref, list):
            for host_ref in hosts_ref:
                if isinstance(host_ref, str):
                    ep_ids.append(host_ref.strip())
                elif isinstance(host_ref, dict):
                    eid = host_ref.get("endpoint_id") or host_ref.get("id")
                    if eid:
                        ep_ids.append(str(eid))
        if not ep_ids:
            ep_ids = ["__unknown__"]
        for ep_id in ep_ids:
            buckets.setdefault(ep_id, [])
            buckets[ep_id].append(vuln)

    # Alerts: fan out per endpoint_id.
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        vuln = build_alert_vulnerability(alert, endpoint_lookup=endpoint_lookup)
        if vuln is None:
            continue
        if allowed_severities and vuln["severity"] not in allowed_severities:
            continue
        ep_id = alert.get("endpoint_id") or alert.get("endpointId") or alert.get("agent_id")
        bucket_key = str(ep_id) if ep_id else "__unknown__"
        buckets.setdefault(bucket_key, [])
        buckets[bucket_key].append(vuln)

    hosts = []
    for key, vulns in buckets.items():
        sample = endpoint_lookup.get(key) if key != "__unknown__" else {}
        hosts.append(build_host(key, sample, vulns))

    params_bits = [f"min_severity={min_severity}"]
    if incident_statuses:
        params_bits.append(f"incident_statuses={','.join(incident_statuses)}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "cortex_xdr",
            "command": "cortex_xdr",
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
