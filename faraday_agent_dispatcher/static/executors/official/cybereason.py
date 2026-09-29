#!/usr/bin/env python
"""Cybereason Defense Platform REST importer.

Pulls Malops, sensor inventory and per-malop process evidence from a
Cybereason on-prem or hosted EDR tenant. Emits Faraday bulk-create JSON
to stdout. Each Cybereason sensor becomes one Faraday host (``ip`` =
the first non-loopback ``internalIpAddress`` / ``externalIpAddress``
from the sensor record, falling back to a synthetic ``0.0.0.0``);
Malops attach as Faraday vulnerabilities — one per Malop GUID with
engine prefix ``[EDR]``.

Endpoints used:
  POST {CR_HOST}/login.html
      -> form-encoded ``username=<u>&password=<p>`` login.  Cybereason
      returns a ``JSESSIONID`` cookie that has to be carried on every
      subsequent /rest/ call (the platform's cookie-based session model;
      there is no API key or bearer token surface today).
  POST {CR_HOST}/rest/crimes/unified
      -> Malop search.  POST body carries a ``queryPath`` (the Malop
      type filter — MalopProcess / MalopLogon / MalopFileless /
      MalopMobileApp etc.) plus pagination caps and the result template
      context.  Response shape is the nested envelope
      ``{"data": {"resultIdToElementDataMap": {malopId: {...}}}}``
      where each entry exposes ``simpleValues`` (severity / priority /
      status / decisionFeature / detectionType / activityTypes /
      creationTime / lastUpdateTime / machineCount / userCount /
      affectedUsers) plus ``elementValues`` (affectedMachines,
      rootCauseElements with process / file / actor metadata).
  POST {CR_HOST}/rest/sensors/query
      -> paginated sensor (endpoint) inventory.  POST body carries
      ``limit`` + ``offset`` pagination and an optional ``filters``
      array; response shape is ``{"sensors": [...]}`` with each entry
      exposing sensorId / machineName / internalIpAddress /
      externalIpAddress / osType / osVersionType / status / policyName /
      groupName / siteName / lastPylumInfoMsgUpdateTime etc.  Used to
      enrich the host record with sensor metadata and to surface
      sensors with no Malops as inventory-only hosts.
  POST {CR_HOST}/rest/visualsearch/query/simple
      -> per-Malop process evidence search.  POST body carries a
      ``queryPath`` referencing the Malop GUID + a process-type filter;
      response shape mirrors /rest/crimes/unified.  Optional — gated
      by CR_INCLUDE_PROCESS_EVIDENCE so operators can disable the
      extra round-trips on large tenants where the malop catalogue
      already carries the rootCauseElements summary.

Auth: Cybereason uses a session-cookie login flow rooted at /login.html.
The dispatcher carries the operator's user + password as ``CR_USER`` /
``CR_PASSWORD`` (a dedicated `read-only` Cybereason analyst / API user
created in the console: System -> Users -> add user with the
`Responder L1` role granted at the global scope is the minimal posture).
``CR_HOST`` is the tenant's UI host (e.g. ``https://acme.cybereason.net``
for the hosted service or ``https://defense.acme.corp:8443`` for on-prem).
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
PAGE_SIZE = 1000
MALOP_RESULT_LIMIT = 10000

# Cybereason severity surfaces.  The platform historically surfaces only
# LOW / MEDIUM / HIGH (the Malop "severity" column on the Defense
# Platform UI) plus a 1-3 numeric ``malopPriority`` on some shapes.
# Newer versions surface CRITICAL on Mobile Threat Defense (MTD).
CR_STRING_SEVERITY = {
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

# Cybereason Malop status surfaces.  The platform exposes the lifecycle
# state through ``simpleValues.managementStatus`` (Active / Closed),
# ``simpleValues.malopStatus`` (UnderInvestigation / Remediated /
# FalsePositive / Open) plus a ``simpleValues.investigationStatus`` on
# the newer MTD shape.  Resolution decisions (FalsePositive / Muted /
# Excluded) collapse onto Faraday risk-accepted; investigations /
# Active malops collapse onto open; Remediated / Closed collapse onto
# closed.
CR_STATUS_BY_STATE = {
    "open": "open",
    "opened": "open",
    "active": "open",
    "new": "open",
    "todo": "open",
    "to_do": "open",
    "in_progress": "open",
    "inprogress": "open",
    "underinvestigation": "open",
    "under_investigation": "open",
    "investigating": "open",
    "pending": "open",
    "reopened": "open",
    "resolved": "closed",
    "remediated": "closed",
    "closed": "closed",
    "fixed": "closed",
    "done": "closed",
    "mitigated": "closed",
    "falsepositive": "risk-accepted",
    "false_positive": "risk-accepted",
    "fp": "risk-accepted",
    "muted": "risk-accepted",
    "suppressed": "risk-accepted",
    "excluded": "risk-accepted",
    "ignored": "risk-accepted",
    "dismissed": "risk-accepted",
    "wontfix": "risk-accepted",
    "won't_fix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
}

# Cybereason Malop "queryPath.requestedType" values.  The most common
# is MalopProcess (process tree malops), with MalopLogon / MalopFileless
# / MalopMobileApp / MalopMobileProcess covering the other vectors.
# Older versions also surface MalopMfileWeb / MalopFlash but those are
# accepted verbatim when supplied — Cybereason will error server-side
# if the type does not exist on the tenant.
VALID_MALOP_TYPES = (
    "MalopProcess",
    "MalopLogon",
    "MalopFileless",
    "MalopMobileApp",
    "MalopMobileProcess",
    "MalopMfileWeb",
    "MalopFlash",
    "MalopMTD",
)

DEFAULT_MALOP_TYPES = ("MalopProcess", "MalopLogon", "MalopFileless")


def log(msg):
    print(f"{datetime.utcnow()} - Cybereason: {msg}", file=sys.stderr, flush=True)


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


def severity_from_cr(value, cvss=None):
    """Map a Cybereason severity value to a Faraday bucket.

    Accepts the freeform string enum (HIGH / MEDIUM / LOW /
    INFORMATIONAL / CRITICAL), the 1-3 numeric ``malopPriority`` scale
    (1=low, 2=medium, 3=high) plus Faraday-side synonyms, and falls
    back to CVSS bucketing on ``cvss`` when the primary value is
    missing or unrecognised.
    """
    if isinstance(value, bool):
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"
    if isinstance(value, (int, float)):
        score = float(value)
        # Cybereason malopPriority is a 1-3 scale on most surfaces; we
        # also accept a 0-10 CVSS-style scale for forward compatibility.
        if score <= 0:
            return "info"
        if score <= 1:
            return "low"
        if score <= 2:
            return "medium"
        if score <= 3:
            return "high"
        if score < 4:
            return "low"
        if score < 7:
            return "medium"
        if score < 9:
            return "high"
        if score > 10:
            return "info"
        return "critical"
    if isinstance(value, str) and value.strip():
        text = value.strip().lower()
        if text in CR_STRING_SEVERITY:
            return CR_STRING_SEVERITY[text]
        try:
            return severity_from_cr(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def _walk_status_value(raw):
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    compact = text.lower().replace(" ", "_").replace("-", "_")
    squashed = compact.replace("_", "")
    if compact in CR_STATUS_BY_STATE:
        return CR_STATUS_BY_STATE[compact]
    if squashed in CR_STATUS_BY_STATE:
        return CR_STATUS_BY_STATE[squashed]
    return None


def status_from_cr(item):
    """Derive Faraday status from a Cybereason Malop payload.

    Walks ``simpleValues.managementStatus`` / ``simpleValues.malopStatus``
    first (the v21+ Defense Platform lifecycle fields), then falls back
    to top-level ``managementStatus`` / ``status`` / ``investigationStatus``
    keys for re-emitted shapes.
    """
    if not isinstance(item, dict):
        return "open"
    simple = item.get("simpleValues")
    if isinstance(simple, dict):
        for key in (
            "managementStatus",
            "malopStatus",
            "status",
            "investigationStatus",
            "decisionFeature",
            "manualStatus",
            "lifecycleStatus",
        ):
            raw = simple.get(key)
            if isinstance(raw, dict):
                values = raw.get("values")
                if isinstance(values, list):
                    for v in values:
                        if isinstance(v, str):
                            resolved = _walk_status_value(v)
                            if resolved:
                                return resolved
            elif isinstance(raw, list):
                for v in raw:
                    if isinstance(v, str):
                        resolved = _walk_status_value(v)
                        if resolved:
                            return resolved
            else:
                resolved = _walk_status_value(raw)
                if resolved:
                    return resolved
    for key in (
        "managementStatus",
        "malopStatus",
        "status",
        "state",
        "investigationStatus",
        "decisionFeature",
        "manualStatus",
    ):
        raw = item.get(key)
        resolved = _walk_status_value(raw)
        if resolved:
            return resolved
    return "open"


def validate_min_severity(value):
    """Validate CR_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied
    beyond the default). Accepts the canonical Faraday buckets plus
    Cybereason-side synonyms (informational, none, unspecified,
    unknown).
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = CR_STRING_SEVERITY.get(text)
    if bucket is None:
        try:
            bucket = severity_from_cr(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"CR_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_malop_type(value):
    """Validate CR_MALOP_TYPE (Cybereason Malop type filter).

    Accepts a single type or a CSV of types (MalopProcess / MalopLogon
    / MalopFileless / MalopMobileApp / MalopMobileProcess / MalopMTD).
    None / blank -> the default trio (MalopProcess + MalopLogon +
    MalopFileless) which is what the Cybereason Defense Platform UI
    queries by default. Unknown types are accepted verbatim — the
    Cybereason API will error server-side if the type does not exist
    on the tenant, and some on-prem federated stacks register custom
    malop types.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return list(DEFAULT_MALOP_TYPES)
    if isinstance(value, (list, tuple)):
        text_iter = [str(v) for v in value]
    else:
        text_iter = str(value).split(",")
    out = []
    seen = set()
    for entry in text_iter:
        s = entry.strip()
        if not s:
            continue
        canonical = None
        lowered = s.lower()
        for canon in VALID_MALOP_TYPES:
            if canon.lower() == lowered:
                canonical = canon
                break
        if canonical is None:
            # Accept verbatim — operator might be using a custom type
            # registered on the tenant.  Log a debug line so operators
            # can spot typos but don't reject.
            canonical = s
            if not canonical.lower().startswith("malop"):
                log(f"CR_MALOP_TYPE '{s}' does not start with 'Malop'; passing through verbatim")
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    if not out:
        return list(DEFAULT_MALOP_TYPES)
    return out


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on the CR host."""
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def build_login_url(host):
    base = normalize_base_url(host)
    return f"{base}/login.html"


def build_malop_url(host):
    base = normalize_base_url(host)
    return f"{base}/rest/crimes/unified"


def build_sensor_url(host):
    base = normalize_base_url(host)
    return f"{base}/rest/sensors/query"


def build_visualsearch_url(host):
    base = normalize_base_url(host)
    return f"{base}/rest/visualsearch/query/simple"


def build_login_payload(user, password):
    """Cybereason /login.html accepts form-encoded credentials."""
    return {"username": user, "password": password}


def build_malop_search_body(malop_types):
    """Build the POST body for /rest/crimes/unified.

    Returns the canonical multi-type queryPath body Cybereason's
    Defense Platform UI uses to populate the Malop list.  Each entry in
    ``malop_types`` becomes one queryPath leaf, and the templateContext
    OVERVIEW returns the simpleValues / elementValues summary used by
    the UI's Malop list (vs. DETAILS which returns the full evidence
    tree, which we fetch on demand via /rest/visualsearch).
    """
    types = list(malop_types) if malop_types else list(DEFAULT_MALOP_TYPES)
    return {
        "totalResultLimit": MALOP_RESULT_LIMIT,
        "perGroupLimit": MALOP_RESULT_LIMIT,
        "perFeatureLimit": 100,
        "templateContext": "OVERVIEW",
        "queryPath": [
            {
                "requestedType": malop_type,
                "filters": [],
                "guidList": [],
                "result": True,
            }
            for malop_type in types
        ],
    }


def build_sensor_search_body(limit, offset):
    """Build the POST body for /rest/sensors/query."""
    return {
        "limit": int(limit),
        "offset": int(offset),
        "filters": [],
    }


def build_process_query_body(malop_guid):
    """Build the POST body for /rest/visualsearch/query/simple.

    Issues a process-element search rooted at the supplied Malop GUID
    so the response surfaces every process that the malop touched.
    The templateContext PROCESS pulls the canonical process metadata
    (calculatedName / parentProcess / commandLine / processHash) used
    to enrich the per-malop description.
    """
    return {
        "queryPath": [
            {
                "requestedType": "Process",
                "filters": [],
                "guidList": [],
                "isResult": True,
                "rootCause": True,
                "connectionFeature": {
                    "elementInstanceType": "MalopProcess",
                    "featureName": "rootCauseElements",
                },
                "malopGuid": malop_guid,
            }
        ],
        "totalResultLimit": 100,
        "perGroupLimit": 100,
        "perFeatureLimit": 100,
        "templateContext": "PROCESS",
    }


def extract_malops(payload):
    """Pull the per-malop dicts out of the /rest/crimes/unified envelope.

    Cybereason returns the malop catalogue under
    ``data.resultIdToElementDataMap`` keyed by malop GUID.  We flatten
    that into a list of ``{"id": guid, ...rest}`` dicts so downstream
    helpers can walk a uniform shape regardless of which malop type
    the payload covers.
    """
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    result_map = data.get("resultIdToElementDataMap") or data.get("resultIdToElementData") or {}
    if not isinstance(result_map, dict):
        return []
    out = []
    for guid, entry in result_map.items():
        if not isinstance(entry, dict):
            continue
        flat = dict(entry)
        flat.setdefault("guid", guid)
        flat.setdefault("id", guid)
        out.append(flat)
    return out


def extract_sensors(payload):
    """Pull the sensor dicts out of the /rest/sensors/query envelope."""
    if not isinstance(payload, dict):
        return []
    for key in ("sensors", "results", "data"):
        v = payload.get(key)
        if isinstance(v, list):
            return v
    return []


def _simple_value(item, key):
    """Pull a scalar out of Cybereason's simpleValues dict.

    The Defense Platform wraps simple scalars in ``{"values": [...]}``
    or ``{"totalValues": N}`` envelopes.  Some legacy shapes use bare
    scalars.  Walk all three.
    """
    if not isinstance(item, dict):
        return None
    simple = item.get("simpleValues")
    if isinstance(simple, dict):
        entry = simple.get(key)
        if isinstance(entry, dict):
            values = entry.get("values")
            if isinstance(values, list) and values:
                v = values[0]
                if v is not None and v != "":
                    return v
            total = entry.get("totalValues")
            if total not in (None, ""):
                return total
        elif isinstance(entry, list):
            for v in entry:
                if v not in (None, ""):
                    return v
        elif entry not in (None, ""):
            return entry
    raw = item.get(key)
    if raw is not None and raw != "":
        if isinstance(raw, dict):
            values = raw.get("values")
            if isinstance(values, list) and values:
                return values[0]
        else:
            return raw
    return None


def _simple_values_list(item, key):
    """Pull the full list of scalars out of simpleValues for a key."""
    out = []
    if not isinstance(item, dict):
        return out
    simple = item.get("simpleValues")
    sources = []
    if isinstance(simple, dict):
        entry = simple.get(key)
        if isinstance(entry, dict):
            values = entry.get("values")
            if isinstance(values, list):
                sources.extend(values)
        elif isinstance(entry, list):
            sources.extend(entry)
        elif entry not in (None, ""):
            sources.append(entry)
    raw = item.get(key)
    if isinstance(raw, dict):
        values = raw.get("values")
        if isinstance(values, list):
            sources.extend(values)
    elif isinstance(raw, list):
        sources.extend(raw)
    elif raw not in (None, ""):
        sources.append(raw)
    for v in sources:
        if isinstance(v, str) and v.strip():
            out.append(v.strip())
        elif v not in (None, ""):
            out.append(str(v))
    return out


def _element_values(item, key):
    """Pull the element references out of elementValues for a key.

    Returns the list of ``{"guid": ..., "name": ..., ...}`` dicts that
    Cybereason emits for affectedMachines / rootCauseElements /
    affectedUsers etc.
    """
    if not isinstance(item, dict):
        return []
    element = item.get("elementValues")
    if not isinstance(element, dict):
        return []
    entry = element.get(key)
    if not isinstance(entry, dict):
        return []
    values = entry.get("elementValues") or entry.get("values")
    if isinstance(values, list):
        return [v for v in values if isinstance(v, dict)]
    return []


def cvss_score(item):
    """Pull a numeric CVSS score from a Cybereason Malop payload.

    Cybereason rarely carries CVSS on its own; some MTD shapes surface
    ``cvssScore`` / ``cvss`` though, and re-emitted shapes can carry
    them too.  Walk defensively.
    """
    if not isinstance(item, dict):
        return None
    for key in ("cvssScore", "cvss_score", "score", "baseScore", "base_score"):
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
    sv = _simple_value(item, "cvssScore")
    if sv not in (None, "") and not isinstance(sv, bool):
        try:
            return float(sv)
        except (TypeError, ValueError):
            pass
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
    """Pull CVE-* ids out of a Cybereason Malop payload.

    Walks the simpleValues catalogue + free-form description /
    detectionType / activityType text first, then any explicit
    cve / cves / aliases lists.
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

    for key in ("cve", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            add(v)
        elif isinstance(v, dict):
            add(v.get("id") or v.get("name") or v.get("value"))
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
        "description",
        "detectionType",
        "malopDetectionType",
        "primaryRootCauseName",
        "primaryRootCauseElementName",
        "rootCauseElementName",
        "rootCauseElementType",
        "decisionFeature",
        "decisionFeatureSet",
    ):
        for v in _simple_values_list(item, key):
            scan(v)

    for key in ("description", "Description", "title", "reason", "name"):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)

    activity = _simple_values_list(item, "malopActivityTypes")
    for entry in activity:
        scan(entry)

    return found


def collect_refs(item):
    """Walk a Cybereason Malop for advisory URLs / pivots.

    Surfaces Cybereason-side pivots (``CR-Malop: {guid}``,
    ``CR-MalopType: {type}``, ``CR-DecisionFeature: {feature}``,
    ``CR-RootCause: {name}``, ``CR-Group: {group}``) plus MITRE
    ATT&CK tactic / technique references and any inline URLs from the
    description / detectionType text.
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

    guid = item.get("guid") or item.get("id") or item.get("malopGuid")
    if isinstance(guid, str) and guid.strip():
        add(f"CR-Malop: {guid.strip()}")
    elif guid is not None:
        add(f"CR-Malop: {guid}")

    malop_type = item.get("requestedType") or item.get("malopType") or item.get("type")
    if isinstance(malop_type, str) and malop_type.strip():
        add(f"CR-MalopType: {malop_type.strip()}")

    detection_type = _simple_value(item, "malopDetectionType") or _simple_value(item, "detectionType")
    if isinstance(detection_type, str) and detection_type.strip():
        add(f"CR-DetectionType: {detection_type.strip()}")

    decision = _simple_value(item, "decisionFeature")
    if isinstance(decision, str) and decision.strip():
        add(f"CR-DecisionFeature: {decision.strip()}")
    elif decision is not None:
        add(f"CR-DecisionFeature: {decision}")

    root_cause = (
        _simple_value(item, "primaryRootCauseName")
        or _simple_value(item, "rootCauseElementName")
        or _simple_value(item, "primaryRootCauseElementName")
    )
    if isinstance(root_cause, str) and root_cause.strip():
        add(f"CR-RootCause: {root_cause.strip()}")

    root_cause_type = _simple_value(item, "primaryRootCauseElementType") or _simple_value(item, "rootCauseElementType")
    if isinstance(root_cause_type, str) and root_cause_type.strip():
        add(f"CR-RootCauseType: {root_cause_type.strip()}")

    for activity in _simple_values_list(item, "malopActivityTypes"):
        if activity:
            add(f"CR-Activity: {activity}")

    for key in ("mitre_tactics", "mitreTactics", "tactics", "tacticIds"):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, list):
            for tactic in v:
                if isinstance(tactic, str) and tactic.strip():
                    add(f"MITRE-Tactic: {tactic.strip()}")
                elif isinstance(tactic, dict):
                    name = tactic.get("name") or tactic.get("id") or tactic.get("value")
                    if isinstance(name, str) and name.strip():
                        add(f"MITRE-Tactic: {name.strip()}")
    for key in ("mitre_techniques", "mitreTechniques", "techniques", "techniqueIds"):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, list):
            for tech in v:
                if isinstance(tech, str) and tech.strip():
                    add(f"MITRE-Technique: {tech.strip()}")
                elif isinstance(tech, dict):
                    name = tech.get("name") or tech.get("id") or tech.get("value")
                    if isinstance(name, str) and name.strip():
                        add(f"MITRE-Technique: {name.strip()}")

    # MITRE tactics / techniques can also live under simpleValues on
    # the Defense Platform's "extended" malop shape.
    for key in ("mitreTactics", "mitreTechniques", "tacticIds", "techniqueIds"):
        for v in _simple_values_list(item, key):
            if not v:
                continue
            if key.lower().startswith("mitretactic") or key.lower().startswith("tactic"):
                add(f"MITRE-Tactic: {v}")
            else:
                add(f"MITRE-Technique: {v}")

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


def sensor_label(sensor):
    """Build a friendly label for a Cybereason sensor record."""
    if not isinstance(sensor, dict):
        return ""
    for key in ("machineName", "computerName", "hostname", "fqdn"):
        v = sensor.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("userName", "lastUserName", "fullMachineName"):
        v = sensor.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("sensorId", "guid", "pylumId"):
        v = sensor.get(key)
        if v is not None:
            s = str(v).strip()
            if s:
                return s
    return ""


def malop_label(item):
    """Build the leading title fragment for a Cybereason Malop finding."""
    if not isinstance(item, dict):
        return ""

    detection_type = _simple_value(item, "malopDetectionType") or _simple_value(item, "detectionType")
    activity = _simple_values_list(item, "malopActivityTypes")
    root_cause = _simple_value(item, "primaryRootCauseName") or _simple_value(item, "rootCauseElementName")
    parts = []
    if isinstance(detection_type, str) and detection_type.strip():
        parts.append(detection_type.strip())
    if activity:
        parts.append("/".join(activity))
    if isinstance(root_cause, str) and root_cause.strip():
        parts.append(root_cause.strip())
    if parts:
        return " - ".join(parts)

    for key in ("malopName", "name", "title", "description", "reason"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "Cybereason Malop"


def host_bucket_key(item):
    """Pick a stable bucket key for a Cybereason malop or sensor record."""
    if not isinstance(item, dict):
        return "__unknown__"
    for key in ("sensorId", "guid", "pylumId"):
        v = item.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    for key in ("machineName", "computerName", "hostname"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "__unknown__"


def host_ip(item):
    """Pick the host IP from a Cybereason sensor / element record."""
    if not isinstance(item, dict):
        return "0.0.0.0"
    for key in (
        "internalIpAddress",
        "internal_ip_address",
        "externalIpAddress",
        "external_ip_address",
        "ip",
        "ipAddress",
        "ip_address",
        "lastInternalIpAddress",
        "lastExternalIpAddress",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1"):
            return v.strip()
    return "0.0.0.0"


def host_mac(item):
    if not isinstance(item, dict):
        return ""
    for key in ("macAddress", "mac_address", "mac"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def host_os(item):
    if not isinstance(item, dict):
        return ""
    os_name = item.get("osType") or item.get("os") or item.get("operatingSystem") or item.get("osName") or ""
    os_version = item.get("osVersionType") or item.get("osVersion") or item.get("os_version") or ""
    if os_name and os_version:
        return f"{os_name} {os_version}".strip()
    return str(os_name or os_version or "").strip()


def affected_machine_keys(item):
    """Return every sensor bucket key referenced by a Malop.

    Walks ``elementValues.affectedMachines`` and emits one bucket key
    per machine — sensorId / guid / machineName — so the per-malop
    vulnerability is duplicated across every endpoint it touched.
    """
    keys = []
    seen = set()
    for entry in _element_values(item, "affectedMachines"):
        for key in ("sensorId", "guid", "machineGuid", "elementValues_guid", "machineName"):
            v = entry.get(key)
            if v is None:
                continue
            s = str(v).strip()
            if not s or s in seen:
                continue
            seen.add(s)
            keys.append(s)
            break
        else:
            name = entry.get("name") or entry.get("displayName")
            if isinstance(name, str) and name.strip():
                s = name.strip()
                if s not in seen:
                    seen.add(s)
                    keys.append(s)
    return keys


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


def build_vulnerability(item, sensor_lookup=None, process_evidence=None):
    """Build a Faraday vulnerability dict from a Cybereason Malop record.

    ``sensor_lookup`` is an optional ``{sensorId: sensor_record}`` map
    used to enrich the malop's host context with sensor-side metadata
    (sensorVersion / policyName / groupName / siteName).
    ``process_evidence`` is an optional list of process records pulled
    from /rest/visualsearch/query/simple for the same malop GUID;
    when supplied each process surfaces in the description so the
    Faraday vuln tells the full attack-chain story without forcing
    an analyst to open the Cybereason UI.
    """
    if not isinstance(item, dict):
        return None

    score = cvss_score(item)
    severity_raw = (
        _simple_value(item, "severity")
        or _simple_value(item, "malopPriority")
        or item.get("severity")
        or item.get("malopPriority")
    )
    severity = severity_from_cr(severity_raw, score)
    status = status_from_cr(item)

    label = malop_label(item)
    name = f"[EDR] {label}" if label else "[EDR] Cybereason Malop"

    desc_parts = []
    description = item.get("description") or item.get("Description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    guid = item.get("guid") or item.get("id") or item.get("malopGuid")
    if guid not in (None, ""):
        desc_parts.append(f"malop_guid: {guid}")

    for label_key, key in (
        ("malop_detection_type", "malopDetectionType"),
        ("detection_type", "detectionType"),
        ("malop_activity_types", "malopActivityTypes"),
        ("decision_feature", "decisionFeature"),
        ("decision_feature_set", "decisionFeatureSet"),
        ("severity_raw", "severity"),
        ("malop_priority", "malopPriority"),
        ("management_status", "managementStatus"),
        ("malop_status", "malopStatus"),
        ("investigation_status", "investigationStatus"),
        ("creation_time", "creationTime"),
        ("last_update_time", "lastUpdateTime"),
        ("close_time", "closeTime"),
        ("machine_count", "machineCount"),
        ("user_count", "userCount"),
        ("file_count", "fileCount"),
        ("process_count", "processCount"),
        ("primary_root_cause_name", "primaryRootCauseName"),
        ("primary_root_cause_element_type", "primaryRootCauseElementType"),
        ("root_cause_element_name", "rootCauseElementName"),
        ("root_cause_element_type", "rootCauseElementType"),
        ("malop_assigned_user", "assignedUser"),
        ("malop_assigned_to_user", "malopAssignedToUser"),
        ("malop_close_reason", "closeReason"),
        ("malop_closer", "malopClosedBy"),
        ("primary_machine_name", "primaryMachineName"),
        ("affected_users", "affectedUsersList"),
        ("scope_name", "scopeName"),
        ("mitre_tactics", "mitreTactics"),
        ("mitre_techniques", "mitreTechniques"),
    ):
        scalar = _simple_value(item, key)
        values = _simple_values_list(item, key) if scalar is None else None
        if scalar not in (None, ""):
            desc_parts.append(f"{label_key}: {scalar}")
        elif values:
            desc_parts.append(f"{label_key}: {', '.join(str(v) for v in values)}")
        else:
            raw = item.get(key)
            if raw in (None, ""):
                continue
            if isinstance(raw, (dict, list)):
                desc_parts.append(f"{label_key}: {_serialise(raw)}")
            else:
                desc_parts.append(f"{label_key}: {raw}")

    affected = _element_values(item, "affectedMachines")
    if affected:
        for machine in affected[:20]:
            bits = []
            for key in ("name", "displayName", "machineName", "guid", "osType", "osVersionType"):
                v = machine.get(key)
                if v not in (None, ""):
                    bits.append(f"{key}={v}")
            if bits:
                desc_parts.append(f"affected_machine: {'; '.join(bits)}")

    root_causes = _element_values(item, "rootCauseElements")
    if root_causes:
        for rc in root_causes[:10]:
            bits = []
            for key in ("name", "elementType", "calculatedName", "imageFileHash", "commandLine"):
                v = rc.get(key)
                if v not in (None, ""):
                    bits.append(f"{key}={v}")
            if bits:
                desc_parts.append(f"root_cause: {'; '.join(bits)}")

    affected_users = _element_values(item, "affectedUsers")
    if affected_users:
        for user in affected_users[:10]:
            bits = []
            for key in ("name", "displayName", "guid", "userName"):
                v = user.get(key)
                if v not in (None, ""):
                    bits.append(f"{key}={v}")
            if bits:
                desc_parts.append(f"affected_user: {'; '.join(bits)}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(item)
    if vector:
        desc_parts.append(f"vector: {vector}")

    if isinstance(process_evidence, list) and process_evidence:
        for proc in process_evidence[:25]:
            if not isinstance(proc, dict):
                continue
            bits = []
            for key in (
                "calculatedName",
                "commandLine",
                "imageFileHash",
                "parentName",
                "ownerMachine",
                "elementDisplayName",
            ):
                v = _simple_value(proc, key) if isinstance(proc.get("simpleValues"), dict) else proc.get(key)
                if v not in (None, ""):
                    bits.append(f"{key}={v}")
            if bits:
                desc_parts.append(f"process_evidence: {'; '.join(bits)}")

    if isinstance(sensor_lookup, dict):
        sensor_keys = affected_machine_keys(item) or []
        for key in sensor_keys[:5]:
            sensor = sensor_lookup.get(str(key))
            if not isinstance(sensor, dict):
                continue
            for sub_key in (
                "sensorId",
                "machineName",
                "osType",
                "osVersionType",
                "policyName",
                "groupName",
                "siteName",
                "sensorVersion",
                "preventionStatus",
                "ransomwareStatus",
                "antiMalwareStatus",
                "firstSeen",
                "lastSeen",
                "internalIpAddress",
                "externalIpAddress",
                "deviceType",
                "deviceModel",
                "departmentName",
                "isolated",
                "amStatus",
                "status",
            ):
                sv = sensor.get(sub_key)
                if sv in (None, ""):
                    continue
                if isinstance(sv, (dict, list)):
                    desc_parts.append(f"sensor_{sub_key}: {_serialise(sv)}")
                else:
                    desc_parts.append(f"sensor_{sub_key}: {sv}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    rem = item.get("remediation") or item.get("Remediation") or item.get("remediationDescription")
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution:
        prevention = _simple_value(item, "preventionEvent")
        if isinstance(prevention, str) and prevention.strip():
            resolution = (
                f"Cybereason prevention event: {prevention.strip()}. "
                "Investigate the Malop in the Defense Platform UI and confirm "
                "the prevention action was correct; if not, tune the policy."
            )
    if not resolution:
        resolution = (
            "Investigate the Malop in the Cybereason Defense Platform UI "
            "(Malops -> select malop) and decide a disposition (true positive "
            "-> isolate / remediate; false positive -> close with FalsePositive)."
        )

    external_id = str(item.get("guid") or item.get("id") or item.get("malopGuid") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Cybereason Malop {external_id}",
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
        "tags": ["cybereason", "edr", "endpoint-edr"],
    }


def build_host(bucket_key, sample_malop, sample_sensor, vulns):
    """Build a Faraday host record for the supplied sensor bucket."""
    sample = sample_sensor or sample_malop
    label = sensor_label(sample) if sample else ""
    hostname = ""
    if label:
        hostname = label
    elif bucket_key and bucket_key != "__unknown__":
        hostname = bucket_key

    ip = host_ip(sample_sensor) if sample_sensor else (host_ip(sample_malop) if sample_malop else "0.0.0.0")
    mac = host_mac(sample_sensor) if sample_sensor else (host_mac(sample_malop) if sample_malop else "")
    os_str = host_os(sample_sensor) if sample_sensor else (host_os(sample_malop) if sample_malop else "")

    desc_parts = []
    if bucket_key and bucket_key != "__unknown__":
        desc_parts.append(f"sensor_id={bucket_key}")

    if isinstance(sample_sensor, dict):
        for label_key, key in (
            ("machine_name", "machineName"),
            ("computer_name", "computerName"),
            ("fqdn", "fqdn"),
            ("os_type", "osType"),
            ("os_version_type", "osVersionType"),
            ("policy_name", "policyName"),
            ("group_name", "groupName"),
            ("site_name", "siteName"),
            ("sensor_version", "sensorVersion"),
            ("prevention_status", "preventionStatus"),
            ("am_status", "amStatus"),
            ("ransomware_status", "ransomwareStatus"),
            ("anti_malware_status", "antiMalwareStatus"),
            ("first_seen", "firstSeen"),
            ("last_seen", "lastSeen"),
            ("last_pylum_info_msg_update_time", "lastPylumInfoMsgUpdateTime"),
            ("internal_ip_address", "internalIpAddress"),
            ("external_ip_address", "externalIpAddress"),
            ("user_name", "userName"),
            ("device_type", "deviceType"),
            ("device_model", "deviceModel"),
            ("department_name", "departmentName"),
            ("isolated", "isolated"),
            ("organization", "organization"),
        ):
            v = sample_sensor.get(key)
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


def cybereason_login(requests_module, host, user, password, verify=True):
    """POST /login.html with form-encoded credentials.

    Returns the ``requests.Session`` that owns the JSESSIONID cookie on
    success.  Cybereason occasionally re-issues the cookie on the first
    /rest/ call; using a Session ensures the cookie is carried across
    every subsequent request.
    """
    session = requests_module.Session()
    url = build_login_url(host)
    payload = build_login_payload(user, password)
    try:
        resp = session.post(
            url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT,
            verify=verify,
            allow_redirects=False,
        )
    except Exception as exc:  # noqa: BLE001
        log(f"Login POST {url} failed: {exc}")
        sys.exit(1)
    # Cybereason returns 200 + Set-Cookie on success, 200 + an HTML
    # error page (no cookie) on failure.  Validate by cookie presence.
    cookies = session.cookies
    if not any(c.name == "JSESSIONID" for c in cookies):
        log(
            "Cybereason login did not return a JSESSIONID cookie — check "
            f"CR_USER / CR_PASSWORD (HTTP {resp.status_code})"
        )
        sys.exit(1)
    return session


def fetch_malops(session, url, malop_types, verify=True):
    """POST the /rest/crimes/unified Malop search and return the dicts."""
    body = build_malop_search_body(malop_types)
    try:
        resp = session.post(
            url,
            json=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=TIMEOUT,
            verify=verify,
        )
    except Exception as exc:  # noqa: BLE001
        log(f"Malop POST {url} failed: {exc}")
        return []
    if resp.status_code == 401 or resp.status_code == 403:
        log(f"Cybereason Malop request rejected ({resp.status_code}). Check CR_USER / CR_PASSWORD.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Cybereason Malop request failed ({resp.status_code}): {resp.text[:500]}")
        return []
    try:
        payload = resp.json()
    except ValueError:
        log(f"Cybereason Malop response was not JSON ({url})")
        return []
    return extract_malops(payload)


def fetch_sensors(session, url, verify=True, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk the /rest/sensors/query envelope page-by-page."""
    out = []
    offset = 0
    pages = 0
    while pages < max_pages:
        body = build_sensor_search_body(page_size, offset)
        try:
            resp = session.post(
                url,
                json=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=TIMEOUT,
                verify=verify,
            )
        except Exception as exc:  # noqa: BLE001
            log(f"Sensor POST {url} failed: {exc}")
            return out
        if resp.status_code == 401 or resp.status_code == 403:
            log(f"Cybereason Sensor request rejected ({resp.status_code}).")
            sys.exit(1)
        if resp.status_code >= 400:
            log(f"Cybereason Sensor request failed ({resp.status_code}): {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Cybereason Sensor response was not JSON ({url})")
            return out
        sensors = extract_sensors(payload)
        if not sensors:
            break
        for entry in sensors:
            if isinstance(entry, dict):
                out.append(entry)
        if len(sensors) < page_size:
            break
        offset += len(sensors)
        total = payload.get("totalResults") if isinstance(payload, dict) else None
        if isinstance(total, int) and offset >= total:
            break
        pages += 1
    if pages >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping sensor pagination")
    return out


def fetch_process_evidence(session, url, malop_guid, verify=True):
    """POST /rest/visualsearch/query/simple for a malop's process tree."""
    body = build_process_query_body(malop_guid)
    try:
        resp = session.post(
            url,
            json=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=TIMEOUT,
            verify=verify,
        )
    except Exception as exc:  # noqa: BLE001
        log(f"VisualSearch POST {url} failed: {exc}")
        return []
    if resp.status_code >= 400:
        log(f"VisualSearch failed ({resp.status_code}) for malop {malop_guid}: {resp.text[:200]}")
        return []
    try:
        payload = resp.json()
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    result_map = data.get("resultIdToElementDataMap") or {}
    if not isinstance(result_map, dict):
        return []
    return [entry for entry in result_map.values() if isinstance(entry, dict)]


def main():
    started = time.time()

    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_CR_MIN_SEVERITY"))
    malop_types = validate_malop_type(env("EXECUTOR_CONFIG_CR_MALOP_TYPE"))
    allowed_severities = set(severities_at_or_above(min_severity))
    include_process_evidence = (env("EXECUTOR_CONFIG_CR_INCLUDE_PROCESS_EVIDENCE") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    host = env("CR_HOST", required=True)
    user = env("CR_USER", required=True)
    password = env("CR_PASSWORD", required=True)
    verify_env = (os.getenv("CR_VERIFY_SSL") or "").strip().lower()
    verify = verify_env not in ("0", "false", "no", "off")

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    session = cybereason_login(requests, host, user, password, verify=verify)

    malop_url = build_malop_url(host)
    sensor_url = build_sensor_url(host)
    visualsearch_url = build_visualsearch_url(host)

    malops = fetch_malops(session, malop_url, malop_types, verify=verify)
    sensors = fetch_sensors(session, sensor_url, verify=verify)

    log(
        f"Processing {len(malops)} Cybereason malops + {len(sensors)} sensors "
        f"(types={','.join(malop_types)}, min_severity={min_severity}, "
        f"evidence={include_process_evidence})"
    )

    sensor_lookup = {}
    for sensor in sensors:
        if not isinstance(sensor, dict):
            continue
        for key in ("sensorId", "guid", "pylumId", "machineName"):
            v = sensor.get(key)
            if v is not None:
                s = str(v).strip()
                if s:
                    sensor_lookup.setdefault(s, sensor)

    buckets = {}
    sample_malops = {}
    for malop in malops:
        keys = affected_machine_keys(malop)
        if not keys:
            keys = [host_bucket_key(malop)]
        for key in keys:
            buckets.setdefault(key, []).append(malop)
            sample_malops.setdefault(key, malop)

    # Sensors with no malops still surface as inventory hosts so the
    # Faraday workspace mirrors the full sensor inventory.
    for key, sensor in sensor_lookup.items():
        buckets.setdefault(key, [])
        sample_malops.setdefault(key, None)

    process_evidence_cache = {}

    hosts = []
    for key, malop_items in buckets.items():
        vulns = []
        for malop in malop_items:
            guid = malop.get("guid") or malop.get("id") or malop.get("malopGuid")
            evidence = None
            if include_process_evidence and guid:
                if guid not in process_evidence_cache:
                    process_evidence_cache[guid] = fetch_process_evidence(
                        session,
                        visualsearch_url,
                        guid,
                        verify=verify,
                    )
                evidence = process_evidence_cache[guid]
            built = build_vulnerability(
                malop,
                sensor_lookup=sensor_lookup,
                process_evidence=evidence,
            )
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        sample_malop = sample_malops.get(key)
        sample_sensor = sensor_lookup.get(key) if key != "__unknown__" else None
        hosts.append(build_host(key, sample_malop, sample_sensor, vulns))

    params_bits = [
        f"min_severity={min_severity}",
        f"malop_types={','.join(malop_types)}",
    ]
    if include_process_evidence:
        params_bits.append("evidence=1")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "cybereason",
            "command": "cybereason",
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
