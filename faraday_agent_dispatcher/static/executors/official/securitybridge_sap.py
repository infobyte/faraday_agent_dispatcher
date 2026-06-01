#!/usr/bin/env python
"""SecurityBridge SAP-security REST importer.

Pulls the system-level metadata record (SAP SID + instance + version
+ risk score) and the open finding catalogue from a SecurityBridge
tenant and emits Faraday bulk-create JSON to stdout.  Each monitored
SAP system becomes one Faraday host (keyed by the SAP system
identifier — SecurityBridge's surface is SAP-system-scoped so the
host record is keyed on the SAP SID / internal system id rather than
synthetic); the system's open findings attach as Faraday
vulnerabilities with the engine prefix ``[SAP-SECURITY]``.  The host
record carries ``host.os`` set to the SAP product + release string
(e.g. ``SAP NetWeaver 7.50 SP12 (risk=72)``) so the SAP stack version
is visible alongside the per-finding observations.

Endpoints used:
  GET <SB_HOST>/api/v1/systems/{system_id}
      -> the monitored SAP system's metadata (SID, instance number,
      client, product, release, hostname, internal ip, risk score,
      last scan timestamp).  Used to build the host record +
      host.description enrichment + host.os string.
  GET <SB_HOST>/api/v1/findings?systemId={system_id}
      -> paginated open findings (each finding = one observation
      tied to one SAP object / report / table / role).  Pagination
      is ``limit`` + ``offset`` cursor with ``links.next`` /
      ``total`` exhaustion detection.  Each finding maps onto a
      Faraday vulnerability — severity bucketed from the freeform
      ``severity`` string enum (critical / high / medium / low /
      info) with the numeric ``cvss`` / ``riskScore`` (0-10) used as
      a CVSS-style fallback.

Auth: SecurityBridge issues per-tenant API keys that are carried as
``Authorization: Bearer <SB_API_KEY>`` plus ``Accept:
application/json`` on every call.  ``SB_API_KEY`` is the API key
created in the SecurityBridge console under ``Administration -> API
Keys``.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# SAP Note ids on SecurityBridge findings — 7-digit numeric usually
# but kept loose at 4-10 digits to survive any older 4-digit notes
# that still ship in the corpus.
SAP_NOTE_RE = re.compile(r"\b(?:SAP[- ]?Note[: ]?)?(\d{4,10})\b", re.IGNORECASE)
SAP_NOTE_LABEL_RE = re.compile(r"SAP[- ]?Note", re.IGNORECASE)
# SecurityBridge host validation — accept http(s)://host[:port],
# strip trailing slash.  Control chars (newline / tab / null / etc)
# rejected outright so a header-injection attempt can't sneak through.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")
# SB system id validation — SAP SIDs are 3-char alphanumeric (e.g.
# "PRD") but SecurityBridge sometimes exposes a numeric internal id
# instead.  Allow either shape: alphanumeric + `_-.` up to 64 chars
# (gives room for tenant-scoped SIDs like "PRD_001.dev").  Anchored
# with \A/\Z (not ^/$) so a trailing newline cannot sneak through —
# Python's default `$` matches just before a trailing `\n`.
SYSTEM_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\-]{0,63}\Z")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# SecurityBridge surfaces ``severity`` as a freeform string enum
# (critical / high / medium / low / info) plus a numeric ``cvss`` /
# ``riskScore`` 0-10.  The string enum buckets onto Faraday tiers;
# numeric bucketing is used as a fallback when the string is missing
# or unrecognised.
SB_STRING_SEVERITY = {
    "critical": "critical",
    "very_high": "critical",
    "veryhigh": "critical",
    "severe": "critical",
    "high": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "neutral": "info",
    "none": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# SecurityBridge finding lifecycle is exposed through ``status`` /
# ``state`` / ``findingStatus``.  Open / new / active map onto
# Faraday open; resolved / fixed / mitigated map onto closed;
# acknowledged / accepted / deferred / false_positive map onto
# risk-accepted.
SB_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "active": "open",
    "detected": "open",
    "in_progress": "open",
    "inprogress": "open",
    "investigating": "open",
    "triaging": "open",
    "reopened": "open",
    "remediated": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "patched": "closed",
    "mitigated": "closed",
    "closed": "closed",
    "completed": "closed",
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
    print(f"{datetime.utcnow()} - SecurityBridge: {msg}", file=sys.stderr, flush=True)


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


def severity_from_securitybridge(value, numeric=None):
    """Map a SecurityBridge severity string onto a Faraday bucket.

    Accepts the freeform string enum (critical / high / medium / low /
    info), Faraday-side synonyms (severe / major / moderate / minor /
    informational), numeric inputs (0-10 CVSS-style), numeric strings,
    and falls back to numeric bucketing on ``numeric`` when the primary
    value is missing or unrecognised.
    """
    if isinstance(value, bool):
        if numeric is not None:
            return severity_from_cvss(numeric)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        if text in SB_STRING_SEVERITY:
            return SB_STRING_SEVERITY[text]
        squashed = text.replace("_", "")
        if squashed in SB_STRING_SEVERITY:
            return SB_STRING_SEVERITY[squashed]
        try:
            return severity_from_cvss(float(value.strip()))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def status_from_securitybridge(item):
    """Derive Faraday status from a SecurityBridge finding payload.

    Walks ``status`` / ``state`` / ``findingStatus`` and falls back
    to ``remediation_status`` / ``resolutionStatus`` for re-emitted
    shapes.
    """
    if not isinstance(item, dict):
        return "open"
    for key in (
        "status",
        "state",
        "findingStatus",
        "finding_status",
        "remediation_status",
        "remediationStatus",
        "resolutionStatus",
        "resolution_status",
        "Status",
        "State",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in SB_STATUS_BY_STATE:
                return SB_STATUS_BY_STATE[compact]
            if squashed in SB_STATUS_BY_STATE:
                return SB_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in SB_STATUS_BY_STATE:
                        return SB_STATUS_BY_STATE[compact]
                    if squashed in SB_STATUS_BY_STATE:
                        return SB_STATUS_BY_STATE[squashed]
    return "open"


def validate_min_severity(value):
    """Validate SB_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus SecurityBridge-side
    synonyms (severe / very_high -> critical, major -> high, moderate
    / warning -> medium, minor -> low, informational / information ->
    info) plus numeric-string input bucketed via severity_from_cvss.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "info"
    bucket = SB_STRING_SEVERITY.get(text)
    if bucket is None:
        bucket = SB_STRING_SEVERITY.get(text.replace("_", ""))
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(str(value).strip()))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"SB_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_system_id(value):
    """Validate SB_SYSTEM_ID.

    None / blank -> sys.exit(1).  SAP SIDs are 3-character alphanumeric
    (e.g. ``PRD``) but SecurityBridge can also key on a numeric internal
    id — accept either shape up to 64 chars (alnum + ``._-``) so a
    typo or control char can't fan out into ``/api/v1/systems/None``
    calls.
    """
    if value is None or value == "":
        log("SB_SYSTEM_ID is required")
        sys.exit(1)
    raw = str(value)
    # Reject any control char on the *raw* value before .strip() runs
    # — .strip() would otherwise eat trailing newlines so a typo
    # ending in \n / \r could sneak through SYSTEM_ID_RE.
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("SB_SYSTEM_ID contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("SB_SYSTEM_ID is required")
        sys.exit(1)
    if not SYSTEM_ID_RE.match(text):
        log(f"SB_SYSTEM_ID '{text}' is not a valid identifier " "(alphanumeric + ._- up to 64 chars)")
        sys.exit(1)
    return text


def validate_host(value):
    """Validate SB_HOST.

    None / blank -> sys.exit(1).  Must be ``http(s)://host[:port]``;
    trailing slash stripped client-side.  Control chars rejected so a
    header-injection attempt can't sneak through.
    """
    if value is None or value == "":
        log("SB_HOST is required")
        sys.exit(1)
    raw = str(value)
    # Reject any control char (incl. CR / LF / NUL) on the *raw* value
    # before .strip() runs — .strip() would otherwise eat trailing
    # newlines so a header-injection attempt could sneak through.
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("SB_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("SB_HOST is required")
        sys.exit(1)
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"SB_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(api_key):
    """SecurityBridge expects ``Authorization: Bearer <SB_API_KEY>``."""
    return {
        "Authorization": f"Bearer {api_key or ''}",
        "Accept": "application/json",
    }


def build_system_url(host, system_id):
    return f"{host}/api/v1/systems/{system_id}"


def build_findings_url(host):
    return f"{host}/api/v1/findings"


def build_findings_params(system_id, offset, limit):
    """SecurityBridge finding pagination is ``limit`` + ``offset`` cursor."""
    return {
        "systemId": system_id,
        "limit": int(limit),
        "offset": int(offset),
    }


def extract_results(body):
    """Pull the result list out of a SecurityBridge pagination envelope.

    SecurityBridge uses ``{"results": [...], "total": N, "links":
    {"next": "..."}}`` on /findings — accept ``data`` / ``items`` /
    ``findings`` / ``entries`` as alt-keys for federated stacks.
    """
    if not isinstance(body, dict):
        return []
    for key in ("results", "data", "items", "findings", "entries"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_count(body):
    """Pull the total record count from a SecurityBridge envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("total", "count", "total_count", "totalCount"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def extract_next_link(body):
    """Pull the ``links.next`` URL from a SecurityBridge envelope (None if exhausted)."""
    if not isinstance(body, dict):
        return None
    links = body.get("links")
    if isinstance(links, dict):
        nxt = links.get("next")
        if isinstance(nxt, str) and nxt.strip():
            return nxt.strip()
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
    """Walk a SecurityBridge finding payload for CVE-* ids."""
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
    for key in ("cves", "cve_ids"):
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
        "details_description",
        "evidence",
        "summary",
        "name",
        "title",
        "finding_description",
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


def collect_sap_notes(item):
    """Walk a SecurityBridge finding payload for SAP Note ids.

    SAP Notes are SecurityBridge's primary advisory reference — each
    finding usually links one or more notes that publish the patch /
    workaround.  Notes are numeric (typically 7-digit but kept loose
    at 4-10 digits to survive older 4-digit notes).
    """
    found = []
    seen = set()

    def add(num):
        if not num:
            return
        s = str(num).strip()
        if not s.isdigit() or not (4 <= len(s) <= 10):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    if not isinstance(item, dict):
        return found

    for key in ("sap_note", "sapNote", "note", "noteNumber", "note_number"):
        v = item.get(key)
        if isinstance(v, (int, str)):
            add(v)
    for key in ("sap_notes", "sapNotes", "notes"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, (int, str)):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("number") or entry.get("note"))

    details = item.get("details") if isinstance(item, dict) else None
    if isinstance(details, dict):
        for key in ("sap_note", "sap_notes", "note", "notes"):
            v = details.get(key)
            if isinstance(v, str):
                add(v)
            elif isinstance(v, list):
                for entry in v:
                    if isinstance(entry, (int, str)):
                        add(entry)

    # Inline scan only on text that *mentions* "SAP Note" — a bare
    # 7-digit number in a description is more often a transport id
    # than a note number, so we anchor on the "SAP Note" label to
    # avoid false positives.
    for key in (
        "description",
        "finding_description",
        "evidence",
        "summary",
        "resolution",
        "recommendation",
    ):
        v = item.get(key)
        if not isinstance(v, str):
            continue
        if not SAP_NOTE_LABEL_RE.search(v):
            continue
        for m in SAP_NOTE_RE.finditer(v):
            add(m.group(1))

    return found


def collect_refs(item):
    """Walk a SecurityBridge finding payload for advisory URLs and SB pivots."""
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
            add(f"SecurityBridge-Finding: {s}")

    rule_id = item.get("rule_id") or item.get("ruleId") or item.get("ruleName") or item.get("rule_name")
    if rule_id is not None:
        s = str(rule_id).strip()
        if s:
            add(f"SecurityBridge-Rule: {s}")

    category = item.get("category") or item.get("findingCategory") or item.get("finding_category")
    if isinstance(category, str) and category.strip():
        add(f"SecurityBridge-Category: {category.strip()}")

    risk_area = item.get("risk_area") or item.get("riskArea") or item.get("area")
    if isinstance(risk_area, str) and risk_area.strip():
        add(f"SecurityBridge-RiskArea: {risk_area.strip()}")

    for key in ("system_id", "systemId", "sid", "system"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            add(f"SecurityBridge-System: {v.strip()}")
        elif isinstance(v, dict):
            label = v.get("id") or v.get("name") or v.get("sid")
            if isinstance(label, str) and label.strip():
                add(f"SecurityBridge-System: {label.strip()}")

    for key in ("client", "instance", "instance_number", "instanceNumber"):
        v = item.get(key)
        if isinstance(v, (str, int)) and str(v).strip():
            add(f"SecurityBridge-{key.split('_')[0].title()}: {str(v).strip()}")

    transport = item.get("transport") or item.get("transportRequest") or item.get("transport_request")
    if isinstance(transport, str) and transport.strip():
        add(f"SecurityBridge-Transport: {transport.strip()}")

    sap_object = item.get("object") or item.get("sap_object") or item.get("sapObject")
    if isinstance(sap_object, str) and sap_object.strip():
        add(f"SecurityBridge-Object: {sap_object.strip()}")

    for key in ("references", "remediations", "links", "advisory_urls"):
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
    """Build the leading title fragment for a SecurityBridge finding."""
    if not isinstance(item, dict):
        return ""
    for key in ("title", "name", "ruleName", "rule_name"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("category", "findingCategory", "finding_category"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("summary", "finding_description"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    details = item.get("details")
    if isinstance(details, dict):
        for key in ("description", "summary", "title"):
            v = details.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return "SecurityBridge finding"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from a SecurityBridge finding record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    for key in ("cvss", "cvssScore", "cvss_score", "riskScore", "risk_score", "score"):
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
        or item.get("severity_label")
        or item.get("severityLabel")
        or item.get("risk_level")
        or item.get("riskLevel")
    )
    severity = severity_from_securitybridge(severity_string, severity_numeric)
    status = status_from_securitybridge(item)

    label = finding_label(item)
    name = f"[SAP-SECURITY] {label}" if label else "[SAP-SECURITY] SecurityBridge finding"

    desc_parts = []
    description = (
        item.get("description")
        or item.get("Description")
        or item.get("finding_description")
        or item.get("details_description")
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
        ("rule_id", "rule_id"),
        ("rule_name", "rule_name"),
        ("category", "category"),
        ("risk_area", "risk_area"),
        ("first_seen", "first_seen"),
        ("last_seen", "last_seen"),
        ("first_seen_time", "first_seen_time"),
        ("last_seen_time", "last_seen_time"),
        ("severity", "severity"),
        ("cvss", "cvss"),
        ("risk_score", "risk_score"),
        ("status", "status"),
        ("client", "client"),
        ("instance", "instance"),
        ("sap_object", "sap_object"),
        ("transport", "transport"),
        ("transport_request", "transport_request"),
        ("user", "user"),
        ("program", "program"),
        ("report", "report"),
        ("table", "table"),
        ("role", "role"),
        ("authorization_object", "authorization_object"),
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
    sap_notes = collect_sap_notes(item)
    refs = collect_refs(item)
    for note in sap_notes:
        ref = {"name": f"SAP-Note: {note}", "type": "other"}
        if ref["name"] not in {r.get("name") for r in refs}:
            refs.append(ref)

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
        note_hint = ""
        if sap_notes:
            note_hint = f" Apply SAP Note(s) {', '.join(sap_notes[:5])}."
        resolution = (
            "Investigate the finding in the SecurityBridge console "
            "(Findings -> select the finding -> Evidence tab) and "
            "drive remediation through the SAP basis team for the "
            "affected system; accept the risk via SecurityBridge's "
            "Risk Acceptance workflow if the underlying issue cannot "
            "be remediated."
            f"{note_hint}"
        )

    external_id = str(
        item.get("id")
        or item.get("findingId")
        or item.get("finding_id")
        or (cves[0] if cves else "")
        or (f"sapnote-{sap_notes[0]}" if sap_notes else "")
    )

    return {
        "name": str(name).strip()[:200] or f"SecurityBridge finding {external_id}",
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
        "tags": ["securitybridge", "sap-security", "securitybridge-sap"],
    }


def system_hostname(system, fallback):
    """Pick the canonical hostname for a SecurityBridge system record."""
    if isinstance(system, dict):
        for key in ("hostname", "host", "fqdn", "applicationServer", "application_server", "sid", "name"):
            v = system.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return ""


def system_ip(system):
    """Pick an IP address for the SAP system (if surfaced)."""
    if not isinstance(system, dict):
        return "0.0.0.0"
    for key in ("ip", "ip_address", "ipAddress", "internalIp", "internal_ip"):
        v = system.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "0.0.0.0"


def system_os(system):
    """Build the host.os string from a SecurityBridge system record.

    SecurityBridge is SAP-system-scoped, so host.os carries the SAP
    product + release + (optional) risk-score label (e.g. ``SAP
    NetWeaver 7.50 SP12 (risk=72)``) rather than the underlying OS.
    Falls back to the literal ``SAP`` if no version metadata is
    present.
    """
    if not isinstance(system, dict):
        return "SAP"
    product = (
        system.get("product") or system.get("productName") or system.get("product_name") or system.get("component")
    )
    release = (
        system.get("release") or system.get("version") or system.get("productVersion") or system.get("product_version")
    )
    sp = system.get("supportPackage") or system.get("support_package") or system.get("sp")
    risk = system.get("riskScore") or system.get("risk_score") or system.get("score")
    parts = []
    if isinstance(product, str) and product.strip():
        parts.append(product.strip())
    else:
        parts.append("SAP")
    if isinstance(release, (str, int, float)) and str(release).strip():
        parts.append(str(release).strip())
    if isinstance(sp, (str, int, float)) and str(sp).strip():
        parts.append(f"SP{str(sp).strip()}" if not str(sp).strip().upper().startswith("SP") else str(sp).strip())
    label = " ".join(parts)
    if risk not in (None, ""):
        try:
            label = f"{label} (risk={int(round(float(risk)))})"
        except (TypeError, ValueError):
            label = f"{label} (risk={risk})"
    return label


def build_host(system_id, system, vulns):
    """Build a Faraday host record for the monitored SAP system."""
    if not isinstance(system, dict):
        system = {}
    hostname = system_hostname(system, system_id)
    os_str = system_os(system)
    ip = system_ip(system)

    desc_parts = [f"system_id={system_id}"]
    for label_key, key in (
        ("sid", "sid"),
        ("name", "name"),
        ("description", "description"),
        ("client", "client"),
        ("instance_number", "instanceNumber"),
        ("product", "product"),
        ("release", "release"),
        ("support_package", "supportPackage"),
        ("kernel_release", "kernelRelease"),
        ("hostname", "hostname"),
        ("ip", "ip"),
        ("risk_score", "riskScore"),
        ("last_scan", "lastScan"),
        ("environment", "environment"),
        ("landscape", "landscape"),
    ):
        v = system.get(key)
        if v not in (None, ""):
            desc_parts.append(f"{label_key}={v}")

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


def fetch_system(requests_module, host, system_id, headers):
    """GET the SecurityBridge system metadata record."""
    url = build_system_url(host, system_id)
    try:
        resp = requests_module.get(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return {}
    if resp.status_code == 401:
        log("SecurityBridge request rejected (401). Check SB_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log("SecurityBridge request rejected (403). Check the key's role / scope.")
        return {}
    if resp.status_code == 404:
        log(f"SecurityBridge system {system_id} not found (404).")
        return {}
    if resp.status_code >= 400:
        log(f"SecurityBridge request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return {}
    try:
        payload = resp.json()
    except ValueError:
        log(f"SecurityBridge response was not JSON ({url})")
        return {}
    if isinstance(payload, dict):
        # SecurityBridge wraps single-resource responses in a top-level
        # ``data`` envelope on some routes — unwrap to the inner dict.
        inner = payload.get("data") if "data" in payload else None
        if isinstance(inner, dict):
            return inner
        return payload
    return {}


def fetch_findings(requests_module, host, system_id, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk the SecurityBridge findings catalogue for ``system_id`` via limit/offset."""
    out = []
    url = build_findings_url(host)
    offset = 0
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_findings_params(system_id, offset, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("SecurityBridge request rejected (401). Check SB_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("SecurityBridge request rejected (403). Check the key's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"SecurityBridge findings endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"SecurityBridge findings request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"SecurityBridge findings response was not JSON ({url})")
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
        if isinstance(total, int) and (offset + len(results)) >= total:
            break
        if not extract_next_link(payload):
            # links.next is the canonical exhaustion marker — if it's
            # missing we trust it and stop even if `total` lied.
            if total is None:
                break
        offset += page_size
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    system_id = validate_system_id(env("EXECUTOR_CONFIG_SB_SYSTEM_ID"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_SB_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = validate_host(env("SB_HOST", required=True))
    api_key = env("SB_API_KEY", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(api_key)
    system = fetch_system(requests, host, system_id, headers)
    findings = fetch_findings(requests, host, system_id, headers)

    log(f"Processing {len(findings)} SecurityBridge findings for system {system_id} " f"(min_severity={min_severity})")

    vulns = []
    for finding in findings:
        built = build_vulnerability(finding)
        if built is None:
            continue
        if allowed_severities and built["severity"] not in allowed_severities:
            continue
        vulns.append(built)

    host_record = build_host(system_id, system, vulns)

    params_bits = [f"system_id={system_id}", f"min_severity={min_severity}"]

    output = {
        "hosts": [host_record],
        "command": {
            "tool": "securitybridge_sap",
            "command": "securitybridge_sap",
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
