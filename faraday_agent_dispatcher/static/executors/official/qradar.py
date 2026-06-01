#!/usr/bin/env python
"""IBM QRadar SIEM importer.

Pulls security findings out of an IBM QRadar tenant via the REST API
and emits Faraday bulk-create JSON to stdout.  The executor has two
modes that can run together or independently in a single scan:

  1. **AQL (Ariel Query Language) search**.  When
     ``QRADAR_AQL_QUERY`` is set the dispatcher posts the AQL string
     to the Ariel search endpoint, polls until the search job
     completes, paginates the result rows, and emits one Faraday
     vulnerability per row attached to a synthetic per-search host
     record keyed on the QRadar endpoint hostname (Ariel's surface is
     search-scoped, not asset-scoped, so the host record is a
     synthetic bucket rather than an IP-keyed asset).
  2. **Offense pull**.  When ``QRADAR_OFFENSE_STATUS`` is set the
     dispatcher GETs the SIEM offenses list filtered by status (one of
     ``OPEN`` / ``HIDDEN`` / ``CLOSED``) and emits one Faraday
     vulnerability per offense attached to the same synthetic host
     record.  Offenses don't pin to a single asset (an offense
     correlates across multiple events / sources / destinations) so
     they share the search-scoped host bucket.

Each result row attaches as a Faraday vulnerability with the engine
prefix ``[SIEM]``.

Endpoints used (AQL search):
  POST {QRADAR_HOST}/api/ariel/searches?query_expression=<AQL>
      -> create an Ariel search.  Returns
      ``{"search_id": "<uuid>", "status": "WAIT" | "EXECUTE" | ...}``.
  GET  {QRADAR_HOST}/api/ariel/searches/{search_id}
      -> poll search state.  Body carries ``status`` (one of WAIT /
      EXECUTE / SORTING / COMPLETED / CANCELED / ERROR).  Polled until
      COMPLETED (or terminal failure) with a 2-second sleep, capped at
      ``MAX_POLLS`` (~5 minutes by default).
  GET  {QRADAR_HOST}/api/ariel/searches/{search_id}/results?Range=items=M-N
      -> paginated result rows.  QRadar's REST API uses an HTTP
      ``Range: items=M-N`` header for pagination.  Each row maps onto
      a Faraday vulnerability — severity bucketed from a freeform
      ``severity`` column (informational / low / medium / high /
      critical) and / or a numeric ``severity`` 1-10 fallback.

Endpoints used (Offense pull):
  GET  {QRADAR_HOST}/api/siem/offenses?filter=status%3DOPEN&Range=items=M-N
      -> paginated offense list filtered by status.  Each offense
      surfaces ``magnitude`` (1-10 computed), ``severity`` (1-10),
      ``credibility`` (1-10), ``relevance`` (1-10), ``status`` (OPEN /
      HIDDEN / CLOSED), ``description``, ``offense_type``, ``rules``,
      ``source_address_ids``, ``local_destination_address_ids``,
      ``event_count``, ``flow_count``, ``start_time``, ``last_updated_time``.

Auth: QRadar accepts a session-key style ``SEC: <QRADAR_SEC_TOKEN>``
header (created in QRadar Web under ``Admin -> User Management ->
Authorized Services -> Add Authorized Service``; the resulting service
token has a configurable role + security profile).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# QRadar search ids are UUIDs (lowercase hex + hyphens) but some
# customised deployments / forks emit shorter alnum ids — keep the
# shape strict enough that a garbage value can't fan out into junk URLs.
SEARCH_ID_RE = re.compile(r"^[A-Za-z0-9_\-]+$")
# Lenient http(s)://host[:port] URL recogniser (used to validate
# QRADAR_HOST client-side so a typo can't fan out into "None/api/siem
# /offenses" calls).
HOST_RE = re.compile(r"^https?://[A-Za-z0-9_.\-]+(?::\d{1,5})?(?:/[^\s]*)?$")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100
MAX_POLLS = 150  # ~5 minutes at POLL_INTERVAL=2s
POLL_INTERVAL = 2

# QRadar AQL columns surface ``severity`` as either a freeform string
# enum (Informational / Low / Medium / High / Critical) or a numeric
# 1-10 scale (QRadar Offenses).  The string enum buckets onto Faraday
# tiers; numeric bucketing is used as a fallback when the string is
# missing or unrecognised.
QRADAR_STRING_SEVERITY = {
    "critical": "critical",
    "fatal": "critical",
    "severe": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "minor": "low",
    "notice": "low",
    "info": "info",
    "informational": "info",
    "debug": "info",
    "unknown": "info",
    "none": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# QRadar SIEM Offense status is "OPEN" / "HIDDEN" / "CLOSED" (the
# closed state may carry a closing_reason_id).  HIDDEN is an
# analyst-side suppression rather than a remediation -> map onto
# Faraday risk-accepted.
QRADAR_OFFENSE_STATUS_TO_FARADAY = {
    "open": "open",
    "active": "open",
    "new": "open",
    "in_progress": "open",
    "inprogress": "open",
    "hidden": "risk-accepted",
    "suppressed": "risk-accepted",
    "ignored": "risk-accepted",
    "closed": "closed",
    "resolved": "closed",
    "remediated": "closed",
    "fixed": "closed",
    "mitigated": "closed",
}


# QRadar Offenses surface ``severity`` / ``magnitude`` on a 1-10
# scale.  Map onto Faraday buckets.  1-3 low, 4-6 medium, 7-8 high,
# 9-10 critical, 0 / negative info.
def severity_from_qradar_110(value):
    """Bucket a QRadar 1-10 severity / magnitude onto a Faraday tier."""
    if isinstance(value, bool):
        return "info"
    try:
        as_float = float(value)
    except (TypeError, ValueError):
        return "info"
    if as_float <= 0:
        return "info"
    if as_float < 4:
        return "low"
    if as_float < 7:
        return "medium"
    if as_float < 9:
        return "high"
    if as_float <= 10:
        return "critical"
    return "info"


VALID_OFFENSE_STATUSES = ("OPEN", "HIDDEN", "CLOSED")


def log(msg):
    print(f"{datetime.utcnow()} - QRadar: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
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


def severity_from_qradar(value, numeric=None):
    """Map a QRadar AQL ``severity`` column onto a Faraday bucket.

    Accepts the freeform string enum (informational / low / medium /
    high / critical), Faraday-side synonyms, numeric inputs (QRadar
    1-10 scale OR 0-10 CVSS-style), numeric strings, and falls back to
    numeric bucketing on ``numeric`` when the primary value is missing
    or unrecognised.
    """
    if isinstance(value, bool):
        if numeric is not None:
            return severity_from_qradar_110(numeric)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_qradar_110(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower()
        if text in QRADAR_STRING_SEVERITY:
            return QRADAR_STRING_SEVERITY[text]
        try:
            as_float = float(text)
            return severity_from_qradar_110(as_float)
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_qradar_110(numeric)
    return "info"


def status_from_qradar(item):
    """Derive Faraday status from a QRadar offense / AQL row.

    Walks ``status`` / ``offense_status`` / ``state`` and accepts
    QRadar's OPEN / HIDDEN / CLOSED enum.  Falls back to ``open`` when
    nothing is recognisable.
    """
    if not isinstance(item, dict):
        return "open"
    for key in (
        "status",
        "offense_status",
        "state",
        "Status",
        "State",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            if compact in QRADAR_OFFENSE_STATUS_TO_FARADAY:
                return QRADAR_OFFENSE_STATUS_TO_FARADAY[compact]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    if compact in QRADAR_OFFENSE_STATUS_TO_FARADAY:
                        return QRADAR_OFFENSE_STATUS_TO_FARADAY[compact]
    return "open"


def validate_min_severity(value):
    """Validate QRADAR_MIN_SEVERITY (optional severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus QRadar-side synonyms
    (informational / debug -> info, warning / moderate -> medium,
    notice / minor -> low, fatal / severe -> critical) plus numeric
    input bucketed via the QRadar 1-10 scale.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = QRADAR_STRING_SEVERITY.get(text)
    if bucket is None:
        try:
            bucket = severity_from_qradar_110(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"QRADAR_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_aql_query(value):
    """Validate QRADAR_AQL_QUERY.

    None / blank -> "" (no AQL search will run; offense pull may still
    fire).  AQL is freeform SQL-like text — we just sanity-check for
    control characters that QRadar's URL-encoded query parameter
    can't carry cleanly.  No SELECT-style hard requirement because
    QRadar accepts both SELECT and DESCRIBE / SHOW / etc. statements.
    """
    if value is None or value == "":
        return ""
    raw = str(value)
    if "\n" in raw or "\r" in raw or "\t" in raw:
        log("QRADAR_AQL_QUERY contains a control character; ignoring")
        return ""
    text = raw.strip()
    if not text:
        return ""
    return text


def validate_offense_status(value):
    """Validate QRADAR_OFFENSE_STATUS.

    None / blank -> "" (no offense pull will run; AQL search may still
    fire).  Accepts QRadar's documented enum (OPEN / HIDDEN / CLOSED)
    plus case-insensitive variants.  Garbage values are logged +
    ignored rather than fanned out into a 400.
    """
    if value is None or value == "":
        return ""
    text = str(value).strip().upper()
    if not text:
        return ""
    if text in VALID_OFFENSE_STATUSES:
        return text
    log(f"QRADAR_OFFENSE_STATUS '{value}' not recognised; ignoring")
    return ""


def validate_host(value):
    """Validate QRADAR_HOST.

    None / blank -> sys.exit(1).  QRadar's REST endpoint is typically
    ``https://<console>`` (no port — the console listens on 443).  We
    hard-enforce the http(s)://host[:port] shape client-side so a typo
    can't fan out into "None/api/siem/offenses" calls.  Trailing
    slashes are stripped.
    """
    if value is None or value == "":
        log("QRADAR_HOST is required")
        sys.exit(1)
    text = str(value).strip()
    if not text:
        log("QRADAR_HOST is required")
        sys.exit(1)
    if not HOST_RE.match(text):
        log(f"QRADAR_HOST '{text}' is not a valid http(s)://host[:port] URL")
        sys.exit(1)
    return text.rstrip("/")


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(token):
    """Build the QRadar REST auth headers (``SEC: <token>``)."""
    headers = {
        "Accept": "application/json",
        "Version": "12.0",
    }
    if isinstance(token, str) and token.strip():
        headers["SEC"] = token.strip()
    return headers


def build_ariel_search_url(host):
    return f"{host}/api/ariel/searches"


def build_ariel_search_status_url(host, search_id):
    return f"{host}/api/ariel/searches/{search_id}"


def build_ariel_results_url(host, search_id):
    return f"{host}/api/ariel/searches/{search_id}/results"


def build_offenses_url(host):
    return f"{host}/api/siem/offenses"


def build_ariel_search_params(aql):
    """Build the query-string body for POST /api/ariel/searches.

    QRadar's Ariel endpoint expects ``query_expression`` as a URL
    query parameter (not a form body); requests handles the encoding
    via the ``params`` arg.
    """
    return {"query_expression": aql}


def build_range_header(offset, count):
    """Build the QRadar pagination ``Range: items=M-N`` header.

    QRadar's REST API uses HTTP Range headers for pagination — the
    last index is inclusive, so ``items=0-99`` returns 100 rows.
    """
    return f"items={int(offset)}-{int(offset) + int(count) - 1}"


def build_offense_filter(status):
    """Build the QRadar offense filter query.

    ``status`` is the validated QRADAR_OFFENSE_STATUS (one of OPEN /
    HIDDEN / CLOSED).  None / blank -> no filter, pull everything.
    """
    if not status:
        return None
    return f"status={status}"


def extract_search_id(body):
    """Pull the search_id out of a QRadar Ariel POST response."""
    if isinstance(body, dict):
        sid = body.get("search_id") or body.get("cursor_id")
        if isinstance(sid, str) and sid.strip():
            return sid.strip()
    return ""


def extract_search_status(body):
    """Pull the AQL search ``status`` field from a status payload."""
    if not isinstance(body, dict):
        return ""
    status = body.get("status")
    if isinstance(status, str):
        return status.strip().upper()
    return ""


def extract_ariel_results(body):
    """Pull the result-row list out of a QRadar Ariel /results envelope.

    QRadar's Ariel /results endpoint surfaces the rows under a key
    named after the AQL table being queried (``events`` / ``flows`` /
    ``offenses`` / ``assets`` / ``simarcs`` / etc.).  Walk all
    list-valued keys and return the first non-empty match.
    """
    if not isinstance(body, dict):
        return []
    for key in ("events", "flows", "offenses", "assets", "simarcs", "results", "rows", "data"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    for value in body.values():
        if isinstance(value, list) and value and isinstance(value[0], dict):
            return value
    return []


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
    """Walk a QRadar offense / row for CVE-* ids."""
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

    for key in (
        "description",
        "offense_source",
        "offense_type_name",
        "rule_name",
        "rules",
        "categories",
        "summary",
        "name",
        "title",
        "message",
        "signature",
    ):
        v = item.get(key)
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)
                elif isinstance(entry, dict):
                    scan(entry.get("name") or entry.get("description"))
    return found


def collect_refs(item, source="offense"):
    """Walk a QRadar offense / AQL row for QRadar pivots + advisory URLs."""
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

    offense_id = item.get("id") or item.get("offense_id")
    if offense_id is not None:
        s = str(offense_id).strip()
        if s:
            if source == "offense":
                add(f"QRadar-Offense: {s}")
            else:
                add(f"QRadar-Event: {s}")

    offense_type = item.get("offense_type") or item.get("offense_type_name")
    if isinstance(offense_type, (str, int)):
        s = str(offense_type).strip()
        if s:
            add(f"QRadar-OffenseType: {s}")

    rules = item.get("rules")
    if isinstance(rules, list):
        for r in rules:
            if isinstance(r, dict):
                name = r.get("name") or r.get("id")
                if name:
                    add(f"QRadar-Rule: {name}")
            elif isinstance(r, (str, int)):
                add(f"QRadar-Rule: {r}")

    categories = item.get("categories")
    if isinstance(categories, list):
        for c in categories:
            if isinstance(c, str) and c.strip():
                add(f"QRadar-Category: {c.strip()}")
            elif isinstance(c, dict):
                name = c.get("name") or c.get("id")
                if name:
                    add(f"QRadar-Category: {name}")

    domain_id = item.get("domain_id")
    if domain_id is not None:
        s = str(domain_id).strip()
        if s:
            add(f"QRadar-Domain: {s}")

    log_source_ids = item.get("log_sources")
    if isinstance(log_source_ids, list):
        for ls in log_source_ids:
            if isinstance(ls, dict):
                name = ls.get("name") or ls.get("id")
                if name:
                    add(f"QRadar-LogSource: {name}")
            elif isinstance(ls, (str, int)):
                add(f"QRadar-LogSource: {ls}")

    for key in ("references", "url", "urls", "advisory_urls", "links"):
        entry = item.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("link") or it.get("name")
                    if href:
                        add(href)
                elif isinstance(it, str):
                    add(it)
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def offense_label(item):
    """Build the leading title fragment for a QRadar offense."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "description",
        "offense_type_name",
        "offense_source",
        "name",
        "title",
        "summary",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().split("\n", 1)[0][:200]
    offense_id = item.get("id") or item.get("offense_id")
    if offense_id is not None:
        return f"Offense {offense_id}"
    return "QRadar offense"


def ariel_label(item):
    """Build the leading title fragment for a QRadar AQL result row."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "qid_name",
        "qidname",
        "rule_name",
        "ruleName",
        "category_name",
        "categoryname",
        "high_level_category_name",
        "low_level_category_name",
        "eventname",
        "name",
        "title",
        "signature",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("description", "summary", "message"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().split("\n", 1)[0][:200]
    return "QRadar event"


def build_offense_vulnerability(item):
    """Build a Faraday vulnerability dict from a QRadar offense."""
    if not isinstance(item, dict):
        return None

    # QRadar offenses surface severity 1-10 + magnitude 1-10.  Prefer
    # the offense severity if present, fall back to magnitude.
    raw_severity = item.get("severity")
    raw_magnitude = item.get("magnitude")
    severity = severity_from_qradar(raw_severity, raw_magnitude)
    status = status_from_qradar(item)

    label = offense_label(item)
    name = f"[SIEM] {label}" if label else "[SIEM] QRadar offense"

    desc_parts = []
    description = item.get("description") or item.get("offense_source")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    for label_key, key in (
        ("offense_id", "id"),
        ("offense_type", "offense_type"),
        ("offense_type_name", "offense_type_name"),
        ("severity", "severity"),
        ("magnitude", "magnitude"),
        ("credibility", "credibility"),
        ("relevance", "relevance"),
        ("event_count", "event_count"),
        ("flow_count", "flow_count"),
        ("source_count", "source_count"),
        ("destination_count", "destination_count"),
        ("status", "status"),
        ("offense_source", "offense_source"),
        ("domain_id", "domain_id"),
        ("start_time", "start_time"),
        ("last_updated_time", "last_updated_time"),
        ("inactive", "inactive"),
        ("protected", "protected"),
        ("closing_reason_id", "closing_reason_id"),
        ("closing_user", "closing_user"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    cves = collect_cves(item)
    refs = collect_refs(item, source="offense")

    resolution = ""
    remediation = item.get("remediation") or item.get("recommendation") or item.get("resolution")
    if isinstance(remediation, str) and remediation.strip():
        resolution = remediation.strip()
    if not resolution:
        resolution = (
            "Investigate the offense in the QRadar console (Offenses tab "
            "-> All Offenses, drill in via the offense id) and drive "
            "remediation through the owning rule / asset team; close the "
            "offense via the QRadar workflow (Close with a closing_reason_id) "
            "once handled so the offense lifecycle stays in sync."
        )

    offense_id = item.get("id") or item.get("offense_id")
    external_id = str(offense_id) if offense_id is not None else ""
    if not external_id and cves:
        external_id = cves[0]

    return {
        "name": str(name).strip()[:200] or f"QRadar offense {external_id}",
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
        "tags": ["qradar", "siem", "siem-analytics"],
    }


def build_ariel_vulnerability(item):
    """Build a Faraday vulnerability dict from a QRadar AQL result row."""
    if not isinstance(item, dict):
        return None

    raw_severity_numeric = None
    severity_keys = ("severity", "Severity", "severity_id", "severityId")
    for key in severity_keys:
        v = item.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            raw_severity_numeric = float(v)
            break

    severity_string = None
    for key in ("severity_label", "severityLabel", "level", "severity"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            severity_string = v
            break

    severity = severity_from_qradar(severity_string, raw_severity_numeric)
    status = status_from_qradar(item)

    label = ariel_label(item)
    name = f"[SIEM] {label}" if label else "[SIEM] QRadar event"

    desc_parts = []
    description = item.get("description") or item.get("Description") or item.get("message") or item.get("summary")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    # AQL rows are freeform — surface whatever well-known fields are
    # present without enumerating every possible column.
    for label_key, key in (
        ("qid", "qid"),
        ("qid_name", "qid_name"),
        ("qidname", "qidname"),
        ("eventname", "eventname"),
        ("category", "category"),
        ("category_name", "category_name"),
        ("high_level_category_name", "high_level_category_name"),
        ("low_level_category_name", "low_level_category_name"),
        ("rule_name", "rule_name"),
        ("sourceip", "sourceip"),
        ("sourceaddress", "sourceaddress"),
        ("destinationip", "destinationip"),
        ("destinationaddress", "destinationaddress"),
        ("sourceport", "sourceport"),
        ("destinationport", "destinationport"),
        ("username", "username"),
        ("logsourcename", "logsourcename"),
        ("magnitude", "magnitude"),
        ("severity", "severity"),
        ("credibility", "credibility"),
        ("relevance", "relevance"),
        ("eventcount", "eventcount"),
        ("starttime", "starttime"),
        ("endtime", "endtime"),
        ("devicetime", "devicetime"),
        ("status", "status"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    payload = item.get("payload") or item.get("raw_message") or item.get("utf8_payload")
    if isinstance(payload, str) and payload.strip():
        snippet = payload.strip()
        if len(snippet) > 2000:
            snippet = snippet[:2000] + "...(truncated)"
        desc_parts.append(f"payload: {snippet}")

    cves = collect_cves(item)
    refs = collect_refs(item, source="event")

    resolution = ""
    remediation = item.get("remediation") or item.get("recommendation") or item.get("resolution")
    if isinstance(remediation, str) and remediation.strip():
        resolution = remediation.strip()
    if not resolution:
        resolution = (
            "Investigate the AQL result row in the QRadar console (Log "
            "Activity tab; pivot on the qid / rule_name / sourceip) and "
            "drive remediation through the owning rule / asset team."
        )

    external_id = str(
        item.get("event_id") or item.get("eventid") or item.get("qid") or item.get("id") or (cves[0] if cves else "")
    )

    return {
        "name": str(name).strip()[:200] or f"QRadar event {external_id}",
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
        "tags": ["qradar", "siem", "siem-analytics"],
    }


def synthetic_hostname(host):
    """Pick the synthetic host's hostname from the QRadar endpoint URL."""
    if not isinstance(host, str):
        return ""
    text = host.strip()
    if not text:
        return ""
    m = re.match(r"^https?://([^:/]+)", text)
    if m:
        return m.group(1).strip().lower()
    return text


def build_host(host, aql, offense_status, search_id, vulns):
    """Build a Faraday host record for the synthetic QRadar-search bucket."""
    hostname = synthetic_hostname(host)
    os_str = f"QRadar ({hostname})" if hostname else "QRadar"

    desc_parts = [f"qradar_host={host}"]
    if hostname:
        desc_parts.append(f"hostname={hostname}")
    if aql:
        desc_parts.append(f"aql={aql}")
    if offense_status:
        desc_parts.append(f"offense_status={offense_status}")
    if search_id:
        desc_parts.append(f"search_id={search_id}")
    if vulns:
        desc_parts.append(f"results={len(vulns)}")

    return {
        "ip": "0.0.0.0",
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def create_ariel_search(requests_module, host, headers, aql):
    """POST /api/ariel/searches and return the search_id."""
    url = build_ariel_search_url(host)
    params = build_ariel_search_params(aql)
    try:
        resp = requests_module.post(url, headers=headers, params=params, timeout=TIMEOUT, verify=True)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        return ""
    if resp.status_code == 401:
        log("QRadar request rejected (401). Check QRADAR_SEC_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log("QRadar request rejected (403). Check the service token's role / security profile.")
        return ""
    if resp.status_code == 422:
        log(f"QRadar rejected the AQL query (422): {resp.text[:500]}")
        return ""
    if resp.status_code >= 400:
        log(f"QRadar Ariel search creation failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return ""
    sid = ""
    try:
        sid = extract_search_id(resp.json())
    except ValueError:
        log(f"QRadar Ariel search response was not JSON ({url})")
        return ""
    if not sid:
        log("QRadar Ariel search succeeded but no search_id was returned")
        return ""
    if not SEARCH_ID_RE.match(sid):
        log(f"QRadar returned a malformed search_id '{sid}'; refusing to poll")
        return ""
    log(f"created Ariel search search_id={sid}")
    return sid


def wait_for_ariel_search(
    requests_module, host, search_id, headers, max_polls=MAX_POLLS, interval=POLL_INTERVAL, sleep_fn=time.sleep
):
    """Poll /api/ariel/searches/{search_id} until COMPLETED / terminal failure / timeout."""
    url = build_ariel_search_status_url(host, search_id)
    polls = 0
    while polls < max_polls:
        try:
            resp = requests_module.get(url, headers=headers, timeout=TIMEOUT, verify=True)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            return False
        if resp.status_code == 401:
            log("QRadar request rejected (401). Check QRADAR_SEC_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("QRadar request rejected (403). Check the service token's role / security profile.")
            return False
        if resp.status_code == 404:
            log(f"QRadar Ariel search {search_id} not found (404).")
            return False
        if resp.status_code >= 400:
            log(f"QRadar Ariel status request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return False
        try:
            payload = resp.json()
        except ValueError:
            log(f"QRadar Ariel status response was not JSON ({url})")
            return False
        state = extract_search_status(payload)
        if state == "COMPLETED":
            return True
        if state in ("CANCELED", "ERROR"):
            log(f"QRadar Ariel search {search_id} ended in status={state}")
            return False
        polls += 1
        sleep_fn(interval)
    log(f"hit MAX_POLLS={max_polls}; abandoning search_id={search_id}")
    return False


def fetch_ariel_results(requests_module, host, search_id, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk /api/ariel/searches/{search_id}/results via Range: items=M-N pagination."""
    out = []
    url = build_ariel_results_url(host, search_id)
    offset = 0
    pages_walked = 0
    while pages_walked < max_pages:
        page_headers = dict(headers)
        page_headers["Range"] = build_range_header(offset, page_size)
        try:
            resp = requests_module.get(url, headers=page_headers, timeout=TIMEOUT, verify=True)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("QRadar request rejected (401). Check QRADAR_SEC_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("QRadar request rejected (403). Check the service token's role / security profile.")
            return out
        if resp.status_code == 204:
            return out
        if resp.status_code == 416:
            # Range Not Satisfiable -> reached the end.
            return out
        if resp.status_code >= 400:
            log(f"QRadar Ariel results request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"QRadar Ariel results response was not JSON ({url})")
            return out
        results = extract_ariel_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < page_size:
            break
        offset += page_size
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def fetch_offenses(requests_module, host, headers, offense_status, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk /api/siem/offenses via Range: items=M-N pagination, filtered by status."""
    out = []
    url = build_offenses_url(host)
    offset = 0
    pages_walked = 0
    while pages_walked < max_pages:
        page_headers = dict(headers)
        page_headers["Range"] = build_range_header(offset, page_size)
        params = {}
        filter_expr = build_offense_filter(offense_status)
        if filter_expr:
            params["filter"] = filter_expr
        try:
            resp = requests_module.get(
                url,
                headers=page_headers,
                params=params or None,
                timeout=TIMEOUT,
                verify=True,
            )
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("QRadar request rejected (401). Check QRADAR_SEC_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("QRadar request rejected (403). Check the service token's role / security profile.")
            return out
        if resp.status_code == 204:
            return out
        if resp.status_code == 416:
            return out
        if resp.status_code >= 400:
            log(f"QRadar offenses request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"QRadar offenses response was not JSON ({url})")
            return out
        # /api/siem/offenses returns a top-level JSON list (no envelope).
        if isinstance(payload, list):
            results = payload
        elif isinstance(payload, dict):
            results = extract_ariel_results(payload)
        else:
            results = []
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < page_size:
            break
        offset += page_size
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    aql = validate_aql_query(env("EXECUTOR_CONFIG_QRADAR_AQL_QUERY"))
    offense_status = validate_offense_status(env("EXECUTOR_CONFIG_QRADAR_OFFENSE_STATUS"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_QRADAR_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    if not aql and not offense_status:
        log("Provide QRADAR_AQL_QUERY and/or QRADAR_OFFENSE_STATUS")
        sys.exit(1)

    host = validate_host(env("QRADAR_HOST", required=True))
    token = env("QRADAR_SEC_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    log("auth_mode=sec-token")

    vulns = []
    search_id = ""

    if aql:
        search_id = create_ariel_search(requests, host, headers, aql)
        if search_id:
            if wait_for_ariel_search(requests, host, search_id, headers):
                ariel_rows = fetch_ariel_results(requests, host, search_id, headers)
                log(
                    f"Processing {len(ariel_rows)} Ariel result rows for "
                    f"search_id={search_id} (min_severity={min_severity})"
                )
                for row in ariel_rows:
                    built = build_ariel_vulnerability(row)
                    if built is None:
                        continue
                    if allowed_severities and built["severity"] not in allowed_severities:
                        continue
                    vulns.append(built)

    if offense_status:
        offenses = fetch_offenses(requests, host, headers, offense_status)
        log(f"Processing {len(offenses)} QRadar offenses (status={offense_status}, " f"min_severity={min_severity})")
        for off in offenses:
            built = build_offense_vulnerability(off)
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)

    host_record = build_host(host, aql, offense_status, search_id, vulns)

    params_bits = [
        f"aql={aql or 'none'}",
        f"offense_status={offense_status or 'none'}",
        f"search_id={search_id or 'none'}",
        f"min_severity={min_severity}",
    ]

    output = {
        "hosts": [host_record],
        "command": {
            "tool": "qradar",
            "command": "qradar",
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
