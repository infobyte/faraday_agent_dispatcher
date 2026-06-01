#!/usr/bin/env python
"""IBM Guardium (DAM / classification) REST importer.

Pulls Database Activity Monitoring (DAM) violations and sensitive-data
classification findings from an IBM Guardium collector via the
``/restAPI/online_dam_violations`` and ``/restAPI/online_classification``
report endpoints and emits Faraday bulk-create JSON on stdout.  Each
unique monitored database server (keyed by the source / server hostname
+ database type + database name surfaced on the violation /
classification record) becomes one Faraday host (Guardium is
database-server-scoped); each per-row observation attaches as a
Faraday vulnerability with the engine prefix ``[DATABASE-SECURITY]``.

Endpoints used:
  POST <GUARDIUM_HOST>/oauth/token
      -> OAuth2 token exchange.  Guardium REST APIs require a bearer
      access-token issued via the OAuth2 password grant.  The dispatcher
      submits ``grant_type=password&username=<user>&password=<pwd>&
      client_id=<id>&client_secret=<secret>`` (the default client_id /
      client_secret are the Guardium-shipped ``guardium`` / unspecified
      pair — override via GUARDIUM_CLIENT_ID / GUARDIUM_CLIENT_SECRET).
  GET <GUARDIUM_HOST>/restAPI/online_dam_violations?reportName=<name>
      -> paginated DAM-violation rows (each row = one observed policy
      violation tied to one database server / database / user).
  GET <GUARDIUM_HOST>/restAPI/online_classification?reportName=<name>
      -> paginated classification rows (each row = one sensitive-data
      classification observation tied to one database server /
      database / table / column).

Pagination is Guardium's canonical ``fetchSize`` + ``indexFrom``
cursor (Guardium reports always paginate over a 1-based index).
Auth is HTTP Bearer with the OAuth2 access token obtained on first
request.  ``GUARDIUM_HOST`` is hard-validated client-side as
``http(s)://host[:port]``; ``GUARDIUM_REPORT_NAME`` is validated as
alphanumeric + spaces + ``._-`` (covers friendly canned report names
like ``Policy Violations``).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Guardium host validation — accept http(s)://host[:port], strip
# trailing slash.  Control chars rejected outright so a header
# injection attempt can't sneak through.  Anchored with \A/\Z (not
# ^/$) so a trailing newline cannot sneak through — Python's default
# `$` matches just before a trailing `\n`.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")

# Guardium canned report names are operator-friendly strings — accept
# alphanumeric + spaces + `._-` up to 128 chars.  Anchored with \A/\Z.
REPORT_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 ._\-]{0,127}\Z")

# OAuth2 client id (Guardium's shipped default REST client id is
# ``guardium`` per the public REST API guide).  Restricted to a safe
# token alphabet up to 64 chars.
CLIENT_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\-]{0,63}\Z")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# Guardium DAM violations surface ``severity`` as the Guardium 3-tier
# enum (HIGH / MED / LOW — plus the ``INFO`` informational tier from
# Vulnerability Assessment-derived reports).  The string enum buckets
# onto Faraday tiers; numeric ``severityScore`` / ``riskScore`` 0-10
# fallback is used when the string is missing or unrecognised.
GUARDIUM_STRING_SEVERITY = {
    "critical": "critical",
    "severe": "critical",
    "high": "high",
    "h": "high",
    "major": "high",
    "important": "high",
    "med": "medium",
    "medium": "medium",
    "m": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "l": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "i": "info",
    "neutral": "info",
    "none": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Guardium violation lifecycle is exposed through ``status`` /
# ``state`` / ``violationStatus`` plus the Guardium-specific
# ``incidentStatus`` (Open / In Review / Closed / Reviewed) and the
# DAM-side ``acknowledged`` boolean.
GUARDIUM_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "active": "open",
    "detected": "open",
    "in_progress": "open",
    "inprogress": "open",
    "in_review": "open",
    "inreview": "open",
    "investigating": "open",
    "triaging": "open",
    "reopened": "open",
    "remediated": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "mitigated": "closed",
    "closed": "closed",
    "completed": "closed",
    "reviewed": "closed",
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
    print(f"{datetime.utcnow()} - Guardium: {msg}", file=sys.stderr, flush=True)


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


def severity_from_guardium(value, numeric=None):
    """Map a Guardium severity string onto a Faraday bucket.

    Accepts the Guardium 3-tier enum (HIGH / MED / LOW) plus the INFO
    tier emitted by VA-derived reports, Faraday-side synonyms (critical /
    severe / major / moderate / minor / informational), numeric inputs
    (0-10 CVSS-style), numeric strings, and falls back to numeric
    bucketing on ``numeric`` when the primary value is missing or
    unrecognised.
    """
    if isinstance(value, bool):
        if numeric is not None:
            return severity_from_cvss(numeric)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        if text in GUARDIUM_STRING_SEVERITY:
            return GUARDIUM_STRING_SEVERITY[text]
        squashed = text.replace("_", "")
        if squashed in GUARDIUM_STRING_SEVERITY:
            return GUARDIUM_STRING_SEVERITY[squashed]
        try:
            return severity_from_cvss(float(value.strip()))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def status_from_guardium(item):
    """Derive Faraday status from a Guardium violation / classification row.

    Walks ``status`` / ``state`` / ``violationStatus`` /
    ``incidentStatus`` / ``Incident Status``.  Respects the Guardium
    ``acknowledged`` boolean as a risk-acceptance gate (acknowledged
    violations move to risk-accepted because the operator has triaged
    + signed off on the finding).
    """
    if not isinstance(item, dict):
        return "open"

    acknowledged = item.get("acknowledged")
    if acknowledged is None:
        acknowledged = item.get("Acknowledged")
    if isinstance(acknowledged, bool) and acknowledged:
        return "risk-accepted"

    for key in (
        "status",
        "state",
        "violationStatus",
        "violation_status",
        "incidentStatus",
        "incident_status",
        "Incident Status",
        "Violation Status",
        "Status",
        "State",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in GUARDIUM_STATUS_BY_STATE:
                return GUARDIUM_STATUS_BY_STATE[compact]
            if squashed in GUARDIUM_STATUS_BY_STATE:
                return GUARDIUM_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    if compact in GUARDIUM_STATUS_BY_STATE:
                        return GUARDIUM_STATUS_BY_STATE[compact]
    return "open"


def validate_min_severity(value):
    """Validate GUARDIUM_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts canonical Faraday buckets plus Guardium synonyms (med ->
    medium, severe -> critical, major / important -> high, moderate /
    warning -> medium, minor -> low, informational / information / h /
    m / l / i -> matching bucket) plus numeric-string CVSS-style input.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "info"
    bucket = GUARDIUM_STRING_SEVERITY.get(text)
    if bucket is None:
        bucket = GUARDIUM_STRING_SEVERITY.get(text.replace("_", ""))
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(str(value).strip()))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"GUARDIUM_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_report_name(value):
    """Validate GUARDIUM_REPORT_NAME.  None / blank -> sys.exit(1)."""
    if value is None or value == "":
        log("GUARDIUM_REPORT_NAME is required")
        sys.exit(1)
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("GUARDIUM_REPORT_NAME contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("GUARDIUM_REPORT_NAME is required")
        sys.exit(1)
    if not REPORT_NAME_RE.match(text):
        log(
            f"GUARDIUM_REPORT_NAME '{text}' is not a valid report name "
            "(alphanumeric + spaces + ._- up to 128 chars)"
        )
        sys.exit(1)
    return text


def validate_host(value):
    """Validate GUARDIUM_HOST.  None / blank -> sys.exit(1)."""
    if value is None or value == "":
        log("GUARDIUM_HOST is required")
        sys.exit(1)
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("GUARDIUM_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("GUARDIUM_HOST is required")
        sys.exit(1)
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"GUARDIUM_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def validate_client_id(value, default="guardium"):
    """Validate GUARDIUM_CLIENT_ID (OAuth2 client identifier)."""
    if value is None or value == "":
        return default
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("GUARDIUM_CLIENT_ID contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return default
    if not CLIENT_ID_RE.match(text):
        log(f"GUARDIUM_CLIENT_ID '{text}' is not a valid client id " "(alphanumeric + ._- up to 64 chars)")
        sys.exit(1)
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def build_token_url(host):
    return f"{host}/oauth/token"


def build_dam_url(host):
    return f"{host}/restAPI/online_dam_violations"


def build_classification_url(host):
    return f"{host}/restAPI/online_classification"


def build_report_params(report_name, index_from, fetch_size):
    """Guardium report pagination uses fetchSize + indexFrom cursors."""
    return {
        "reportName": report_name,
        "fetchSize": int(fetch_size),
        "indexFrom": int(index_from),
    }


def fetch_oauth_token(requests_module, host, user, password, client_id, client_secret):
    """Exchange Guardium user creds for an OAuth2 bearer access token.

    Guardium REST APIs require a bearer access-token via the OAuth2
    ``password`` grant.  Returns the access token string on success;
    sys.exit(1) on auth failure (so the executor doesn't fan out into
    a series of /restAPI calls that will all 401).
    """
    url = build_token_url(host)
    body = {
        "grant_type": "password",
        "username": user,
        "password": password,
        "client_id": client_id,
    }
    if client_secret:
        body["client_secret"] = client_secret
    try:
        resp = requests_module.post(
            url,
            data=body,
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        sys.exit(1)
    if resp.status_code == 401:
        log("Guardium OAuth2 token exchange rejected (401). Check GUARDIUM_USER / GUARDIUM_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        log("Guardium OAuth2 token exchange rejected (403). Check the user's role / scope.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Guardium OAuth2 token exchange failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        sys.exit(1)
    try:
        payload = resp.json()
    except ValueError:
        log(f"Guardium OAuth2 token response was not JSON ({url})")
        sys.exit(1)
    if not isinstance(payload, dict):
        log(f"Guardium OAuth2 token response was not a JSON object ({url})")
        sys.exit(1)
    token = payload.get("access_token") or payload.get("accessToken")
    if not isinstance(token, str) or not token.strip():
        log(f"Guardium OAuth2 token response missing access_token field ({url})")
        sys.exit(1)
    return token.strip()


def auth_headers(token):
    """Guardium REST routes expect ``Authorization: Bearer <access_token>``."""
    return {
        "Authorization": f"Bearer {token or ''}",
        "Accept": "application/json",
    }


def extract_results(body):
    """Pull the result list out of a Guardium report-result envelope.

    Guardium reports vend ``[{...}, {...}]`` on the body root for most
    routes — but some federated stacks wrap the list in ``{"data":
    [...]}`` / ``{"records": [...]}`` / ``{"rows": [...]}``.
    """
    if isinstance(body, list):
        return [it for it in body if isinstance(it, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("data", "records", "rows", "results", "items", "entries"):
        v = body.get(key)
        if isinstance(v, list):
            return [it for it in v if isinstance(it, dict)]
    return []


def extract_count(body):
    """Pull the total record count from a Guardium response envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("total", "count", "totalCount", "total_count", "recordsTotal"):
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
    """Walk a Guardium row for CVE-* ids."""
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

    for key in ("cve", "cveId", "cve_id", "CVE"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "cve_ids", "CVEs"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    for key in (
        "description",
        "Description",
        "policyDescription",
        "policy_description",
        "ruleDescription",
        "rule_description",
        "details",
        "summary",
        "title",
        "name",
        "violation_text",
        "violationText",
        "remediation",
        "recommendation",
    ):
        v = item.get(key)
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)

    return found


def collect_refs(item, source):
    """Walk a Guardium row for Guardium pivot refs + advisory URLs.

    ``source`` is ``dam`` for online_dam_violations rows or
    ``classification`` for online_classification rows so the refs can
    carry the source-of-record pivot.
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

    add(f"Guardium-Source: {source}")

    for label, key in (
        ("Guardium-PolicyRule", "policyRuleId"),
        ("Guardium-PolicyRule", "policy_rule_id"),
        ("Guardium-Policy", "policyName"),
        ("Guardium-Policy", "policy_name"),
        ("Guardium-Policy", "Policy"),
        ("Guardium-Rule", "ruleDescription"),
        ("Guardium-Rule", "rule_description"),
        ("Guardium-Rule", "Rule"),
        ("Guardium-Category", "category"),
        ("Guardium-Category", "policyCategory"),
        ("Guardium-Classification", "classificationName"),
        ("Guardium-Classification", "classification_name"),
        ("Guardium-ClassifierPolicy", "classifierPolicy"),
        ("Guardium-ClassifierPolicy", "classifier_policy"),
        ("Guardium-Server", "serverHostName"),
        ("Guardium-Server", "server_host_name"),
        ("Guardium-Server", "Server"),
        ("Guardium-ServerIp", "serverIp"),
        ("Guardium-ServerIp", "server_ip"),
        ("Guardium-Database", "databaseName"),
        ("Guardium-Database", "database_name"),
        ("Guardium-Database", "Database Name"),
        ("Guardium-DbUser", "dbUserName"),
        ("Guardium-DbUser", "db_user_name"),
        ("Guardium-DbUser", "DB User Name"),
        ("Guardium-DbType", "databaseType"),
        ("Guardium-DbType", "database_type"),
        ("Guardium-Schema", "schemaName"),
        ("Guardium-Schema", "schema_name"),
        ("Guardium-Table", "tableName"),
        ("Guardium-Table", "table_name"),
        ("Guardium-Column", "columnName"),
        ("Guardium-Column", "column_name"),
        ("Guardium-ClientIp", "clientIp"),
        ("Guardium-ClientIp", "client_ip"),
        ("Guardium-SourceProgram", "sourceProgram"),
        ("Guardium-SourceProgram", "source_program"),
        ("Guardium-SqlVerb", "sqlVerb"),
        ("Guardium-SqlVerb", "sql_verb"),
        ("Guardium-OsUser", "osUser"),
        ("Guardium-OsUser", "os_user"),
        ("Guardium-Timestamp", "violationTimestamp"),
        ("Guardium-Timestamp", "violation_timestamp"),
        ("Guardium-Timestamp", "timestamp"),
    ):
        v = item.get(key)
        if isinstance(v, (str, int)) and str(v).strip():
            add(f"{label}: {str(v).strip()}")

    for key in ("references", "advisory_urls", "links", "remediations"):
        entry = item.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("link") or it.get("help_text")
                    if href:
                        add(href)
                elif isinstance(it, str):
                    add(it)
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def row_label(item, source):
    """Build the leading title fragment for a Guardium row."""
    if not isinstance(item, dict):
        return "Guardium violation" if source == "dam" else "Guardium classification"
    for key in (
        "policyName",
        "policy_name",
        "Policy",
        "ruleDescription",
        "rule_description",
        "Rule",
        "classificationName",
        "classification_name",
        "Classification",
        "violationText",
        "violation_text",
        "title",
        "name",
        "description",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            chunk = v.strip()
            return chunk if len(chunk) < 120 else chunk[:117] + "..."
    return "Guardium violation" if source == "dam" else "Guardium classification"


def row_severity_string(item):
    """Pick the severity string field from a Guardium row."""
    if not isinstance(item, dict):
        return None
    return (
        item.get("severity")
        or item.get("Severity")
        or item.get("severityLabel")
        or item.get("severity_label")
        or item.get("risk_level")
        or item.get("riskLevel")
    )


def row_severity_numeric(item):
    """Pick a numeric severity score from a Guardium row (None if absent)."""
    if not isinstance(item, dict):
        return None
    for key in (
        "severityScore",
        "severity_score",
        "riskScore",
        "risk_score",
        "score",
        "cvss",
        "cvssScore",
        "cvss_score",
    ):
        raw = item.get(key)
        if isinstance(raw, bool):
            continue
        if isinstance(raw, (int, float)):
            return float(raw)
        if isinstance(raw, str) and raw.strip():
            try:
                return float(raw.strip())
            except ValueError:
                continue
    return None


def build_vulnerability(item, source):
    """Build a Faraday vulnerability dict from a Guardium row.

    ``source`` is ``dam`` for online_dam_violations rows or
    ``classification`` for online_classification rows.
    """
    if not isinstance(item, dict):
        return None

    severity_numeric = row_severity_numeric(item)
    severity_string = row_severity_string(item)
    severity = severity_from_guardium(severity_string, severity_numeric)
    status = status_from_guardium(item)

    label = row_label(item, source)
    prefix = "[DATABASE-SECURITY]"
    name = f"{prefix} {label}"

    desc_parts = []
    description = (
        item.get("description")
        or item.get("Description")
        or item.get("violationText")
        or item.get("violation_text")
        or item.get("details")
        or item.get("summary")
    )
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    desc_parts.append(f"source={source}")

    for label_key, key in (
        ("id", "id"),
        ("violation_id", "violationId"),
        ("violation_id", "violation_id"),
        ("policy_id", "policyId"),
        ("policy_id", "policy_id"),
        ("policy_name", "policyName"),
        ("policy_name", "policy_name"),
        ("rule_description", "ruleDescription"),
        ("category", "category"),
        ("server_host_name", "serverHostName"),
        ("server_host_name", "server_host_name"),
        ("server_ip", "serverIp"),
        ("database_type", "databaseType"),
        ("database_name", "databaseName"),
        ("db_user_name", "dbUserName"),
        ("client_ip", "clientIp"),
        ("client_host_name", "clientHostName"),
        ("source_program", "sourceProgram"),
        ("sql_verb", "sqlVerb"),
        ("os_user", "osUser"),
        ("violation_timestamp", "violationTimestamp"),
        ("schema_name", "schemaName"),
        ("table_name", "tableName"),
        ("column_name", "columnName"),
        ("classification_name", "classificationName"),
        ("classifier_policy", "classifierPolicy"),
        ("severity", "severity"),
        ("status", "status"),
        ("incident_status", "incidentStatus"),
        ("acknowledged", "acknowledged"),
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

    cves = collect_cves(item)
    refs = collect_refs(item, source)

    resolution = ""
    remediations = (
        item.get("remediation") or item.get("remediations") or item.get("recommendation") or item.get("resolution")
    )
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
            "Investigate the violation in the Guardium console "
            "(Investigate -> Outliers / Policy Violations -> select the "
            "row) and drive remediation through the DBA team for the "
            "monitored database; acknowledge the violation in Guardium "
            "(sets acknowledged=true) once the underlying issue has been "
            "triaged."
        )

    external_id = str(
        item.get("id")
        or item.get("violationId")
        or item.get("violation_id")
        or item.get("incidentId")
        or item.get("incident_id")
        or (cves[0] if cves else "")
        or ""
    )

    tags = ["ibm", "guardium", "database-security", "ibm-guardium"]
    if source == "dam":
        tags.append("dam")
    else:
        tags.append("classification")

    return {
        "name": str(name).strip()[:200] or f"Guardium row {external_id}",
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
        "tags": tags,
    }


def server_hostname(item, fallback):
    """Pick the canonical hostname for a Guardium row's database server."""
    if isinstance(item, dict):
        for key in (
            "serverHostName",
            "server_host_name",
            "Server",
            "serverHost",
            "hostName",
            "host_name",
        ):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return ""


def server_ip(item):
    """Pick the database server's IP address (if surfaced)."""
    if not isinstance(item, dict):
        return "0.0.0.0"
    for key in ("serverIp", "server_ip", "Server IP", "serverIpAddress", "server_ip_address"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "0.0.0.0"


def server_os(item):
    """Build the host.os string from a Guardium row.

    Guardium is database-server-scoped, so host.os carries the database
    product + version label (e.g. ``Oracle 19c (Guardium monitored)``)
    when the row surfaces it, falling back to a literal ``Guardium
    monitored database`` if no product metadata is present.
    """
    if not isinstance(item, dict):
        return "Guardium monitored database"
    db_type = (
        item.get("databaseType")
        or item.get("database_type")
        or item.get("DB Type")
        or item.get("DBType")
        or item.get("dbType")
    )
    db_version = (
        item.get("databaseVersion")
        or item.get("database_version")
        or item.get("DBVersion")
        or item.get("dbVersion")
        or item.get("DB Version")
    )
    parts = []
    if isinstance(db_type, str) and db_type.strip():
        parts.append(db_type.strip())
    if isinstance(db_version, (str, int, float)) and str(db_version).strip():
        parts.append(str(db_version).strip())
    if parts:
        return " ".join(parts) + " (Guardium monitored)"
    return "Guardium monitored database"


def server_key(item):
    """Build the host-grouping key for a Guardium row.

    Guardium DAM violations + classification rows always carry a
    ``serverHostName`` (or ``serverIp``).  Group by hostname when
    available — else by IP — else fall back to a synthetic
    ``unknown`` bucket so orphans aren't silently dropped.
    """
    if not isinstance(item, dict):
        return "unknown"
    for key in (
        "serverHostName",
        "server_host_name",
        "Server",
        "serverHost",
        "hostName",
        "host_name",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("serverIp", "server_ip", "Server IP"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "unknown"


def build_host(key, sample_row, vulns):
    """Build a Faraday host record for a Guardium-monitored database server."""
    if not isinstance(sample_row, dict):
        sample_row = {}
    hostname = server_hostname(sample_row, key)
    os_str = server_os(sample_row)
    ip = server_ip(sample_row)

    desc_parts = [f"server={key}"]
    for label_key, key_name in (
        ("server_host_name", "serverHostName"),
        ("server_ip", "serverIp"),
        ("database_type", "databaseType"),
        ("database_name", "databaseName"),
        ("database_version", "databaseVersion"),
        ("schema_name", "schemaName"),
    ):
        v = sample_row.get(key_name)
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


def fetch_report(
    requests_module,
    url,
    report_name,
    headers,
    max_pages=MAX_PAGES,
    page_size=PAGE_SIZE,
):
    """Walk a Guardium report endpoint via fetchSize + indexFrom pagination."""
    out = []
    index_from = 1
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_report_params(report_name, index_from, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Guardium request rejected (401). Check GUARDIUM_USER / GUARDIUM_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Guardium request rejected (403). Check the user's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"Guardium report endpoint 404 for {url} (reportName={report_name})")
            return out
        if resp.status_code >= 400:
            log(f"Guardium report request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Guardium report response was not JSON ({url})")
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
        if isinstance(total, int) and len(out) >= total:
            break
        index_from += page_size
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination for {url}")
    return out


def main():
    started = time.time()

    report_name = validate_report_name(env("EXECUTOR_CONFIG_GUARDIUM_REPORT_NAME"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_GUARDIUM_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = validate_host(env("GUARDIUM_HOST", required=True))
    user = env("GUARDIUM_USER", required=True)
    password = env("GUARDIUM_PASSWORD", required=True)
    client_id = validate_client_id(env("GUARDIUM_CLIENT_ID"))
    client_secret = env("GUARDIUM_CLIENT_SECRET") or ""

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_oauth_token(requests, host, user, password, client_id, client_secret)
    headers = auth_headers(token)

    dam_rows = fetch_report(requests, build_dam_url(host), report_name, headers)
    classification_rows = fetch_report(requests, build_classification_url(host), report_name, headers)

    log(
        f"Processing {len(dam_rows)} DAM violations + "
        f"{len(classification_rows)} classification rows "
        f"(report={report_name}, min_severity={min_severity})"
    )

    # Group rows by server key so each monitored database server
    # becomes one Faraday host record carrying both DAM + classification
    # observations attached to it.
    rows_by_server = {}
    sample_by_server = {}

    def fold(row, source):
        built = build_vulnerability(row, source)
        if built is None:
            return
        if allowed_severities and built["severity"] not in allowed_severities:
            return
        key = server_key(row)
        rows_by_server.setdefault(key, []).append(built)
        sample_by_server.setdefault(key, row)

    for r in dam_rows:
        fold(r, "dam")
    for r in classification_rows:
        fold(r, "classification")

    hosts = []
    for key, vulns in rows_by_server.items():
        hosts.append(build_host(key, sample_by_server.get(key, {}), vulns))

    # Always emit a synthetic placeholder if nothing came back so the
    # Faraday workspace records the Guardium query was processed.
    if not hosts:
        hosts.append(
            {
                "ip": "0.0.0.0",
                "os": "Guardium monitored database (empty)",
                "hostnames": [],
                "mac": "",
                "description": (
                    f"report_name={report_name} | " "no Guardium DAM violations or classification rows returned"
                ),
                "vulnerabilities": [],
            }
        )

    params_bits = [
        f"report_name={report_name}",
        f"min_severity={min_severity}",
    ]

    output = {
        "hosts": hosts,
        "command": {
            "tool": "ibm_guardium",
            "command": "ibm_guardium",
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
