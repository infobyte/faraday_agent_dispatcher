#!/usr/bin/env python
"""Uptycs cloud workload / XDR importer.

Pulls assets and alerts out of an Uptycs tenant via the REST API and
emits Faraday bulk-create JSON to stdout.  Uptycs is asset-scoped —
unlike Splunk / QRadar (search-scoped) the platform maintains a
per-endpoint inventory keyed by ``assetId`` (servers, workstations,
containers, cloud workloads).  Each Uptycs asset becomes one Faraday
host record (carrying the asset's hostname, IPs, OS string, and tag
catalogue); each Uptycs alert is converted into a Faraday vulnerability
with the engine prefix ``[SIEM]`` (the executor sits in the
``siem-analytics`` group alongside splunk / qradar so the naming is
consistent with peers).

Endpoints used:
  GET {UPTYCS_HOST}/public/api/customers/{cid}/assets
      -> paginated asset catalogue.  When ``UPTYCS_TAG_FILTER`` is set
      the executor sends the filter as URL-encoded JSON in the
      ``filters`` query param (Uptycs's documented filter shape is a
      JSON object — ``{"tags":{"in":["tagA","tagB"]}}``).  Pagination
      is ``limit`` + ``offset`` cursor with exhaustion detected when
      fewer than ``limit`` rows come back.
  GET {UPTYCS_HOST}/public/api/customers/{cid}/alerts
      -> paginated alert catalogue.  Same pagination cursor.  When
      ``UPTYCS_TAG_FILTER`` is set the alert pull is additionally
      filtered to the asset-ids returned by the asset pull so the
      result-row catalogue stays bounded to the tag-scoped subset.
      Each alert maps onto a Faraday vulnerability — severity bucketed
      from the freeform ``severity`` string enum (critical / high /
      medium / low / info) with the numeric ``score`` (0-10) used as
      a CVSS-style fallback.

Auth: Uptycs uses HMAC-signed JWTs.  The dispatcher builds a short-
lived JWT signed with HS256 using ``UPTYCS_API_SECRET`` as the HMAC
key and ``UPTYCS_API_KEY_ID`` as ``iss``, then carries
``Authorization: Bearer <JWT>`` plus ``Accept: application/json`` on
every call.  The JWT carries a 5-minute expiry (``exp = iat + 300``)
so it's refreshed once per scan; the key id + secret are created in
the Uptycs console under ``Configuration -> Users -> API Keys``.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Uptycs customer ids are uuid4 strings (8-4-4-4-12 hex groups).  Hard
# -enforce the shape so a typo can't fan out into "/public/api/customers
# /None/assets" calls.
CUSTOMER_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
# Uptycs tag values: alnum + '_-.:/' separators (Uptycs accepts
# arbitrary ascii but we reject control chars + commas so the CSV
# splitter doesn't fan out into junk filters).
TAG_RE = re.compile(r"^[A-Za-z0-9_.:/\-+= @]+$")
# Lenient http(s)://host[:port] URL recogniser (used to validate
# UPTYCS_HOST client-side so a typo can't fan out into "None/public
# /api/customers/..." calls).
HOST_RE = re.compile(r"^https?://[A-Za-z0-9_.\-]+(?::\d{1,5})?(?:/[^\s]*)?$")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100
JWT_LIFETIME_SECONDS = 300

# Uptycs alerts surface ``severity`` as a freeform string enum
# (critical / high / medium / low / info) plus an optional numeric
# ``score`` 0-10.  The string enum buckets onto Faraday tiers; numeric
# bucketing is used as a fallback when the string is missing or
# unrecognised.
UPTYCS_STRING_SEVERITY = {
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

# Uptycs alert lifecycle is exposed through ``alertState`` /
# ``state`` / ``status``.  open / new / in_progress map onto Faraday
# open; closed / resolved / suppressed-with-remediation map onto
# closed; suppressed / dismissed / false_positive map onto risk-
# accepted.
UPTYCS_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "active": "open",
    "unassigned": "open",
    "assigned": "open",
    "in_progress": "open",
    "inprogress": "open",
    "investigating": "open",
    "triaging": "open",
    "pending": "open",
    "remediated": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "closed": "closed",
    "mitigated": "closed",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "waived": "risk-accepted",
    "suppressed": "risk-accepted",
    "dismissed": "risk-accepted",
    "ignored": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "will_not_fix": "risk-accepted",
    "willnotfix": "risk-accepted",
    "wontfix": "risk-accepted",
    "won't_fix": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - Uptycs: {msg}", file=sys.stderr, flush=True)


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


def severity_from_uptycs(value, numeric=None):
    """Map an Uptycs severity string onto a Faraday bucket.

    Accepts the freeform string enum (critical / high / medium / low /
    info), Uptycs-side synonyms, numeric inputs (0-10 CVSS-style),
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
        text = value.strip().lower()
        if text in UPTYCS_STRING_SEVERITY:
            return UPTYCS_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def status_from_uptycs(item):
    """Derive Faraday status from an Uptycs alert payload.

    Walks ``alertState`` / ``state`` / ``status`` and accepts Uptycs's
    documented lifecycle keywords.  Falls back to ``open`` when nothing
    recognisable is set.
    """
    if not isinstance(item, dict):
        return "open"
    for key in (
        "alertState",
        "alert_state",
        "status",
        "state",
        "Status",
        "State",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in UPTYCS_STATUS_BY_STATE:
                return UPTYCS_STATUS_BY_STATE[compact]
            if squashed in UPTYCS_STATUS_BY_STATE:
                return UPTYCS_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in UPTYCS_STATUS_BY_STATE:
                        return UPTYCS_STATUS_BY_STATE[compact]
                    if squashed in UPTYCS_STATUS_BY_STATE:
                        return UPTYCS_STATUS_BY_STATE[squashed]
    return "open"


def validate_min_severity(value):
    """Validate UPTYCS_MIN_SEVERITY (optional severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus Uptycs-side synonyms
    (informational / debug -> info, warning / moderate -> medium,
    notice / minor -> low, fatal / severe -> critical) plus numeric
    input bucketed via the CVSS-style 0-10 scale.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = UPTYCS_STRING_SEVERITY.get(text)
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"UPTYCS_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_tag_filter(value):
    """Validate UPTYCS_TAG_FILTER (CSV of tag tokens, all optional).

    None / blank -> [] (no tag filter; the executor pulls all assets).
    Splits on comma, strips each tag, rejects control characters /
    suspicious shapes (anything outside ``[A-Za-z0-9_.:/\\-+= @]``).
    Tags that don't match the shape are logged + skipped rather than
    failing the whole run — the dispatcher should still emit findings
    for the tags that did validate cleanly.
    """
    if value is None or value == "":
        return []
    text = str(value)
    if "\n" in text or "\r" in text or "\t" in text:
        log("UPTYCS_TAG_FILTER contains a control character; ignoring")
        return []
    out = []
    seen = set()
    for raw in text.split(","):
        token = raw.strip()
        if not token:
            continue
        if not TAG_RE.match(token):
            log(f"UPTYCS_TAG_FILTER skipping malformed tag '{token}'")
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def validate_host(value):
    """Validate UPTYCS_HOST.

    None / blank -> sys.exit(1).  Uptycs's REST endpoint is the
    tenant-specific console URL (``https://<tenant>.uptycs.io``).  We
    hard-enforce the http(s)://host[:port] shape client-side so a typo
    can't fan out into "None/public/api/customers/..." calls.
    Trailing slashes are stripped.
    """
    if value is None or value == "":
        log("UPTYCS_HOST is required")
        sys.exit(1)
    text = str(value).strip()
    if not text:
        log("UPTYCS_HOST is required")
        sys.exit(1)
    if not HOST_RE.match(text):
        log(f"UPTYCS_HOST '{text}' is not a valid http(s)://host[:port] URL")
        sys.exit(1)
    return text.rstrip("/")


def validate_customer_id(value):
    """Validate UPTYCS_CUSTOMER_ID (uuid4 shape).

    None / blank -> sys.exit(1).  Uptycs customer ids are uuid4
    strings (8-4-4-4-12 hex groups) — hard-enforce the shape so a
    typo can't fan out into "/customers/None/assets" calls.
    """
    if value is None or value == "":
        log("UPTYCS_CUSTOMER_ID is required")
        sys.exit(1)
    text = str(value).strip()
    if not text:
        log("UPTYCS_CUSTOMER_ID is required")
        sys.exit(1)
    if not CUSTOMER_ID_RE.match(text):
        log(f"UPTYCS_CUSTOMER_ID '{text}' is not a uuid4 (8-4-4-4-12 hex groups)")
        sys.exit(1)
    return text.lower()


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def _b64url(data):
    """Base64url-encode ``data`` (bytes) without trailing '=' padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_jwt(key_id, secret, lifetime_seconds=JWT_LIFETIME_SECONDS, now=None):
    """Build a HS256 JWT (header.payload.sig) for Uptycs API auth.

    ``iss`` carries the API key id; ``iat`` / ``exp`` carry the
    standard timestamp pair.  The HMAC key is the API secret (utf-8
    encoded).  Returns the compact ``<header>.<payload>.<sig>`` form.
    """
    if not key_id or not secret:
        return ""
    if now is None:
        now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = _b64url(
        json.dumps(
            {"iss": str(key_id), "iat": int(now), "exp": int(now) + int(lifetime_seconds)},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = hmac.new(str(secret).encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


def auth_headers(jwt_token):
    """Build the Uptycs REST auth headers (``Authorization: Bearer <JWT>``)."""
    headers = {"Accept": "application/json"}
    if isinstance(jwt_token, str) and jwt_token.strip():
        headers["Authorization"] = f"Bearer {jwt_token.strip()}"
    return headers


def build_assets_url(host, customer_id):
    return f"{host}/public/api/customers/{customer_id}/assets"


def build_alerts_url(host, customer_id):
    return f"{host}/public/api/customers/{customer_id}/alerts"


def build_tag_filter_json(tags):
    """Build the URL-encoded JSON ``filters`` query value for tag-scoped pulls.

    Uptycs's documented filter shape is ``{"tags":{"in":["a","b"]}}``
    — we URL-encode it inline rather than relying on ``requests`` to
    do the right thing with a nested dict.  Returns "" when no tags
    are provided so the caller can skip the param entirely.
    """
    clean = [t for t in (tags or []) if isinstance(t, str) and t.strip()]
    if not clean:
        return ""
    return json.dumps({"tags": {"in": clean}}, separators=(",", ":"))


def build_assets_params(offset, limit, tag_filter_json=""):
    """Build the GET /assets query params (limit + offset + optional filters)."""
    params = {"limit": int(limit), "offset": int(offset)}
    if tag_filter_json:
        params["filters"] = tag_filter_json
    return params


def build_alerts_params(offset, limit, asset_ids=None):
    """Build the GET /alerts query params (limit + offset + optional asset filter).

    When ``asset_ids`` is set the executor narrows the alert pull to
    the asset subset returned by the tag-scoped /assets call — Uptycs
    accepts ``{"assetId":{"in":[...]}}`` in the same ``filters`` JSON
    blob.  When ``asset_ids`` is empty or None the param is omitted
    and the alert pull walks every alert in the tenant.
    """
    params = {"limit": int(limit), "offset": int(offset)}
    if asset_ids:
        clean = [str(a).strip() for a in asset_ids if str(a).strip()]
        if clean:
            params["filters"] = json.dumps({"assetId": {"in": clean}}, separators=(",", ":"))
    return params


def extract_results(body):
    """Pull the result-row list out of an Uptycs pagination envelope.

    Uptycs uses ``{"items": [...]}`` on most paginated endpoints, with
    ``{"data": [...]}`` on some older shapes.  Walks both, then any
    list-valued top-level key as a last resort.
    """
    if not isinstance(body, dict):
        return []
    for key in ("items", "data", "results", "rows"):
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
    """Walk an Uptycs alert / asset payload for CVE-* ids."""
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

    for key in (
        "description",
        "summary",
        "name",
        "title",
        "message",
        "ruleName",
        "rule_name",
        "code",
        "signature",
        "details",
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


def collect_refs(item):
    """Walk an Uptycs alert payload for Uptycs pivots + advisory URLs."""
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

    alert_id = item.get("id") or item.get("alertId") or item.get("alert_id")
    if alert_id is not None:
        s = str(alert_id).strip()
        if s:
            add(f"Uptycs-Alert: {s}")

    asset_id = item.get("assetId") or item.get("asset_id")
    if asset_id is not None:
        s = str(asset_id).strip()
        if s:
            add(f"Uptycs-Asset: {s}")

    rule_id = item.get("ruleId") or item.get("rule_id")
    if rule_id is not None:
        s = str(rule_id).strip()
        if s:
            add(f"Uptycs-Rule: {s}")

    rule_name = item.get("ruleName") or item.get("rule_name")
    if isinstance(rule_name, str) and rule_name.strip():
        add(f"Uptycs-Rule: {rule_name.strip()}")

    code = item.get("code")
    if isinstance(code, str) and code.strip():
        add(f"Uptycs-Code: {code.strip()}")

    tags = item.get("tags")
    if isinstance(tags, list):
        for t in tags:
            if isinstance(t, str) and t.strip():
                add(f"Uptycs-Tag: {t.strip()}")
            elif isinstance(t, dict):
                tag_name = t.get("name") or t.get("value") or t.get("tag")
                if tag_name:
                    add(f"Uptycs-Tag: {tag_name}")

    threat = item.get("threatName") or item.get("threat_name")
    if isinstance(threat, str) and threat.strip():
        add(f"Uptycs-Threat: {threat.strip()}")

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


def alert_label(item):
    """Build the leading title fragment for an Uptycs alert."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "name",
        "ruleName",
        "rule_name",
        "threatName",
        "threat_name",
        "title",
        "code",
        "category",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().split("\n", 1)[0][:200]
    for key in ("description", "summary", "message"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().split("\n", 1)[0][:200]
    alert_id = item.get("id") or item.get("alertId") or item.get("alert_id")
    if alert_id is not None:
        return f"Alert {alert_id}"
    return "Uptycs alert"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from an Uptycs alert record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    raw_numeric = item.get("score") or item.get("severityScore") or item.get("severity_score")
    if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
        severity_numeric = float(raw_numeric)
    elif isinstance(raw_numeric, str) and raw_numeric.strip():
        try:
            severity_numeric = float(raw_numeric.strip())
        except ValueError:
            severity_numeric = None

    severity_string = item.get("severity") or item.get("severityLabel") or item.get("level")
    severity = severity_from_uptycs(severity_string, severity_numeric)
    status = status_from_uptycs(item)

    label = alert_label(item)
    name = f"[SIEM] {label}" if label else "[SIEM] Uptycs alert"

    desc_parts = []
    description = item.get("description") or item.get("Description") or item.get("message") or item.get("summary")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    for label_key, key in (
        ("alert_id", "id"),
        ("alertId", "alertId"),
        ("alert_id", "alert_id"),
        ("ruleId", "ruleId"),
        ("rule_id", "rule_id"),
        ("ruleName", "ruleName"),
        ("rule_name", "rule_name"),
        ("code", "code"),
        ("category", "category"),
        ("severity", "severity"),
        ("score", "score"),
        ("threatName", "threatName"),
        ("threat_name", "threat_name"),
        ("assetId", "assetId"),
        ("asset_id", "asset_id"),
        ("hostname", "hostname"),
        ("hostName", "hostName"),
        ("host_name", "host_name"),
        ("osVersion", "osVersion"),
        ("os_version", "os_version"),
        ("alertState", "alertState"),
        ("alert_state", "alert_state"),
        ("status", "status"),
        ("state", "state"),
        ("createdAt", "createdAt"),
        ("created_at", "created_at"),
        ("updatedAt", "updatedAt"),
        ("updated_at", "updated_at"),
        ("firstSeen", "firstSeen"),
        ("lastSeen", "lastSeen"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    details = item.get("details") or item.get("metadata") or item.get("alertContext")
    if isinstance(details, dict):
        snippet = _serialise(details)
        if len(snippet) > 2000:
            snippet = snippet[:2000] + "...(truncated)"
        desc_parts.append(f"details: {snippet}")
    elif isinstance(details, str) and details.strip():
        snippet = details.strip()
        if len(snippet) > 2000:
            snippet = snippet[:2000] + "...(truncated)"
        desc_parts.append(f"details: {snippet}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    remediation = item.get("remediation") or item.get("recommendation") or item.get("resolution")
    if isinstance(remediation, str) and remediation.strip():
        resolution = remediation.strip()
    if not resolution:
        resolution = (
            "Investigate the alert in the Uptycs console (Detections -> "
            "Alerts -> select the row, drill into the asset via assetId) "
            "and drive remediation through the asset owner; close the "
            "alert via the Uptycs workflow once handled so the alert "
            "lifecycle stays in sync."
        )

    alert_id = item.get("id") or item.get("alertId") or item.get("alert_id")
    external_id = str(alert_id) if alert_id is not None else ""
    if not external_id and cves:
        external_id = cves[0]

    return {
        "name": str(name).strip()[:200] or f"Uptycs alert {external_id}",
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
        "tags": ["uptycs", "siem", "siem-analytics"],
    }


def asset_hostname(asset):
    """Pick the canonical hostname for an Uptycs asset record."""
    if not isinstance(asset, dict):
        return ""
    for key in (
        "hostName",
        "hostname",
        "host_name",
        "name",
        "computerName",
        "computer_name",
        "fqdn",
    ):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def asset_ip(asset):
    """Pick the canonical IPv4 address for an Uptycs asset record."""
    if not isinstance(asset, dict):
        return "0.0.0.0"
    for key in ("ipAddress", "ip_address", "ip", "primaryIp", "primary_ip"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    addrs = asset.get("ipAddresses") or asset.get("ip_addresses")
    if isinstance(addrs, list):
        for entry in addrs:
            if isinstance(entry, str) and entry.strip():
                return entry.strip()
            if isinstance(entry, dict):
                v = entry.get("address") or entry.get("ip") or entry.get("value")
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return "0.0.0.0"


def asset_mac(asset):
    """Pick the canonical MAC address for an Uptycs asset record."""
    if not isinstance(asset, dict):
        return ""
    for key in ("macAddress", "mac_address", "mac", "primaryMac"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def asset_os(asset):
    """Build the host.os string from an Uptycs asset record."""
    if not isinstance(asset, dict):
        return "Uptycs"
    bits = []
    for key in ("osVersion", "os_version", "osFlavor", "os_flavor", "platform"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
    if bits:
        return " ".join(bits[:2])
    return "Uptycs"


def asset_key(asset):
    """Pick the asset id for grouping alerts by host."""
    if not isinstance(asset, dict):
        return ""
    for key in ("id", "assetId", "asset_id"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, int):
            return str(v)
    return ""


def alert_asset_key(alert):
    """Pick the asset id off an Uptycs alert record."""
    if not isinstance(alert, dict):
        return ""
    for key in ("assetId", "asset_id", "asset"):
        v = alert.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, int):
            return str(v)
        if isinstance(v, dict):
            inner = v.get("id") or v.get("assetId")
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
            if isinstance(inner, int):
                return str(inner)
    return ""


def build_host(asset, vulns):
    """Build a Faraday host record for a single Uptycs asset."""
    if not isinstance(asset, dict):
        asset = {}
    hostname = asset_hostname(asset)
    ip = asset_ip(asset)
    mac = asset_mac(asset)
    os_str = asset_os(asset)

    desc_parts = []
    asset_id = asset_key(asset)
    if asset_id:
        desc_parts.append(f"asset_id={asset_id}")
    for label_key, key in (
        ("hostname", "hostName"),
        ("os_version", "osVersion"),
        ("os_flavor", "osFlavor"),
        ("platform", "platform"),
        ("architecture", "architecture"),
        ("agent_version", "agentVersion"),
        ("kernel_version", "kernelVersion"),
        ("status", "status"),
        ("environment", "environment"),
        ("cloud_provider", "cloudProvider"),
        ("cloud_region", "cloudRegion"),
        ("created_at", "createdAt"),
        ("updated_at", "updatedAt"),
        ("last_activity_at", "lastActivityAt"),
    ):
        v = asset.get(key)
        if v not in (None, ""):
            desc_parts.append(f"{label_key}={v}")

    tags = asset.get("tags")
    if isinstance(tags, list) and tags:
        labels = []
        for t in tags:
            if isinstance(t, str) and t.strip():
                labels.append(t.strip())
            elif isinstance(t, dict):
                tag_name = t.get("name") or t.get("value") or t.get("tag")
                if tag_name:
                    labels.append(str(tag_name))
        if labels:
            desc_parts.append(f"tags={','.join(labels[:20])}")

    if vulns:
        desc_parts.append(f"alerts={len(vulns)}")

    return {
        "ip": ip or "0.0.0.0",
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def build_synthetic_host(host_url, customer_id, tags, vulns):
    """Build a synthetic catch-all host for alerts that don't map to a known asset."""
    parsed = re.match(r"^https?://([^:/]+)", host_url or "")
    hostname = parsed.group(1).strip().lower() if parsed else ""
    desc_parts = [f"uptycs_host={host_url}"]
    if customer_id:
        desc_parts.append(f"customer_id={customer_id}")
    if tags:
        desc_parts.append(f"tag_filter={','.join(tags)}")
    if vulns:
        desc_parts.append(f"alerts={len(vulns)}")
    desc_parts.append("synthetic=true")
    return {
        "ip": "0.0.0.0",
        "os": f"Uptycs ({hostname})" if hostname else "Uptycs",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_assets(
    requests_module, host, customer_id, headers, tag_filter_json, max_pages=MAX_PAGES, page_size=PAGE_SIZE
):
    """Walk /public/api/customers/{cid}/assets via limit/offset pagination."""
    out = []
    url = build_assets_url(host, customer_id)
    offset = 0
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_assets_params(offset, page_size, tag_filter_json)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=True)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Uptycs request rejected (401). Check UPTYCS_API_KEY_ID / UPTYCS_API_SECRET.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Uptycs request rejected (403). Check the API key's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"Uptycs assets endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"Uptycs assets request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Uptycs assets response was not JSON ({url})")
            return out
        results = extract_results(payload)
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
        log(f"hit MAX_PAGES={max_pages}; stopping assets pagination")
    return out


def fetch_alerts(
    requests_module, host, customer_id, headers, asset_ids=None, max_pages=MAX_PAGES, page_size=PAGE_SIZE
):
    """Walk /public/api/customers/{cid}/alerts via limit/offset pagination."""
    out = []
    url = build_alerts_url(host, customer_id)
    offset = 0
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_alerts_params(offset, page_size, asset_ids)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=True)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Uptycs request rejected (401). Check UPTYCS_API_KEY_ID / UPTYCS_API_SECRET.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Uptycs request rejected (403). Check the API key's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"Uptycs alerts endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"Uptycs alerts request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Uptycs alerts response was not JSON ({url})")
            return out
        results = extract_results(payload)
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
        log(f"hit MAX_PAGES={max_pages}; stopping alerts pagination")
    return out


def main():
    started = time.time()

    tag_filter = validate_tag_filter(env("EXECUTOR_CONFIG_UPTYCS_TAG_FILTER"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_UPTYCS_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = validate_host(env("UPTYCS_HOST", required=True))
    customer_id = validate_customer_id(env("UPTYCS_CUSTOMER_ID", required=True))
    api_key_id = env("UPTYCS_API_KEY_ID", required=True)
    api_secret = env("UPTYCS_API_SECRET", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    jwt_token = build_jwt(api_key_id, api_secret)
    if not jwt_token:
        log("failed to build Uptycs JWT (missing api_key_id / api_secret)")
        sys.exit(1)
    headers = auth_headers(jwt_token)
    log(f"auth_mode=jwt-hs256 jwt_lifetime_seconds={JWT_LIFETIME_SECONDS}")

    tag_filter_json = build_tag_filter_json(tag_filter)
    assets = fetch_assets(requests, host, customer_id, headers, tag_filter_json)
    log(f"Fetched {len(assets)} Uptycs assets " f"(tag_filter={','.join(tag_filter) if tag_filter else 'none'})")

    asset_ids = []
    asset_by_id = {}
    for asset in assets:
        aid = asset_key(asset)
        if aid:
            asset_ids.append(aid)
            asset_by_id[aid] = asset

    alerts = fetch_alerts(
        requests,
        host,
        customer_id,
        headers,
        asset_ids=asset_ids if tag_filter else None,
    )
    log(f"Processing {len(alerts)} Uptycs alerts " f"(min_severity={min_severity})")

    vulns_by_asset = {}
    orphan_vulns = []
    for alert in alerts:
        built = build_vulnerability(alert)
        if built is None:
            continue
        if allowed_severities and built["severity"] not in allowed_severities:
            continue
        aid = alert_asset_key(alert)
        if aid and aid in asset_by_id:
            vulns_by_asset.setdefault(aid, []).append(built)
        else:
            orphan_vulns.append(built)

    hosts = []
    for aid, asset in asset_by_id.items():
        hosts.append(build_host(asset, vulns_by_asset.get(aid, [])))

    # Assets with no alerts still get emitted so the Faraday workspace
    # records that the endpoint exists + is monitored by Uptycs.  Alerts
    # that didn't map to a known asset attach to a synthetic catch-all
    # host so they're not silently dropped.
    if orphan_vulns or not hosts:
        hosts.append(build_synthetic_host(host, customer_id, tag_filter, orphan_vulns))

    params_bits = [
        f"customer_id={customer_id}",
        f"tag_filter={','.join(tag_filter) if tag_filter else 'none'}",
        f"min_severity={min_severity}",
    ]

    output = {
        "hosts": hosts,
        "command": {
            "tool": "uptycs",
            "command": "uptycs",
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
