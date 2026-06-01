#!/usr/bin/env python
"""Prisma Cloud (CNAPP / CSPM) REST importer.

Pulls cloud-security alerts from a Prisma Cloud (formerly RedLock /
Palo Alto Networks CSPM) tenant via the canonical ``POST /alert``,
``GET /v2/alert/policy``, and ``GET /cloud`` endpoints and emits
Faraday bulk-create JSON to stdout. Each Prisma Cloud resource
(``resource.rrn`` / ``resource.id``) becomes one Faraday host (``ip``
= synthetic ``0.0.0.0`` because CSPM findings live on cloud
resources, not on IPs); per-resource alerts are attached as Faraday
vulnerabilities — one per Prisma alert id with engine prefix
``[CNAPP]``.

Endpoints used:
  POST {PRISMA_HOST}/login
      -> credentials exchange. Body ``{"username": <access_key>,
      "password": <secret_key>}`` returns ``{"token": "..."}``
      (Prisma's short-lived JWT, ~10 min validity). Subsequent calls
      send ``x-redlock-auth: <token>``.
  POST {PRISMA_HOST}/alert
      -> primary alert listing endpoint. Body carries ``timeRange``,
      ``sortBy``, ``filters`` (alert.status / policy.severity /
      account.group), ``limit`` + ``offset`` cursor. Returns
      ``{"items": [...], "totalRows": N, "nextPageToken": "..."}``;
      pagination via ``nextPageToken`` (also tolerated as ``offset``
      bump when token is absent).
  GET {PRISMA_HOST}/v2/alert/policy
      -> policy catalogue. Optional enrichment when the alert
      payload's ``policy`` block is compact (no recommendation /
      remediationDescription). Keyed by ``policyId``.
  GET {PRISMA_HOST}/cloud
      -> cloud account roster. Optional enrichment to surface the
      friendly account name when the alert payload only carries the
      account id.

Auth: Prisma Cloud uses an access-key / secret-key pair tied to a
service account. The pair is sent as JSON to ``/login``; the response
carries a short-lived JWT that is then sent as ``x-redlock-auth:
<token>`` on subsequent calls. The tenant URL is the API base of the
stack the operator's tenant lives on (``https://api.prismacloud.io``
for AWS-NA, ``https://api2.prismacloud.io`` for AWS-EU,
``https://api.eu.prismacloud.io`` / ``https://api.anz.prismacloud.io``
/ etc. for regional stacks).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200
DEFAULT_WINDOW_AMOUNT = 1
DEFAULT_WINDOW_UNIT = "day"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Prisma Cloud alert lifecycle:
#   open / new / active / reopened -> open
#   resolved / closed / fixed / remediated -> closed
#   dismissed / snoozed / suppressed / muted / ignored / wont_fix /
#   risk_accepted / false_positive / expired -> risk-accepted
VALID_PRISMA_STATUS = ("OPEN", "RESOLVED", "DISMISSED", "SNOOZED")

PRISMA_STRING_SEVERITY = {
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

PRISMA_STATUS_TO_FARADAY = {
    "open": "open",
    "new": "open",
    "active": "open",
    "reopened": "open",
    "re_opened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "resolved": "closed",
    "closed": "closed",
    "fixed": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "dismissed": "risk-accepted",
    "snoozed": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "expired": "risk-accepted",
}

PRISMA_API_SEVERITY = {
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - PrismaCloud: {msg}", file=sys.stderr, flush=True)


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


def normalize_base_url(host):
    """Prefix a bare hostname with https:// and strip trailing slashes."""
    if not host:
        return ""
    text = str(host).strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    return text.rstrip("/")


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"PRISMA_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def validate_status(value):
    """Validate PRISMA_STATUS — Prisma uses open / resolved / dismissed / snoozed.

    None / blank -> None (no filter). Garbage tokens are dropped with
    a log line so the operator can spot typos rather than silently
    scanning the whole tenant. Returns lower-case canonical tokens
    for use as Prisma filter values.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (list, tuple, set)):
        text = ",".join(str(v) for v in value)
    else:
        text = str(value)
    raw = [t.strip().upper().replace("-", "_").replace(" ", "_") for t in text.split(",") if t.strip()]
    valid = []
    for token in raw:
        if token in VALID_PRISMA_STATUS:
            canonical = token
        elif token in ("REOPENED", "RE_OPENED", "NEW", "ACTIVE", "IN_PROGRESS", "INPROGRESS"):
            canonical = "OPEN"
        elif token in ("CLOSED", "FIXED", "REMEDIATED", "MITIGATED", "PATCHED"):
            canonical = "RESOLVED"
        elif token in (
            "IGNORED",
            "SUPPRESSED",
            "MUTED",
            "WONT_FIX",
            "WONTFIX",
            "RISK_ACCEPTED",
            "RISKACCEPTED",
            "ACCEPTED",
            "FALSE_POSITIVE",
            "FALSEPOSITIVE",
            "EXPIRED",
        ):
            canonical = "DISMISSED"
        else:
            log(f"PRISMA_STATUS token '{token}' not recognised; ignored")
            continue
        if canonical not in valid:
            valid.append(canonical)
    return valid or None


def severities_at_or_above(min_severity):
    """Return the Prisma severity tokens at or above ``min_severity``.

    Used to build the ``policy.severity`` filter so the tenant only
    paginates results that survive the client-side floor. ``info``
    yields every bucket (no filter applied).
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = PRISMA_API_SEVERITY.get(bucket)
            if api and api not in out:
                out.append(api)
    return out


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


def severity_from_prisma(value, cvss=None):
    """Map a Prisma Cloud severity to a Faraday bucket.

    Accepts Prisma's string enum (critical / high / medium / low /
    informational) and falls back to CVSS bucketing on ``cvss`` when
    the primary value is missing or unrecognised. Numeric inputs are
    interpreted as CVSS base scores so vendor-shaped reports that
    surface a bare score still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in PRISMA_STRING_SEVERITY:
            return PRISMA_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_prisma(alert):
    """Derive Faraday status from a Prisma Cloud alert payload.

    Prisma carries a top-level ``status`` enum (open / resolved /
    dismissed / snoozed). We tolerate dict-wrapped and synonym shapes
    so downstream re-emissions through generic CNAPP pipelines still
    map cleanly.
    """
    if not isinstance(alert, dict):
        return "open"
    for key in ("status", "alertStatus", "alert_status", "state"):
        raw = alert.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
        if isinstance(raw, str):
            mapped = PRISMA_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in PRISMA_STATUS_TO_FARADAY:
                return PRISMA_STATUS_TO_FARADAY[compact]
    return "open"


def request(method, url, headers, params=None, json_body=None):
    """Wrap requests with shared error handling."""
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=TIMEOUT,
            verify=False,
        )
    except requests.RequestException as exc:
        log(f"{method} {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log(f"{method} {url} rejected (401). Check PRISMA_USERNAME / PRISMA_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"{method} {url} rejected (403). Token lacks required scopes.")
        return None
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        log(f"{method} {url} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"{method} {url} response was not JSON")
        return None


def fetch_access_token(base_url, username, password):
    """Exchange Prisma Cloud access-key / secret-key for a short-lived JWT.

    Prisma's auth endpoint is ``POST {base_url}/login`` with JSON
    body ``{"username": <access_key>, "password": <secret_key>}`` ->
    ``{"token": "..."}``. Some stacks wrap the token under ``data``;
    ``extract_token`` tolerates both shapes plus ``accessToken`` /
    ``access_token`` synonyms.
    """
    if not base_url or not username or not password:
        return None
    url = f"{base_url}/login"
    body = {"username": username, "password": password}
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Login rejected (401). Check PRISMA_USERNAME / PRISMA_PASSWORD.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Login failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        payload = resp.json()
    except ValueError:
        log("Login response was not JSON")
        return None
    return extract_token(payload)


def extract_token(payload):
    """Pull the JWT out of a Prisma Cloud ``/login`` response.

    Tolerates the bare ``{"token": "..."}`` shape, the wrapped
    ``{"data": {"token": "..."}}`` / ``{"data": [{"token": "..."}]}``
    shape, and a few synonym keys (``accessToken`` /
    ``access_token``).
    """
    if not isinstance(payload, dict):
        return None
    for key in ("token", "accessToken", "access_token"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    data = payload.get("data")
    if isinstance(data, dict):
        for key in ("token", "accessToken", "access_token"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            for key in ("token", "accessToken", "access_token"):
                value = first.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def extract_items(payload):
    """Pull the alert / policy / account list out of a Prisma envelope.

    Prisma returns ``{"items": [...], "totalRows": N, "nextPageToken":
    "..."}`` for paginated alert lists, a bare list for /cloud and
    /v2/alert/policy, and occasionally an ``{"data": [...]}``
    envelope; tolerate all shapes plus a handful of seen alt keys
    (``results`` / ``alerts`` / ``policies``).
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("items", "data", "results", "alerts", "policies"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def next_page_token(payload):
    """Extract the next-page cursor from a Prisma paged envelope."""
    if not isinstance(payload, dict):
        return None
    for key in ("nextPageToken", "next_page_token", "pageToken", "page_token"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def build_alert_body(statuses, severities, account_group, limit, page_token=None):
    """Build the JSON body for POST /alert.

    Filters: ``alert.status`` (CSV), ``policy.severity`` (CSV),
    ``account.group`` (single). ``timeRange`` defaults to the last
    24h (``relative.day.1``). ``sortBy`` always pins
    ``lastSeen:desc``. ``limit`` caps the page size; ``page_token``
    drives cursor-based pagination when the tenant returns one.
    """
    body = {
        "timeRange": {
            "type": "relative",
            "value": {"unit": DEFAULT_WINDOW_UNIT, "amount": DEFAULT_WINDOW_AMOUNT},
        },
        "sortBy": ["lastSeen:desc"],
        "limit": limit,
    }
    filters = []
    if statuses:
        for status in statuses:
            filters.append({"name": "alert.status", "operator": "=", "value": status.lower()})
    if severities:
        for sev in severities:
            filters.append({"name": "policy.severity", "operator": "=", "value": sev})
    if account_group:
        filters.append({"name": "account.group", "operator": "=", "value": account_group})
    if filters:
        body["filters"] = filters
    if page_token:
        body["pageToken"] = page_token
    return body


def fetch_alerts(base_url, headers, statuses, severities, account_group):
    """Paginate through /alert for the supplied filters."""
    results = []
    seen_ids = set()
    page_token = None
    offset = 0
    for _ in range(MAX_PAGES):
        body = build_alert_body(statuses, severities, account_group, PAGE_SIZE, page_token)
        if not page_token:
            body["offset"] = offset
        payload = request("POST", f"{base_url}/alert", headers, json_body=body)
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for alert in chunk:
            aid = alert.get("id") or alert.get("alertId") or alert.get("alert_id")
            if isinstance(aid, str) and aid in seen_ids:
                continue
            if isinstance(aid, str):
                seen_ids.add(aid)
            results.append(alert)
            added += 1
        if added == 0:
            break
        page_token = next_page_token(payload)
        offset += len(chunk)
        total = None
        if isinstance(payload, dict):
            total = payload.get("totalRows") or payload.get("totalItems") or payload.get("total")
        if isinstance(total, (int, float)) and offset >= int(total):
            break
        if not page_token and len(chunk) < PAGE_SIZE:
            break
    return results


def fetch_policies(base_url, headers):
    """Pull the policy catalogue for enrichment, indexed by policyId."""
    payload = request("GET", f"{base_url}/v2/alert/policy", headers)
    items = extract_items(payload)
    by_id = {}
    for policy in items:
        pid = policy.get("policyId") or policy.get("id")
        if isinstance(pid, str) and pid:
            by_id[pid] = policy
    return by_id


def fetch_cloud_accounts(base_url, headers):
    """Pull the cloud-account roster for enrichment, indexed by accountId."""
    payload = request("GET", f"{base_url}/cloud", headers)
    items = extract_items(payload)
    by_id = {}
    for account in items:
        aid = account.get("accountId") or account.get("id") or account.get("cloudAccountId")
        if isinstance(aid, str) and aid:
            by_id[aid] = account
    return by_id


def cvss_score(alert):
    """Pull a numeric CVSS / score out of a Prisma alert + policy payload."""
    if not isinstance(alert, dict):
        return None
    candidates = [alert]
    policy = alert.get("policy")
    if isinstance(policy, dict):
        candidates.append(policy)
    for source in candidates:
        for key in ("cvss_score", "cvssScore", "score", "baseScore", "base_score"):
            value = source.get(key)
            if value is None or isinstance(value, (dict, list, bool)):
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
            nested = source.get(nested_key)
            if isinstance(nested, dict):
                for k in ("score", "baseScore", "base_score", "overallScore", "overall_score"):
                    score = nested.get(k)
                    if score is None or isinstance(score, (dict, list, bool)):
                        continue
                    try:
                        return float(score)
                    except (TypeError, ValueError):
                        continue
    return None


def cvss_vector(alert):
    if not isinstance(alert, dict):
        return ""
    candidates = [alert]
    policy = alert.get("policy")
    if isinstance(policy, dict):
        candidates.append(policy)
    for source in candidates:
        for key in ("cvss_vector", "cvssVector", "vector", "vector_string", "vectorString"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
            nested = source.get(nested_key)
            if isinstance(nested, dict):
                for k in ("vector", "vectorString", "vector_string"):
                    v = nested.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    return ""


def collect_cves(alert):
    """Pull CVE-* ids out of a Prisma alert + policy payload."""
    found = []
    seen = set()

    def add_token(text):
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
        for match in CVE_RE.findall(text):
            add_token(match)

    def add(text):
        if not isinstance(text, str):
            if text:
                add_token(text)
            return
        if CVE_RE.fullmatch(text.strip().upper()):
            add_token(text)
        else:
            scan(text)

    if not isinstance(alert, dict):
        return found

    sources = [alert]
    policy = alert.get("policy")
    if isinstance(policy, dict):
        sources.append(policy)

    for source in sources:
        for key in ("id", "alertId", "alert_id", "name", "title", "description", "summary"):
            v = source.get(key)
            if isinstance(v, str):
                add(v)
        for key in ("cve", "cveId", "cve_id"):
            v = source.get(key)
            if isinstance(v, str) and v.strip():
                add_token(v)
        for key in ("cves", "cveIds", "cve_ids", "aliases"):
            v = source.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add_token(entry)
                    elif isinstance(entry, dict):
                        add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
        for key in ("recommendation", "remediationDescription", "remediation"):
            v = source.get(key)
            if isinstance(v, str):
                scan(v)
    return found


def collect_refs(alert, policy_meta=None):
    """Walk a Prisma alert + policy for CWE / advisory / URL refs."""
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

    if not isinstance(alert, dict):
        return refs

    sources = [alert]
    policy = alert.get("policy")
    if isinstance(policy, dict):
        sources.append(policy)
    if isinstance(policy_meta, dict):
        sources.append(policy_meta)

    for source in sources:
        cwe_raw = source.get("cwe_id") or source.get("cweId") or source.get("cwe")
        if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
            add(f"CWE-{int(cwe_raw)}")
        elif isinstance(cwe_raw, str) and cwe_raw.strip():
            s = cwe_raw.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("cwes", "cweIds", "cwe_ids"):
            items = source.get(key)
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, dict):
                        cid = it.get("id") or it.get("value") or it.get("name")
                        if cid is None:
                            continue
                        text = str(cid).strip()
                        add(text if text.upper().startswith("CWE-") else f"CWE-{text}")
                    elif isinstance(it, (int, float)) and not isinstance(it, bool):
                        add(f"CWE-{int(it)}")
                    elif isinstance(it, str) and it.strip():
                        s = it.strip()
                        add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("references", "links", "external_references", "externalReferences"):
            entry = source.get(key)
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

    if isinstance(policy, dict):
        pid = policy.get("policyId") or policy.get("id")
        if isinstance(pid, str) and pid.strip():
            add(f"Prisma-Policy: {pid.strip()}")
        for key in ("complianceMetadata", "compliance_metadata"):
            entry = policy.get(key)
            if isinstance(entry, list):
                for it in entry:
                    if not isinstance(it, dict):
                        continue
                    std = it.get("standardName") or it.get("standard_name")
                    sec = it.get("sectionId") or it.get("section_id") or it.get("sectionLabel")
                    if std and sec:
                        add(f"Compliance: {std} {sec}")
                    elif std:
                        add(f"Compliance: {std}")

    resource = alert.get("resource") if isinstance(alert, dict) else None
    if isinstance(resource, dict):
        for key in ("url", "cloud_provider_url", "cloudProviderUrl", "consoleUrl"):
            v = resource.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())
        rrn = resource.get("rrn")
        if isinstance(rrn, str) and rrn.strip():
            add(f"Prisma-RRN: {rrn.strip()}")

    return refs


def resource_label(alert):
    """Build a friendly label for the affected cloud resource."""
    if not isinstance(alert, dict):
        return "", "", "", ""
    resource = alert.get("resource") if isinstance(alert.get("resource"), dict) else {}
    name = (
        resource.get("name")
        or resource.get("resourceName")
        or alert.get("resourceName")
        or alert.get("resource_name")
        or ""
    )
    rtype = (
        resource.get("resourceType")
        or resource.get("resource_type")
        or resource.get("resourceApiName")
        or alert.get("resourceType")
        or alert.get("resource_type")
        or ""
    )
    region = resource.get("regionId") or resource.get("region") or alert.get("regionId") or alert.get("region") or ""
    rid = resource.get("rrn") or resource.get("id") or resource.get("resourceId") or alert.get("resourceId") or ""
    return str(name), str(rtype), str(region), str(rid)


def policy_label(alert, policy_meta=None):
    """Build a friendly identifier for the policy that produced the alert."""
    if not isinstance(alert, dict):
        return ""
    policy = alert.get("policy") if isinstance(alert.get("policy"), dict) else {}
    name = policy.get("name") or policy.get("policyName") or ""
    if not name and isinstance(policy_meta, dict):
        name = policy_meta.get("name") or policy_meta.get("policyName") or ""
    if not name:
        name = policy.get("policyId") or alert.get("policyId") or alert.get("policy_id") or ""
    return str(name).strip()


def build_vulnerability(alert, policy_meta=None):
    """Build a Faraday vulnerability dict from one Prisma Cloud alert."""
    if not isinstance(alert, dict):
        return None

    policy = alert.get("policy") if isinstance(alert.get("policy"), dict) else {}
    score = cvss_score(alert)
    severity_raw = policy.get("severity") or alert.get("severity")
    if not severity_raw and isinstance(policy_meta, dict):
        severity_raw = policy_meta.get("severity")
    severity = severity_from_prisma(severity_raw, score)
    status = status_from_prisma(alert)

    plabel = policy_label(alert, policy_meta)
    rname, rtype, region, rid = resource_label(alert)
    if rname and rtype:
        resource = f"{rtype} {rname}"
    elif rname:
        resource = rname
    elif rtype:
        resource = rtype
    else:
        resource = rid or "resource"
    if region:
        resource_label_str = f"{resource} [{region}]"
    else:
        resource_label_str = resource

    base_title = plabel or str(
        alert.get("title") or alert.get("name") or alert.get("id") or alert.get("alertId") or "Prisma Cloud finding"
    )
    raw_name = f"{base_title} on {resource_label_str}" if resource_label_str else base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = policy.get("description") or alert.get("description") or alert.get("alertDescription")
    if not description and isinstance(policy_meta, dict):
        description = policy_meta.get("description")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))

    if plabel:
        desc_parts.append(f"policy: {plabel}")
    policy_id = policy.get("policyId") or alert.get("policyId") or alert.get("policy_id")
    if policy_id:
        desc_parts.append(f"policy_id: {policy_id}")
    policy_type = policy.get("policyType") or policy.get("policy_type")
    if policy_type:
        desc_parts.append(f"policy_type: {policy_type}")
    if rname:
        desc_parts.append(f"resource: {rname}")
    if rtype:
        desc_parts.append(f"resource_type: {rtype}")
    if rid and rid != rname:
        desc_parts.append(f"resource_id: {rid}")

    resource = alert.get("resource") if isinstance(alert.get("resource"), dict) else {}
    for label, keys in (
        ("cloud_type", ("cloudType", "cloud_type")),
        ("cloud_account_id", ("accountId", "account_id", "cloudAccountId")),
        ("cloud_account", ("account", "accountName", "account_name")),
        ("region", ("regionId", "region")),
        ("rrn", ("rrn",)),
    ):
        for k in keys:
            v = resource.get(k) if isinstance(resource, dict) else None
            if v in (None, ""):
                v = alert.get(k)
            if v not in (None, ""):
                desc_parts.append(f"{label}: {v}")
                break

    account_group = alert.get("accountGroup") or alert.get("account_group")
    if account_group:
        desc_parts.append(f"account_group: {account_group}")

    raw_status = alert.get("status") or alert.get("alertStatus")
    if raw_status:
        desc_parts.append(f"status: {raw_status}")
    if severity_raw:
        desc_parts.append(f"severity: {severity_raw}")

    for label, keys in (
        ("first_seen", ("firstSeen", "first_seen", "firstSeenTs", "firstSeenTime")),
        ("last_seen", ("lastSeen", "last_seen", "lastSeenTs", "lastSeenTime")),
        ("alert_time", ("alertTime", "alert_time")),
        ("event_occurred", ("eventOccurred", "event_occurred")),
        ("dismissed_at", ("dismissedAt", "dismissed_at")),
        ("resolved_at", ("resolvedAt", "resolved_at")),
        ("snoozed_until", ("snoozeExpires", "snoozedUntil", "snoozed_until")),
    ):
        for k in keys:
            v = alert.get(k)
            if v:
                desc_parts.append(f"{label}: {v}")
                break

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(alert)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(alert)
    refs = collect_refs(alert, policy_meta)

    resolution = (
        alert.get("recommendation")
        or alert.get("remediation")
        or alert.get("resolution")
        or alert.get("solution")
        or policy.get("recommendation")
        or policy.get("remediationDescription")
        or policy.get("remediation_description")
        or policy.get("remediation")
        or ""
    )
    if not resolution and isinstance(policy_meta, dict):
        resolution = (
            policy_meta.get("recommendation")
            or policy_meta.get("remediationDescription")
            or policy_meta.get("remediation_description")
            or policy_meta.get("remediation")
            or ""
        )
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    external_id = str(alert.get("id") or alert.get("alertId") or alert.get("alert_id") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Prisma Cloud finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["prisma_cloud", "cnapp", "cloud-security"],
    }


def host_bucket_key(alert):
    """Build a stable bucket key for grouping alerts into hosts."""
    if not isinstance(alert, dict):
        return "__unknown__"
    resource = alert.get("resource") if isinstance(alert.get("resource"), dict) else {}
    key = (
        resource.get("rrn")
        or resource.get("id")
        or resource.get("resourceId")
        or alert.get("resourceId")
        or resource.get("name")
        or alert.get("resourceName")
        or ""
    )
    return str(key) if key else "__unknown__"


def build_host(bucket_key, alerts, vulns, cloud_account=None):
    """Build a Faraday host shell from a Prisma resource bucket."""
    first = alerts[0] if alerts else {}
    rname, rtype, region, rid = resource_label(first) if isinstance(first, dict) else ("", "", "", "")
    resource = first.get("resource") if isinstance(first, dict) and isinstance(first.get("resource"), dict) else {}
    cloud_type = resource.get("cloudType") or resource.get("cloud_type") or first.get("cloudType") or ""
    account_id = (
        resource.get("accountId")
        or resource.get("account_id")
        or resource.get("cloudAccountId")
        or first.get("accountId")
        or ""
    )
    account_name = (
        resource.get("account")
        or resource.get("accountName")
        or resource.get("account_name")
        or first.get("account")
        or first.get("accountName")
        or ""
    )
    if not account_name and isinstance(cloud_account, dict):
        account_name = cloud_account.get("name") or cloud_account.get("accountName") or ""
    if rname and bucket_key and rname != bucket_key:
        hostname = f"{rname}@{bucket_key}"
    else:
        hostname = rname or bucket_key
    desc_parts = []
    if rid:
        desc_parts.append(f"resource_id={rid}")
    if rname:
        desc_parts.append(f"resource={rname}")
    if rtype:
        desc_parts.append(f"resource_type={rtype}")
    if cloud_type:
        desc_parts.append(f"cloud_type={cloud_type}")
    if account_id:
        desc_parts.append(f"cloud_account_id={account_id}")
    if account_name:
        desc_parts.append(f"cloud_account={account_name}")
    if region:
        desc_parts.append(f"region={region}")
    if alerts:
        desc_parts.append(f"alerts={len(alerts)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("PRISMA_HOST", required=True)
    username = env("PRISMA_USERNAME", required=True)
    password = env("PRISMA_PASSWORD", required=True)
    account_group = env("EXECUTOR_CONFIG_PRISMA_ACCOUNT_GROUP")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_PRISMA_MIN_SEVERITY"))
    statuses = validate_status(env("EXECUTOR_CONFIG_PRISMA_STATUS"))
    floor = SEVERITY_ORDER[min_severity]
    severities = severities_at_or_above(min_severity)
    if severities and len(severities) == len(PRISMA_API_SEVERITY):
        severities = None

    base_url = normalize_base_url(host)
    if not base_url:
        log("PRISMA_HOST is required")
        sys.exit(1)

    token = fetch_access_token(base_url, username, password)
    if not token:
        log("Failed to obtain Prisma Cloud access token; aborting.")
        sys.exit(1)
    headers = {
        "x-redlock-auth": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    alerts = fetch_alerts(base_url, headers, statuses, severities, account_group)
    log(
        f"Processing {len(alerts)} Prisma Cloud alerts "
        f"(account_group={account_group or 'ALL'}, status={statuses or 'ALL'}, "
        f"min_severity={min_severity})"
    )

    policies = fetch_policies(base_url, headers) if alerts else {}
    cloud_accounts = fetch_cloud_accounts(base_url, headers) if alerts else {}

    buckets = {}
    for alert in alerts:
        key = host_bucket_key(alert)
        buckets.setdefault(key, []).append(alert)

    hosts = []
    for key, bucket in buckets.items():
        vulns = []
        first = bucket[0] if bucket else {}
        account_id = ""
        resource = first.get("resource") if isinstance(first, dict) and isinstance(first.get("resource"), dict) else {}
        if isinstance(resource, dict):
            account_id = (
                resource.get("accountId") or resource.get("account_id") or resource.get("cloudAccountId") or ""
            )
        cloud_account_meta = cloud_accounts.get(account_id) if account_id else None
        for alert in bucket:
            policy_id = ""
            ap = alert.get("policy") if isinstance(alert, dict) else None
            if isinstance(ap, dict):
                policy_id = ap.get("policyId") or ap.get("id") or ""
            if not policy_id and isinstance(alert, dict):
                policy_id = alert.get("policyId") or alert.get("policy_id") or ""
            policy_meta = policies.get(policy_id) if policy_id else None
            built = build_vulnerability(alert, policy_meta)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        bucket_id = "" if key == "__unknown__" else key
        hosts.append(build_host(bucket_id, bucket, vulns, cloud_account_meta))

    params = f"min_severity={min_severity}"
    if account_group:
        params = f"{params},account_group={account_group}"
    if statuses:
        params = f"{params},status={'|'.join(statuses)}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "prisma_cloud",
            "command": "prisma_cloud",
            "params": params,
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
