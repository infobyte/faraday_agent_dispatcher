#!/usr/bin/env python
"""CrowdStrike Falcon Cloud Security (CNAPP / CSPM) REST importer.

Pulls Indicators of Misconfiguration (IOMs) from a Falcon Cloud Security
tenant via the canonical ``GET /cloud-security/queries/iom`` +
``GET /cloud-security/entities/iom`` two-step pattern and emits Faraday
bulk-create JSON to stdout. Each Falcon cloud account becomes one
Faraday host (``ip`` = synthetic ``0.0.0.0`` because CSPM findings live
on cloud accounts / resources, not on IPs); per-account IOMs are
attached as Faraday vulnerabilities — one per Falcon IOM ``id`` with
engine prefix ``[CNAPP]``.

Endpoints used:
  POST {FALCON_HOST}/oauth2/token
      -> OAuth2 client_credentials. Returns ``{"access_token": "...",
      "expires_in": N}``; subsequent calls send
      ``Authorization: Bearer <access_token>``.
  GET {FALCON_HOST}/cloud-security/queries/iom/v1
      -> primary query endpoint. Paginated via ``offset`` + ``limit``
      cursor. Filters built via FQL (``filter=cloud_provider:'aws'``).
      Returns IOM ids in ``resources``.
  GET {FALCON_HOST}/cloud-security/entities/iom/v1?ids=...
      -> entity fetch. Returns full IOM payloads (one per id) in
      ``resources``. Batched in chunks of ``ENTITIES_BATCH`` ids.

Auth: Falcon Cloud Security uses OAuth2 client_credentials, identical
to Falcon Spotlight / Detect / Hosts. A service account ("API client")
is created in the Falcon UI, the client id / secret are stored in
``FALCON_CLIENT_ID`` / ``FALCON_CLIENT_SECRET``, and the API tenant URL
is ``FALCON_HOST`` (e.g. ``https://api.crowdstrike.com``,
``https://api.us-2.crowdstrike.com``, ``https://api.eu-1.crowdstrike.com``,
``https://api.laggar.gcw.crowdstrike.com``). The token exchange is
``POST {FALCON_HOST}/oauth2/token`` with form body
``client_id=...&client_secret=...&grant_type=client_credentials``.
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
PAGE_SIZE = 500
MAX_PAGES = 200
ENTITIES_BATCH = 100

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

VALID_CLOUD_PROVIDER = ("aws", "azure", "gcp")
CLOUD_PROVIDER_ALIASES = {
    "aws": "aws",
    "amazon": "aws",
    "amazon_web_services": "aws",
    "amazonwebservices": "aws",
    "azure": "azure",
    "microsoft": "azure",
    "microsoft_azure": "azure",
    "microsoftazure": "azure",
    "gcp": "gcp",
    "google": "gcp",
    "google_cloud": "gcp",
    "googlecloud": "gcp",
    "google_cloud_platform": "gcp",
    "googlecloudplatform": "gcp",
}

# Falcon Cloud Security severity is an upper-case string enum
# (Critical / High / Medium / Low / Informational); accept synonyms
# surfaced by adjacent products and downstream pipelines.
FCS_STRING_SEVERITY = {
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

# Falcon IOM status enum:
#   Open / New / Active / Reopened / InProgress -> open
#   Closed / Fixed / Resolved / Remediated / Mitigated / Patched -> closed
#   Suppressed / Muted / Ignored / Dismissed / WontFix / RiskAccepted /
#     Excluded / FalsePositive / Expired -> risk-accepted
FCS_STATUS_TO_FARADAY = {
    "open": "open",
    "new": "open",
    "active": "open",
    "reopened": "open",
    "re_opened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "closed": "closed",
    "fixed": "closed",
    "resolved": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "dismissed": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "excluded": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "expired": "risk-accepted",
}

# Falcon IOM severity is forwarded to the tenant in FQL as the canonical
# capitalised enum so the wire filter survives stricter tenants.
FCS_API_SEVERITY = {
    "info": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - CrowdStrike Cloud: {msg}", file=sys.stderr, flush=True)


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
    if not host:
        return ""
    text = str(host).strip()
    if not text:
        return ""
    base = text if text.startswith(("http://", "https://")) else f"https://{text}"
    return base.rstrip("/")


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"FCS_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def validate_cloud_provider(value):
    """Validate FCS_CLOUD_PROVIDER — Falcon expects aws | azure | gcp.

    None / blank -> None (no provider filter). Garbage logs a warning
    and falls back to None so the operator can spot typos rather than
    silently scanning the whole tenant.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (list, tuple, set)):
        for entry in value:
            mapped = validate_cloud_provider(entry)
            if mapped:
                return mapped
        return None
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if not text:
        return None
    mapped = CLOUD_PROVIDER_ALIASES.get(text)
    if mapped in VALID_CLOUD_PROVIDER:
        return mapped
    log(f"FCS_CLOUD_PROVIDER '{value}' not recognised; ignoring")
    return None


def severities_at_or_above(min_severity):
    """Return the Falcon severity tokens at or above ``min_severity``.

    Used to build the FQL ``severity:[...]`` filter so the tenant only
    paginates results that survive the client-side floor. ``info``
    yields every bucket (no filter applied).
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = FCS_API_SEVERITY.get(bucket)
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


def severity_from_fcs(value, cvss=None):
    """Map a Falcon severity to a Faraday bucket.

    Accepts Falcon's string enum (Critical / High / Medium / Low /
    Informational) and falls back to CVSS bucketing on ``cvss`` when
    the primary value is missing or unrecognised. Numeric inputs are
    interpreted as CVSS base scores so vendor-shaped reports that
    surface a bare score still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in FCS_STRING_SEVERITY:
            return FCS_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_fcs(iom):
    """Derive Faraday status from a Falcon IOM payload.

    Falcon IOMs carry a top-level ``status`` (Open / Closed / etc.) plus
    common alt keys; tolerate dict-wrapped and synonym shapes so
    downstream re-emissions through generic CNAPP pipelines still map
    cleanly.
    """
    if not isinstance(iom, dict):
        return "open"
    for key in ("status", "state", "iom_status", "iomStatus", "alert_status", "alertStatus"):
        raw = iom.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
        if isinstance(raw, str):
            mapped = FCS_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in FCS_STATUS_TO_FARADAY:
                return FCS_STATUS_TO_FARADAY[compact]
    return "open"


def build_filter_fql(cloud_provider, severities):
    """Build the Falcon Query Language filter for /cloud-security/queries/iom.

    Falcon FQL uses ``field:'value'`` for single values and
    ``field:['a','b']`` for sets, joined by ``+`` for AND. Empty filter
    is returned as an empty string so the caller can omit the query
    parameter cleanly.
    """
    clauses = []
    if cloud_provider:
        clauses.append(f"cloud_provider:'{cloud_provider}'")
    if severities and len(severities) < len(FCS_API_SEVERITY):
        joined = ",".join(f"'{s}'" for s in severities)
        clauses.append(f"severity:[{joined}]")
    return "+".join(clauses)


def fetch_access_token(host, client_id, client_secret):
    """Exchange Falcon service-account credentials for a short-lived bearer.

    Falcon's OAuth endpoint is ``POST {host}/oauth2/token`` with
    form-encoded body
    ``client_id=...&client_secret=...&grant_type=client_credentials``
    -> ``{"access_token": "...", "expires_in": N, "token_type": "bearer"}``.
    """
    if not host or not client_id or not client_secret:
        return None
    base = normalize_base_url(host)
    url = f"{base}/oauth2/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        resp = requests.post(url, data=payload, headers=headers, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("OAuth token request rejected (401). Check FALCON_CLIENT_ID / FALCON_CLIENT_SECRET.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"OAuth token request failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log("OAuth response was not JSON")
        return None
    token = extract_token(body)
    if not token:
        log("OAuth response missing access_token")
        return None
    return token


def extract_token(payload):
    """Pull the bearer token out of a Falcon OAuth response.

    Handles bare (``{"access_token": "..."}``), camel-cased
    (``{"accessToken": "..."}``), wrapped (``{"data": {"token": "..."}}``)
    and list-wrapped (``{"data": [{"token": "..."}]}``) shapes.
    """
    if not isinstance(payload, dict):
        return None
    for key in ("access_token", "accessToken", "token"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    data = payload.get("data")
    if isinstance(data, dict):
        for key in ("access_token", "accessToken", "token"):
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            for key in ("access_token", "accessToken", "token"):
                v = first.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return None


def extract_resources(payload):
    """Pull the resources list out of a Falcon response envelope.

    Falcon's canonical shape is ``{"meta": {...}, "resources": [...],
    "errors": [...]}``; tolerate bare lists and a handful of alt keys
    seen in adjacent endpoints (``data`` / ``results`` / ``items``).
    """
    if isinstance(payload, list):
        return [x for x in payload if x is not None]
    if not isinstance(payload, dict):
        return []
    for key in ("resources", "data", "results", "items"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if x is not None]
    return []


def extract_total(payload):
    """Pull the total-item count out of a Falcon response envelope."""
    if not isinstance(payload, dict):
        return None
    meta = payload.get("meta")
    if isinstance(meta, dict):
        pagination = meta.get("pagination")
        if isinstance(pagination, dict):
            for key in ("total", "totalItems", "total_items"):
                v = pagination.get(key)
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    return int(v)
        for key in ("total", "totalItems", "total_items"):
            v = meta.get(key)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                return int(v)
    for key in ("total", "totalItems", "total_items", "totalCount"):
        v = payload.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return int(v)
    return None


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
        log(f"{method} {url} rejected (401). Bearer expired or invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"{method} {url} rejected (403). API client lacks required scopes.")
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


def fetch_iom_ids(base_url, headers, cloud_provider, severities):
    """Paginate through /cloud-security/queries/iom and return all ids."""
    ids = []
    seen = set()
    offset = 0
    fql = build_filter_fql(cloud_provider, severities)
    for _ in range(MAX_PAGES):
        params = {"limit": PAGE_SIZE, "offset": offset}
        if fql:
            params["filter"] = fql
        payload = request(
            "GET",
            f"{base_url}/cloud-security/queries/iom/v1",
            headers,
            params=params,
        )
        if payload is None:
            break
        chunk = extract_resources(payload)
        if not chunk:
            break
        added = 0
        for iid in chunk:
            if isinstance(iid, dict):
                iid = iid.get("id") or iid.get("resource_id")
            if not isinstance(iid, str):
                continue
            s = iid.strip()
            if not s or s in seen:
                continue
            seen.add(s)
            ids.append(s)
            added += 1
        if added == 0:
            break
        offset += len(chunk)
        total = extract_total(payload)
        if isinstance(total, int) and offset >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
    return ids


def fetch_iom_entities(base_url, headers, ids):
    """Batch-fetch full IOM entities by id from /cloud-security/entities/iom."""
    entities = []
    if not ids:
        return entities
    for i in range(0, len(ids), ENTITIES_BATCH):
        batch = ids[i : i + ENTITIES_BATCH]
        params = [("ids", b) for b in batch]
        payload = request(
            "GET",
            f"{base_url}/cloud-security/entities/iom/v1",
            headers,
            params=params,
        )
        if payload is None:
            continue
        for entity in extract_resources(payload):
            if isinstance(entity, dict):
                entities.append(entity)
    return entities


def cvss_score(iom):
    """Pull a numeric CVSS / severity score out of a Falcon IOM payload.

    Falcon IOMs don't typically carry CVSS (CSPM is config-drift not a
    CVE scanner) but adjacent re-emissions do; walk the usual suspects.
    """
    if not isinstance(iom, dict):
        return None
    for key in (
        "cvss_score",
        "cvssScore",
        "score",
        "base_score",
        "baseScore",
        "severity_score",
        "severityScore",
        "risk_score",
        "riskScore",
    ):
        value = iom.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = iom.get(nested_key)
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


def cvss_vector(iom):
    if not isinstance(iom, dict):
        return ""
    for key in ("cvss_vector", "cvssVector", "vector", "vector_string", "vectorString"):
        value = iom.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = iom.get(nested_key)
        if isinstance(nested, dict):
            for k in ("vector", "vectorString", "vector_string"):
                v = nested.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def collect_cves(iom):
    """Pull CVE-* ids out of a Falcon IOM payload."""
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

    if not isinstance(iom, dict):
        return found
    for key in (
        "id",
        "policy_name",
        "policyName",
        "rule_name",
        "ruleName",
        "name",
        "title",
        "description",
        "summary",
        "remediation",
        "remediation_summary",
    ):
        v = iom.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cve", "cveId", "cve_id"):
        v = iom.get(key)
        if isinstance(v, str) and v.strip():
            add_token(v)
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = iom.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add_token(entry)
                elif isinstance(entry, dict):
                    add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
    return found


def collect_refs(iom):
    """Walk a Falcon IOM payload for CWE / advisory / URL refs."""
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

    if not isinstance(iom, dict):
        return refs

    cwe_raw = iom.get("cwe_id") or iom.get("cweId") or iom.get("cwe")
    if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
        add(f"CWE-{int(cwe_raw)}")
    elif isinstance(cwe_raw, str) and cwe_raw.strip():
        s = cwe_raw.strip()
        add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
    for key in ("cwes", "cweIds", "cwe_ids"):
        items = iom.get(key)
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

    # Surface the policy id as a stable pivot label
    policy_id = iom.get("policy_id") or iom.get("policyId")
    if policy_id not in (None, ""):
        add(f"Falcon-Policy: {policy_id}")
    # And the resource id, since it identifies the affected cloud asset
    resource_id = iom.get("resource_id") or iom.get("resourceId") or iom.get("resource_uuid")
    if isinstance(resource_id, str) and resource_id.strip():
        add(f"Falcon-Resource: {resource_id.strip()}")

    # Compliance pivots harvested from compliance / compliances tag-style
    # arrays (e.g. {"name": "CIS", "section": "2.1"})
    for key in ("compliance", "compliances", "frameworks"):
        items = iom.get(key)
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    name = it.get("name") or it.get("standard") or it.get("framework")
                    section = it.get("section") or it.get("sectionId") or it.get("section_id") or it.get("id")
                    if name and section:
                        add(f"Compliance: {name} {section}")
                    elif name:
                        add(f"Compliance: {name}")
                elif isinstance(it, str) and it.strip():
                    add(f"Compliance: {it.strip()}")

    for key in (
        "policy_url",
        "policyUrl",
        "url",
        "console_url",
        "consoleUrl",
        "cloud_provider_url",
        "cloudProviderUrl",
    ):
        url = iom.get(key)
        if isinstance(url, str) and url.strip():
            add(url.strip())

    for key in ("references", "links", "external_references", "externalReferences"):
        entry = iom.get(key)
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


def resource_label(iom):
    """Build a friendly label for the affected cloud resource."""
    if not isinstance(iom, dict):
        return ""
    name = iom.get("resource_name") or iom.get("resourceName") or iom.get("resource") or ""
    rtype = iom.get("resource_type") or iom.get("resourceType") or ""
    region = iom.get("region") or iom.get("cloud_provider_region") or ""
    if not name:
        name = iom.get("resource_id") or iom.get("resourceId") or iom.get("resource_uuid") or ""
    if name and rtype:
        label = f"{rtype} {name}"
    elif name:
        label = str(name)
    elif rtype:
        label = str(rtype)
    else:
        label = ""
    if region:
        label = f"{label} [{region}]" if label else f"[{region}]"
    return label.strip()


def policy_label(iom):
    if not isinstance(iom, dict):
        return ""
    for key in ("policy_name", "policyName", "rule_name", "ruleName", "name", "title"):
        v = iom.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    pid = iom.get("policy_id") or iom.get("policyId")
    if pid not in (None, ""):
        return str(pid).strip()
    return ""


def build_vulnerability(iom):
    """Build a Faraday vulnerability dict from one Falcon IOM."""
    if not isinstance(iom, dict):
        return None

    score = cvss_score(iom)
    severity = severity_from_fcs(iom.get("severity") or iom.get("policy_severity"), score)
    status = status_from_fcs(iom)

    plabel = policy_label(iom)
    rlabel = resource_label(iom)
    base_title = plabel or str(iom.get("title") or iom.get("id") or "Falcon IOM finding")
    raw_name = f"{base_title} on {rlabel}" if rlabel else base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = iom.get("description") or iom.get("details") or iom.get("policy_description")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if plabel:
        desc_parts.append(f"policy: {plabel}")
    policy_id = iom.get("policy_id") or iom.get("policyId")
    if policy_id not in (None, ""):
        desc_parts.append(f"policy_id: {policy_id}")
    policy_type = iom.get("policy_type") or iom.get("policyType")
    if policy_type:
        desc_parts.append(f"policy_type: {policy_type}")
    if rlabel:
        desc_parts.append(f"resource: {rlabel}")
    for label, keys in (
        ("resource_type", ("resource_type", "resourceType")),
        ("resource_id", ("resource_id", "resourceId", "resource_uuid")),
        ("cloud_provider", ("cloud_provider", "cloudProvider")),
        ("cloud_service", ("cloud_service_name", "cloudServiceName", "service")),
        ("cloud_account_id", ("account_id", "accountId", "cloud_account_id", "cloudAccountId")),
        ("cloud_account_name", ("account_name", "accountName", "cloud_account_name", "cloudAccountName")),
        ("region", ("region", "cloud_provider_region")),
        ("subscription_id", ("subscription_id", "subscriptionId")),
        ("resource_group", ("resource_group", "resourceGroup")),
    ):
        for k in keys:
            v = iom.get(k)
            if v not in (None, ""):
                desc_parts.append(f"{label}: {v}")
                break

    status_raw = iom.get("status") or iom.get("state")
    if status_raw:
        desc_parts.append(f"status: {status_raw}")
    sev_raw = iom.get("severity") or iom.get("policy_severity")
    if sev_raw:
        desc_parts.append(f"severity: {sev_raw}")

    for label, keys in (
        ("created", ("created_timestamp", "createdTimestamp", "created_at", "createdAt")),
        ("updated", ("updated_timestamp", "updatedTimestamp", "updated_at", "updatedAt")),
        ("first_seen", ("first_seen", "firstSeen", "first_seen_timestamp")),
        ("last_seen", ("last_seen", "lastSeen", "last_seen_timestamp", "scan_time", "scanTime")),
        ("closed", ("closed_timestamp", "closedTimestamp", "closed_at", "closedAt")),
    ):
        for k in keys:
            v = iom.get(k)
            if v:
                desc_parts.append(f"{label}: {v}")
                break

    tags_raw = iom.get("tags")
    if isinstance(tags_raw, list):
        flat = []
        for t in tags_raw:
            if isinstance(t, dict):
                tv = t.get("name") or t.get("value") or t.get("id")
                if tv:
                    flat.append(str(tv))
            elif t:
                flat.append(str(t))
        if flat:
            desc_parts.append(f"tags: {', '.join(flat)}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(iom)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(iom)
    refs = collect_refs(iom)

    resolution = (
        iom.get("remediation_summary")
        or iom.get("remediationSummary")
        or iom.get("remediation")
        or iom.get("recommendation")
        or iom.get("resolution")
        or iom.get("solution")
        or iom.get("fix")
        or ""
    )
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    external_id = str(iom.get("id") or iom.get("iom_id") or iom.get("iomId") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Falcon IOM {external_id}",
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
        "tags": ["crowdstrike_cloud", "cnapp", "cloud-security"],
    }


def host_bucket_key(iom):
    """Return the cloud-account bucket key for one IOM payload."""
    if not isinstance(iom, dict):
        return "__unknown__"
    for key in (
        "account_id",
        "accountId",
        "cloud_account_id",
        "cloudAccountId",
        "subscription_id",
        "subscriptionId",
        "project_id",
        "projectId",
    ):
        v = iom.get(key)
        if v not in (None, ""):
            return str(v)
    return "__unknown__"


def build_host(account_id, iom_meta, ioms, vulns):
    """Build a Faraday host shell from a Falcon cloud-account bucket."""
    name = ""
    vendor = ""
    region = ""
    if isinstance(iom_meta, dict):
        name = iom_meta.get("account_name") or iom_meta.get("accountName") or ""
        vendor = iom_meta.get("cloud_provider") or iom_meta.get("cloudProvider") or ""
        region = iom_meta.get("region") or iom_meta.get("cloud_provider_region") or ""
    if not name and ioms:
        first = ioms[0]
        if isinstance(first, dict):
            name = (
                first.get("account_name")
                or first.get("accountName")
                or first.get("cloud_account_name")
                or first.get("cloudAccountName")
                or ""
            )
            if not vendor:
                vendor = first.get("cloud_provider") or first.get("cloudProvider") or ""
            if not region:
                region = first.get("region") or first.get("cloud_provider_region") or ""
    hostname = ""
    if name and account_id:
        hostname = f"{name}@{account_id}"
    else:
        hostname = name or account_id or ""
    desc_parts = []
    if account_id:
        desc_parts.append(f"cloud_account_id={account_id}")
    if name:
        desc_parts.append(f"account={name}")
    if vendor:
        desc_parts.append(f"cloud_provider={vendor}")
    if region:
        desc_parts.append(f"region={region}")
    if ioms:
        desc_parts.append(f"ioms={len(ioms)}")
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
    host = env("FALCON_HOST", required=True)
    client_id = env("FALCON_CLIENT_ID", required=True)
    client_secret = env("FALCON_CLIENT_SECRET", required=True)
    cloud_provider = validate_cloud_provider(env("EXECUTOR_CONFIG_FCS_CLOUD_PROVIDER"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_FCS_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]
    severities = severities_at_or_above(min_severity)

    base_url = normalize_base_url(host)
    if not base_url:
        log("FALCON_HOST is required")
        sys.exit(1)

    token = fetch_access_token(host, client_id, client_secret)
    if not token:
        log("Failed to obtain Falcon access token; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    ids = fetch_iom_ids(base_url, headers, cloud_provider, severities)
    log(
        f"Resolved {len(ids)} Falcon Cloud Security IOM ids "
        f"(cloud_provider={cloud_provider or 'ALL'}, min_severity={min_severity})"
    )
    ioms = fetch_iom_entities(base_url, headers, ids)
    log(f"Fetched {len(ioms)} IOM entities")

    # Group IOMs by cloud account (one Faraday host per Falcon account)
    buckets = {}
    for iom in ioms:
        key = host_bucket_key(iom)
        buckets.setdefault(key, []).append(iom)

    hosts = []
    for key, bucket in buckets.items():
        meta = bucket[0] if bucket else {}
        vulns = []
        for iom in bucket:
            built = build_vulnerability(iom)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        host_id = "" if key == "__unknown__" else key
        hosts.append(build_host(host_id, meta, bucket, vulns))

    params = f"min_severity={min_severity}"
    if cloud_provider:
        params = f"cloud_provider={cloud_provider},{params}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "crowdstrike_cloud",
            "command": "crowdstrike_cloud",
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
