#!/usr/bin/env python
"""Trend Micro Cloud One Conformity (CNAPP / CSPM) REST importer.

Pulls cloud-security checks (config / compliance failures) from a
Conformity tenant via the canonical ``GET /api/checks`` endpoint and
emits Faraday bulk-create JSON to stdout. Each Conformity cloud account
becomes one Faraday host (``ip`` = synthetic ``0.0.0.0`` because CSPM
findings live on cloud accounts / resources, not on IPs); per-account
failing checks are attached as Faraday vulnerabilities — one per
Conformity check id with engine prefix ``[CNAPP]``.

Endpoints used:
  GET {CONFORMITY_HOST}/api/checks
      -> primary listing endpoint. Uses JSON:API-style filters
      (``filter[accountIds]``, ``filter[regions]``, ``filter[statuses]``,
      ``filter[riskLevels]``) and ``page[number]`` / ``page[size]``
      pagination with cursor-style ``links.next`` honoured when present.
      The tenant's response is tolerated in both bare list and envelope
      (``data`` / ``items`` / ``results`` / ``checks``) shapes.
  GET {CONFORMITY_HOST}/api/accounts/{id}
      -> optional cloud-account enrichment. Looked up by id to surface
      account name / environment / cloud-type / aws-account-id metadata
      when the check payload is compact. Tolerant to 404 / missing.

Auth: Conformity uses a single API key tied to a service account;
``Authorization: ApiKey <CONFORMITY_API_KEY>`` on every call. A
pre-built ``Bearer <token>`` (or ``ApiKey <token>``) value in
``CONFORMITY_API_KEY`` short-circuits the scheme so federated /
JWT-style credentials still work.

Region: Conformity is region-pinned; ``CONFORMITY_REGION`` selects the
regional SaaS endpoint (``us-west-2`` default; ``eu-west-1``,
``ap-southeast-2``, etc.) and is forwarded as ``filter[regions]`` so
the tenant only paginates checks for that region.
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

VALID_MIN_RISK_LEVEL = ("low", "medium", "high", "very_high", "extreme")

# Conformity native risk levels mapped to Faraday severity buckets.
# Conformity has no "info" level (the lowest score is LOW); EXTREME +
# VERY_HIGH both bucket as critical because Faraday has a single top
# bucket.
CONFORMITY_RISK_TO_FARADAY = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "very_high": "critical",
    "veryhigh": "critical",
    "extreme": "critical",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Map a Faraday floor bucket to the Conformity native risk-level tokens
# at or above that floor. Used to build ``filter[riskLevels]``.
RISK_LEVEL_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "very_high": 3,
    "extreme": 4,
}

CONFORMITY_API_RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "VERY_HIGH", "EXTREME")

# Conformity standalone (cloudconformity.com) regional endpoints.
# Cloud One regions use the same hyphen-prefixed pattern.
DEFAULT_CONFORMITY_REGION = "us-west-2"
CONFORMITY_REGION_ALIASES = {
    "": "us-west-2",
    "default": "us-west-2",
    "us": "us-west-2",
    "us-west": "us-west-2",
    "us-west-2": "us-west-2",
    "eu": "eu-west-1",
    "eu-west": "eu-west-1",
    "eu-west-1": "eu-west-1",
    "ap": "ap-southeast-2",
    "apac": "ap-southeast-2",
    "ap-southeast": "ap-southeast-2",
    "ap-southeast-2": "ap-southeast-2",
    "sydney": "ap-southeast-2",
    "ap-southeast-1": "ap-southeast-1",
    "singapore": "ap-southeast-1",
    "sg": "ap-southeast-1",
    "ca-central-1": "ca-central-1",
    "ca-central": "ca-central-1",
    "ca": "ca-central-1",
}

# Conformity check status enum (post status filter)
CONFORMITY_STATUS_TO_FARADAY = {
    "failure": "open",
    "fail": "open",
    "failed": "open",
    "open": "open",
    "new": "open",
    "active": "open",
    "reopened": "open",
    "re_opened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "not_scored": "open",
    "notscored": "open",
    "warning": "open",
    "success": "closed",
    "succeeded": "closed",
    "pass": "closed",
    "passed": "closed",
    "ok": "closed",
    "closed": "closed",
    "fixed": "closed",
    "resolved": "closed",
    "mitigated": "closed",
    "remediated": "closed",
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


def log(msg):
    print(f"{datetime.utcnow()} - Conformity: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Normalize a fully-qualified URL or bare hostname; '' / None passthrough."""
    if not host:
        return ""
    text = str(host).strip()
    if not text:
        return ""
    base = text if text.startswith(("http://", "https://")) else f"https://{text}"
    return base.rstrip("/")


def resolve_region(value):
    """Resolve a region token to a canonical Conformity regional endpoint URL.

    Accepts the standalone Conformity / Cloud One canonical region tokens
    (``us-west-2``, ``eu-west-1``, ``ap-southeast-2``, etc.) and a handful
    of friendly aliases (``us``, ``eu``, ``apac``, ``singapore``, ``sg``,
    ``sydney``). A pre-built fully-qualified URL (``https://...``) is
    honoured as-is (stripped of trailing slashes); unrecognised tokens
    log a warning and fall back to the US default so a typo never surfaces
    as an opaque DNS / 404 failure.

    Returns a tuple of ``(base_url, region_token)``. ``region_token`` is
    the canonical region name (forwarded as ``filter[regions]``) and may
    be ``""`` for custom hosts.
    """
    if value is None:
        return (
            f"https://{DEFAULT_CONFORMITY_REGION}-api.cloudconformity.com",
            DEFAULT_CONFORMITY_REGION,
        )
    text = str(value).strip()
    if not text:
        return (
            f"https://{DEFAULT_CONFORMITY_REGION}-api.cloudconformity.com",
            DEFAULT_CONFORMITY_REGION,
        )
    # Honour fully-qualified URLs as-is.
    if text.lower().startswith(("http://", "https://")):
        return (text.rstrip("/"), "")
    lower = text.lower()
    canon = CONFORMITY_REGION_ALIASES.get(lower)
    if canon:
        return (f"https://{canon}-api.cloudconformity.com", canon)
    # Tolerate previously-unmapped regions if they look like AWS region
    # tokens (``<region>-<az>-<digit>``) so new Conformity regions don't
    # break the executor before this table is updated.
    if re.fullmatch(r"[a-z]{2}-[a-z]+-\d", lower):
        return (f"https://{lower}-api.cloudconformity.com", lower)
    log(f"CONFORMITY_REGION '{value}' not recognised; defaulting to " f"{DEFAULT_CONFORMITY_REGION}")
    return (
        f"https://{DEFAULT_CONFORMITY_REGION}-api.cloudconformity.com",
        DEFAULT_CONFORMITY_REGION,
    )


def validate_min_risk_level(value):
    """Validate CONFORMITY_MIN_RISK_LEVEL; unrecognised defaults to 'low'.

    Accepts Conformity's native enum (LOW | MEDIUM | HIGH | VERY_HIGH |
    EXTREME) plus a couple of Faraday-style synonyms (``critical``
    → ``extreme``). Garbage falls back to ``low`` (the lowest bucket =
    no filtering).
    """
    if value is None or value == "":
        return "low"
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    # Friendly synonyms.
    synonyms = {
        "critical": "extreme",
        "informational": "low",
        "info": "low",
    }
    text = synonyms.get(text, text)
    if text in VALID_MIN_RISK_LEVEL:
        return text
    log(f"CONFORMITY_MIN_RISK_LEVEL '{value}' not recognised; defaulting to 'low'")
    return "low"


def risk_levels_at_or_above(min_risk_level):
    """Return the Conformity ``riskLevels`` tokens at or above ``min_risk_level``.

    Used to build the ``filter[riskLevels]`` query param so the tenant
    only paginates results that survive the client-side floor. ``low``
    yields every bucket (no filter applied).
    """
    floor = RISK_LEVEL_ORDER.get(min_risk_level, 0)
    out = []
    for bucket, order in RISK_LEVEL_ORDER.items():
        if order >= floor:
            api = bucket.upper()
            if api not in out:
                out.append(api)
    return out


def severity_from_cvss(score):
    """Bucket a numeric CVSS / Conformity score to a Faraday severity."""
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


def severity_from_conformity(value, cvss=None):
    """Map a Conformity risk-level to a Faraday bucket.

    Accepts Conformity's native enum (LOW / MEDIUM / HIGH / VERY_HIGH /
    EXTREME) and falls back to CVSS bucketing on ``cvss`` when the
    primary value is missing or unrecognised. Numeric inputs are
    interpreted as CVSS-like base scores so vendor-shaped reports that
    surface a bare numeric ``risk-score`` still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        if text in CONFORMITY_RISK_TO_FARADAY:
            return CONFORMITY_RISK_TO_FARADAY[text]
        # Conformity also sometimes surfaces severity in the
        # informational / negligible / critical Faraday vocabulary;
        # tolerate that.
        fallback = {
            "info": "info",
            "informational": "info",
            "negligible": "info",
            "trivial": "info",
            "none": "info",
            "unknown": "info",
            "minor": "low",
            "moderate": "medium",
            "major": "high",
            "important": "high",
            "critical": "critical",
        }
        if text in fallback:
            return fallback[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def _attr_get(item, key, *alt_keys):
    """Pull a key out of a Conformity check / account, tolerating both
    the JSON:API-style ``{"attributes": {...}}`` envelope and a flat
    dict shape, plus a handful of camel ↔ kebab ↔ snake casing variants.
    """
    if not isinstance(item, dict):
        return None
    keys = (key,) + alt_keys
    # Try every key in the top-level (flat) shape.
    for k in keys:
        if k in item and item[k] not in (None, ""):
            return item[k]
        camel = re.sub(r"[-_](\w)", lambda m: m.group(1).upper(), k)
        if camel != k and camel in item and item[camel] not in (None, ""):
            return item[camel]
        snake = re.sub(r"[A-Z]", lambda m: f"_{m.group(0).lower()}", k).lstrip("_")
        if snake != k and snake in item and item[snake] not in (None, ""):
            return item[snake]
        kebab = re.sub(r"[A-Z]", lambda m: f"-{m.group(0).lower()}", k).lstrip("-")
        if kebab != k and kebab in item and item[kebab] not in (None, ""):
            return item[kebab]
    # JSON:API-style attributes envelope.
    attrs = item.get("attributes")
    if isinstance(attrs, dict):
        for k in keys:
            if k in attrs and attrs[k] not in (None, ""):
                return attrs[k]
            camel = re.sub(r"[-_](\w)", lambda m: m.group(1).upper(), k)
            if camel != k and camel in attrs and attrs[camel] not in (None, ""):
                return attrs[camel]
            snake = re.sub(r"[A-Z]", lambda m: f"_{m.group(0).lower()}", k).lstrip("_")
            if snake != k and snake in attrs and attrs[snake] not in (None, ""):
                return attrs[snake]
            kebab = re.sub(r"[A-Z]", lambda m: f"-{m.group(0).lower()}", k).lstrip("-")
            if kebab != k and kebab in attrs and attrs[kebab] not in (None, ""):
                return attrs[kebab]
    return None


def status_from_conformity(check):
    """Derive Faraday status from a Conformity check payload.

    Conformity surfaces ``status`` (FAILURE / SUCCESS / NOT_SCORED) and
    ``suppressed`` (bool) on each check. We tolerate dict-wrapped values
    and a handful of alt keys so downstream re-emissions still map
    cleanly. A truthy ``suppressed`` flag overrides the raw status.
    """
    if not isinstance(check, dict):
        return "open"
    # suppressed flag wins.
    suppressed = _attr_get(check, "suppressed", "is_suppressed", "isSuppressed")
    if isinstance(suppressed, bool) and suppressed:
        return "risk-accepted"
    if isinstance(suppressed, str) and suppressed.strip().lower() in ("true", "1", "yes"):
        return "risk-accepted"
    for key in ("status", "state", "checkStatus", "check_status", "result"):
        raw = _attr_get(check, key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
        if isinstance(raw, str):
            text = raw.strip().lower().replace(" ", "_").replace("-", "_")
            mapped = CONFORMITY_STATUS_TO_FARADAY.get(text)
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in CONFORMITY_STATUS_TO_FARADAY:
                return CONFORMITY_STATUS_TO_FARADAY[compact]
    return "open"


def auth_header(api_key):
    """Build the Authorization header.

    A pre-built ``Bearer <token>`` or ``ApiKey <token>`` value in
    ``api_key`` short-circuits the scheme so federated / JWT-style
    credentials still work; otherwise Conformity's native ``ApiKey
    <token>`` scheme is used.
    """
    if not api_key:
        return None
    key = str(api_key).strip()
    if not key:
        return None
    lower = key.lower()
    if lower.startswith(("bearer ", "apikey ", "api-key ", "api_key ")):
        parts = key.split(None, 1)
        scheme_raw = parts[0]
        # Canonicalise scheme: Bearer / ApiKey.
        if scheme_raw.lower() == "bearer":
            scheme = "Bearer"
        else:
            scheme = "ApiKey"
        return f"{scheme} {parts[1].strip()}"
    return f"ApiKey {key}"


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
        log(f"{method} {url} rejected (401). Check CONFORMITY_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"{method} {url} rejected (403). API key lacks required scopes.")
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


def extract_items(payload):
    """Pull the check / account list out of a Conformity response envelope."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "items", "results", "checks", "accounts", "findings"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def next_page_url(payload):
    """Pull the JSON:API-style ``links.next`` cursor URL out of a response."""
    if not isinstance(payload, dict):
        return ""
    links = payload.get("links")
    if isinstance(links, dict):
        for key in ("next", "next_page", "nextPage"):
            v = links.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    # Some tenants surface paging via top-level keys.
    for key in ("next", "nextPage", "next_page", "nextPageToken", "next_page_token"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def fetch_checks(base_url, headers, account_id, region, statuses, risk_levels):
    """Paginate through /api/checks for the supplied filters.

    Honours JSON:API-style ``links.next`` when the tenant returns one;
    otherwise falls back to ``page[number]`` + ``page[size]`` paging
    until the response is short or a total counter is hit.
    """
    results = []
    seen_ids = set()
    page = 1
    next_url = None
    for _ in range(MAX_PAGES):
        if next_url:
            url = next_url
            params = None
        else:
            url = f"{base_url}/api/checks"
            params = {
                "page[number]": page,
                "page[size]": PAGE_SIZE,
            }
            if account_id:
                params["filter[accountIds]"] = account_id
            if region:
                params["filter[regions]"] = region
            if statuses:
                params["filter[statuses]"] = ",".join(statuses)
            if risk_levels:
                params["filter[riskLevels]"] = ",".join(risk_levels)
        payload = request("GET", url, headers, params=params)
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for check in chunk:
            cid = check.get("id") or _attr_get(check, "id", "checkId", "check_id")
            if isinstance(cid, str) and cid in seen_ids:
                continue
            if isinstance(cid, str):
                seen_ids.add(cid)
            results.append(check)
            added += 1
        if added == 0:
            break
        total = None
        if isinstance(payload, dict):
            meta = payload.get("meta")
            if isinstance(meta, dict):
                total = (
                    meta.get("totalCount") or meta.get("total_count") or meta.get("totalItems") or meta.get("total")
                )
            if total is None:
                total = payload.get("totalCount") or payload.get("totalItems") or payload.get("total")
        if isinstance(total, (int, float)) and len(results) >= int(total):
            break
        next_url = next_page_url(payload)
        if next_url:
            continue
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def fetch_account(base_url, headers, account_id):
    """Look up an account by id; tolerant to 404 / missing."""
    if not account_id:
        return None
    payload = request(
        "GET",
        f"{base_url}/api/accounts/{account_id}",
        headers,
    )
    if isinstance(payload, dict):
        # JSON:API envelope.
        for key in ("data", "result", "account"):
            nested = payload.get(key)
            if isinstance(nested, dict):
                return nested
            if isinstance(nested, list) and nested and isinstance(nested[0], dict):
                return nested[0]
        return payload
    items = extract_items(payload)
    return items[0] if items else None


def cvss_score(check):
    """Pull a numeric CVSS / score out of a Conformity check payload."""
    if not isinstance(check, dict):
        return None
    sources = [check]
    attrs = check.get("attributes")
    if isinstance(attrs, dict):
        sources.append(attrs)
    for source in sources:
        for key in (
            "cvss_score",
            "cvssScore",
            "score",
            "base_score",
            "baseScore",
            "riskScore",
            "risk_score",
            "risk-score",
            "severityScore",
            "severity_score",
        ):
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
                    s = nested.get(k)
                    if s is None or isinstance(s, (dict, list, bool)):
                        continue
                    try:
                        return float(s)
                    except (TypeError, ValueError):
                        continue
    return None


def cvss_vector(check):
    if not isinstance(check, dict):
        return ""
    sources = [check]
    attrs = check.get("attributes")
    if isinstance(attrs, dict):
        sources.append(attrs)
    for source in sources:
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


def collect_cves(check):
    """Pull CVE-* ids out of a Conformity check payload.

    Conformity is a CSPM (config drift) tool, not a CVE scanner, but
    tenants occasionally surface CVE-shaped tokens in rule titles /
    descriptions (e.g. a Kubernetes admission policy that references
    ``CVE-2024-12345`` in its remediation text). We harvest defensively
    so downstream Faraday workspaces can pivot on CVE.
    """
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

    if not isinstance(check, dict):
        return found
    sources = [check]
    attrs = check.get("attributes")
    if isinstance(attrs, dict):
        sources.append(attrs)
    for source in sources:
        for key in (
            "id",
            "ruleId",
            "rule-id",
            "rule_id",
            "ruleTitle",
            "rule-title",
            "rule_title",
            "name",
            "title",
            "description",
            "message",
            "summary",
        ):
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
    return found


def collect_refs(check, account=None):
    """Walk a Conformity check + account for CWE / advisory / URL refs."""
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

    sources = []
    if isinstance(check, dict):
        sources.append(check)
        attrs = check.get("attributes")
        if isinstance(attrs, dict):
            sources.append(attrs)
    if isinstance(account, dict):
        sources.append(account)
        attrs = account.get("attributes")
        if isinstance(attrs, dict):
            sources.append(attrs)

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

    if isinstance(check, dict):
        rule_id = _attr_get(check, "rule-id", "ruleId", "rule_id")
        if rule_id:
            add(f"Conformity-Rule: {rule_id}")
        compliance = _attr_get(check, "compliance", "compliances", "compliance-standards")
        if isinstance(compliance, list):
            for c in compliance:
                if isinstance(c, dict):
                    name = c.get("name") or c.get("standard") or c.get("framework") or c.get("id")
                    section = c.get("sectionId") or c.get("section_id") or c.get("section")
                    if name and section:
                        add(f"Compliance: {name} {section}")
                    elif name:
                        add(f"Compliance: {name}")
                elif isinstance(c, str) and c.strip():
                    add(f"Compliance: {c.strip()}")
        categories = _attr_get(check, "categories", "category")
        if isinstance(categories, list):
            for cat in categories:
                if isinstance(cat, str) and cat.strip():
                    add(f"Conformity-Category: {cat.strip()}")
        resource = _attr_get(check, "resource", "resource-id", "resourceId")
        if isinstance(resource, str) and resource.strip():
            add(f"Conformity-Resource: {resource.strip()}")
        for key in (
            "resolution-page-url",
            "resolutionPageUrl",
            "resolution_page_url",
            "url",
            "consoleUrl",
            "console-url",
            "knowledge-base-url",
            "knowledgeBaseUrl",
        ):
            v = _attr_get(check, key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    if isinstance(account, dict):
        for key in ("url", "consoleUrl", "console-url", "console_url"):
            v = _attr_get(account, key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def resource_label(check):
    """Build a friendly label for the affected cloud resource."""
    name = ""
    nat = ""
    region = ""
    if isinstance(check, dict):
        name = (
            _attr_get(check, "resource-name", "resourceName", "resource_name")
            or _attr_get(check, "resource", "resource-id", "resourceId", "resource_id")
            or ""
        )
        nat = (
            _attr_get(check, "service", "service-name", "serviceName")
            or _attr_get(check, "resource-type", "resourceType", "resource_type")
            or ""
        )
        region = _attr_get(check, "region", "regions") or ""
    if name and nat:
        label = f"{nat} {name}"
    elif name:
        label = str(name)
    elif nat:
        label = str(nat)
    else:
        label = ""
    if region:
        label = f"{label} [{region}]" if label else f"[{region}]"
    return label.strip()


def rule_label(check):
    """Pick the most descriptive rule label out of a Conformity check."""
    if not isinstance(check, dict):
        return ""
    label = (
        _attr_get(check, "rule-title", "ruleTitle", "rule_title")
        or _attr_get(check, "title")
        or _attr_get(check, "message")
        or _attr_get(check, "name")
    )
    if not label:
        label = _attr_get(check, "rule-id", "ruleId", "rule_id") or ""
    return str(label).strip()


def build_vulnerability(check, account=None):
    """Build a Faraday vulnerability dict from one Conformity check."""
    if not isinstance(check, dict):
        return None

    score = cvss_score(check)
    risk_raw = _attr_get(check, "risk-level", "riskLevel", "risk_level", "severity")
    severity = severity_from_conformity(risk_raw, score)
    status = status_from_conformity(check)

    rlabel = rule_label(check)
    elabel = resource_label(check)
    base_title = rlabel or str(_attr_get(check, "title") or check.get("id") or "Conformity check")
    raw_name = f"{base_title} on {elabel}" if elabel else base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = _attr_get(check, "description", "details", "message")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if rlabel:
        desc_parts.append(f"rule: {rlabel}")
    rule_id = _attr_get(check, "rule-id", "ruleId", "rule_id")
    if rule_id:
        desc_parts.append(f"rule_id: {rule_id}")
    if elabel:
        desc_parts.append(f"resource: {elabel}")

    surfaced = set()
    for label, getter in (
        ("service", lambda c: _attr_get(c, "service", "service-name", "serviceName")),
        ("resource_type", lambda c: _attr_get(c, "resource-type", "resourceType", "resource_type")),
        ("resource_id", lambda c: _attr_get(c, "resource", "resource-id", "resourceId", "resource_id")),
        ("cloud_type", lambda c: _attr_get(c, "cloud-type", "cloudType", "cloud_type", "provider")),
        (
            "cloud_account_id",
            lambda c: _attr_get(
                c,
                "aws-account-id",
                "awsAccountId",
                "azure-subscription-id",
                "gcp-project-id",
                "accountId",
                "account_id",
            ),
        ),
        ("cloud_account_name", lambda c: _attr_get(c, "account-name", "accountName", "account_name", "name")),
        ("region", lambda c: _attr_get(c, "region", "regions")),
        ("environment", lambda c: _attr_get(c, "environment", "env")),
    ):
        v = getter(check)
        if v in (None, "") and isinstance(account, dict):
            v = getter(account)
        if v not in (None, "") and label not in surfaced:
            desc_parts.append(f"{label}: {v}")
            surfaced.add(label)

    state = _attr_get(check, "status", "state")
    if state:
        desc_parts.append(f"status: {state}")
    if risk_raw:
        desc_parts.append(f"risk_level: {risk_raw}")
    suppressed = _attr_get(check, "suppressed", "is_suppressed", "isSuppressed")
    if suppressed is not None and not isinstance(suppressed, bool):
        desc_parts.append(f"suppressed: {suppressed}")
    elif suppressed is True:
        desc_parts.append("suppressed: true")
    for label, keys in (
        ("created", ("created-date", "createdDate", "created_date", "createdAt", "created_at")),
        ("updated", ("last-modified-date", "lastModifiedDate", "last_modified_date", "updatedAt", "updated_at")),
        ("first_seen", ("first-seen", "firstSeen", "first_seen")),
        ("last_seen", ("last-seen", "lastSeen", "last_seen")),
    ):
        for k in keys:
            v = _attr_get(check, k)
            if v:
                desc_parts.append(f"{label}: {v}")
                break

    categories = _attr_get(check, "categories", "category")
    if isinstance(categories, list):
        flat = [str(c) for c in categories if isinstance(c, str) and c.strip()]
        if flat:
            desc_parts.append(f"categories: {', '.join(flat)}")
    compliance = _attr_get(check, "compliance", "compliances", "compliance-standards")
    if isinstance(compliance, list):
        flat = []
        for c in compliance:
            if isinstance(c, str) and c.strip():
                flat.append(c.strip())
            elif isinstance(c, dict):
                v = c.get("name") or c.get("standard") or c.get("framework") or c.get("id")
                if v:
                    flat.append(str(v))
        if flat:
            desc_parts.append(f"compliance: {', '.join(flat)}")
    tags = _attr_get(check, "tags", "labels")
    if isinstance(tags, list):
        flat = []
        for t in tags:
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
    vector = cvss_vector(check)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(check)
    refs = collect_refs(check, account)

    resolution = (
        _attr_get(check, "resolution", "resolution-page-url", "resolutionPageUrl")
        or _attr_get(check, "remediation", "recommendation", "fix", "solution")
        or ""
    )
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    external_id = str(check.get("id") or _attr_get(check, "checkId", "check_id") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Conformity check {external_id}",
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
        "tags": ["trendmicro_conformity", "cnapp", "cloud-security"],
    }


def host_bucket_key(check):
    """Pick the most stable cloud-account identifier in a check.

    Conformity exposes the account id both directly on the check
    (``aws-account-id`` / ``azure-subscription-id`` / etc.) and through
    the ``relationships.account.data.id`` JSON:API pointer. We try the
    relationship pointer first (it's the Conformity-internal id used by
    /api/accounts/{id}) and fall back to the native cloud account
    number when the relationship pointer is missing.
    """
    if not isinstance(check, dict):
        return "__unknown__"
    relationships = check.get("relationships")
    if isinstance(relationships, dict):
        account_rel = relationships.get("account")
        if isinstance(account_rel, dict):
            data = account_rel.get("data")
            if isinstance(data, dict) and data.get("id"):
                return str(data["id"])
    for key in (
        "accountId",
        "account_id",
        "account-id",
        "aws-account-id",
        "awsAccountId",
        "azure-subscription-id",
        "azureSubscriptionId",
        "gcp-project-id",
        "gcpProjectId",
    ):
        v = _attr_get(check, key)
        if v not in (None, ""):
            return str(v)
    return "__unknown__"


def build_host(account_id, account, checks, vulns):
    """Build a Faraday host shell from a Conformity account bucket."""
    name = ""
    environment = ""
    cloud_type = ""
    cloud_account_number = ""
    region = ""
    if isinstance(account, dict):
        name = _attr_get(account, "name", "account-name", "accountName") or ""
        environment = _attr_get(account, "environment", "env") or ""
        cloud_type = _attr_get(account, "cloud-type", "cloudType", "cloud_type", "provider") or ""
        cloud_account_number = (
            _attr_get(
                account,
                "aws-account-id",
                "awsAccountId",
                "azure-subscription-id",
                "gcp-project-id",
                "external-account-number",
                "externalAccountNumber",
            )
            or ""
        )
        region = _attr_get(account, "region", "regions") or ""
    if not name and checks:
        first = checks[0]
        if isinstance(first, dict):
            name = _attr_get(first, "account-name", "accountName", "account_name", "name") or ""
            if not cloud_type:
                cloud_type = _attr_get(first, "cloud-type", "cloudType", "cloud_type", "provider") or ""
            if not cloud_account_number:
                cloud_account_number = (
                    _attr_get(
                        first,
                        "aws-account-id",
                        "awsAccountId",
                        "azure-subscription-id",
                        "gcp-project-id",
                    )
                    or ""
                )
            if not region:
                region = _attr_get(first, "region", "regions") or ""
    hostname = ""
    if name and account_id and account_id != "__unknown__":
        hostname = f"{name}@{account_id}"
    elif account_id and account_id != "__unknown__":
        hostname = account_id
    else:
        hostname = name
    desc_parts = []
    if account_id and account_id != "__unknown__":
        desc_parts.append(f"account_id={account_id}")
    if name:
        desc_parts.append(f"account={name}")
    if environment:
        desc_parts.append(f"environment={environment}")
    if cloud_type:
        desc_parts.append(f"cloud_type={cloud_type}")
    if cloud_account_number:
        desc_parts.append(f"cloud_account_number={cloud_account_number}")
    if region:
        desc_parts.append(f"region={region}")
    if checks:
        desc_parts.append(f"checks={len(checks)}")
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
    api_key = env("CONFORMITY_API_KEY", required=True)
    account_id = env("EXECUTOR_CONFIG_CONFORMITY_ACCOUNT_ID")
    region_raw = env("EXECUTOR_CONFIG_CONFORMITY_REGION")
    min_risk_level = validate_min_risk_level(env("EXECUTOR_CONFIG_CONFORMITY_MIN_RISK_LEVEL"))

    base_url, region = resolve_region(region_raw)
    if not base_url:
        log("Failed to resolve Conformity base URL; aborting.")
        sys.exit(1)

    auth = auth_header(api_key)
    if not auth:
        log("Failed to build Authorization header from CONFORMITY_API_KEY; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": auth,
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
    }

    # Conformity's /api/checks returns all checks (SUCCESS + FAILURE +
    # NOT_SCORED) by default. We're an issue importer so we forward
    # filter[statuses]=FAILURE to keep the payload focused; SUCCESS
    # checks are dropped at the bucketing stage as a defensive
    # secondary filter.
    statuses = ["FAILURE"]
    risk_levels = risk_levels_at_or_above(min_risk_level)
    if risk_levels and len(risk_levels) == len(CONFORMITY_API_RISK_LEVELS):
        risk_levels = None

    floor_severity = CONFORMITY_RISK_TO_FARADAY.get(min_risk_level, "low")
    floor = SEVERITY_ORDER[floor_severity]

    checks = fetch_checks(
        base_url,
        headers,
        account_id,
        region,
        statuses,
        risk_levels,
    )
    log(
        f"Processing {len(checks)} Conformity checks "
        f"(account_id={account_id or 'ALL'}, region={region or 'ALL'}, "
        f"min_risk_level={min_risk_level.upper()})"
    )

    # Group checks by cloud account (one Faraday host per account)
    account_buckets = {}
    account_meta = {}
    for check in checks:
        key = host_bucket_key(check)
        account_buckets.setdefault(key, []).append(check)

    # Best-effort account enrichment per unique account id
    for key in list(account_buckets.keys()):
        if key == "__unknown__":
            continue
        account = fetch_account(base_url, headers, key)
        if account:
            account_meta[key] = account

    hosts = []
    for key, bucket in account_buckets.items():
        account = account_meta.get(key)
        vulns = []
        for check in bucket:
            # Defensive secondary filter: drop SUCCESS-status checks
            # even if the tenant ignored filter[statuses].
            built = build_vulnerability(check, account)
            if built is None:
                continue
            if built["status"] == "closed":
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        host_id = "" if key == "__unknown__" else key
        hosts.append(build_host(host_id, account, bucket, vulns))

    params = f"min_risk_level={min_risk_level.upper()},region={region or 'ALL'}"
    if account_id:
        params = f"{params},account_id={account_id}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "trendmicro_conformity",
            "command": "trendmicro_conformity",
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
