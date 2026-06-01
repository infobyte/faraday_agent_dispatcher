#!/usr/bin/env python
"""Lacework (CNAPP / CSPM) REST importer.

Pulls cloud-security vulnerability findings from a Lacework tenant via
the canonical ``POST /api/v2/Vulnerabilities/Hosts/search`` and
``POST /api/v2/Vulnerabilities/Containers/search`` endpoints and emits
Faraday bulk-create JSON to stdout. Each affected machine (host scope)
or container image (container scope) becomes one Faraday host (``ip`` =
synthetic ``0.0.0.0`` because CNAPP findings live on cloud resources,
not on IPs); per-resource findings are attached as Faraday
vulnerabilities — one per ``evalGuid`` / vuln+feature pair with engine
prefix ``[CNAPP]``.

Endpoints used:
  POST {LACEWORK_HOST}/api/v2/access/tokens
      -> OAuth-ish access-token exchange. Body ``{"keyId": "...",
      "expiryTime": 3600}`` sent with header ``X-LW-UAKS: <api_secret>``
      returns ``{"token": "...", "expiresAt": "..."}`` (also tolerated
      wrapped under ``data[0]``). Subsequent calls send
      ``Authorization: Bearer <token>``.
  POST {LACEWORK_HOST}/api/v2/Vulnerabilities/Hosts/search
      -> host-level vulnerability assessments. Filters on
      ``severity`` (string enum) and the standard ``timeFilter``
      window. Paginated via ``paging.urls.nextPage`` cursor. Each
      record carries ``mid`` (machine id) + ``machineTags.Hostname`` +
      ``featureKey`` (package) + ``vulnId`` (CVE) + ``fixInfo`` +
      ``cveProps`` (cvss / description / link).
  POST {LACEWORK_HOST}/api/v2/Vulnerabilities/Containers/search
      -> container-image vulnerability assessments. Same envelope as
      the hosts endpoint; record carries ``imageId`` +
      ``evalCtx.image_info.repo / registry / digest / tags`` +
      ``featureKey`` + ``vulnId`` + ``fixInfo``.

Auth: Lacework uses an api-key / api-secret pair tied to a service
account. The secret is sent as ``X-LW-UAKS: <api_secret>`` to
``/api/v2/access/tokens`` together with a JSON body that names the key
id; the response carries a short-lived bearer token that is then sent
as ``Authorization: Bearer <token>`` on subsequent calls. The tenant
URL is derived from ``LACEWORK_ACCOUNT`` (bare subdomain →
``https://<account>.lacework.net``; a fully qualified URL is honoured
as-is).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

import requests
import urllib3

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 500
MAX_PAGES = 200
DEFAULT_WINDOW_DAYS = 1
TOKEN_EXPIRY_SECONDS = 3600

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

VALID_SCOPE = ("hosts", "containers", "both")

# Lacework severity enum: Critical / High / Medium / Low / Info.
# Accept the usual synonyms surfaced by adjacent CNAPP feeds and
# downstream pipelines that re-emit Lacework findings.
LACEWORK_STRING_SEVERITY = {
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

# Lacework vulnerability assessment status lifecycle:
#   new / active / reopened           -> open
#   fixed / resolved / vulnerability_fixed / patched / remediated -> closed
#   suppressed / muted / wont_fix / risk_accepted / false_positive / expired -> risk-accepted
LACEWORK_STATUS_TO_FARADAY = {
    "new": "open",
    "open": "open",
    "active": "open",
    "reopened": "open",
    "re_opened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "vulnerability_fixed": "closed",
    "vulnerabilityfixed": "closed",
    "patched": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "dismissed": "risk-accepted",
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

LACEWORK_API_SEVERITY = {
    "info": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - Lacework: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(account):
    """Expand a bare account slug to the full Lacework tenant URL.

    Honours fully-qualified URLs (``https://acme.lacework.net``) and
    bare hostnames (``acme.lacework.net``) as-is; bare account slugs
    (``acme``) are expanded to ``https://acme.lacework.net``.
    """
    if not account:
        return ""
    text = str(account).strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return text.rstrip("/")
    if "." in text:
        return f"https://{text}".rstrip("/")
    return f"https://{text}.lacework.net"


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"LACEWORK_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def validate_scope(value):
    """Validate LACEWORK_SCOPE — hosts | containers | both.

    None / blank defaults to ``both`` so a fresh deployment surfaces
    every assessment surface without extra wiring. Garbage falls back
    to ``both`` with a log line so the operator can spot typos.
    """
    if value is None or value == "":
        return "both"
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if text in VALID_SCOPE:
        return text
    if text in ("host",):
        return "hosts"
    if text in ("container", "image", "images"):
        return "containers"
    if text in ("all", "any"):
        return "both"
    log(f"LACEWORK_SCOPE '{value}' not recognised; defaulting to 'both'")
    return "both"


def severities_at_or_above(min_severity):
    """Return the Lacework severity tokens at or above ``min_severity``.

    Used to build the ``severity`` filter in the Hosts/Containers
    search bodies so the tenant only paginates results that survive
    the client-side floor. ``info`` yields every bucket (no filter
    applied).
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = LACEWORK_API_SEVERITY.get(bucket)
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


def severity_from_lacework(value, cvss=None):
    """Map a Lacework severity to a Faraday bucket.

    Accepts Lacework's string enum (Critical / High / Medium / Low /
    Info) and falls back to CVSS bucketing on ``cvss`` when the
    primary value is missing or unrecognised. Numeric inputs are
    interpreted as CVSS base scores so vendor-shaped reports that
    surface a bare score still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in LACEWORK_STRING_SEVERITY:
            return LACEWORK_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_lacework(finding):
    """Derive Faraday status from a Lacework finding payload.

    Lacework carries a top-level ``status`` enum (New / Active /
    Reopened / Fixed / Resolved). We tolerate dict-wrapped and synonym
    shapes so downstream re-emissions through generic CNAPP pipelines
    still map cleanly.
    """
    if not isinstance(finding, dict):
        return "open"
    for key in ("status", "state", "vuln_status", "vulnStatus", "evalStatus"):
        raw = finding.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
        if isinstance(raw, str):
            mapped = LACEWORK_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in LACEWORK_STATUS_TO_FARADAY:
                return LACEWORK_STATUS_TO_FARADAY[compact]
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
        log(f"{method} {url} rejected (401). Check LACEWORK_API_KEY / LACEWORK_API_SECRET.")
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


def fetch_access_token(base_url, key_id, api_secret):
    """Exchange Lacework key/secret credentials for a short-lived bearer.

    Lacework's auth endpoint is ``POST {base_url}/api/v2/access/tokens``
    with header ``X-LW-UAKS: <api_secret>`` and JSON body
    ``{"keyId": "...", "expiryTime": 3600}`` -> ``{"token": "...",
    "expiresAt": "..."}`` (also tolerated wrapped under ``data[0]``).
    """
    if not base_url or not key_id or not api_secret:
        return None
    url = f"{base_url}/api/v2/access/tokens"
    headers = {
        "X-LW-UAKS": api_secret,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = {"keyId": key_id, "expiryTime": TOKEN_EXPIRY_SECONDS}
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Token exchange rejected (401). Check LACEWORK_API_KEY / LACEWORK_API_SECRET.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Token exchange failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        payload = resp.json()
    except ValueError:
        log("Token response was not JSON")
        return None
    return extract_token(payload)


def extract_token(payload):
    """Pull the bearer token out of a Lacework access-token response.

    Tolerates the bare ``{"token": "..."}`` shape, the wrapped
    ``{"data": [{"token": "..."}]}`` shape, and a few synonym keys
    (``accessToken`` / ``access_token``).
    """
    if not isinstance(payload, dict):
        return None
    for key in ("token", "accessToken", "access_token"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    data = payload.get("data")
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            for key in ("token", "accessToken", "access_token"):
                value = first.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    if isinstance(data, dict):
        for key in ("token", "accessToken", "access_token"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def extract_items(payload):
    """Pull the findings list out of a Lacework response envelope.

    Lacework returns ``{"data": [...], "paging": {...}}`` for
    paginated lists and sometimes a bare list; tolerate both shapes
    plus a handful of seen alt keys (``results`` / ``items`` /
    ``findings``).
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "results", "items", "findings"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def next_page_url(payload):
    """Extract the next-page URL from a Lacework paging envelope."""
    if not isinstance(payload, dict):
        return None
    paging = payload.get("paging")
    if not isinstance(paging, dict):
        return None
    urls = paging.get("urls")
    if isinstance(urls, dict):
        nxt = urls.get("nextPage") or urls.get("next_page") or urls.get("next")
        if isinstance(nxt, str) and nxt.strip():
            return nxt.strip()
    nxt = paging.get("nextPage") or paging.get("next_page") or paging.get("next")
    if isinstance(nxt, str) and nxt.strip():
        return nxt.strip()
    return None


def build_search_body(start_time, end_time, severities):
    """Build the JSON body for the Hosts/Containers search endpoints."""
    body = {
        "timeFilter": {
            "startTime": start_time,
            "endTime": end_time,
        },
    }
    filters = []
    if severities:
        filters.append({"field": "severity", "expression": "in", "values": list(severities)})
    if filters:
        body["filters"] = filters
    return body


def fetch_findings(base_url, headers, path, body):
    """Paginate through a Lacework vulnerability search endpoint."""
    results = []
    seen_ids = set()
    url = f"{base_url}{path}"
    next_url = None
    for _ in range(MAX_PAGES):
        if next_url:
            payload = request("GET", next_url, headers)
        else:
            payload = request("POST", url, headers, json_body=body)
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        for finding in chunk:
            fid = finding.get("evalGuid") or finding.get("eval_guid") or finding.get("id")
            if isinstance(fid, str) and fid in seen_ids:
                continue
            if isinstance(fid, str):
                seen_ids.add(fid)
            results.append(finding)
        next_url = next_page_url(payload)
        if not next_url:
            break
    return results


def cvss_score(finding):
    """Pull a numeric CVSS score out of a Lacework finding payload."""
    if not isinstance(finding, dict):
        return None
    for key in ("cvss_score", "cvssScore", "score", "baseScore", "base_score"):
        value = finding.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for nested_key in (
        "cveProps",
        "cve_props",
        "cve",
        "cvss",
        "cvss3",
        "cvssV3",
        "cvss_v3",
        "cvss2",
        "cvssV2",
        "cvss_v2",
    ):
        nested = finding.get(nested_key)
        if isinstance(nested, dict):
            for k in ("score", "baseScore", "base_score", "cvss_score", "cvssScore", "overallScore", "overall_score"):
                score = nested.get(k)
                if score is None or isinstance(score, (dict, list, bool)):
                    continue
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
            for nested_key2 in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2"):
                nested2 = nested.get(nested_key2)
                if isinstance(nested2, dict):
                    for k in ("score", "baseScore", "base_score"):
                        score = nested2.get(k)
                        if score is None or isinstance(score, (dict, list, bool)):
                            continue
                        try:
                            return float(score)
                        except (TypeError, ValueError):
                            continue
    return None


def cvss_vector(finding):
    if not isinstance(finding, dict):
        return ""
    for key in ("cvss_vector", "cvssVector", "vector", "vector_string", "vectorString"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for nested_key in (
        "cveProps",
        "cve_props",
        "cve",
        "cvss",
        "cvss3",
        "cvssV3",
        "cvss_v3",
        "cvss2",
        "cvssV2",
        "cvss_v2",
    ):
        nested = finding.get(nested_key)
        if isinstance(nested, dict):
            for k in ("vector", "vectorString", "vector_string"):
                v = nested.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
            for nested_key2 in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2"):
                nested2 = nested.get(nested_key2)
                if isinstance(nested2, dict):
                    for k in ("vector", "vectorString", "vector_string"):
                        v = nested2.get(k)
                        if isinstance(v, str) and v.strip():
                            return v.strip()
    return ""


def collect_cves(finding):
    """Pull CVE-* ids out of a Lacework finding payload."""
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

    if not isinstance(finding, dict):
        return found
    for key in ("vulnId", "vuln_id", "cveId", "cve_id", "cve"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            add_token(v)
    for key in ("name", "title", "description", "summary"):
        v = finding.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = finding.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add_token(entry)
                elif isinstance(entry, dict):
                    add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
    cve_block = finding.get("cveProps") or finding.get("cve_props") or finding.get("cve")
    if isinstance(cve_block, dict):
        for key in ("cve", "cveId", "cve_id", "name", "id"):
            v = cve_block.get(key)
            if isinstance(v, str) and v.strip():
                add_token(v)
        for key in ("description", "summary"):
            v = cve_block.get(key)
            if isinstance(v, str):
                scan(v)
    return found


def collect_refs(finding):
    """Walk a Lacework finding for CWE / advisory / URL refs."""
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

    if not isinstance(finding, dict):
        return refs

    cwe_raw = finding.get("cwe_id") or finding.get("cweId") or finding.get("cwe")
    if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
        add(f"CWE-{int(cwe_raw)}")
    elif isinstance(cwe_raw, str) and cwe_raw.strip():
        s = cwe_raw.strip()
        add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
    for key in ("cwes", "cweIds", "cwe_ids"):
        items = finding.get(key)
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

    vuln_id = finding.get("vulnId") or finding.get("vuln_id")
    if isinstance(vuln_id, str) and vuln_id.strip():
        add(f"Lacework-Vuln: {vuln_id.strip()}")

    for key in ("link", "url", "advisoryUrl", "advisory_url"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            add(v.strip())

    for key in ("references", "links", "external_references", "externalReferences"):
        entry = finding.get(key)
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

    cve_block = finding.get("cveProps") or finding.get("cve_props") or finding.get("cve")
    if isinstance(cve_block, dict):
        for key in ("link", "url", "advisoryUrl"):
            v = cve_block.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())
        for key in ("references", "links"):
            entry = cve_block.get(key)
            if isinstance(entry, list):
                for it in entry:
                    if isinstance(it, dict):
                        href = it.get("href") or it.get("url") or it.get("name") or it.get("value")
                        if href:
                            add(href)
                    elif it:
                        add(str(it))

    return refs


def machine_label(finding):
    """Build a friendly hostname for a host-level finding."""
    if not isinstance(finding, dict):
        return "", "", ""
    tags = finding.get("machineTags") if isinstance(finding.get("machineTags"), dict) else {}
    hostname = (
        tags.get("Hostname")
        or tags.get("hostname")
        or tags.get("Name")
        or finding.get("hostname")
        or finding.get("machine_hostname")
        or ""
    )
    mid = finding.get("mid") or finding.get("machineId") or finding.get("machine_id") or ""
    region = tags.get("Region") or tags.get("region") or tags.get("VmRegion") or finding.get("region") or ""
    return str(hostname), str(mid), str(region)


def image_label(finding):
    """Build a friendly identifier for a container-image finding."""
    if not isinstance(finding, dict):
        return "", "", "", ""
    eval_ctx = finding.get("evalCtx") if isinstance(finding.get("evalCtx"), dict) else {}
    image_info = eval_ctx.get("image_info") if isinstance(eval_ctx.get("image_info"), dict) else {}
    repo = (
        image_info.get("repo")
        or image_info.get("repository")
        or finding.get("imageRepo")
        or finding.get("image_repo")
        or ""
    )
    registry = image_info.get("registry") or finding.get("imageRegistry") or finding.get("image_registry") or ""
    digest = (
        image_info.get("digest")
        or image_info.get("image_digest")
        or finding.get("imageDigest")
        or finding.get("image_digest")
        or ""
    )
    image_id = (
        finding.get("imageId") or finding.get("image_id") or image_info.get("image_id") or image_info.get("id") or ""
    )
    repo_label = f"{registry}/{repo}" if registry and repo else (repo or registry)
    return str(repo_label), str(image_id), str(digest), str(registry)


def feature_label(finding):
    """Build a 'pkg@version' label from the featureKey block."""
    if not isinstance(finding, dict):
        return ""
    fkey = finding.get("featureKey") if isinstance(finding.get("featureKey"), dict) else {}
    name = fkey.get("name") or fkey.get("package") or finding.get("package") or ""
    version = fkey.get("version") or fkey.get("installed_version") or finding.get("package_version") or ""
    namespace = fkey.get("namespace") or ""
    if name and version:
        base = f"{name}@{version}"
    elif name:
        base = str(name)
    else:
        base = ""
    if base and namespace:
        return f"{base} ({namespace})"
    return base


def build_vulnerability(finding, scope="hosts"):
    """Build a Faraday vulnerability dict from one Lacework finding."""
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding)
    severity = severity_from_lacework(finding.get("severity"), score)
    status = status_from_lacework(finding)

    vuln_id = finding.get("vulnId") or finding.get("vuln_id") or finding.get("cveId") or finding.get("cve_id") or ""
    flabel = feature_label(finding)

    if scope == "containers":
        repo_label, image_id, digest, registry = image_label(finding)
        resource = repo_label or image_id or "image"
    else:
        hostname, mid, region = machine_label(finding)
        repo_label = ""
        image_id = ""
        digest = ""
        registry = ""
        resource = hostname or (f"machine-{mid}" if mid else "host")

    base_title = str(vuln_id or finding.get("title") or finding.get("name") or "Lacework finding")
    if flabel and resource:
        raw_name = f"{base_title} in {flabel} on {resource}"
    elif flabel:
        raw_name = f"{base_title} in {flabel}"
    elif resource:
        raw_name = f"{base_title} on {resource}"
    else:
        raw_name = base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = finding.get("description") or finding.get("summary")
    if not description:
        cve_block = finding.get("cveProps") or finding.get("cve_props") or finding.get("cve")
        if isinstance(cve_block, dict):
            description = cve_block.get("description") or cve_block.get("summary")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))

    if vuln_id:
        desc_parts.append(f"vuln_id: {vuln_id}")
    if flabel:
        desc_parts.append(f"package: {flabel}")
    desc_parts.append(f"scope: {scope}")

    if scope == "containers":
        if image_id:
            desc_parts.append(f"image_id: {image_id}")
        if repo_label:
            desc_parts.append(f"image: {repo_label}")
        if registry:
            desc_parts.append(f"registry: {registry}")
        if digest:
            desc_parts.append(f"digest: {digest}")
        eval_ctx = finding.get("evalCtx") if isinstance(finding.get("evalCtx"), dict) else {}
        image_info = eval_ctx.get("image_info") if isinstance(eval_ctx.get("image_info"), dict) else {}
        if isinstance(image_info, dict):
            tags = image_info.get("tags")
            if isinstance(tags, list) and tags:
                desc_parts.append(f"tags: {', '.join(str(t) for t in tags)}")
    else:
        hostname, mid, region = machine_label(finding)
        if hostname:
            desc_parts.append(f"hostname: {hostname}")
        if mid:
            desc_parts.append(f"mid: {mid}")
        if region:
            desc_parts.append(f"region: {region}")
        machine_tags = finding.get("machineTags") if isinstance(finding.get("machineTags"), dict) else {}
        if isinstance(machine_tags, dict):
            for label, keys in (
                ("cloud_provider", ("VmProvider", "Provider", "cloud_provider")),
                ("account_id", ("Account", "AwsAccountID", "AzureSubscriptionId", "ProjectId", "GcpProjectId")),
                ("instance_id", ("InstanceId", "instance_id", "VmInstanceId")),
                ("image_id", ("ImageId", "image_id")),
                ("os", ("Os", "OperatingSystem", "os")),
            ):
                for k in keys:
                    val = machine_tags.get(k)
                    if val not in (None, ""):
                        desc_parts.append(f"{label}: {val}")
                        break

    fix_info = finding.get("fixInfo") or finding.get("fix_info")
    if isinstance(fix_info, dict):
        fix_available = fix_info.get("fix_available") or fix_info.get("fixAvailable")
        if fix_available is not None:
            desc_parts.append(f"fix_available: {fix_available}")
        fixed_version = fix_info.get("fixed_version") or fix_info.get("fixedVersion")
        if fixed_version:
            desc_parts.append(f"fixed_version: {fixed_version}")

    state = finding.get("status") or finding.get("state")
    if state:
        desc_parts.append(f"status: {state}")
    sev_raw = finding.get("severity")
    if sev_raw:
        desc_parts.append(f"severity: {sev_raw}")
    for label, keys in (
        ("first_seen", ("first_seen_time", "firstSeen", "firstSeenTime", "first_seen")),
        ("last_seen", ("last_updated_time", "lastUpdatedTime", "lastSeen", "last_seen")),
        ("start_time", ("startTime", "start_time")),
        ("end_time", ("endTime", "end_time")),
    ):
        for k in keys:
            v = finding.get(k)
            if v:
                desc_parts.append(f"{label}: {v}")
                break

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(finding)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(finding)
    refs = collect_refs(finding)

    resolution = ""
    if isinstance(fix_info, dict):
        fixed_version = fix_info.get("fixed_version") or fix_info.get("fixedVersion")
        if fixed_version:
            resolution = f"Upgrade {feature_label(finding) or 'package'} to {fixed_version}."
    if not resolution:
        resolution = (
            finding.get("recommendation")
            or finding.get("remediation")
            or finding.get("resolution")
            or finding.get("solution")
            or ""
        )
        if isinstance(resolution, dict):
            resolution = (
                resolution.get("text")
                or resolution.get("description")
                or resolution.get("value")
                or json.dumps(resolution, separators=(",", ":"))
            )

    external_id = str(
        finding.get("evalGuid")
        or finding.get("eval_guid")
        or finding.get("id")
        or (f"{vuln_id}@{flabel}@{resource}" if vuln_id else "")
        or (cves[0] if cves else "")
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Lacework finding {external_id}",
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
        "tags": ["lacework", "cnapp", "cloud-security"],
    }


def host_bucket_key(finding, scope):
    """Build a stable bucket key for grouping findings into hosts."""
    if scope == "containers":
        repo_label, image_id, _digest, _reg = image_label(finding)
        key = image_id or repo_label
        return ("container", str(key)) if key else ("container", "__unknown__")
    hostname, mid, _region = machine_label(finding)
    key = mid or hostname
    return ("host", str(key)) if key else ("host", "__unknown__")


def build_host_record(key, scope, findings, vulns):
    """Build a Faraday host shell from a Lacework finding bucket."""
    if scope == "containers":
        first = findings[0] if findings else {}
        repo_label, image_id, digest, registry = image_label(first)
        name = repo_label or image_id
        hostname = ""
        if name and image_id and name != image_id:
            hostname = f"{name}@{image_id}"
        else:
            hostname = name or image_id or key
        desc_parts = []
        if image_id:
            desc_parts.append(f"image_id={image_id}")
        if repo_label:
            desc_parts.append(f"image={repo_label}")
        if registry:
            desc_parts.append(f"registry={registry}")
        if digest:
            desc_parts.append(f"digest={digest}")
        desc_parts.append("scope=containers")
        if findings:
            desc_parts.append(f"findings={len(findings)}")
        return {
            "ip": "0.0.0.0",
            "os": "",
            "hostnames": [hostname] if hostname else [],
            "mac": "",
            "description": " | ".join(desc_parts),
            "vulnerabilities": vulns,
        }
    first = findings[0] if findings else {}
    hostname, mid, region = machine_label(first)
    cloud_provider = ""
    account = ""
    os_str = ""
    tags = first.get("machineTags") if isinstance(first.get("machineTags"), dict) else {}
    if isinstance(tags, dict):
        cloud_provider = tags.get("VmProvider") or tags.get("Provider") or ""
        account = (
            tags.get("Account")
            or tags.get("AwsAccountID")
            or tags.get("AzureSubscriptionId")
            or tags.get("GcpProjectId")
            or ""
        )
        os_str = tags.get("Os") or tags.get("OperatingSystem") or ""
    if hostname and mid:
        host_hostname = f"{hostname}@{mid}"
    elif hostname:
        host_hostname = hostname
    elif mid:
        host_hostname = f"machine-{mid}"
    else:
        host_hostname = key
    desc_parts = []
    if mid:
        desc_parts.append(f"mid={mid}")
    if hostname:
        desc_parts.append(f"hostname={hostname}")
    if cloud_provider:
        desc_parts.append(f"cloud_provider={cloud_provider}")
    if account:
        desc_parts.append(f"account={account}")
    if region:
        desc_parts.append(f"region={region}")
    desc_parts.append("scope=hosts")
    if findings:
        desc_parts.append(f"findings={len(findings)}")
    return {
        "ip": "0.0.0.0",
        "os": str(os_str) if os_str else "",
        "hostnames": [host_hostname] if host_hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def iso8601(dt):
    """Format a datetime as the Lacework-friendly ISO-8601 string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def main():
    started = time.time()
    account = env("LACEWORK_ACCOUNT", required=True)
    key_id = env("LACEWORK_API_KEY", required=True)
    api_secret = env("LACEWORK_API_SECRET", required=True)
    scope = validate_scope(env("EXECUTOR_CONFIG_LACEWORK_SCOPE"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_LACEWORK_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]
    severities = severities_at_or_above(min_severity)
    if severities and len(severities) == len(LACEWORK_API_SEVERITY):
        severities = None

    base_url = normalize_base_url(account)
    if not base_url:
        log("LACEWORK_ACCOUNT is required")
        sys.exit(1)

    token = fetch_access_token(base_url, key_id, api_secret)
    if not token:
        log("Failed to obtain Lacework access token; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    end_dt = datetime.now(tz=timezone.utc)
    start_dt = end_dt - timedelta(days=DEFAULT_WINDOW_DAYS)
    body = build_search_body(iso8601(start_dt), iso8601(end_dt), severities)

    host_findings = []
    container_findings = []
    if scope in ("hosts", "both"):
        host_findings = fetch_findings(base_url, headers, "/api/v2/Vulnerabilities/Hosts/search", body)
    if scope in ("containers", "both"):
        container_findings = fetch_findings(base_url, headers, "/api/v2/Vulnerabilities/Containers/search", body)
    log(
        f"Processing {len(host_findings)} host findings + "
        f"{len(container_findings)} container findings "
        f"(scope={scope}, min_severity={min_severity})"
    )

    buckets = {}
    for finding in host_findings:
        key = host_bucket_key(finding, "hosts")
        buckets.setdefault((key, "hosts"), []).append(finding)
    for finding in container_findings:
        key = host_bucket_key(finding, "containers")
        buckets.setdefault((key, "containers"), []).append(finding)

    hosts = []
    for (bucket_key, bucket_scope), bucket in buckets.items():
        vulns = []
        for finding in bucket:
            built = build_vulnerability(finding, scope=bucket_scope)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        hosts.append(build_host_record(bucket_key[1], bucket_scope, bucket, vulns))

    params = f"scope={scope},min_severity={min_severity}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "lacework",
            "command": "lacework",
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
