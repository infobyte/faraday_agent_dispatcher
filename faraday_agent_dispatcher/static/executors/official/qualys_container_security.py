#!/usr/bin/env python
"""Qualys Container Security (QCS) REST importer.

Pulls container image and running-container vulnerability findings from
a Qualys Container Security tenant via the canonical
``GET /csapi/v1.3/images`` and ``GET /csapi/v1.3/containers`` endpoints
and emits Faraday bulk-create JSON to stdout. Each QCS image bucket
(``imageId`` / ``sha``) becomes one Faraday host (synthetic ``0.0.0.0``
ip because image scans live on container layers, not on IPs) with
hostname ``{registry}/{repo}:{tag}@{image_id}``; each QCS container
bucket (``containerId`` / ``name``) becomes one Faraday host (synthetic
``0.0.0.0`` ip because the API does not surface a stable container ip
and the container id / name carries the pivot) with hostname
``{name}@{containerId}``. Per-bucket findings are attached as Faraday
vulnerabilities — one per QCS vulnerability (``qid`` + ``cve`` +
parent) — with engine prefix ``[CNAPP]``.

Endpoints used:
  POST {QUALYS_HOST}/auth
      -> credentials exchange. Body
      ``username=<user>&password=<pass>&token=true`` (form-encoded);
      response carries Qualys's short-lived JWT (~4 h validity, returned
      as plain text). Subsequent calls send
      ``Authorization: Bearer <token>``.
  GET {QUALYS_HOST}/csapi/v1.3/images
      -> image inventory. Paginated via ``pageNo`` (1-based) +
      ``pageSize`` cursor. Filtered via the Qualys QQL syntax
      (``filter=registry:'docker.io' and repo:'myorg/myapp'``). Each
      image carries the embedded ``vulnerabilities`` array; we surface
      one Faraday vuln per entry.
  GET {QUALYS_HOST}/csapi/v1.3/containers
      -> running container inventory. Same pagination + filter syntax.
      Each container carries the embedded ``vulnerabilities`` array.

Auth: Qualys Container Security shares the same identity store as the
classic Qualys VMDR / PC / WAS subscriptions — the QUALYS_USER /
QUALYS_PASSWORD pair (or a SAML/federated identity) is sent as form
data to ``POST /auth`` and exchanged for a short-lived JWT. The JWT is
then sent as ``Authorization: Bearer <token>`` on all subsequent calls.
``QUALYS_HOST`` is the QCS gateway URL for the customer's platform
pod (e.g. ``https://gateway.qg2.apps.qualys.com`` for US2,
``https://gateway.qg3.apps.qualys.com`` for US3,
``https://gateway.qg1.apps.qualys.eu`` for EU1).
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
PAGE_SIZE = 50
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Qualys Container Security severity scale (1-5):
#   1 = Minimal -> info
#   2 = Medium -> medium
#   3 = Serious -> high
#   4 = Critical -> critical
#   5 = Urgent -> critical
QCS_NUMERIC_SEVERITY = {
    1: "info",
    2: "medium",
    3: "high",
    4: "critical",
    5: "critical",
}

# Qualys also surfaces severity as free-form tokens on some endpoints
# (NVD / upstream feeds tokens for image vulnerabilities). Tolerate the
# usual synonyms.
QCS_STRING_SEVERITY = {
    "urgent": "critical",
    "critical": "critical",
    "serious": "high",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "minimal": "info",
    "negligible": "info",
    "unimportant": "info",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "unknown": "info",
}

# QCS vulnerability status lives on the embedded vulnerability and is
# free-form (``Active`` / ``Fixed`` / ``Reopened`` / ``Disabled`` /
# ``Excluded``). Map to Faraday's open / closed / risk-accepted buckets.
QCS_STATUS_TO_FARADAY = {
    "active": "open",
    "new": "open",
    "open": "open",
    "detected": "open",
    "needed": "open",
    "reopened": "open",
    "re_opened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "patched": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "disabled": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "excluded": "risk-accepted",
    "dismissed": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "acknowledged": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "expired": "risk-accepted",
    "deferred": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - QualysContainerSecurity: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
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
        log(f"QCS_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


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


def severity_from_qcs(value, cvss=None):
    """Map a Qualys Container Security severity to a Faraday bucket.

    Accepts Qualys's 1-5 numeric scale (1=Minimal ... 5=Urgent) and the
    more familiar critical/high/medium/low/info tokens upstream feeds
    use. Falls back to CVSS bucketing on ``cvss`` when the primary
    value is missing or unrecognised. Numeric strings that fall in the
    Qualys 1-5 range are interpreted as the QCS scale; everything else
    is treated as a CVSS base score.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, int) and value in QCS_NUMERIC_SEVERITY:
            return QCS_NUMERIC_SEVERITY[value]
        if isinstance(value, float) and value.is_integer() and int(value) in QCS_NUMERIC_SEVERITY:
            return QCS_NUMERIC_SEVERITY[int(value)]
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in QCS_STRING_SEVERITY:
            return QCS_STRING_SEVERITY[text]
        try:
            as_num = float(text)
        except ValueError:
            as_num = None
        if as_num is not None:
            if as_num.is_integer() and int(as_num) in QCS_NUMERIC_SEVERITY:
                return QCS_NUMERIC_SEVERITY[int(as_num)]
            return severity_from_cvss(as_num)
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_qcs(finding):
    """Derive Faraday status from a QCS vulnerability payload."""
    if not isinstance(finding, dict):
        return "open"
    raw = finding.get("status") or finding.get("state") or finding.get("vulnStatus")
    if isinstance(raw, dict):
        raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in QCS_STATUS_TO_FARADAY:
            return QCS_STATUS_TO_FARADAY[text]
        compact = text.replace(" ", "").replace("-", "").replace("_", "")
        if compact in QCS_STATUS_TO_FARADAY:
            return QCS_STATUS_TO_FARADAY[compact]
    fix_info = finding.get("fixInfo") or finding.get("fix_info")
    if isinstance(fix_info, dict):
        ftype = fix_info.get("status") or fix_info.get("state")
        if isinstance(ftype, str) and ftype.strip().lower() in QCS_STATUS_TO_FARADAY:
            return QCS_STATUS_TO_FARADAY[ftype.strip().lower()]
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
        log(f"{method} {url} rejected (401). Check QUALYS_USER / QUALYS_PASSWORD.")
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
    """Exchange Qualys user / password for a short-lived JWT.

    Qualys's QCS auth endpoint is ``POST {base_url}/auth`` with
    ``Content-Type: application/x-www-form-urlencoded`` body
    ``username=<user>&password=<pass>&token=true``. The response body
    is the JWT as plain text (no JSON wrapper). Some stacks return
    ``{"token": "..."}`` JSON instead; ``extract_token`` tolerates both
    shapes.
    """
    if not base_url or not username or not password:
        return None
    url = f"{base_url}/auth"
    body = {"username": username, "password": password, "token": "true"}
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        resp = requests.post(url, headers=headers, data=body, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Login rejected (401). Check QUALYS_USER / QUALYS_PASSWORD.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Login failed ({resp.status_code}): {resp.text[:500]}")
        return None
    text = resp.text.strip() if resp.text else ""
    try:
        payload = resp.json()
    except ValueError:
        return text or None
    token = extract_token(payload)
    return token or text or None


def extract_token(payload):
    """Pull the JWT out of a Qualys ``/auth`` response.

    Tolerates the bare ``"<jwt-string>"`` shape (plain-text body
    consumers may also pass already-string payloads through), the
    ``{"token": "..."}`` shape, the ``{"access_token": "..."}`` shape,
    and the wrapped ``{"data": {"token": "..."}}`` /
    ``{"data": [{"token": "..."}]}`` shape.
    """
    if isinstance(payload, str):
        return payload.strip() or None
    if not isinstance(payload, dict):
        return None
    for key in ("token", "accessToken", "access_token", "jwt", "jwtToken"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    data = payload.get("data")
    if isinstance(data, dict):
        for key in ("token", "accessToken", "access_token", "jwt", "jwtToken"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            for key in ("token", "accessToken", "access_token", "jwt", "jwtToken"):
                value = first.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def extract_items(payload):
    """Pull the image / container list out of a QCS envelope.

    Qualys QCS returns ``{"count": N, "data": [...]}`` for both
    /images and /containers. Some stacks return a bare list (when
    behind a reverse proxy that re-wraps); tolerate both shapes.
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "results", "items", "images", "containers", "list"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def build_qql_filter(registry, repo):
    """Build a Qualys QQL filter string from registry / repo fragments.

    QCS uses a ``field:'value'`` syntax with ``and`` separating ANDed
    terms (the same QQL grammar used by Qualys's other modules). Empty
    fragments are dropped so the filter stays short.
    """
    parts = []
    if registry:
        parts.append(f"registry:'{registry}'")
    if repo:
        parts.append(f"repo:'{repo}'")
    return " and ".join(parts)


def fetch_page(base_url, headers, endpoint, qql, page_no, page_size):
    """Pull one page from a QCS listing endpoint."""
    params = {"pageNo": page_no, "pageSize": page_size}
    if qql:
        params["filter"] = qql
    return request("GET", f"{base_url}{endpoint}", headers, params=params)


def fetch_all(base_url, headers, endpoint, qql):
    """Paginate through a QCS listing endpoint."""
    results = []
    seen_ids = set()
    for page_no in range(1, MAX_PAGES + 1):
        payload = fetch_page(base_url, headers, endpoint, qql, page_no, PAGE_SIZE)
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for item in chunk:
            iid = (
                item.get("imageId") or item.get("containerId") or item.get("sha") or item.get("_id") or item.get("id")
            )
            key = str(iid).strip() if iid else None
            if key and key in seen_ids:
                continue
            if key:
                seen_ids.add(key)
            results.append(item)
            added += 1
        if added == 0:
            break
        if len(chunk) < PAGE_SIZE:
            break
    return results


def cvss_score(finding, meta=None):
    """Pull a numeric CVSS / score out of a QCS vuln payload."""
    candidates = []
    if isinstance(finding, dict):
        candidates.append(finding)
    if isinstance(meta, dict):
        candidates.append(meta)
    for source in candidates:
        for key in ("cvss", "cvssScore", "cvss_score", "score", "baseScore", "base_score"):
            value = source.get(key)
            if value is None or isinstance(value, (dict, list, bool)):
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        for nested_key in ("cvss3Info", "cvssV3", "cvss_v3", "cvss3", "cvss2Info", "cvssV2", "cvss_v2"):
            nested = source.get(nested_key)
            if isinstance(nested, dict):
                for k in ("baseScore", "base_score", "score", "overallScore", "overall_score"):
                    score = nested.get(k)
                    if score is None or isinstance(score, (dict, list, bool)):
                        continue
                    try:
                        return float(score)
                    except (TypeError, ValueError):
                        continue
    return None


def cvss_vector(finding, meta=None):
    candidates = []
    if isinstance(finding, dict):
        candidates.append(finding)
    if isinstance(meta, dict):
        candidates.append(meta)
    for source in candidates:
        for key in ("vectorString", "vector_string", "cvssVector", "cvss_vector", "vector"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for nested_key in ("cvss3Info", "cvssV3", "cvss_v3", "cvss3", "cvss2Info", "cvssV2", "cvss_v2"):
            nested = source.get(nested_key)
            if isinstance(nested, dict):
                for k in ("vector", "vectorString", "vector_string"):
                    v = nested.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    return ""


def collect_cves(finding, meta=None):
    """Pull CVE-* ids out of a QCS vuln payload."""
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

    sources = []
    if isinstance(finding, dict):
        sources.append(finding)
    if isinstance(meta, dict):
        sources.append(meta)

    for source in sources:
        for key in ("cve", "cveId", "cve_id", "CVE"):
            v = source.get(key)
            if isinstance(v, str) and v.strip():
                add_token(v)
        for key in ("cveids", "cveIds", "cve_ids", "cves", "aliases"):
            v = source.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add_token(entry)
                    elif isinstance(entry, dict):
                        add_token(entry.get("id") or entry.get("name") or entry.get("cve") or entry.get("cveId"))
        for key in ("title", "description", "summary", "name"):
            v = source.get(key)
            if isinstance(v, str):
                add(v)
    return found


def collect_refs(finding, parent=None, meta=None):
    """Walk a QCS vuln + parent + meta payload for CWE / advisory / URL refs."""
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
    if isinstance(finding, dict):
        sources.append(finding)
    if isinstance(meta, dict):
        sources.append(meta)
    if isinstance(parent, dict):
        sources.append(parent)

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
        for key in ("link", "url", "advisoryUrl", "advisory_url", "vendor_url", "vendorUrl", "nvd_url", "nvdUrl"):
            v = source.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())
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

    return refs


def image_label(image):
    """Build registry / repo / tag / image_id / os from a QCS Image payload."""
    if not isinstance(image, dict):
        return "", "", "", "", ""
    registry = image.get("registry") or image.get("registryUuid") or ""
    repo = image.get("repo") or image.get("repository") or ""
    tag = image.get("tag") or ""
    if not tag:
        tags = image.get("tags") or image.get("repoTags")
        if isinstance(tags, list) and tags:
            first = tags[0]
            if isinstance(first, str) and first.strip():
                tag = first.strip()
            elif isinstance(first, dict):
                tag = first.get("name") or first.get("tag") or ""
                if not (registry or repo):
                    registry = first.get("registry") or registry
                    repo = first.get("repo") or first.get("repository") or repo
    image_id = (
        image.get("imageId") or image.get("sha") or image.get("id") or image.get("_id") or image.get("digest") or ""
    )
    os_name = image.get("operatingSystem") or image.get("os") or image.get("osDistro") or ""
    return str(registry), str(repo), str(tag), str(image_id), str(os_name)


def container_label(container):
    """Build name / containerId / image / host fields from a QCS Container payload."""
    if not isinstance(container, dict):
        return "", "", "", ""
    name = container.get("name") or container.get("containerName") or ""
    container_id = (
        container.get("containerId") or container.get("id") or container.get("_id") or container.get("sha") or ""
    )
    image_text = ""
    image_field = container.get("image") or container.get("imageName") or container.get("imageRepo")
    if isinstance(image_field, dict):
        registry = image_field.get("registry") or ""
        repo = image_field.get("repo") or image_field.get("repository") or ""
        tag = image_field.get("tag") or ""
        if registry and repo:
            image_text = f"{registry}/{repo}"
        elif repo:
            image_text = repo
        elif registry:
            image_text = registry
        if tag and image_text:
            image_text = f"{image_text}:{tag}"
    elif isinstance(image_field, str) and image_field.strip():
        image_text = image_field.strip()
    host_field = container.get("host") or container.get("hostName") or container.get("hostname") or ""
    if isinstance(host_field, dict):
        host_text = host_field.get("hostname") or host_field.get("name") or ""
    else:
        host_text = host_field
    return str(name), str(container_id), str(image_text), str(host_text)


def package_label(finding):
    """Build a friendly label for the affected package."""
    if not isinstance(finding, dict):
        return ""
    name = (
        finding.get("packageName")
        or finding.get("package_name")
        or finding.get("software")
        or finding.get("packagePath")
        or finding.get("name")
        or ""
    )
    if isinstance(name, dict):
        name = name.get("name") or name.get("package") or ""
    version = (
        finding.get("packageVersion")
        or finding.get("package_version")
        or finding.get("installedVersion")
        or finding.get("installed_version")
        or finding.get("version")
        or ""
    )
    if name and version:
        return f"{name}@{version}"
    return str(name).strip()


def vuln_label(finding):
    """Build a friendly label for the vulnerability id (QID or CVE)."""
    if not isinstance(finding, dict):
        return ""
    cve = finding.get("cve") or finding.get("CVE")
    if isinstance(cve, str) and cve.strip():
        return cve.strip()
    cves = finding.get("cveids") or finding.get("cveIds") or finding.get("cves")
    if isinstance(cves, list) and cves:
        first = cves[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
        if isinstance(first, dict):
            v = first.get("id") or first.get("name") or first.get("cve")
            if isinstance(v, str) and v.strip():
                return v.strip()
    qid = finding.get("qid") or finding.get("QID")
    if qid:
        return f"QID-{qid}"
    return ""


def build_vulnerability(finding, parent_label="", parent_kind="image", meta=None):
    """Build a Faraday vulnerability dict from one QCS finding.

    ``parent_label`` is the registry/repo:tag (image) or name@id
    (container) of the bucket; ``parent_kind`` is ``image`` or
    ``container``; ``meta`` is an optional CVE-catalogue / context
    payload (unused today but kept for symmetry with the sibling
    container-security importers).
    """
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding, meta)
    severity_raw = finding.get("severity")
    if severity_raw in (None, "") and isinstance(meta, dict):
        severity_raw = meta.get("severity")
    severity = severity_from_qcs(severity_raw, score)
    status = status_from_qcs(finding)

    vname = vuln_label(finding)
    plabel = package_label(finding)
    if vname and plabel:
        base_title = f"{vname} in {plabel}"
    elif vname:
        base_title = vname
    elif plabel:
        base_title = plabel
    else:
        base_title = str(finding.get("title") or finding.get("description") or "Qualys Container Security finding")
    if parent_label:
        raw_name = f"{base_title} on {parent_label}"
    else:
        raw_name = base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = (
        finding.get("description") or finding.get("summary") or finding.get("details") or finding.get("threat")
    )
    if not description and isinstance(meta, dict):
        description = meta.get("description") or meta.get("summary")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))

    if vname:
        desc_parts.append(f"vuln_id: {vname}")
    qid = finding.get("qid") or finding.get("QID")
    if qid and (not vname or not vname.startswith("QID-")):
        desc_parts.append(f"qid: {qid}")
    if plabel:
        desc_parts.append(f"package: {plabel}")
    if parent_label:
        desc_parts.append(f"{parent_kind}: {parent_label}")

    for label, keys in (
        ("severity", ("severity",)),
        ("status", ("status", "state", "vulnStatus")),
        ("category", ("category", "type")),
        ("first_found", ("firstFound", "first_found", "firstFoundOn")),
        ("last_found", ("lastFound", "last_found", "lastFoundOn")),
        ("published", ("published", "publishedDate", "publishedTime", "publishedOn")),
        ("discovered", ("discovered", "discoveredDate", "discoveredTime")),
        ("vendor", ("vendor", "vendorName")),
        ("patchable", ("patchable", "patchAvailable")),
    ):
        for k in keys:
            v = finding.get(k)
            if v not in (None, ""):
                desc_parts.append(f"{label}: {v}")
                break

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(finding, meta)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(finding, meta)
    refs = collect_refs(finding, None, meta)

    resolution = (
        finding.get("solution")
        or finding.get("remediation")
        or finding.get("recommendation")
        or finding.get("resolution")
        or finding.get("fix")
        or ""
    )
    if not resolution and isinstance(meta, dict):
        resolution = meta.get("solution") or meta.get("remediation") or meta.get("recommendation") or ""
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    pkg_part = ""
    if isinstance(finding.get("packageName"), str):
        pkg_part = finding.get("packageName")
    elif isinstance(finding.get("software"), str):
        pkg_part = finding.get("software")
    external_id_raw = vname or str(qid) if qid else ""
    if external_id_raw and pkg_part and parent_label:
        external_id = f"{external_id_raw}@{pkg_part}@{parent_label}"
    elif external_id_raw and pkg_part:
        external_id = f"{external_id_raw}@{pkg_part}"
    elif external_id_raw:
        external_id = str(external_id_raw)
    else:
        external_id = str(cves[0] if cves else "")

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Qualys Container Security finding {external_id}",
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
        "tags": ["qualys_container_security", "qualys", "cnapp", "container-security"],
    }


def image_bucket_key(image):
    """Build a stable bucket key for grouping an image."""
    if not isinstance(image, dict):
        return "__unknown__"
    iid = image.get("imageId") or image.get("sha") or image.get("id") or image.get("_id") or image.get("digest")
    if isinstance(iid, str) and iid.strip():
        return iid.strip()
    registry, repo, tag, _, _ = image_label(image)
    if registry and repo and tag:
        return f"{registry}/{repo}:{tag}"
    if registry and repo:
        return f"{registry}/{repo}"
    if repo:
        return str(repo)
    return "__unknown__"


def container_bucket_key(container):
    """Build a stable bucket key for grouping a container."""
    if not isinstance(container, dict):
        return "__unknown__"
    cid = (
        container.get("containerId")
        or container.get("id")
        or container.get("_id")
        or container.get("sha")
        or container.get("name")
    )
    if isinstance(cid, str) and cid.strip():
        return cid.strip()
    return "__unknown__"


def build_image_host(bucket_key, image, vulns):
    """Build a Faraday host shell from a QCS image bucket."""
    registry, repo, tag, image_id, os_name = image_label(image)
    label = ""
    if registry and repo:
        label = f"{registry}/{repo}"
    elif repo:
        label = str(repo)
    elif registry:
        label = str(registry)
    if tag and label:
        label = f"{label}:{tag}"
    if label and image_id and image_id != bucket_key:
        hostname = f"{label}@{image_id}"
    elif label and bucket_key and bucket_key != label:
        hostname = f"{label}@{bucket_key}"
    elif label:
        hostname = label
    else:
        hostname = image_id or bucket_key or ""
    desc_parts = ["scope=image"]
    if image_id:
        desc_parts.append(f"image_id={image_id}")
    if registry:
        desc_parts.append(f"registry={registry}")
    if repo:
        desc_parts.append(f"repository={repo}")
    if tag:
        desc_parts.append(f"tag={tag}")
    if os_name:
        desc_parts.append(f"os={os_name}")
    if vulns:
        desc_parts.append(f"findings={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": str(os_name) if os_name else "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def build_container_host(bucket_key, container, vulns):
    """Build a Faraday host shell from a QCS container bucket."""
    name, container_id, image_text, host_text = container_label(container)
    base = name or container_id or bucket_key or ""
    if name and container_id and container_id != base:
        hostname = f"{name}@{container_id}"
    elif base and bucket_key and bucket_key != base:
        hostname = f"{base}@{bucket_key}"
    else:
        hostname = base or bucket_key or ""
    desc_parts = ["scope=container"]
    if container_id:
        desc_parts.append(f"container_id={container_id}")
    if name:
        desc_parts.append(f"name={name}")
    if image_text:
        desc_parts.append(f"image={image_text}")
    if host_text:
        desc_parts.append(f"host={host_text}")
    if vulns:
        desc_parts.append(f"findings={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def emit_image_bucket(image, floor):
    """Build a Faraday host (+ vulns) from one QCS image record."""
    raw_vulns = image.get("vulnerabilities")
    if not isinstance(raw_vulns, list):
        return None
    registry, repo, tag, image_id, _ = image_label(image)
    if registry and repo:
        parent_label = f"{registry}/{repo}"
    elif repo:
        parent_label = repo
    elif image_id:
        parent_label = image_id
    else:
        parent_label = ""
    if tag and parent_label:
        parent_label = f"{parent_label}:{tag}"

    vulns = []
    for finding in raw_vulns:
        if not isinstance(finding, dict):
            continue
        built = build_vulnerability(finding, parent_label, "image", None)
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)
    if not vulns:
        return None
    return build_image_host(image_bucket_key(image), image, vulns)


def emit_container_bucket(container, floor):
    """Build a Faraday host (+ vulns) from one QCS container record."""
    raw_vulns = container.get("vulnerabilities")
    if not isinstance(raw_vulns, list):
        return None
    name, container_id, image_text, _ = container_label(container)
    parent_label = image_text or name or container_id or ""

    vulns = []
    for finding in raw_vulns:
        if not isinstance(finding, dict):
            continue
        built = build_vulnerability(finding, parent_label, "container", None)
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)
    if not vulns:
        return None
    return build_container_host(container_bucket_key(container), container, vulns)


def main():
    started = time.time()
    qualys_host = env("QUALYS_HOST", required=True)
    username = env("QUALYS_USER") or env("QUALYS_USERNAME")
    password = env("QUALYS_PASSWORD")
    if not username:
        log("QUALYS_USER (or legacy QUALYS_USERNAME) is required")
        sys.exit(1)
    if not password:
        log("QUALYS_PASSWORD is required")
        sys.exit(1)

    registry = env("EXECUTOR_CONFIG_QCS_REGISTRY")
    repo = env("EXECUTOR_CONFIG_QCS_REPO")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_QCS_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(qualys_host)
    if not base_url:
        log("QUALYS_HOST is required")
        sys.exit(1)

    token = fetch_access_token(base_url, username, password)
    if not token:
        log("Failed to obtain Qualys Container Security access token; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    qql = build_qql_filter(registry, repo)

    hosts_out = []

    images = fetch_all(base_url, headers, "/csapi/v1.3/images", qql)
    log(
        f"Processing {len(images)} Qualys Container Security images "
        f"(registry={registry or '*'}, repo={repo or '*'}, min_severity={min_severity})"
    )
    for image in images:
        host_obj = emit_image_bucket(image, floor)
        if host_obj is not None:
            hosts_out.append(host_obj)

    containers = fetch_all(base_url, headers, "/csapi/v1.3/containers", qql)
    log(
        f"Processing {len(containers)} Qualys Container Security containers "
        f"(registry={registry or '*'}, repo={repo or '*'}, min_severity={min_severity})"
    )
    for container in containers:
        host_obj = emit_container_bucket(container, floor)
        if host_obj is not None:
            hosts_out.append(host_obj)

    params = f"registry={registry or ''},repo={repo or ''},min_severity={min_severity}"

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "qualys_container_security",
            "command": "qualys_container_security",
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
