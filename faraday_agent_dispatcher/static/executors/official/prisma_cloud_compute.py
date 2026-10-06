#!/usr/bin/env python
"""Prisma Cloud Compute (Twistlock) REST importer.

Pulls container image and host vulnerability findings from a Prisma
Cloud Compute Edition (formerly Twistlock) console via the canonical
``GET /api/v22.01/images``, ``GET /api/v22.01/hosts`` and
``GET /api/v22.01/vulnerabilities`` endpoints and emits Faraday
bulk-create JSON to stdout. Each Twistlock image (``_id`` or
``repoTag``) and each Twistlock host (``_id`` / ``hostname``) becomes
one Faraday host (images get a synthetic ``0.0.0.0`` ip because image
scans live on container layers, not on IPs; hosts get ``0.0.0.0``
too because the API does not surface a reliable host ip and the
hostname carries the pivot); per-image / per-host vulnerabilities are
attached as Faraday vulnerabilities — one per Twistlock vulnerability
id with engine prefix ``[CNAPP]``.

Endpoints used:
  POST {TWISTLOCK_HOST}/api/v22.01/authenticate
      -> credentials exchange. Body ``{"username": <user>, "password":
      <password>}`` returns ``{"token": "..."}`` (Twistlock's
      short-lived JWT, ~30 min validity). Subsequent calls send
      ``Authorization: Bearer <token>``.
  GET {TWISTLOCK_HOST}/api/v22.01/images
      -> image scan listing. Paginated via ``limit`` + ``offset``
      cursor. Each image carries the embedded ``vulnerabilities``
      array; we surface one Faraday vuln per entry. Skipped when
      TWISTLOCK_SCOPE is ``hosts``.
  GET {TWISTLOCK_HOST}/api/v22.01/hosts
      -> host scan listing. Same pagination + vulnerability shape as
      /images. Skipped when TWISTLOCK_SCOPE is ``images``.
  GET {TWISTLOCK_HOST}/api/v22.01/vulnerabilities
      -> optional CVE catalogue. Keyed by ``cve`` for enrichment when
      the embedded image / host vulnerability payload is compact (no
      description / link / cvssVector). Tolerant to 404 / missing.

Auth: Twistlock / Prisma Cloud Compute uses a local-account username /
password pair (or a SAML/LDAP-federated identity). The pair is sent
as JSON to ``POST /api/v22.01/authenticate``; the response carries a
short-lived JWT that is then sent as ``Authorization: Bearer
<token>`` on subsequent calls. The TWISTLOCK_HOST is the console URL
of the on-prem / SaaS Prisma Cloud Compute installation
(``https://<console>:8083`` for on-prem,
``https://<tenant>.cloud.twistlock.com`` for the SaaS edition).
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

VALID_SCOPE = ("images", "hosts", "both")
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Twistlock severity enum: critical / high / medium / low / important
# (rare) / unimportant. The platform also accepts "Important" /
# "Major" / "Moderate" / "Minor" / "Negligible" / "Trivial" /
# "Unknown" depending on the upstream feed; we tolerate the usual
# synonyms.
TWISTLOCK_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
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

# Twistlock vulnerability lifecycle:
#   open / new / active / detected / needed -> open
#   fixed / resolved / mitigated / patched / remediated -> closed
#   suppressed / muted / ignored / dismissed / wont_fix /
#   risk_accepted / false_positive / expired / acknowledged ->
#   risk-accepted
TWISTLOCK_STATUS_TO_FARADAY = {
    "open": "open",
    "new": "open",
    "active": "open",
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
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
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

TWISTLOCK_API_SEVERITY = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - PrismaCloudCompute: {msg}", file=sys.stderr, flush=True)


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


def validate_scope(value):
    if value is None or value == "":
        return "both"
    text = str(value).strip().lower()
    if text not in VALID_SCOPE:
        log(f"TWISTLOCK_SCOPE '{value}' not recognised; defaulting to 'both'")
        return "both"
    return text


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"TWISTLOCK_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def severities_at_or_above(min_severity):
    """Return the Twistlock severity tokens at or above ``min_severity``.

    Twistlock does not natively floor on the listing endpoints (there
    is no ``?severity=`` query param on /images or /hosts) so this
    helper is used purely for the client-side floor. ``info`` yields
    every bucket.
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = TWISTLOCK_API_SEVERITY.get(bucket)
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


def severity_from_twistlock(value, cvss=None):
    """Map a Twistlock severity to a Faraday bucket.

    Accepts Twistlock's string enum (critical / high / medium / low /
    important / unimportant) and falls back to CVSS bucketing on
    ``cvss`` when the primary value is missing or unrecognised.
    Numeric inputs are interpreted as CVSS base scores so vendor-shaped
    reports that surface a bare ``cvss`` still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in TWISTLOCK_STRING_SEVERITY:
            return TWISTLOCK_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_twistlock(finding):
    """Derive Faraday status from a Twistlock vulnerability payload.

    Twistlock carries ``status`` (a free-form string — e.g. "fixed in
    1.1.1q", "deferred", "needed"), ``fixDate`` (epoch seconds when
    upstream cut the fix) and ``binaryPkgs`` (rare). We tolerate the
    usual synonyms — "fixed in X" tokens map to closed when followed
    by a version, "needed" maps to open.
    """
    if not isinstance(finding, dict):
        return "open"
    raw = finding.get("status")
    if isinstance(raw, dict):
        raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text.startswith("fixed in") or text.startswith("fix in") or text.startswith("fixed:"):
            return "closed"
        if text in TWISTLOCK_STATUS_TO_FARADAY:
            return TWISTLOCK_STATUS_TO_FARADAY[text]
        compact = text.replace(" ", "").replace("-", "").replace("_", "")
        if compact in TWISTLOCK_STATUS_TO_FARADAY:
            return TWISTLOCK_STATUS_TO_FARADAY[compact]
    fix_date = finding.get("fixDate") or finding.get("fix_date")
    if isinstance(fix_date, (int, float)) and fix_date > 0:
        return "closed"
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
        log(f"{method} {url} rejected (401). Check TWISTLOCK_USER / TWISTLOCK_PASSWORD.")
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
    """Exchange Twistlock user / password for a short-lived JWT.

    Twistlock's auth endpoint is ``POST {base_url}/api/v22.01/authenticate``
    with JSON body ``{"username": <user>, "password": <password>}`` ->
    ``{"token": "..."}``. Some stacks wrap the token under ``data``;
    ``extract_token`` tolerates both shapes plus ``accessToken`` /
    ``access_token`` synonyms.
    """
    if not base_url or not username or not password:
        return None
    url = f"{base_url}/api/v22.01/authenticate"
    body = {"username": username, "password": password}
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Login rejected (401). Check TWISTLOCK_USER / TWISTLOCK_PASSWORD.")
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
    """Pull the JWT out of a Twistlock ``/api/v22.01/authenticate`` response.

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
    """Pull the image / host / catalogue list out of a Twistlock envelope.

    Twistlock returns a bare JSON list for /images, /hosts and
    /vulnerabilities. Some stacks (especially when behind a reverse
    proxy that re-wraps) return ``{"data": [...]}`` or
    ``{"results": [...]}``; tolerate both shapes.
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "results", "items", "vulnerabilities", "images", "hosts", "findings"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def fetch_page(base_url, headers, endpoint, offset, page_size):
    """Pull one page from a Twistlock listing endpoint."""
    params = {"limit": page_size, "offset": offset}
    return request("GET", f"{base_url}{endpoint}", headers, params=params)


def fetch_all(base_url, headers, endpoint):
    """Paginate through a Twistlock listing endpoint."""
    results = []
    seen_ids = set()
    offset = 0
    for _ in range(MAX_PAGES):
        payload = fetch_page(base_url, headers, endpoint, offset, PAGE_SIZE)
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for item in chunk:
            iid = item.get("_id") or item.get("id") or item.get("hostname")
            key = str(iid).strip() if iid else None
            if key and key in seen_ids:
                continue
            if key:
                seen_ids.add(key)
            results.append(item)
            added += 1
        if added == 0:
            break
        offset += len(chunk)
        if len(chunk) < PAGE_SIZE:
            break
    return results


def fetch_images(base_url, headers):
    """Pull the image-scan inventory (vulnerabilities embedded)."""
    return fetch_all(base_url, headers, "/api/v22.01/images")


def fetch_hosts(base_url, headers):
    """Pull the host-scan inventory (vulnerabilities embedded)."""
    return fetch_all(base_url, headers, "/api/v22.01/hosts")


def fetch_cve_catalog(base_url, headers):
    """Pull the CVE catalogue for enrichment, keyed by CVE id."""
    items = fetch_all(base_url, headers, "/api/v22.01/vulnerabilities")
    by_cve = {}
    for entry in items:
        cve = entry.get("cve") or entry.get("CVE") or entry.get("id")
        if isinstance(cve, str) and cve.strip():
            by_cve[cve.strip().upper()] = entry
    return by_cve


def cvss_score(finding, meta=None):
    """Pull a numeric CVSS / score out of a Twistlock vuln payload + catalogue."""
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
        for nested_key in ("cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
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


def cvss_vector(finding, meta=None):
    candidates = []
    if isinstance(finding, dict):
        candidates.append(finding)
    if isinstance(meta, dict):
        candidates.append(meta)
    for source in candidates:
        for key in ("vecStr", "vectorString", "vector_string", "cvssVector", "cvss_vector", "vector"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for nested_key in ("cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
            nested = source.get(nested_key)
            if isinstance(nested, dict):
                for k in ("vector", "vectorString", "vector_string"):
                    v = nested.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    return ""


def collect_cves(finding, meta=None):
    """Pull CVE-* ids out of a Twistlock vuln + catalogue payload."""
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
        for key in ("cves", "cveIds", "cve_ids", "aliases"):
            v = source.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add_token(entry)
                    elif isinstance(entry, dict):
                        add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
        for key in ("title", "description", "summary", "name"):
            v = source.get(key)
            if isinstance(v, str):
                add(v)
    return found


def collect_refs(finding, image=None, meta=None):
    """Walk a Twistlock vuln + image + catalogue for CWE / advisory / URL refs."""
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
    if isinstance(image, dict):
        sources.append(image)

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
        for key in ("link", "url", "nvd_url", "nvdUrl", "vendor_url", "vendorUrl", "advisoryUrl", "advisory_url"):
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

    if isinstance(finding, dict):
        risk = finding.get("riskFactors")
        if isinstance(risk, dict):
            for label, present in risk.items():
                if present:
                    add(f"RiskFactor: {label}")

    return refs


def image_label(image):
    """Build a friendly label for the affected container image."""
    if not isinstance(image, dict):
        return "", "", "", "", ""
    repo_tag = image.get("repoTag")
    registry = ""
    repo = ""
    tag = ""
    if isinstance(repo_tag, dict):
        registry = repo_tag.get("registry") or ""
        repo = repo_tag.get("repo") or ""
        tag = repo_tag.get("tag") or ""
    repo_tags = image.get("repoTags") or image.get("tags")
    if not (registry or repo or tag) and isinstance(repo_tags, list) and repo_tags:
        first = repo_tags[0]
        if isinstance(first, dict):
            registry = first.get("registry") or registry
            repo = first.get("repo") or repo
            tag = first.get("tag") or tag
        elif isinstance(first, str) and first.strip():
            text = first.strip()
            if ":" in text:
                head, tag = text.rsplit(":", 1)
            else:
                head, tag = text, ""
            if "/" in head:
                registry, repo = head.split("/", 1)
            else:
                repo = head
    if not registry:
        registry = image.get("registry") or image.get("registry_name") or ""
    if not repo:
        repo = image.get("repo") or image.get("repository") or image.get("image_name") or ""
    if not tag:
        tag = image.get("tag") or image.get("image_tag") or ""
    image_id = image.get("_id") or image.get("id") or image.get("digest") or ""
    os_name = image.get("osDistro") or image.get("distro") or image.get("os") or ""
    if isinstance(os_name, str) and not os_name and isinstance(image.get("osDistroVersion"), str):
        os_name = image.get("osDistroVersion")
    return str(registry), str(repo), str(tag), str(image_id), str(os_name)


def host_label(host):
    """Build a friendly label for the affected host."""
    if not isinstance(host, dict):
        return "", "", ""
    hostname = host.get("hostname") or host.get("host") or host.get("_id") or host.get("id") or ""
    distro = host.get("distro") or host.get("osDistro") or ""
    if not distro and isinstance(host.get("osDistroVersion"), str):
        distro = host.get("osDistroVersion")
    kernel = host.get("kernelVersion") or host.get("kernel") or ""
    return str(hostname), str(distro), str(kernel)


def package_label(finding):
    """Build a friendly label for the affected package."""
    if not isinstance(finding, dict):
        return ""
    name = finding.get("packageName") or finding.get("package_name") or finding.get("name") or ""
    version = (
        finding.get("packageVersion")
        or finding.get("package_version")
        or finding.get("installedVersion")
        or finding.get("installed_version")
        or ""
    )
    if name and version:
        return f"{name}@{version}"
    return str(name).strip()


def vuln_label(finding):
    """Build a friendly label for the vulnerability id."""
    if not isinstance(finding, dict):
        return ""
    return str(
        finding.get("cve") or finding.get("id") or finding.get("CVE") or finding.get("vulnerability_id") or ""
    ).strip()


def build_vulnerability(finding, parent_label="", parent_kind="image", meta=None):
    """Build a Faraday vulnerability dict from one Twistlock finding.

    ``parent_label`` is the registry/repo:tag (image) or hostname
    (host) of the bucket; ``parent_kind`` is ``image`` or ``host``;
    ``meta`` is the optional CVE catalogue entry from
    /api/v22.01/vulnerabilities.
    """
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding, meta)
    severity_raw = finding.get("severity")
    if not severity_raw and isinstance(meta, dict):
        severity_raw = meta.get("severity")
    severity = severity_from_twistlock(severity_raw, score)
    status = status_from_twistlock(finding)

    vname = vuln_label(finding)
    plabel = package_label(finding)
    if vname and plabel:
        base_title = f"{vname} in {plabel}"
    elif vname:
        base_title = vname
    elif plabel:
        base_title = plabel
    else:
        base_title = str(finding.get("title") or finding.get("description") or "Prisma Cloud Compute finding")
    if parent_label:
        raw_name = f"{base_title} on {parent_label}"
    else:
        raw_name = base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = finding.get("description") or finding.get("summary") or finding.get("details")
    if not description and isinstance(meta, dict):
        description = meta.get("description") or meta.get("summary")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))

    if vname:
        desc_parts.append(f"vuln_id: {vname}")
    if plabel:
        desc_parts.append(f"package: {plabel}")
    if parent_label:
        desc_parts.append(f"{parent_kind}: {parent_label}")

    for label, keys in (
        ("layer", ("layerTime", "layer", "layerDigest")),
        ("severity", ("severity",)),
        ("status", ("status",)),
        ("vendor", ("vendor", "vendorName")),
        ("fix_status", ("fixStatus", "fix_status")),
        ("fix_date", ("fixDate", "fix_date")),
        ("published", ("published", "publishedDate", "publishedTime")),
        ("discovered", ("discovered", "discoveredDate", "discoveredTime")),
        ("first_seen", ("firstSeen", "first_seen")),
        ("last_seen", ("lastSeen", "last_seen")),
    ):
        for k in keys:
            v = finding.get(k)
            if v not in (None, ""):
                if label in ("severity", "status") and v == severity_raw:
                    desc_parts.append(f"{label}: {v}")
                    break
                desc_parts.append(f"{label}: {v}")
                break

    risk = finding.get("riskFactors")
    if isinstance(risk, dict):
        active = sorted(k for k, v in risk.items() if v)
        if active:
            desc_parts.append(f"risk_factors: {', '.join(active)}")

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
    status_text = finding.get("status")
    if not resolution and isinstance(status_text, str) and status_text.strip().lower().startswith("fixed in"):
        if plabel:
            pkg = plabel.split("@")[0]
            resolution = f"Upgrade {pkg}: {status_text.strip()}."
        else:
            resolution = status_text.strip()
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    external_id_raw = finding.get("cve") or finding.get("id") or finding.get("CVE") or finding.get("vulnerability_id")
    pkg_part = finding.get("packageName") or finding.get("package_name") or ""
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
        "name": str(name).strip()[:200] or f"Prisma Cloud Compute finding {external_id}",
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
        "tags": ["prisma_cloud_compute", "twistlock", "cnapp", "cloud-security"],
    }


def image_bucket_key(image):
    """Build a stable bucket key for grouping an image."""
    if not isinstance(image, dict):
        return "__unknown__"
    iid = image.get("_id") or image.get("id") or image.get("digest")
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


def host_bucket_key(host):
    """Build a stable bucket key for grouping a host."""
    if not isinstance(host, dict):
        return "__unknown__"
    hid = host.get("_id") or host.get("id") or host.get("hostname")
    if isinstance(hid, str) and hid.strip():
        return hid.strip()
    return "__unknown__"


def build_image_host(bucket_key, image, vulns):
    """Build a Faraday host shell from a Twistlock image bucket."""
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


def build_host_host(bucket_key, host, vulns):
    """Build a Faraday host shell from a Twistlock host bucket."""
    hostname, distro, kernel = host_label(host)
    if hostname and bucket_key and hostname != bucket_key:
        hostname_label = f"{hostname}@{bucket_key}"
    else:
        hostname_label = hostname or bucket_key or ""
    desc_parts = ["scope=host"]
    if hostname:
        desc_parts.append(f"hostname={hostname}")
    if distro:
        desc_parts.append(f"distro={distro}")
    if kernel:
        desc_parts.append(f"kernel={kernel}")
    if vulns:
        desc_parts.append(f"findings={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": str(distro) if distro else "",
        "hostnames": [hostname_label] if hostname_label else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def emit_image_bucket(image, catalog, floor):
    """Build a Faraday host (+ vulns) from one Twistlock image record."""
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
        cve = finding.get("cve") or finding.get("CVE")
        meta = catalog.get(str(cve).strip().upper()) if isinstance(cve, str) and cve.strip() else None
        built = build_vulnerability(finding, parent_label, "image", meta)
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)
    if not vulns:
        return None
    return build_image_host(image_bucket_key(image), image, vulns)


def emit_host_bucket(host, catalog, floor):
    """Build a Faraday host (+ vulns) from one Twistlock host record."""
    raw_vulns = host.get("vulnerabilities")
    if not isinstance(raw_vulns, list):
        return None
    hostname, _, _ = host_label(host)
    parent_label = hostname or host_bucket_key(host)
    if parent_label == "__unknown__":
        parent_label = ""

    vulns = []
    for finding in raw_vulns:
        if not isinstance(finding, dict):
            continue
        cve = finding.get("cve") or finding.get("CVE")
        meta = catalog.get(str(cve).strip().upper()) if isinstance(cve, str) and cve.strip() else None
        built = build_vulnerability(finding, parent_label, "host", meta)
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)
    if not vulns:
        return None
    return build_host_host(host_bucket_key(host), host, vulns)


def main():
    started = time.time()
    twistlock_host = env("TWISTLOCK_HOST", required=True)
    username = env("TWISTLOCK_USER", required=True)
    password = env("TWISTLOCK_PASSWORD", required=True)
    scope = validate_scope(env("EXECUTOR_CONFIG_TWISTLOCK_SCOPE"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_TWISTLOCK_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(twistlock_host)
    if not base_url:
        log("TWISTLOCK_HOST is required")
        sys.exit(1)

    token = fetch_access_token(base_url, username, password)
    if not token:
        log("Failed to obtain Prisma Cloud Compute access token; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    catalog = fetch_cve_catalog(base_url, headers)
    log(f"Loaded {len(catalog)} entries from the Prisma Cloud Compute CVE catalogue")

    hosts_out = []

    if scope in ("images", "both"):
        images = fetch_images(base_url, headers)
        log(f"Processing {len(images)} Prisma Cloud Compute images (scope={scope}, min_severity={min_severity})")
        for image in images:
            host_obj = emit_image_bucket(image, catalog, floor)
            if host_obj is not None:
                hosts_out.append(host_obj)

    if scope in ("hosts", "both"):
        hosts = fetch_hosts(base_url, headers)
        log(f"Processing {len(hosts)} Prisma Cloud Compute hosts (scope={scope}, min_severity={min_severity})")
        for host in hosts:
            host_obj = emit_host_bucket(host, catalog, floor)
            if host_obj is not None:
                hosts_out.append(host_obj)

    params = f"scope={scope},min_severity={min_severity}"

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "prisma_cloud_compute",
            "command": "prisma_cloud_compute",
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
