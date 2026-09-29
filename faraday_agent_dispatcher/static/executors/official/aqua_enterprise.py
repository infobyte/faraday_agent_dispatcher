#!/usr/bin/env python
"""Aqua Enterprise (CNAPP / CSPM) REST importer.

Pulls cloud-security vulnerability findings from an Aqua Enterprise
Platform (formerly Aqua Container Security Platform — CSP) tenant via
the canonical ``GET /api/v2/risks/vulnerabilities`` and
``GET /api/v2/images`` endpoints and emits Faraday bulk-create JSON to
stdout. Each Aqua image (``registry`` + ``repository`` + ``image_id``)
becomes one Faraday host (``ip`` = synthetic ``0.0.0.0`` because CNAPP
findings live on container images, not on IPs); per-image findings are
attached as Faraday vulnerabilities — one per Aqua finding id with
engine prefix ``[CNAPP]``.

Endpoints used:
  POST {AQUA_HOST}/api/v1/login
      -> credentials exchange. Body ``{"id": <user>, "password":
      <password>}`` returns ``{"token": "..."}`` (also tolerated wrapped
      under ``data`` / ``data[0]`` and ``access_token`` / ``accessToken``
      synonyms). Subsequent calls send ``Authorization: Bearer <token>``.
  GET {AQUA_HOST}/api/v2/risks/vulnerabilities
      -> primary listing endpoint. Paginated via ``page`` + ``pagesize``
      cursor. Filters on ``registry_name`` (optional, scopes the search
      to a single registry), ``image_name`` (optional, scopes to a
      single repository), ``severity`` (CSV of critical / high / medium
      / low / negligible). Returns ``{"result": [...], "count": N,
      "page": N, "pagesize": N}``; pagination via ``page`` bump with
      length-of-chunk fallback when ``count`` is missing, dedup via
      ``vulnerability_id`` / ``id``.
  GET {AQUA_HOST}/api/v2/images
      -> optional image enrichment. Looked up by ``image_id`` /
      ``registry`` + ``repository`` to surface os / digest / labels /
      base_image metadata when the vulnerability payload is compact.
      Tolerant to 404 / missing.

Auth: Aqua Enterprise uses a local-account username / password pair
(or a SAML/LDAP-federated identity). The pair is sent as JSON to
``POST /api/v1/login``; the response carries a short-lived bearer token
that is then sent as ``Authorization: Bearer <token>`` on subsequent
calls. The tenant URL is the API base of the on-prem / SaaS Aqua
console (``https://<aqua-console>:8080`` for on-prem,
``https://cloudsploit.com`` for the SaaS edition — though the SaaS
flavour is handled separately by the ``aqua_saas`` executor with a
hardcoded host).
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

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Aqua severity enum: critical / high / medium / low / negligible (Info).
# The platform also accepts "Important" / "Major" / "Moderate" /
# "Minor" / "Trivial" / "Unknown" depending on the integration that
# fed the finding in; we tolerate the usual synonyms.
AQUA_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "negligible": "info",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "unknown": "info",
}

# Aqua vulnerability lifecycle:
#   open / new / active / detected -> open
#   fixed / resolved / mitigated / patched / remediated -> closed
#   suppressed / muted / ignored / dismissed / wont_fix / risk_accepted
#   / false_positive / expired / acknowledged -> risk-accepted
AQUA_STATUS_TO_FARADAY = {
    "open": "open",
    "new": "open",
    "active": "open",
    "detected": "open",
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
}

AQUA_API_SEVERITY = {
    "info": "negligible",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - AquaEnterprise: {msg}", file=sys.stderr, flush=True)


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
        log(f"AQUA_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def severities_at_or_above(min_severity):
    """Return the Aqua severity tokens at or above ``min_severity``.

    Used to build the ``severity`` query parameter so the tenant only
    paginates results that survive the client-side floor. ``info``
    yields every bucket (no filter applied).
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = AQUA_API_SEVERITY.get(bucket)
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


def severity_from_aqua(value, cvss=None):
    """Map an Aqua severity to a Faraday bucket.

    Accepts Aqua's string enum (critical / high / medium / low /
    negligible) and falls back to CVSS bucketing on ``cvss`` when the
    primary value is missing or unrecognised. Numeric inputs are
    interpreted as CVSS base scores so vendor-shaped reports that
    surface a bare ``aqua_score`` still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in AQUA_STRING_SEVERITY:
            return AQUA_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_aqua(finding):
    """Derive Faraday status from an Aqua finding payload.

    Aqua surfaces several status surrogates depending on the API
    revision: ``ack_status`` (acknowledged / open), ``fix_status`` /
    ``fix_version`` (when a fix is available), ``status`` (open / fixed
    / mitigated). We tolerate dict-wrapped and synonym shapes so
    downstream re-emissions through generic CNAPP pipelines still map
    cleanly.
    """
    if not isinstance(finding, dict):
        return "open"
    for key in ("status", "vuln_status", "vulnStatus", "ack_status", "ackStatus", "state"):
        raw = finding.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
        if isinstance(raw, str):
            mapped = AQUA_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in AQUA_STATUS_TO_FARADAY:
                return AQUA_STATUS_TO_FARADAY[compact]
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
        log(f"{method} {url} rejected (401). Check AQUA_USER / AQUA_PASSWORD.")
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
    """Exchange Aqua user / password for a short-lived JWT.

    Aqua's auth endpoint is ``POST {base_url}/api/v1/login`` with JSON
    body ``{"id": <user>, "password": <password>}`` -> ``{"token":
    "..."}``. Some stacks wrap the token under ``data``;
    ``extract_token`` tolerates both shapes plus ``accessToken`` /
    ``access_token`` synonyms.
    """
    if not base_url or not username or not password:
        return None
    url = f"{base_url}/api/v1/login"
    body = {"id": username, "password": password}
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Login rejected (401). Check AQUA_USER / AQUA_PASSWORD.")
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
    """Pull the JWT out of an Aqua ``/api/v1/login`` response.

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
    """Pull the finding / image list out of an Aqua envelope.

    Aqua returns ``{"result": [...], "count": N, "page": N,
    "pagesize": N}`` for paginated lists and occasionally a bare list;
    tolerate both shapes plus a handful of seen alt keys (``data`` /
    ``results`` / ``items`` / ``vulnerabilities`` / ``images``).
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("result", "data", "results", "items", "vulnerabilities", "images", "findings"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def fetch_findings(base_url, headers, registry, repo, severities):
    """Paginate through /api/v2/risks/vulnerabilities for the supplied filters."""
    results = []
    seen_ids = set()
    page = 1
    for _ in range(MAX_PAGES):
        params = {"page": page, "pagesize": PAGE_SIZE}
        if registry:
            params["registry_name"] = registry
        if repo:
            params["image_name"] = repo
        if severities:
            params["severity"] = ",".join(severities)
        payload = request(
            "GET",
            f"{base_url}/api/v2/risks/vulnerabilities",
            headers,
            params=params,
        )
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for finding in chunk:
            fid = (
                finding.get("vulnerability_id")
                or finding.get("vulnerabilityId")
                or finding.get("id")
                or finding.get("finding_id")
            )
            key = None
            if isinstance(fid, str) and fid.strip():
                cve = finding.get("name") or finding.get("vulnerability") or ""
                resource = finding.get("image_id") or finding.get("imageId") or finding.get("image") or ""
                key = f"{fid}|{cve}|{resource}"
            if key and key in seen_ids:
                continue
            if key:
                seen_ids.add(key)
            results.append(finding)
            added += 1
        if added == 0:
            break
        total = None
        if isinstance(payload, dict):
            total = payload.get("count") or payload.get("total") or payload.get("totalItems")
        page += 1
        seen_count = len(results)
        if isinstance(total, (int, float)) and seen_count >= int(total):
            break
        if len(chunk) < PAGE_SIZE:
            break
    return results


def fetch_image(base_url, headers, registry, repo, image_id=None):
    """Look up an image by registry + repository; tolerant to 404 / missing.

    Aqua's /api/v2/images supports filtering by ``registry`` and
    ``image_name`` (and optionally a ``digest`` / ``image_id`` for
    pinned lookups). Returns the first match.
    """
    if not registry and not repo and not image_id:
        return None
    params = {}
    if registry:
        params["registry"] = registry
    if repo:
        params["image_name"] = repo
    if image_id:
        params["digest"] = image_id
    payload = request("GET", f"{base_url}/api/v2/images", headers, params=params)
    items = extract_items(payload)
    return items[0] if items else None


def cvss_score(finding):
    """Pull a numeric CVSS / severity score out of an Aqua finding payload."""
    if not isinstance(finding, dict):
        return None
    for key in (
        "aqua_score",
        "aquaScore",
        "cvss_score",
        "cvssScore",
        "score",
        "base_score",
        "baseScore",
        "severity_score",
        "severityScore",
        "nvd_score",
        "nvdScore",
    ):
        value = finding.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2", "nvd"):
        nested = finding.get(nested_key)
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


def cvss_vector(finding):
    if not isinstance(finding, dict):
        return ""
    for key in (
        "cvss_vector",
        "cvssVector",
        "vector",
        "vector_string",
        "vectorString",
        "nvd_vector",
        "nvdVector",
    ):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2", "nvd"):
        nested = finding.get(nested_key)
        if isinstance(nested, dict):
            for k in ("vector", "vectorString", "vector_string"):
                v = nested.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def collect_cves(finding):
    """Pull CVE-* ids out of an Aqua finding payload."""
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

    for key in ("name", "vulnerability", "vulnerability_id", "vulnerabilityId", "title", "description", "summary"):
        v = finding.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cve", "cveId", "cve_id"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            add_token(v)
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = finding.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add_token(entry)
                elif isinstance(entry, dict):
                    add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
    return found


def collect_refs(finding, image=None):
    """Walk an Aqua finding + image for CWE / advisory / URL refs."""
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
        for key in ("nvd_url", "nvdUrl", "vendor_url", "vendorUrl", "url", "link", "advisoryUrl", "advisory_url"):
            v = finding.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())
        vname = (
            finding.get("name")
            or finding.get("vulnerability")
            or finding.get("vulnerability_id")
            or finding.get("vulnerabilityId")
        )
        if isinstance(vname, str) and vname.strip():
            add(f"Aqua-Vuln: {vname.strip()}")

    if isinstance(image, dict):
        for key in ("image_url", "imageUrl", "url", "console_url", "consoleUrl"):
            v = image.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def image_label(image, finding=None):
    """Build a friendly label for the affected container image."""
    registry = ""
    repo = ""
    image_id = ""
    tag = ""
    if isinstance(image, dict):
        registry = image.get("registry") or image.get("registry_name") or ""
        repo = image.get("repository") or image.get("image_name") or image.get("name") or ""
        image_id = image.get("image_id") or image.get("imageId") or image.get("digest") or ""
        tag = image.get("image_tag") or image.get("tag") or ""
    if isinstance(finding, dict):
        if not registry:
            registry = finding.get("registry") or finding.get("registry_name") or ""
        if not repo:
            repo = finding.get("repository") or finding.get("image_name") or finding.get("image_repository_name") or ""
        if not image_id:
            image_id = finding.get("image_id") or finding.get("imageId") or finding.get("digest") or ""
        if not tag:
            tag = finding.get("image_tag") or finding.get("tag") or ""
    parts = []
    if registry and repo:
        parts.append(f"{registry}/{repo}")
    elif repo:
        parts.append(str(repo))
    elif registry:
        parts.append(str(registry))
    if tag:
        if parts:
            parts[0] = f"{parts[0]}:{tag}"
        else:
            parts.append(f":{tag}")
    label = parts[0] if parts else ""
    if not label and image_id:
        label = str(image_id)
    return label.strip()


def package_label(finding):
    """Build a friendly label for the affected package."""
    if not isinstance(finding, dict):
        return ""
    name = finding.get("resource", {}).get("name") if isinstance(finding.get("resource"), dict) else None
    if not name:
        name = (
            finding.get("package_name")
            or finding.get("packageName")
            or finding.get("resource_name")
            or finding.get("name")
            or ""
        )
    version = ""
    if isinstance(finding.get("resource"), dict):
        version = finding["resource"].get("version") or finding["resource"].get("installed_version") or ""
    if not version:
        version = (
            finding.get("package_version")
            or finding.get("packageVersion")
            or finding.get("installed_version")
            or finding.get("resource_version")
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
        finding.get("name")
        or finding.get("vulnerability")
        or finding.get("vulnerability_id")
        or finding.get("vulnerabilityId")
        or finding.get("id")
        or ""
    ).strip()


def build_vulnerability(finding, image=None):
    """Build a Faraday vulnerability dict from one Aqua finding."""
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding)
    severity_raw = finding.get("aqua_severity") or finding.get("severity")
    severity = severity_from_aqua(severity_raw, score)
    status = status_from_aqua(finding)

    vname = vuln_label(finding)
    plabel = package_label(finding)
    ilabel = image_label(image, finding)
    if vname and plabel:
        base_title = f"{vname} in {plabel}"
    elif vname:
        base_title = vname
    elif plabel:
        base_title = plabel
    else:
        base_title = str(finding.get("title") or finding.get("description") or "Aqua finding")
    if ilabel:
        raw_name = f"{base_title} on {ilabel}"
    else:
        raw_name = base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = finding.get("description") or finding.get("summary") or finding.get("details")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if vname:
        desc_parts.append(f"vuln_id: {vname}")
    if plabel:
        desc_parts.append(f"package: {plabel}")
    if ilabel:
        desc_parts.append(f"image: {ilabel}")

    snap_sources = [s for s in (finding, image) if isinstance(s, dict)]
    surfaced = set()
    for label, keys in (
        ("registry", ("registry", "registry_name", "registryName")),
        ("repository", ("repository", "image_name", "image_repository_name")),
        ("image_id", ("image_id", "imageId", "digest")),
        ("image_tag", ("image_tag", "tag")),
        ("os", ("os", "os_version", "osVersion", "image_os")),
        ("architecture", ("architecture", "arch")),
        ("base_image", ("base_image", "baseImage", "base_image_name")),
        ("scan_date", ("scan_date", "scanDate", "scan_started_at", "scanStartedAt")),
        ("fix_version", ("fix_version", "fixVersion", "vendor_cpe_fix_version")),
        ("first_seen", ("first_seen", "firstSeen", "first_found_date", "firstFoundDate")),
        ("last_seen", ("last_seen", "lastSeen", "last_found_date", "lastFoundDate")),
    ):
        for s in snap_sources:
            v = s.get(keys[0])
            for k in keys[1:]:
                if v in (None, ""):
                    v = s.get(k)
            if v not in (None, "") and label not in surfaced:
                desc_parts.append(f"{label}: {v}")
                surfaced.add(label)
                break

    state = finding.get("status") or finding.get("ack_status") or finding.get("vuln_status")
    if state:
        desc_parts.append(f"status: {state}")
    if severity_raw:
        desc_parts.append(f"severity: {severity_raw}")

    fix_available = finding.get("fix_available") or finding.get("fixAvailable")
    if fix_available is not None and fix_available != "":
        desc_parts.append(f"fix_available: {fix_available}")

    exploit = finding.get("exploitability") or finding.get("has_exploit") or finding.get("hasExploit")
    if exploit is not None and exploit != "":
        desc_parts.append(f"exploitability: {exploit}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(finding)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(finding)
    refs = collect_refs(finding, image)

    resolution = (
        finding.get("solution")
        or finding.get("remediation")
        or finding.get("recommendation")
        or finding.get("resolution")
        or finding.get("fix")
        or ""
    )
    fix_version = finding.get("fix_version") or finding.get("fixVersion") or finding.get("vendor_cpe_fix_version")
    if not resolution and fix_version and plabel:
        pkg_name = plabel.split("@")[0]
        resolution = f"Upgrade {pkg_name} to {fix_version}."
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    external_id_raw = (
        finding.get("vulnerability_id")
        or finding.get("vulnerabilityId")
        or finding.get("id")
        or finding.get("finding_id")
    )
    if external_id_raw:
        image_id_part = (
            finding.get("image_id")
            or finding.get("imageId")
            or (image.get("image_id") if isinstance(image, dict) else None)
            or ""
        )
        pkg_part = finding.get("package_name") or finding.get("packageName") or finding.get("resource_name") or ""
        if image_id_part and pkg_part:
            external_id = f"{external_id_raw}@{pkg_part}@{image_id_part}"
        else:
            external_id = str(external_id_raw)
    else:
        external_id = str(cves[0] if cves else "")

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Aqua finding {external_id}",
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
        "tags": ["aqua_enterprise", "cnapp", "cloud-security"],
    }


def host_bucket_key(finding):
    """Build a stable bucket key for grouping findings into image hosts."""
    if not isinstance(finding, dict):
        return "__unknown__"
    image_id = finding.get("image_id") or finding.get("imageId") or finding.get("digest")
    if isinstance(image_id, str) and image_id.strip():
        return image_id.strip()
    registry = finding.get("registry") or finding.get("registry_name") or ""
    repo = finding.get("repository") or finding.get("image_name") or finding.get("image_repository_name") or ""
    if registry and repo:
        return f"{registry}/{repo}"
    if repo:
        return str(repo)
    if registry:
        return str(registry)
    return "__unknown__"


def build_host(bucket_key, image, findings, vulns):
    """Build a Faraday host shell from an Aqua image bucket."""
    registry = ""
    repo = ""
    image_id = ""
    tag = ""
    os_name = ""
    architecture = ""
    if isinstance(image, dict):
        registry = image.get("registry") or image.get("registry_name") or ""
        repo = image.get("repository") or image.get("image_name") or image.get("name") or ""
        image_id = image.get("image_id") or image.get("imageId") or image.get("digest") or ""
        tag = image.get("image_tag") or image.get("tag") or ""
        os_name = image.get("os") or image.get("os_version") or ""
        architecture = image.get("architecture") or image.get("arch") or ""
    if not registry and findings:
        first = findings[0]
        if isinstance(first, dict):
            registry = first.get("registry") or first.get("registry_name") or ""
            if not repo:
                repo = first.get("repository") or first.get("image_name") or first.get("image_repository_name") or ""
            if not image_id:
                image_id = first.get("image_id") or first.get("imageId") or first.get("digest") or ""
            if not tag:
                tag = first.get("image_tag") or first.get("tag") or ""
            if not os_name:
                os_name = first.get("os") or first.get("os_version") or ""
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
    desc_parts = []
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
    if architecture:
        desc_parts.append(f"architecture={architecture}")
    if findings:
        desc_parts.append(f"findings={len(findings)}")
    return {
        "ip": "0.0.0.0",
        "os": str(os_name) if os_name else "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("AQUA_HOST", required=True)
    username = env("AQUA_USER", required=True)
    password = env("AQUA_PASSWORD", required=True)
    registry = env("EXECUTOR_CONFIG_AQUA_REGISTRY")
    repo = env("EXECUTOR_CONFIG_AQUA_REPO")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_AQUA_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]
    severities = severities_at_or_above(min_severity)
    if severities and len(severities) == len(AQUA_API_SEVERITY):
        severities = None

    base_url = normalize_base_url(host)
    if not base_url:
        log("AQUA_HOST is required")
        sys.exit(1)

    token = fetch_access_token(base_url, username, password)
    if not token:
        log("Failed to obtain Aqua Enterprise access token; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    findings = fetch_findings(base_url, headers, registry, repo, severities)
    log(
        f"Processing {len(findings)} Aqua Enterprise findings "
        f"(registry={registry or 'ALL'}, repo={repo or 'ALL'}, min_severity={min_severity})"
    )

    buckets = {}
    for finding in findings:
        key = host_bucket_key(finding)
        buckets.setdefault(key, []).append(finding)

    # Best-effort image enrichment per unique bucket
    image_meta = {}
    for key in list(buckets.keys()):
        if key == "__unknown__":
            continue
        first = buckets[key][0] if buckets[key] else {}
        f_registry = first.get("registry") or first.get("registry_name") or registry or ""
        f_repo = first.get("repository") or first.get("image_name") or first.get("image_repository_name") or repo or ""
        f_image_id = first.get("image_id") or first.get("imageId") or first.get("digest") or ""
        image = fetch_image(base_url, headers, f_registry, f_repo, f_image_id)
        if image:
            image_meta[key] = image

    hosts = []
    for key, bucket in buckets.items():
        image = image_meta.get(key)
        vulns = []
        for finding in bucket:
            built = build_vulnerability(finding, image)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        bucket_id = "" if key == "__unknown__" else key
        hosts.append(build_host(bucket_id, image, bucket, vulns))

    params = f"min_severity={min_severity}"
    if registry:
        params = f"{params},registry={registry}"
    if repo:
        params = f"{params},repo={repo}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "aqua_enterprise",
            "command": "aqua_enterprise",
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
