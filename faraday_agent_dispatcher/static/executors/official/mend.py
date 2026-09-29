#!/usr/bin/env python
"""Mend (formerly WhiteSource) REST API importer.

Pulls Software Composition Analysis findings from Mend (formerly
WhiteSource / Mend.io) and emits Faraday bulk-create JSON to stdout.
Each Mend project becomes one Faraday host (``ip`` = synthetic
``0.0.0.0`` because SCA findings live in dependency manifests, not on
IPs); per-project security alerts are attached as Faraday
vulnerabilities — one per alert with engine prefix ``[SCA]``.

Endpoints used:
  POST /api/v2.0/login
      -> exchange ``userKey`` + ``orgToken`` for a short-lived
      ``jwtToken`` used in the ``Authorization: Bearer <token>`` header
      of every subsequent call.
  GET  /api/v2.0/products/{productToken}/projects
      -> list every project under a product (used when
      MEND_PRODUCT_TOKEN is given without MEND_PROJECT_TOKEN, so the
      executor fans out across the product's projects).
  GET  /api/v2.0/projects/{projectToken}/alerts/security
      -> list security alerts (vulnerable libraries) for one project,
      paginated via ``page`` / ``pageSize``. Falls back to
      ``/api/v2.0/projects/{projectToken}/alerts`` (all alert types,
      filtered client-side to SECURITY_VULNERABILITY) when the
      ``security`` sub-resource is not exposed by the tenant.
  GET  /api/v2.0/projects/{projectToken}/libraries
      -> list every library in the project's BOM, paginated. Used to
      populate the host description with the library count.

Auth: Mend's v2.0 REST API uses a two-step auth flow — a long-lived
``orgToken`` + ``userKey`` pair is exchanged for a short-lived
``jwtToken`` via POST /api/v2.0/login (JSON body ``{"orgToken": ...,
"userKey": ...}``). The response ``retVal.jwtToken`` is then sent as
``Authorization: Bearer <jwtToken>`` on every subsequent call. A
pre-built ``Bearer <token>`` value in MEND_API_KEY is accepted and
routed verbatim so OAuth tokens minted by an external identity provider
can skip the exchange step.

MEND_HOST is the Mend tenant base URL (e.g.
``https://saas.mend.io`` or ``https://app-eu.mend.io``).
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Mend surfaces severity as an upper-case enum (CRITICAL / HIGH /
# MEDIUM / LOW) on the vulnerability object plus an alert-level field
# (MAJOR / MEDIUM / MINOR) on the alert wrapper. Tolerant of casing
# and the synonyms surfaced by adjacent products that share severity
# vocabularies with Mend.
MEND_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "major": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "ok": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
}

# Mend alert status enum:
#   ACTIVE -> open
#   RESOLVED / FIXED / CLOSED -> closed
#   IGNORED / SUPPRESSED -> risk-accepted (analyst declared not-an-issue)
MEND_STATUS_TO_FARADAY = {
    "active": "open",
    "open": "open",
    "new": "open",
    "in_progress": "open",
    "inprogress": "open",
    "reopened": "open",
    "resolved": "closed",
    "fixed": "closed",
    "closed": "closed",
    "remediated": "closed",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "accepted": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "acceptedrisk": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - Mend: {msg}", file=sys.stderr, flush=True)


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


def severity_from_mend(value, cvss=None):
    """Map a Mend severity / alert-level to a Faraday bucket.

    Accepts Mend's vulnerability severity enum (CRITICAL / HIGH /
    MEDIUM / LOW) as well as the alert-level enum (MAJOR / MEDIUM /
    MINOR) — they share buckets. Falls back to CVSS bucketing on the
    provided ``cvss`` argument when the primary value is missing or
    unrecognised. Numeric inputs are interpreted as CVSS base scores
    so vendor-shaped reports that surface a bare score still bucket
    correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in MEND_STRING_SEVERITY:
            return MEND_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_mend(alert):
    """Derive Faraday status from a Mend alert payload.

    Mend alerts carry a ``status`` enum (ACTIVE / IGNORED / RESOLVED)
    plus per-tenant analyst-triage flags (``ignored``, ``muted``,
    ``falsePositive``). Analyst triage wins over the lifecycle status
    so a Mend alert that's still ACTIVE but flagged false-positive
    surfaces as risk-accepted.
    """
    if not isinstance(alert, dict):
        return "open"
    # Analyst-triage flags first — they win even when the lifecycle
    # status says ACTIVE.
    if alert.get("falsePositive") is True or alert.get("false_positive") is True:
        return "risk-accepted"
    if alert.get("ignored") is True or alert.get("muted") is True:
        return "risk-accepted"
    if alert.get("suppressed") is True:
        return "risk-accepted"
    if alert.get("fixed") is True or alert.get("resolved") is True:
        return "closed"
    for key in ("status", "state", "alertStatus", "alert_status"):
        raw = alert.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value")
        if isinstance(raw, str):
            compact_key = raw.strip().lower().replace(" ", "_").replace("-", "_")
            mapped = MEND_STATUS_TO_FARADAY.get(compact_key)
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in MEND_STATUS_TO_FARADAY:
                return MEND_STATUS_TO_FARADAY[compact]
    return "open"


def normalize_base_url(host):
    if not host:
        return ""
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def exchange_token(base_url, user_key, api_key):
    """Exchange a Mend userKey + orgToken for a short-lived JWT.

    Returns the JWT string. Pre-built ``Bearer <token>`` values in
    MEND_API_KEY short-circuit the exchange and are returned unchanged
    (stripped of the ``Bearer `` prefix so the caller can re-wrap it).
    Mend tenants that front the v2.0 API with an OAuth gateway can
    pass the issued bearer directly.
    """
    if not api_key:
        return None
    text = str(api_key).strip()
    lower = text.lower()
    if lower.startswith("bearer "):
        return text[7:].strip()
    if not user_key:
        log("MEND_USER_KEY is required when MEND_API_KEY is not a pre-built bearer")
        return None
    url = f"{base_url}/api/v2.0/login"
    payload = {"orgToken": text, "userKey": str(user_key).strip()}
    email = os.getenv("MEND_EMAIL")
    if email:
        payload["email"] = email.strip()
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST /api/v2.0/login failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Login rejected (401). Check MEND_USER_KEY / MEND_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log("Login forbidden (403). Check that the userKey has access to the orgToken.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Login failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log("Login returned non-JSON body")
        return None
    # Mend wraps the JWT in ``retVal``; some older builds return the
    # token at the top level. Tolerate both.
    container = body.get("retVal") if isinstance(body, dict) else None
    if not isinstance(container, dict):
        container = body if isinstance(body, dict) else {}
    jwt = (
        container.get("jwtToken")
        or container.get("jwt_token")
        or container.get("accessToken")
        or container.get("access_token")
        or container.get("token")
    )
    if not jwt:
        log("Login response missing jwtToken")
        return None
    return str(jwt).strip()


def request_json(method, url, headers, params=None, payload=None):
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=payload,
            timeout=TIMEOUT,
            verify=False,
        )
    except requests.RequestException as exc:
        log(f"{method} {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). JWT expired or invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {url}. Check token scope.")
        return None
    if resp.status_code == 404:
        log(f"{method} {url} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"{method} {url} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        log(f"{method} {url} returned non-JSON body")
        return None


def extract_list(body):
    """Pluck a list of values out of a Mend REST response.

    Mend's v2.0 endpoints wrap pages in ``{"retVal": [...],
    "additionalData": {"totalItems": N}}``. A handful of older /
    internal endpoints surface a bare list / ``items`` / ``results`` /
    ``data`` shape, so we tolerate each of those.
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for candidate in (
            "retVal",
            "items",
            "results",
            "data",
            "values",
            "content",
            "alerts",
            "projects",
            "libraries",
        ):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
        # retVal can itself wrap a list under e.g. "alerts" / "projects".
        ret = body.get("retVal")
        if isinstance(ret, dict):
            for candidate in ("alerts", "items", "projects", "libraries", "data", "values"):
                value = ret.get(candidate)
                if isinstance(value, list):
                    return value
    return []


def collect(base_url, path, headers, params=None, allow_404=False):
    """Walk a Mend paginated endpoint via ``page`` / ``pageSize``."""
    results = []
    url = f"{base_url}{path}" if path.startswith("/") else f"{base_url}/{path}"
    page = 0
    for _ in range(MAX_PAGES):
        query = dict(params or {})
        query["page"] = page
        query["pageSize"] = PAGE_SIZE
        body = request_json("GET", url, headers, params=query)
        if body is None and allow_404:
            return None
        chunk = extract_list(body)
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            meta = body.get("additionalData")
            if isinstance(meta, dict):
                total = meta.get("totalItems") or meta.get("total_items")
            total = total or body.get("totalItems") or body.get("total_items") or body.get("total")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def get_product_projects(base_url, headers, product_token):
    return collect(
        base_url,
        f"/api/v2.0/products/{product_token}/projects",
        headers,
    )


def get_project_alerts(base_url, headers, project_token):
    """Pull all SECURITY_VULNERABILITY alerts for a Mend project.

    Tries the typed ``alerts/security`` sub-resource first (returned
    by modern tenants) and falls back to the generic ``alerts`` endpoint
    when the typed sub-resource is absent or rejects the call. The
    fallback path is filtered client-side to ``SECURITY_VULNERABILITY``
    alerts so non-security alerts (e.g. NEW_MAJOR_VERSION, policy
    violations) don't leak into Faraday's vulnerability stream.
    """
    typed = collect(
        base_url,
        f"/api/v2.0/projects/{project_token}/alerts/security",
        headers,
        allow_404=True,
    )
    if typed is not None:
        return typed
    raw = collect(
        base_url,
        f"/api/v2.0/projects/{project_token}/alerts",
        headers,
    )
    filtered = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        t = entry.get("type") or entry.get("alertType")
        if not isinstance(t, str):
            filtered.append(entry)
            continue
        if t.strip().upper() in ("SECURITY_VULNERABILITY", "SECURITY VULNERABILITY", "SECURITY"):
            filtered.append(entry)
    return filtered


def get_project_libraries(base_url, headers, project_token):
    return collect(
        base_url,
        f"/api/v2.0/projects/{project_token}/libraries",
        headers,
    )


def get_project_meta(base_url, headers, project_token):
    """Best-effort project detail fetch for the host description.

    Returns the project dict; empty when the Mend API rejects the call
    (e.g. token lacks read scope on the project), which is non-fatal.
    """
    url = f"{base_url}/api/v2.0/projects/{project_token}"
    body = request_json("GET", url, headers) or {}
    if isinstance(body, dict):
        ret = body.get("retVal")
        if isinstance(ret, dict):
            return ret
        if "projectName" in body or "name" in body or "projectToken" in body:
            return body
    return {}


def cvss_score(vuln):
    """Pull a numeric CVSS score out of a Mend vulnerability payload.

    Mend surfaces a top-level ``score`` (CVSS base) on the
    vulnerability object plus nested ``cvss3`` / ``cvss2`` breakdowns
    on tenants that import the full NVD payload. We walk the usual
    suspects so the imported severity matches what Mend originally
    posted.
    """
    if not isinstance(vuln, dict):
        return None
    for key in ("score", "cvss3Score", "cvss_3_score", "cvssScore", "baseScore", "base_score", "overallScore"):
        value = vuln.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for key in ("cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = vuln.get(key)
        if isinstance(nested, dict):
            for k in ("base_score", "baseScore", "overallScore", "overall_score", "score"):
                score = nested.get(k)
                if score is None:
                    continue
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
    return None


def collect_refs(alert, vuln):
    """Walk a Mend alert + vulnerability for CWE / advisory / URL refs."""
    refs = []
    seen = set()

    def add(text, ref_type="other"):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": ref_type})

    sources = []
    if isinstance(alert, dict):
        sources.append(alert)
    if isinstance(vuln, dict):
        sources.append(vuln)

    for src in sources:
        cwe_raw = src.get("cwe") or src.get("cweId") or src.get("cwe_id")
        if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
            add(f"CWE-{int(cwe_raw)}")
        elif isinstance(cwe_raw, str) and cwe_raw.strip():
            s = cwe_raw.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("cwes", "cweIds", "cwe_ids"):
            items = src.get(key)
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

        for key in ("references", "links"):
            entry = src.get(key)
            if isinstance(entry, list):
                for it in entry:
                    if isinstance(it, dict):
                        href = it.get("url") or it.get("href") or it.get("name")
                        if href:
                            add(href)
                    elif it:
                        add(str(it))

        top_fix = src.get("topFix") or src.get("top_fix")
        if isinstance(top_fix, dict):
            for key in ("url", "origin", "vulnerability"):
                value = top_fix.get(key)
                if isinstance(value, str) and value.strip():
                    add(value.strip())

        for key in ("allFixes", "all_fixes"):
            entries = src.get(key)
            if isinstance(entries, list):
                for fx in entries:
                    if isinstance(fx, dict):
                        url = fx.get("url") or fx.get("origin")
                        if isinstance(url, str) and url.strip():
                            add(url.strip())

    return refs


def collect_cves(alert, vuln):
    """Pull CVE-* ids out of a Mend alert + vulnerability payload."""
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if not s.startswith("CVE-"):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    sources = []
    if isinstance(alert, dict):
        sources.append(alert)
    if isinstance(vuln, dict):
        sources.append(vuln)

    for src in sources:
        for key in ("name", "vulnerabilityName", "vulnerability_name", "cve", "cveId", "cveName"):
            v = src.get(key)
            if isinstance(v, str) and v.strip():
                add(v)
        for key in ("cves", "cveIds", "cve_ids", "aliases"):
            v = src.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add(entry)
                    elif isinstance(entry, dict):
                        add(entry.get("name") or entry.get("id") or entry.get("value"))
    return found


def library_meta(alert):
    """Pull library coordinates out of a Mend alert payload.

    Mend's ``library`` object carries Maven-style ``groupId`` /
    ``artifactId`` / ``version`` for Java, ``name`` / ``version`` for
    everything else, plus a ``filename`` and a package ``type``
    (MAVEN_ARTIFACT, JAVA_SCRIPT_LIBRARY, PYTHON_PACKAGE, ...).
    """
    if not isinstance(alert, dict):
        return {}
    lib = alert.get("library")
    if not isinstance(lib, dict):
        return {}
    meta = {
        "name": lib.get("name") or lib.get("artifactId") or "",
        "version": lib.get("version") or "",
        "groupId": lib.get("groupId") or "",
        "artifactId": lib.get("artifactId") or "",
        "filename": lib.get("filename") or "",
        "type": lib.get("type") or "",
        "language": lib.get("language") or "",
    }
    licenses = lib.get("licenses")
    if isinstance(licenses, list):
        labels = []
        for lic in licenses:
            if isinstance(lic, dict):
                labels.append(lic.get("name") or lic.get("licenseDisplay") or "")
            elif lic:
                labels.append(str(lic))
        meta["licenses"] = ", ".join(label for label in labels if label)
    return meta


def coord_label(meta):
    """Build a human-readable component coordinate from library_meta."""
    if not meta:
        return ""
    group = meta.get("groupId")
    artifact = meta.get("artifactId") or meta.get("name")
    version = meta.get("version")
    if group and artifact:
        coord = f"{group}:{artifact}"
    else:
        coord = artifact or meta.get("name") or ""
    if coord and version:
        return f"{coord}@{version}"
    if version:
        return version
    return coord


def build_vulnerability(alert, project_name=None, project_token=None):
    """Build a Faraday vulnerability dict from one Mend alert entry."""
    if not isinstance(alert, dict):
        return None
    vuln = alert.get("vulnerability")
    if not isinstance(vuln, dict):
        vuln = {}

    lmeta = library_meta(alert)
    coord = coord_label(lmeta)

    score = cvss_score(vuln)
    # Prefer the vulnerability severity (CRITICAL/HIGH/MEDIUM/LOW); the
    # alert-level enum (MAJOR / MEDIUM / MINOR) is a less granular
    # fallback used when the vulnerability shape is omitted.
    severity = severity_from_mend(vuln.get("severity"), score)
    if severity == "info" and not vuln.get("severity"):
        severity = severity_from_mend(alert.get("level"), score)
    status = status_from_mend(alert)

    vname = (
        vuln.get("name")
        or vuln.get("vulnerabilityName")
        or vuln.get("cve")
        or alert.get("name")
        or alert.get("uuid")
        or "Mend finding"
    )
    raw_name = vname if not coord else f"{vname} in {coord}"
    name = f"[SCA] {raw_name}"

    desc_parts = []
    description = vuln.get("description") or alert.get("description")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if coord:
        desc_parts.append(f"component: {coord}")
    if lmeta.get("filename"):
        desc_parts.append(f"filename: {lmeta['filename']}")
    if lmeta.get("type"):
        desc_parts.append(f"packageType: {lmeta['type']}")
    if lmeta.get("language"):
        desc_parts.append(f"language: {lmeta['language']}")
    if lmeta.get("licenses"):
        desc_parts.append(f"licenses: {lmeta['licenses']}")
    alert_type = alert.get("type") or alert.get("alertType")
    if alert_type:
        desc_parts.append(f"alertType: {alert_type}")
    level = alert.get("level")
    if level:
        desc_parts.append(f"alertLevel: {level}")
    vuln_type = vuln.get("type")
    if vuln_type:
        desc_parts.append(f"vulnerabilityType: {vuln_type}")
    publish = vuln.get("publishDate") or vuln.get("publish_date") or vuln.get("published")
    if publish:
        desc_parts.append(f"published: {publish}")
    updated = vuln.get("lastUpdatedDate") or vuln.get("last_updated_date") or vuln.get("updated")
    if updated:
        desc_parts.append(f"updated: {updated}")
    creation = alert.get("creationDate") or alert.get("creation_date")
    if creation:
        desc_parts.append(f"alertCreated: {creation}")
    modification = alert.get("modificationDate") or alert.get("modification_date")
    if modification:
        desc_parts.append(f"alertModified: {modification}")
    raw_status = alert.get("status")
    if raw_status:
        desc_parts.append(f"status: {raw_status}")
    vector = vuln.get("scoreMetadataVector") or vuln.get("vector") or vuln.get("cvssVector")
    if vector:
        desc_parts.append(f"vector: {vector}")
    if score is not None:
        desc_parts.append(f"score: {score}")
    if project_name:
        desc_parts.append(f"project: {project_name}")
    if project_token:
        desc_parts.append(f"projectToken: {project_token}")

    cves = collect_cves(alert, vuln)
    refs = collect_refs(alert, vuln)

    resolution_parts = []
    top_fix = vuln.get("topFix") or vuln.get("top_fix") or alert.get("topFix")
    if isinstance(top_fix, dict):
        for key in ("fixResolution", "fix_resolution", "message", "type", "vulnerability"):
            value = top_fix.get(key)
            if isinstance(value, str) and value.strip():
                resolution_parts.append(value.strip())
                break
        top_url = top_fix.get("url") or top_fix.get("origin")
        if isinstance(top_url, str) and top_url.strip() and top_url.strip() not in resolution_parts:
            resolution_parts.append(top_url.strip())
    elif isinstance(top_fix, str) and top_fix.strip():
        resolution_parts.append(top_fix.strip())
    for key in ("fixResolution", "fix_resolution", "remediation", "recommendation", "solution"):
        for src in (vuln, alert):
            if not isinstance(src, dict):
                continue
            v = src.get(key)
            if isinstance(v, str) and v.strip():
                resolution_parts.append(v.strip())
                break
    resolution = " | ".join(dict.fromkeys(resolution_parts))

    external_id = (
        alert.get("uuid")
        or alert.get("id")
        or vuln.get("name")
        or vuln.get("vulnerabilityName")
        or (cves[0] if cves else "")
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    vector = vuln.get("scoreMetadataVector") or vuln.get("vector")
    if isinstance(vector, str) and vector.strip():
        cvss3["vector_string"] = vector.strip()

    return {
        "name": str(name).strip()[:200] or f"Mend finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id),
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["mend", "whitesource", "sca"],
    }


def build_host(project_token, project, libraries, vulns):
    project_name = ""
    if isinstance(project, dict):
        project_name = project.get("projectName") or project.get("name") or project.get("project_name") or ""
    hostname = f"{project_name}@{project_token}" if project_name else project_token
    desc_parts = [f"projectToken={project_token}"]
    if project_name:
        desc_parts.append(f"project={project_name}")
    if isinstance(project, dict):
        product = project.get("productName") or project.get("product_name") or project.get("product")
        if product:
            desc_parts.append(f"product={product}")
        last_scan = project.get("lastScanDate") or project.get("last_scan_date") or project.get("lastModificationDate")
        if last_scan:
            desc_parts.append(f"lastScan={last_scan}")
    if libraries:
        desc_parts.append(f"libraries={len(libraries)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"MEND_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def resolve_project_tokens(base_url, headers, project_token, product_token):
    """Return the list of project tokens to import + per-token metadata.

    When ``project_token`` is supplied that single project is imported;
    otherwise ``product_token`` is walked via
    ``/api/v2.0/products/{token}/projects`` and every project under the
    product is imported (with its project payload pre-cached so we
    don't have to re-fetch the per-project meta separately).
    """
    if project_token:
        return [(project_token, None)]
    if not product_token:
        log("Either MEND_PROJECT_TOKEN or MEND_PRODUCT_TOKEN must be provided")
        sys.exit(1)
    projects = get_product_projects(base_url, headers, product_token) or []
    tokens = []
    for project in projects:
        if not isinstance(project, dict):
            continue
        tok = (
            project.get("projectToken") or project.get("project_token") or project.get("token") or project.get("uuid")
        )
        if tok:
            tokens.append((tok, project))
    if not tokens:
        log(f"No projects found under product {product_token}; " "check MEND_PRODUCT_TOKEN and token scope.")
    return tokens


def main():
    started = time.time()
    host = env("MEND_HOST", required=True)
    user_key = env("MEND_USER_KEY")
    api_key = env("MEND_API_KEY", required=True)
    project_token = env("EXECUTOR_CONFIG_MEND_PROJECT_TOKEN")
    product_token = env("EXECUTOR_CONFIG_MEND_PRODUCT_TOKEN")
    if not project_token and not product_token:
        log("Either MEND_PROJECT_TOKEN or MEND_PRODUCT_TOKEN must be provided")
        sys.exit(1)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_MEND_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    if not base_url:
        log("MEND_HOST is required")
        sys.exit(1)

    jwt = exchange_token(base_url, user_key, api_key)
    if not jwt:
        log("Failed to obtain JWT; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/json",
    }

    tokens = resolve_project_tokens(base_url, headers, project_token, product_token)

    hosts = []
    total_vulns = 0
    for tok, cached_project in tokens:
        project = cached_project or get_project_meta(base_url, headers, tok) or {}
        libraries = get_project_libraries(base_url, headers, tok) or []
        alerts = get_project_alerts(base_url, headers, tok) or []
        project_name = project.get("projectName") or project.get("name") if isinstance(project, dict) else None
        log(
            f"Processing {len(alerts)} security alerts "
            f"(project_token={tok}, libraries={len(libraries)}, "
            f"min_severity={min_severity})"
        )

        vulns = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            built = build_vulnerability(alert, project_name=project_name, project_token=tok)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        total_vulns += len(vulns)
        if vulns:
            hosts.append(build_host(tok, project, libraries, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "mend",
            "command": "mend",
            "params": (
                f"project_token={project_token or ''},product_token={product_token or ''},"
                f"min_severity={min_severity}"
            ),
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
