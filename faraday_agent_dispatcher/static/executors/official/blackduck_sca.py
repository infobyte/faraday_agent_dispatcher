#!/usr/bin/env python
"""Black Duck Hub (Black Duck Software Composition Analysis) REST API importer.

Pulls Software Composition Analysis findings from a Black Duck Hub
(Synopsys / Black Duck) project version's BOM and emits Faraday
bulk-create JSON to stdout. Each Black Duck project version becomes
one Faraday host (``ip`` = synthetic ``0.0.0.0`` because SCA findings
live in dependency manifests, not on IPs); per-version vulnerable-BOM
components are attached as Faraday vulnerabilities — one per
``componentName@componentVersionName`` + ``vulnerabilityName`` pair
with engine prefix ``[SCA]``.

Endpoints used:
  GET /api/projects/{id}/versions/{vid}/components
      -> list every component currently in the project version's BOM
      (paginated via ``offset`` / ``limit``). Used to build the
      component inventory surfaced in the host description.
  GET /api/projects/{id}/versions/{vid}/vulnerable-bom-components
      -> list every BOM component that carries at least one
      vulnerability for the given project version (paginated). Each
      entry carries ``componentName``, ``componentVersionName`` and a
      ``vulnerabilityWithRemediation`` object with ``vulnerabilityName``
      (CVE-* / BDSA-* id), ``severity``, ``baseScore`` /
      ``overallScore``, ``cweId``, ``remediationStatus`` and source
      (NVD / BDSA).

Auth: Black Duck Hub uses an API token exchanged into a short-lived
bearer:
  POST /api/tokens/authenticate
      Header: ``Authorization: token <BD_TOKEN>``
      -> JSON ``{"bearerToken": "...", "expiresInMilliseconds": N}``
Subsequent calls send ``Authorization: Bearer <bearerToken>``. A
pre-built ``Bearer <token>`` value in BD_TOKEN is accepted and routed
to the Authorization header verbatim (skips the exchange step) so
short-lived OAuth tokens from external identity providers can be used
directly.

BD_HOST is the Black Duck Hub base URL (e.g.
``https://blackduck.corp.example.com``); the hosted SaaS appliance
URL is also accepted.
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

# Black Duck Hub emits severity as an upper-case enum (CRITICAL / HIGH /
# MEDIUM / LOW), plus UNSPECIFIED / OK / NONE for components without an
# active vulnerability. Tolerant of casing and a few synonyms surfaced
# by adjacent products that share severity vocabularies with Black Duck.
BD_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
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

# Black Duck remediationStatus enum:
#   NEW / NEEDS_REVIEW / REMEDIATION_REQUIRED -> open
#   PATCHED / REMEDIATION_COMPLETE / MITIGATED -> closed
#   IGNORED / DUPLICATE -> risk-accepted (analyst declared not-an-issue)
BD_STATUS_TO_FARADAY = {
    "new": "open",
    "needs_review": "open",
    "needsreview": "open",
    "remediation_required": "open",
    "remediationrequired": "open",
    "open": "open",
    "active": "open",
    "patched": "closed",
    "remediation_complete": "closed",
    "remediationcomplete": "closed",
    "mitigated": "closed",
    "resolved": "closed",
    "closed": "closed",
    "fixed": "closed",
    "ignored": "risk-accepted",
    "duplicate": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "accepted": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "acceptedrisk": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "suppressed": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - BlackDuckSCA: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
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


def severity_from_bd(value, cvss=None):
    """Map a Black Duck severity to a Faraday bucket.

    Accepts Black Duck's string enum (CRITICAL / HIGH / MEDIUM / LOW
    plus UNSPECIFIED / OK / NONE) and falls back to CVSS bucketing on
    the provided ``cvss`` argument when the primary value is missing
    or unrecognised. Numeric inputs are interpreted as CVSS base
    scores so vendor-shaped reports that surface a bare score still
    bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in BD_STRING_SEVERITY:
            return BD_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_bd(vuln):
    """Derive Faraday status from a Black Duck vulnerability payload.

    Black Duck's ``vulnerabilityWithRemediation`` object carries a
    ``remediationStatus`` enum (NEW / NEEDS_REVIEW / PATCHED / etc.)
    and an optional ``remediationActualAt`` timestamp. We honour the
    most specific signal first so analyst-triaged findings land where
    Faraday users expect.
    """
    if not isinstance(vuln, dict):
        return "open"
    for key in ("remediationStatus", "remediation_status", "status", "state"):
        raw = vuln.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value")
        if isinstance(raw, str):
            mapped = BD_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in BD_STATUS_TO_FARADAY:
                return BD_STATUS_TO_FARADAY[compact]
    return "open"


def normalize_base_url(host):
    if not host:
        return ""
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def build_auth_header(token):
    """Build the Authorization header for the Black Duck Hub REST API.

    Black Duck Hub's documented auth flow is to POST an API token to
    /api/tokens/authenticate with ``Authorization: token <api_key>``
    and exchange it for a short-lived bearer. A pre-built ``Bearer
    <token>`` value in BD_TOKEN is forwarded verbatim because some
    customers front Black Duck with an OAuth gateway that already
    issues bearers.
    """
    if not token:
        return {}
    text = str(token).strip()
    lower = text.lower()
    if lower.startswith("bearer "):
        return {"Authorization": text}
    return {"Authorization": f"token {text}"}


def exchange_token(base_url, token):
    """Exchange a Black Duck API token for a short-lived bearer.

    Returns the bearer string. Pre-built ``Bearer <token>`` values
    short-circuit the exchange and are returned unchanged (stripped
    of the ``Bearer `` prefix so the caller can re-wrap it).
    """
    if not token:
        return None
    text = str(token).strip()
    lower = text.lower()
    if lower.startswith("bearer "):
        return text[7:].strip()
    url = f"{base_url}/api/tokens/authenticate"
    headers = {"Authorization": f"token {text}", "Accept": "application/json"}
    try:
        resp = requests.post(url, headers=headers, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST /api/tokens/authenticate failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Token exchange rejected (401). Check BD_TOKEN.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Token exchange failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log("Token exchange returned non-JSON body")
        return None
    bearer = body.get("bearerToken") or body.get("bearer_token") or body.get("access_token")
    if not bearer:
        log("Token exchange response missing bearerToken")
        return None
    return bearer


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
        log("Authentication rejected (401). Bearer expired or invalid.")
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
    """Pluck a list of values out of a Black Duck REST response.

    Black Duck's REST endpoints wrap pages in ``{"items": [...],
    "totalCount": N}``. A handful of older / internal endpoints also
    surface a bare list / ``results`` / ``data`` shape, so we tolerate
    each of those.
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for candidate in ("items", "results", "data", "values", "content"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, params=None):
    """Walk a Black Duck paginated endpoint via ``offset`` / ``limit``."""
    results = []
    url = f"{base_url}{path}" if path.startswith("/") else f"{base_url}/{path}"
    offset = 0
    for _ in range(MAX_PAGES):
        query = dict(params or {})
        query["offset"] = offset
        query["limit"] = PAGE_SIZE
        body = request_json("GET", url, headers, params=query)
        chunk = extract_list(body)
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("totalCount") or body.get("total_count") or body.get("total")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return results


def get_components(base_url, headers, project_id, version_id):
    return collect(
        base_url,
        f"/api/projects/{project_id}/versions/{version_id}/components",
        headers,
    )


def get_vulnerable_components(base_url, headers, project_id, version_id):
    return collect(
        base_url,
        f"/api/projects/{project_id}/versions/{version_id}/vulnerable-bom-components",
        headers,
    )


def get_project_version(base_url, headers, project_id, version_id):
    """Best-effort project + version detail fetch for the host description.

    Returns ``(project, version)`` dicts; either may be empty when the
    Black Duck API rejects the call (e.g. token lacks read scope on the
    project), which is non-fatal.
    """
    project_url = f"{base_url}/api/projects/{project_id}"
    version_url = f"{base_url}/api/projects/{project_id}/versions/{version_id}"
    project = request_json("GET", project_url, headers) or {}
    version = request_json("GET", version_url, headers) or {}
    project = project if isinstance(project, dict) else {}
    version = version if isinstance(version, dict) else {}
    return project, version


def cvss_score(vuln):
    """Pull a numeric CVSS score out of a Black Duck vulnerability payload.

    Black Duck surfaces a top-level ``baseScore`` / ``overallScore`` for
    the vulnerability and a nested ``cvss3`` / ``cvss2`` object for the
    spec-version-specific breakdown. We walk the usual suspects so the
    imported severity matches what Black Duck originally posted.
    """
    if not isinstance(vuln, dict):
        return None
    for key in ("overallScore", "baseScore", "overall_score", "base_score", "score", "cvssScore"):
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


def collect_refs(vuln):
    """Walk a Black Duck vulnerability for CWE / advisory / URL refs."""
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

    cwe_raw = vuln.get("cweId") or vuln.get("cwe_id") or vuln.get("cwe")
    if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
        add(f"CWE-{int(cwe_raw)}")
    elif isinstance(cwe_raw, str) and cwe_raw.strip():
        s = cwe_raw.strip()
        add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
    for key in ("cwes", "cweIds", "cwe_ids"):
        items = vuln.get(key)
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

    related = vuln.get("relatedVulnerability") or vuln.get("related_vulnerability")
    if isinstance(related, str) and related.strip():
        add(related.strip())

    source = vuln.get("source")
    name = vuln.get("vulnerabilityName") or vuln.get("name") or vuln.get("vulnerability_name")
    if isinstance(source, str) and source.strip() and isinstance(name, str) and name.strip():
        add(f"{source.strip()}: {name.strip()}")

    for key in ("references", "links", "_meta"):
        entry = vuln.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("name")
                    if href:
                        add(href)
                elif it:
                    add(str(it))
        elif isinstance(entry, dict):
            href = entry.get("href") or entry.get("url")
            if href:
                add(href)
            links = entry.get("links")
            if isinstance(links, list):
                for lk in links:
                    if isinstance(lk, dict):
                        href = lk.get("href") or lk.get("url")
                        if href:
                            add(href)

    return refs


def collect_cves(vuln):
    """Pull CVE-* ids out of a Black Duck vulnerability payload."""
    if not isinstance(vuln, dict):
        return []
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

    name = vuln.get("vulnerabilityName") or vuln.get("name") or vuln.get("vulnerability_name")
    if isinstance(name, str):
        add(name)
    for key in ("cve", "cveId", "cveName"):
        v = vuln.get(key)
        if isinstance(v, str) and v.strip():
            add(v)
    for key in ("cves", "cveIds", "cve_ids"):
        v = vuln.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("name") or entry.get("id") or entry.get("value"))
    related = vuln.get("relatedVulnerability") or vuln.get("related_vulnerability")
    if isinstance(related, str):
        # Black Duck stores related CVEs as full hrefs ending in /CVE-2021-44228
        tail = related.rstrip("/").split("/")[-1]
        if tail:
            add(tail)
    return found


def component_meta(vuln):
    """Pull componentName@componentVersionName + license / origin info."""
    if not isinstance(vuln, dict):
        return {}
    meta = {
        "name": vuln.get("componentName") or vuln.get("component_name") or "",
        "version": vuln.get("componentVersionName") or vuln.get("component_version_name") or "",
        "origin": vuln.get("componentVersionOriginName") or vuln.get("componentVersionOriginId") or "",
    }
    licenses = vuln.get("licenses")
    if isinstance(licenses, list):
        labels = []
        for lic in licenses:
            if isinstance(lic, dict):
                labels.append(lic.get("licenseDisplay") or lic.get("name") or "")
            elif lic:
                labels.append(str(lic))
        meta["licenses"] = ", ".join(label for label in labels if label)
    return meta


def build_vulnerability(entry, project_name=None, version_name=None):
    """Build a Faraday vulnerability dict from one vulnerable-bom entry."""
    vuln = entry.get("vulnerabilityWithRemediation") if isinstance(entry, dict) else None
    if not isinstance(vuln, dict):
        vuln = entry if isinstance(entry, dict) else {}
    # Component metadata can be on either the top-level entry or nested.
    cmeta = component_meta(entry if isinstance(entry, dict) else {})
    if not cmeta.get("name"):
        cmeta = component_meta(vuln)

    score = cvss_score(vuln)
    severity = severity_from_bd(vuln.get("severity"), score)
    status = status_from_bd(vuln)

    vname = (
        vuln.get("vulnerabilityName")
        or vuln.get("name")
        or vuln.get("vulnerability_name")
        or vuln.get("id")
        or "Black Duck finding"
    )
    component_label = ""
    if cmeta.get("name"):
        component_label = cmeta["name"]
        if cmeta.get("version"):
            component_label = f"{component_label}@{cmeta['version']}"

    raw_name = vname if not component_label else f"{vname} in {component_label}"
    name = f"[SCA] {raw_name}"

    desc_parts = []
    description = vuln.get("description") or vuln.get("summary")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if component_label:
        desc_parts.append(f"component: {component_label}")
    if cmeta.get("origin"):
        desc_parts.append(f"origin: {cmeta['origin']}")
    if cmeta.get("licenses"):
        desc_parts.append(f"licenses: {cmeta['licenses']}")
    source = vuln.get("source")
    if source:
        desc_parts.append(f"source: {source}")
    published = vuln.get("vulnerabilityPublishedDate") or vuln.get("publishedDate") or vuln.get("published")
    if published:
        desc_parts.append(f"published: {published}")
    updated = vuln.get("vulnerabilityUpdatedDate") or vuln.get("updatedDate") or vuln.get("updated")
    if updated:
        desc_parts.append(f"updated: {updated}")
    remediation_status = vuln.get("remediationStatus") or vuln.get("remediation_status")
    if remediation_status:
        desc_parts.append(f"remediationStatus: {remediation_status}")
    remediation_target = vuln.get("remediationTargetAt") or vuln.get("remediation_target_at")
    if remediation_target:
        desc_parts.append(f"remediationTargetAt: {remediation_target}")
    if score is not None:
        desc_parts.append(f"score: {score}")
    if project_name:
        desc_parts.append(f"project: {project_name}")
    if version_name:
        desc_parts.append(f"version: {version_name}")

    cves = collect_cves(vuln)
    refs = collect_refs(vuln)

    resolution = (
        vuln.get("remediationComment")
        or vuln.get("remediation_comment")
        or vuln.get("remediation")
        or vuln.get("recommendation")
        or vuln.get("solution")
        or ""
    )

    external_id = vuln.get("vulnerabilityName") or vuln.get("name") or vuln.get("id") or (cves[0] if cves else "")

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score

    return {
        "name": str(name).strip()[:200] or f"Black Duck finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id),
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["blackduck_sca", "sca"],
    }


def build_host(project_id, version_id, project, version, components, vulns):
    project_name = (project or {}).get("name") or (project or {}).get("projectName") or project_id
    version_name = (
        (version or {}).get("versionName")
        or (version or {}).get("version_name")
        or (version or {}).get("name")
        or version_id
    )
    hostname = (
        f"{project_name}@{version_name}" if project_name and version_name else (project_name or version_name or "")
    )
    desc_parts = [f"project_id={project_id}", f"version_id={version_id}"]
    if project_name and project_name != project_id:
        desc_parts.append(f"project={project_name}")
    if version_name and version_name != version_id:
        desc_parts.append(f"version={version_name}")
    if isinstance(version, dict):
        phase = version.get("phase")
        if phase:
            desc_parts.append(f"phase={phase}")
        distribution = version.get("distribution")
        if distribution:
            desc_parts.append(f"distribution={distribution}")
    if components:
        desc_parts.append(f"components={len(components)}")
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
        log(f"BD_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def main():
    started = time.time()
    host = env("BD_HOST", required=True)
    raw_token = env("BD_TOKEN", required=True)
    project_id = env("EXECUTOR_CONFIG_BD_PROJECT_ID", required=True)
    version_id = env("EXECUTOR_CONFIG_BD_VERSION_ID", required=True)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_BD_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    if not base_url:
        log("BD_HOST is required")
        sys.exit(1)

    bearer = exchange_token(base_url, raw_token)
    if not bearer:
        log("Failed to obtain bearer token; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json",
    }

    project, version = get_project_version(base_url, headers, project_id, version_id)
    components = get_components(base_url, headers, project_id, version_id)
    entries = get_vulnerable_components(base_url, headers, project_id, version_id)
    log(
        f"Processing {len(entries)} vulnerable-bom entries "
        f"(project_id={project_id}, version_id={version_id}, "
        f"components={len(components)}, min_severity={min_severity})"
    )

    project_name = (project or {}).get("name") if isinstance(project, dict) else None
    version_name = None
    if isinstance(version, dict):
        version_name = version.get("versionName") or version.get("name")

    vulns = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        built = build_vulnerability(entry, project_name=project_name, version_name=version_name)
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)

    hosts = [build_host(project_id, version_id, project, version, components, vulns)] if vulns else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "blackduck_sca",
            "command": "blackduck_sca",
            "params": (f"project_id={project_id},version_id={version_id}," f"min_severity={min_severity}"),
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
