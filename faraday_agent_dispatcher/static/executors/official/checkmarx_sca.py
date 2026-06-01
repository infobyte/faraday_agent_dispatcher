#!/usr/bin/env python
"""Checkmarx SCA (CxSCA standalone) REST API importer.

Pulls Software Composition Analysis findings from a Checkmarx SCA
tenant and emits Faraday bulk-create JSON to stdout. Each Checkmarx
SCA project becomes one Faraday host (``ip`` = synthetic ``0.0.0.0``
because SCA findings live in dependency manifests, not on IPs); the
project's most recent scan's vulnerabilities are attached as Faraday
vulnerabilities — one per CxSCA vulnerability identifier.

Endpoints used:
  GET  /api/projects                                        -> list
      projects (or a single project via /api/projects/{id} when
      CXSCA_PROJECT_ID is set).
  GET  /api/projects/{id}/scans (or /api/scans?projectId=)  -> per-
      project scan list; the most recent successful scan is selected.
  GET  /api/scans/{id}/vulnerabilities                      -> per-
      scan vulnerabilities. Each entry carries severity, status,
      state, CVE, package name + version, fixed-in version and
      CVSS v3 score.

Auth: Static bearer token via CXSCA_ACCESS_TOKEN sent as
``Authorization: Bearer <token>`` on every API call. CXSCA_HOST is
the Checkmarx SCA regional base URL (e.g. https://api-sca.checkmarx.net,
https://eu.api-sca.checkmarx.net).
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

# Checkmarx SCA exposes severities both as the upper-case enum
# ("CRITICAL"/"HIGH"/"MEDIUM"/"LOW") and as the older lower-case
# string ("critical"/"high"/"medium"/"low"/"none"/"informational").
# CVSS numeric scores are used as a fallback when the severity bucket
# is absent.
CXSCA_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "negligible": "info",
}

# Checkmarx SCA result `state` (analyst triage) -> Faraday status.
# NOT_EXPLOITABLE / NotExploitable behave like risk-accepted (analyst
# declared the finding a false positive); CONFIRMED / URGENT /
# TO_VERIFY remain open. CxSCA additionally surfaces SNOOZED for
# temporarily-suppressed findings.
STATE_TO_STATUS = {
    "to_verify": "open",
    "toverify": "open",
    "confirmed": "open",
    "urgent": "open",
    "not_exploitable": "risk-accepted",
    "notexploitable": "risk-accepted",
    "proposed_not_exploitable": "risk-accepted",
    "proposednotexploitable": "risk-accepted",
    "ignored": "risk-accepted",
    "snoozed": "risk-accepted",
}

STATUS_OPEN = ("new", "recurrent", "active", "open")
STATUS_CLOSED = ("fixed", "resolved", "closed")


def log(msg):
    print(f"{datetime.utcnow()} - CheckmarxSCA: {msg}", file=sys.stderr, flush=True)


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
    return "critical"


def severity_from_cxsca(value, cvss=None):
    if value is not None:
        if isinstance(value, bool):
            pass
        elif isinstance(value, (int, float)):
            return severity_from_cvss(value)
        else:
            text = str(value).strip().lower()
            if text in CXSCA_TO_FARADAY:
                return CXSCA_TO_FARADAY[text]
            try:
                return severity_from_cvss(float(text))
            except ValueError:
                pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_cxsca(status_value, state_value):
    if state_value:
        text = str(state_value).strip().lower().replace(" ", "_").replace("-", "_")
        if text in STATE_TO_STATUS:
            return STATE_TO_STATUS[text]
        text_compact = text.replace("_", "")
        if text_compact in STATE_TO_STATUS:
            return STATE_TO_STATUS[text_compact]
    if status_value:
        text = str(status_value).strip().lower()
        if text in STATUS_CLOSED:
            return "closed"
        if text in STATUS_OPEN:
            return "open"
    return "open"


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"GET {path} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). Token expired or invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check token scope.")
        return None
    if resp.status_code == 404:
        log(f"GET {path} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def extract_list(body, *keys):
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys:
            value = body.get(key)
            if isinstance(value, list):
                return value
        for candidate in ("results", "data", "items", "value", "content"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, base_params, *list_keys):
    results = []
    offset = 0
    for _ in range(MAX_PAGES):
        params = dict(base_params or {})
        params["offset"] = offset
        params["limit"] = PAGE_SIZE
        body = get_page(base_url, path, headers, params)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("totalCount") or body.get("filteredTotalCount") or body.get("total")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return results


def get_projects(base_url, headers, project_id):
    if project_id:
        body = get_page(base_url, f"/api/projects/{project_id}", headers, {})
        if isinstance(body, dict):
            return [body]
        return []
    body = get_page(base_url, "/api/projects", headers, {})
    if isinstance(body, list):
        return body
    return extract_list(body, "projects")


def get_last_scan(base_url, headers, project_id):
    """Return the most recent scan id for a CxSCA project.

    Tries `/api/projects/{id}/scans` first (newer CxSCA shape) and
    falls back to `/api/scans?projectId=<id>` for older builds.
    """
    body = get_page(base_url, f"/api/projects/{project_id}/scans", headers, {})
    scans = body if isinstance(body, list) else extract_list(body, "scans")
    if not scans:
        body = get_page(base_url, "/api/scans", headers, {"projectId": project_id})
        scans = body if isinstance(body, list) else extract_list(body, "scans")
    # Prefer the most recent successful / completed scan.
    successful = []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        status = str(scan.get("status") or scan.get("scanStatus") or "").strip().lower()
        if status in ("done", "completed", "success", "successful", "finished"):
            successful.append(scan)
    pool = successful or [s for s in scans if isinstance(s, dict)]
    if not pool:
        return None

    def _sort_key(scan):
        return scan.get("createdOn") or scan.get("created_at") or scan.get("scanCreatedOn") or scan.get("date") or ""

    pool.sort(key=_sort_key, reverse=True)
    chosen = pool[0]
    return chosen.get("scanId") or chosen.get("id")


def get_vulnerabilities(base_url, headers, scan_id):
    body = get_page(base_url, f"/api/scans/{scan_id}/vulnerabilities", headers, {})
    if isinstance(body, list):
        return body
    return extract_list(body, "vulnerabilities", "results", "items")


def collect_refs(vuln):
    refs = []
    for entry in vuln.get("references") or []:
        if isinstance(entry, str) and entry:
            refs.append({"name": entry, "type": "other"})
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("name") or entry.get("value")
            if value:
                refs.append({"name": value, "type": entry.get("type", "other") or "other"})
    cwe = vuln.get("cweId") or vuln.get("cwe")
    if cwe:
        refs.append({"name": f"CWE-{cwe}", "type": "other"})
    for advisory in vuln.get("advisories") or []:
        if isinstance(advisory, str) and advisory:
            refs.append({"name": advisory, "type": "other"})
        elif isinstance(advisory, dict):
            value = advisory.get("url") or advisory.get("name") or advisory.get("id")
            if value:
                refs.append({"name": value, "type": "other"})
    return refs


def collect_cves(vuln):
    cves = []
    candidates = []
    for key in ("cve", "cveId", "cveName", "cve_id"):
        value = vuln.get(key)
        if value:
            candidates.append(value)
    for entry in vuln.get("cves") or []:
        if isinstance(entry, str):
            candidates.append(entry)
        elif isinstance(entry, dict):
            value = entry.get("name") or entry.get("id") or entry.get("value")
            if value:
                candidates.append(value)
    seen = set()
    for value in candidates:
        text = str(value).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)
    return cves


def build_vulnerability(vuln):
    cvss_obj = vuln.get("cvss3") or vuln.get("cvssV3") or vuln.get("cvss") or {}
    if isinstance(cvss_obj, dict):
        cvss_score = (
            cvss_obj.get("baseScore")
            or cvss_obj.get("base_score")
            or cvss_obj.get("score")
            or vuln.get("score")
            or vuln.get("cvssScore")
        )
    else:
        cvss_score = cvss_obj
    severity = severity_from_cxsca(vuln.get("severity"), cvss_score)
    status = status_from_cxsca(vuln.get("status"), vuln.get("state"))
    cves = collect_cves(vuln)
    raw_name = (
        vuln.get("name")
        or vuln.get("title")
        or (cves[0] if cves else None)
        or vuln.get("vulnerabilityId")
        or vuln.get("id")
        or "CxSCA finding"
    )
    name = f"[SCA] {raw_name}"
    desc_parts = []
    description = vuln.get("description") or vuln.get("summary") or vuln.get("vulnerabilityDetails")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    package_name = (
        vuln.get("packageName")
        or vuln.get("package_name")
        or vuln.get("packageId")
        or (vuln.get("package") or {}).get("name")
    )
    package_version = (
        vuln.get("packageVersion")
        or vuln.get("package_version")
        or vuln.get("currentVersion")
        or (vuln.get("package") or {}).get("version")
    )
    if package_name:
        if package_version:
            desc_parts.append(f"package: {package_name}@{package_version}")
        else:
            desc_parts.append(f"package: {package_name}")
    ecosystem = vuln.get("ecosystem") or vuln.get("packageManager") or (vuln.get("package") or {}).get("manager")
    if ecosystem:
        desc_parts.append(f"ecosystem: {ecosystem}")
    fixed_in = (
        vuln.get("recommendedVersion") or vuln.get("fixVersion") or vuln.get("fixedVersion") or vuln.get("fixVersions")
    )
    if fixed_in:
        if isinstance(fixed_in, list):
            fixed_in = ", ".join(str(v) for v in fixed_in if v)
        if fixed_in:
            desc_parts.append(f"fixed_in: {fixed_in}")
    published = vuln.get("publishDate") or vuln.get("publishedDate") or vuln.get("disclosureDate")
    if published:
        desc_parts.append(f"published: {published}")
    similarity = vuln.get("similarityId") or vuln.get("similarity_id")
    if similarity:
        desc_parts.append(f"similarityId: {similarity}")
    state_raw = vuln.get("state")
    if state_raw:
        desc_parts.append(f"state: {state_raw}")
    return {
        "name": str(name).strip()[:200] or "CxSCA finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(
            vuln.get("id") or vuln.get("vulnerabilityId") or vuln.get("similarityId") or (cves[0] if cves else "")
        ),
        "type": "Vulnerability",
        "status": status,
        "resolution": vuln.get("recommendations") or vuln.get("remediation") or "",
        "data": vuln.get("data") or "",
        "refs": collect_refs(vuln),
        "cve": cves,
        "cvss3": {"base_score": str(cvss_score)} if cvss_score else {},
        "tags": ["checkmarx_sca", "sca"],
    }


def build_host(project, vulns):
    name = project.get("name") or project.get("projectName") or project.get("id", "unknown")
    repo = project.get("repoUrl") or project.get("repositoryUrl") or project.get("scmRepoUrl")
    desc_parts = [f"Checkmarx SCA project name={name}", f"id={project.get('id', 'N/A')}"]
    if repo:
        desc_parts.append(f"repo={repo}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [str(name)] if name else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("CXSCA_HOST", required=True).rstrip("/")
    token = env("CXSCA_ACCESS_TOKEN", required=True)
    project_id = env("EXECUTOR_CONFIG_CXSCA_PROJECT_ID")
    min_severity = (env("EXECUTOR_CONFIG_CXSCA_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"CXSCA_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    projects = get_projects(base_url, headers, project_id)
    log(f"Found {len(projects)} project(s) (project_id={project_id or 'all'})")

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    for project in projects:
        if not isinstance(project, dict):
            continue
        pid = project.get("id") or project.get("projectId")
        if not pid:
            continue
        scan_id = get_last_scan(base_url, headers, pid)
        if not scan_id:
            log(f"No scan found for project {pid}")
            continue
        raw_vulns = get_vulnerabilities(base_url, headers, scan_id)
        vulns = [build_vulnerability(v) for v in raw_vulns if isinstance(v, dict)]
        vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
        if not vulns:
            continue
        hosts.append(build_host(project, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "checkmarx_sca",
            "command": "checkmarx_sca",
            "params": f"project_id={project_id or 'all'} min_severity={min_severity}",
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
