#!/usr/bin/env python
"""Checkmarx One (formerly Checkmarx AST) REST API importer.

Pulls SAST / SCA / KICS / API-security findings from a Checkmarx One tenant
and emits Faraday bulk-create JSON to stdout. Each Checkmarx project becomes
one Faraday host (`ip` = synthetic ``0.0.0.0`` because findings live in
source repos, not on IPs); per-project results are attached as Faraday
vulnerabilities — one per Checkmarx result identifier.

Endpoints used:
  POST /auth/realms/{tenant}/protocol/openid-connect/token  -> OAuth2
      client_credentials grant; returns an access_token used as Bearer
      auth on subsequent API calls.
  GET  /api/projects                                        -> list
      projects (paginated via ``offset`` / ``limit``).
  GET  /api/projects/last-scan                              -> per-project
      latest scan id (optionally filtered by ``branch``).
  GET  /api/results/?scan-id=...                            -> per-scan
      results (paginated). Each entry carries severity, status, state,
      engine type, description and `vulnerabilityDetails`.

Auth: OAuth2 client_credentials against
``/auth/realms/<CXONE_TENANT>/protocol/openid-connect/token`` using
CXONE_CLIENT_ID / CXONE_CLIENT_SECRET. The returned ``access_token`` is
sent as ``Authorization: Bearer <token>`` on every API call. CXONE_HOST is
the Checkmarx One regional base URL (e.g. https://ast.checkmarx.net).
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

# Checkmarx One reports severity using upper-case enum values. The platform
# emits CRITICAL on newer tenants, HIGH/MEDIUM/LOW everywhere, and INFO /
# INFORMATIONAL for hardening rules. CVSS numeric scores are used as a
# fallback when the severity bucket is absent.
CXONE_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "trace": "info",
}

# Checkmarx One result state -> Faraday status mapping. NOT_EXPLOITABLE /
# PROPOSED_NOT_EXPLOITABLE behave like risk-accepted (analyst declared
# the finding a false positive); CONFIRMED / URGENT / TO_VERIFY remain
# open; resolved / fixed states close the finding.
STATE_TO_STATUS = {
    "to_verify": "open",
    "confirmed": "open",
    "urgent": "open",
    "proposed_not_exploitable": "risk-accepted",
    "not_exploitable": "risk-accepted",
    "ignored": "risk-accepted",
}

STATUS_OPEN = ("new", "recurrent", "active", "open")
STATUS_CLOSED = ("fixed", "resolved", "closed")


def log(msg):
    print(f"{datetime.utcnow()} - CheckmarxOne: {msg}", file=sys.stderr, flush=True)


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


def severity_from_cxone(value, cvss=None):
    if value is not None:
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in CXONE_TO_FARADAY:
            return CXONE_TO_FARADAY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_cxone(status_value, state_value):
    # Checkmarx One exposes both `status` (lifecycle) and `state` (analyst
    # triage). State overrides status when the analyst has declared the
    # finding non-exploitable.
    if state_value:
        text = str(state_value).strip().lower()
        if text in STATE_TO_STATUS:
            return STATE_TO_STATUS[text]
    if status_value:
        text = str(status_value).strip().lower()
        if text in STATUS_CLOSED:
            return "closed"
        if text in STATUS_OPEN:
            return "open"
    return "open"


def get_token(base_url, tenant, client_id, client_secret):
    path = f"/auth/realms/{tenant}/protocol/openid-connect/token"
    url = f"{base_url}{path}"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    try:
        resp = requests.post(url, data=data, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"Token request failed: {exc}")
        sys.exit(1)
    if resp.status_code != 200:
        log(f"Token endpoint returned {resp.status_code}: {resp.text[:500]}")
        sys.exit(1)
    try:
        payload = resp.json()
    except ValueError:
        log("Token endpoint returned non-JSON body")
        sys.exit(1)
    token = payload.get("access_token")
    if not token:
        log("Token endpoint did not return access_token")
        sys.exit(1)
    return token


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
        log(f"Authorization rejected (403) on {path}. Check client scope / roles.")
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
        for candidate in ("results", "data", "items"):
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
    return collect(base_url, "/api/projects", headers, {}, "projects")


def get_last_scan(base_url, headers, project_id, branch):
    """Return the most recent completed scan id for a project."""
    params = {"project-ids": project_id, "limit": 1}
    if branch:
        params["branch"] = branch
    body = get_page(base_url, "/api/projects/last-scan", headers, params)
    if isinstance(body, dict):
        # /last-scan returns {<project_id>: {<scan record>}}
        record = body.get(project_id) or next(iter(body.values()), None)
        if isinstance(record, dict):
            return record.get("id") or record.get("scanId")
    # Fallback: list scans directly.
    scan_params = {"project-id": project_id, "limit": 1, "sort": "+created_at"}
    if branch:
        scan_params["branch"] = branch
    scans = collect(base_url, "/api/scans", headers, scan_params, "scans")
    for scan in scans:
        scan_id = scan.get("id") or scan.get("scanId")
        if scan_id:
            return scan_id
    return None


def get_results(base_url, headers, scan_id, min_severity):
    params = {"scan-id": scan_id}
    if min_severity and min_severity != "info":
        # Checkmarx One severity filter accepts comma-separated CSV.
        wanted = [s.upper() for s in VALID_MIN_SEVERITY if SEVERITY_ORDER[s] >= SEVERITY_ORDER[min_severity]]
        params["severity"] = ",".join(wanted)
    return collect(base_url, "/api/results/", headers, params, "results")


def collect_refs(result):
    refs = []
    details = result.get("vulnerabilityDetails") or {}
    cwe = details.get("cweId") or result.get("cweId")
    if cwe:
        refs.append({"name": f"CWE-{cwe}", "type": "other"})
    for entry in details.get("compliance") or details.get("compliances") or []:
        if isinstance(entry, str) and entry:
            refs.append({"name": entry, "type": "other"})
    for entry in result.get("references") or []:
        if isinstance(entry, str) and entry:
            refs.append({"name": entry, "type": "other"})
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("name") or entry.get("value")
            if value:
                refs.append({"name": value, "type": entry.get("type", "other") or "other"})
    return refs


def collect_cves(result):
    cves = []
    details = result.get("vulnerabilityDetails") or {}
    candidates = []
    if details.get("cveName"):
        candidates.append(details["cveName"])
    for key in ("cve", "cveId", "cveName", "cve_id"):
        value = result.get(key)
        if value:
            candidates.append(value)
    for entry in result.get("cves") or details.get("cves") or []:
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


def build_vulnerability(result):
    details = result.get("vulnerabilityDetails") or {}
    cvss = details.get("cvssScore") or details.get("cvss_score") or result.get("score") or result.get("cvss")
    severity = severity_from_cxone(result.get("severity"), cvss)
    status = status_from_cxone(result.get("status"), result.get("state"))
    engine = result.get("type") or result.get("engine") or result.get("engineType") or "result"
    raw_name = (
        result.get("vulnerabilityName")
        or result.get("queryName")
        or details.get("queryName")
        or details.get("name")
        or result.get("name")
        or result.get("title")
        or details.get("cveName")
        or f"Checkmarx One {engine} finding"
    )
    name = f"[{str(engine).upper()}] {raw_name}"
    desc_parts = []
    description = (
        result.get("description")
        or details.get("description")
        or result.get("queryDescription")
        or details.get("ruleDescription")
    )
    if description:
        desc_parts.append(str(description))
    location_parts = []
    file_name = result.get("fileName") or result.get("sourceFile") or details.get("fileName") or details.get("file")
    if file_name:
        line = result.get("line") or details.get("line") or result.get("lineNumber")
        if line:
            location_parts.append(f"{file_name}:{line}")
        else:
            location_parts.append(str(file_name))
    if location_parts:
        desc_parts.append("location: " + ", ".join(location_parts))
    package = details.get("packageIdentifier") or details.get("packageName")
    if package:
        version = details.get("packageVersion") or details.get("currentVersion")
        if version:
            desc_parts.append(f"package: {package}@{version}")
        else:
            desc_parts.append(f"package: {package}")
    fixed_in = details.get("recommendedVersion") or details.get("fixVersion") or details.get("fixedVersion")
    if fixed_in:
        desc_parts.append(f"fixed_in: {fixed_in}")
    similarity = result.get("similarityId") or result.get("similarity_id")
    if similarity:
        desc_parts.append(f"similarityId: {similarity}")
    state_raw = result.get("state")
    if state_raw:
        desc_parts.append(f"state: {state_raw}")
    return {
        "name": str(name).strip()[:200] or f"Checkmarx One {engine} finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(result.get("id") or result.get("resultId") or result.get("similarityId") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": result.get("recommendations") or details.get("recommendations") or "",
        "data": result.get("data") or details.get("data") or "",
        "refs": collect_refs(result),
        "cve": collect_cves(result),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["checkmarx_one", str(engine).lower()],
    }


def build_host(project, vulns):
    name = project.get("name") or project.get("projectName") or project.get("id", "unknown")
    repo = project.get("repoUrl") or project.get("mainBranch") or project.get("scmRepoUrl")
    desc_parts = [f"Checkmarx One project name={name}", f"id={project.get('id', 'N/A')}"]
    if repo:
        desc_parts.append(f"repo={repo}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [name] if name else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("CXONE_HOST", required=True).rstrip("/")
    tenant = env("CXONE_TENANT", required=True)
    client_id = env("CXONE_CLIENT_ID", required=True)
    client_secret = env("CXONE_CLIENT_SECRET", required=True)
    project_id = env("EXECUTOR_CONFIG_CXONE_PROJECT_ID")
    branch = env("EXECUTOR_CONFIG_CXONE_BRANCH")
    min_severity = (env("EXECUTOR_CONFIG_CXONE_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"CXONE_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"

    token = get_token(base_url, tenant, client_id, client_secret)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    projects = get_projects(base_url, headers, project_id)
    log(f"Found {len(projects)} project(s) (project_id={project_id or 'all'})")

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    for project in projects:
        pid = project.get("id") or project.get("projectId")
        if not pid:
            continue
        scan_id = get_last_scan(base_url, headers, pid, branch)
        if not scan_id:
            log(f"No scan found for project {pid} (branch={branch or 'default'})")
            continue
        raw_results = get_results(base_url, headers, scan_id, min_severity)
        vulns = [build_vulnerability(r) for r in raw_results if isinstance(r, dict)]
        vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
        if not vulns:
            continue
        hosts.append(build_host(project, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "checkmarx_one",
            "command": "checkmarx_one",
            "params": (
                f"project_id={project_id or 'all'} branch={branch or 'default'} " f"min_severity={min_severity}"
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
