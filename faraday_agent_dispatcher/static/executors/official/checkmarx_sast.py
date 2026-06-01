#!/usr/bin/env python
"""Checkmarx SAST (CxSAST 9.x) REST API importer.

Pulls source-code findings from a Checkmarx CxSAST appliance and emits
Faraday bulk-create JSON to stdout. Each CxSAST project becomes one
Faraday host (``ip`` = synthetic ``0.0.0.0`` because SAST findings live
in source repos, not on IPs); per-scan results are attached as Faraday
vulnerabilities — one per Checkmarx result identifier.

Endpoints used:
  POST /cxrestapi/auth/identity/connect/token            -> OAuth2
      password grant (``grant_type=password``, scope=``sast_rest_api``);
      returns an access_token used as Bearer auth on subsequent calls.
  GET  /cxrestapi/projects                               -> list of
      projects (or single project via /cxrestapi/projects/{id} when
      CXSAST_PROJECT_ID is set).
  GET  /cxrestapi/sast/scans?projectId=...&last=1        -> per-project
      latest finished scan (fallback when CXSAST_SCAN_ID is unset).
  GET  /cxrestapi/sast/results?scanId=...                -> per-scan
      results (paginated via offset / limit). Each entry carries
      severity, status, state, queryName, sourceFile/line, CWE id and
      similarity id.

Auth: OAuth2 password grant against
``/cxrestapi/auth/identity/connect/token`` with the default CxSAST
``resource_owner_client`` client_id and the well-known client_secret
shipped with the appliance. The returned ``access_token`` is sent as
``Authorization: Bearer <token>`` on every API call. CXSAST_HOST is
the CxSAST manager base URL (e.g. https://cx.corp.example.com).
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

# Default CxSAST OAuth client. CxSAST ships with a fixed resource-owner
# client (``resource_owner_client``) and a well-known secret published
# in Checkmarx documentation; the password grant uses these together
# with the human user's username/password.
CXSAST_CLIENT_ID = "resource_owner_client"
CXSAST_CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"
CXSAST_SCOPE = "sast_rest_api"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# CxSAST reports severity as either a string ("High"/"Medium"/"Low"/
# "Information") or as a 0-4 numeric severity index (0=info, 1=low,
# 2=medium, 3=high, 4=critical). Both shapes are normalised here.
CXSAST_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "information": "info",
    "informational": "info",
    "none": "info",
}

CXSAST_NUMERIC_SEVERITY = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# CxSAST result `state` (analyst triage) -> Faraday status. NOT_EXPLOITABLE
# is the analyst-declared false-positive state and maps to risk-accepted.
# TO_VERIFY / CONFIRMED / URGENT remain open. CxSAST also surfaces
# numeric state codes (0=TO_VERIFY, 1=NOT_EXPLOITABLE, 2=CONFIRMED,
# 3=URGENT, 4=PROPOSED_NOT_EXPLOITABLE).
STATE_STRING_TO_STATUS = {
    "to_verify": "open",
    "to verify": "open",
    "confirmed": "open",
    "urgent": "open",
    "not_exploitable": "risk-accepted",
    "not exploitable": "risk-accepted",
    "proposed_not_exploitable": "risk-accepted",
    "proposed not exploitable": "risk-accepted",
}

STATE_NUMERIC_TO_STATUS = {
    0: "open",
    1: "risk-accepted",
    2: "open",
    3: "open",
    4: "risk-accepted",
}

# CxSAST result `status` (lifecycle) -> Faraday status.
STATUS_OPEN = ("new", "recurrent", "active", "open")
STATUS_CLOSED = ("fixed", "resolved", "closed")


def log(msg):
    print(f"{datetime.utcnow()} - CheckmarxSAST: {msg}", file=sys.stderr, flush=True)


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


def severity_from_cxsast(value, cvss=None):
    if value is not None:
        if isinstance(value, bool):
            # bool is a subclass of int — guard against True/False sneaking in.
            pass
        elif isinstance(value, int):
            if value in CXSAST_NUMERIC_SEVERITY:
                return CXSAST_NUMERIC_SEVERITY[value]
        elif isinstance(value, float):
            return severity_from_cvss(value)
        else:
            text = str(value).strip().lower()
            if text in CXSAST_STRING_SEVERITY:
                return CXSAST_STRING_SEVERITY[text]
            try:
                numeric = int(text)
                if numeric in CXSAST_NUMERIC_SEVERITY:
                    return CXSAST_NUMERIC_SEVERITY[numeric]
            except ValueError:
                pass
            try:
                return severity_from_cvss(float(text))
            except ValueError:
                pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_cxsast(status_value, state_value):
    if state_value is not None:
        if isinstance(state_value, bool):
            pass
        elif isinstance(state_value, int):
            if state_value in STATE_NUMERIC_TO_STATUS:
                return STATE_NUMERIC_TO_STATUS[state_value]
        else:
            text = str(state_value).strip().lower()
            if text in STATE_STRING_TO_STATUS:
                return STATE_STRING_TO_STATUS[text]
            try:
                numeric = int(text)
                if numeric in STATE_NUMERIC_TO_STATUS:
                    return STATE_NUMERIC_TO_STATUS[numeric]
            except ValueError:
                pass
    if status_value is not None:
        text = str(status_value).strip().lower()
        if text in STATUS_CLOSED:
            return "closed"
        if text in STATUS_OPEN:
            return "open"
    return "open"


def get_token(base_url, user, password):
    path = "/cxrestapi/auth/identity/connect/token"
    url = f"{base_url}{path}"
    data = {
        "grant_type": "password",
        "username": user,
        "password": password,
        "scope": CXSAST_SCOPE,
        "client_id": CXSAST_CLIENT_ID,
        "client_secret": CXSAST_CLIENT_SECRET,
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
        log(f"Authorization rejected (403) on {path}. Check user role / scope.")
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
        for candidate in ("results", "data", "items", "value"):
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
        body = get_page(base_url, f"/cxrestapi/projects/{project_id}", headers, {})
        if isinstance(body, dict):
            return [body]
        return []
    body = get_page(base_url, "/cxrestapi/projects", headers, {})
    if isinstance(body, list):
        return body
    return extract_list(body, "projects")


def get_last_scan(base_url, headers, project_id):
    """Return the most recent finished scan id for a project."""
    body = get_page(
        base_url,
        "/cxrestapi/sast/scans",
        headers,
        {"projectId": project_id, "last": 1, "scanStatus": "Finished"},
    )
    scans = body if isinstance(body, list) else extract_list(body, "scans")
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        scan_id = scan.get("id") or scan.get("scanId")
        if scan_id:
            return scan_id
    # Fallback without the scanStatus filter (some CxSAST builds reject it).
    body = get_page(base_url, "/cxrestapi/sast/scans", headers, {"projectId": project_id, "last": 1})
    scans = body if isinstance(body, list) else extract_list(body, "scans")
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        scan_id = scan.get("id") or scan.get("scanId")
        if scan_id:
            return scan_id
    return None


def get_results(base_url, headers, scan_id):
    return collect(base_url, "/cxrestapi/sast/results", headers, {"scanId": scan_id}, "results")


def collect_refs(result):
    refs = []
    cwe = result.get("cweId") or result.get("cwe") or (result.get("vulnerabilityDetails") or {}).get("cweId")
    if cwe:
        refs.append({"name": f"CWE-{cwe}", "type": "other"})
    query_id = result.get("queryId") or result.get("queryVersionId")
    if query_id:
        refs.append({"name": f"CxQuery-{query_id}", "type": "other"})
    for entry in result.get("compliance") or result.get("compliances") or []:
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


def build_vulnerability(result):
    details = result.get("vulnerabilityDetails") or {}
    cvss = details.get("cvssScore") or details.get("cvss_score") or result.get("cvssScore") or result.get("cvss")
    severity = severity_from_cxsast(result.get("severity"), cvss)
    status = status_from_cxsast(result.get("status"), result.get("state"))
    query_name = (
        result.get("queryName")
        or result.get("query_name")
        or details.get("queryName")
        or result.get("name")
        or "CxSAST finding"
    )
    name = f"[SAST] {query_name}"
    desc_parts = []
    description = (
        result.get("description")
        or result.get("queryDescription")
        or details.get("description")
        or details.get("queryDescription")
    )
    if description:
        desc_parts.append(str(description))
    file_name = (
        result.get("sourceFile")
        or result.get("fileName")
        or result.get("file")
        or details.get("fileName")
        or details.get("file")
    )
    if file_name:
        line = result.get("line") or result.get("lineNumber") or details.get("line")
        if line:
            desc_parts.append(f"location: {file_name}:{line}")
        else:
            desc_parts.append(f"location: {file_name}")
    sink_file = result.get("sinkFile") or result.get("destFile") or details.get("sinkFile")
    if sink_file:
        sink_line = result.get("sinkLine") or details.get("sinkLine")
        if sink_line:
            desc_parts.append(f"sink: {sink_file}:{sink_line}")
        else:
            desc_parts.append(f"sink: {sink_file}")
    similarity = result.get("similarityId") or result.get("similarity_id")
    if similarity:
        desc_parts.append(f"similarityId: {similarity}")
    state_raw = result.get("state")
    if state_raw is not None and state_raw != "":
        desc_parts.append(f"state: {state_raw}")
    assignee = result.get("assignedTo") or result.get("assignee")
    if assignee:
        desc_parts.append(f"assignee: {assignee}")
    return {
        "name": str(name).strip()[:200] or "CxSAST finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(
            result.get("id") or result.get("resultId") or result.get("pathId") or result.get("similarityId") or ""
        ),
        "type": "Vulnerability",
        "status": status,
        "resolution": result.get("recommendations") or details.get("recommendations") or "",
        "data": result.get("data") or details.get("data") or "",
        "refs": collect_refs(result),
        "cve": [],
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["checkmarx_sast", "sast"],
    }


def build_host(project, vulns):
    name = project.get("name") or project.get("projectName") or project.get("id", "unknown")
    repo = (
        project.get("repoUrl") or project.get("repositoryUrl") or (project.get("sourceSettingsLink") or {}).get("uri")
    )
    desc_parts = [f"Checkmarx SAST project name={name}", f"id={project.get('id', 'N/A')}"]
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
    host = env("CXSAST_HOST", required=True).rstrip("/")
    user = env("CXSAST_USER", required=True)
    password = env("CXSAST_PASSWORD", required=True)
    project_id = env("EXECUTOR_CONFIG_CXSAST_PROJECT_ID")
    scan_id_arg = env("EXECUTOR_CONFIG_CXSAST_SCAN_ID")
    min_severity = (env("EXECUTOR_CONFIG_CXSAST_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"CXSAST_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"

    token = get_token(base_url, user, password)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "cxOriginUrl": base_url,
    }

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []

    if scan_id_arg:
        # Direct scan import — resolve the owning project for host naming.
        scan_body = get_page(base_url, f"/cxrestapi/sast/scans/{scan_id_arg}", headers, {})
        project = {}
        if isinstance(scan_body, dict):
            scan_project = scan_body.get("project") or {}
            if isinstance(scan_project, dict):
                project = scan_project
            if not project.get("id") and scan_body.get("projectId"):
                project["id"] = scan_body.get("projectId")
            if not project.get("name") and scan_body.get("projectName"):
                project["name"] = scan_body.get("projectName")
        if not project:
            project = {"id": "unknown", "name": f"scan-{scan_id_arg}"}
        raw_results = get_results(base_url, headers, scan_id_arg)
        vulns = [build_vulnerability(r) for r in raw_results if isinstance(r, dict)]
        vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
        if vulns:
            hosts.append(build_host(project, vulns))
    else:
        projects = get_projects(base_url, headers, project_id)
        log(f"Found {len(projects)} project(s) (project_id={project_id or 'all'})")
        for project in projects:
            if not isinstance(project, dict):
                continue
            pid = project.get("id") or project.get("projectId")
            if not pid:
                continue
            scan_id = get_last_scan(base_url, headers, pid)
            if not scan_id:
                log(f"No finished scan found for project {pid}")
                continue
            raw_results = get_results(base_url, headers, scan_id)
            vulns = [build_vulnerability(r) for r in raw_results if isinstance(r, dict)]
            vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
            if not vulns:
                continue
            hosts.append(build_host(project, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "checkmarx_sast",
            "command": "checkmarx_sast",
            "params": (
                f"project_id={project_id or 'all'} scan_id={scan_id_arg or 'last'} " f"min_severity={min_severity}"
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
