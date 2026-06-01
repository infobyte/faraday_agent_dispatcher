#!/usr/bin/env python
"""Dynatrace Application Security REST API importer.

Pulls security problems (vulnerabilities) and HOST entities from a Dynatrace
tenant and emits Faraday bulk-create JSON to stdout. One Faraday host is
emitted per Dynatrace HOST entity referenced by an in-scope security problem,
with the problems attached as vulnerabilities. Problems whose affected
entities do not include any HOST (e.g. only PROCESS_GROUP_INSTANCE or
KUBERNETES_CLUSTER references) are attached to a synthetic ``0.0.0.0`` host
so the data is still imported.

Endpoints used:
  GET /api/v2/securityProblems       -> list security problems (filtered by
                                        riskLevel / timeframe)
  GET /api/v2/securityProblems/{id}  -> per-problem details (affectedEntities,
                                        vulnerableComponents, references)
  GET /api/v2/entities               -> entitySelector=type(HOST), gives us
                                        ip / hostname / os for the host
                                        entities referenced by the problems.

Auth: ``Authorization: Api-Token <DT_API_TOKEN>`` with the
``entities.read`` and ``securityProblems.read`` token scopes.
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
PAGE_SIZE = 500
MAX_PAGES = 200

VALID_RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

DT_TO_FARADAY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
    "UNKNOWN": "info",
}


def log(msg):
    print(f"{datetime.utcnow()} - DynatraceSecurity: {msg}", file=sys.stderr, flush=True)


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
    return "critical"


def severity_from_dt(risk_level, risk_score=None):
    if risk_level:
        key = str(risk_level).strip().upper()
        if key in DT_TO_FARADAY:
            return DT_TO_FARADAY[key]
    if risk_score is not None:
        return severity_from_cvss(risk_score)
    return "info"


def get(base_url, path, headers, params=None):
    url = f"{base_url}{path}"
    resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check DT_API_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log("Authorization rejected (403). DT_API_TOKEN needs entities.read,securityProblems.read scopes.")
        sys.exit(1)
    if resp.status_code == 404:
        log(f"GET {path} returned 404 (not found)")
        return None
    if resp.status_code != 200:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def paginate(base_url, path, headers, params, list_key):
    """Iterate through Dynatrace v2 pagination.

    The v2 API returns ``nextPageKey`` in the body. The next page is fetched
    by sending ONLY ``nextPageKey`` as the query parameter — any other
    filters must be omitted from subsequent requests.
    """
    items = []
    current_params = dict(params or {})
    for _ in range(MAX_PAGES):
        body = get(base_url, path, headers, current_params)
        if not isinstance(body, dict):
            break
        chunk = body.get(list_key) or []
        if chunk:
            items.extend(chunk)
        next_key = body.get("nextPageKey")
        if not next_key:
            break
        current_params = {"nextPageKey": next_key}
    return items


def fetch_host_entities(base_url, headers):
    params = {
        "entitySelector": "type(HOST)",
        "pageSize": PAGE_SIZE,
        "fields": "+properties.ipAddress,+properties.osType,+properties.osVersion,+properties.networkZone",
    }
    entities = paginate(base_url, "/api/v2/entities", headers, params, "entities")
    log(f"Fetched {len(entities)} HOST entities")
    return entities


def host_index(entities):
    index = {}
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_id = entity.get("entityId")
        if not entity_id:
            continue
        index[entity_id] = entity
    return index


def fetch_security_problems(base_url, headers, risk_levels, timeframe):
    params = {"pageSize": PAGE_SIZE}
    if risk_levels:
        levels = ",".join(f'"{level}"' for level in risk_levels)
        params["securityProblemSelector"] = f"riskLevel({levels})"
    if timeframe:
        params["from"] = timeframe
    problems = paginate(base_url, "/api/v2/securityProblems", headers, params, "securityProblems")
    log(f"Fetched {len(problems)} security problems")
    return problems


DETAIL_FIELDS = (
    "+affectedEntities,+vulnerableComponents,+relatedEntities,"
    "+description,+riskAssessment,+codeLevelVulnerabilityDetails"
)


def fetch_security_problem_detail(base_url, headers, problem_id):
    params = {"fields": DETAIL_FIELDS}
    return get(base_url, f"/api/v2/securityProblems/{problem_id}", headers, params)


def collect_refs(problem):
    refs = []
    url = problem.get("url")
    if url:
        refs.append({"name": url, "type": "other"})
    for entry in problem.get("references") or []:
        if isinstance(entry, str):
            refs.append({"name": entry, "type": "other"})
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("value") or entry.get("name")
            if value:
                refs.append({"name": value, "type": entry.get("type", "other") or "other"})
    for component in problem.get("vulnerableComponents") or []:
        if isinstance(component, dict):
            name = component.get("displayName") or component.get("id")
            if name:
                refs.append({"name": f"vulnerableComponent: {name}", "type": "other"})
    return refs


def collect_cves(problem):
    cves = []
    for entry in problem.get("cveIds") or problem.get("cves") or []:
        if not entry:
            continue
        text = str(entry).strip().upper()
        if text.startswith("CVE-"):
            cves.append(text)
    return cves


def build_vulnerability(problem):
    risk = problem.get("riskAssessment") or {}
    risk_score = risk.get("riskScore") or risk.get("baseRiskScore")
    severity = severity_from_dt(risk.get("riskLevel") or problem.get("riskLevel"), risk_score)
    cvss = risk.get("baseRiskScore") or risk.get("riskScore")
    name = (
        problem.get("title")
        or problem.get("displayId")
        or f"Dynatrace security problem {problem.get('securityProblemId', '')}"
    )
    status_raw = (problem.get("status") or "OPEN").upper()
    if status_raw in ("RESOLVED", "CLOSED"):
        status = "closed"
    elif status_raw == "MUTED":
        status = "risk-accepted"
    else:
        status = "open"
    desc_parts = []
    if problem.get("description"):
        desc_parts.append(str(problem["description"]))
    if problem.get("packageName"):
        desc_parts.append(f"package: {problem['packageName']}")
    if problem.get("technology"):
        desc_parts.append(f"technology: {problem['technology']}")
    if problem.get("vulnerabilityType"):
        desc_parts.append(f"vulnerability_type: {problem['vulnerabilityType']}")
    if risk.get("vector"):
        desc_parts.append(f"vector: {risk['vector']}")
    if risk.get("exploit"):
        desc_parts.append(f"exploit: {risk['exploit']}")
    if risk.get("dataAssets"):
        desc_parts.append(f"data_assets: {risk['dataAssets']}")
    return {
        "name": str(name).strip()[:200] or f"Dynatrace security problem {problem.get('securityProblemId', '')}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(problem.get("securityProblemId") or problem.get("displayId") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": problem.get("remediation") or problem.get("remediationDescription") or "",
        "data": problem.get("displayId") or "",
        "refs": collect_refs(problem),
        "cve": collect_cves(problem),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["dynatrace_security"],
    }


def host_ip(entity):
    properties = entity.get("properties") or {}
    addresses = properties.get("ipAddress") or properties.get("ipAddresses") or []
    if isinstance(addresses, list) and addresses:
        return str(addresses[0])
    if isinstance(addresses, str) and addresses:
        return addresses
    return None


def build_host(entity, vulns):
    properties = entity.get("properties") if isinstance(entity.get("properties"), dict) else {}
    ip = host_ip(entity) or "0.0.0.0"
    hostname = entity.get("displayName") or properties.get("hostName") or properties.get("detectedName") or ""
    os_type = properties.get("osType") or ""
    os_version = properties.get("osVersion") or ""
    os_name = " ".join(filter(None, [os_type, os_version]))
    desc_parts = [f"Dynatrace entityId={entity.get('entityId', 'N/A')}"]
    zone = properties.get("networkZone")
    if zone:
        desc_parts.append(f"network_zone={zone}")
    return {
        "ip": ip,
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def synthetic_host(vulns):
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [],
        "mac": "",
        "description": "Dynatrace security problems without HOST affected entities",
        "vulnerabilities": vulns,
    }


def collect_host_entity_ids(problem):
    """Extract host entityIds the problem is affecting.

    Dynatrace surfaces affected hosts in two shapes:
      * ``affectedEntities`` — list of either entity id strings or dicts with
        an ``id`` / ``entityId`` field. Only HOST-prefixed ids are kept.
      * ``relatedEntities.hosts`` — list of dicts with ``id``.
    """
    ids = []
    for entry in problem.get("affectedEntities") or []:
        candidate = None
        if isinstance(entry, str):
            candidate = entry
        elif isinstance(entry, dict):
            candidate = entry.get("id") or entry.get("entityId")
        if candidate and str(candidate).startswith("HOST-"):
            ids.append(candidate)
    related = problem.get("relatedEntities") or {}
    for entry in related.get("hosts") or []:
        if isinstance(entry, dict):
            candidate = entry.get("id") or entry.get("entityId")
            if candidate:
                ids.append(candidate)
        elif isinstance(entry, str) and entry.startswith("HOST-"):
            ids.append(entry)
    seen = []
    for entity_id in ids:
        if entity_id not in seen:
            seen.append(entity_id)
    return seen


def parse_risk_levels(raw):
    if not raw:
        return []
    tokens = [token.strip().upper() for token in raw.split(",") if token.strip()]
    invalid = [token for token in tokens if token not in VALID_RISK_LEVELS]
    if invalid:
        log(f"DT_RISK_LEVEL has invalid values {invalid}; valid: {list(VALID_RISK_LEVELS)}")
        sys.exit(1)
    return tokens


def main():
    started = time.time()
    host = env("DT_HOST", required=True).rstrip("/")
    token = env("DT_API_TOKEN", required=True)
    risk_levels = parse_risk_levels(env("EXECUTOR_CONFIG_DT_RISK_LEVEL"))
    timeframe = env("EXECUTOR_CONFIG_DT_TIMEFRAME") or "now-30d"

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    headers = {
        "Authorization": f"Api-Token {token}",
        "Accept": "application/json",
    }

    entities = fetch_host_entities(base_url, headers)
    entities_by_id = host_index(entities)

    problems = fetch_security_problems(base_url, headers, risk_levels, timeframe)

    by_host = {}
    orphan_vulns = []
    for problem in problems:
        if not isinstance(problem, dict):
            continue
        problem_id = problem.get("securityProblemId") or problem.get("displayId")
        if not problem_id:
            continue
        detail = fetch_security_problem_detail(base_url, headers, problem_id) or problem
        host_ids = collect_host_entity_ids(detail)
        vuln = build_vulnerability(detail)
        if not host_ids:
            orphan_vulns.append(vuln)
            continue
        for entity_id in host_ids:
            by_host.setdefault(entity_id, []).append(vuln)

    hosts = []
    for entity_id, vulns in by_host.items():
        entity = entities_by_id.get(entity_id) or {"entityId": entity_id, "displayName": entity_id, "properties": {}}
        hosts.append(build_host(entity, vulns))
    if orphan_vulns:
        hosts.append(synthetic_host(orphan_vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "dynatrace_security",
            "command": "dynatrace_security",
            "params": f"risk_level={','.join(risk_levels) or 'all'} timeframe={timeframe}",
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
