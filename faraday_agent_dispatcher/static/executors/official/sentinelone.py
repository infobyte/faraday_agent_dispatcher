#!/usr/bin/env python3
import os
import sys
import json
import socket
import time
import urllib3
from datetime import datetime, timezone

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "med",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def log(msg: str):
    print(msg, file=sys.stderr, flush=True)


def env(name: str, required: bool = False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def get_threats(base_url: str, token: str, account_id: str, since: str, verify_ssl: bool):
    headers = {"Authorization": f"ApiToken {token}"}
    params = {"limit": 1000, "sortBy": "createdAt", "sortOrder": "desc"}
    if account_id:
        params["accountIds"] = account_id
    if since:
        params["createdAt__gte"] = since

    threats = []
    cursor = None
    while True:
        if cursor:
            params["cursor"] = cursor
        resp = requests.get(
            f"{base_url}/web/api/v2.1/threats",
            headers=headers,
            params=params,
            verify=verify_ssl,
            timeout=30,
        )
        if resp.status_code != 200:
            log(f"SentinelOne /threats failed ({resp.status_code}): {resp.text}")
            return threats
        body = resp.json()
        threats.extend(body.get("data", []))
        pagination = body.get("pagination") or {}
        cursor = pagination.get("nextCursor")
        if not cursor:
            break
    return threats


def normalize_severity(value: str) -> str:
    return SEVERITY_MAP.get((value or "").lower(), "unclassified")


def to_host_payload(threats):
    by_agent = {}
    for t in threats:
        agent = t.get("agentRealtimeInfo", {}) or {}
        agent_id = agent.get("agentId") or t.get("id", "unknown")
        if agent_id not in by_agent:
            by_agent[agent_id] = {
                "ip": agent.get("agentIp") or agent_id,
                "hostnames": [agent.get("agentComputerName")] if agent.get("agentComputerName") else [],
                "os": agent.get("agentOsName") or "",
                "description": (
                    f"SentinelOne agent {agent_id}\n"
                    f"OS: {agent.get('agentOsName', 'N/A')} {agent.get('agentOsRevision', '')}\n"
                    f"Domain: {agent.get('agentDomain', 'N/A')}"
                ),
                "vulnerabilities": [],
            }
        ti = t.get("threatInfo", {}) or {}
        agent_data = by_agent[agent_id]
        agent_data["vulnerabilities"].append(
            {
                "name": ti.get("threatName", t.get("id", "SentinelOne threat"))[:80],
                "desc": (
                    f"Classification: {ti.get('classification', 'N/A')}\n"
                    f"Classification source: {ti.get('classificationSource', 'N/A')}\n"
                    f"Detection type: {ti.get('detectionType', 'N/A')}\n"
                    f"Mitigation status: {ti.get('mitigationStatus', 'N/A')}\n"
                    f"Confidence: {ti.get('confidenceLevel', 'N/A')}\n"
                    f"File path: {ti.get('filePath', 'N/A')}\n"
                    f"SHA1: {ti.get('sha1', 'N/A')}"
                ),
                "severity": normalize_severity(ti.get("confidenceLevel")),
                "type": "Vulnerability",
                "external_id": t.get("id", ""),
                "resolution": ti.get("mitigationStatus", ""),
                "refs": (
                    [{"type": "other", "name": ti.get("originatorProcess", "")}] if ti.get("originatorProcess") else []
                ),
            }
        )
    return list(by_agent.values())


def main():
    started = time.time()
    base_url = env("SENTINELONE_URL", required=True).rstrip("/")
    token = env("SENTINELONE_TOKEN", required=True)
    account_id = env("SENTINELONE_ACCOUNT_ID")
    since = os.getenv("EXECUTOR_CONFIG_SENTINELONE_SINCE")
    verify_ssl = os.getenv("EXECUTOR_CONFIG_SENTINELONE_VERIFY_SSL", "true").lower() == "true"

    threats = get_threats(base_url, token, account_id, since, verify_ssl)
    log(f"SentinelOne: {len(threats)} threats fetched")

    hosts = to_host_payload(threats)

    command = {
        "tool": "SentinelOne",
        "command": "SentinelOne",
        "params": base_url,
        "user": os.environ.get("USER", ""),
        "hostname": socket.gethostname(),
        "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
        "duration": int((time.time() - started) * 1000),
        "import_source": "report",
    }
    print(json.dumps({"hosts": hosts, "command": command}))


if __name__ == "__main__":
    main()
