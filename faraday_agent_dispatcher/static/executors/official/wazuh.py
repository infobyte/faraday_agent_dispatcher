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
    "untriaged": "unclassified",
    "negligible": "info",
}


def log(msg: str):
    print(msg, file=sys.stderr, flush=True)


def env(name: str, default=None, required: bool = False):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def authenticate(base_url: str, username: str, password: str, verify_ssl: bool) -> str:
    resp = requests.post(
        f"{base_url}/security/user/authenticate",
        auth=(username, password),
        verify=verify_ssl,
        timeout=30,
    )
    if resp.status_code != 200:
        log(f"Wazuh auth failed ({resp.status_code}): {resp.text}")
        sys.exit(1)
    return resp.json()["data"]["token"]


def list_agents(base_url: str, token: str, agent_filter: str, verify_ssl: bool):
    headers = {"Authorization": f"Bearer {token}"}
    params = {"limit": 500, "status": "active"}
    if agent_filter:
        params["agents_list"] = agent_filter

    agents = []
    offset = 0
    while True:
        params["offset"] = offset
        resp = requests.get(
            f"{base_url}/agents",
            headers=headers,
            params=params,
            verify=verify_ssl,
            timeout=30,
        )
        if resp.status_code != 200:
            log(f"Wazuh /agents failed ({resp.status_code}): {resp.text}")
            sys.exit(1)
        data = resp.json()["data"]
        page = data.get("affected_items", [])
        agents.extend(page)
        if len(page) < params["limit"]:
            break
        offset += params["limit"]
    return agents


def get_agent_vulns(base_url: str, token: str, agent_id: str, min_severity: str, verify_ssl: bool):
    headers = {"Authorization": f"Bearer {token}"}
    params = {"limit": 500}
    if min_severity:
        params["severity"] = min_severity

    resp = requests.get(
        f"{base_url}/vulnerability/{agent_id}",
        headers=headers,
        params=params,
        verify=verify_ssl,
        timeout=60,
    )
    if resp.status_code == 404:
        return []
    if resp.status_code != 200:
        log(f"Wazuh /vulnerability/{agent_id} failed ({resp.status_code}): {resp.text}")
        return []
    return resp.json()["data"].get("affected_items", [])


def normalize_severity(value: str) -> str:
    return SEVERITY_MAP.get((value or "").lower(), "unclassified")


def to_vuln(item: dict) -> dict:
    cve_id = item.get("cve", "")
    return {
        "name": cve_id or item.get("title", "Wazuh finding"),
        "desc": (
            f"Package: {item.get('name', 'N/A')} {item.get('version', '')}\n"
            f"Architecture: {item.get('architecture', 'N/A')}\n"
            f"Condition: {item.get('condition', 'N/A')}\n"
            f"Detection time: {item.get('detection_time', 'N/A')}"
        ),
        "severity": normalize_severity(item.get("severity")),
        "type": "Vulnerability",
        "external_id": cve_id,
        "cve": [cve_id] if cve_id else [],
        "data": json.dumps({k: v for k, v in item.items() if k in {"cvss2_score", "cvss3_score", "status"}}),
        "refs": [{"type": "other", "name": item.get("external_references", "")}] if item.get("external_references") else [],
        "resolution": item.get("solution", ""),
    }


def main():
    started = time.time()
    base_url = env("WAZUH_URL", required=True).rstrip("/")
    username = env("WAZUH_USERNAME", required=True)
    password = env("WAZUH_PASSWORD", required=True)

    agent_filter = os.getenv("EXECUTOR_CONFIG_WAZUH_AGENT_IDS")
    min_severity = os.getenv("EXECUTOR_CONFIG_WAZUH_MIN_SEVERITY")
    verify_ssl = (os.getenv("EXECUTOR_CONFIG_WAZUH_VERIFY_SSL", "true").lower() == "true")

    token = authenticate(base_url, username, password, verify_ssl)
    agents = list_agents(base_url, token, agent_filter, verify_ssl)
    log(f"Wazuh: {len(agents)} active agents")

    hosts = []
    for agent in agents:
        ip = agent.get("ip") or agent.get("id") or "unknown"
        hostnames = [agent["name"]] if agent.get("name") else []
        vulns = [to_vuln(v) for v in get_agent_vulns(base_url, token, agent["id"], min_severity, verify_ssl)]
        hosts.append({
            "ip": ip,
            "hostnames": hostnames,
            "os": agent.get("os", {}).get("name", ""),
            "description": (
                f"Wazuh agent {agent.get('id')} ({agent.get('name', 'N/A')})\n"
                f"OS: {agent.get('os', {}).get('platform', 'N/A')} {agent.get('os', {}).get('version', '')}\n"
                f"Last keep-alive: {agent.get('lastKeepAlive', 'N/A')}"
            ),
            "vulnerabilities": vulns,
        })

    command = {
        "tool": "Wazuh",
        "command": "Wazuh",
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
