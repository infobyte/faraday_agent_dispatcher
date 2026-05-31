#!/usr/bin/env python
"""Tripwire IP360 vulnerability scanner import executor.

Pulls the most recent IP360 scan results and emits Faraday bulk-create JSON
to stdout. One Faraday host per scanned device, with vulnerabilities attached.

Endpoints used:
  GET /api/2.0/vulnscans                -> list scans (optionally filtered by scope)
  GET /api/2.0/devices/{device_id}/vulns -> per-device vulnerability list

Auth: HTTP Basic (IP360_USER + IP360_API_KEY).
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(f"{datetime.utcnow()} - TripwireIP360: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_score(score):
    """Map IP360 severity score to Faraday severity bucket.

    IP360 severity is a numeric score (typically 0-100000); the standard
    bucketing used by the Tripwire console is: 0=info, <=2500=low,
    <=10000=medium, <=25000=high, >25000=critical.
    """
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "info"
    if value <= 0:
        return "info"
    if value <= 2500:
        return "low"
    if value <= 10000:
        return "medium"
    if value <= 25000:
        return "high"
    return "critical"


def get_scans(base_url, auth, scope_id):
    params = {}
    if scope_id:
        params["scope"] = scope_id
    resp = requests.get(
        f"{base_url}/api/2.0/vulnscans",
        params=params,
        auth=auth,
        verify=False,
        timeout=TIMEOUT,
    )
    if resp.status_code != 200:
        log(f"/vulnscans failed ({resp.status_code}): {resp.text}")
        sys.exit(1)
    body = resp.json()
    scans = body.get("results") if isinstance(body, dict) else body
    return scans or []


def get_devices(base_url, auth, scan_id):
    resp = requests.get(
        f"{base_url}/api/2.0/vulnscans/{scan_id}/devices",
        auth=auth,
        verify=False,
        timeout=TIMEOUT,
    )
    if resp.status_code != 200:
        log(f"/vulnscans/{scan_id}/devices failed ({resp.status_code}): {resp.text}")
        return []
    body = resp.json()
    return (body.get("results") if isinstance(body, dict) else body) or []


def get_device_vulns(base_url, auth, device_id):
    resp = requests.get(
        f"{base_url}/api/2.0/devices/{device_id}/vulns",
        auth=auth,
        verify=False,
        timeout=TIMEOUT,
    )
    if resp.status_code != 200:
        log(f"/devices/{device_id}/vulns failed ({resp.status_code}): {resp.text}")
        return []
    body = resp.json()
    return (body.get("results") if isinstance(body, dict) else body) or []


def pick_latest_scan(scans):
    if not scans:
        return None

    def started_at(scan):
        for key in ("started", "start_time", "scan_start", "created"):
            v = scan.get(key)
            if v:
                return v
        return ""

    return sorted(scans, key=started_at, reverse=True)[0]


def build_vulnerability(vuln, min_bucket):
    severity = severity_from_score(vuln.get("severity") or vuln.get("score"))
    if SEVERITY_ORDER[severity] < SEVERITY_ORDER[min_bucket]:
        return None
    cves = vuln.get("cves") or vuln.get("cve") or []
    if isinstance(cves, str):
        cves = [cves]
    refs = []
    for url in vuln.get("references") or vuln.get("refs") or []:
        ref = url if isinstance(url, str) else url.get("url") or url.get("name")
        if ref:
            refs.append({"name": ref, "type": "other"})
    return {
        "name": (vuln.get("name") or vuln.get("title") or f"IP360 vuln {vuln.get('id', '')}")[:200],
        "desc": vuln.get("description") or vuln.get("desc") or "",
        "severity": severity,
        "external_id": str(vuln.get("id") or vuln.get("vuln_id") or ""),
        "type": "Vulnerability",
        "status": "open",
        "resolution": vuln.get("solution") or vuln.get("remediation") or "",
        "data": "",
        "refs": refs,
        "cve": [c for c in cves if isinstance(c, str)],
        "cvss3": {"base_score": str(vuln["cvss_score"])} if vuln.get("cvss_score") else {},
        "tags": ["tripwire-ip360"],
    }


def build_host(device, vulns):
    ip = device.get("ip") or device.get("address") or "0.0.0.0"
    hostname = device.get("hostname") or device.get("dns_name") or device.get("name")
    os_name = device.get("os") or device.get("os_name") or ""
    desc_parts = [f"IP360 device id={device.get('id', 'N/A')}"]
    if device.get("scope"):
        desc_parts.append(f"scope={device['scope']}")
    if device.get("last_seen"):
        desc_parts.append(f"last_seen={device['last_seen']}")
    return {
        "ip": ip,
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": device.get("mac") or "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("IP360_HOST", required=True).rstrip("/")
    user = env("IP360_USER", required=True)
    api_key = env("IP360_API_KEY", required=True)
    scope_id = env("EXECUTOR_CONFIG_IP360_SCOPE_ID")
    min_severity = (env("EXECUTOR_CONFIG_IP360_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"IP360_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    auth = HTTPBasicAuth(user, api_key)

    scans = get_scans(base_url, auth, scope_id)
    log(f"Found {len(scans)} scans (scope={scope_id or 'all'})")
    scan = pick_latest_scan(scans)
    if not scan:
        log("No scans available for the requested scope")
        print(json.dumps({"hosts": []}))
        return
    scan_id = scan.get("id") or scan.get("scan_id")
    log(f"Using scan id={scan_id}")

    hosts = []
    for device in get_devices(base_url, auth, scan_id):
        device_id = device.get("id") or device.get("device_id")
        if not device_id:
            continue
        raw_vulns = get_device_vulns(base_url, auth, device_id)
        vulns = [v for v in (build_vulnerability(rv, min_severity) for rv in raw_vulns) if v]
        if not vulns:
            continue
        hosts.append(build_host(device, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "tripwire_ip360",
            "command": f"tripwire_ip360 scan={scan_id}",
            "params": f"scope={scope_id or 'all'} min_severity={min_severity}",
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
