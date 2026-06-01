#!/usr/bin/env python
"""Eclypsium firmware security platform import executor.

Pulls devices and firmware findings from Eclypsium and emits Faraday
bulk-create JSON to stdout. One Faraday host per Eclypsium device, with
firmware-level findings attached. ``host.os`` is set to the firmware
vendor/model (e.g. ``Dell Inc. / OptiPlex 7080``) rather than the OS, so
firmware-targeted vulnerabilities land on a recognisable asset record.

Endpoints used:
  GET /api/v1/devices   -> list devices (optionally filtered by device group)
  GET /api/v1/findings  -> list findings (filtered by device id)

Auth: bearer token in the ``Authorization`` header (ECLYPSIUM_TOKEN).
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

SEVERITY_MAP = {
    "informational": "info",
    "info": "info",
    "none": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - Eclypsium: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_eclypsium(value):
    if value is None:
        return "info"
    return SEVERITY_MAP.get(str(value).strip().lower(), "info")


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check ECLYPSIUM_TOKEN.")
        sys.exit(1)
    if resp.status_code != 200:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def collect(base_url, path, headers, base_params):
    results = []
    page = 1
    while page <= MAX_PAGES:
        params = dict(base_params)
        params["page"] = page
        params["page_size"] = PAGE_SIZE
        body = get_page(base_url, path, headers, params)
        if body is None:
            break
        chunk = body
        if isinstance(body, dict):
            chunk = (
                body.get("results") or body.get("data") or body.get("items") or body.get(path.rsplit("/", 1)[-1]) or []
            )
        if not chunk:
            break
        results.extend(chunk)
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def get_devices(base_url, headers, device_group):
    params = {}
    if device_group:
        params["group"] = device_group
    return collect(base_url, "/api/v1/devices", headers, params)


def get_findings(base_url, headers, device_id):
    params = {"device_id": device_id}
    return collect(base_url, "/api/v1/findings", headers, params)


def collect_refs(finding):
    refs = []
    for entry in finding.get("references") or finding.get("links") or []:
        if isinstance(entry, str):
            refs.append({"name": entry, "type": "other"})
            continue
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or entry.get("href") or entry.get("value") or entry.get("name")
        if url:
            refs.append({"name": url, "type": entry.get("type", "other") or "other"})
    return refs


def collect_cves(finding):
    cves = []
    for entry in finding.get("cves") or finding.get("cve") or []:
        if isinstance(entry, str):
            cves.append(entry)
        elif isinstance(entry, dict):
            value = entry.get("name") or entry.get("id") or entry.get("value")
            if value:
                cves.append(value)
    return cves


def firmware_os(device):
    """Return a 'vendor / model' string built from the device's firmware metadata.

    Falls back to higher-level device fields when firmware blocks are missing
    so the host still lands with something recognisable in Faraday.
    """
    firmware = device.get("firmware") or device.get("bios") or {}
    vendor = (
        firmware.get("vendor")
        or firmware.get("manufacturer")
        or device.get("manufacturer")
        or device.get("vendor")
        or ""
    )
    model = firmware.get("model") or firmware.get("product") or device.get("model") or device.get("product_name") or ""
    version = firmware.get("version") or device.get("firmware_version") or ""
    parts = [p for p in (str(vendor).strip(), str(model).strip()) if p]
    os_label = " / ".join(parts)
    if version:
        os_label = f"{os_label} ({version})" if os_label else f"firmware {version}"
    return os_label


def build_vulnerability(finding):
    severity = severity_from_eclypsium(finding.get("severity") or finding.get("risk_level") or finding.get("risk"))
    cvss = finding.get("cvss_score") or finding.get("cvss_v3_score") or finding.get("cvss")
    name = (
        finding.get("name")
        or finding.get("title")
        or finding.get("rule_name")
        or f"Eclypsium finding {finding.get('id', '')}"
    )
    status_raw = (finding.get("status") or "open").lower()
    status = "closed" if status_raw in ("closed", "fixed", "resolved", "mitigated") else "open"
    return {
        "name": str(name)[:200],
        "desc": finding.get("description") or finding.get("summary") or "",
        "severity": severity,
        "external_id": str(finding.get("id") or finding.get("finding_id") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": finding.get("remediation") or finding.get("recommendation") or "",
        "data": finding.get("evidence") or finding.get("details") or "",
        "refs": collect_refs(finding),
        "cve": collect_cves(finding),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["eclypsium", "firmware"],
    }


def build_host(device, vulns):
    ip = device.get("ip_address") or device.get("ip") or device.get("last_known_ip") or "0.0.0.0"
    hostname = device.get("hostname") or device.get("name") or device.get("device_name")
    os_label = firmware_os(device)
    desc_parts = [f"Eclypsium device id={device.get('id', 'N/A')}"]
    if device.get("group") or device.get("device_group"):
        desc_parts.append(f"group={device.get('group') or device.get('device_group')}")
    if device.get("serial_number") or device.get("serial"):
        desc_parts.append(f"serial={device.get('serial_number') or device.get('serial')}")
    if device.get("os") or device.get("operating_system"):
        desc_parts.append(f"os={device.get('os') or device.get('operating_system')}")
    return {
        "ip": ip,
        "os": os_label,
        "hostnames": [hostname] if hostname else [],
        "mac": device.get("mac") or device.get("mac_address") or "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("ECLYPSIUM_HOST", required=True).rstrip("/")
    token = env("ECLYPSIUM_TOKEN", required=True)
    device_group = env("EXECUTOR_CONFIG_ECLYPSIUM_DEVICE_GROUP")

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    devices = get_devices(base_url, headers, device_group)
    log(f"Found {len(devices)} devices (group={device_group or 'all'})")

    hosts = []
    for device in devices:
        device_id = device.get("id") or device.get("device_id")
        if device_id is None:
            continue
        raw_findings = get_findings(base_url, headers, device_id)
        vulns = [build_vulnerability(f) for f in raw_findings]
        if not vulns:
            continue
        hosts.append(build_host(device, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "eclypsium",
            "command": "eclypsium",
            "params": f"device_group={device_group or 'all'}",
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
