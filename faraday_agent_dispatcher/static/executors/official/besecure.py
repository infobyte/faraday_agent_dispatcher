#!/usr/bin/env python
"""Beyond Security beSecure (AVDS) REST API importer.

Pulls vulnerability scan results from a Beyond Security beSecure appliance
and emits Faraday bulk-create JSON to stdout. One Faraday host is emitted
per scanned target, with that target's vulnerabilities attached.

Endpoints used:
  GET /api/scan/list          -> list scans
  GET /api/scan/report/{id}   -> per-scan report (hosts + vulnerabilities)

Auth: HTTP Basic with BESECURE_USER / BESECURE_PASSWORD; BESECURE_HOST is
the appliance base URL.
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

TIMEOUT = 120

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# beSecure uses both string severities ("High", "Medium", ...) and numeric
# risk levels (1-5). Numeric scores fall back to the CVSS v3 ranges.
BESECURE_TO_FARADAY = {
    "informational": "info",
    "info": "info",
    "none": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}

NUMERIC_TO_FARADAY = {
    "1": "info",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - beSecure: {msg}", file=sys.stderr, flush=True)


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


def severity_from_besecure(value):
    if value is None:
        return "info"
    if isinstance(value, (int, float)):
        as_str = str(int(value)) if float(value).is_integer() else str(value)
        if as_str in NUMERIC_TO_FARADAY:
            return NUMERIC_TO_FARADAY[as_str]
        return severity_from_cvss(value)
    text = str(value).strip().lower()
    if text in BESECURE_TO_FARADAY:
        return BESECURE_TO_FARADAY[text]
    if text in NUMERIC_TO_FARADAY:
        return NUMERIC_TO_FARADAY[text]
    try:
        return severity_from_cvss(float(text))
    except ValueError:
        return "info"


def get_json(base_url, path, auth):
    url = f"{base_url}{path}"
    resp = requests.get(url, auth=auth, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check BESECURE_USER / BESECURE_PASSWORD.")
        sys.exit(1)
    if resp.status_code != 200:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def extract_list(body, key=None):
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        if key and isinstance(body.get(key), list):
            return body[key]
        for candidate in ("scans", "data", "results", "items", "report", "hosts", "vulnerabilities"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def list_scans(base_url, auth):
    body = get_json(base_url, "/api/scan/list", auth)
    return extract_list(body, key="scans")


def get_scan_report(base_url, auth, scan_id):
    body = get_json(base_url, f"/api/scan/report/{scan_id}", auth)
    if body is None:
        return None, []
    if isinstance(body, dict):
        report = body.get("report") if isinstance(body.get("report"), dict) else body
        hosts = extract_list(report, key="hosts")
        return report, hosts
    if isinstance(body, list):
        return {}, body
    return {}, []


def collect_refs(vuln):
    refs = []
    for entry in vuln.get("references") or vuln.get("refs") or vuln.get("links") or []:
        if isinstance(entry, str):
            refs.append({"name": entry, "type": "other"})
            continue
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or entry.get("href") or entry.get("value") or entry.get("name")
        if url:
            refs.append({"name": url, "type": entry.get("type", "other") or "other"})
    return refs


def collect_cves(vuln):
    cves = []
    for entry in vuln.get("cves") or vuln.get("cve") or vuln.get("cve_ids") or []:
        if isinstance(entry, str):
            cves.append(entry)
        elif isinstance(entry, dict):
            value = entry.get("name") or entry.get("id") or entry.get("value")
            if value:
                cves.append(value)
    return cves


def build_vulnerability(vuln):
    severity = severity_from_besecure(
        vuln.get("severity") or vuln.get("risk") or vuln.get("risk_level") or vuln.get("level")
    )
    cvss = vuln.get("cvss_score") or vuln.get("cvss") or vuln.get("cvss_v3_score") or vuln.get("score")
    name = (
        vuln.get("name")
        or vuln.get("title")
        or vuln.get("vuln_name")
        or vuln.get("plugin_name")
        or f"beSecure finding {vuln.get('id', '')}"
    )
    status_raw = (vuln.get("status") or "open").lower()
    status = "closed" if status_raw in ("closed", "fixed", "resolved", "patched", "mitigated") else "open"
    return {
        "name": str(name)[:200],
        "desc": vuln.get("description") or vuln.get("summary") or vuln.get("synopsis") or "",
        "severity": severity,
        "external_id": str(vuln.get("id") or vuln.get("plugin_id") or vuln.get("vuln_id") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": vuln.get("solution") or vuln.get("remediation") or vuln.get("fix") or "",
        "data": vuln.get("evidence") or vuln.get("proof") or vuln.get("plugin_output") or "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["besecure"],
    }


def build_host(host_entry, scan_meta):
    ip = (
        host_entry.get("ip")
        or host_entry.get("ip_address")
        or host_entry.get("address")
        or host_entry.get("host")
        or "0.0.0.0"
    )
    hostname = host_entry.get("hostname") or host_entry.get("name") or host_entry.get("dns_name")
    os_name = host_entry.get("os") or host_entry.get("operating_system") or host_entry.get("os_name") or ""

    raw_vulns = (
        host_entry.get("vulnerabilities")
        or host_entry.get("findings")
        or host_entry.get("vulns")
        or host_entry.get("issues")
        or []
    )
    vulns = [build_vulnerability(v) for v in raw_vulns if isinstance(v, dict)]

    desc_parts = []
    scan_id = scan_meta.get("scan_id") if scan_meta else None
    scan_name = scan_meta.get("scan_name") if scan_meta else None
    if scan_id is not None:
        desc_parts.append(f"scan_id={scan_id}")
    if scan_name:
        desc_parts.append(f"scan={scan_name}")
    if host_entry.get("mac") or host_entry.get("mac_address"):
        desc_parts.append(f"mac={host_entry.get('mac') or host_entry.get('mac_address')}")

    return {
        "ip": ip,
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": host_entry.get("mac") or host_entry.get("mac_address") or "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("BESECURE_HOST", required=True).rstrip("/")
    user = env("BESECURE_USER", required=True)
    password = env("BESECURE_PASSWORD", required=True)
    scan_id_arg = env("EXECUTOR_CONFIG_BESECURE_SCAN_ID")

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    auth = (user, password)

    if scan_id_arg:
        scan_ids = [scan_id_arg]
    else:
        scans = list_scans(base_url, auth)
        scan_ids = []
        for scan in scans:
            if not isinstance(scan, dict):
                continue
            sid = scan.get("id") or scan.get("scan_id") or scan.get("uuid")
            if sid is not None:
                scan_ids.append(str(sid))
        log(f"Found {len(scan_ids)} scans (BESECURE_SCAN_ID unset, importing all)")

    hosts = []
    for sid in scan_ids:
        report, host_entries = get_scan_report(base_url, auth, sid)
        scan_meta = {
            "scan_id": sid,
            "scan_name": (report or {}).get("name") or (report or {}).get("scan_name"),
        }
        for host_entry in host_entries:
            if not isinstance(host_entry, dict):
                continue
            built = build_host(host_entry, scan_meta)
            if built["vulnerabilities"]:
                hosts.append(built)

    output = {
        "hosts": hosts,
        "command": {
            "tool": "besecure",
            "command": "besecure",
            "params": f"scan_id={scan_id_arg or 'all'}",
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
