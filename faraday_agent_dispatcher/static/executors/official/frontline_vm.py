#!/usr/bin/env python
"""Digital Defense Frontline VM REST API importer.

Pulls assets and vulnerabilities from the Frontline.Cloud platform and emits
Faraday bulk-create JSON to stdout. One Faraday host per Frontline asset, with
the asset's vulnerabilities attached.

Endpoints used:
  GET /api/v2/assets           -> list assets (optionally filtered by
                                  business group)
  GET /api/v2/vulnerabilities  -> list vulnerabilities (optionally filtered
                                  by asset id and severity)

Auth: token in the ``Authorization`` header as ``Token <FRONTLINE_TOKEN>``.
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

# Frontline VM exposes severity as a string ("Critical", "High", ...) plus a
# numeric CVSS score. We accept both and bucket numeric scores using the
# standard CVSS v3 ranges (0=info, 0.1-3.9=low, 4-6.9=medium, 7-8.9=high,
# 9-10=critical).
FRONTLINE_TO_FARADAY = {
    "informational": "info",
    "info": "info",
    "trivial": "info",
    "none": "info",
    "low": "low",
    "minor": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "important": "high",
    "critical": "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - FrontlineVM: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_frontline(value):
    if value is None:
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    text = str(value).strip().lower()
    if text in FRONTLINE_TO_FARADAY:
        return FRONTLINE_TO_FARADAY[text]
    try:
        return severity_from_cvss(float(text))
    except ValueError:
        return "info"


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


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check FRONTLINE_TOKEN.")
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


def get_assets(base_url, headers, business_group):
    params = {}
    if business_group:
        params["business_group"] = business_group
    return collect(base_url, "/api/v2/assets", headers, params)


def get_vulnerabilities(base_url, headers, asset_id, min_severity):
    params = {"severity_gte": min_severity}
    if asset_id is not None:
        params["asset_id"] = asset_id
    return collect(base_url, "/api/v2/vulnerabilities", headers, params)


def collect_refs(vuln):
    refs = []
    for entry in vuln.get("references") or vuln.get("links") or []:
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
    for entry in vuln.get("cves") or vuln.get("cve") or []:
        if isinstance(entry, str):
            cves.append(entry)
        elif isinstance(entry, dict):
            value = entry.get("name") or entry.get("id") or entry.get("value")
            if value:
                cves.append(value)
    return cves


def build_vulnerability(vuln):
    severity = severity_from_frontline(vuln.get("severity") or vuln.get("risk_level"))
    cvss = vuln.get("cvss_score") or vuln.get("cvss_v3_score") or vuln.get("cvss")
    name = vuln.get("name") or vuln.get("title") or vuln.get("vuln_name") or f"Frontline finding {vuln.get('id', '')}"
    status_raw = (vuln.get("status") or "open").lower()
    status = "closed" if status_raw in ("closed", "fixed", "resolved", "mitigated") else "open"
    return {
        "name": str(name)[:200],
        "desc": vuln.get("description") or vuln.get("summary") or "",
        "severity": severity,
        "external_id": str(vuln.get("id") or vuln.get("vulnerability_id") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": vuln.get("remediation") or vuln.get("solution") or "",
        "data": vuln.get("evidence") or vuln.get("proof") or "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["frontline_vm"],
    }


def build_host(asset, vulns):
    ip = asset.get("ip_address") or asset.get("ip") or asset.get("primary_ip") or "0.0.0.0"
    hostname = asset.get("hostname") or asset.get("name") or asset.get("dns_name")
    os_name = asset.get("os") or asset.get("operating_system") or asset.get("os_name") or ""
    desc_parts = [f"Frontline asset id={asset.get('id', 'N/A')}"]
    if asset.get("business_group") or asset.get("group"):
        desc_parts.append(f"business_group={asset.get('business_group') or asset.get('group')}")
    if asset.get("asset_type") or asset.get("type"):
        desc_parts.append(f"type={asset.get('asset_type') or asset.get('type')}")
    if asset.get("tags"):
        tags = asset.get("tags") or []
        if isinstance(tags, list):
            tags = ",".join(str(t) for t in tags)
        desc_parts.append(f"tags={tags}")
    return {
        "ip": ip,
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": asset.get("mac") or asset.get("mac_address") or "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("FRONTLINE_HOST", required=True).rstrip("/")
    token = env("FRONTLINE_TOKEN", required=True)
    business_group = env("EXECUTOR_CONFIG_FRONTLINE_BUSINESS_GROUP")
    min_severity = (env("EXECUTOR_CONFIG_FRONTLINE_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"FRONTLINE_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    headers = {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
    }

    assets = get_assets(base_url, headers, business_group)
    log(f"Found {len(assets)} assets (business_group={business_group or 'all'})")

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    for asset in assets:
        asset_id = asset.get("id") or asset.get("asset_id")
        if asset_id is None:
            continue
        raw_vulns = get_vulnerabilities(base_url, headers, asset_id, min_severity)
        vulns = [build_vulnerability(v) for v in raw_vulns]
        vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
        if not vulns:
            continue
        hosts.append(build_host(asset, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "frontline_vm",
            "command": "frontline_vm",
            "params": f"business_group={business_group or 'all'} min_severity={min_severity}",
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
