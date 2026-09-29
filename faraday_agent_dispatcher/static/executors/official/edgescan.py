#!/usr/bin/env python
"""Edgescan REST API importer.

Pulls assets and vulnerabilities from the Edgescan platform and emits Faraday
bulk-create JSON to stdout. One Faraday host per Edgescan asset, with the
asset's vulnerabilities attached.

Endpoints used:
  GET /api/v1/assets           -> list assets (optionally filtered by tag)
  GET /api/v1/vulnerabilities  -> list vulnerabilities (optionally filtered
                                  by asset id and severity)

Auth: token in the ``X-API-TOKEN`` header (EDGESCAN_TOKEN).
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

DEFAULT_BASE_URL = "https://live.edgescan.com"
TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Edgescan reports severity on a 1-5 integer scale. 1=Trivial, 2=Minor,
# 3=Moderate, 4=High, 5=Critical.
EDGESCAN_TO_FARADAY = {
    0: "info",
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

MIN_SEVERITY_TO_EDGESCAN = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def log(msg):
    print(f"{datetime.utcnow()} - Edgescan: {msg}", file=sys.stderr, flush=True)


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


def severity_from_edgescan(value):
    try:
        bucket = int(float(value))
    except (TypeError, ValueError):
        return "info"
    return EDGESCAN_TO_FARADAY.get(bucket, "info")


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check EDGESCAN_TOKEN.")
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
        params["per_page"] = PAGE_SIZE
        body = get_page(base_url, path, headers, params)
        if body is None:
            break
        chunk = body
        if isinstance(body, dict):
            chunk = body.get(path.rsplit("/", 1)[-1]) or body.get("results") or body.get("data") or []
        if not chunk:
            break
        results.extend(chunk)
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def get_assets(base_url, headers, asset_tag):
    params = {}
    if asset_tag:
        params["c[asset_tags]"] = asset_tag
    return collect(base_url, "/api/v1/assets", headers, params)


def get_vulnerabilities(base_url, headers, asset_id, min_edgescan_severity):
    params = {"c[severity_gte]": min_edgescan_severity}
    if asset_id is not None:
        params["c[asset_id]"] = asset_id
    return collect(base_url, "/api/v1/vulnerabilities", headers, params)


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
    severity = severity_from_edgescan(vuln.get("severity"))
    cvss = vuln.get("cvss_score") or vuln.get("cvss_v3_score") or vuln.get("cvss")
    return {
        "name": (vuln.get("name") or vuln.get("title") or f"Edgescan finding {vuln.get('id', '')}")[:200],
        "desc": vuln.get("description") or vuln.get("definition") or "",
        "severity": severity,
        "external_id": str(vuln.get("id") or vuln.get("vulnerability_id") or ""),
        "type": "Vulnerability",
        "status": "open" if (vuln.get("status") or "open").lower() not in ("closed", "fixed") else "closed",
        "resolution": vuln.get("remediation") or vuln.get("solution") or "",
        "data": vuln.get("evidence") or "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["edgescan"],
    }


def build_host(asset, vulns):
    ip = asset.get("location") or asset.get("ip_address") or asset.get("ip") or "0.0.0.0"
    hostname = asset.get("name") or asset.get("hostname")
    os_name = asset.get("os") or asset.get("operating_system") or ""
    desc_parts = [f"Edgescan asset id={asset.get('id', 'N/A')}"]
    if asset.get("type"):
        desc_parts.append(f"type={asset['type']}")
    if asset.get("asset_tags") or asset.get("tags"):
        tags = asset.get("asset_tags") or asset.get("tags") or []
        if isinstance(tags, list):
            tags = ",".join(str(t) for t in tags)
        desc_parts.append(f"tags={tags}")
    return {
        "ip": ip,
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": asset.get("mac") or "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = (env("EDGESCAN_HOST") or DEFAULT_BASE_URL).rstrip("/")
    token = env("EDGESCAN_TOKEN", required=True)
    asset_tag = env("EXECUTOR_CONFIG_EDGESCAN_ASSET_TAG")
    min_severity = (env("EXECUTOR_CONFIG_EDGESCAN_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"EDGESCAN_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    headers = {
        "X-API-TOKEN": token,
        "Accept": "application/json",
    }
    min_edgescan_severity = MIN_SEVERITY_TO_EDGESCAN[min_severity]

    assets = get_assets(base_url, headers, asset_tag)
    log(f"Found {len(assets)} assets (tag={asset_tag or 'all'})")

    hosts = []
    for asset in assets:
        asset_id = asset.get("id") or asset.get("asset_id")
        if asset_id is None:
            continue
        raw_vulns = get_vulnerabilities(base_url, headers, asset_id, min_edgescan_severity)
        vulns = [build_vulnerability(v) for v in raw_vulns]
        if not vulns:
            continue
        hosts.append(build_host(asset, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "edgescan",
            "command": "edgescan",
            "params": f"asset_tag={asset_tag or 'all'} min_severity={min_severity}",
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
