#!/usr/bin/env python
"""Oligo Security REST API importer.

Pulls runtime application detection and response (ADR) findings from the Oligo
Security platform and emits Faraday bulk-create JSON to stdout. Oligo monitors
running workloads (containers / pods / hosts) for vulnerable and actively
exploited open-source libraries — each finding ties a CVE to the asset where
the vulnerable library is loaded at runtime.

Endpoints used:
  GET /api/v1/assets                   -> list runtime assets (optionally
                                          filtered by cluster).
  GET /api/v1/runtime/vulnerabilities  -> list vulnerabilities, paginated,
                                          filtered by asset id and severity.

Each Oligo asset becomes one Faraday host with its runtime vulnerabilities
attached. Findings that cannot be resolved to a known asset are collapsed
onto a synthetic ``0.0.0.0`` host so the data is still imported.

Auth: bearer token in the ``Authorization`` header (``Bearer <OLIGO_TOKEN>``).
OLIGO_HOST is the Oligo tenant base URL (e.g. https://app.oligo.security).
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

# Oligo reports severity using the standard string buckets plus an optional
# numeric CVSS score. Strings are mapped directly; numeric scores fall back
# to the CVSS v3 ranges.
OLIGO_TO_FARADAY = {
    "informational": "info",
    "information": "info",
    "info": "info",
    "none": "info",
    "negligible": "info",
    "low": "low",
    "minor": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "important": "high",
    "critical": "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - Oligo: {msg}", file=sys.stderr, flush=True)


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


def severity_from_oligo(value, cvss=None):
    if value is not None:
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in OLIGO_TO_FARADAY:
            return OLIGO_TO_FARADAY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check OLIGO_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the token's scope.")
        return None
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
    page = 1
    while page <= MAX_PAGES:
        params = dict(base_params or {})
        params["page"] = page
        params["page_size"] = PAGE_SIZE
        body = get_page(base_url, path, headers, params)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def get_assets(base_url, headers, cluster):
    params = {}
    if cluster:
        params["cluster"] = cluster
    return collect(base_url, "/api/v1/assets", headers, params, "assets")


def get_vulnerabilities(base_url, headers, asset_id, min_severity, cluster):
    params = {"severity_gte": min_severity}
    if asset_id is not None:
        params["asset_id"] = asset_id
    if cluster:
        params["cluster"] = cluster
    return collect(base_url, "/api/v1/runtime/vulnerabilities", headers, params, "vulnerabilities")


def collect_refs(vuln):
    refs = []
    for entry in vuln.get("references") or vuln.get("links") or vuln.get("refs") or []:
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
            text = entry.strip().upper()
            if text:
                cves.append(text)
        elif isinstance(entry, dict):
            value = entry.get("name") or entry.get("id") or entry.get("value")
            if value:
                cves.append(str(value).strip().upper())
    single = vuln.get("cve_id") or vuln.get("cveId")
    if single:
        text = str(single).strip().upper()
        if text and text not in cves:
            cves.append(text)
    return cves


def build_vulnerability(vuln):
    cvss = (
        vuln.get("cvss3_score")
        or vuln.get("cvss_v3_score")
        or vuln.get("cvss_score")
        or vuln.get("cvss")
        or vuln.get("score")
    )
    severity = severity_from_oligo(
        vuln.get("severity") or vuln.get("risk") or vuln.get("risk_level") or vuln.get("level"),
        cvss,
    )
    name = (
        vuln.get("name")
        or vuln.get("title")
        or vuln.get("cve_id")
        or vuln.get("cveId")
        or f"Oligo finding {vuln.get('id', '')}"
    )
    status_raw = (vuln.get("status") or vuln.get("state") or "open").lower()
    if status_raw in ("closed", "fixed", "resolved", "patched", "mitigated"):
        status = "closed"
    elif status_raw in ("accepted", "risk_accepted", "risk-accepted", "suppressed", "ignored"):
        status = "risk-accepted"
    else:
        status = "open"
    desc_parts = []
    description = vuln.get("description") or vuln.get("summary") or vuln.get("synopsis")
    if description:
        desc_parts.append(str(description))
    library = vuln.get("library") or vuln.get("package") or vuln.get("component")
    if isinstance(library, dict):
        lib_name = library.get("name")
        lib_version = library.get("version") or library.get("installed_version")
        if lib_name:
            desc_parts.append(f"library: {lib_name}" + (f"@{lib_version}" if lib_version else ""))
        ecosystem = library.get("ecosystem") or library.get("language")
        if ecosystem:
            desc_parts.append(f"ecosystem: {ecosystem}")
    elif library:
        desc_parts.append(f"library: {library}")
    if vuln.get("loaded_at_runtime") is True or vuln.get("runtime") is True:
        desc_parts.append("runtime: loaded")
    if vuln.get("exploited") is True or vuln.get("in_use") is True:
        desc_parts.append("runtime: in use / exploited")
    fixed_in = vuln.get("fixed_version") or vuln.get("fix_version")
    if fixed_in:
        desc_parts.append(f"fixed_in: {fixed_in}")
    return {
        "name": str(name).strip()[:200] or f"Oligo finding {vuln.get('id', '')}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(vuln.get("id") or vuln.get("vulnerability_id") or vuln.get("finding_id") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": vuln.get("remediation") or vuln.get("solution") or vuln.get("fix") or "",
        "data": vuln.get("evidence") or vuln.get("proof") or vuln.get("call_stack") or "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["oligo", "runtime"],
    }


def asset_identity(asset):
    """Return a stable identity tuple for an Oligo asset."""
    return (
        asset.get("id") or asset.get("asset_id") or asset.get("uuid"),
        asset.get("name") or asset.get("hostname") or asset.get("workload"),
    )


def build_host(asset, vulns):
    ip = (
        asset.get("ip_address")
        or asset.get("ip")
        or asset.get("primary_ip")
        or asset.get("node_ip")
        or asset.get("pod_ip")
        or "0.0.0.0"
    )
    hostname = (
        asset.get("hostname")
        or asset.get("name")
        or asset.get("workload")
        or asset.get("pod_name")
        or asset.get("node_name")
    )
    os_name = asset.get("os") or asset.get("operating_system") or asset.get("os_name") or ""
    desc_parts = [f"Oligo asset id={asset.get('id', 'N/A')}"]
    cluster = asset.get("cluster") or asset.get("cluster_name")
    if cluster:
        desc_parts.append(f"cluster={cluster}")
    namespace = asset.get("namespace") or asset.get("k8s_namespace")
    if namespace:
        desc_parts.append(f"namespace={namespace}")
    workload = asset.get("workload") or asset.get("workload_name")
    if workload and workload != hostname:
        desc_parts.append(f"workload={workload}")
    image = asset.get("image") or asset.get("container_image")
    if image:
        desc_parts.append(f"image={image}")
    asset_type = asset.get("type") or asset.get("asset_type") or asset.get("kind")
    if asset_type:
        desc_parts.append(f"type={asset_type}")
    return {
        "ip": str(ip) or "0.0.0.0",
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": asset.get("mac") or asset.get("mac_address") or "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def synthetic_host(vulns, cluster):
    desc = "Oligo runtime findings without a resolvable asset"
    if cluster:
        desc = f"{desc} (cluster={cluster})"
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [],
        "mac": "",
        "description": desc,
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("OLIGO_HOST", required=True).rstrip("/")
    token = env("OLIGO_TOKEN", required=True)
    cluster = env("EXECUTOR_CONFIG_OLIGO_CLUSTER")
    min_severity = (env("EXECUTOR_CONFIG_OLIGO_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"OLIGO_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    assets = get_assets(base_url, headers, cluster)
    log(f"Found {len(assets)} assets (cluster={cluster or 'all'})")

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    orphan_vulns = []
    for asset in assets:
        asset_id = asset.get("id") or asset.get("asset_id") or asset.get("uuid")
        if asset_id is None:
            continue
        raw_vulns = get_vulnerabilities(base_url, headers, asset_id, min_severity, cluster)
        vulns = [build_vulnerability(v) for v in raw_vulns]
        vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
        if not vulns:
            continue
        hosts.append(build_host(asset, vulns))

    # Sweep up any runtime findings not tied to an asset we listed.
    cluster_vulns = get_vulnerabilities(base_url, headers, None, min_severity, cluster)
    seen_ids = set()
    for h in hosts:
        for v in h["vulnerabilities"]:
            if v["external_id"]:
                seen_ids.add(v["external_id"])
    for raw in cluster_vulns:
        if not isinstance(raw, dict):
            continue
        ext_id = str(raw.get("id") or raw.get("vulnerability_id") or raw.get("finding_id") or "")
        if ext_id and ext_id in seen_ids:
            continue
        built = build_vulnerability(raw)
        if SEVERITY_ORDER.get(built["severity"], 0) < min_threshold:
            continue
        orphan_vulns.append(built)
    if orphan_vulns:
        hosts.append(synthetic_host(orphan_vulns, cluster))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "oligo",
            "command": "oligo",
            "params": f"cluster={cluster or 'all'} min_severity={min_severity}",
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
