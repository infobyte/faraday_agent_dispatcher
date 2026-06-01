#!/usr/bin/env python
"""Outpost24 REST API importer (AppSec + NetSec).

Pulls vulnerability findings from an Outpost24 appliance / cloud tenant and
emits Faraday bulk-create JSON to stdout. Covers both the Network Security
(Outscan NX / HIAB) and Application Security (SWAT) scopes — both expose the
same v2 REST surface under ``/api/2.0/``.

Endpoints used:
  GET /api/2.0/scans             -> list scans (filtered by OUTPOST24_SCAN_ID
                                    when set, otherwise every visible scan).
  GET /api/2.0/scans/{id}        -> per-scan detail (asset / target / scope
                                    enrichment).
  GET /api/2.0/vulnerabilities   -> list vulnerabilities, paginated, filtered
                                    by ``scan_id`` (and ``scope`` for the
                                    AppSec / NetSec split when set).

Each vulnerability is grouped by its target (host / asset / URL) so one
Faraday host is emitted per affected target with the findings attached.
Vulnerabilities that do not carry a resolvable target are attached to a
synthetic ``0.0.0.0`` host so the data is still imported.

Auth: HTTP Basic with OUTPOST24_USER / OUTPOST24_PASSWORD. OUTPOST24_HOST is
the appliance base URL (e.g. https://outscan.outpost24.com or the HIAB
hostname).
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 200
MAX_PAGES = 200

VALID_SCOPES = ("appsec", "netsec")

# Outpost24 reports severity as both strings and as CVSS-derived numeric
# risk levels. Strings are mapped directly; numeric scores fall back to the
# CVSS v3 ranges.
OUTPOST24_TO_FARADAY = {
    "informational": "info",
    "information": "info",
    "info": "info",
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
    print(f"{datetime.utcnow()} - Outpost24: {msg}", file=sys.stderr, flush=True)


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


def severity_from_outpost24(value, cvss=None):
    if value is not None:
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in OUTPOST24_TO_FARADAY:
            return OUTPOST24_TO_FARADAY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def get_json(base_url, path, auth, params=None):
    url = f"{base_url}{path}"
    resp = requests.get(url, auth=auth, params=params, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check OUTPOST24_USER / OUTPOST24_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the account's scope permissions.")
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


def paginate(base_url, path, auth, base_params, *list_keys):
    results = []
    page = 1
    while page <= MAX_PAGES:
        params = dict(base_params or {})
        params["page"] = page
        params["per_page"] = PAGE_SIZE
        body = get_json(base_url, path, auth, params=params)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def list_scans(base_url, auth, scope, scan_id):
    if scan_id:
        body = get_json(base_url, f"/api/2.0/scans/{scan_id}", auth)
        if body is None:
            return []
        if isinstance(body, dict):
            return [body]
        if isinstance(body, list):
            return body
        return []
    params = {}
    if scope:
        params["scope"] = scope
    return paginate(base_url, "/api/2.0/scans", auth, params, "scans")


def list_vulnerabilities(base_url, auth, scope, scan_id):
    params = {}
    if scan_id:
        params["scan_id"] = scan_id
    if scope:
        params["scope"] = scope
    return paginate(base_url, "/api/2.0/vulnerabilities", auth, params, "vulnerabilities")


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
            text = entry.strip().upper()
            if text:
                cves.append(text)
        elif isinstance(entry, dict):
            value = entry.get("name") or entry.get("id") or entry.get("value")
            if value:
                cves.append(str(value).strip().upper())
    return cves


def build_vulnerability(vuln, scope):
    cvss = (
        vuln.get("cvss3_score")
        or vuln.get("cvss_v3_score")
        or vuln.get("cvss_score")
        or vuln.get("cvss")
        or vuln.get("score")
    )
    severity = severity_from_outpost24(
        vuln.get("severity") or vuln.get("risk") or vuln.get("risk_level") or vuln.get("level"),
        cvss,
    )
    name = (
        vuln.get("name")
        or vuln.get("title")
        or vuln.get("check_name")
        or vuln.get("plugin_name")
        or f"Outpost24 finding {vuln.get('id', '')}"
    )
    status_raw = (vuln.get("status") or vuln.get("state") or "open").lower()
    if status_raw in ("closed", "fixed", "resolved", "patched", "mitigated"):
        status = "closed"
    elif status_raw in ("accepted", "risk_accepted", "risk-accepted", "false_positive", "false-positive"):
        status = "risk-accepted"
    else:
        status = "open"
    desc_parts = []
    description = vuln.get("description") or vuln.get("summary") or vuln.get("synopsis")
    if description:
        desc_parts.append(str(description))
    if vuln.get("port") not in (None, ""):
        desc_parts.append(f"port: {vuln.get('port')}")
    if vuln.get("protocol"):
        desc_parts.append(f"protocol: {vuln.get('protocol')}")
    if vuln.get("url"):
        desc_parts.append(f"url: {vuln.get('url')}")
    if vuln.get("path"):
        desc_parts.append(f"path: {vuln.get('path')}")
    if vuln.get("parameter"):
        desc_parts.append(f"parameter: {vuln.get('parameter')}")
    return {
        "name": str(name).strip()[:200] or f"Outpost24 finding {vuln.get('id', '')}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(vuln.get("id") or vuln.get("vulnerability_id") or vuln.get("finding_id") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": vuln.get("solution") or vuln.get("remediation") or vuln.get("fix") or "",
        "data": vuln.get("evidence") or vuln.get("proof") or vuln.get("plugin_output") or "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["outpost24", f"outpost24_{scope}"] if scope else ["outpost24"],
    }


def target_key(vuln):
    """Stable per-target key used to group vulnerabilities into hosts.

    AppSec findings carry a URL (so we collapse on its hostname); NetSec
    findings carry an IP / hostname directly.
    """
    url = vuln.get("url") or vuln.get("target_url")
    if url:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or url
        return ("host", host.lower())
    ip = vuln.get("ip") or vuln.get("ip_address") or vuln.get("address") or vuln.get("target_ip")
    if ip:
        return ("ip", str(ip))
    hostname = vuln.get("hostname") or vuln.get("host") or vuln.get("target_hostname") or vuln.get("target")
    if hostname:
        return ("host", str(hostname).lower())
    asset_id = vuln.get("asset_id") or vuln.get("target_id")
    if asset_id is not None:
        return ("asset", str(asset_id))
    return None


def build_host(key, sample_vuln, vulns, scope, scan_meta):
    kind, value = key
    ip = "0.0.0.0"
    hostname = ""
    if kind == "ip":
        ip = value
        hostname = sample_vuln.get("hostname") or sample_vuln.get("host") or sample_vuln.get("target_hostname") or ""
    elif kind == "host":
        hostname = value
        ip = (
            sample_vuln.get("ip")
            or sample_vuln.get("ip_address")
            or sample_vuln.get("address")
            or sample_vuln.get("target_ip")
            or "0.0.0.0"
        )
    elif kind == "asset":
        hostname = (
            sample_vuln.get("hostname") or sample_vuln.get("host") or sample_vuln.get("target_hostname") or value
        )
        ip = (
            sample_vuln.get("ip")
            or sample_vuln.get("ip_address")
            or sample_vuln.get("address")
            or sample_vuln.get("target_ip")
            or "0.0.0.0"
        )
    os_name = sample_vuln.get("os") or sample_vuln.get("operating_system") or ""
    desc_parts = []
    if scope:
        desc_parts.append(f"scope={scope}")
    scan_id = scan_meta.get("scan_id") if scan_meta else None
    if scan_id is not None:
        desc_parts.append(f"scan_id={scan_id}")
    scan_name = scan_meta.get("scan_name") if scan_meta else None
    if scan_name:
        desc_parts.append(f"scan={scan_name}")
    return {
        "ip": str(ip) or "0.0.0.0",
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": sample_vuln.get("mac") or sample_vuln.get("mac_address") or "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def synthetic_host(vulns, scope):
    desc = "Outpost24 findings without a resolvable target"
    if scope:
        desc = f"{desc} (scope={scope})"
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [],
        "mac": "",
        "description": desc,
        "vulnerabilities": vulns,
    }


def parse_scope(raw):
    if not raw:
        return None
    scope = raw.strip().lower()
    if scope not in VALID_SCOPES:
        log(f"OUTPOST24_SCOPE must be one of {list(VALID_SCOPES)}, got {raw!r}")
        sys.exit(1)
    return scope


def scan_meta_from(scan):
    if not isinstance(scan, dict):
        return {}
    return {
        "scan_id": scan.get("id") or scan.get("scan_id") or scan.get("uuid"),
        "scan_name": scan.get("name") or scan.get("scan_name") or scan.get("title"),
    }


def main():
    started = time.time()
    host = env("OUTPOST24_HOST", required=True).rstrip("/")
    user = env("OUTPOST24_USER", required=True)
    password = env("OUTPOST24_PASSWORD", required=True)
    scope = parse_scope(env("EXECUTOR_CONFIG_OUTPOST24_SCOPE"))
    scan_id_arg = env("EXECUTOR_CONFIG_OUTPOST24_SCAN_ID")

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    auth = (user, password)

    scans = list_scans(base_url, auth, scope, scan_id_arg)
    if not scans and scan_id_arg:
        log(f"Scan {scan_id_arg} not found or not accessible")
        scans = [{"id": scan_id_arg}]
    log(f"Processing {len(scans)} scans (scope={scope or 'all'})")

    by_target = {}
    orphan_vulns = []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        meta = scan_meta_from(scan)
        sid = meta.get("scan_id")
        if sid is None:
            continue
        vulns = list_vulnerabilities(base_url, auth, scope, sid)
        for raw in vulns:
            if not isinstance(raw, dict):
                continue
            built = build_vulnerability(raw, scope)
            key = target_key(raw)
            if key is None:
                orphan_vulns.append(built)
                continue
            bucket = by_target.setdefault(key, {"sample": raw, "vulns": [], "scan_meta": meta})
            bucket["vulns"].append(built)

    hosts = []
    for key, bucket in by_target.items():
        hosts.append(build_host(key, bucket["sample"], bucket["vulns"], scope, bucket["scan_meta"]))
    if orphan_vulns:
        hosts.append(synthetic_host(orphan_vulns, scope))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "outpost24",
            "command": "outpost24",
            "params": f"scope={scope or 'all'} scan_id={scan_id_arg or 'all'}",
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
