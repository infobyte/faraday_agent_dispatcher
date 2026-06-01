#!/usr/bin/env python
"""VulnDB / Flashpoint vulnerability database importer.

VulnDB is a curated CVE / vulnerability database (originally Risk Based
Security, now Flashpoint). Unlike a network scanner it has no assets of its
own — instead the caller asks "what affects this CPE?" or "what affects this
vendor/product?" and gets back vulnerability records.

This executor exposes two query modes; at least one must be provided:

  EXECUTOR_CONFIG_VULNDB_CPE      -> GET /vulnerabilities?cpe=<urlencoded>
  EXECUTOR_CONFIG_VULNDB_VENDOR   -> GET /vendors/{vendor_id}/vulnerabilities
                                     (optionally narrowed by
                                      EXECUTOR_CONFIG_VULNDB_PRODUCT)

Authentication: HMAC-SHA1. VULNDB_KEY identifies the consumer, VULNDB_SECRET
signs each request. The signature is computed over

    string_to_sign = http_method + request_path + timestamp + nonce

and sent as base64 in X-Vulndb-Hmac alongside X-Vulndb-Key,
X-Vulndb-Timestamp and X-Vulndb-Nonce.

Output: Faraday bulk-create JSON with one synthetic host per queried target
(the CPE string, or "vendor[/product]"). Vulnerabilities returned by the
query are attached to that host.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_BASE_URL = "https://vulndb.cyberriskanalytics.com"
TIMEOUT = 60
DEFAULT_LIMIT = 100
MAX_PAGES = 50

SEVERITY_BUCKETS = ("info", "low", "medium", "high", "critical")


def log(msg):
    print(f"{datetime.utcnow()} - VulnDB: {msg}", file=sys.stderr, flush=True)


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
    """CVSS v3-style bucketing used by Faraday."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "info"
    if value <= 0:
        return "info"
    if value < 4.0:
        return "low"
    if value < 7.0:
        return "medium"
    if value < 9.0:
        return "high"
    return "critical"


def sign_request(method, path, key, secret):
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    string_to_sign = f"{method.upper()}{path}{timestamp}{nonce}"
    digest = hmac.new(
        secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return {
        "X-Vulndb-Key": key,
        "X-Vulndb-Hmac": base64.b64encode(digest).decode("ascii"),
        "X-Vulndb-Timestamp": timestamp,
        "X-Vulndb-Nonce": nonce,
        "Accept": "application/json",
    }


def request_page(base_url, path, params, key, secret):
    query = urlencode(params, doseq=True)
    signed_path = f"{path}?{query}" if query else path
    headers = sign_request("GET", signed_path, key, secret)
    url = f"{base_url}{signed_path}"
    resp = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("HMAC authentication rejected (401). Check VULNDB_KEY / VULNDB_SECRET.")
        sys.exit(1)
    if resp.status_code != 200:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def collect_results(base_url, path, base_params, key, secret, hard_cap):
    results = []
    page = 1
    per_page = min(hard_cap, 100) or 100
    while page <= MAX_PAGES and len(results) < hard_cap:
        params = dict(base_params)
        params["page"] = page
        params["size"] = per_page
        body = request_page(base_url, path, params, key, secret)
        if not body:
            break
        chunk = body.get("results") if isinstance(body, dict) else body
        if not chunk:
            break
        results.extend(chunk)
        total = (body or {}).get("total_entries") if isinstance(body, dict) else None
        if total is not None and len(results) >= int(total):
            break
        if len(chunk) < per_page:
            break
        page += 1
    return results[:hard_cap]


def collect_refs(vuln):
    refs = []
    for entry in vuln.get("ext_references") or vuln.get("references") or []:
        if isinstance(entry, str):
            refs.append({"name": entry, "type": "other"})
            continue
        if not isinstance(entry, dict):
            continue
        url = entry.get("value") or entry.get("url") or entry.get("name")
        if url:
            refs.append({"name": url, "type": entry.get("type", "other") or "other"})
    return refs


def collect_cves(vuln):
    cves = []
    for entry in vuln.get("cve") or vuln.get("cves") or []:
        if isinstance(entry, str):
            cves.append(entry)
        elif isinstance(entry, dict):
            value = entry.get("cve_id") or entry.get("id") or entry.get("value")
            if value:
                cves.append(value)
    for entry in vuln.get("ext_references") or []:
        if isinstance(entry, dict) and entry.get("type", "").lower() == "cve id":
            value = entry.get("value")
            if value and value not in cves:
                cves.append(value)
    return cves


def pick_cvss(vuln):
    metrics = vuln.get("cvss_metrics") or vuln.get("cvss_v3_metrics") or []
    if isinstance(metrics, list) and metrics:
        first = metrics[0]
        if isinstance(first, dict):
            score = first.get("score") or first.get("base_score")
            if score:
                return str(score)
    for key in ("cvss_score", "score", "base_score"):
        value = vuln.get(key)
        if value:
            return str(value)
    return ""


def build_vulnerability(vuln):
    cvss = pick_cvss(vuln)
    severity = severity_from_cvss(cvss) if cvss else "info"
    title = vuln.get("title") or vuln.get("name") or f"VulnDB entry {vuln.get('vulndb_id', '')}"
    description_parts = []
    if vuln.get("description"):
        description_parts.append(vuln["description"])
    if vuln.get("technical_description"):
        description_parts.append(vuln["technical_description"])
    if vuln.get("disclosure_date"):
        description_parts.append(f"Disclosure date: {vuln['disclosure_date']}")
    return {
        "name": title[:200],
        "desc": "\n\n".join(description_parts),
        "severity": severity,
        "external_id": str(vuln.get("vulndb_id") or vuln.get("id") or ""),
        "type": "Vulnerability",
        "status": "open",
        "resolution": vuln.get("solution") or vuln.get("solution_description") or "",
        "data": "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": {"base_score": cvss} if cvss else {},
        "tags": ["vulndb"],
    }


def build_host(label, vulns, extras=None):
    description_parts = [f"VulnDB query target: {label}"]
    if extras:
        description_parts.extend(extras)
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [label] if label else [],
        "mac": "",
        "description": " | ".join(description_parts),
        "vulnerabilities": vulns,
    }


def fetch_by_cpe(base_url, cpe, key, secret, limit):
    log(f"Querying /vulnerabilities?cpe={cpe}")
    return collect_results(
        base_url,
        "/api/v1/vulnerabilities",
        {"cpe": cpe},
        key,
        secret,
        limit,
    )


def resolve_vendor_id(base_url, vendor_name, key, secret):
    body = request_page(
        base_url,
        "/api/v1/vendors",
        {"name": vendor_name, "size": 25},
        key,
        secret,
    )
    if not body:
        return None
    results = body.get("results") if isinstance(body, dict) else body
    if not results:
        return None
    for entry in results:
        if not isinstance(entry, dict):
            continue
        if (entry.get("name") or "").lower() == vendor_name.lower():
            return entry.get("id") or entry.get("vendor_id")
    first = results[0]
    return first.get("id") if isinstance(first, dict) else None


def fetch_by_vendor(base_url, vendor, product, key, secret, limit):
    if vendor.isdigit():
        vendor_id = vendor
    else:
        vendor_id = resolve_vendor_id(base_url, vendor, key, secret)
        if not vendor_id:
            log(f"Vendor {vendor!r} not found via /vendors lookup")
            return []
    log(f"Querying /vendors/{vendor_id}/vulnerabilities (product={product or 'any'})")
    params = {}
    if product:
        params["product_name"] = product
    return collect_results(
        base_url,
        f"/api/v1/vendors/{quote(str(vendor_id), safe='')}/vulnerabilities",
        params,
        key,
        secret,
        limit,
    )


def main():
    started = time.time()
    key = env("VULNDB_KEY", required=True)
    secret = env("VULNDB_SECRET", required=True)
    cpe = env("EXECUTOR_CONFIG_VULNDB_CPE")
    vendor = env("EXECUTOR_CONFIG_VULNDB_VENDOR")
    product = env("EXECUTOR_CONFIG_VULNDB_PRODUCT")
    limit_raw = env("EXECUTOR_CONFIG_VULNDB_LIMIT")
    base_url = (env("VULNDB_HOST") or DEFAULT_BASE_URL).rstrip("/")

    if not cpe and not vendor:
        log("Must provide VULNDB_CPE or VULNDB_VENDOR")
        sys.exit(1)

    try:
        limit = int(limit_raw) if limit_raw else DEFAULT_LIMIT
    except ValueError:
        log(f"VULNDB_LIMIT must be an integer, got {limit_raw!r}")
        sys.exit(1)
    if limit <= 0:
        limit = DEFAULT_LIMIT

    hosts = []

    if cpe:
        cpe_vulns = fetch_by_cpe(base_url, cpe, key, secret, limit)
        log(f"CPE query returned {len(cpe_vulns)} vulnerabilities")
        vulns = [build_vulnerability(v) for v in cpe_vulns]
        if vulns:
            hosts.append(build_host(cpe, vulns, extras=["mode=cpe", f"count={len(vulns)}"]))

    if vendor:
        vendor_vulns = fetch_by_vendor(base_url, vendor, product, key, secret, limit)
        log(f"Vendor query returned {len(vendor_vulns)} vulnerabilities")
        vulns = [build_vulnerability(v) for v in vendor_vulns]
        if vulns:
            label = f"{vendor}/{product}" if product else vendor
            hosts.append(
                build_host(
                    label,
                    vulns,
                    extras=["mode=vendor", f"vendor={vendor}", f"product={product or '*'}"],
                )
            )

    params_summary = ",".join(
        part
        for part in (
            f"cpe={cpe}" if cpe else "",
            f"vendor={vendor}" if vendor else "",
            f"product={product}" if product else "",
            f"limit={limit}",
        )
        if part
    )
    output = {
        "hosts": hosts,
        "command": {
            "tool": "vulndb",
            "command": "vulndb",
            "params": params_summary,
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
