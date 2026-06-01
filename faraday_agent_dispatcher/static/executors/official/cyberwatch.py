#!/usr/bin/env python
"""Cyberwatch REST API importer.

Pulls assets and vulnerabilities from a Cyberwatch master (Vulnerability
Manager / Compliance Manager) and emits Faraday bulk-create JSON to stdout.
One Faraday host is emitted per Cyberwatch asset, with the asset's
vulnerabilities attached.

Endpoints used:
  GET /api/v3/assets           -> list assets (optionally filtered by group)
  GET /api/v3/vulnerabilities  -> list vulnerabilities (optionally filtered
                                  by asset id and severity)

Auth: HTTP Signatures draft (cbw-api-toolbox compatible). Each request is
signed with HMAC-SHA256 over the string

    (request-target): <method> <path>\\n
    host: <host>\\n
    date: <rfc1123 date>\\n
    accept: application/json

The base64 signature is sent in the ``Authorization`` header as

    Signature keyId="<API_KEY>",algorithm="hmac-sha256",
              headers="(request-target) host date accept",
              signature="<sig>"

CYBERWATCH_API_KEY identifies the consumer; CYBERWATCH_SECRET_KEY signs the
request.
"""

import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from email.utils import formatdate
from urllib.parse import urlencode, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Cyberwatch exposes a level string ("level_critical", "level_high", ...) and
# may also surface a raw CVSS score. We accept both and bucket numeric scores
# using the standard CVSS v3 ranges.
CYBERWATCH_TO_FARADAY = {
    "level_critical": "critical",
    "level_high": "high",
    "level_medium": "medium",
    "level_low": "low",
    "level_negligible": "info",
    "level_unknown": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "negligible": "info",
    "info": "info",
    "informational": "info",
    "none": "info",
    "unknown": "info",
}


def log(msg):
    print(f"{datetime.utcnow()} - Cyberwatch: {msg}", file=sys.stderr, flush=True)


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


def severity_from_cyberwatch(value):
    if value is None:
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    text = str(value).strip().lower()
    if text in CYBERWATCH_TO_FARADAY:
        return CYBERWATCH_TO_FARADAY[text]
    try:
        return severity_from_cvss(float(text))
    except ValueError:
        return "info"


def sign_request(method, path, host, api_key, secret_key):
    date_header = formatdate(timeval=None, localtime=False, usegmt=True)
    signing_string = (
        f"(request-target): {method.lower()} {path}\n"
        f"host: {host}\n"
        f"date: {date_header}\n"
        f"accept: application/json"
    )
    digest = hmac.new(
        secret_key.encode("utf-8"),
        signing_string.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    signature = base64.b64encode(digest).decode("ascii")
    authorization = (
        f'Signature keyId="{api_key}",'
        f'algorithm="hmac-sha256",'
        f'headers="(request-target) host date accept",'
        f'signature="{signature}"'
    )
    return {
        "Authorization": authorization,
        "Date": date_header,
        "Accept": "application/json",
        "Host": host,
    }


def request_path(path, params):
    if not params:
        return path
    query = urlencode(sorted(params.items()), doseq=True)
    return f"{path}?{query}"


def get_page(base_url, host_header, path, api_key, secret_key, params):
    full_path = request_path(path, params)
    headers = sign_request("GET", full_path, host_header, api_key, secret_key)
    url = f"{base_url}{full_path}"
    resp = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check CYBERWATCH_API_KEY / CYBERWATCH_SECRET_KEY.")
        sys.exit(1)
    if resp.status_code != 200:
        log(f"GET {full_path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {full_path} returned non-JSON body")
        return None


def collect(base_url, host_header, path, api_key, secret_key, base_params):
    results = []
    page = 1
    while page <= MAX_PAGES:
        params = dict(base_params)
        params["page"] = page
        params["per_page"] = PAGE_SIZE
        body = get_page(base_url, host_header, path, api_key, secret_key, params)
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


def get_assets(base_url, host_header, api_key, secret_key, group):
    params = {}
    if group:
        params["group"] = group
    return collect(base_url, host_header, "/api/v3/assets", api_key, secret_key, params)


def get_vulnerabilities(base_url, host_header, api_key, secret_key, asset_id, min_severity):
    params = {}
    if asset_id is not None:
        params["asset_id"] = asset_id
    if min_severity:
        params["min_severity"] = min_severity
    return collect(
        base_url,
        host_header,
        "/api/v3/vulnerabilities",
        api_key,
        secret_key,
        params,
    )


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
    for entry in vuln.get("cve_announcements") or vuln.get("cves") or vuln.get("cve") or []:
        if isinstance(entry, str):
            cves.append(entry)
        elif isinstance(entry, dict):
            value = entry.get("cve_code") or entry.get("name") or entry.get("id") or entry.get("value")
            if value:
                cves.append(value)
    return cves


def build_vulnerability(vuln):
    raw_severity = vuln.get("level") or vuln.get("severity") or vuln.get("risk_level")
    severity = severity_from_cyberwatch(raw_severity)
    cvss = vuln.get("score") or vuln.get("cvss_v3_score") or vuln.get("cvss_score") or vuln.get("cvss")
    name = vuln.get("name") or vuln.get("title") or vuln.get("cve_code") or f"Cyberwatch finding {vuln.get('id', '')}"
    status_raw = (vuln.get("status") or "open").lower()
    status = "closed" if status_raw in ("closed", "fixed", "resolved", "patched", "ignored") else "open"
    return {
        "name": str(name)[:200],
        "desc": vuln.get("description") or vuln.get("summary") or "",
        "severity": severity,
        "external_id": str(vuln.get("id") or vuln.get("cve_code") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": vuln.get("remediation") or vuln.get("solution") or vuln.get("fix") or "",
        "data": vuln.get("evidence") or vuln.get("detection_information") or vuln.get("proof") or "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["cyberwatch"],
    }


def build_host(asset, vulns):
    ip = asset.get("ip_address") or asset.get("ip") or asset.get("primary_ip") or asset.get("address") or "0.0.0.0"
    hostname = asset.get("hostname") or asset.get("name") or asset.get("dns_name")
    os_name = (
        asset.get("os")
        or asset.get("operating_system")
        or asset.get("os_name")
        or (asset.get("os_detail") or {}).get("name")
        or ""
    )
    desc_parts = [f"Cyberwatch asset id={asset.get('id', 'N/A')}"]
    if asset.get("group") or asset.get("groups"):
        groups = asset.get("group") or asset.get("groups")
        if isinstance(groups, list):
            groups = ",".join(str(g.get("name") if isinstance(g, dict) else g) for g in groups)
        desc_parts.append(f"group={groups}")
    if asset.get("category") or asset.get("type"):
        desc_parts.append(f"type={asset.get('category') or asset.get('type')}")
    if asset.get("tags"):
        tags = asset.get("tags") or []
        if isinstance(tags, list):
            tags = ",".join(str(t.get("name") if isinstance(t, dict) else t) for t in tags)
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
    host = env("CYBERWATCH_HOST", required=True).rstrip("/")
    api_key = env("CYBERWATCH_API_KEY", required=True)
    secret_key = env("CYBERWATCH_SECRET_KEY", required=True)
    group = env("EXECUTOR_CONFIG_CYBERWATCH_GROUP")
    min_severity = (env("EXECUTOR_CONFIG_CYBERWATCH_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"CYBERWATCH_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    parsed = urlparse(base_url)
    host_header = parsed.netloc or parsed.path

    assets = get_assets(base_url, host_header, api_key, secret_key, group)
    log(f"Found {len(assets)} assets (group={group or 'all'})")

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    for asset in assets:
        asset_id = asset.get("id") or asset.get("asset_id")
        if asset_id is None:
            continue
        raw_vulns = get_vulnerabilities(base_url, host_header, api_key, secret_key, asset_id, min_severity)
        vulns = [build_vulnerability(v) for v in raw_vulns]
        vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
        if not vulns:
            continue
        hosts.append(build_host(asset, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "cyberwatch",
            "command": "cyberwatch",
            "params": f"group={group or 'all'} min_severity={min_severity}",
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
