#!/usr/bin/env python
"""Palo Alto Cortex XSOAR (Demisto) REST API importer.

Pulls security incidents from a Cortex XSOAR tenant and emits Faraday
bulk-create JSON to stdout. Each incident is mapped to a Faraday
vulnerability — one host per affected asset (resolved from the incident's
``labels`` / ``CustomFields`` blocks, falling back to a synthetic
``0.0.0.0`` host when no asset can be derived).

Endpoints used:
  POST /incidents/search   -> paginate incidents, optionally filtered by a
                              Lucene-style ``query`` (XSOAR_INCIDENT_FILTER)
                              and ``fromDate`` (XSOAR_FROM_DATE).
  GET  /incident/{id}      -> per-incident detail (labels, CustomFields,
                              indicators) for asset enrichment.

Auth: ``Authorization: <XSOAR_API_KEY>`` plus ``x-xdr-auth-id:
<XSOAR_API_KEY_ID>`` (the latter is required by the XSOAR 8 / Cortex
platform; ignored — but harmless — on classic XSOAR 6 tenants).
XSOAR_HOST is the tenant base URL (e.g. https://<tenant>.xsoar.paloalto
networks.com).
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

# XSOAR severity scale: 0 = Unknown, 0.5 = Informational, 1 = Low,
# 2 = Medium, 3 = High, 4 = Critical. Strings are also accepted because
# some integrations surface the human label rather than the numeric value.
XSOAR_TO_FARADAY = {
    "unknown": "info",
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}

# Incident status codes used by XSOAR:
#   0 = Pending, 1 = Active, 2 = Done, 3 = Archive.
STATUS_OPEN = {0, 1}
STATUS_CLOSED = {2, 3}


def log(msg):
    print(f"{datetime.utcnow()} - XSOAR: {msg}", file=sys.stderr, flush=True)


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


def severity_from_xsoar(value):
    if value is None:
        return "info"
    if isinstance(value, (int, float)):
        score = float(value)
        if score >= 4:
            return "critical"
        if score >= 3:
            return "high"
        if score >= 2:
            return "medium"
        if score >= 1:
            return "low"
        return "info"
    text = str(value).strip().lower()
    if text in XSOAR_TO_FARADAY:
        return XSOAR_TO_FARADAY[text]
    try:
        return severity_from_xsoar(float(text))
    except ValueError:
        return "info"


def status_from_xsoar(value, close_reason):
    if close_reason:
        return "closed"
    if value is None:
        return "open"
    try:
        code = int(value)
    except (TypeError, ValueError):
        text = str(value).strip().lower()
        if text in ("closed", "done", "archive", "archived", "resolved"):
            return "closed"
        return "open"
    if code in STATUS_CLOSED:
        return "closed"
    if code in STATUS_OPEN:
        return "open"
    return "open"


def post(base_url, path, headers, payload):
    url = f"{base_url}{path}"
    resp = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check XSOAR_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log("Authorization rejected (403). Check XSOAR_API_KEY_ID and the key's role.")
        sys.exit(1)
    if resp.status_code == 404:
        log(f"POST {path} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"POST {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"POST {path} returned non-JSON body")
        return None


def get(base_url, path, headers):
    url = f"{base_url}{path}"
    resp = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check XSOAR_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log("Authorization rejected (403). Check XSOAR_API_KEY_ID and the key's role.")
        return None
    if resp.status_code == 404:
        log(f"GET {path} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def search_incidents(base_url, headers, query, from_date):
    incidents = []
    for page in range(MAX_PAGES):
        payload_filter = {"page": page, "size": PAGE_SIZE}
        if query:
            payload_filter["query"] = query
        if from_date:
            payload_filter["fromDate"] = from_date
        body = post(base_url, "/incidents/search", headers, {"filter": payload_filter})
        if not isinstance(body, dict):
            break
        chunk = body.get("data") or body.get("incidents") or []
        if not chunk:
            break
        incidents.extend(chunk)
        total = body.get("total")
        if isinstance(total, int) and len(incidents) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
    return incidents


def fetch_incident_detail(base_url, headers, incident_id):
    detail = get(base_url, f"/incident/{incident_id}", headers)
    if isinstance(detail, dict) and detail:
        return detail
    return None


# Label / CustomField keys XSOAR integrations commonly use to convey the
# affected asset. Lower-cased for case-insensitive lookup.
IP_KEYS = (
    "ip",
    "ipaddress",
    "ip_address",
    "sourceip",
    "source_ip",
    "src_ip",
    "srcip",
    "destinationip",
    "destination_ip",
    "dst_ip",
    "dstip",
    "hostip",
    "host_ip",
)

HOSTNAME_KEYS = (
    "hostname",
    "host_name",
    "host",
    "asset",
    "assetname",
    "asset_name",
    "computername",
    "computer_name",
    "devicename",
    "device_name",
    "endpoint",
    "endpointname",
    "endpoint_name",
    "fqdn",
)

OS_KEYS = ("os", "operatingsystem", "operating_system", "ostype", "os_type", "platform")

MAC_KEYS = ("mac", "macaddress", "mac_address", "hwaddress", "hw_address")


def _label_iter(incident):
    """Yield (key_lower, value) pairs from labels + CustomFields."""
    for entry in incident.get("labels") or []:
        if isinstance(entry, dict):
            key = entry.get("type") or entry.get("name")
            value = entry.get("value")
            if key and value is not None:
                yield str(key).strip().lower(), value
    custom = incident.get("CustomFields") or incident.get("customFields") or {}
    if isinstance(custom, dict):
        for key, value in custom.items():
            if value is None:
                continue
            yield str(key).strip().lower(), value


def _first_match(incident, keys):
    keyset = set(keys)
    for key, value in _label_iter(incident):
        if key in keyset:
            if isinstance(value, list):
                for item in value:
                    if item:
                        return item
            elif value:
                return value
    return None


def asset_identity(incident):
    ip = _first_match(incident, IP_KEYS)
    hostname = _first_match(incident, HOSTNAME_KEYS)
    if ip:
        ip = str(ip).strip()
    if hostname:
        hostname = str(hostname).strip()
    return ip or None, hostname or None


def collect_refs(incident):
    refs = []
    source_brand = incident.get("sourceBrand")
    source_instance = incident.get("sourceInstance")
    if source_brand:
        label = f"sourceBrand: {source_brand}"
        if source_instance:
            label = f"{label} ({source_instance})"
        refs.append({"name": label, "type": "other"})
    playbook = incident.get("playbookId") or incident.get("playbookID")
    if playbook:
        refs.append({"name": f"playbook: {playbook}", "type": "other"})
    for entry in incident.get("indicators") or []:
        if isinstance(entry, dict):
            value = entry.get("value") or entry.get("id")
            if value:
                indicator_type = entry.get("indicator_type") or entry.get("type") or "indicator"
                refs.append({"name": f"{indicator_type}: {value}", "type": "other"})
    return refs


def collect_cves(incident):
    cves = []
    for key, value in _label_iter(incident):
        if "cve" not in key:
            continue
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            text = str(candidate).strip().upper()
            if text.startswith("CVE-"):
                cves.append(text)
    return cves


def build_vulnerability(incident):
    severity = severity_from_xsoar(incident.get("severity"))
    status = status_from_xsoar(incident.get("status"), incident.get("closeReason"))
    name = incident.get("name") or incident.get("displayName") or f"XSOAR incident {incident.get('id', '')}"
    desc_parts = []
    if incident.get("details"):
        desc_parts.append(str(incident["details"]))
    incident_type = incident.get("type") or incident.get("category")
    if incident_type:
        desc_parts.append(f"type: {incident_type}")
    occurred = incident.get("occurred") or incident.get("created")
    if occurred:
        desc_parts.append(f"occurred: {occurred}")
    owner = incident.get("owner")
    if owner:
        desc_parts.append(f"owner: {owner}")
    phase = incident.get("phase")
    if phase:
        desc_parts.append(f"phase: {phase}")
    reason = incident.get("reason")
    if reason:
        desc_parts.append(f"reason: {reason}")
    resolution_parts = []
    if incident.get("closeReason"):
        resolution_parts.append(str(incident["closeReason"]))
    if incident.get("closeNotes"):
        resolution_parts.append(str(incident["closeNotes"]))
    return {
        "name": str(name).strip()[:200] or f"XSOAR incident {incident.get('id', '')}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(incident.get("id") or incident.get("investigationId") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": "\n".join(resolution_parts),
        "data": incident.get("investigationId") or "",
        "refs": collect_refs(incident),
        "cve": collect_cves(incident),
        "cvss3": {},
        "tags": ["xsoar"],
    }


def build_host(ip, hostname, incident_sample, vulns):
    os_name = ""
    mac = ""
    if incident_sample is not None:
        os_value = _first_match(incident_sample, OS_KEYS)
        if os_value:
            os_name = str(os_value)
        mac_value = _first_match(incident_sample, MAC_KEYS)
        if mac_value:
            mac = str(mac_value)
    desc = "Cortex XSOAR affected asset"
    if incident_sample is not None and incident_sample.get("sourceBrand"):
        desc = f"{desc} (sourceBrand={incident_sample['sourceBrand']})"
    return {
        "ip": str(ip) if ip else "0.0.0.0",
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": desc,
        "vulnerabilities": vulns,
    }


def synthetic_host(vulns):
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [],
        "mac": "",
        "description": "Cortex XSOAR incidents without a resolvable asset",
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("XSOAR_HOST", required=True).rstrip("/")
    api_key = env("XSOAR_API_KEY", required=True)
    api_key_id = env("XSOAR_API_KEY_ID")
    query = env("EXECUTOR_CONFIG_XSOAR_INCIDENT_FILTER")
    from_date = env("EXECUTOR_CONFIG_XSOAR_FROM_DATE")

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if api_key_id:
        headers["x-xdr-auth-id"] = api_key_id

    incidents = search_incidents(base_url, headers, query, from_date)
    log(f"Fetched {len(incidents)} incidents (query={query or 'all'}, fromDate={from_date or 'none'})")

    grouped = {}
    orphan_vulns = []
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        incident_id = incident.get("id") or incident.get("investigationId")
        if not incident_id:
            continue
        detail = fetch_incident_detail(base_url, headers, incident_id)
        merged = dict(incident)
        if isinstance(detail, dict):
            merged.update(detail)
        vuln = build_vulnerability(merged)
        ip, hostname = asset_identity(merged)
        if not ip and not hostname:
            orphan_vulns.append(vuln)
            continue
        key = (ip or "", hostname or "")
        grouped.setdefault(key, {"sample": merged, "vulns": []})["vulns"].append(vuln)

    hosts = []
    for (ip, hostname), bucket in grouped.items():
        hosts.append(build_host(ip or None, hostname or None, bucket["sample"], bucket["vulns"]))
    if orphan_vulns:
        hosts.append(synthetic_host(orphan_vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "xsoar",
            "command": "xsoar",
            "params": f"query={query or 'all'} fromDate={from_date or 'none'}",
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
