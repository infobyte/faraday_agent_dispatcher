#!/usr/bin/env python3
"""Vicarius vRx remediation/status import executor.

Pulls remediation-relevant data from the vRx External Data API and emits
Faraday bulk-create JSON to stdout.

Modes:
  assets   -> /endpoint/search
  cves     -> /aggregation/searchGroup (OrganizationEndpointVulnerabilities)
  patches  -> /organizationEndpointExternalReferenceExternalReferences/search

VICARIUS_API_URL + VICARIUS_TOKEN are taken from the dispatcher config
(env vars set as varenvs in dispatcher.yaml).
"""

import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VALID_MODES = {"assets", "cves", "patches"}


def _api(path, query):
    base = os.environ.get("VICARIUS_API_URL", "").rstrip("/")
    token = os.environ.get("VICARIUS_TOKEN")
    if not base or not token:
        print("VICARIUS_API_URL and VICARIUS_TOKEN must be set in the agent config", file=sys.stderr)
        sys.exit(1)
    url = f"{base}{path}?{urllib.parse.urlencode(query)}"
    req = urllib.request.Request(url, headers={"Vicarius-Token": token, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode())
    rr = data.get("serverResponseResult", {})
    if rr.get("serverResponseResultCode") != "SUCCESS":
        print(f"vRx API error: {rr}", file=sys.stderr)
        sys.exit(1)
    return data.get("serverResponseObject", []) or []


def _pick(d, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def _severity(sev):
    if isinstance(sev, (int, float)):
        s = float(sev)
        if s >= 9:
            return "critical"
        if s >= 7:
            return "high"
        if s >= 4:
            return "medium"
        if s > 0:
            return "low"
        return "info"
    s = str(sev or "").strip().lower()
    return s if s in {"critical", "high", "medium", "low", "info", "unclassified"} else "info"


def _host_from_asset(a):
    ip = _pick(a, "ipAddress", "ip", "primaryIp", default="")
    name = _pick(a, "assetName", "hostName", "endpointName", "name", default="")
    os_name = _pick(a, "operatingSystem", "os", "osName", default="unknown")
    return {
        "ip": ip or name or "unknown",
        "os": os_name,
        "hostnames": [name] if name and name != ip else [],
        "description": _pick(a, "description", default=""),
        "mac": _pick(a, "macAddress", "mac", default=None),
        "credentials": [],
        "services": [],
        "vulnerabilities": [],
        "tags": [],
    }


def run_assets():
    page_from = int(os.environ.get("EXECUTOR_CONFIG_VICARIUS_FROM", "0"))
    page_size = int(os.environ.get("EXECUTOR_CONFIG_VICARIUS_SIZE", "500"))
    items = _api("/endpoint/search", {"from": page_from, "size": page_size})
    return [_host_from_asset(a) for a in items]


def run_cves():
    page_from = int(os.environ.get("EXECUTOR_CONFIG_VICARIUS_FROM", "1"))
    page_size = int(os.environ.get("EXECUTOR_CONFIG_VICARIUS_SIZE", "500"))
    items = _api(
        "/aggregation/searchGroup",
        {
            "from": page_from,
            "size": page_size,
            "objectName": "OrganizationEndpointVulnerabilities",
            "group": "vulnerabilityId",
            "includeOriginalDoc": "true",
            "q": "",
            "assetCount": "true",
            "sort": "aggregationId",
            "sumLastSubAggregationBuckets": "1",
        },
    )
    hosts = {}
    for agg in items:
        cve = _pick(agg, "aggregationId", "vulnerabilityId", default="")
        if not cve:
            continue
        orig = agg.get("originalDoc") or {}
        sev = _severity(_pick(orig, "severity", "cvssScore", "cvss", default=_pick(agg, "severity")))
        desc = _pick(orig, "description", "title", default=cve)
        affected = agg.get("subAggregations") or agg.get("assets") or orig.get("assets") or []
        if not affected:
            affected = [{"assetName": "unknown", "ipAddress": "0.0.0.0"}]
        for a in affected:
            ip = _pick(a, "ipAddress", "ip", default="") or _pick(a, "assetName", default="unknown")
            host = hosts.setdefault(ip, _host_from_asset(a))
            host["vulnerabilities"].append(
                {
                    "name": cve,
                    "desc": desc,
                    "severity": sev,
                    "refs": (
                        [{"name": f"https://nvd.nist.gov/vuln/detail/{cve}", "type": "other"}]
                        if cve.upper().startswith("CVE-")
                        else []
                    ),
                    "external_id": cve,
                    "type": "Vulnerability",
                    "resolution": "",
                    "data": "",
                    "custom_fields": {},
                    "status": "open",
                    "impact": {},
                    "policyviolations": [],
                    "cve": [cve] if cve.upper().startswith("CVE-") else [],
                    "cvss3": {},
                    "cvss2": {},
                    "confirmed": False,
                    "tags": [],
                    "cwe": [],
                }
            )
    return list(hosts.values())


def run_patches():
    page_from = int(os.environ.get("EXECUTOR_CONFIG_VICARIUS_FROM", "0"))
    page_size = int(os.environ.get("EXECUTOR_CONFIG_VICARIUS_SIZE", "500"))
    items = _api(
        "/organizationEndpointExternalReferenceExternalReferences/search", {"from": page_from, "size": page_size}
    )
    hosts = {}
    for it in items:
        ip = _pick(it, "ipAddress", "ip", default="") or _pick(it, "assetName", "hostName", default="unknown")
        host = hosts.setdefault(ip, _host_from_asset(it))
        patch = _pick(it, "patchName", "kbId", "externalReferenceName", "name", default="missing-patch")
        product = _pick(it, "productName", "applicationName", default="")
        sev = _severity(_pick(it, "severity", default="high"))
        host["vulnerabilities"].append(
            {
                "name": f"Missing patch: {patch}" + (f" ({product})" if product else ""),
                "desc": f"vRx reports missing patch {patch} on this endpoint.",
                "severity": sev,
                "refs": [],
                "external_id": patch,
                "type": "Vulnerability",
                "resolution": "Apply the patch via Vicarius vRx.",
                "data": "",
                "custom_fields": {},
                "status": "open",
                "impact": {},
                "policyviolations": [],
                "cve": [],
                "cvss3": {},
                "cvss2": {},
                "confirmed": False,
                "tags": ["missing-patch"],
                "cwe": [],
            }
        )
    return list(hosts.values())


def main():
    mode = os.environ.get("EXECUTOR_CONFIG_VICARIUS_MODE", "cves").lower()
    if mode not in VALID_MODES:
        print(f"Invalid VICARIUS_MODE: {mode}. Use one of: {sorted(VALID_MODES)}", file=sys.stderr)
        sys.exit(1)

    start = datetime.now(timezone.utc)
    hosts = {"assets": run_assets, "cves": run_cves, "patches": run_patches}[mode]()
    duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    output = {
        "hosts": hosts,
        "command": {
            "tool": "vicarius",
            "command": f"vicarius {mode}",
            "params": "",
            "user": "",
            "hostname": "",
            "start_date": start.isoformat(),
            "duration": duration_ms,
            "import_source": "report",
        },
    }
    print(json.dumps(output))


if __name__ == "__main__":
    main()
