#!/usr/bin/env python3
"""Vicarius vRx remediation/status import executor.

Pulls remediation-relevant data from the vRx External Data API and emits
Faraday bulk-create JSON to stdout.

Modes:
  assets    -> /endpoint/search
  cves      -> /aggregation/searchGroup (OrganizationEndpointVulnerabilities)
  patches   -> /organizationEndpointExternalReferenceExternalReferences/search
  software  -> /organizationEndpointPublisherProductVersions/search
  incidents -> /incidentEvent/search (Detected/MitigatedVulnerability)

VICARIUS_API_URL + VICARIUS_TOKEN can be provided as per-scan args or as agent
varenvs; per-scan values take precedence.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from faraday_agent_dispatcher.utils import arg_helpers

VALID_MODES = {"assets", "cves", "patches", "software", "incidents"}

# Pagination + retry tuning. vRx rate-limits per-tenant; vAnalyzer's reference
# implementation backs off 60s on 429. The hard page cap prevents a runaway
# loop on tenants with millions of records — bump VICARIUS_MAX_PAGES per-scan
# if you genuinely need a deeper walk.
DEFAULT_PAGE_SIZE = 500
DEFAULT_MAX_PAGES = 100
RETRY_429_SLEEP_SECONDS = 60
MAX_429_RETRIES = 3


def _resolve_base_and_token():
    base = arg_helpers.single("EXECUTOR_CONFIG_VICARIUS_API_URL") or os.environ.get("VICARIUS_API_URL", "")
    token = arg_helpers.single("EXECUTOR_CONFIG_VICARIUS_TOKEN") or os.environ.get("VICARIUS_TOKEN", "")
    return base.rstrip("/"), token


def _api_page(path, query):
    base, token = _resolve_base_and_token()
    if not base or not token:
        print("VICARIUS_API_URL and VICARIUS_TOKEN must be set (per-scan or as agent varenvs)", file=sys.stderr)
        sys.exit(1)
    url = f"{base}{path}?{urllib.parse.urlencode(query)}"
    req = urllib.request.Request(url, headers={"Vicarius-Token": token, "Accept": "application/json"})

    for attempt in range(MAX_429_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < MAX_429_RETRIES:
                print(
                    f"vRx 429 rate-limited on {path} (attempt {attempt + 1}/{MAX_429_RETRIES}), "
                    f"sleeping {RETRY_429_SLEEP_SECONDS}s",
                    file=sys.stderr,
                )
                time.sleep(RETRY_429_SLEEP_SECONDS)
                continue
            print(f"vRx HTTP {exc.code} on {path}: {exc.reason}", file=sys.stderr)
            sys.exit(1)

    rr = data.get("serverResponseResult", {})
    if rr.get("serverResponseResultCode") != "SUCCESS":
        print(f"vRx API error: {rr}", file=sys.stderr)
        sys.exit(1)
    return data.get("serverResponseObject", []) or []


def _env_int(name, default):
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _api_all(path, query, start_from=None, page_size=None, max_pages=None):
    """Yield every record across paginated /search-style endpoints.

    Walks `from` in `page_size` strides until the API returns fewer than
    page_size items (last page) or the hard cap is hit. Per-scan overrides:
      VICARIUS_FROM      -> starting `from` cursor (default 0, or 1 for
                            /aggregation/searchGroup which is 1-indexed)
      VICARIUS_SIZE      -> page size (default 500)
      VICARIUS_MAX_PAGES -> hard cap on pages walked (default 100 = 50k rows)
    """
    cursor = _env_int("EXECUTOR_CONFIG_VICARIUS_FROM", start_from if start_from is not None else 0)
    size = _env_int("EXECUTOR_CONFIG_VICARIUS_SIZE", page_size or DEFAULT_PAGE_SIZE)
    cap = _env_int("EXECUTOR_CONFIG_VICARIUS_MAX_PAGES", max_pages or DEFAULT_MAX_PAGES)
    for _ in range(cap):
        page_query = {**query, "from": cursor, "size": size}
        items = _api_page(path, page_query)
        if not items:
            return
        for item in items:
            yield item
        if len(items) < size:
            return
        cursor += size


def _pick(d, *keys, default=""):
    for k in keys:
        v = d.get(k) if isinstance(d, dict) else None
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
    # vRx /endpoint/search records typically carry only endpointName + endpointOperatingSystem;
    # no ipAddress field is exposed. Faraday's bulk_create silently drops hosts whose `ip`
    # isn't IP-shaped, so fall back to 0.0.0.0 and keep the endpointName as the hostname
    # rather than (mis-)using it as the IP.
    ip = _pick(a, "ipAddress", "ip", "primaryIp", default="")
    name = _pick(a, "assetName", "hostName", "endpointName", "name", default="")
    os_blob = a.get("endpointOperatingSystem") or {} if isinstance(a, dict) else {}
    os_name = (
        _pick(a, "operatingSystem", "os", "osName", default="")
        or _pick(os_blob, "operatingSystemName", "name", default="")
        or "unknown"
    )
    desc_parts = []
    base_desc = _pick(a, "description", default="")
    if base_desc:
        desc_parts.append(base_desc)
    endpoint_id = a.get("endpointId") if isinstance(a, dict) else None
    if endpoint_id:
        desc_parts.append(f"vRx endpointId={endpoint_id}")
    scores = a.get("endpointEndpointScores") or {} if isinstance(a, dict) else {}
    score_val = scores.get("endpointScoresScore")
    sens_name = (scores.get("endpointScoresSensitivityLevel") or {}).get("sensitivityLevelName")
    if score_val is not None:
        desc_parts.append(f"vRx score={score_val}" + (f" sensitivity={sens_name}" if sens_name else ""))
    status = (
        (a.get("endpointEndpointStatus") or {}).get("name")
        or (a.get("endpointEndpointStatus") or {}).get("statusName")
        if isinstance(a, dict)
        else None
    )
    if status:
        desc_parts.append(f"status={status}")
    tags = []
    if endpoint_id:
        tags.append(f"vrx:endpoint:{endpoint_id}")
    if sens_name:
        tags.append(f"vrx:sensitivity:{sens_name.lower()}")
    return {
        "ip": ip or "0.0.0.0",
        "os": os_name,
        "hostnames": [name] if name else [],
        "description": " | ".join(desc_parts),
        "mac": _pick(a, "macAddress", "mac", default=None),
        "credentials": [],
        "services": [],
        "vulnerabilities": [],
        "tags": tags,
    }


def _shell_host(endpoint_name, endpoint_id=None, os_name="unknown"):
    """Build a minimal host record for endpoints surfaced by endpoint-pivoting
    endpoints (software/incidents) where the full /endpoint/search blob isn't
    in-line."""
    tags = []
    if endpoint_id:
        tags.append(f"vrx:endpoint:{endpoint_id}")
    return {
        "ip": "0.0.0.0",
        "os": os_name,
        "hostnames": [endpoint_name] if endpoint_name else [],
        "description": (f"vRx endpointId={endpoint_id}" if endpoint_id else ""),
        "mac": None,
        "credentials": [],
        "services": [],
        "vulnerabilities": [],
        "tags": tags,
    }


def _new_vuln(name, desc, severity, external_id, status="open", cve_list=None, refs=None, resolution="", tags=None):
    return {
        "name": name,
        "desc": desc,
        "severity": severity,
        "refs": refs or [],
        "external_id": external_id,
        "type": "Vulnerability",
        "resolution": resolution,
        "data": "",
        "custom_fields": {},
        "status": status,
        "impact": {},
        "policyviolations": [],
        "cve": cve_list or [],
        "cvss3": {},
        "cvss2": {},
        "confirmed": False,
        "tags": tags or [],
        "cwe": [],
    }


def run_assets():
    items = _api_all("/endpoint/search", {})
    return [_host_from_asset(a) for a in items]


def run_cves():
    items = _api_all(
        "/aggregation/searchGroup",
        {
            "objectName": "OrganizationEndpointVulnerabilities",
            "group": "vulnerabilityId",
            "includeOriginalDoc": "true",
            "q": "",
            "assetCount": "true",
            "sort": "aggregationId",
            "sumLastSubAggregationBuckets": "1",
        },
        start_from=1,
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
                _new_vuln(
                    name=cve,
                    desc=desc,
                    severity=sev,
                    external_id=cve,
                    cve_list=[cve] if cve.upper().startswith("CVE-") else [],
                    refs=(
                        [{"name": f"https://nvd.nist.gov/vuln/detail/{cve}", "type": "other"}]
                        if cve.upper().startswith("CVE-")
                        else []
                    ),
                )
            )
    return list(hosts.values())


def run_patches():
    items = _api_all("/organizationEndpointExternalReferenceExternalReferences/search", {})
    hosts = {}
    for it in items:
        ip = _pick(it, "ipAddress", "ip", default="") or _pick(it, "assetName", "hostName", default="unknown")
        host = hosts.setdefault(ip, _host_from_asset(it))
        patch = _pick(it, "patchName", "kbId", "externalReferenceName", "name", default="missing-patch")
        product = _pick(it, "productName", "applicationName", default="")
        sev = _severity(_pick(it, "severity", default="high"))
        host["vulnerabilities"].append(
            _new_vuln(
                name=f"Missing patch: {patch}" + (f" ({product})" if product else ""),
                desc=f"vRx reports missing patch {patch} on this endpoint.",
                severity=sev,
                external_id=patch,
                resolution="Apply the patch via Vicarius vRx.",
                tags=["missing-patch"],
            )
        )
    return list(hosts.values())


def run_software():
    """Installed-software inventory pulled from organizationEndpointPublisherProductVersions.

    Each (endpoint, product, version) tuple is emitted as a severity-info vuln
    tagged 'software-inventory' so the data is searchable in Faraday without
    polluting the actual vuln list. Hosts are keyed by endpoint name (vRx
    doesn't expose an IP, see _host_from_asset).
    """
    items = _api_all("/organizationEndpointPublisherProductVersions/search", {})
    hosts = {}
    for it in items:
        ep = it.get("organizationEndpointPublisherProductVersionsEndpoint") or {}
        app = it.get("organizationEndpointPublisherProductVersionsApplication") or {}
        publisher = it.get("organizationEndpointPublisherProductVersionsPublisher") or {}
        version = it.get("organizationEndpointPublisherProductVersionsVersion") or {}
        raw = it.get("organizationEndpointPublisherProductVersionsProductRawEntry") or {}

        endpoint_name = ep.get("endpointName") or "unknown"
        endpoint_id = ep.get("endpointId")
        product_name = app.get("applicationName") or raw.get("productRawEntryName") or "unknown"
        publisher_name = publisher.get("publisherName") or raw.get("productRawEntryName") or "unknown"
        product_version = version.get("versionName") or "-"

        key = endpoint_name
        host = hosts.setdefault(key, _shell_host(endpoint_name, endpoint_id=endpoint_id))
        host["vulnerabilities"].append(
            _new_vuln(
                name=f"Installed software: {publisher_name} {product_name} {product_version}",
                desc=(
                    f"vRx software inventory entry for endpoint {endpoint_name}: "
                    f"publisher={publisher_name}, product={product_name}, version={product_version}."
                ),
                severity="info",
                external_id=f"vrx-sw:{endpoint_id or endpoint_name}:{product_name}:{product_version}",
                tags=["software-inventory", "vrx:software"],
            )
        )
    return list(hosts.values())


def run_incidents():
    """Vulnerability incident events (Detected / Mitigated).

    Emits one finding per event. MitigatedVulnerability events arrive with
    status='closed' so they can supplement the cves mode (auto-close vulns
    that vRx has remediated). Filters server-side to just the two relevant
    event types.
    """
    items = _api_all(
        "/incidentEvent/search",
        {"q": "incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)"},
    )
    hosts = {}
    for it in items:
        event_type = _pick(it, "incidentEventIncidentEventType", default="")
        endpoint = it.get("incidentEventEndpoint") or {}
        endpoint_name = endpoint.get("endpointName") or "unknown"
        endpoint_id = endpoint.get("endpointId")
        vuln = it.get("incidentEventVulnerability") or {}
        ext_ref = vuln.get("vulnerabilityExternalReference") or {}
        cve = ext_ref.get("externalReferenceExternalId") or _pick(vuln, "vulnerabilityId", default="")
        sens = (vuln.get("vulnerabilitySensitivityLevel") or {}).get("sensitivityLevelName")
        updated = _pick(it, "analyticsEventUpdatedAt", "analyticsEventCreatedAt", default="")

        if not cve:
            continue

        host = hosts.setdefault(endpoint_name, _shell_host(endpoint_name, endpoint_id=endpoint_id))
        status = "closed" if event_type == "MitigatedVulnerability" else "open"
        host["vulnerabilities"].append(
            _new_vuln(
                name=cve,
                desc=(
                    f"vRx {event_type} event on {endpoint_name}"
                    + (f" at {updated}" if updated else "")
                    + (f" (severity {sens})" if sens else "")
                ),
                severity=_severity(sens),
                external_id=f"vrx-incident:{cve}:{endpoint_id or endpoint_name}",
                status=status,
                cve_list=[cve] if cve.upper().startswith("CVE-") else [],
                refs=(
                    [{"name": f"https://nvd.nist.gov/vuln/detail/{cve}", "type": "other"}]
                    if cve.upper().startswith("CVE-")
                    else []
                ),
                tags=[f"vrx:event:{event_type.lower()}"],
            )
        )
    return list(hosts.values())


MODE_RUNNERS = {
    "assets": run_assets,
    "cves": run_cves,
    "patches": run_patches,
    "software": run_software,
    "incidents": run_incidents,
}


def _merge(into, hosts):
    for host in hosts:
        existing = into.get(host["ip"])
        if existing is None:
            into[host["ip"]] = host
        else:
            existing["vulnerabilities"].extend(host.get("vulnerabilities") or [])
            for hostname in host.get("hostnames") or []:
                if hostname not in existing["hostnames"]:
                    existing["hostnames"].append(hostname)


def main():
    modes = [m.lower() for m in arg_helpers.items("EXECUTOR_CONFIG_VICARIUS_MODE")] or ["cves"]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        print(f"Invalid VICARIUS_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}", file=sys.stderr)
        sys.exit(1)

    start = datetime.now(timezone.utc)
    merged: dict = {}
    for mode in modes:
        _merge(merged, MODE_RUNNERS[mode]())
    duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    output = {
        "hosts": list(merged.values()),
        "command": {
            "tool": "vicarius",
            "command": f"vicarius {','.join(modes)}",
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
