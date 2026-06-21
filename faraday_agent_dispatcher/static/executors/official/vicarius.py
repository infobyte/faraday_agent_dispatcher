#!/usr/bin/env python3
"""Vicarius vRx remediation/status import executor.

Pulls remediation-relevant data from the vRx External Data API and emits
Faraday bulk-create JSON to stdout.

Modes:
  assets    -> /endpoint/search
  cves      -> /organizationEndpointVulnerabilities/search
  patches   -> /organizationEndpointExternalReferenceExternalReferences/search
  software  -> /organizationEndpointPublisherProductVersions/search
  incidents -> /incidentEvent/filter (Detected/MitigatedVulnerability)

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


class VRxAPIError(RuntimeError):
    """Raised when a vRx API call fails irrecoverably. Caught per-mode in
    main() so one bad endpoint can't drop the whole multi-mode run."""


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
            raise VRxAPIError(f"vRx HTTP {exc.code} on {path}: {exc.reason}") from exc

    rr = data.get("serverResponseResult", {})
    if rr.get("serverResponseResultCode") != "SUCCESS":
        raise VRxAPIError(f"vRx API error on {path}: {rr}")
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
    """Active vulnerabilities per endpoint via the flat /organizationEndpointVulnerabilities/search.

    Each record is a (endpoint, vulnerability) tuple. Earlier this used
    /aggregation/searchGroup but that grouped by vRx's internal vulnerabilityId
    (the 'aggregationId') and only exposed the actual CVE deep in
    aggregationModelAbs — leading to findings named '458144' instead of the
    CVE string. The flat endpoint has the CVE and severity inline.
    """
    items = _api_all("/organizationEndpointVulnerabilities/search", {})
    hosts = {}
    for it in items:
        ep = it.get("organizationEndpointVulnerabilitiesEndpoint") or {}
        vuln = it.get("organizationEndpointVulnerabilitiesVulnerability") or {}
        ext_ref = vuln.get("vulnerabilityExternalReference") or {}
        sens = vuln.get("vulnerabilitySensitivityLevel") or {}
        product = it.get("organizationEndpointVulnerabilitiesProduct") or {}
        publisher = it.get("organizationEndpointVulnerabilitiesPublisher") or {}

        cve = ext_ref.get("externalReferenceExternalId") or ""
        if not cve:
            continue
        endpoint_name = ep.get("endpointName") or "unknown"
        endpoint_id = ep.get("endpointId")
        cvss_v3 = vuln.get("vulnerabilityV3BaseScore")
        cvss_v2 = vuln.get("vulnerabilityV2BaseScore")
        severity = _severity(sens.get("sensitivityLevelName") or cvss_v3 or cvss_v2)
        summary = vuln.get("vulnerabilitySummary") or ""
        prod_label = (
            f"{publisher.get('publisherName') or ''} {product.get('productName') or ''}".strip() or "unknown product"
        )

        host = hosts.setdefault(endpoint_name, _shell_host(endpoint_name, endpoint_id=endpoint_id))
        host["vulnerabilities"].append(
            _new_vuln(
                name=cve,
                desc=(summary or f"vRx-reported vulnerability {cve} affecting {prod_label}"),
                severity=severity,
                external_id=f"vrx-vuln:{cve}:{endpoint_id or endpoint_name}",
                cve_list=[cve] if cve.upper().startswith("CVE-") else [],
                refs=(
                    [{"name": f"https://nvd.nist.gov/vuln/detail/{cve}", "type": "other"}]
                    if cve.upper().startswith("CVE-")
                    else []
                ),
                tags=(
                    [f"vrx:product:{(product.get('productName') or '').lower()}"] if product.get("productName") else []
                ),
            )
        )
    return list(hosts.values())


def run_patches():
    """Missing-patch entries from /organizationEndpointExternalReferenceExternalReferences/search.

    Each record is an installed-CPE → fixed-CPE pair carrying an embedded
    patch list under organizationEndpointExternalReferenceExternalReferencesPatches.
    The earlier implementation read top-level fields that don't exist on
    this endpoint, so every finding fell through to the literal default
    'missing-patch'.
    """
    items = _api_all("/organizationEndpointExternalReferenceExternalReferences/search", {})
    hosts = {}
    for it in items:
        ep = it.get("organizationEndpointExternalReferenceExternalReferencesEndpoint") or {}
        installed_ref = it.get("organizationEndpointExternalReferenceExternalReferencesExternalReference") or {}
        fixed_ref = it.get("organizationEndpointExternalReferenceExternalReferencesExternalReferenceSource") or {}
        patches = it.get("organizationEndpointExternalReferenceExternalReferencesPatches") or []

        endpoint_name = ep.get("endpointName") or "unknown"
        endpoint_id = ep.get("endpointId")
        installed_cpe = installed_ref.get("externalReferenceExternalId") or ""
        fixed_cpe = fixed_ref.get("externalReferenceExternalId") or ""

        host = hosts.setdefault(endpoint_name, _shell_host(endpoint_name, endpoint_id=endpoint_id))
        # One record can carry multiple patch candidates; emit each so the user
        # sees every fix vRx considers applicable.
        for p in patches or [{}]:
            patch_name = p.get("patchName") or "unknown patch"
            patch_desc = p.get("patchDescription") or ""
            patch_id = p.get("patchId")
            patch_file = p.get("patchFileName") or ""
            cpe_context = f" (installed: {installed_cpe} → fixed: {fixed_cpe})" if installed_cpe and fixed_cpe else ""
            host["vulnerabilities"].append(
                _new_vuln(
                    name=f"Missing patch: {patch_name}" + (f" — {patch_desc}" if patch_desc else ""),
                    desc=(
                        f"vRx reports missing patch '{patch_name}' on {endpoint_name}"
                        + (f" ({patch_desc})" if patch_desc else "")
                        + cpe_context
                        + (f" — installer: {patch_file}" if patch_file else "")
                    ),
                    severity="high",
                    external_id=f"vrx-patch:{patch_id or patch_name}:{endpoint_id or endpoint_name}",
                    resolution="Apply the patch via Vicarius vRx.",
                    tags=["missing-patch", f"vrx:patch:{patch_name.lower()}" if patch_name else "missing-patch"],
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


RELEVANT_INCIDENT_TYPES = {"MitigatedVulnerability", "DetectedVulnerability"}


def run_incidents():
    """Vulnerability incident events (Detected / Mitigated).

    Emits one finding per event. MitigatedVulnerability events arrive with
    status='closed' so they can supplement the cves mode (auto-close vulns
    that vRx has remediated). The /incidentEvent/filter endpoint doesn't
    accept a server-side q-filter, so we walk every event and drop anything
    that isn't a Detected/Mitigated vulnerability event (NewEndpoint,
    EndpointEventInformation, etc.).
    """
    items = _api_all("/incidentEvent/filter", {})
    hosts = {}
    for it in items:
        event_type = _pick(it, "incidentEventIncidentEventType", default="")
        if event_type not in RELEVANT_INCIDENT_TYPES:
            continue
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
    failed_modes = []
    for mode in modes:
        try:
            _merge(merged, MODE_RUNNERS[mode]())
        except VRxAPIError as exc:
            failed_modes.append(mode)
            print(f"vRx mode '{mode}' failed: {exc}. Continuing with other modes.", file=sys.stderr)
    if failed_modes and len(failed_modes) == len(modes):
        # Every mode failed — surface as a hard error so the dispatcher logs it.
        print("All vRx modes failed; nothing to upload.", file=sys.stderr)
        sys.exit(1)
    duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    # Faraday c-5.21.x bulk_create silently drops the entire vulnerabilities
    # array (returning 201, no warning) when any host has duplicate external_id
    # values across its vulns. vRx's /organizationEndpointVulnerabilities/search
    # returns the same (endpoint, CVE) pair once per affected product on the
    # endpoint, so a CVE affecting several products produces N entries with
    # identical external_ids. Last-write-wins so the surviving entry carries
    # the most specific product tag.
    for host in merged.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id")] = v
        host["vulnerabilities"] = list(deduped.values())

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
