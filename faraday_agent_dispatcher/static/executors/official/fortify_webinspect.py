#!/usr/bin/env python
"""Fortify WebInspect Enterprise (WIE) REST API importer.

Pulls dynamic application security testing (DAST) findings from a Fortify
WebInspect Enterprise server and emits Faraday bulk-create JSON to stdout.
Each scan's findings are grouped by target URL into Faraday hosts (one host
per affected web origin); findings without a resolvable URL fall back to the
scan's start URL or a synthetic ``0.0.0.0`` host so the data is still
imported.

Endpoints used:
  GET /api/v2/scans                            -> list scans (paginated via
      ``offset`` / ``limit``); a single scan via /api/v2/scans/{id} when
      WEBINSPECT_SCAN_ID is set.
  GET /api/v2/scans/{id}/vulnerabilities       -> per-scan vulnerabilities
      (paginated). Each entry carries severity (numeric 0-4 / string),
      check / probe metadata, request URL + HTTP method + parameter,
      attack string, evidence, recommendation, CWE / WASC / OWASP refs.

Auth: WEBINSPECT_TOKEN holds the API token returned by WebInspect
Enterprise's ``/api/v2/auth`` endpoint (the same token printed by the WIE
console). It is sent verbatim as the ``Authorization`` header — WIE expects
the raw token, no scheme prefix — unless the supplied value already starts
with ``Bearer`` or ``FortifyToken``, in which case it's forwarded as-is.
WEBINSPECT_HOST is the WIE manager base URL (e.g.
https://webinspect.corp.example.com); the executor accepts both with and
without the documented ``/webinspect`` context path.
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

# WebInspect's severity scale is the same 0-4 ladder Fortify uses across
# its products: 0 = Best Practice (info), 1 = Low, 2 = Medium, 3 = High,
# 4 = Critical. The /vulnerabilities endpoint usually returns the numeric
# code; some WIE versions surface the string form instead.
WEBINSPECT_NUMERIC_SEVERITY = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

WEBINSPECT_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "best practice": "info",
    "best_practice": "info",
    "bestpractice": "info",
    "information": "info",
    "informational": "info",
    "info": "info",
    "none": "info",
}


def log(msg):
    print(f"{datetime.utcnow()} - FortifyWebInspect: {msg}", file=sys.stderr, flush=True)


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


def severity_from_webinspect(value):
    """Map WebInspect's severity field to a Faraday severity bucket.

    Accepts either WIE's 0-4 numeric ladder or its string form
    (Critical / High / Medium / Low / Best Practice). Numeric values are
    interpreted as the WIE severity code, NOT as a CVSS score.
    """
    if value is None or value == "":
        return "info"
    if isinstance(value, bool):
        return "info"
    if isinstance(value, int):
        return WEBINSPECT_NUMERIC_SEVERITY.get(value, "info")
    if isinstance(value, float):
        return WEBINSPECT_NUMERIC_SEVERITY.get(int(value), "info")
    text = str(value).strip()
    if not text:
        return "info"
    lower = text.lower()
    if lower in WEBINSPECT_STRING_SEVERITY:
        return WEBINSPECT_STRING_SEVERITY[lower]
    try:
        return WEBINSPECT_NUMERIC_SEVERITY.get(int(float(text)), "info")
    except ValueError:
        return "info"


def status_from_webinspect(vuln):
    """Derive Faraday status from WebInspect lifecycle / audit flags.

    WebInspect findings carry a few lifecycle markers depending on
    version: a ``removed`` boolean (finding no longer present in the
    latest scan), a ``status`` string (open / fixed / closed) and
    analyst-applied flags ``falsePositive`` / ``ignored`` / ``hidden``.
    Anything analyst-suppressed maps to Faraday ``risk-accepted``;
    removed / fixed maps to ``closed``; everything else stays ``open``.
    """
    if vuln.get("removed") is True:
        return "closed"
    if vuln.get("falsePositive") or vuln.get("isFalsePositive"):
        return "risk-accepted"
    if vuln.get("ignored") or vuln.get("hidden") or vuln.get("suppressed"):
        return "risk-accepted"
    status_raw = vuln.get("status") or vuln.get("state")
    if status_raw:
        text = str(status_raw).strip().lower()
        if text in ("closed", "fixed", "resolved", "patched", "mitigated"):
            return "closed"
        if text in (
            "accepted",
            "risk_accepted",
            "risk-accepted",
            "false_positive",
            "false-positive",
            "falsepositive",
            "ignored",
            "suppressed",
        ):
            return "risk-accepted"
    return "open"


def build_auth_header(token):
    """Forward the WIE token verbatim as the ``Authorization`` header value.

    WebInspect Enterprise expects the raw API token (no ``Bearer`` /
    ``FortifyToken`` prefix). SSO-backed deployments that need a different
    scheme can bake it into the WEBINSPECT_TOKEN value (e.g. ``Bearer xyz``)
    and it'll be forwarded unchanged.
    """
    return token


def normalize_base_url(host):
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"GET {path} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). WEBINSPECT_TOKEN expired or invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the token's role.")
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


def extract_list(body, *keys):
    """Pluck a list out of a WebInspect REST response.

    WIE wraps list responses in ``{"data": [...], "totalCount": N}`` on
    newer builds; older installs return ``{"items": [...]}`` or the bare
    list. ``data`` may also be the single-resource shape when a /{id}
    endpoint is hit, in which case it's a dict not a list.
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys:
            value = body.get(key)
            if isinstance(value, list):
                return value
        for candidate in ("data", "items", "results", "value"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, base_params, *list_keys):
    """Paginate WebInspect list endpoints via ``offset`` + ``limit``."""
    results = []
    offset = 0
    for _ in range(MAX_PAGES):
        params = dict(base_params or {})
        params["offset"] = offset
        params["limit"] = PAGE_SIZE
        body = get_page(base_url, path, headers, params)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("totalCount") or body.get("total") or body.get("count")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return results


def get_scans(base_url, headers, scan_id):
    if scan_id:
        body = get_page(base_url, f"/api/v2/scans/{scan_id}", headers, {})
        if isinstance(body, dict):
            data = body.get("data")
            if isinstance(data, dict):
                return [data]
            if body.get("id") is not None or body.get("scanId") is not None:
                return [body]
        return []
    return collect(base_url, "/api/v2/scans", headers, {}, "scans")


def get_vulnerabilities(base_url, headers, scan_id):
    return collect(
        base_url,
        f"/api/v2/scans/{scan_id}/vulnerabilities",
        headers,
        {},
        "vulnerabilities",
    )


def collect_refs(vuln):
    refs = []
    seen = set()

    def add(name):
        if not name:
            return
        text = str(name).strip()
        if not text or text in seen:
            return
        seen.add(text)
        refs.append({"name": text, "type": "other"})

    for cwe_field in ("cwe", "cweId", "cweIds", "cwes"):
        value = vuln.get(cwe_field)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if isinstance(entry, dict):
                    cwe_val = entry.get("id") or entry.get("name") or entry.get("value")
                    if cwe_val:
                        add(f"CWE-{str(cwe_val).lstrip('CWE-').lstrip('cwe-')}")
                elif entry:
                    add(f"CWE-{str(entry).lstrip('CWE-').lstrip('cwe-')}")
        else:
            add(f"CWE-{str(value).lstrip('CWE-').lstrip('cwe-')}")
    for wasc_field in ("wasc", "wascId", "wascIds"):
        value = vuln.get(wasc_field)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if entry:
                    add(f"WASC-{entry}")
        else:
            add(f"WASC-{value}")
    for owasp_field in ("owasp", "owaspId", "owaspIds", "owaspCategory"):
        value = vuln.get(owasp_field)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if entry:
                    add(f"OWASP: {entry}")
        else:
            add(f"OWASP: {value}")
    check_id = vuln.get("checkId") or vuln.get("checkTypeId")
    if check_id:
        add(f"WebInspectCheck-{check_id}")
    for entry in vuln.get("references") or vuln.get("refs") or vuln.get("links") or []:
        if isinstance(entry, str):
            add(entry)
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("name") or entry.get("value")
            add(value)
    return refs


def collect_cves(vuln):
    cves = []
    seen = set()
    candidates = []
    for key in ("cve", "cveId", "cveName", "cve_id"):
        value = vuln.get(key)
        if value:
            candidates.append(value)
    for entry in vuln.get("cves") or []:
        if isinstance(entry, str):
            candidates.append(entry)
        elif isinstance(entry, dict):
            value = entry.get("name") or entry.get("id") or entry.get("value")
            if value:
                candidates.append(value)
    for value in candidates:
        text = str(value).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)
    return cves


def build_vulnerability(vuln):
    severity = severity_from_webinspect(vuln.get("severity") or vuln.get("severityLevel"))
    status = status_from_webinspect(vuln)
    check_name = (
        vuln.get("checkName")
        or vuln.get("name")
        or vuln.get("title")
        or vuln.get("vulnerabilityName")
        or f"WebInspect finding {vuln.get('id', '')}"
    )
    name = f"[DAST] {check_name}"

    desc_parts = []
    description = (
        vuln.get("description") or vuln.get("summary") or vuln.get("synopsis") or vuln.get("executiveSummary")
    )
    if description:
        desc_parts.append(str(description))
    implication = vuln.get("implication") or vuln.get("impact")
    if implication:
        desc_parts.append(f"implication: {implication}")

    method = vuln.get("method") or vuln.get("httpMethod") or vuln.get("requestMethod")
    url = vuln.get("url") or vuln.get("requestUrl") or vuln.get("targetUrl") or vuln.get("location")
    if url:
        if method:
            desc_parts.append(f"request: {method} {url}")
        else:
            desc_parts.append(f"url: {url}")
    elif method:
        desc_parts.append(f"method: {method}")

    parameter = vuln.get("parameter") or vuln.get("vulnerableParameter") or vuln.get("parameterName")
    if parameter:
        param_type = vuln.get("parameterType") or vuln.get("paramType")
        if param_type:
            desc_parts.append(f"parameter: {parameter} ({param_type})")
        else:
            desc_parts.append(f"parameter: {parameter}")

    attack = vuln.get("attackString") or vuln.get("attack") or vuln.get("payload")
    if attack:
        desc_parts.append(f"attack: {attack}")

    probe = vuln.get("probe") or vuln.get("probeDescription")
    if probe:
        desc_parts.append(f"probe: {probe}")

    instance_id = vuln.get("vulnerabilityInstanceId") or vuln.get("instanceId") or vuln.get("uniqueId")
    if instance_id:
        desc_parts.append(f"instanceId: {instance_id}")

    evidence = vuln.get("evidence") or vuln.get("proof") or vuln.get("attackResponse") or vuln.get("responseContent")
    if evidence and not isinstance(evidence, (dict, list)):
        text = str(evidence)
        desc_parts.append(f"evidence: {text[:500]}{'...' if len(text) > 500 else ''}")

    resolution = vuln.get("recommendation") or vuln.get("fix") or vuln.get("remediation") or vuln.get("solution") or ""

    request_data = vuln.get("requestRaw") or vuln.get("rawRequest") or vuln.get("request")
    if isinstance(request_data, dict):
        request_data = request_data.get("data") or request_data.get("content") or ""

    return {
        "name": str(name).strip()[:200] or f"WebInspect finding {vuln.get('id', '')}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(vuln.get("id") or vuln.get("vulnerabilityId") or vuln.get("uniqueId") or instance_id or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": str(request_data) if request_data else "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": {},
        "tags": ["fortify_webinspect", "dast"],
    }


def target_key(vuln, fallback_url):
    """Stable per-target key used to group vulnerabilities into hosts.

    Each WebInspect finding carries the offending request URL; we
    collapse on hostname so all findings against the same origin land
    on the same Faraday host. Findings without a URL fall back to the
    scan's start URL.
    """
    url = vuln.get("url") or vuln.get("requestUrl") or vuln.get("targetUrl") or vuln.get("location")
    if not url:
        url = fallback_url
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname
    if host:
        return ("host", host.lower())
    return ("host", url.strip().lower())


def build_host(key, sample_url, vulns, scan_meta):
    _, hostname = key
    desc_parts = []
    scan_id = scan_meta.get("scan_id") if scan_meta else None
    if scan_id is not None:
        desc_parts.append(f"scan_id={scan_id}")
    scan_name = scan_meta.get("scan_name") if scan_meta else None
    if scan_name:
        desc_parts.append(f"scan={scan_name}")
    policy = scan_meta.get("policy") if scan_meta else None
    if policy:
        desc_parts.append(f"policy={policy}")
    if sample_url:
        desc_parts.append(f"start_url={sample_url}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def synthetic_host(vulns, scan_meta):
    desc_parts = ["WebInspect findings without a resolvable URL"]
    scan_id = scan_meta.get("scan_id") if scan_meta else None
    if scan_id is not None:
        desc_parts.append(f"scan_id={scan_id}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def scan_meta_from(scan):
    if not isinstance(scan, dict):
        return {}
    return {
        "scan_id": scan.get("id") or scan.get("scanId") or scan.get("uuid"),
        "scan_name": scan.get("name") or scan.get("scanName") or scan.get("title"),
        "start_url": scan.get("startUrl") or scan.get("startURL") or scan.get("targetUrl"),
        "policy": scan.get("policyName") or scan.get("policy"),
    }


def main():
    started = time.time()
    host = env("WEBINSPECT_HOST", required=True).rstrip("/")
    token = env("WEBINSPECT_TOKEN", required=True)
    scan_id_arg = env("EXECUTOR_CONFIG_WEBINSPECT_SCAN_ID")

    base_url = normalize_base_url(host)
    headers = {
        "Authorization": build_auth_header(token),
        "Accept": "application/json",
    }

    scans = get_scans(base_url, headers, scan_id_arg)
    if not scans and scan_id_arg:
        log(f"Scan {scan_id_arg} not found or not accessible")
        scans = [{"id": scan_id_arg}]
    log(f"Processing {len(scans)} scan(s) (scan_id={scan_id_arg or 'all'})")

    hosts = []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        meta = scan_meta_from(scan)
        sid = meta.get("scan_id")
        if sid is None:
            continue
        raw_vulns = get_vulnerabilities(base_url, headers, sid)
        by_target = {}
        orphan = []
        for raw in raw_vulns:
            if not isinstance(raw, dict):
                continue
            built = build_vulnerability(raw)
            key = target_key(raw, meta.get("start_url"))
            if key is None:
                orphan.append(built)
                continue
            bucket = by_target.setdefault(key, {"sample_url": None, "vulns": []})
            if bucket["sample_url"] is None:
                bucket["sample_url"] = raw.get("url") or meta.get("start_url")
            bucket["vulns"].append(built)
        for key, bucket in by_target.items():
            hosts.append(build_host(key, bucket["sample_url"], bucket["vulns"], meta))
        if orphan:
            hosts.append(synthetic_host(orphan, meta))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "fortify_webinspect",
            "command": "fortify_webinspect",
            "params": f"scan_id={scan_id_arg or 'all'}",
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
