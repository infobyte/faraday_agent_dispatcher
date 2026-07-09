#!/usr/bin/env python
"""Strix.ai — autonomous AI-pentester import.

Pulls findings, scans and target inventory from Strix.ai's public REST API
(https://api.strix.ai/v1/) and emits Faraday bulk-create JSON to stdout.

Auth: Bearer PAT (`strix_pat_<...>`). Minted at Strix.ai dashboard ->
Settings -> API Keys. Docs: https://docs.strix.ai/.

Modes (STRIX_MODE, comma-separated; default 'findings'):
  findings  -> /v1/findings   AI-agent-discovered vulns  -> Faraday vulns
  scans     -> /v1/scans      last N scan runs           -> summary vulns
  targets   -> /v1/targets    assets registered in Strix -> Faraday hosts

Env / args:
  STRIX_API_KEY      (mandatory) — PAT prefixed 'strix_pat_'
  STRIX_API_URL      (optional)  — default https://api.strix.ai
  STRIX_MODE         (optional)  — default 'findings'
  STRIX_TARGET       (optional)  — restrict findings to one target id
  STRIX_STATE        (optional)  — filter, default 'open'; also 'confirmed', 'triaged', 'all'
  STRIX_PAGE_SIZE    (optional)  — default 100
  STRIX_MAX_PAGES    (optional)  — default 50
  STRIX_MIN_SEVERITY (optional)  — default 'medium'
"""

from __future__ import annotations

import json
import os
import sys
import time

import requests

VALID_MODES = {"findings", "scans", "targets"}
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

STRIX_SEVERITY_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "note": "info",
}

DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 50
RETRY_429_SLEEP = 30
MAX_429_RETRIES = 3


def log(msg):
    print(msg, file=sys.stderr)


def _cfg(name, default=""):
    return os.environ.get(f"EXECUTOR_CONFIG_{name}") or os.environ.get(name) or default


def _safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _validate_min_severity(value):
    if not value:
        return "medium"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"STRIX_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return text


def _severity(strix_value, default="medium"):
    text = str(strix_value or "").strip().lower()
    return STRIX_SEVERITY_TO_FARADAY.get(text, default)


def _fetch(base, token, path, params, page_size, max_pages):
    url = f"{base.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    cursor = None
    page = 1
    for _ in range(max_pages):
        q = dict(params)
        q["limit"] = page_size
        # Strix docs suggest either cursor-based or page-based; we set both and
        # the server ignores whichever it doesn't understand.
        if cursor:
            q["cursor"] = cursor
        else:
            q["page"] = page
        for attempt in range(MAX_429_RETRIES + 1):
            r = requests.get(url, headers=headers, params=q, timeout=60)
            if r.status_code == 429 and attempt < MAX_429_RETRIES:
                log(f"Strix 429 on {path}; sleeping {RETRY_429_SLEEP}s")
                time.sleep(RETRY_429_SLEEP)
                continue
            break
        if r.status_code != 200:
            log(f"Strix {path} HTTP {r.status_code}: {r.text[:300]}")
            return
        try:
            body = r.json()
        except ValueError:
            log(f"Strix {path} returned non-JSON: {r.text[:200]!r}")
            return
        rows = body.get("data") or body.get("results") or body.get("items") or []
        if not rows:
            return
        for row in rows:
            yield row
        cursor = body.get("next_cursor") or body.get("nextCursor") or (body.get("pagination") or {}).get("next_cursor")
        if not cursor and len(rows) < page_size:
            return
        page += 1


def _host_key(target):
    if not isinstance(target, dict):
        return None, None
    ip = target.get("ipAddress") or target.get("ip") or "0.0.0.0"
    hostname = (
        target.get("hostname")
        or target.get("host")
        or target.get("name")
        or target.get("url")
        or target.get("id")
        or "unknown-strix-target"
    )
    return ip, hostname


def _empty_host(ip, hostname, description):
    return {
        "ip": ip,
        "description": description,
        "hostnames": [hostname] if hostname else [],
        "vulnerabilities": [],
    }


def _add_vuln(hosts, ip, hostname, description, vuln):
    entry = hosts.get(ip)
    if entry is None:
        entry = _empty_host(ip, hostname, description)
        hosts[ip] = entry
    elif hostname and hostname not in entry["hostnames"]:
        entry["hostnames"].append(hostname)
    entry["vulnerabilities"].append(vuln)


def _make_vuln(name, desc, severity, refs, external_id, tags=None):
    return {
        "name": name,
        "desc": desc,
        "severity": severity,
        "type": "Vulnerability",
        "refs": refs,
        "data": "",
        "external_id": external_id,
        "tool": "strix",
        "tags": tags or [],
    }


def _fetch_findings(base, token, target, state, page_size, max_pages, min_severity, hosts):
    params = {}
    if target:
        params["target_id"] = target
    if state and state != "all":
        params["state"] = state
    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    for row in _fetch(base, token, "/v1/findings", params, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        severity = _severity(row.get("severity") or row.get("risk"))
        if SEVERITY_ORDER[severity] < floor:
            continue
        finding_id = row.get("id") or row.get("findingId") or ""
        title = row.get("title") or row.get("name") or f"Strix finding {finding_id}"
        desc_parts = []
        if row.get("description"):
            desc_parts.append(row["description"])
        if row.get("proof_of_concept") or row.get("poc"):
            desc_parts.append("PoC: " + str(row.get("proof_of_concept") or row.get("poc")))
        if row.get("remediation") or row.get("mitigation"):
            desc_parts.append("Remediation: " + str(row.get("remediation") or row.get("mitigation")))
        if row.get("agent"):
            desc_parts.append(f"Agent: {row.get('agent')}")
        if row.get("scan_id"):
            desc_parts.append(f"Scan: {row.get('scan_id')}")
        refs = []
        for cve in row.get("cves") or row.get("cve") or []:
            if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                refs.append({"name": cve.upper(), "type": "cve"})
        for cwe in row.get("cwes") or row.get("cwe") or []:
            refs.append({"name": f"CWE-{cwe}", "type": "other"})
        for url_ref in row.get("references") or []:
            if isinstance(url_ref, str):
                refs.append({"name": url_ref, "type": "url"})
        vuln = _make_vuln(
            name=f"[AGENT] {title}",
            desc="\n".join(desc_parts) or "Strix.ai finding (no description).",
            severity=severity,
            refs=refs,
            external_id=f"strix:finding:{finding_id}" if finding_id else "",
            tags=["agent:strix"],
        )
        target_obj = row.get("target") or row.get("asset") or {}
        ip, hostname = _host_key(target_obj)
        if not target_obj:
            _add_vuln(
                hosts,
                "agent:strix:global",
                "agent-strix",
                "Strix findings not scoped to a single asset",
                vuln,
            )
        else:
            _add_vuln(hosts, ip, hostname, f"Strix.ai-tested asset: {hostname}", vuln)
        kept += 1
    log(f"Strix: kept {kept} findings above floor='{min_severity}'.")


def _fetch_scans(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/v1/scans", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        scan_id = row.get("id") or ""
        status = row.get("status") or row.get("state") or ""
        target_obj = row.get("target") or row.get("asset") or {}
        ip, hostname = _host_key(target_obj)
        if not target_obj:
            ip, hostname = "agent:strix:scans", "strix-scans"
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"Strix.ai scan against {hostname}",
            _make_vuln(
                name=f"[AGENT] Strix.ai scan {scan_id} ({status})",
                desc=(
                    f"Scan id: {scan_id}\n"
                    f"Status: {status}\n"
                    f"Started: {row.get('started_at', '')}\n"
                    f"Finished: {row.get('finished_at', '')}\n"
                    f"Findings: {row.get('finding_count', row.get('findings_count', ''))}"
                ),
                severity="info",
                refs=[],
                external_id=f"strix:scan:{scan_id}",
                tags=["agent:strix:scan"],
            ),
        )
        seen += 1
    log(f"Strix: registered {seen} scans.")


def _fetch_targets(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/v1/targets", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        ip, hostname = _host_key(row)
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"Strix.ai target ({row.get('type', 'asset')})",
            _make_vuln(
                name="[AGENT] Strix.ai-monitored target",
                desc=(
                    f"Type: {row.get('type', '')}\n" f"URL: {row.get('url', '')}\n" f"Owner: {row.get('owner', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"strix:target:{row.get('id', '')}",
                tags=["agent:strix:target-inventory"],
            ),
        )
        seen += 1
    log(f"Strix: registered {seen} targets.")


def main():
    token = _cfg("STRIX_API_KEY")
    if not token:
        log("STRIX_API_KEY is required (PAT prefixed 'strix_pat_').")
        sys.exit(1)

    base = _cfg("STRIX_API_URL", "https://api.strix.ai").rstrip("/")
    modes_raw = _cfg("STRIX_MODE", "findings")
    modes = [m.strip().lower() for m in modes_raw.split(",") if m.strip()]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        log(f"Invalid STRIX_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    target = _cfg("STRIX_TARGET")
    state = _cfg("STRIX_STATE", "open")
    page_size = _safe_int(_cfg("STRIX_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    max_pages = _safe_int(_cfg("STRIX_MAX_PAGES"), DEFAULT_MAX_PAGES)
    min_severity = _validate_min_severity(_cfg("STRIX_MIN_SEVERITY"))

    hosts: dict = {}
    if "findings" in modes:
        _fetch_findings(base, token, target, state, page_size, max_pages, min_severity, hosts)
    if "scans" in modes:
        _fetch_scans(base, token, page_size, max_pages, hosts)
    if "targets" in modes:
        _fetch_targets(base, token, page_size, max_pages, hosts)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"Strix: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
