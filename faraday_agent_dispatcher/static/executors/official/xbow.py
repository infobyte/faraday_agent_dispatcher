#!/usr/bin/env python
"""XBOW — autonomous AI-pentester import.

Pulls findings, engagements and asset inventory from XBOW's public API
(default https://api.xbow.com/) and emits Faraday bulk-create JSON to
stdout.

Auth: Bearer API key. Sent as 'Authorization: Bearer <token>'. XBOW's
public API is limited and endpoint paths below reflect current best-effort
guesses drawn from their partner integration docs; override
XBOW_API_URL / XBOW_FINDINGS_PATH per install if the paths differ.

Modes (XBOW_MODE, comma-separated; default 'findings'):
  findings     -> {findings_path}          agent-discovered vulns -> vulns
  engagements  -> {engagements_path}       assessment runs        -> summary vulns
  assets       -> {assets_path}            registered assets      -> hosts

Env / args:
  XBOW_API_KEY          (mandatory)
  XBOW_API_URL          (optional) — default https://api.xbow.com
  XBOW_MODE             (optional) — default 'findings'
  XBOW_FINDINGS_PATH    (optional) — default /v1/findings
  XBOW_ENGAGEMENTS_PATH (optional) — default /v1/engagements
  XBOW_ASSETS_PATH      (optional) — default /v1/assets
  XBOW_PAGE_SIZE        (optional) — default 100
  XBOW_MAX_PAGES        (optional) — default 50
  XBOW_MIN_SEVERITY     (optional) — default 'medium'
"""

from __future__ import annotations

import json
import os
import sys
import time

import requests

VALID_MODES = {"findings", "engagements", "assets"}
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

XBOW_SEVERITY_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
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
        log(f"XBOW_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return text


def _severity(xbow_value, default="medium"):
    text = str(xbow_value or "").strip().lower()
    return XBOW_SEVERITY_TO_FARADAY.get(text, default)


def _fetch(base, token, path, params, page_size, max_pages):
    url = f"{base.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    page = 1
    cursor = None
    for _ in range(max_pages):
        q = dict(params)
        q["limit"] = page_size
        if cursor:
            q["cursor"] = cursor
        else:
            q["page"] = page
        for attempt in range(MAX_429_RETRIES + 1):
            r = requests.get(url, headers=headers, params=q, timeout=60)
            if r.status_code == 429 and attempt < MAX_429_RETRIES:
                log(f"XBOW 429 on {path}; sleeping {RETRY_429_SLEEP}s")
                time.sleep(RETRY_429_SLEEP)
                continue
            break
        if r.status_code != 200:
            log(f"XBOW {path} HTTP {r.status_code}: {r.text[:300]}")
            return
        try:
            body = r.json()
        except ValueError:
            log(f"XBOW {path} returned non-JSON: {r.text[:200]!r}")
            return
        rows = body.get("data") or body.get("results") or body.get("items") or (body if isinstance(body, list) else [])
        if not rows:
            return
        for row in rows:
            yield row
        cursor = body.get("next_cursor") or body.get("nextCursor") if isinstance(body, dict) else None
        if not cursor and len(rows) < page_size:
            return
        page += 1


def _host_key(asset):
    if not isinstance(asset, dict):
        return None, None
    ip = asset.get("ipAddress") or asset.get("ip") or "0.0.0.0"
    hostname = (
        asset.get("hostname")
        or asset.get("host")
        or asset.get("name")
        or asset.get("url")
        or asset.get("id")
        or "unknown-xbow-asset"
    )
    return ip, str(hostname)


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
        "tool": "xbow",
        "tags": tags or [],
    }


def _fetch_findings(base, token, findings_path, page_size, max_pages, min_severity, hosts):
    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    for row in _fetch(base, token, findings_path, {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        severity = _severity(row.get("severity") or row.get("risk"))
        if SEVERITY_ORDER[severity] < floor:
            continue
        finding_id = row.get("id") or row.get("findingId") or ""
        title = row.get("title") or row.get("name") or f"XBOW finding {finding_id}"
        desc_parts = []
        if row.get("description"):
            desc_parts.append(row["description"])
        if row.get("proof_of_concept") or row.get("reproduction"):
            desc_parts.append("PoC: " + str(row.get("proof_of_concept") or row.get("reproduction")))
        if row.get("remediation"):
            desc_parts.append("Remediation: " + str(row["remediation"]))
        if row.get("agent") or row.get("attacker"):
            desc_parts.append(f"Agent: {row.get('agent') or row.get('attacker')}")
        refs = []
        for cve in row.get("cves") or ([row["cve"]] if row.get("cve") else []):
            if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                refs.append({"name": cve.upper(), "type": "other"})
        for cwe in row.get("cwes") or []:
            refs.append({"name": f"CWE-{cwe}", "type": "other"})
        for u in row.get("references") or []:
            if isinstance(u, str):
                refs.append({"name": u, "type": "other"})
        vuln = _make_vuln(
            name=f"[AGENT] {title}",
            desc="\n".join(desc_parts) or "XBOW finding (no description).",
            severity=severity,
            refs=refs,
            external_id=f"xbow:finding:{finding_id}" if finding_id else "",
            tags=["agent:xbow"],
        )
        target_obj = row.get("target") or row.get("asset") or {}
        ip, hostname = _host_key(target_obj)
        if not target_obj:
            _add_vuln(
                hosts,
                "agent:xbow:global",
                "agent-xbow",
                "XBOW findings not scoped to a single asset",
                vuln,
            )
        else:
            _add_vuln(hosts, ip, hostname, f"XBOW-tested asset: {hostname}", vuln)
        kept += 1
    log(f"XBOW: kept {kept} findings above floor='{min_severity}'.")


def _fetch_engagements(base, token, engagements_path, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, engagements_path, {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        eng_id = row.get("id") or ""
        target_obj = row.get("target") or row.get("asset") or {}
        ip, hostname = _host_key(target_obj)
        if not target_obj:
            ip, hostname = "agent:xbow:engagements", "xbow-engagements"
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"XBOW engagement against {hostname}",
            _make_vuln(
                name=f"[AGENT] XBOW engagement {eng_id} ({row.get('status', '')})",
                desc=(
                    f"Engagement id: {eng_id}\n"
                    f"Status: {row.get('status', '')}\n"
                    f"Started: {row.get('started_at', '')}\n"
                    f"Finished: {row.get('finished_at', '')}\n"
                    f"Findings: {row.get('finding_count', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"xbow:engagement:{eng_id}",
                tags=["agent:xbow:engagement"],
            ),
        )
        seen += 1
    log(f"XBOW: registered {seen} engagements.")


def _fetch_assets(base, token, assets_path, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, assets_path, {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        ip, hostname = _host_key(row)
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"XBOW-monitored asset ({row.get('type', 'asset')})",
            _make_vuln(
                name="[AGENT] XBOW-monitored asset",
                desc=(
                    f"Type: {row.get('type', '')}\n" f"URL: {row.get('url', '')}\n" f"Owner: {row.get('owner', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"xbow:asset:{row.get('id', '')}",
                tags=["agent:xbow:asset-inventory"],
            ),
        )
        seen += 1
    log(f"XBOW: registered {seen} assets.")


def main():
    token = _cfg("XBOW_API_KEY")
    if not token:
        log("XBOW_API_KEY is required.")
        sys.exit(1)

    base = _cfg("XBOW_API_URL", "https://api.xbow.com").rstrip("/")
    modes_raw = _cfg("XBOW_MODE", "findings")
    modes = [m.strip().lower() for m in modes_raw.split(",") if m.strip()]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        log(f"Invalid XBOW_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    findings_path = _cfg("XBOW_FINDINGS_PATH", "/v1/findings")
    engagements_path = _cfg("XBOW_ENGAGEMENTS_PATH", "/v1/engagements")
    assets_path = _cfg("XBOW_ASSETS_PATH", "/v1/assets")
    page_size = _safe_int(_cfg("XBOW_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    max_pages = _safe_int(_cfg("XBOW_MAX_PAGES"), DEFAULT_MAX_PAGES)
    min_severity = _validate_min_severity(_cfg("XBOW_MIN_SEVERITY"))

    hosts: dict = {}
    if "findings" in modes:
        _fetch_findings(base, token, findings_path, page_size, max_pages, min_severity, hosts)
    if "engagements" in modes:
        _fetch_engagements(base, token, engagements_path, page_size, max_pages, hosts)
    if "assets" in modes:
        _fetch_assets(base, token, assets_path, page_size, max_pages, hosts)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"XBOW: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
