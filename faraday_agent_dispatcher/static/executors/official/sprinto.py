#!/usr/bin/env python
"""Sprinto — GRC / continuous-compliance import.

Pulls failing checks and asset/personnel inventory from Sprinto's public
REST API (https://api.sprinto.com/v1/) and emits Faraday bulk-create JSON
to stdout.

Auth: Bearer API key. Minted at Sprinto admin -> API Access.

Modes (SPRINTO_MODE, comma-separated; default 'checks'):
  checks     -> /v1/checks       failing checks -> vulns
  assets     -> /v1/assets       monitored assets -> Faraday hosts
  personnel  -> /v1/personnel    workforce inventory -> synthetic hosts

Env / args:
  SPRINTO_API_KEY     (mandatory)
  SPRINTO_API_URL     (optional)   default https://api.sprinto.com
  SPRINTO_MODE        (optional)   default 'checks'
  SPRINTO_FRAMEWORK   (optional)   restrict to a Sprinto framework key
  SPRINTO_PAGE_SIZE   (optional)   default 100
  SPRINTO_MAX_PAGES   (optional)   default 50 (= 5k rows/mode)
  SPRINTO_MIN_SEVERITY (optional)  default 'medium'
"""

from __future__ import annotations

import json
import os
import sys
import time

import requests

VALID_MODES = {"checks", "assets", "personnel"}
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SPRINTO_SEVERITY_TO_FARADAY = {
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
        log(f"SPRINTO_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return text


def _severity(sprinto_value, default="medium"):
    text = str(sprinto_value or "").strip().lower()
    return SPRINTO_SEVERITY_TO_FARADAY.get(text, default)


def _fetch(base, token, path, params, page_size, max_pages):
    url = f"{base.rstrip('/')}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    offset = 0
    for _ in range(max_pages):
        q = dict(params)
        q["limit"] = page_size
        q["offset"] = offset
        for attempt in range(MAX_429_RETRIES + 1):
            r = requests.get(url, headers=headers, params=q, timeout=60)
            if r.status_code == 429 and attempt < MAX_429_RETRIES:
                log(f"Sprinto 429 on {path}; sleeping {RETRY_429_SLEEP}s")
                time.sleep(RETRY_429_SLEEP)
                continue
            break
        if r.status_code != 200:
            log(f"Sprinto {path} HTTP {r.status_code}: {r.text[:300]}")
            return
        try:
            body = r.json()
        except ValueError:
            log(f"Sprinto {path} returned non-JSON: {r.text[:200]!r}")
            return
        rows = body.get("data") or body.get("results") or []
        if not rows:
            return
        for row in rows:
            yield row
        # Sprinto returns 'total' + 'offset' so we detect end-of-stream via
        # short page rather than a hasNext flag.
        if len(rows) < page_size:
            return
        offset += page_size


def _host_key(asset):
    if not isinstance(asset, dict):
        return None, None
    ip = asset.get("ipAddress") or asset.get("externalId") or "0.0.0.0"
    hostname = asset.get("name") or asset.get("displayName") or asset.get("id") or "unknown-sprinto-asset"
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
        "tool": "sprinto",
        "tags": tags or [],
    }


def _fetch_checks(base, token, framework, page_size, max_pages, min_severity, hosts):
    params = {"status": "failing"}
    if framework:
        params["framework"] = framework
    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    for row in _fetch(base, token, "/v1/checks", params, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").lower()
        if status == "passing":
            continue
        severity = _severity(row.get("severity") or row.get("riskLevel"), default="high")
        if SEVERITY_ORDER[severity] < floor:
            continue
        check_id = row.get("id") or row.get("checkId") or ""
        title = row.get("name") or row.get("title") or f"Sprinto check {check_id}"
        desc_parts = []
        if row.get("description"):
            desc_parts.append(row["description"])
        if row.get("failureReason"):
            desc_parts.append(f"Failure: {row['failureReason']}")
        if row.get("framework"):
            desc_parts.append(f"Framework: {row['framework']}")
        if row.get("lastRunAt"):
            desc_parts.append(f"Last run: {row['lastRunAt']}")
        refs = []
        for fw in row.get("frameworks") or []:
            if isinstance(fw, dict) and fw.get("name"):
                refs.append({"name": f"Sprinto-Framework-{fw['name']}", "type": "other"})
        for ctrl in row.get("controls") or []:
            if isinstance(ctrl, dict) and ctrl.get("id"):
                refs.append({"name": f"Sprinto-Control-{ctrl['id']}", "type": "other"})
        vuln = _make_vuln(
            name=f"[GRC] {title}",
            desc="\n".join(desc_parts) or "Sprinto failing check (no description).",
            severity=severity,
            refs=refs,
            external_id=f"sprinto:check:{check_id}" if check_id else "",
            tags=["grc:sprinto"],
        )
        assets = row.get("assets") or row.get("affectedAssets") or []
        if assets:
            for asset in assets:
                ip, hostname = _host_key(asset)
                _add_vuln(
                    hosts,
                    ip,
                    hostname,
                    f"Sprinto-tracked asset: {hostname}",
                    dict(vuln),
                )
        else:
            _add_vuln(
                hosts,
                "grc:sprinto:global",
                "grc-sprinto",
                "Sprinto control-level findings not scoped to a single asset",
                vuln,
            )
        kept += 1
    log(f"Sprinto: kept {kept} failing checks above floor='{min_severity}'.")


def _fetch_assets(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/v1/assets", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        ip, hostname = _host_key(row)
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"Sprinto-monitored asset ({row.get('type', 'asset')})",
            _make_vuln(
                name="[GRC] Sprinto-monitored asset",
                desc=(
                    f"Type: {row.get('type', '')}\n"
                    f"Owner: {row.get('owner', '')}\n"
                    f"Provider: {row.get('provider', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"sprinto:asset:{row.get('id', '')}",
                tags=["grc:sprinto:asset-inventory"],
            ),
        )
        seen += 1
    log(f"Sprinto: registered {seen} monitored assets.")


def _fetch_personnel(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/v1/personnel", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        person_id = row.get("id") or ""
        display = row.get("fullName") or row.get("displayName") or row.get("email") or f"sprinto-person-{person_id}"
        _add_vuln(
            hosts,
            f"sprinto:person:{person_id}",
            display,
            "Sprinto-tracked workforce member",
            _make_vuln(
                name="[GRC] Sprinto workforce member",
                desc=(
                    f"Email: {row.get('email', '')}\n"
                    f"Role: {row.get('role', '')}\n"
                    f"Status: {row.get('employmentStatus', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"sprinto:person:{person_id}",
                tags=["grc:sprinto:people-inventory"],
            ),
        )
        seen += 1
    log(f"Sprinto: registered {seen} personnel.")


def main():
    token = _cfg("SPRINTO_API_KEY")
    if not token:
        log("SPRINTO_API_KEY is required.")
        sys.exit(1)

    base = _cfg("SPRINTO_API_URL", "https://api.sprinto.com").rstrip("/")
    modes_raw = _cfg("SPRINTO_MODE", "checks")
    modes = [m.strip().lower() for m in modes_raw.split(",") if m.strip()]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        log(f"Invalid SPRINTO_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    framework = _cfg("SPRINTO_FRAMEWORK")
    page_size = _safe_int(_cfg("SPRINTO_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    max_pages = _safe_int(_cfg("SPRINTO_MAX_PAGES"), DEFAULT_MAX_PAGES)
    min_severity = _validate_min_severity(_cfg("SPRINTO_MIN_SEVERITY"))

    hosts: dict = {}
    if "checks" in modes:
        _fetch_checks(base, token, framework, page_size, max_pages, min_severity, hosts)
    if "assets" in modes:
        _fetch_assets(base, token, page_size, max_pages, hosts)
    if "personnel" in modes:
        _fetch_personnel(base, token, page_size, max_pages, hosts)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"Sprinto: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
