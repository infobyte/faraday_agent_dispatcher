#!/usr/bin/env python
"""Drata — GRC / continuous-compliance import.

Pulls failing tests and asset/personnel inventory from Drata's public REST
API (https://public-api.drata.com/public/) and emits Faraday bulk-create
JSON to stdout.

Auth: Bearer API key. Minted at Drata admin -> Company Settings -> API.
Drata scopes API keys per-workspace so DRATA_API_KEY alone is enough — no
workspace-ID needs to be passed.

Modes (DRATA_MODE, comma-separated; default 'tests'):
  tests      -> /public/tests            failing / needs-attention tests
  assets     -> /public/assets           monitored assets -> Faraday hosts
  personnel  -> /public/personnel        workforce inventory -> synthetic hosts

Env / args:
  DRATA_API_KEY     (mandatory)
  DRATA_API_URL     (optional)   default https://public-api.drata.com
  DRATA_MODE        (optional)   default 'tests'
  DRATA_FRAMEWORK   (optional)   restrict tests to a framework id/key
  DRATA_PAGE_SIZE   (optional)   default 100 (Drata max)
  DRATA_MAX_PAGES   (optional)   default 50 (= 5k rows/mode)
  DRATA_MIN_SEVERITY (optional)  default 'medium'
"""

from __future__ import annotations

import json
import os
import sys
import time

import requests

VALID_MODES = {"tests", "assets", "personnel"}
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Drata uses severity + status. Failing tests default to 'high' when Drata
# ships nothing else; we still let the caller override via DRATA_MIN_SEVERITY.
DRATA_SEVERITY_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    "unknown": "medium",
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
        log(f"DRATA_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return text


def _severity(drata_value, default="medium"):
    text = str(drata_value or "").strip().lower()
    return DRATA_SEVERITY_TO_FARADAY.get(text, default)


def _fetch(base, token, path, params, page_size, max_pages):
    url = f"{base.rstrip('/')}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    page = 1
    for _ in range(max_pages):
        q = dict(params)
        q["limit"] = page_size
        q["page"] = page
        for attempt in range(MAX_429_RETRIES + 1):
            r = requests.get(url, headers=headers, params=q, timeout=60)
            if r.status_code == 429 and attempt < MAX_429_RETRIES:
                log(f"Drata 429 on {path}; sleeping {RETRY_429_SLEEP}s")
                time.sleep(RETRY_429_SLEEP)
                continue
            break
        if r.status_code != 200:
            log(f"Drata {path} HTTP {r.status_code}: {r.text[:300]}")
            return
        try:
            body = r.json()
        except ValueError:
            log(f"Drata {path} returned non-JSON: {r.text[:200]!r}")
            return
        # Drata returns {'data': [...], 'pagination': {'hasNextPage': bool}}
        rows = body.get("data") or []
        if not rows:
            return
        for row in rows:
            yield row
        if not (body.get("pagination") or {}).get("hasNextPage"):
            return
        page += 1


def _host_key(asset):
    if not isinstance(asset, dict):
        return None, None
    ip = asset.get("ipAddress") or asset.get("externalId") or "0.0.0.0"
    hostname = asset.get("name") or asset.get("displayName") or asset.get("id") or "unknown-drata-asset"
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
        "tool": "drata",
        "tags": tags or [],
    }


def _fetch_tests(base, token, framework, page_size, max_pages, min_severity, hosts):
    params = {}
    if framework:
        params["framework"] = framework
    # Drata separates status ('passing', 'failing', 'not_applicable') from a
    # 'needsAttention' boolean. Anything not-passing that's also flagged
    # needs-attention is what an auditor would consider open.
    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    for row in _fetch(base, token, "/public/tests", params, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").lower()
        if status == "passing":
            continue
        if status == "not_applicable":
            continue
        severity = _severity(row.get("severity"), default="high")
        if SEVERITY_ORDER[severity] < floor:
            continue
        test_id = row.get("id") or row.get("testId") or ""
        title = row.get("name") or row.get("title") or f"Drata test {test_id}"
        desc_parts = []
        if row.get("description"):
            desc_parts.append(row["description"])
        if row.get("failureReason"):
            desc_parts.append(f"Failure: {row['failureReason']}")
        if row.get("framework"):
            desc_parts.append(f"Framework: {row['framework']}")
        if row.get("lastCheckedAt"):
            desc_parts.append(f"Last checked: {row['lastCheckedAt']}")
        refs = []
        for fw in row.get("frameworks") or []:
            if isinstance(fw, dict) and fw.get("name"):
                refs.append({"name": f"Drata-Framework-{fw['name']}", "type": "other"})
        for ctrl in row.get("controls") or []:
            if isinstance(ctrl, dict) and ctrl.get("id"):
                refs.append({"name": f"Drata-Control-{ctrl['id']}", "type": "other"})
        vuln = _make_vuln(
            name=f"[GRC] {title}",
            desc="\n".join(desc_parts) or "Drata failing test (no description).",
            severity=severity,
            refs=refs,
            external_id=f"drata:test:{test_id}" if test_id else "",
            tags=["grc:drata"],
        )
        # Drata tests may point at zero or more affected assets; if none, bucket
        # under a synthetic global host so bare control failures still surface.
        assets = row.get("assets") or row.get("affectedAssets") or []
        if assets:
            for asset in assets:
                ip, hostname = _host_key(asset)
                _add_vuln(
                    hosts,
                    ip,
                    hostname,
                    f"Drata-tracked asset: {hostname}",
                    dict(vuln),
                )
        else:
            _add_vuln(
                hosts,
                "grc:drata:global",
                "grc-drata",
                "Drata control-level findings not scoped to a single asset",
                vuln,
            )
        kept += 1
    log(f"Drata: kept {kept} failing tests above floor='{min_severity}'.")


def _fetch_assets(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/public/assets", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        ip, hostname = _host_key(row)
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"Drata-monitored asset ({row.get('type', 'asset')})",
            _make_vuln(
                name="[GRC] Drata-monitored asset",
                desc=(
                    f"Type: {row.get('type', '')}\n"
                    f"Owner: {row.get('owner', '')}\n"
                    f"Provider: {row.get('provider', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"drata:asset:{row.get('id', '')}",
                tags=["grc:drata:asset-inventory"],
            ),
        )
        seen += 1
    log(f"Drata: registered {seen} monitored assets.")


def _fetch_personnel(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/public/personnel", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        person_id = row.get("id") or ""
        display = row.get("fullName") or row.get("displayName") or row.get("email") or f"drata-person-{person_id}"
        _add_vuln(
            hosts,
            f"drata:person:{person_id}",
            display,
            "Drata-tracked workforce member",
            _make_vuln(
                name="[GRC] Drata workforce member",
                desc=(
                    f"Email: {row.get('email', '')}\n"
                    f"Role: {row.get('role', '')}\n"
                    f"Status: {row.get('employmentStatus', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"drata:person:{person_id}",
                tags=["grc:drata:people-inventory"],
            ),
        )
        seen += 1
    log(f"Drata: registered {seen} personnel.")


def main():
    token = _cfg("DRATA_API_KEY")
    if not token:
        log("DRATA_API_KEY is required.")
        sys.exit(1)

    base = _cfg("DRATA_API_URL", "https://public-api.drata.com").rstrip("/")
    modes_raw = _cfg("DRATA_MODE", "tests")
    modes = [m.strip().lower() for m in modes_raw.split(",") if m.strip()]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        log(f"Invalid DRATA_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    framework = _cfg("DRATA_FRAMEWORK")
    page_size = _safe_int(_cfg("DRATA_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    max_pages = _safe_int(_cfg("DRATA_MAX_PAGES"), DEFAULT_MAX_PAGES)
    min_severity = _validate_min_severity(_cfg("DRATA_MIN_SEVERITY"))

    hosts: dict = {}
    if "tests" in modes:
        _fetch_tests(base, token, framework, page_size, max_pages, min_severity, hosts)
    if "assets" in modes:
        _fetch_assets(base, token, page_size, max_pages, hosts)
    if "personnel" in modes:
        _fetch_personnel(base, token, page_size, max_pages, hosts)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"Drata: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
