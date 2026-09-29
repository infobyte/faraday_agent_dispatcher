#!/usr/bin/env python
"""Vanta — GRC / continuous-compliance import.

Pulls failing tests and monitored resources from Vanta's public REST API
(https://api.vanta.com/v1/) and emits Faraday bulk-create JSON to stdout.

Auth: OAuth2 client credentials. VANTA_CLIENT_ID + VANTA_CLIENT_SECRET are
exchanged at /oauth/token for a short-lived Bearer, then reused across
calls in the same run.

Modes (VANTA_MODE, comma-separated or repeated; default 'tests'):
  tests      -> /v1/tests            failing / not-passing tests -> vulns
  resources  -> /v1/resources        monitored assets            -> hosts
  people     -> /v1/people           workforce inventory         -> hosts
                                     (severity=info, tagged people-inventory)

Each row lands as a Faraday vulnerability under either the tested asset
(when Vanta returns one) or a synthetic 'grc:vanta:global' host so bare
control failures still surface. External IDs are stable and idempotent so
re-runs don't multiply rows.

Env / args (all read from EXECUTOR_CONFIG_* first, then raw env):
  VANTA_CLIENT_ID       (mandatory)
  VANTA_CLIENT_SECRET   (mandatory)
  VANTA_API_URL         (optional)   default https://api.vanta.com
  VANTA_MODE            (optional)   default 'tests'
  VANTA_FRAMEWORK       (optional)   restrict to a Vanta framework key
                                     (e.g. 'soc2', 'iso27001', 'hipaa')
  VANTA_PAGE_SIZE       (optional)   default 100 (Vanta API max)
  VANTA_MAX_PAGES       (optional)   default 50 (= 5k rows/mode)
  VANTA_MIN_SEVERITY    (optional)   default 'medium'
"""

from __future__ import annotations

import json
import os
import sys
import time

import requests

VALID_MODES = {"tests", "resources", "people"}
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Vanta severity levels observed in test payloads.
VANTA_SEVERITY_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "not_evaluated": "info",
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
        log(f"VANTA_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return text


def _get_token(base, client_id, client_secret):
    """OAuth2 client-credentials exchange. Vanta rejects requests with anything
    but 'application/x-www-form-urlencoded' on this endpoint."""
    url = f"{base.rstrip('/')}/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "vanta-api.all:read",
    }
    r = requests.post(url, data=payload, timeout=30)
    if r.status_code != 200:
        log(f"Vanta oauth/token HTTP {r.status_code}: {r.text[:300]}")
        sys.exit(1)
    token = r.json().get("access_token")
    if not token:
        log(f"Vanta oauth/token response missing access_token: {r.text[:300]}")
        sys.exit(1)
    return token


def _fetch(base, token, path, params, page_size, max_pages):
    """Yield every row from a Vanta list endpoint. Vanta paginates with a
    'pageCursor' returned on the response envelope."""
    url = f"{base.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    cursor = None
    for _ in range(max_pages):
        q = dict(params)
        q["pageSize"] = page_size
        if cursor:
            q["pageCursor"] = cursor
        for attempt in range(MAX_429_RETRIES + 1):
            r = requests.get(url, headers=headers, params=q, timeout=60)
            if r.status_code == 429 and attempt < MAX_429_RETRIES:
                log(f"Vanta 429 on {path}; sleeping {RETRY_429_SLEEP}s")
                time.sleep(RETRY_429_SLEEP)
                continue
            break
        if r.status_code != 200:
            log(f"Vanta {path} HTTP {r.status_code}: {r.text[:300]}")
            return
        try:
            body = r.json()
        except ValueError:
            log(f"Vanta {path} returned non-JSON: {r.text[:200]!r}")
            return
        # Vanta responses are either {'results': {'data': [...], 'pageCursor':
        # X}} (newer public API) or {'data': [...], 'pageInfo': {...}}. Handle
        # both.
        results = body.get("results") or body
        rows = results.get("data") or []
        if not rows:
            return
        for row in rows:
            yield row
        page_info = results.get("pageInfo") or {}
        cursor = results.get("pageCursor") or page_info.get("endCursor")
        if not cursor:
            return


def _severity(vanta_value):
    text = str(vanta_value or "").strip().lower().replace("-", "_")
    return VANTA_SEVERITY_TO_FARADAY.get(text, "medium")


def _host_key(resource):
    """Stable host key for grouping. Prefer an IP/hostname if Vanta happens to
    ship one; otherwise fall back to a resource identifier so we still get one
    Faraday host per asset."""
    if not isinstance(resource, dict):
        return None, None
    ip = resource.get("ipAddress") or resource.get("externalId") or "0.0.0.0"
    hostname = resource.get("displayName") or resource.get("name") or resource.get("id") or "unknown-vanta-resource"
    return ip, hostname


def _empty_host(ip, hostname, description):
    return {
        "ip": ip,
        "description": description,
        "hostnames": [hostname] if hostname else [],
        "vulnerabilities": [],
    }


def _add_vuln(hosts, ip, hostname, description, vuln):
    key = ip
    entry = hosts.get(key)
    if entry is None:
        entry = _empty_host(ip, hostname, description)
        hosts[key] = entry
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
        "tool": "vanta",
        "tags": tags or [],
    }


def _fetch_tests(base, token, framework, page_size, max_pages, min_severity, hosts):
    params = {"status": "failing"}
    if framework:
        params["framework"] = framework
    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    for row in _fetch(base, token, "/v1/tests", params, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or row.get("outcome") or "").lower()
        if status in ("passing", "passed", "ok"):
            continue
        severity = _severity(row.get("severity") or row.get("riskProfile"))
        if SEVERITY_ORDER[severity] < floor:
            continue
        test_id = row.get("id") or row.get("testId") or ""
        title = row.get("name") or row.get("displayName") or f"Vanta test {test_id}"
        desc_parts = []
        if row.get("description"):
            desc_parts.append(row["description"])
        if row.get("statusReason"):
            desc_parts.append(f"Reason: {row['statusReason']}")
        if row.get("framework"):
            desc_parts.append(f"Framework: {row['framework']}")
        if row.get("lastEvaluatedAt"):
            desc_parts.append(f"Last evaluated: {row['lastEvaluatedAt']}")
        refs = []
        for fw in row.get("frameworks") or []:
            if isinstance(fw, dict) and fw.get("name"):
                refs.append({"name": f"Vanta-Framework-{fw['name']}", "type": "other"})
        if row.get("controlIds"):
            for ctrl in row["controlIds"]:
                refs.append({"name": f"Vanta-Control-{ctrl}", "type": "other"})
        vuln = _make_vuln(
            name=f"[GRC] {title}",
            desc="\n".join(desc_parts) or "Vanta failing test (no description).",
            severity=severity,
            refs=refs,
            external_id=f"vanta:test:{test_id}" if test_id else "",
            tags=["grc:vanta"],
        )
        # Vanta failing tests may or may not carry an affected-resource pointer;
        # if not, bucket under the synthetic global host so the finding still
        # shows up in the workspace.
        resource = row.get("resource") or row.get("affectedResource")
        if resource:
            ip, hostname = _host_key(resource)
            _add_vuln(
                hosts,
                ip,
                hostname,
                f"Vanta-tracked asset: {hostname}",
                vuln,
            )
        else:
            _add_vuln(
                hosts,
                "grc:vanta:global",
                "grc-vanta",
                "Vanta control-level findings not scoped to a single asset",
                vuln,
            )
        kept += 1
    log(f"Vanta: kept {kept} failing tests above floor='{min_severity}'.")


def _fetch_resources(base, token, page_size, max_pages, hosts):
    """Register every Vanta-monitored asset as a Faraday host so subsequent
    scans/imports converge on the same object."""
    seen = 0
    for row in _fetch(base, token, "/v1/resources", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        ip, hostname = _host_key(row)
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"Vanta-monitored resource ({row.get('type') or 'asset'})",
            _make_vuln(
                name="[GRC] Vanta-monitored asset",
                desc=(
                    f"Type: {row.get('type', '')}\n"
                    f"Owner: {row.get('owner', '')}\n"
                    f"Cloud: {row.get('cloud', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"vanta:resource:{row.get('id', '')}",
                tags=["grc:vanta:asset-inventory"],
            ),
        )
        seen += 1
    log(f"Vanta: registered {seen} monitored resources.")


def _fetch_people(base, token, page_size, max_pages, hosts):
    """People inventory — Vanta tracks employees/contractors and their access.
    Represented as synthetic 'user' hosts so onboarding/offboarding-related
    control failures can pivot to a Faraday host object."""
    seen = 0
    for row in _fetch(base, token, "/v1/people", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        person_id = row.get("id") or ""
        display = row.get("displayName") or row.get("email") or f"vanta-person-{person_id}"
        _add_vuln(
            hosts,
            f"vanta:person:{person_id}",
            display,
            "Vanta-tracked workforce member",
            _make_vuln(
                name="[GRC] Vanta workforce member",
                desc=(
                    f"Email: {row.get('email', '')}\n"
                    f"Role: {row.get('title', '')}\n"
                    f"Status: {row.get('employmentStatus', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"vanta:person:{person_id}",
                tags=["grc:vanta:people-inventory"],
            ),
        )
        seen += 1
    log(f"Vanta: registered {seen} people.")


def main():
    client_id = _cfg("VANTA_CLIENT_ID")
    client_secret = _cfg("VANTA_CLIENT_SECRET")
    if not client_id or not client_secret:
        log("VANTA_CLIENT_ID and VANTA_CLIENT_SECRET are required.")
        sys.exit(1)

    base = _cfg("VANTA_API_URL", "https://api.vanta.com").rstrip("/")
    modes_raw = _cfg("VANTA_MODE", "tests")
    modes = [m.strip().lower() for m in modes_raw.split(",") if m.strip()]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        log(f"Invalid VANTA_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    framework = _cfg("VANTA_FRAMEWORK")
    page_size = _safe_int(_cfg("VANTA_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    max_pages = _safe_int(_cfg("VANTA_MAX_PAGES"), DEFAULT_MAX_PAGES)
    min_severity = _validate_min_severity(_cfg("VANTA_MIN_SEVERITY"))

    token = _get_token(base, client_id, client_secret)

    hosts: dict = {}
    if "tests" in modes:
        _fetch_tests(base, token, framework, page_size, max_pages, min_severity, hosts)
    if "resources" in modes:
        _fetch_resources(base, token, page_size, max_pages, hosts)
    if "people" in modes:
        _fetch_people(base, token, page_size, max_pages, hosts)

    # Dedup vulns by external_id per host (Faraday drops the whole vuln array
    # if the same external_id appears twice on a host).
    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"Vanta: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
