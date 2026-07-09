#!/usr/bin/env python
"""Aikido — continuous AppSec / cloud posture import.

Pulls open issues, monitored repositories and cloud resources from Aikido's
public REST API (https://app.aikido.dev/api/) and emits Faraday bulk-create
JSON to stdout.

Auth: OAuth2 client credentials (AIK_CLIENT_/AIK_SECRET_ prefixed pair)
sent as HTTP Basic auth, plus grant_type=client_credentials in the body.
Exchanged at /api/oauth/token for a short-lived Bearer, reused across
calls in the same run. Docs: https://apidocs.aikido.dev/.

Modes (AIKIDO_MODE, comma-separated; default 'issues'):
  issues        -> /public/v1/open_issues        open findings -> vulns
  repositories  -> /public/v1/repositories/code  code repos    -> hosts
  cloud         -> /public/v1/repositories/container  cloud/container repos -> hosts

Env / args:
  AIKIDO_CLIENT_ID     (mandatory) — AIK_CLIENT_...
  AIKIDO_CLIENT_SECRET (mandatory) — AIK_SECRET_...
  AIKIDO_API_URL       (optional)  — default https://app.aikido.dev
  AIKIDO_MODE          (optional)  — default 'issues'
  AIKIDO_SEVERITY_MIN  (optional)  — default 'medium'
  AIKIDO_PAGE_SIZE     (optional)  — default 100 (Aikido max)
  AIKIDO_MAX_PAGES     (optional)  — default 50
  AIKIDO_ISSUE_TYPE    (optional)  — restrict to sast / iac / secret / open_source / cloud / container / mobile / dast
"""

from __future__ import annotations

import json
import os
import sys
import time

import requests

VALID_MODES = {"issues", "repositories", "cloud"}
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Aikido severity is numeric (1..10 on CVSS-style scale) OR a bucket name.
AIKIDO_SEVERITY_TO_FARADAY = {
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
        log(f"AIKIDO_SEVERITY_MIN '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return text


def _severity_from_score(score):
    """Aikido returns severity_score 0..10 (CVSS-like) plus severity name."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"


def _severity(row, default="medium"):
    text = str(row.get("severity") or "").strip().lower()
    bucket = AIKIDO_SEVERITY_TO_FARADAY.get(text)
    if bucket:
        return bucket
    from_score = _severity_from_score(row.get("severity_score") or row.get("cvss"))
    if from_score:
        return from_score
    return default


def _get_token(base, client_id, client_secret):
    """OAuth2 client-credentials at /api/oauth/token. Aikido REQUIRES HTTP
    Basic auth of client:secret and grant_type=client_credentials in the
    body — the body-only form returns 401 'invalid_client — missing
    Authorization header'. Verified live against app.aikido.dev on
    2026-07-09."""
    url = f"{base.rstrip('/')}/api/oauth/token"
    r = requests.post(
        url,
        auth=(client_id, client_secret),
        data={"grant_type": "client_credentials"},
        timeout=30,
    )
    if r.status_code != 200:
        log(f"Aikido oauth/token HTTP {r.status_code}: {r.text[:300]}")
        sys.exit(1)
    token = r.json().get("access_token")
    if not token:
        log(f"Aikido oauth/token response missing access_token: {r.text[:300]}")
        sys.exit(1)
    return token


def _fetch(base, token, path, params, page_size, max_pages):
    url = f"{base.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    page = 0
    for _ in range(max_pages):
        q = dict(params)
        q["per_page"] = page_size
        q["page"] = page
        for attempt in range(MAX_429_RETRIES + 1):
            r = requests.get(url, headers=headers, params=q, timeout=60)
            if r.status_code == 429 and attempt < MAX_429_RETRIES:
                log(f"Aikido 429 on {path}; sleeping {RETRY_429_SLEEP}s")
                time.sleep(RETRY_429_SLEEP)
                continue
            break
        if r.status_code != 200:
            log(f"Aikido {path} HTTP {r.status_code}: {r.text[:300]}")
            return
        try:
            body = r.json()
        except ValueError:
            log(f"Aikido {path} returned non-JSON: {r.text[:200]!r}")
            return
        # Aikido returns either a bare list or {'data': [...]}. Handle both.
        rows = (
            body if isinstance(body, list) else (body.get("data") or body.get("issues") or body.get("results") or [])
        )
        if not rows:
            return
        for row in rows:
            yield row
        if len(rows) < page_size:
            return
        page += 1


def _host_key_from_repo(repo):
    if not isinstance(repo, dict):
        return None, None
    hostname = repo.get("name") or repo.get("repo_name") or repo.get("id") or "unknown-aikido-repo"
    ip = "0.0.0.0"
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
        "tool": "aikido",
        "tags": tags or [],
    }


def _fetch_issues(base, token, issue_type, page_size, max_pages, min_severity, hosts):
    params = {}
    if issue_type:
        params["filter_status"] = "open"
        params["filter_group"] = issue_type
    else:
        params["filter_status"] = "open"
    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    # Real endpoint: /api/public/v1/open-issue-groups (dashes, not
    # underscores). Verified live 2026-07-09. Response is a flat list of
    # {id, type, title, description, severity_score, severity, group_status,
    # locations: [{id, name, type}]}.
    for row in _fetch(base, token, "/api/public/v1/open-issue-groups", params, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        severity = _severity(row)
        if SEVERITY_ORDER[severity] < floor:
            continue
        issue_id = row.get("id") or ""
        title = row.get("title") or f"Aikido issue {issue_id}"
        desc_parts = []
        if row.get("description"):
            desc_parts.append(row["description"])
        if row.get("how_to_fix"):
            desc_parts.append(f"Fix: {row['how_to_fix']}")
        if row.get("type"):
            desc_parts.append(f"Type: {row['type']}")
        if row.get("group_status"):
            desc_parts.append(f"Status: {row['group_status']}")
        if row.get("time_to_fix_minutes"):
            desc_parts.append(f"TTF: {row['time_to_fix_minutes']}min")
        refs = []
        for cve in row.get("related_cve_ids") or []:
            if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                refs.append({"name": cve.upper(), "type": "cve"})
        vuln = _make_vuln(
            name=f"[AGENT] {title}",
            desc="\n".join(desc_parts) or "Aikido open issue (no description).",
            severity=severity,
            refs=refs,
            external_id=f"aikido:issue-group:{issue_id}" if issue_id else "",
            tags=[f"agent:aikido:{row.get('type', 'unknown')}"],
        )
        # Aikido returns a `locations` list; one issue can affect multiple
        # repositories. Emit one vuln per affected location so Faraday can
        # pivot back to the right host.
        locations = row.get("locations") or []
        if locations:
            for loc in locations:
                ip, hostname = _host_key_from_repo(loc)
                _add_vuln(hosts, ip, hostname, f"Aikido-monitored: {hostname}", dict(vuln))
        else:
            _add_vuln(
                hosts,
                "agent:aikido:global",
                "agent-aikido",
                "Aikido issues not scoped to a single asset",
                vuln,
            )
        kept += 1
    log(f"Aikido: kept {kept} open issues above floor='{min_severity}'.")


def _fetch_code_repos(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/api/public/v1/repositories/code", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        ip, hostname = _host_key_from_repo(row)
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"Aikido-monitored code repo ({row.get('provider', 'git')})",
            _make_vuln(
                name="[AGENT] Aikido-monitored code repository",
                desc=(
                    f"Provider: {row.get('provider', '')}\n"
                    f"Default branch: {row.get('default_branch', '')}\n"
                    f"Language: {row.get('language', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"aikido:repo:{row.get('id', '')}",
                tags=["agent:aikido:repo-inventory"],
            ),
        )
        seen += 1
    log(f"Aikido: registered {seen} code repos.")


def _fetch_container_repos(base, token, page_size, max_pages, hosts):
    """Aikido's public API doesn't expose /repositories/container; the closest
    equivalent is /clouds (AWS/GCP/Azure connections). Import those as hosts
    so Faraday can see the cloud-account inventory. Verified live 2026-07-09."""
    seen = 0
    for row in _fetch(base, token, "/api/public/v1/clouds", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        ip, hostname = _host_key_from_repo(row)
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"Aikido-monitored cloud ({row.get('provider', 'cloud')})",
            _make_vuln(
                name="[AGENT] Aikido-monitored cloud account",
                desc=(
                    f"Provider: {row.get('provider', '')}\n"
                    f"Account: {row.get('account_id', row.get('external_id', ''))}\n"
                    f"Region: {row.get('region', '')}"
                ),
                severity="info",
                refs=[],
                external_id=f"aikido:cloud:{row.get('id', '')}",
                tags=["agent:aikido:cloud-inventory"],
            ),
        )
        seen += 1
    log(f"Aikido: registered {seen} cloud accounts.")


def main():
    client_id = _cfg("AIKIDO_CLIENT_ID")
    client_secret = _cfg("AIKIDO_CLIENT_SECRET")
    if not client_id or not client_secret:
        log("AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET are required.")
        sys.exit(1)

    base = _cfg("AIKIDO_API_URL", "https://app.aikido.dev").rstrip("/")
    modes_raw = _cfg("AIKIDO_MODE", "issues")
    modes = [m.strip().lower() for m in modes_raw.split(",") if m.strip()]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        log(f"Invalid AIKIDO_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    issue_type = _cfg("AIKIDO_ISSUE_TYPE")
    page_size = _safe_int(_cfg("AIKIDO_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    max_pages = _safe_int(_cfg("AIKIDO_MAX_PAGES"), DEFAULT_MAX_PAGES)
    min_severity = _validate_min_severity(_cfg("AIKIDO_SEVERITY_MIN"))

    token = _get_token(base, client_id, client_secret)

    hosts: dict = {}
    if "issues" in modes:
        _fetch_issues(base, token, issue_type, page_size, max_pages, min_severity, hosts)
    if "repositories" in modes:
        _fetch_code_repos(base, token, page_size, max_pages, hosts)
    if "cloud" in modes:
        _fetch_container_repos(base, token, page_size, max_pages, hosts)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"Aikido: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
