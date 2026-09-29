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

VALID_MODES = {"issues", "repositories", "cloud", "domains"}
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
    """Aikido assets all share ip=0.0.0.0 (no L3 pointers), so keying the
    hosts dict by ip would collapse every domain/repo/cloud into a single
    Faraday host. Bucket by hostname instead so each asset lands as its own
    Faraday host (or by ip if it's a synthetic 'agent:aikido:*' key)."""
    key = hostname if hostname and ip == "0.0.0.0" else ip
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
        "tool": "aikido",
        "tags": tags or [],
    }


def _host_key_from_issue(row):
    """Pick the right host for an issue based on which asset field is set.

    Priority: code_repo > container_repo > cloud > domain > virtual_machine >
    pentest_project. Falls back to a synthetic 'agent:aikido:global' host so
    control-level findings still surface.
    """
    if row.get("code_repo_name"):
        return "0.0.0.0", str(row["code_repo_name"]), "code_repo"
    if row.get("container_repo_name"):
        return "0.0.0.0", str(row["container_repo_name"]), "container"
    if row.get("cloud_name"):
        return "0.0.0.0", str(row["cloud_name"]), "cloud"
    if row.get("domain_name"):
        # domain_name can include a scheme (e.g. https://faradaysec.com); strip
        # it so the Faraday host matches other executors that see the bare host.
        raw = str(row["domain_name"])
        host = raw.split("://", 1)[-1].split("/", 1)[0]
        return "0.0.0.0", host or raw, "domain"
    if row.get("virtual_machine_name"):
        return "0.0.0.0", str(row["virtual_machine_name"]), "vm"
    return "agent:aikido:global", "agent-aikido", "global"


def _fetch_issues(base, token, issue_type, page_size, max_pages, min_severity, hosts):
    """Pull per-issue detail from /issues/export.

    Unlike /open-issue-groups (which returns one grouped row per rule with
    only the repo name), /issues/export returns one row per (rule, file, line)
    triple — so we get affected_file, start_line, end_line, cve_id, cwe_classes
    and the concrete asset the issue lives on (code_repo_name / domain_name /
    cloud_name / ...). Verified live against api.public/v1 2026-07-09.
    """
    params = {"format": "json", "filter_status": "open"}
    if issue_type:
        # /issues/export takes filter_type = sast | iac | secret | open_source |
        # cloud | container | mobile | dast | surface_monitoring | ...
        params["filter_type"] = issue_type
    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    for row in _fetch(base, token, "/api/public/v1/issues/export", params, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        severity = _severity(row)
        if SEVERITY_ORDER[severity] < floor:
            continue
        issue_id = row.get("id") or ""
        group_id = row.get("group_id") or ""
        rule = row.get("rule") or row.get("rule_id") or f"Aikido issue {issue_id}"
        affected_file = row.get("affected_file") or ""
        # Build a title that surfaces the file/line — this is what the user
        # asked for so SAST findings are directly clickable.
        if affected_file:
            loc = affected_file
            if row.get("start_line"):
                loc += f":{row['start_line']}"
                if row.get("end_line") and row["end_line"] != row["start_line"]:
                    loc += f"-{row['end_line']}"
            title = f"{rule} — {loc}"
        elif row.get("affected_package"):
            v = row.get("installed_version")
            title = f"{rule} — {row['affected_package']}" + (f"@{v}" if v else "")
        elif row.get("domain_name"):
            title = f"{rule} — {row['domain_name']}"
        else:
            title = rule
        desc_parts = []
        if affected_file:
            desc_parts.append(f"File: {affected_file}")
            if row.get("start_line"):
                desc_parts.append(f"Line: {row['start_line']}-{row.get('end_line') or row['start_line']}")
        if row.get("affected_package"):
            desc_parts.append(f"Package: {row['affected_package']}")
        if row.get("installed_version"):
            desc_parts.append(f"Installed version: {row['installed_version']}")
        if row.get("patched_versions"):
            desc_parts.append(f"Patched in: {', '.join(row['patched_versions'])}")
        if row.get("attack_surface"):
            desc_parts.append(f"Attack surface: {row['attack_surface']}")
        if row.get("type"):
            desc_parts.append(f"Type: {row['type']}")
        if row.get("programming_language"):
            desc_parts.append(f"Language: {row['programming_language']}")
        if row.get("exploitability"):
            desc_parts.append(f"Exploitability: {row['exploitability']}")
        if row.get("sla_days"):
            desc_parts.append(f"SLA: {row['sla_days']}d")
        if row.get("first_detected_at"):
            try:
                dt = time.strftime("%Y-%m-%d", time.gmtime(int(row["first_detected_at"])))
                desc_parts.append(f"First detected: {dt}")
            except (TypeError, ValueError):
                pass
        refs = []
        if row.get("cve_id"):
            # Faraday only accepts ref type: exploit | patch | other
            refs.append({"name": row["cve_id"], "type": "other"})
        for cwe in row.get("cwe_classes") or []:
            if isinstance(cwe, str) and cwe.upper().startswith("CWE-"):
                refs.append({"name": cwe.upper(), "type": "other"})
            elif isinstance(cwe, (int, str)):
                refs.append({"name": f"CWE-{cwe}", "type": "other"})
        if row.get("rule_id"):
            refs.append({"name": f"Aikido-Rule-{row['rule_id']}", "type": "other"})
        if group_id:
            refs.append({"name": f"Aikido-Group-{group_id}", "type": "other"})
        vuln = _make_vuln(
            name=f"[AGENT] {title}",
            desc="\n".join(desc_parts) or "Aikido open issue (no description).",
            severity=severity,
            refs=refs,
            external_id=f"aikido:issue:{issue_id}" if issue_id else "",
            tags=[
                f"agent:aikido:{row.get('type', 'unknown')}",
                f"agent:aikido:surface:{row.get('attack_surface', 'unknown')}",
            ],
        )
        ip, hostname, host_kind = _host_key_from_issue(row)
        _add_vuln(hosts, ip, hostname, f"Aikido-monitored {host_kind}: {hostname}", vuln)
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


def _fetch_domains(base, token, page_size, max_pages, hosts):
    """Import Aikido attack-surface domains (and their subdomains) as Faraday
    hosts. Response shape: [{id, domain, kind, is_auth_configured,
    last_scanned_at, linked_resource}]. `kind` is 'front_end' or
    'infra_pentest'. This is where you see faradaysec.com etc. show up in the
    Aikido UI under Attack Surface -> Domains."""
    seen_domains = 0
    for row in _fetch(base, token, "/api/public/v1/domains", {}, page_size, max_pages):
        if not isinstance(row, dict):
            continue
        raw = str(row.get("domain") or row.get("id") or "unknown-aikido-domain")
        hostname = raw.split("://", 1)[-1].split("/", 1)[0] or raw
        did = row.get("id") or ""
        # Inventory record so the host exists even if it has no findings.
        _add_vuln(
            hosts,
            "0.0.0.0",
            hostname,
            f"Aikido attack-surface domain ({row.get('kind', 'domain')})",
            _make_vuln(
                name="[AGENT] Aikido attack-surface domain",
                desc=(
                    f"Domain: {raw}\n"
                    f"Kind: {row.get('kind', '')}\n"
                    f"Auth configured: {row.get('is_auth_configured', '')}\n"
                    f"Last scanned: {row.get('last_scanned_at', '')}\n"
                    f"Aikido link: https://app.aikido.dev/domain/{did}"
                ),
                severity="info",
                refs=(
                    [
                        # Faraday only accepts ref type: exploit | patch | other
                        {"name": f"https://app.aikido.dev/domain/{did}", "type": "other"},
                    ]
                    if did
                    else []
                ),
                external_id=f"aikido:domain:{did}",
                tags=[
                    "agent:aikido:domain-inventory",
                    f"agent:aikido:domain-kind:{row.get('kind', 'unknown')}",
                ],
            ),
        )
        seen_domains += 1
        # Pull subdomains too (Aikido tracks discovered subdomains per attack
        # surface domain). Cheap enough to inline.
        if did:
            for sub in _fetch(base, token, f"/api/public/v1/domains/{did}/subdomains", {}, page_size, max_pages):
                if not isinstance(sub, dict):
                    continue
                sub_raw = str(sub.get("subdomain") or sub.get("domain") or "")
                if not sub_raw:
                    continue
                sub_hostname = sub_raw.split("://", 1)[-1].split("/", 1)[0]
                _add_vuln(
                    hosts,
                    "0.0.0.0",
                    sub_hostname,
                    f"Aikido discovered subdomain of {hostname}",
                    _make_vuln(
                        name="[AGENT] Aikido attack-surface subdomain",
                        desc=(
                            f"Subdomain: {sub_raw}\n"
                            f"Parent domain: {raw}\n"
                            f"Aikido link: https://app.aikido.dev/domain/{did}"
                        ),
                        severity="info",
                        refs=[],
                        external_id=f"aikido:subdomain:{did}:{sub_hostname}",
                        tags=[
                            "agent:aikido:subdomain-inventory",
                            f"agent:aikido:parent:{hostname}",
                        ],
                    ),
                )
    log(f"Aikido: registered {seen_domains} attack-surface domains (plus subdomains).")


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
    if "domains" in modes:
        _fetch_domains(base, token, page_size, max_pages, hosts)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"Aikido: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
