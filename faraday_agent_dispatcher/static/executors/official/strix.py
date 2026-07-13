#!/usr/bin/env python
"""Strix.ai Cloud — REST client for the managed AI-pentester dashboard.

Pulls scans, per-scan validated vulnerabilities, monitored repositories
and attack-surface domains from Strix Cloud (default
https://app.strix.ai/api/v1/) and emits Faraday bulk-create JSON to
stdout.

Auth: Bearer PAT (`strix_pat_<...>`). Minted at
https://app.strix.ai/settings -> API keys. Docs: https://docs.strix.ai/.

The Strix agent runs remotely in the vendor's cloud sandbox; this
executor does NOT launch a local strix CLI (an earlier iteration of
this executor did — kept as a fallback via STRIX_MODE=cli, but the
default now is 'scans' which hits the Cloud API).

Modes (STRIX_MODE, comma-separated; default 'scans,domains,repositories'):
  scans         -> /api/v1/scans + /api/v1/scans/{id}
                   Each completed scan's vulnerabilities become Faraday
                   vulns tagged '[AGENT]' on the affected asset. Rich
                   fields — endpoint, method, CVSS, CWE, PoC script,
                   code_diff, remediation_steps — are folded into the
                   Faraday desc + refs + data fields.
  domains       -> /api/v1/domains
                   Attack-surface domains -> Faraday hosts tagged
                   'agent:strix:domain-inventory' with
                   https://app.strix.ai/domains/<id> deep link.
  repositories  -> /api/v1/repositories
                   Monitored repos -> Faraday hosts tagged
                   'agent:strix:repo-inventory'.

Env / args (all read from EXECUTOR_CONFIG_* first, then raw env):
  STRIX_API_KEY        (optional in WebUI, resolved from varenv on the
                        dispatcher) — PAT prefixed 'strix_pat_'
  STRIX_API_URL        (optional)   — default https://app.strix.ai
  STRIX_MODE           (optional)   — default 'scans,domains,repositories'
  STRIX_SCAN_ID        (optional)   — restrict scans mode to one scan id
  STRIX_MAX_SCANS      (optional)   — scan-list hard cap (default 20)
  STRIX_PAGE_SIZE      (optional)   — page size for /scans (default 20)
  STRIX_MAX_PAGES      (optional)   — hard cap (default 20 = 400 scans)
  STRIX_MIN_SEVERITY   (optional)   — default 'medium'
  STRIX_STATUS         (optional)   — default 'open' (only emit vulns
                                       whose status is 'open'; set to
                                       'all' to include closed/snoozed)
"""

from __future__ import annotations

import json
import os
import sys
import time

import requests

VALID_MODES = {"scans", "domains", "repositories"}
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
    "none": "info",
}

DEFAULT_PAGE_SIZE = 20
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_SCANS = 20
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


def _fetch(base, token, path, params=None, page_size=DEFAULT_PAGE_SIZE, max_pages=DEFAULT_MAX_PAGES):
    """Yield every row across paginated /api/v1/{scans,domains,repositories}.

    Strix Cloud returns {'items': [...], 'next_cursor': X | null} on list
    endpoints and a bare dict on detail endpoints. This helper only handles
    the list shape."""
    url = f"{base.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    cursor = None
    page = 0
    for _ in range(max_pages):
        q = dict(params or {})
        q["limit"] = page_size
        if cursor:
            q["cursor"] = cursor
        else:
            q["offset"] = page * page_size
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
        rows = body.get("items") if isinstance(body, dict) else body
        if not isinstance(rows, list) or not rows:
            return
        for row in rows:
            yield row
        cursor = body.get("next_cursor") if isinstance(body, dict) else None
        if not cursor and len(rows) < page_size:
            return
        page += 1


def _fetch_one(base, token, path):
    """GET a single detail resource. Returns dict on 200, None otherwise."""
    url = f"{base.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    for attempt in range(MAX_429_RETRIES + 1):
        r = requests.get(url, headers=headers, timeout=60)
        if r.status_code == 429 and attempt < MAX_429_RETRIES:
            log(f"Strix 429 on {path}; sleeping {RETRY_429_SLEEP}s")
            time.sleep(RETRY_429_SLEEP)
            continue
        break
    if r.status_code != 200:
        log(f"Strix {path} HTTP {r.status_code}: {r.text[:300]}")
        return None
    try:
        return r.json()
    except ValueError:
        log(f"Strix {path} returned non-JSON: {r.text[:200]!r}")
        return None


def _empty_host(ip, hostname, description):
    return {
        "ip": ip,
        "description": description,
        "hostnames": [hostname] if hostname else [],
        "vulnerabilities": [],
    }


def _add_vuln(hosts, ip, hostname, description, vuln):
    """Bucket by hostname when ip is a placeholder. Faraday keys hosts by ip
    server-side, so if we leave every asset at ip=0.0.0.0 they all collapse
    into a single Faraday host row. Promote the hostname into the ip field
    so each Strix asset (vpn.app.faradaysec.com, infobyte/faraday, etc.)
    becomes its own row in the Faraday hosts view."""
    if ip in ("0.0.0.0", "", None) and hostname:
        effective_ip = hostname
    else:
        effective_ip = ip
    key = effective_ip
    entry = hosts.get(key)
    if entry is None:
        entry = _empty_host(effective_ip, hostname, description)
        hosts[key] = entry
    elif hostname and hostname not in entry["hostnames"]:
        entry["hostnames"].append(hostname)
    entry["vulnerabilities"].append(vuln)


def _make_vuln(name, desc, severity, refs, external_id, tags=None, data="", resolution="", method=""):
    v = {
        "name": name,
        "desc": desc,
        "severity": severity,
        "type": "Vulnerability",
        "refs": refs,
        "data": data,
        "external_id": external_id,
        "tool": "strix",
        "tags": tags or [],
    }
    if resolution:
        v["resolution"] = resolution
    if method:
        v["method"] = method
    return v


def _repo_slug(value):
    """Reduce a repo pointer (dict / URL / bare slug) to 'owner/name'."""
    if isinstance(value, dict):
        for k in ("full_name", "slug", "path_with_namespace", "name", "url", "id"):
            if value.get(k):
                value = value[k]
                break
        else:
            return ""
    text = str(value or "").strip()
    for prefix in (
        "https://github.com/",
        "http://github.com/",
        "git@github.com:",
        "https://gitlab.com/",
        "https://bitbucket.org/",
    ):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text.rstrip("/").removesuffix(".git")


def _first_url(raw):
    """Pick the first URL/host from a comma/space/newline-joined string."""
    for sep in (",", "\n", " "):
        if sep in raw:
            raw = raw.split(sep, 1)[0]
    return raw.strip().rstrip(",;.")


def _host_from_url(raw):
    """Extract 'host.example.com' from a URL, or 'owner/name' from a git URL.

    Strix `target` values come in three flavours:
      - Full URLs: 'https://vpn.app.faradaysec.com'
      - Git-forge URLs: 'https://github.com/infobyte/faraday/blob/...'
      - Bare repo slugs: 'infobyte/faraday'
    For git-forge URLs we keep the first two path segments; for bare slugs
    (no scheme) we return the value verbatim so 'infobyte/faraday' does NOT
    collapse to just 'infobyte'."""
    raw = _first_url(str(raw))
    if not raw:
        return ""
    if "://" not in raw:
        return raw
    host_plus_path = raw.split("://", 1)[-1]
    parts = host_plus_path.split("/")
    host = parts[0]
    if host in ("github.com", "gitlab.com", "bitbucket.org") and len(parts) >= 3:
        slug = f"{parts[1]}/{parts[2]}"
        return slug.removesuffix(".git")
    return host or raw


def _target_from_vuln(vuln, scan):
    """Pick the right Faraday host for a Strix vuln.

    Strix vulns carry `target` (a URL/host), `endpoint` (a URL path), and
    `code_file` (a source path). Prefer target -> host; for URL targets,
    strip the scheme and pick the host; for git URLs, keep 'owner/name'.
    Fall back to the scan's repositories or urls when target is unset.
    Returns (ip, hostname, target_kind)."""
    target = vuln.get("target") or ""
    if target:
        host = _host_from_url(target)
        if host:
            return "0.0.0.0", host, "target"
    if vuln.get("code_file") or vuln.get("code_files") or vuln.get("locations"):
        repos = scan.get("repositories") or []
        if repos:
            slug = _repo_slug(repos[0])
            if slug:
                return "0.0.0.0", slug, "code_repo"
    urls = scan.get("urls") or []
    if urls:
        host = _host_from_url(urls[0])
        if host:
            return "0.0.0.0", host, "scan_url"
    return "agent:strix:global", "agent-strix", "global"


def _fetch_scans(base, token, scan_id, max_scans, page_size, max_pages, min_severity, status_filter, hosts):
    floor = SEVERITY_ORDER[min_severity]
    total_vulns = 0
    scans_iter: list
    if scan_id:
        one = _fetch_one(base, token, f"/api/v1/scans/{scan_id}")
        scans_iter = [one] if one else []
    else:
        scans_iter = []
        for row in _fetch(base, token, "/api/v1/scans", page_size=page_size, max_pages=max_pages):
            scans_iter.append(row)
            if len(scans_iter) >= max_scans:
                break
    log(f"Strix: iterating {len(scans_iter)} scan(s).")

    for scan_list_row in scans_iter:
        if not isinstance(scan_list_row, dict):
            continue
        sid = scan_list_row.get("id")
        if not sid:
            continue
        # /api/v1/scans list rows don't always carry the vulnerabilities array,
        # so re-fetch detail unless we already have it.
        if "vulnerabilities" in scan_list_row:
            scan = scan_list_row
        else:
            scan = _fetch_one(base, token, f"/api/v1/scans/{sid}")
            if not scan:
                continue
        title = scan.get("title") or f"Strix scan {sid}"
        vulns = scan.get("vulnerabilities") or []
        kept_this_scan = 0
        for v in vulns:
            if not isinstance(v, dict):
                continue
            severity = _severity(v.get("severity"))
            if SEVERITY_ORDER[severity] < floor:
                continue
            if status_filter != "all" and str(v.get("status") or "").lower() != status_filter:
                continue
            vid = v.get("id") or ""
            vtitle = v.get("title") or f"Strix finding {vid}"

            def _stringify(value):
                if isinstance(value, list):
                    return ", ".join(str(x) for x in value if x is not None)
                return str(value) if value is not None else ""

            endpoint = _stringify(v.get("endpoint") or v.get("endpoints"))
            method = _stringify(v.get("method") or v.get("methods"))
            code_file = _stringify(v.get("code_file") or v.get("code_files"))
            locations = v.get("locations") or v.get("code_locations") or []
            if isinstance(locations, str):
                locations = [locations]
            first_endpoint = endpoint.split(",", 1)[0].strip() if endpoint else ""
            first_code = code_file.split(",", 1)[0].strip() if code_file else ""
            if first_endpoint:
                vtitle_display = f"{vtitle} — {first_endpoint}"
            elif first_code:
                vtitle_display = f"{vtitle} — {first_code}"
            else:
                vtitle_display = vtitle
            desc_parts = []
            if v.get("description"):
                desc_parts.append(v["description"])
            if endpoint:
                desc_parts.append(f"Endpoint: {endpoint}")
            if method:
                desc_parts.append(f"Method: {method}")
            if code_file:
                desc_parts.append(f"Code file: {code_file}")
            if locations:
                loc_lines = []
                for loc in locations:
                    if isinstance(loc, dict):
                        file_ = loc.get("file") or loc.get("path") or ""
                        line = loc.get("end_line") or loc.get("line") or loc.get("start_line") or ""
                        label = loc.get("label") or ""
                        head = f"{file_}:{line}" if file_ and line else (file_ or str(loc))
                        loc_lines.append(f"  - {head}" + (f" — {label}" if label else ""))
                    elif loc:
                        loc_lines.append(f"  - {loc}")
                if loc_lines:
                    desc_parts.append("Locations:\n" + "\n".join(loc_lines))
            if v.get("impact"):
                desc_parts.append(f"Impact: {v['impact']}")
            if v.get("technical_analysis"):
                # This can be long; truncate to keep the Faraday payload sane.
                ta = str(v["technical_analysis"])
                if len(ta) > 3000:
                    ta = ta[:3000] + "…(truncated)"
                desc_parts.append(f"Technical analysis:\n{ta}")
            if v.get("poc_description"):
                desc_parts.append(f"PoC:\n{v['poc_description']}")
            if v.get("evidence"):
                ev = str(v["evidence"])
                if len(ev) > 1500:
                    ev = ev[:1500] + "…(truncated)"
                desc_parts.append(f"Evidence:\n{ev}")
            if v.get("cvss") is not None:
                desc_parts.append(f"CVSS: {v['cvss']}")
            if v.get("fix_effort"):
                desc_parts.append(f"Fix effort: {v['fix_effort']}")
            if v.get("finding_class"):
                desc_parts.append(f"Class: {v['finding_class']}")
            resolution_parts = []
            if v.get("remediation_steps"):
                resolution_parts.append(str(v["remediation_steps"]))
            if v.get("code_diff"):
                cd = str(v["code_diff"])
                if len(cd) > 3000:
                    cd = cd[:3000] + "…(truncated)"
                resolution_parts.append(f"Code diff:\n{cd}")
            resolution = "\n\n".join(resolution_parts)
            # Compact PoC script / code before/after go into `data` so
            # operators can pivot into the underlying artefact from the Faraday
            # vuln detail.
            data_parts = []
            if v.get("poc_script_code"):
                psc = str(v["poc_script_code"])
                if len(psc) > 4000:
                    psc = psc[:4000] + "…(truncated)"
                data_parts.append(f"# PoC script\n{psc}")
            if v.get("code_before"):
                cb = str(v["code_before"])
                if len(cb) > 1500:
                    cb = cb[:1500] + "…(truncated)"
                data_parts.append(f"# code_before\n{cb}")
            if v.get("code_after"):
                ca = str(v["code_after"])
                if len(ca) > 1500:
                    ca = ca[:1500] + "…(truncated)"
                data_parts.append(f"# code_after\n{ca}")
            data = "\n\n".join(data_parts)
            refs = []
            if v.get("cve"):
                refs.append({"name": str(v["cve"]), "type": "other"})
            if v.get("cwe"):
                cwe_val = str(v["cwe"])
                if not cwe_val.upper().startswith("CWE-"):
                    cwe_val = f"CWE-{cwe_val}"
                refs.append({"name": cwe_val, "type": "other"})
            # A stable deep link back into the Strix dashboard.
            refs.append(
                {
                    "name": f"https://app.strix.ai/scans/{sid}/vulnerabilities/{vid}",
                    "type": "other",
                }
            )
            refs.append({"name": f"Strix-Scan-{sid}", "type": "other"})
            if v.get("finding_class"):
                refs.append({"name": f"Strix-Class-{v['finding_class']}", "type": "other"})
            # Bucket into the right host.
            ip, hostname, host_kind = _target_from_vuln(v, scan)
            faraday_vuln = _make_vuln(
                name=vtitle_display,
                desc="\n\n".join(desc_parts) or "Strix.ai finding (no description).",
                severity=severity,
                refs=refs,
                external_id=f"strix:vuln:{vid}" if vid else "",
                tags=[
                    "agent:strix",
                    f"agent:strix:scan:{sid}",
                    f"agent:strix:host-kind:{host_kind}",
                ],
                data=data,
                resolution=resolution,
                method=str(v.get("method") or "").strip(),
            )
            _add_vuln(hosts, ip, hostname, f"Strix.ai-tested {host_kind}: {hostname}", faraday_vuln)
            kept_this_scan += 1
            total_vulns += 1
        # Emit a summary vuln per scan so the workspace records the scan
        # itself as an info-level artefact.
        summary_target = (scan.get("urls") or [""])[0] or (scan.get("repositories") or [""])[0] or "agent-strix"
        host_from_summary = str(summary_target).split("://", 1)[-1].split("/", 1)[0] or "agent-strix"
        _add_vuln(
            hosts,
            "0.0.0.0" if host_from_summary != "agent-strix" else "agent:strix:global",
            host_from_summary,
            f"Strix.ai scan target: {host_from_summary}",
            _make_vuln(
                name=f"Strix.ai scan: {title}",
                desc=(
                    (scan.get("executive_summary") or "")[:3000]
                    + ("\n\nReport: " + scan["report_url"] if scan.get("report_url") else "")
                ),
                severity="info",
                refs=[
                    {"name": f"https://app.strix.ai/scans/{sid}", "type": "other"},
                    {"name": f"Strix-Scan-Status-{scan.get('status', 'unknown')}", "type": "other"},
                ],
                external_id=f"strix:scan:{sid}",
                tags=[
                    "agent:strix:scan-summary",
                    f"agent:strix:scan-status:{scan.get('status', 'unknown')}",
                ],
            ),
        )
        log(f"Strix: scan {sid} '{title[:60]}': kept {kept_this_scan} vulns.")
    log(f"Strix: kept {total_vulns} vulns total across {len(scans_iter)} scan(s).")


def _fetch_domains(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/api/v1/domains", page_size=page_size, max_pages=max_pages):
        if not isinstance(row, dict):
            continue
        did = row.get("id") or ""
        raw = str(row.get("domain") or row.get("name") or f"strix-domain-{did}")
        hostname = raw.split("://", 1)[-1].split("/", 1)[0] or raw
        _add_vuln(
            hosts,
            "0.0.0.0",
            hostname,
            f"Strix.ai-monitored domain: {hostname}",
            _make_vuln(
                name="Strix.ai-monitored domain",
                desc=(
                    f"Domain: {raw}\n"
                    f"Kind: {row.get('kind', '')}\n"
                    f"Verified: {row.get('is_verified', '')}\n"
                    f"Strix link: https://app.strix.ai/domains/{did}"
                ),
                severity="info",
                refs=[{"name": f"https://app.strix.ai/domains/{did}", "type": "other"}] if did else [],
                external_id=f"strix:domain:{did}",
                tags=["agent:strix:domain-inventory"],
            ),
        )
        seen += 1
    log(f"Strix: registered {seen} attack-surface domains.")


def _fetch_repositories(base, token, page_size, max_pages, hosts):
    seen = 0
    for row in _fetch(base, token, "/api/v1/repositories", page_size=page_size, max_pages=max_pages):
        if not isinstance(row, dict):
            continue
        rid = row.get("id") or ""
        raw = str(row.get("full_name") or row.get("name") or row.get("url") or f"strix-repo-{rid}")
        hostname = raw.replace("https://github.com/", "").rstrip("/") or raw
        _add_vuln(
            hosts,
            "0.0.0.0",
            hostname,
            f"Strix.ai-monitored repo: {hostname}",
            _make_vuln(
                name="Strix.ai-monitored repository",
                desc=(
                    f"Repo: {raw}\n"
                    f"Provider: {row.get('provider', '')}\n"
                    f"Default branch: {row.get('default_branch', '')}\n"
                    f"Strix link: https://app.strix.ai/repositories/{rid}"
                ),
                severity="info",
                refs=[{"name": f"https://app.strix.ai/repositories/{rid}", "type": "other"}] if rid else [],
                external_id=f"strix:repo:{rid}",
                tags=["agent:strix:repo-inventory"],
            ),
        )
        seen += 1
    log(f"Strix: registered {seen} repositories.")


def main():
    token = _cfg("STRIX_API_KEY")
    if not token:
        log("STRIX_API_KEY is required (PAT prefixed 'strix_pat_').")
        sys.exit(1)

    base = _cfg("STRIX_API_URL", "https://app.strix.ai").rstrip("/")
    modes_raw = _cfg("STRIX_MODE", "scans,domains,repositories")
    modes = [m.strip().lower() for m in modes_raw.split(",") if m.strip()]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        log(f"Invalid STRIX_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    scan_id = _cfg("STRIX_SCAN_ID")
    max_scans = _safe_int(_cfg("STRIX_MAX_SCANS"), DEFAULT_MAX_SCANS)
    page_size = _safe_int(_cfg("STRIX_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    max_pages = _safe_int(_cfg("STRIX_MAX_PAGES"), DEFAULT_MAX_PAGES)
    min_severity = _validate_min_severity(_cfg("STRIX_MIN_SEVERITY"))
    status_filter = _cfg("STRIX_STATUS", "open").strip().lower()

    hosts: dict = {}
    if "scans" in modes:
        _fetch_scans(base, token, scan_id, max_scans, page_size, max_pages, min_severity, status_filter, hosts)
    if "domains" in modes:
        _fetch_domains(base, token, page_size, max_pages, hosts)
    if "repositories" in modes:
        _fetch_repositories(base, token, page_size, max_pages, hosts)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"Strix: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
