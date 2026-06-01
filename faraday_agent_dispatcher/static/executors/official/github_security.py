#!/usr/bin/env python
"""GitHub Advanced Security REST API importer (fan-out).

Pulls findings from one or more of GitHub Advanced Security's three
alert APIs against a single repository and emits Faraday bulk-create
JSON to stdout. This executor is a superset of the per-API ``codeql``,
``github_secrets`` and ``dependabot`` executors — set
``GH_SCAN_TYPES`` (CSV of ``code|secrets|dependabot``) to pick a
subset; omit it to fan out to all three. The per-API executors are
kept for users who only want a single signal; this one exists so a
single GitHub PAT can drive every GitHub-side import in a single
agent invocation.

Each GitHub repository becomes one Faraday host (``ip`` = synthetic
``0.0.0.0`` because GitHub Advanced Security findings live in source
repos and pull-request diffs, not on IPs) with hostnames =
``{owner}/{repo}``; each alert becomes one Faraday vulnerability with
an engine prefix matching the alert source (``[CODE]`` / ``[SECRETS]``
/ ``[SCA]``).

Endpoints used:
  GET /repos/{owner}/{repo}/code-scanning/alerts
      -> code-scanning (CodeQL + third-party SARIF) alerts. Each alert
      carries rule.id / rule.description / rule.security_severity_level
      / rule.tags (CWE-* + language category), most_recent_instance
      (location.path:start_line / commit_sha / category / message),
      state (open / dismissed / fixed) and tool metadata.
  GET /repos/{owner}/{repo}/secret-scanning/alerts
      -> secret-scanning alerts. Each alert carries secret_type /
      secret_type_display_name / push_protection_bypassed / state
      (open / resolved) and html_url. GitHub does not assign a
      severity to secret-scanning alerts; we surface them at ``high``
      to match the priority CISOs typically assign exposed creds.
  GET /repos/{owner}/{repo}/dependabot/alerts
      -> Dependabot alerts (advisory + affected dependency). Each
      alert carries security_advisory (summary, description, severity,
      cwes, identifiers, references, cvss vector / score) and
      security_vulnerability (package.ecosystem + package.name,
      vulnerable_version_range, first_patched_version.identifier) plus
      a state of open / dismissed / fixed / auto_dismissed.

Auth: ``Authorization: Bearer <GH_TOKEN>`` carrying a GitHub PAT
(classic or fine-grained) or a GitHub App installation token. The
token needs ``security_events`` (read) for code-scanning,
``secret_scanning_alerts`` (read) for secret-scanning, and the
``Dependabot alerts`` repository permission for dependabot alerts —
fine-grained tokens must explicitly grant each. The Server-side path
``https://api.github.com`` is the default; ``GH_HOST`` can be set to
a GitHub Enterprise Server REST root (e.g.
``https://github.corp.example.com/api/v3``) for self-hosted GHES.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200
DEFAULT_HOST = "https://api.github.com"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

VALID_SCAN_TYPES = ("code", "secrets", "dependabot")

# GitHub uses a few different severity buckets across the three APIs:
#   * code-scanning rule.severity:           none / note / warning / error
#   * code-scanning security_severity_level: low / medium / high / critical
#   * dependabot security_advisory.severity: low / medium / high / critical
#   * secret-scanning has no severity (we default to high — exposed
#     credentials are typically the highest-priority finding class).
GH_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "error": "high",
    "warning": "medium",
    "note": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unknown": "info",
}

# Combined state -> Faraday status map for all three alert APIs:
#   * code-scanning: open / dismissed / fixed
#   * secret-scanning: open / resolved
#   * dependabot: open / dismissed / fixed / auto_dismissed
STATE_TO_STATUS = {
    "open": "open",
    "fixed": "closed",
    "resolved": "closed",
    "auto_dismissed": "closed",
    "dismissed": "risk-accepted",
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)


def log(msg):
    print(f"{datetime.utcnow()} - GitHubSecurity: {msg}", file=sys.stderr, flush=True)


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


def severity_from_cvss(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "info"
    if score <= 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def severity_from_gh(value, cvss=None):
    """Map a GitHub severity field to a Faraday severity bucket.

    Accepts GitHub's string enum across all three APIs (critical / high
    / medium / low / none + the code-scanning rule.severity enum
    error / warning / note) plus a couple of nearby aliases. Falls
    back to CVSS bucketing on the provided ``cvss`` argument when the
    primary value is missing or unrecognised.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in GH_TO_FARADAY:
            return GH_TO_FARADAY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_state(state):
    """Map a GitHub alert ``state`` to a Faraday status."""
    if not state:
        return "open"
    text = str(state).strip().lower()
    return STATE_TO_STATUS.get(text, "open")


def build_auth_headers(token):
    """Build the GitHub REST auth headers.

    A pre-built ``Bearer ...`` / ``token ...`` prefix in ``GH_TOKEN``
    is forwarded verbatim; otherwise we wrap the bare value in
    ``Authorization: Bearer <token>`` which works for both classic and
    fine-grained PATs as well as GitHub App installation tokens.
    """
    if not token:
        return {}
    text = str(token).strip()
    lower = text.lower()
    if lower.startswith("bearer ") or lower.startswith("token "):
        auth_value = text
    else:
        auth_value = f"Bearer {text}"
    return {
        "Authorization": auth_value,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def normalize_base_url(host):
    if not host:
        return DEFAULT_HOST
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def parse_scan_types(value):
    """Parse the ``GH_SCAN_TYPES`` CSV into a normalised tuple.

    Empty / missing input is treated as "all three" so the executor
    has a sensible no-config default. Unknown tokens are logged and
    skipped — the user gets a warning but the executor still runs the
    valid subset.
    """
    if value is None or str(value).strip() == "":
        return VALID_SCAN_TYPES
    seen = []
    for chunk in str(value).split(","):
        text = chunk.strip().lower()
        if not text:
            continue
        if text in VALID_SCAN_TYPES:
            if text not in seen:
                seen.append(text)
        else:
            log(f"GH_SCAN_TYPES token '{chunk.strip()}' is not in " f"{', '.join(VALID_SCAN_TYPES)}; ignoring")
    return tuple(seen) if seen else VALID_SCAN_TYPES


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"GH_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def parse_next_link(link_header):
    """Pull the ``rel="next"`` URL out of a GitHub Link response header."""
    if not link_header:
        return None
    for chunk in link_header.split(","):
        parts = chunk.strip().split(";")
        if len(parts) < 2:
            continue
        url = parts[0].strip().lstrip("<").rstrip(">")
        for attr in parts[1:]:
            if attr.strip().lower() == 'rel="next"':
                return url
    return None


def request_paginated(url, headers, params=None):
    """Walk a GitHub paginated list endpoint honouring the Link header.

    GitHub's REST API paginates with ``page`` + ``per_page`` and
    advertises the next page via the ``Link`` response header
    (``rel="next"``). We honour that header when present and fall back
    to incrementing ``page`` when the server omits it.
    """
    results = []
    query = dict(params or {})
    query.setdefault("per_page", PAGE_SIZE)
    page = 1
    next_url = url
    for _ in range(MAX_PAGES):
        if "page" not in query:
            query["page"] = page
        try:
            resp = requests.get(
                next_url,
                headers=headers,
                params=query,
                timeout=TIMEOUT,
                verify=False,
            )
        except requests.RequestException as exc:
            log(f"GET {next_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Authentication rejected (401). Check GH_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"Authorization rejected (403) on {next_url}. Check the token scope.")
            break
        if resp.status_code == 404:
            log(f"GET {next_url} returned 404 (alerts disabled or repo not accessible)")
            break
        if resp.status_code >= 400:
            log(f"GET {next_url} failed ({resp.status_code}): {resp.text[:500]}")
            break
        try:
            chunk = resp.json()
        except ValueError:
            log(f"GET {next_url} returned non-JSON body")
            break
        if not isinstance(chunk, list):
            break
        if not chunk:
            break
        results.extend(chunk)
        link = resp.headers.get("Link") if hasattr(resp, "headers") else None
        next_link = parse_next_link(link)
        if next_link:
            next_url = next_link
            query = None
            continue
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
        query = {"per_page": PAGE_SIZE, "page": page}
    return results


def collect_cwes(rule_or_advisory):
    """Pluck CWE-* identifiers out of a rule.tags / cwes payload."""
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        match = CWE_PATTERN.search(str(text))
        if not match:
            return
        norm = match.group(0).upper()
        if norm in seen:
            return
        seen.add(norm)
        found.append(norm)

    if isinstance(rule_or_advisory, dict):
        for tag in rule_or_advisory.get("tags") or []:
            if isinstance(tag, str):
                add(tag)
        cwes = rule_or_advisory.get("cwes")
        if isinstance(cwes, list):
            for entry in cwes:
                if isinstance(entry, dict):
                    add(entry.get("cwe_id") or entry.get("id") or entry.get("name"))
                elif isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, (int, float)) and not isinstance(entry, bool):
                    add(f"CWE-{int(entry)}")
        # Advisory descriptions occasionally embed bare CWE refs.
        for key in ("description", "summary"):
            text = rule_or_advisory.get(key)
            if isinstance(text, str):
                for m in CWE_PATTERN.findall(text):
                    add(m)
    return found


def collect_cves(advisory):
    """Pluck CVE-* identifiers out of a dependabot advisory payload."""
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        match = CVE_PATTERN.search(str(text))
        if not match:
            return
        norm = match.group(0).upper()
        if norm in seen:
            return
        seen.add(norm)
        found.append(norm)

    if isinstance(advisory, dict):
        cve = advisory.get("cve_id") or advisory.get("cve")
        if isinstance(cve, str):
            add(cve)
        for entry in advisory.get("identifiers") or []:
            if isinstance(entry, dict):
                if (entry.get("type") or "").upper() == "CVE":
                    add(entry.get("value"))
                else:
                    add(entry.get("value"))
            elif isinstance(entry, str):
                add(entry)
        for key in ("description", "summary"):
            text = advisory.get(key)
            if isinstance(text, str):
                for m in CVE_PATTERN.findall(text):
                    add(m)
    return found


def collect_advisory_refs(advisory):
    """Walk a dependabot advisory for refs (GHSA, CWE, URLs)."""
    refs = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(advisory, dict):
        return refs

    ghsa = advisory.get("ghsa_id")
    if isinstance(ghsa, str) and ghsa.strip():
        add(ghsa.strip())
    for entry in advisory.get("identifiers") or []:
        if isinstance(entry, dict):
            etype = (entry.get("type") or "").upper()
            if etype == "GHSA":
                add(entry.get("value"))
    for cwe in collect_cwes(advisory):
        add(cwe)
    for entry in advisory.get("references") or []:
        if isinstance(entry, dict):
            url = entry.get("url") or entry.get("href") or entry.get("name")
            if url:
                add(url)
        elif entry:
            add(str(entry))
    return refs


def code_scanning_location(alert):
    """Format the file:line location surfaced by a code-scanning alert."""
    instance = alert.get("most_recent_instance") or {}
    if not isinstance(instance, dict):
        return None, ""
    loc = instance.get("location")
    if not isinstance(loc, dict):
        return None, ""
    path = loc.get("path")
    start = loc.get("start_line")
    end = loc.get("end_line")
    if path and start and end and str(start) != str(end):
        return f"location: {path}:{start}-{end}", path
    if path and start:
        return f"location: {path}:{start}", path
    if path:
        return f"location: {path}", path
    return None, ""


def build_code_scanning_vuln(alert, owner, repo):
    rule = alert.get("rule") or {}
    if not isinstance(rule, dict):
        rule = {}
    severity = severity_from_gh(rule.get("security_severity_level") or rule.get("severity"))
    status = status_from_state(alert.get("state"))

    name_text = (
        rule.get("description")
        or rule.get("name")
        or rule.get("id")
        or f"Code scanning alert {alert.get('number') or ''}"
    )
    name = f"[CODE] {name_text}".strip()

    desc_parts = []
    full_desc = rule.get("full_description")
    if full_desc:
        desc_parts.append(str(full_desc))
    instance = alert.get("most_recent_instance") or {}
    message = (instance.get("message") or {}).get("text") if isinstance(instance, dict) else None
    if message:
        desc_parts.append(f"message: {message}")
    loc_text, path = code_scanning_location(alert)
    if loc_text:
        desc_parts.append(loc_text)
    commit_sha = instance.get("commit_sha") if isinstance(instance, dict) else None
    if commit_sha and path:
        link = (
            f"[View it on Github]"
            f"(https://github.com/{owner}/{repo}/blob/{commit_sha}/{path}"
            f"#L{(instance.get('location') or {}).get('start_line', 'N/A')})"
        )
        desc_parts.append(link)
    if commit_sha:
        desc_parts.append(f"commit: {commit_sha}")
    category = instance.get("category") if isinstance(instance, dict) else None
    if category:
        desc_parts.append(f"category: {category}")
    tool = alert.get("tool") or {}
    if isinstance(tool, dict):
        tool_name = tool.get("name")
        if tool_name:
            desc_parts.append(f"tool: {tool_name}")
    rule_id = rule.get("id")
    if rule_id:
        desc_parts.append(f"rule_id: {rule_id}")
    state_raw = alert.get("state")
    if state_raw:
        desc_parts.append(f"state: {state_raw}")
    created = alert.get("created_at")
    if created:
        desc_parts.append(f"created: {created}")
    updated = alert.get("updated_at")
    if updated:
        desc_parts.append(f"updated: {updated}")

    cwes = collect_cwes(rule)
    refs = []
    refs_seen = set()
    for cwe in cwes:
        if cwe not in refs_seen:
            refs.append({"name": cwe, "type": "other"})
            refs_seen.add(cwe)
    html_url = alert.get("html_url")
    if html_url and html_url not in refs_seen:
        refs.append({"name": html_url, "type": "other"})
        refs_seen.add(html_url)

    resolution = ""
    help_text = rule.get("help")
    if isinstance(help_text, str) and help_text:
        # Some rules stuff a "## References" block at the tail — strip it.
        resolution = help_text.split("## References", 1)[0].strip()

    external_id = str(alert.get("number") or alert.get("id") or "")

    tags = ["github_security", "code_scanning"]
    if isinstance(category, str) and category.startswith("/language:"):
        tags.append(category.split(":", 1)[1])

    return {
        "name": str(name).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": [],
        "cvss3": {},
        "cwe": cwes,
        "tags": tags,
        "_path": path,
    }


def build_secret_scanning_vuln(alert, owner, repo):
    state = alert.get("state")
    # Secret-scanning has only open/resolved; resolution may have details.
    if isinstance(state, str) and state.strip().lower() == "resolved":
        resolution_raw = alert.get("resolution")
        if isinstance(resolution_raw, str) and resolution_raw.strip().lower() in (
            "false_positive",
            "revoked",
            "used_in_tests",
            "wont_fix",
        ):
            status = "risk-accepted" if resolution_raw.strip().lower() in ("false_positive", "wont_fix") else "closed"
        else:
            status = "closed"
    else:
        status = "open"

    secret_type_display = alert.get("secret_type_display_name") or alert.get("secret_type") or "Secret"
    name = f"[SECRETS] {secret_type_display}".strip()

    desc_parts = []
    secret_type = alert.get("secret_type")
    if secret_type:
        desc_parts.append(f"secret_type: {secret_type}")
    html_url = alert.get("html_url")
    if html_url:
        desc_parts.append(f"[View it on Github]({html_url})")
    push_protection = alert.get("push_protection_bypassed")
    if push_protection is not None:
        desc_parts.append(f"push_protection_bypassed: {push_protection}")
    validity = alert.get("validity")
    if validity:
        desc_parts.append(f"validity: {validity}")
    state_raw = alert.get("state")
    if state_raw:
        desc_parts.append(f"state: {state_raw}")
    resolution_raw = alert.get("resolution")
    if resolution_raw:
        desc_parts.append(f"resolution: {resolution_raw}")
    created = alert.get("created_at")
    if created:
        desc_parts.append(f"created: {created}")
    updated = alert.get("updated_at")
    if updated:
        desc_parts.append(f"updated: {updated}")

    refs = []
    if html_url:
        refs.append({"name": html_url, "type": "other"})

    external_id = str(alert.get("number") or alert.get("id") or "")

    return {
        "name": str(name).strip()[:200],
        "desc": "\n".join(desc_parts),
        # Exposed credentials are treated as high-severity by default —
        # GitHub does not assign severity to secret-scanning alerts.
        "severity": "high",
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": "",
        "data": "Severity not provided by GitHub Secret Scanning; defaulted to 'high'.",
        "refs": refs,
        "cve": [],
        "cvss3": {},
        "cwe": [],
        "tags": ["github_security", "secret_detection"],
        "_path": "",
    }


def build_dependabot_vuln(alert, owner, repo):
    advisory = alert.get("security_advisory") or {}
    if not isinstance(advisory, dict):
        advisory = {}
    vulnerability = alert.get("security_vulnerability") or {}
    if not isinstance(vulnerability, dict):
        vulnerability = {}

    cvss = advisory.get("cvss") or {}
    cvss_score = None
    cvss_vector = None
    if isinstance(cvss, dict):
        cvss_score = cvss.get("score")
        cvss_vector = cvss.get("vector_string")
    severity = severity_from_gh(advisory.get("severity"), cvss_score)
    status = status_from_state(alert.get("state"))

    raw_name = advisory.get("summary") or advisory.get("ghsa_id") or "Dependabot alert"
    name = f"[SCA] {raw_name}".strip()

    desc_parts = []
    description = advisory.get("description")
    if description:
        desc_parts.append(str(description))

    package = vulnerability.get("package") or {}
    pkg_name = package.get("name") if isinstance(package, dict) else None
    pkg_ecosystem = package.get("ecosystem") if isinstance(package, dict) else None
    vulnerable_range = vulnerability.get("vulnerable_version_range")
    first_patched = (vulnerability.get("first_patched_version") or {}).get("identifier")
    dependency = alert.get("dependency") or {}
    manifest_path = dependency.get("manifest_path") if isinstance(dependency, dict) else None
    if pkg_name:
        desc_parts.append(f"package: {pkg_name}" + (f" ({pkg_ecosystem})" if pkg_ecosystem else ""))
    if vulnerable_range:
        desc_parts.append(f"affected_versions: {vulnerable_range}")
    if first_patched:
        desc_parts.append(f"first_patched_version: {first_patched}")
    if manifest_path:
        desc_parts.append(f"manifest_path: {manifest_path}")
    html_url = alert.get("html_url")
    if html_url:
        desc_parts.append(f"[View it on Github]({html_url})")
    ghsa = advisory.get("ghsa_id")
    if ghsa:
        desc_parts.append(f"ghsa_id: {ghsa}")
    state_raw = alert.get("state")
    if state_raw:
        desc_parts.append(f"state: {state_raw}")
    if cvss_score is not None:
        desc_parts.append(f"cvss: {cvss_score}")
    created = alert.get("created_at")
    if created:
        desc_parts.append(f"created: {created}")
    updated = alert.get("updated_at")
    if updated:
        desc_parts.append(f"updated: {updated}")

    cves = collect_cves(advisory)
    cwes = collect_cwes(advisory)
    refs = collect_advisory_refs(advisory)
    refs_seen = {r["name"] for r in refs}
    if html_url and html_url not in refs_seen:
        refs.append({"name": html_url, "type": "other"})

    cvss3 = {}
    if cvss_score is not None:
        cvss3["base_score"] = cvss_score
    if isinstance(cvss_vector, str) and cvss_vector.startswith("CVSS:3"):
        cvss3["vector_string"] = cvss_vector
    cvss2 = {}
    if isinstance(cvss_vector, str) and cvss_vector and not cvss_vector.startswith("CVSS:3"):
        cvss2["vector_string"] = cvss_vector

    external_id = str(alert.get("number") or alert.get("id") or ghsa or "")

    result = {
        "name": str(name).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": "",
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "cwe": cwes,
        "tags": ["github_security", "dependabot"],
        "_path": manifest_path or "",
    }
    if cvss2:
        result["cvss2"] = cvss2
    return result


def fetch_code_scanning(base_url, headers, owner, repo):
    return request_paginated(
        f"{base_url}/repos/{owner}/{repo}/code-scanning/alerts",
        headers,
        params={"state": "open"},
    )


def fetch_secret_scanning(base_url, headers, owner, repo):
    return request_paginated(
        f"{base_url}/repos/{owner}/{repo}/secret-scanning/alerts",
        headers,
    )


def fetch_dependabot(base_url, headers, owner, repo):
    return request_paginated(
        f"{base_url}/repos/{owner}/{repo}/dependabot/alerts",
        headers,
    )


def build_host(owner, repo, vulns):
    hostname = f"{owner}/{repo}" if owner and repo else (owner or repo or "")
    hostnames = [hostname] if hostname else []
    desc_parts = [f"repo=https://github.com/{owner}/{repo}"] if owner and repo else []
    # Drop the private _path tag before emitting.
    for v in vulns:
        v.pop("_path", None)
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("GH_HOST", default=DEFAULT_HOST)
    token = env("GH_TOKEN", required=True)
    owner = env("EXECUTOR_CONFIG_GH_OWNER", required=True)
    repo = env("EXECUTOR_CONFIG_GH_REPO", required=True)
    scan_types = parse_scan_types(env("EXECUTOR_CONFIG_GH_SCAN_TYPES"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_GH_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    headers = build_auth_headers(token)

    log(f"Processing {owner}/{repo} " f"(scan_types={','.join(scan_types)}, min_severity={min_severity})")

    vulns = []
    if "code" in scan_types:
        for alert in fetch_code_scanning(base_url, headers, owner, repo):
            if not isinstance(alert, dict):
                continue
            built = build_code_scanning_vuln(alert, owner, repo)
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
    if "secrets" in scan_types:
        for alert in fetch_secret_scanning(base_url, headers, owner, repo):
            if not isinstance(alert, dict):
                continue
            built = build_secret_scanning_vuln(alert, owner, repo)
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
    if "dependabot" in scan_types:
        for alert in fetch_dependabot(base_url, headers, owner, repo):
            if not isinstance(alert, dict):
                continue
            built = build_dependabot_vuln(alert, owner, repo)
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)

    hosts = [build_host(owner, repo, vulns)] if vulns else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "github_security",
            "command": "github_security",
            "params": (
                f"owner={owner},repo={repo}," f"scan_types={','.join(scan_types)}," f"min_severity={min_severity}"
            ),
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
