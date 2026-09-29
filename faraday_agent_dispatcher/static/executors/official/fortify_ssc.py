#!/usr/bin/env python
"""Fortify Software Security Center (SSC) REST API importer.

Pulls source-code findings from a Fortify SSC server and emits Faraday
bulk-create JSON to stdout. Each Fortify SSC project version becomes one
Faraday host (``ip`` = synthetic ``0.0.0.0`` because SAST findings live
in source repos, not on IPs); per-project-version issues are attached
as Faraday vulnerabilities — one per Fortify issue identifier.

Endpoints used:
  GET  /api/v1/projectVersions                            -> list of
      project versions (paginated via ``start`` / ``limit``); or single
      project version via /api/v1/projectVersions/{id} when
      FORTIFY_SSC_PROJECT_VERSION_ID is set.
  GET  /api/v1/projectVersions/{id}/issues                -> per
      project-version issues (paginated). Each entry carries severity
      bucket (``friority``), numeric severity score, analyzer / engine
      type, source ``fullFileName`` + ``lineNumber``, primaryTag,
      ``issueInstanceId`` (similarity-like correlation key), audit
      state (``audited``, ``primaryTagValueAutoApplied``) and
      removal / suppression flags.
  GET  /api/v1/issueDetails/{id}                          -> optional
      per-issue enrichment: detail / recommendation / brief / kingdom /
      subType. Used to populate Faraday ``desc`` and ``resolution``.

Auth: two supported shapes —
  * Token (preferred): FORTIFY_SSC_TOKEN holds a Fortify
    ``UnifiedLoginToken`` (or any ``CIToken`` / similar) and is sent as
    ``Authorization: FortifyToken <token>`` on every API call.
  * Basic: FORTIFY_SSC_USER + FORTIFY_SSC_PASSWORD are sent as HTTP
    Basic auth — used when no token is configured.
FORTIFY_SSC_HOST is the SSC manager base URL (e.g.
https://ssc.corp.example.com/ssc — Fortify SSC is typically deployed
under the ``/ssc`` context path; either with or without the suffix is
accepted, the executor will append ``/ssc`` when the path is missing).
"""

import base64
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 200
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Fortify SSC reports severity buckets via the ``friority`` field
# (Critical/High/Medium/Low). Older / configurable installs may report
# ``severity`` as a string or as a numeric severity score (Fortify's
# 0.0-5.0 scale). Both shapes are normalised here.
FORTIFY_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "information": "info",
    "informational": "info",
    "none": "info",
}


def log(msg):
    print(f"{datetime.utcnow()} - FortifySSC: {msg}", file=sys.stderr, flush=True)


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


def severity_from_fortify_score(score):
    """Map Fortify's 0.0 - 5.0 numeric severity score to a Faraday bucket.

    Fortify documents the scale as: <2.5 low, 2.5-4 medium, 4-5 high,
    and Critical for high-likelihood + high-impact (typically scored 5).
    """
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "info"
    if score <= 0:
        return "info"
    if score < 2.5:
        return "low"
    if score < 4:
        return "medium"
    if score < 5:
        return "high"
    return "critical"


def severity_from_fortify(value, score=None):
    if value is not None:
        if isinstance(value, (int, float)):
            return severity_from_fortify_score(value)
        text = str(value).strip().lower()
        if text in FORTIFY_STRING_SEVERITY:
            return FORTIFY_STRING_SEVERITY[text]
        try:
            return severity_from_fortify_score(float(text))
        except ValueError:
            pass
    if score is not None:
        return severity_from_fortify_score(score)
    return "info"


def status_from_fortify(issue):
    """Derive Faraday status from Fortify SSC issue flags.

    Fortify SSC issues carry several lifecycle / audit flags:
      * ``removed`` — finding no longer exists in the latest scan.
      * ``suppressed`` / ``hidden`` — analyst-hidden from default views.
      * ``primaryTag`` / ``primaryTagValueAutoApplied`` — audit verdict.
        The canonical "Analysis" custom tag has values like
        ``Not an Issue``, ``Suspicious``, ``Reliability Issue``,
        ``Bad Practice`` and ``Exploitable``. ``Not an Issue`` /
        ``Not Exploitable`` -> risk-accepted; everything else stays open.
    """
    if issue.get("removed"):
        return "closed"
    if issue.get("suppressed") or issue.get("hidden"):
        return "risk-accepted"
    tag = issue.get("primaryTag") or issue.get("primaryTagValueAutoApplied")
    if isinstance(tag, dict):
        tag = tag.get("value") or tag.get("name")
    if tag:
        text = str(tag).strip().lower()
        if text in (
            "not an issue",
            "not_an_issue",
            "not exploitable",
            "not_exploitable",
            "false positive",
            "false_positive",
        ):
            return "risk-accepted"
    return "open"


def build_auth_header(token, user, password):
    if token:
        # Fortify SSC accepts a UnifiedLoginToken / CIToken via the
        # ``FortifyToken <token>`` Authorization scheme (the same string
        # format ``fortifyclient`` prints). Some deployments also accept
        # a bare ``Bearer <token>`` — FortifyToken is the documented
        # default and works on every supported SSC version.
        return f"FortifyToken {token}"
    if user and password is not None:
        creds = f"{user}:{password}".encode("utf-8")
        return f"Basic {base64.b64encode(creds).decode('ascii')}"
    log("Either FORTIFY_SSC_TOKEN or FORTIFY_SSC_USER + FORTIFY_SSC_PASSWORD are required")
    sys.exit(1)


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"GET {path} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). Token expired or credentials invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check token scope / user permissions.")
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
    """Pluck a list out of a Fortify SSC JSON response.

    Fortify SSC wraps list responses in ``{"data": [...], "count": N,
    "responseCode": 200, "links": {...}}``. Single-resource responses
    wrap the resource in ``{"data": {...}}``. Older deployments may
    return ``items`` instead of ``data``.
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
        for candidate in ("data", "items", "results"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, base_params):
    """Paginate Fortify SSC list endpoints via ``start`` + ``limit``."""
    results = []
    start = 0
    for _ in range(MAX_PAGES):
        params = dict(base_params or {})
        params["start"] = start
        params["limit"] = PAGE_SIZE
        body = get_page(base_url, path, headers, params)
        chunk = extract_list(body, "data")
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("count") or body.get("totalCount") or body.get("total")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        start += PAGE_SIZE
    return results


def get_project_versions(base_url, headers, project_version_id):
    if project_version_id:
        body = get_page(base_url, f"/api/v1/projectVersions/{project_version_id}", headers, {})
        if isinstance(body, dict):
            data = body.get("data")
            if isinstance(data, dict):
                return [data]
            if isinstance(body.get("id"), int) or isinstance(body.get("id"), str):
                return [body]
        return []
    return collect(base_url, "/api/v1/projectVersions", headers, {})


def get_issues(base_url, headers, project_version_id):
    # ``showremoved=true`` so we can map ``removed`` -> Faraday closed
    # status; ``showsuppressed=true`` / ``showhidden=true`` so analyst
    # decisions show up as ``risk-accepted``.
    base_params = {
        "showremoved": "true",
        "showsuppressed": "true",
        "showhidden": "true",
    }
    return collect(
        base_url,
        f"/api/v1/projectVersions/{project_version_id}/issues",
        headers,
        base_params,
    )


def get_issue_details(base_url, headers, issue_id):
    body = get_page(base_url, f"/api/v1/issueDetails/{issue_id}", headers, {})
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, dict):
            return data
    return {}


def collect_refs(issue, details):
    refs = []
    seen = set()

    def add(name, ref_type="other"):
        if not name:
            return
        text = str(name).strip()
        if not text or text in seen:
            return
        seen.add(text)
        refs.append({"name": text, "type": ref_type or "other"})

    for source in (details, issue):
        if not isinstance(source, dict):
            continue
        kingdom = source.get("kingdom")
        if kingdom:
            add(f"Kingdom: {kingdom}")
        sub_type = source.get("subType") or source.get("subtype")
        if sub_type:
            add(f"SubType: {sub_type}")
        primary_rule = source.get("primaryRuleGuid") or source.get("primaryRuleId")
        if primary_rule:
            add(f"FortifyRule-{primary_rule}")
        for cwe_field in ("cwe", "cweId", "cweIds", "cwes"):
            value = source.get(cwe_field)
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
    return refs


def build_vulnerability(issue, details):
    score = (
        issue.get("severity")
        if isinstance(issue.get("severity"), (int, float))
        else issue.get("scaledSeverity") or issue.get("impact")
    )
    severity = severity_from_fortify(issue.get("friority") or issue.get("severity"), score)
    status = status_from_fortify(issue)
    analyzer = (
        issue.get("analyzer")
        or issue.get("analyzerName")
        or issue.get("engineType")
        or details.get("engineType")
        or "SAST"
    )
    issue_name = (
        issue.get("issueName")
        or issue.get("primaryRuleGuid")
        or details.get("issueName")
        or details.get("brief")
        or f"Fortify SSC {analyzer} finding"
    )
    name = f"[SAST] {issue_name}"

    desc_parts = []
    brief = details.get("brief") or details.get("briefHTML") or details.get("detail")
    if brief:
        desc_parts.append(str(brief))
    description = details.get("detail") or details.get("explanation") or details.get("description")
    if description and description != brief:
        desc_parts.append(str(description))

    location_parts = []
    file_name = (
        issue.get("fullFileName")
        or issue.get("primaryLocation")
        or issue.get("fileName")
        or details.get("fullFileName")
    )
    if file_name:
        line = issue.get("lineNumber") or details.get("lineNumber") or issue.get("primaryLine")
        if line:
            location_parts.append(f"{file_name}:{line}")
        else:
            location_parts.append(str(file_name))
    if location_parts:
        desc_parts.append("location: " + ", ".join(location_parts))

    sink_file = issue.get("sinkFileName") or details.get("sinkFileName")
    if sink_file:
        sink_line = issue.get("sinkLineNumber") or details.get("sinkLineNumber")
        if sink_line:
            desc_parts.append(f"sink: {sink_file}:{sink_line}")
        else:
            desc_parts.append(f"sink: {sink_file}")

    instance_id = issue.get("issueInstanceId") or issue.get("instanceId") or details.get("instanceId")
    if instance_id:
        desc_parts.append(f"issueInstanceId: {instance_id}")

    tag = issue.get("primaryTag") or issue.get("primaryTagValueAutoApplied")
    if isinstance(tag, dict):
        tag = tag.get("value") or tag.get("name")
    if tag:
        desc_parts.append(f"primaryTag: {tag}")

    if issue.get("audited"):
        desc_parts.append("audited: true")
    if issue.get("revision"):
        desc_parts.append(f"revision: {issue.get('revision')}")

    resolution = details.get("recommendation") or details.get("tips") or ""

    score_value = issue.get("scaledSeverity") if isinstance(issue.get("scaledSeverity"), (int, float)) else score

    return {
        "name": str(name).strip()[:200] or f"Fortify SSC {analyzer} finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(issue.get("id") or issue.get("issueInstanceId") or instance_id or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": collect_refs(issue, details),
        "cve": [],
        "cvss3": {"base_score": str(score_value)} if score_value not in (None, "") else {},
        "tags": ["fortify_ssc", str(analyzer).lower()],
    }


def build_host(project_version, vulns):
    project = project_version.get("project") or {}
    project_name = project.get("name") if isinstance(project, dict) else None
    pv_name = project_version.get("name") or "unknown"
    label = f"{project_name}/{pv_name}" if project_name and project_name != pv_name else pv_name
    pv_id = project_version.get("id", "N/A")
    desc_parts = [f"Fortify SSC project version name={label}", f"id={pv_id}"]
    issue_template = project_version.get("issueTemplateName")
    if issue_template:
        desc_parts.append(f"issueTemplate={issue_template}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [label] if label else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def normalize_base_url(host):
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    base = base.rstrip("/")
    # Fortify SSC is typically deployed under ``/ssc``; accept both
    # ``https://ssc.corp.example.com`` and
    # ``https://ssc.corp.example.com/ssc`` by appending the context path
    # when the URL doesn't already include it.
    if not base.endswith("/ssc") and "/ssc/" not in base + "/":
        base = f"{base}/ssc"
    return base


def main():
    started = time.time()
    host = env("FORTIFY_SSC_HOST", required=True).rstrip("/")
    token = env("FORTIFY_SSC_TOKEN")
    user = env("FORTIFY_SSC_USER")
    password = env("FORTIFY_SSC_PASSWORD")
    project_version_id = env("EXECUTOR_CONFIG_FORTIFY_SSC_PROJECT_VERSION_ID")
    min_severity = (env("EXECUTOR_CONFIG_FORTIFY_SSC_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"FORTIFY_SSC_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = normalize_base_url(host)

    headers = {
        "Authorization": build_auth_header(token, user, password),
        "Accept": "application/json",
    }

    project_versions = get_project_versions(base_url, headers, project_version_id)
    log(f"Found {len(project_versions)} project version(s) " f"(project_version_id={project_version_id or 'all'})")

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    for pv in project_versions:
        pv_id = pv.get("id")
        if not pv_id:
            continue
        raw_issues = get_issues(base_url, headers, pv_id)
        vulns = []
        for issue in raw_issues:
            if not isinstance(issue, dict):
                continue
            issue_id = issue.get("id")
            details = get_issue_details(base_url, headers, issue_id) if issue_id else {}
            vuln = build_vulnerability(issue, details)
            if SEVERITY_ORDER.get(vuln["severity"], 0) >= min_threshold:
                vulns.append(vuln)
        if not vulns:
            continue
        hosts.append(build_host(pv, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "fortify_ssc",
            "command": "fortify_ssc",
            "params": (f"project_version_id={project_version_id or 'all'} " f"min_severity={min_severity}"),
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
