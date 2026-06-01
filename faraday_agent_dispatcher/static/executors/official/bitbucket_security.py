#!/usr/bin/env python
"""Bitbucket Cloud Code Insights REST API importer.

Pulls Code Insights security reports (and their annotations) from a
Bitbucket Cloud repository at a specific commit and emits Faraday
bulk-create JSON to stdout. Each Bitbucket repository becomes one
Faraday host (``ip`` = synthetic ``0.0.0.0`` because Code Insights
findings live in source repos and pull-request diffs, not on IPs); each
Code Insights annotation attached to a SECURITY-type report becomes one
Faraday vulnerability.

Endpoints used:
  GET /2.0/repositories/{workspace}/{repo}/commit/{commit}/reports
      -> list Code Insights reports posted against the commit
      (paginated via ``page`` / ``pagelen``). Each report carries
      report_type (SECURITY / COVERAGE / TEST / BUG), title, details,
      result, reporter and link metadata.
  GET /2.0/repositories/{workspace}/{repo}/commit/{commit}/reports/
      {report_id}/annotations
      -> per-report annotations (paginated). Each annotation carries
      annotation_type (VULNERABILITY / CODE_SMELL / BUG), severity
      (CRITICAL/HIGH/MEDIUM/LOW), summary, details, path, line, link
      and result (PASSED / FAILED / SKIPPED / IGNORED).
  GET /2.0/repositories/{workspace}/{repo}
      -> single repository meta (used for host description / hostname).

Auth: HTTP Basic with BB_USER + BB_APP_PASSWORD. BB_APP_PASSWORD is a
Bitbucket Cloud App Password (Personal Settings → App passwords) with
``repository:read`` scope at minimum. The legacy ``username:password``
combination is rejected by Bitbucket Cloud since 2022 — App Passwords
or Workspace Access Tokens are the only supported auth methods. A
pre-built ``Bearer <token>`` value (Workspace / Project Access Token)
is also accepted in BB_APP_PASSWORD and routed to the Authorization
header verbatim.
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
PAGE_SIZE = 100
MAX_PAGES = 200
DEFAULT_HOST = "https://api.bitbucket.org"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Bitbucket Code Insights severity enum is CRITICAL / HIGH / MEDIUM / LOW.
# A handful of integrators also surface INFO / INFORMATIONAL / NONE — we
# accept those so older / vendor-specific report producers still import.
BB_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unknown": "info",
}

# Bitbucket Code Insights annotation_type values. Only the
# vulnerability-shaped ones are imported by default; CODE_SMELL / BUG
# / TEST are filtered out unless BB_INCLUDE_NON_VULN is set, because
# they are not security findings.
SECURITY_ANNOTATION_TYPES = {"vulnerability", "security"}

# Bitbucket Code Insights annotation ``result`` enum:
#   PASSED  -> check passed (the finding is informational only -> closed)
#   FAILED  -> the security check identified the issue (open)
#   SKIPPED -> the check did not run (treated as open so analysts see it)
#   IGNORED -> the integrator explicitly ignored the finding
#              (risk-accepted)
RESULT_TO_STATUS = {
    "failed": "open",
    "skipped": "open",
    "pending": "open",
    "passed": "closed",
    "ignored": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - BitbucketSecurity: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
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


def severity_from_bb(value, cvss=None):
    """Map a Bitbucket Code Insights severity to a Faraday bucket.

    Accepts Bitbucket's string enum (CRITICAL / HIGH / MEDIUM / LOW)
    plus a handful of nearby aliases, and falls back to CVSS bucketing
    on the provided ``cvss`` argument when the primary value is
    missing / unrecognised. Numeric inputs are interpreted as CVSS v3
    scores so vendor-shaped reports that surface a bare score still
    bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in BB_TO_FARADAY:
            return BB_TO_FARADAY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_annotation(annotation):
    """Derive Faraday status from an annotation's result / state flags.

    Bitbucket annotations carry a top-level ``result`` enum (PASSED /
    FAILED / SKIPPED / IGNORED / PENDING). Some integrators also
    surface a separate ``state`` / ``status`` field plus a boolean
    ``ignored`` / ``false_positive`` triage flag — we honour the most
    specific signal first so analyst-triaged findings land where
    Faraday users expect.
    """
    if not isinstance(annotation, dict):
        return "open"
    for key in ("false_positive", "falsePositive", "is_false_positive", "isFalsePositive"):
        if annotation.get(key) is True:
            return "risk-accepted"
    for key in ("ignored", "isIgnored", "is_ignored", "suppressed", "is_suppressed"):
        if annotation.get(key) is True:
            return "risk-accepted"
    for key in ("fixed", "isFixed", "is_fixed", "resolved", "is_resolved"):
        if annotation.get(key) is True:
            return "closed"
    for key in ("result", "state", "status"):
        raw = annotation.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value")
        if isinstance(raw, str):
            mapped = RESULT_TO_STATUS.get(raw.strip().lower())
            if mapped:
                return mapped
    return "open"


def build_auth_header(user, app_password):
    """Build the Authorization header for the Bitbucket REST API.

    Bitbucket Cloud accepts HTTP Basic with user + app password as the
    documented auth scheme. A pre-built ``Bearer ...`` value in
    BB_APP_PASSWORD (Workspace / Project Access Token) is forwarded
    verbatim because those tokens are sent as ``Authorization: Bearer
    <token>``.
    """
    if not app_password:
        return {}
    text = str(app_password).strip()
    lower = text.lower()
    if lower.startswith("bearer ") or lower.startswith("token "):
        return {"Authorization": text}
    if not user:
        return {"Authorization": f"Bearer {text}"}
    encoded = base64.b64encode(f"{user}:{text}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def normalize_base_url(host):
    if not host:
        return DEFAULT_HOST
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def request_json(method, url, headers, params=None, payload=None):
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=payload,
            timeout=TIMEOUT,
            verify=False,
        )
    except requests.RequestException as exc:
        log(f"{method} {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). Check BB_USER / BB_APP_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {url}. Check the App Password scope.")
        return None
    if resp.status_code == 404:
        log(f"{method} {url} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"{method} {url} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        log(f"{method} {url} returned non-JSON body")
        return None


def extract_list(body):
    """Pluck a list of values out of a Bitbucket REST response.

    Bitbucket's REST endpoints uniformly wrap pages in ``{"values":
    [...], "next": "..."}``. A handful of internal endpoints also
    surface a bare list / ``data`` / ``items`` shape, so we tolerate
    each of those (and an empty-string / None response from a 204).
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for candidate in ("values", "data", "items", "results", "annotations", "reports"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, params=None):
    """Walk a Bitbucket paginated endpoint via ``page`` / ``pagelen``.

    Bitbucket Cloud honours the ``next`` URL on every page; we prefer
    that when present and fall back to incrementing the page counter
    otherwise.
    """
    results = []
    url = f"{base_url}{path}" if path.startswith("/") else f"{base_url}/{path}"
    query = dict(params or {})
    query.setdefault("pagelen", PAGE_SIZE)
    page = 1
    for _ in range(MAX_PAGES):
        query["page"] = page
        body = request_json("GET", url, headers, params=query)
        chunk = extract_list(body)
        if not chunk:
            break
        results.extend(chunk)
        next_url = body.get("next") if isinstance(body, dict) else None
        if next_url:
            url = next_url
            query = None
            page += 1
            continue
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def get_repo(base_url, headers, workspace, repo):
    url = f"{base_url}/2.0/repositories/{workspace}/{repo}"
    body = request_json("GET", url, headers)
    return body if isinstance(body, dict) else {}


def get_reports(base_url, headers, workspace, repo, commit):
    return collect(
        base_url,
        f"/2.0/repositories/{workspace}/{repo}/commit/{commit}/reports",
        headers,
    )


def get_annotations(base_url, headers, workspace, repo, commit, report_id):
    return collect(
        base_url,
        f"/2.0/repositories/{workspace}/{repo}/commit/{commit}/reports/{report_id}/annotations",
        headers,
    )


def report_id_of(report):
    if not isinstance(report, dict):
        return None
    return report.get("external_id") or report.get("externalId") or report.get("uuid") or report.get("id")


def is_security_report(report):
    if not isinstance(report, dict):
        return False
    rtype = report.get("report_type") or report.get("reportType") or ""
    return isinstance(rtype, str) and rtype.strip().lower() in {"security", "vulnerability"}


def cvss_score(annotation):
    """Pull a numeric CVSS score out of a Bitbucket annotation.

    Bitbucket's Code Insights spec does not standardise a CVSS field,
    but several integrators (Snyk, JFrog, Checkmarx, etc.) surface one
    on the annotation payload under a handful of conventional keys —
    we walk the usual suspects so the imported severity matches what
    the integrator originally posted.
    """
    if not isinstance(annotation, dict):
        return None
    for key in ("cvss_score", "cvssScore", "cvss", "score"):
        value = annotation.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for key in ("cvss3", "cvssV3", "cvss_v3"):
        nested = annotation.get(key)
        if isinstance(nested, dict):
            for k in ("base_score", "baseScore", "score"):
                score = nested.get(k)
                if score is None:
                    continue
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
    return None


def collect_refs(annotation):
    """Walk an annotation for CWE / OWASP / vendor refs + URLs."""
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

    cwe_raw = annotation.get("cwe") or annotation.get("cweId") or annotation.get("cwe_id")
    if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
        add(f"CWE-{int(cwe_raw)}")
    elif isinstance(cwe_raw, str) and cwe_raw.strip():
        s = cwe_raw.strip()
        add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
    for key in ("cwes", "cweIds", "cwe_ids"):
        items = annotation.get(key)
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    cid = it.get("id") or it.get("value") or it.get("name")
                    if cid is None:
                        continue
                    text = str(cid).strip()
                    add(text if text.upper().startswith("CWE-") else f"CWE-{text}")
                elif isinstance(it, (int, float)) and not isinstance(it, bool):
                    add(f"CWE-{int(it)}")
                elif isinstance(it, str) and it.strip():
                    s = it.strip()
                    add(s if s.upper().startswith("CWE-") else f"CWE-{s}")

    owasp = annotation.get("owasp") or annotation.get("owaspCategory") or annotation.get("owasp_category")
    if isinstance(owasp, str) and owasp.strip():
        add(f"OWASP: {owasp.strip()}")
    elif isinstance(owasp, list):
        for entry in owasp:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("value") or entry.get("id")
                if name:
                    add(f"OWASP: {name}")
            elif entry:
                add(f"OWASP: {entry}")

    rule = annotation.get("rule_id") or annotation.get("ruleId") or annotation.get("rule")
    if rule:
        add(f"BitbucketRule-{rule}")
    check_id = annotation.get("check_id") or annotation.get("checkId")
    if check_id:
        add(f"BitbucketCheck-{check_id}")

    link = annotation.get("link")
    if isinstance(link, str) and link.strip():
        add(link.strip())
    elif isinstance(link, dict):
        href = link.get("href") or link.get("url") or link.get("name")
        if href:
            add(href)

    for entry in annotation.get("references") or annotation.get("links") or []:
        if isinstance(entry, dict):
            href = entry.get("href") or entry.get("url") or entry.get("name")
            if href:
                add(href)
        elif entry:
            add(str(entry))

    return refs


def collect_cves(annotation):
    """Pull CVE-* ids out of a Bitbucket annotation (deduped, upper-cased)."""
    if not isinstance(annotation, dict):
        return []
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if not s:
            return
        if not s.startswith("CVE-"):
            s = f"CVE-{s}"
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    for key in ("cve", "cveId", "cveName", "cve_name"):
        v = annotation.get(key)
        if isinstance(v, str) and v.strip():
            add(v)
    for key in ("cves", "cveIds", "cve_ids"):
        v = annotation.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("name") or entry.get("id") or entry.get("value"))
    return found


def location_summary(annotation):
    """Format the file / line location surfaced by an annotation."""
    if not isinstance(annotation, dict):
        return None
    path = annotation.get("path") or annotation.get("file") or annotation.get("filename")
    line = annotation.get("line") or annotation.get("lineNumber") or annotation.get("line_number")
    if path and line not in (None, "", 0):
        return f"location: {path}:{line}"
    if path:
        return f"location: {path}"
    return None


def report_meta(report):
    if not isinstance(report, dict):
        return {}
    return {
        "id": report_id_of(report),
        "title": report.get("title") or report.get("name") or "",
        "reporter": report.get("reporter") or "",
        "result": report.get("result") or "",
        "report_type": report.get("report_type") or report.get("reportType") or "",
        "link": (
            report.get("link")
            if isinstance(report.get("link"), str)
            else (report.get("link") or {}).get("href") if isinstance(report.get("link"), dict) else ""
        ),
        "logo_url": report.get("logo_url") or report.get("logoUrl") or "",
        "details": report.get("details") or "",
    }


def build_vulnerability(annotation, report=None, commit=None):
    score = cvss_score(annotation)
    severity = severity_from_bb(annotation.get("severity"), score)
    status = status_from_annotation(annotation)

    summary = annotation.get("summary") or annotation.get("title") or annotation.get("name") or ""
    raw_name = summary or (
        f"Bitbucket finding {annotation.get('external_id') or annotation.get('uuid') or ''}".strip()
    )
    rmeta = report_meta(report) if report else {}
    prefix = None
    if rmeta.get("report_type"):
        rt = rmeta["report_type"].strip().lower()
        if rt in ("security", "vulnerability"):
            prefix = "[SAST]"
    if not prefix:
        atype = annotation.get("annotation_type") or annotation.get("annotationType") or ""
        if isinstance(atype, str) and atype.strip().lower() in SECURITY_ANNOTATION_TYPES:
            prefix = "[SAST]"
    name = f"{prefix} {raw_name}" if prefix else str(raw_name)

    desc_parts = []
    details = annotation.get("details") or annotation.get("description")
    if details:
        desc_parts.append(str(details))

    loc_text = location_summary(annotation)
    if loc_text:
        desc_parts.append(loc_text)

    atype = annotation.get("annotation_type") or annotation.get("annotationType")
    if atype:
        desc_parts.append(f"annotation_type: {atype}")

    if rmeta.get("title"):
        desc_parts.append(f"report: {rmeta['title']}")
    if rmeta.get("reporter"):
        desc_parts.append(f"reporter: {rmeta['reporter']}")
    if rmeta.get("id") and rmeta["id"] != (annotation.get("external_id") or annotation.get("uuid")):
        desc_parts.append(f"report_id: {rmeta['id']}")
    if commit:
        desc_parts.append(f"commit: {commit}")

    result_raw = annotation.get("result")
    if result_raw:
        desc_parts.append(f"result: {result_raw}")

    created = annotation.get("created_on") or annotation.get("createdOn")
    if created:
        desc_parts.append(f"created: {created}")
    updated = annotation.get("updated_on") or annotation.get("updatedOn")
    if updated:
        desc_parts.append(f"updated: {updated}")

    external_id = (
        annotation.get("external_id")
        or annotation.get("externalId")
        or annotation.get("uuid")
        or annotation.get("id")
        or ""
    )
    if external_id:
        desc_parts.append(f"annotation_id: {external_id}")

    if score is not None:
        desc_parts.append(f"cvss: {score}")

    cves = collect_cves(annotation)
    refs = collect_refs(annotation)

    resolution = (
        annotation.get("resolution")
        or annotation.get("remediation")
        or annotation.get("recommendation")
        or annotation.get("solution")
        or annotation.get("fix")
        or ""
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score

    return {
        "name": str(name).strip()[:200] or f"Bitbucket finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id),
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["bitbucket_security", "sast"],
    }


def build_host(workspace, repo, commit, repo_meta, vulns):
    hostname = f"{workspace}/{repo}" if workspace and repo else (workspace or repo or "")
    hostnames = [hostname] if hostname else []
    desc_parts = []
    if commit:
        desc_parts.append(f"commit={commit}")
    full_name = ""
    if isinstance(repo_meta, dict):
        full_name = repo_meta.get("full_name") or repo_meta.get("fullName") or ""
        if full_name and full_name != hostname:
            desc_parts.append(f"full_name={full_name}")
        for key, label in (
            ("name", "name"),
            ("uuid", "uuid"),
            ("description", "description"),
            ("language", "language"),
            ("mainbranch", "main_branch"),
        ):
            value = repo_meta.get(key) if isinstance(repo_meta, dict) else None
            if isinstance(value, dict):
                value = value.get("name") or value.get("value")
            if value:
                desc_parts.append(f"{label}={value}")
        links = repo_meta.get("links") if isinstance(repo_meta, dict) else None
        if isinstance(links, dict):
            html = links.get("html")
            if isinstance(html, dict) and html.get("href"):
                desc_parts.append(f"url={html['href']}")
            elif isinstance(html, str):
                desc_parts.append(f"url={html}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"BB_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def main():
    started = time.time()
    host = env("BB_HOST", default=DEFAULT_HOST)
    user = env("BB_USER")
    app_password = env("BB_APP_PASSWORD", required=True)
    workspace = env("EXECUTOR_CONFIG_BB_WORKSPACE", required=True)
    repo = env("EXECUTOR_CONFIG_BB_REPO", required=True)
    commit = env("EXECUTOR_CONFIG_BB_COMMIT", required=True)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_BB_MIN_SEVERITY"))
    include_non_vuln = env("EXECUTOR_CONFIG_BB_INCLUDE_NON_VULN", default="").strip().lower() in (
        "1",
        "true",
        "yes",
        "y",
    )
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    headers = build_auth_header(user, app_password)
    headers["Accept"] = "application/json"

    repo_meta = get_repo(base_url, headers, workspace, repo)

    reports = get_reports(base_url, headers, workspace, repo, commit)
    log(
        f"Processing {len(reports)} Code Insights report(s) "
        f"(workspace={workspace}, repo={repo}, commit={commit[:12] if commit else ''}, "
        f"min_severity={min_severity})"
    )

    vulns = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        if not include_non_vuln and not is_security_report(report):
            continue
        rid = report_id_of(report)
        if not rid:
            continue
        annotations = get_annotations(base_url, headers, workspace, repo, commit, rid)
        for ann in annotations:
            if not isinstance(ann, dict):
                continue
            if not include_non_vuln:
                atype = ann.get("annotation_type") or ann.get("annotationType") or ""
                if isinstance(atype, str) and atype.strip() and atype.strip().lower() not in SECURITY_ANNOTATION_TYPES:
                    continue
            built = build_vulnerability(ann, report=report, commit=commit)
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)

    hosts = [build_host(workspace, repo, commit, repo_meta, vulns)] if vulns else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "bitbucket_security",
            "command": "bitbucket_security",
            "params": (f"workspace={workspace},repo={repo},commit={commit}," f"min_severity={min_severity}"),
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
