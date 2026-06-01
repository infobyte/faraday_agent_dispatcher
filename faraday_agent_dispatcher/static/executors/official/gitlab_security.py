#!/usr/bin/env python
"""GitLab Vulnerability Report REST API importer.

Pulls security findings (SAST / dependency_scanning / container_scanning /
secret_detection / DAST / API-fuzzing / coverage-fuzzing) from a GitLab
instance and emits Faraday bulk-create JSON to stdout. Each GitLab project
becomes one Faraday host (``ip`` = synthetic ``0.0.0.0`` because most
GitLab Security Dashboard findings live in source repos and merge-request
diffs, not on IPs); per-project findings are attached as Faraday
vulnerabilities — one per GitLab vulnerability_findings id.

Endpoints used:
  GET /api/v4/projects/{id}/vulnerability_findings   -> per-project security
      findings (paginated via ``page`` / ``per_page``). Each entry carries
      severity, confidence, scanner, identifiers (CVE / CWE / vendor ids),
      report_type, scanner / report metadata, location (file:line +
      dependency package@version for SCA), description and links.
  GET /api/v4/projects/{id}                          -> single project meta
      (used when GITLAB_PROJECT_ID is set).
  GET /api/v4/projects?membership=true               -> enumerate accessible
      projects when no project id is provided (paginated, simple shape).

Auth: ``PRIVATE-TOKEN: <GITLAB_TOKEN>`` carrying a personal / project /
group access token with at least ``read_api`` scope (and project Reporter
role for vulnerability_findings access). Pre-built ``Bearer`` / ``OAuth``
prefixes in the supplied value are detected and forwarded as the
``Authorization`` header instead so OAuth2 / SSO-backed deployments work
too. GITLAB_HOST is the GitLab base URL (e.g. https://gitlab.com or the
self-hosted instance URL).
"""

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

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# GitLab reports severity using its own bucket set. "unknown" is a real
# GitLab severity value used by some scanners (e.g. dependency_scanning
# when CVSS data is missing); we collapse it to "info" rather than dropping
# the finding. CVSS numeric scores fall back through the same ladder.
GITLAB_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unknown": "info",
}

# GitLab vulnerability_findings ``state`` enum:
#   detected   -> finding present in the latest pipeline (open)
#   confirmed  -> analyst confirmed real (open)
#   dismissed  -> analyst dismissed as false positive / accepted risk
#   resolved   -> remediated in the latest pipeline
STATE_TO_STATUS = {
    "detected": "open",
    "confirmed": "open",
    "dismissed": "risk-accepted",
    "resolved": "closed",
}

# Valid GitLab Security Dashboard report types. Other values silently pass
# through so newer GitLab releases that introduce additional report types
# (e.g. ``api_fuzzing``, ``coverage_fuzzing``) still work without code
# changes.
VALID_REPORT_TYPES = (
    "sast",
    "dependency_scanning",
    "container_scanning",
    "secret_detection",
    "dast",
    "api_fuzzing",
    "coverage_fuzzing",
)

# Per-report-type engine prefix on the vulnerability name. Matches the
# convention used by the other code-sast executors so downstream Faraday
# users can tell at a glance which engine produced the finding.
REPORT_TYPE_TO_PREFIX = {
    "sast": "[SAST]",
    "dependency_scanning": "[SCA]",
    "container_scanning": "[CONTAINER]",
    "secret_detection": "[SECRETS]",
    "dast": "[DAST]",
    "api_fuzzing": "[API-FUZZ]",
    "coverage_fuzzing": "[COV-FUZZ]",
}


def log(msg):
    print(f"{datetime.utcnow()} - GitLabSecurity: {msg}", file=sys.stderr, flush=True)


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


def severity_from_gitlab(value, cvss=None):
    """Map GitLab's severity field to a Faraday severity bucket.

    Accepts GitLab's string enum (info / unknown / low / medium / high /
    critical) plus a couple of nearby aliases. Falls back to CVSS
    bucketing on the provided ``cvss`` argument when the primary value is
    missing or unrecognised. ``unknown`` collapses to ``info`` so the
    finding still imports — analysts can re-triage in Faraday.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in GITLAB_TO_FARADAY:
            return GITLAB_TO_FARADAY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_gitlab(vuln):
    """Derive Faraday status from GitLab's state / dismissal flags.

    GitLab tracks finding lifecycle via ``state`` (detected / confirmed /
    dismissed / resolved). Older API shapes still surface
    ``vulnerability_feedback`` with ``feedback_type=dismissal`` and the
    boolean ``false_positive`` flag — both wind up as risk-accepted.
    """
    if vuln.get("false_positive") is True or vuln.get("falsePositive") is True:
        return "risk-accepted"
    feedback = vuln.get("vulnerability_feedback") or vuln.get("dismissal_feedback")
    if isinstance(feedback, dict):
        ftype = feedback.get("feedback_type") or feedback.get("feedbackType")
        if isinstance(ftype, str) and ftype.strip().lower() == "dismissal":
            return "risk-accepted"
    elif isinstance(feedback, list):
        for entry in feedback:
            if not isinstance(entry, dict):
                continue
            ftype = entry.get("feedback_type") or entry.get("feedbackType")
            if isinstance(ftype, str) and ftype.strip().lower() == "dismissal":
                return "risk-accepted"
    state = vuln.get("state") or vuln.get("status")
    if isinstance(state, str):
        mapped = STATE_TO_STATUS.get(state.strip().lower())
        if mapped:
            return mapped
    return "open"


def build_auth_headers(token):
    """Build the request auth headers for GitLab.

    GitLab accepts a few different schemes. Personal / project / group
    access tokens go in the ``PRIVATE-TOKEN`` header. OAuth2 access
    tokens (and the rare SSO-bridged token) go in ``Authorization:
    Bearer <token>``. A ``CI_JOB_TOKEN`` would go in ``JOB-TOKEN``. We
    detect a pre-built scheme prefix in the supplied value and route it
    accordingly; otherwise default to ``PRIVATE-TOKEN`` which is the
    common case for self-hosted GitLab.
    """
    if not token:
        return {}
    text = str(token).strip()
    lower = text.lower()
    if lower.startswith("bearer "):
        return {"Authorization": text}
    if lower.startswith("oauth "):
        return {"Authorization": "Bearer " + text.split(None, 1)[1]}
    if lower.startswith("private-token "):
        return {"PRIVATE-TOKEN": text.split(None, 1)[1]}
    if lower.startswith("job-token "):
        return {"JOB-TOKEN": text.split(None, 1)[1]}
    return {"PRIVATE-TOKEN": text}


def normalize_base_url(host):
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def request_json(method, base_url, path, headers, params=None, payload=None):
    url = f"{base_url}{path}"
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
        log(f"{method} {path} failed: {exc}")
        return None, None
    if resp.status_code == 401:
        log("Authentication rejected (401). GITLAB_TOKEN expired or invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the token scope / role.")
        return None, resp.headers
    if resp.status_code == 404:
        log(f"{method} {path} returned 404")
        return None, resp.headers
    if resp.status_code >= 400:
        log(f"{method} {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None, resp.headers
    if not resp.content:
        return {}, resp.headers
    try:
        return resp.json(), resp.headers
    except ValueError:
        log(f"{method} {path} returned non-JSON body")
        return None, resp.headers


def extract_list(body):
    """Pluck a list out of a GitLab REST response.

    GitLab's REST endpoints uniformly return a JSON list at the top
    level. A handful of internal endpoints wrap results in
    ``{"data": [...]}`` / ``{"items": [...]}``, so we tolerate both
    shapes (and an empty-string / None response from a 204).
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for candidate in ("data", "items", "results", "findings", "vulnerabilities"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, base_params):
    """Paginate GitLab list endpoints via ``page`` + ``per_page``."""
    results = []
    page = 1
    for _ in range(MAX_PAGES):
        params = dict(base_params or {})
        params["page"] = page
        params["per_page"] = PAGE_SIZE
        body, resp_headers = request_json("GET", base_url, path, headers, params=params)
        chunk = extract_list(body)
        if not chunk:
            break
        results.extend(chunk)
        if len(chunk) < PAGE_SIZE:
            break
        # Honour X-Next-Page when GitLab provides it; otherwise increment.
        next_page = None
        if isinstance(resp_headers, dict) or hasattr(resp_headers, "get"):
            next_page = resp_headers.get("X-Next-Page") if resp_headers else None
        if next_page in (None, "", 0, "0"):
            try:
                next_page = page + 1
            except TypeError:
                break
        try:
            page = int(next_page)
        except (TypeError, ValueError):
            break
    return results


def get_projects(base_url, headers, project_id):
    if project_id:
        body, _ = request_json("GET", base_url, f"/api/v4/projects/{project_id}", headers)
        if isinstance(body, dict) and body:
            return [body]
        return [{"id": project_id, "name": str(project_id)}]
    return collect(
        base_url,
        "/api/v4/projects",
        headers,
        {"membership": "true", "simple": "true", "archived": "false"},
    )


def get_findings(base_url, headers, project_id, report_type, min_severity):
    params = {}
    if report_type:
        params["report_type[]"] = report_type
    if min_severity and min_severity != "info":
        # GitLab severity filter is multi-valued; submit every severity at
        # or above the configured floor so the server-side filter mirrors
        # the client-side floor.
        ladder = ["critical", "high", "medium", "low", "info"]
        floor_idx = ladder.index(min_severity) if min_severity in ladder else len(ladder) - 1
        params["severity[]"] = ladder[: floor_idx + 1]
    return collect(
        base_url,
        f"/api/v4/projects/{project_id}/vulnerability_findings",
        headers,
        params,
    )


def cvss_score(vuln):
    """Pull a numeric CVSS score out of a GitLab vulnerability_finding.

    GitLab Security Dashboard surfaces CVSS data in two places: top-level
    ``cvss`` (a list of ``{vendor, vector}`` entries) and inside
    ``details`` / ``raw_metadata`` (scanner-native shape). We pull the
    explicit base_score where available; otherwise we try to parse a v3
    vector string and fall back to ``scanner.severity``.
    """
    for key in ("cvss_score", "cvssScore", "score"):
        value = vuln.get(key)
        if value is None or isinstance(value, (dict, list)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for key in ("cvss3", "cvssV3", "cvss_v3"):
        value = vuln.get(key)
        if isinstance(value, dict):
            score = value.get("base_score") or value.get("baseScore") or value.get("score")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
    cvss_list = vuln.get("cvss")
    if isinstance(cvss_list, list):
        for entry in cvss_list:
            if not isinstance(entry, dict):
                continue
            score = entry.get("base_score") or entry.get("baseScore") or entry.get("score")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
    return None


def collect_identifiers(vuln):
    """Walk a GitLab finding's identifiers array.

    GitLab identifiers carry ``external_type`` discriminators like
    ``cve``, ``cwe``, ``owasp``, ``ghsa``, ``gemnasium``, ``bandit_test_id``,
    ``semgrep_id``, etc. We split the haul into:

      * ``cves``  -> list of CVE-* strings (deduped, upper-cased)
      * ``refs``  -> [{name, type: "other"}] for everything else, normalised
                    so CWE-* / GHSA-* / OWASP / vendor rules surface with a
                    consistent prefix.
    """
    cves = []
    cve_seen = set()
    refs = []
    refs_seen = set()

    def add_ref(name):
        if not name:
            return
        text = str(name).strip()
        if not text or text in refs_seen:
            return
        refs_seen.add(text)
        refs.append({"name": text, "type": "other"})

    identifiers = vuln.get("identifiers") or []
    if not isinstance(identifiers, list):
        identifiers = []
    for entry in identifiers:
        if not isinstance(entry, dict):
            if entry:
                add_ref(str(entry))
            continue
        ext_type = (entry.get("external_type") or entry.get("externalType") or "").strip().lower()
        ext_id = entry.get("external_id") or entry.get("externalId") or entry.get("value")
        name = entry.get("name")
        if ext_type == "cve" and ext_id:
            text = str(ext_id).strip().upper()
            if not text.startswith("CVE-"):
                text = f"CVE-{text}"
            if text not in cve_seen:
                cve_seen.add(text)
                cves.append(text)
            continue
        if ext_type == "cwe" and ext_id:
            num = str(ext_id).strip()
            num = num[4:] if num.lower().startswith("cwe-") else num
            add_ref(f"CWE-{num}")
            continue
        if ext_type == "ghsa" and ext_id:
            text = str(ext_id).strip()
            add_ref(text if text.upper().startswith("GHSA-") else f"GHSA-{text}")
            continue
        if ext_type == "owasp" and (ext_id or name):
            add_ref(f"OWASP: {ext_id or name}")
            continue
        if ext_id and name:
            add_ref(f"{name} ({ext_id})")
        else:
            add_ref(name or ext_id)

    # Top-level links surface as plain refs (the GitLab UI link list).
    for link in vuln.get("links") or []:
        if isinstance(link, dict):
            url = link.get("url") or link.get("href") or link.get("name")
            add_ref(url)
        elif link:
            add_ref(str(link))

    return cves, refs


def location_summary(vuln):
    """Format the location dict GitLab attaches to each finding.

    Shape varies by report_type:
      * sast / secret_detection: {file, start_line, end_line, class, method}
      * dependency_scanning:    {file, dependency: {package: {name}, version}}
      * container_scanning:     {image, operating_system, dependency: ...}
      * dast:                   {hostname, path, method, param}
    """
    loc = vuln.get("location")
    if not isinstance(loc, dict):
        return None, {}
    parts = []
    info = {}

    file_name = loc.get("file") or loc.get("path") or loc.get("fileName")
    start_line = loc.get("start_line") or loc.get("startLine") or loc.get("line")
    end_line = loc.get("end_line") or loc.get("endLine")
    if file_name:
        info["file"] = file_name
        if start_line and end_line and str(start_line) != str(end_line):
            parts.append(f"location: {file_name}:{start_line}-{end_line}")
        elif start_line:
            parts.append(f"location: {file_name}:{start_line}")
        else:
            parts.append(f"location: {file_name}")
    cls = loc.get("class") or loc.get("className")
    method = loc.get("method") or loc.get("methodName")
    if cls and method:
        parts.append(f"symbol: {cls}.{method}")
    elif cls:
        parts.append(f"class: {cls}")
    elif method:
        parts.append(f"method: {method}")

    dependency = loc.get("dependency")
    if isinstance(dependency, dict):
        package = dependency.get("package")
        pkg_name = ""
        if isinstance(package, dict):
            pkg_name = package.get("name") or ""
        elif isinstance(package, str):
            pkg_name = package
        version = dependency.get("version") or ""
        if pkg_name and version:
            parts.append(f"package: {pkg_name}@{version}")
            info["package"] = f"{pkg_name}@{version}"
        elif pkg_name:
            parts.append(f"package: {pkg_name}")
            info["package"] = pkg_name

    image = loc.get("image")
    if image:
        parts.append(f"image: {image}")
        info["image"] = image
    operating_system = loc.get("operating_system") or loc.get("operatingSystem")
    if operating_system:
        parts.append(f"os: {operating_system}")

    hostname = loc.get("hostname")
    path = loc.get("path")
    http_method = loc.get("method") if not cls else None
    param = loc.get("param") or loc.get("parameter")
    if hostname and path:
        if http_method:
            parts.append(f"request: {http_method} {hostname}{path}")
        else:
            parts.append(f"url: {hostname}{path}")
        info["url"] = f"{hostname}{path}"
    elif hostname:
        parts.append(f"hostname: {hostname}")
        info["hostname"] = hostname
    if param:
        parts.append(f"parameter: {param}")

    return ("\n".join(parts) if parts else None), info


def build_vulnerability(vuln, report_type_override=None):
    score = cvss_score(vuln)
    severity = severity_from_gitlab(vuln.get("severity"), score)
    status = status_from_gitlab(vuln)
    report_type = report_type_override or vuln.get("report_type") or vuln.get("reportType") or ""
    prefix = REPORT_TYPE_TO_PREFIX.get(report_type.strip().lower()) if report_type else None

    raw_name = (
        vuln.get("name")
        or vuln.get("title")
        or vuln.get("message")
        or f"GitLab finding {vuln.get('id') or vuln.get('uuid') or ''}"
    )
    name = f"{prefix} {raw_name}" if prefix else str(raw_name)

    desc_parts = []
    description = vuln.get("description") or vuln.get("message")
    if description:
        desc_parts.append(str(description))

    loc_text, loc_info = location_summary(vuln)
    if loc_text:
        desc_parts.append(loc_text)

    scanner = vuln.get("scanner")
    if isinstance(scanner, dict):
        scanner_name = scanner.get("name") or scanner.get("external_id") or scanner.get("vendor")
        if scanner_name:
            desc_parts.append(f"scanner: {scanner_name}")
    elif isinstance(scanner, str) and scanner:
        desc_parts.append(f"scanner: {scanner}")

    confidence = vuln.get("confidence")
    if confidence:
        desc_parts.append(f"confidence: {confidence}")

    project_fp = vuln.get("project_fingerprint") or vuln.get("projectFingerprint")
    if project_fp:
        desc_parts.append(f"fingerprint: {project_fp}")

    state_raw = vuln.get("state") or vuln.get("status")
    if state_raw:
        desc_parts.append(f"state: {state_raw}")

    if score is not None:
        desc_parts.append(f"cvss: {score}")

    if report_type:
        desc_parts.append(f"report_type: {report_type}")

    cves, refs = collect_identifiers(vuln)

    resolution = vuln.get("solution") or vuln.get("remediation") or vuln.get("recommendation") or ""

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    for key in ("cvss3", "cvssV3", "cvss_v3"):
        nested = vuln.get(key)
        if isinstance(nested, dict):
            vector = nested.get("vector_string") or nested.get("vectorString") or nested.get("vector")
            if isinstance(vector, str) and vector.startswith("CVSS:3"):
                cvss3["vector_string"] = vector
                break
    if "vector_string" not in cvss3:
        cvss_list = vuln.get("cvss")
        if isinstance(cvss_list, list):
            for entry in cvss_list:
                if not isinstance(entry, dict):
                    continue
                vector = entry.get("vector") or entry.get("vectorString") or entry.get("vector_string")
                if isinstance(vector, str) and vector.startswith("CVSS:3"):
                    cvss3["vector_string"] = vector
                    break

    external_id = vuln.get("id") or vuln.get("uuid") or vuln.get("vulnerability_id") or project_fp or ""

    return {
        "name": str(name).strip()[:200] or f"GitLab finding {external_id}",
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
        "tags": ["gitlab_security", report_type.strip().lower() or "gitlab"],
        "_loc_info": loc_info,
    }


def project_meta(project):
    if not isinstance(project, dict):
        return {}
    return {
        "id": (project.get("id") or project.get("project_id") or project.get("projectId")),
        "name": (
            project.get("name")
            or project.get("path_with_namespace")
            or project.get("pathWithNamespace")
            or project.get("path")
        ),
        "path": (
            project.get("path_with_namespace")
            or project.get("pathWithNamespace")
            or project.get("full_path")
            or project.get("fullPath")
            or project.get("path")
        ),
        "url": (
            project.get("web_url")
            or project.get("webUrl")
            or project.get("http_url_to_repo")
            or project.get("httpUrlToRepo")
        ),
        "default_branch": (project.get("default_branch") or project.get("defaultBranch")),
    }


def build_host(meta, vulns):
    pid = meta.get("id")
    path = meta.get("path") or meta.get("name") or (str(pid) if pid is not None else "")
    hostnames = [path] if path else []
    desc_parts = []
    if pid is not None:
        desc_parts.append(f"project_id={pid}")
    if meta.get("name") and meta.get("name") != path:
        desc_parts.append(f"name={meta['name']}")
    if meta.get("default_branch"):
        desc_parts.append(f"default_branch={meta['default_branch']}")
    if meta.get("url"):
        desc_parts.append(f"url={meta['url']}")
    # Drop the private _loc_info before emitting.
    for v in vulns:
        v.pop("_loc_info", None)
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
        log(f"GITLAB_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def validate_report_type(value):
    if value is None or value == "":
        return ""
    text = str(value).strip().lower()
    if text not in VALID_REPORT_TYPES:
        log(
            f"GITLAB_REPORT_TYPE '{value}' not in known set "
            f"({', '.join(VALID_REPORT_TYPES)}); forwarding to GitLab unchanged"
        )
    return text


def main():
    started = time.time()
    host = env("GITLAB_HOST", required=True).rstrip("/")
    token = env("GITLAB_TOKEN", required=True)
    project_id = env("EXECUTOR_CONFIG_GITLAB_PROJECT_ID")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_GITLAB_MIN_SEVERITY"))
    report_type = validate_report_type(env("EXECUTOR_CONFIG_GITLAB_REPORT_TYPE"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    headers = build_auth_headers(token)
    headers["Accept"] = "application/json"

    projects = get_projects(base_url, headers, project_id)
    if not projects and project_id:
        log(f"Project {project_id} not found or not accessible")
        projects = [{"id": project_id, "name": str(project_id)}]
    log(
        f"Processing {len(projects)} project(s) "
        f"(project_id={project_id or 'all'}, "
        f"report_type={report_type or 'all'}, min_severity={min_severity})"
    )

    hosts = []
    for project in projects:
        meta = project_meta(project)
        pid = meta.get("id")
        if pid is None:
            continue
        raw_findings = get_findings(base_url, headers, pid, report_type, min_severity)
        vulns = []
        for raw in raw_findings:
            if not isinstance(raw, dict):
                continue
            built = build_vulnerability(raw, report_type_override=report_type or None)
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if vulns:
            hosts.append(build_host(meta, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "gitlab_security",
            "command": "gitlab_security",
            "params": (
                f"project_id={project_id or 'all'},"
                f"report_type={report_type or 'all'},"
                f"min_severity={min_severity}"
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
