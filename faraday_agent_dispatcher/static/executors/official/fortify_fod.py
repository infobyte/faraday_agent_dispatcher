#!/usr/bin/env python
"""Fortify on Demand (FoD) REST API importer.

Pulls SAST / SCA / DAST findings from a Fortify on Demand tenant and emits
Faraday bulk-create JSON to stdout. Each FoD release becomes one Faraday
host (``ip`` = synthetic ``0.0.0.0`` because FoD findings live in
applications / releases, not on IPs); per-release vulnerabilities are
attached as Faraday vulnerabilities — one per FoD vulnId.

Endpoints used:
  POST /oauth/token                                          -> OAuth2
      client_credentials grant; returns an access_token used as Bearer
      auth on subsequent API calls. ``scope=api-tenant``. FoD embeds the
      tenant in the API key; the executor prepends ``{FOD_TENANT}\\``
      to FOD_CLIENT_ID when the client id does not already include it,
      to support both API-Key (tenant in the key) and user (tenant in
      the username) flows.
  GET  /api/v3/applications                                  -> list
      applications (paginated via ``offset`` / ``limit``).
  GET  /api/v3/applications/{id}/releases                    -> per-app
      releases. Used to enumerate every release when FOD_RELEASE_ID is
      not set.
  GET  /api/v3/releases/{id}/vulnerabilities                 -> per-release
      vulnerabilities (paginated). Each entry carries severity (numeric
      1-4 + severityString), engine (analyzer), source ``primaryLocationFull``
      + ``lineNumber``, ``instanceId`` (similarity correlation key),
      ``isSuppressed`` / ``auditorStatus`` and lifecycle ``closedStatus`` /
      ``closedDate``.
  GET  /api/v3/releases/{id}/vulnerabilities/{vulnId}/details   -> optional
      per-vuln enrichment (description, full HTML detail, recommendation,
      CWE id, kingdom / subType).
  GET  /api/v3/releases/{id}/vulnerabilities/{vulnId}/recommendations
                                                              -> optional
      recommendation enrichment (used as Faraday ``resolution``).

Auth: OAuth2 client_credentials against ``/oauth/token`` using
FOD_CLIENT_ID / FOD_CLIENT_SECRET with ``scope=api-tenant``. The returned
``access_token`` is sent as ``Authorization: Bearer <token>`` on every
API call. FOD_HOST is the FoD regional API base URL (e.g.
``https://api.ams.fortify.com``, ``https://api.emea.fortify.com``,
``https://api.apac.fortify.com``, ``https://api.fed.fortifygov.com``).
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
PAGE_SIZE = 50
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# FoD reports severity primarily as ``severityString`` ("Critical" / "High" /
# "Medium" / "Low" / "Best Practice") plus a numeric ``severity`` field (FoD's
# 1-4 ladder; 0 is reserved for Best Practice / Info). Both shapes are
# normalised here.
FOD_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "information": "info",
    "informational": "info",
    "best practice": "info",
    "best_practice": "info",
    "none": "info",
}

FOD_NUMERIC_SEVERITY = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - FortifyFoD: {msg}", file=sys.stderr, flush=True)


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


def severity_from_fod(value, numeric=None):
    """Normalise a FoD severity value into a Faraday bucket.

    ``value`` is FoD's ``severityString`` (or any string equivalent the
    integrations surface). ``numeric`` is FoD's numeric severity 0-4 used
    as a fallback when the string is missing or unknown.
    """
    if value is not None:
        if isinstance(value, bool):
            pass
        elif isinstance(value, int) and value in FOD_NUMERIC_SEVERITY:
            return FOD_NUMERIC_SEVERITY[value]
        elif isinstance(value, float):
            try:
                int_value = int(value)
            except (TypeError, ValueError):
                int_value = None
            if int_value in FOD_NUMERIC_SEVERITY:
                return FOD_NUMERIC_SEVERITY[int_value]
        else:
            text = str(value).strip().lower()
            if text in FOD_STRING_SEVERITY:
                return FOD_STRING_SEVERITY[text]
            try:
                int_value = int(float(text))
            except ValueError:
                int_value = None
            if int_value in FOD_NUMERIC_SEVERITY:
                return FOD_NUMERIC_SEVERITY[int_value]
    if numeric is not None:
        try:
            int_value = int(float(numeric))
        except (TypeError, ValueError):
            int_value = None
        if int_value in FOD_NUMERIC_SEVERITY:
            return FOD_NUMERIC_SEVERITY[int_value]
    return "info"


def status_from_fod(vuln):
    """Derive Faraday status from FoD vulnerability flags.

    FoD exposes several lifecycle / audit fields:
      * ``isSuppressed`` / ``suppressed`` — analyst-suppressed (treated as
        risk-accepted).
      * ``auditorStatus`` — "Not an Issue" / "Not Exploitable" /
        "False Positive" become risk-accepted; "Remediated" closes the
        finding; "Open" / "Suspicious" / "Reliability Issue" stay open.
      * ``closedStatus`` / ``closedDate`` / ``status`` — when FoD marks
        the finding fixed / remediated / closed the Faraday status is
        forced to ``closed``.
    """
    if vuln.get("isSuppressed") or vuln.get("suppressed"):
        return "risk-accepted"
    closed_status = vuln.get("closedStatus")
    if closed_status:
        text = str(closed_status).strip().lower()
        if text in (
            "fixed",
            "resolved",
            "closed",
            "remediated",
            "remediation",
        ):
            return "closed"
    if vuln.get("closedDate") or vuln.get("dateClosed"):
        return "closed"
    auditor = vuln.get("auditorStatus") or vuln.get("developerStatus")
    if isinstance(auditor, dict):
        auditor = auditor.get("value") or auditor.get("name")
    if auditor:
        text = str(auditor).strip().lower()
        if text in (
            "not an issue",
            "not_an_issue",
            "not exploitable",
            "not_exploitable",
            "false positive",
            "false_positive",
            "sanctioned",
        ):
            return "risk-accepted"
        if text in ("remediated", "fixed", "resolved", "closed"):
            return "closed"
    status = vuln.get("status") or vuln.get("state")
    if status:
        text = str(status).strip().lower()
        if text in ("fixed", "resolved", "closed", "remediated"):
            return "closed"
        if text in ("false_positive", "false-positive", "falsepositive", "suppressed"):
            return "risk-accepted"
    return "open"


def get_token(base_url, tenant, client_id, client_secret):
    url = f"{base_url}/oauth/token"
    # FoD embeds the tenant in the API key (the API Key Id surfaced in the
    # FoD UI is opaque), but the user-password flow expects the username
    # formatted as ``{tenant}\\{username}``. Support both shapes by
    # prepending the tenant when the client id is bare.
    cid = client_id
    if tenant and "\\" not in cid and "/" not in cid:
        cid = f"{tenant}\\{client_id}"
    data = {
        "scope": "api-tenant",
        "grant_type": "client_credentials",
        "client_id": cid,
        "client_secret": client_secret,
    }
    try:
        resp = requests.post(url, data=data, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"Token request failed: {exc}")
        sys.exit(1)
    if resp.status_code != 200:
        log(f"Token endpoint returned {resp.status_code}: {resp.text[:500]}")
        sys.exit(1)
    try:
        payload = resp.json()
    except ValueError:
        log("Token endpoint returned non-JSON body")
        sys.exit(1)
    token = payload.get("access_token")
    if not token:
        log("Token endpoint did not return access_token")
        sys.exit(1)
    return token


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
        log(f"Authorization rejected (403) on {path}. Check API key scope / roles.")
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
    """Pluck a list out of a FoD JSON response.

    FoD wraps list responses in ``{"items": [...], "totalCount": N}``.
    Single-resource responses return the resource directly.
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
        for candidate in ("items", "data", "results"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, base_params):
    """Paginate FoD list endpoints via ``offset`` + ``limit``."""
    results = []
    offset = 0
    for _ in range(MAX_PAGES):
        params = dict(base_params or {})
        params["offset"] = offset
        params["limit"] = PAGE_SIZE
        body = get_page(base_url, path, headers, params)
        chunk = extract_list(body, "items")
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("totalCount") or body.get("filteredCount") or body.get("total")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return results


def get_applications(base_url, headers):
    return collect(base_url, "/api/v3/applications", headers, {})


def get_app_releases(base_url, headers, app_id):
    return collect(base_url, f"/api/v3/applications/{app_id}/releases", headers, {})


def get_release(base_url, headers, release_id):
    body = get_page(base_url, f"/api/v3/releases/{release_id}", headers, {})
    if isinstance(body, dict):
        return body
    return {}


def get_vulnerabilities(base_url, headers, release_id, min_severity):
    params = {}
    # FoD's vulnerability endpoint accepts a ``filters`` query param using
    # the syntax ``severityString:Critical|High|Medium``. CSV-forward the
    # min-severity floor; we still enforce client-side after normalisation.
    if min_severity and min_severity != "info":
        wanted = [s.capitalize() for s in VALID_MIN_SEVERITY if SEVERITY_ORDER[s] >= SEVERITY_ORDER[min_severity]]
        params["filters"] = f"severityString:{'|'.join(wanted)}"
    return collect(base_url, f"/api/v3/releases/{release_id}/vulnerabilities", headers, params)


def get_vuln_details(base_url, headers, release_id, vuln_id):
    body = get_page(
        base_url,
        f"/api/v3/releases/{release_id}/vulnerabilities/{vuln_id}/details",
        headers,
        {},
    )
    if isinstance(body, dict):
        return body
    return {}


def get_vuln_recommendation(base_url, headers, release_id, vuln_id):
    body = get_page(
        base_url,
        f"/api/v3/releases/{release_id}/vulnerabilities/{vuln_id}/recommendations",
        headers,
        {},
    )
    if isinstance(body, dict):
        text = body.get("recommendation") or body.get("recommendations") or body.get("tips")
        if text:
            return str(text)
    return ""


def collect_refs(vuln, details):
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

    for source in (details, vuln):
        if not isinstance(source, dict):
            continue
        kingdom = source.get("kingdom")
        if kingdom:
            add(f"Kingdom: {kingdom}")
        sub_type = source.get("subtype") or source.get("subType")
        if sub_type:
            add(f"SubType: {sub_type}")
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
        check_id = source.get("checkId") or source.get("ruleId") or source.get("primaryRuleGuid")
        if check_id:
            add(f"FortifyRule-{check_id}")
        for entry in source.get("references") or []:
            if isinstance(entry, str) and entry:
                add(entry)
            elif isinstance(entry, dict):
                value = entry.get("url") or entry.get("href") or entry.get("name") or entry.get("value")
                if value:
                    add(value, entry.get("type", "other") or "other")
    return refs


def collect_cves(vuln, details):
    cves = []
    candidates = []
    for source in (vuln, details):
        if not isinstance(source, dict):
            continue
        for key in ("cve", "cveId", "cveName", "cve_id"):
            value = source.get(key)
            if value:
                candidates.append(value)
        for entry in source.get("cves") or []:
            if isinstance(entry, str):
                candidates.append(entry)
            elif isinstance(entry, dict):
                value = entry.get("name") or entry.get("id") or entry.get("value")
                if value:
                    candidates.append(value)
    seen = set()
    for value in candidates:
        text = str(value).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)
    return cves


def build_vulnerability(vuln, details, resolution):
    severity = severity_from_fod(vuln.get("severityString") or vuln.get("severityName"), vuln.get("severity"))
    status = status_from_fod(vuln)
    analyzer = (
        vuln.get("analyzer")
        or vuln.get("analysisType")
        or vuln.get("scanType")
        or vuln.get("category")
        or details.get("scanType")
        or details.get("analyzer")
        or "SAST"
    )
    raw_name = (
        vuln.get("category")
        or vuln.get("kingdom")
        or vuln.get("primaryRuleGuid")
        or vuln.get("checkName")
        or vuln.get("vulnerabilityName")
        or details.get("category")
        or details.get("brief")
        or f"Fortify FoD {analyzer} finding"
    )
    name = f"[{str(analyzer).upper()}] {raw_name}"

    desc_parts = []
    brief = details.get("brief") or details.get("description") or vuln.get("brief")
    if brief:
        desc_parts.append(str(brief))
    detail = details.get("detail") or details.get("explanation")
    if detail and detail != brief:
        desc_parts.append(str(detail))

    file_name = (
        vuln.get("primaryLocationFull")
        or vuln.get("primaryLocation")
        or vuln.get("fileName")
        or details.get("primaryLocationFull")
        or details.get("fileName")
    )
    if file_name:
        line = vuln.get("lineNumber") or vuln.get("primaryLine") or details.get("lineNumber")
        if line:
            desc_parts.append(f"location: {file_name}:{line}")
        else:
            desc_parts.append(f"location: {file_name}")

    sink_file = vuln.get("sinkLocation") or vuln.get("sinkLocationFull") or details.get("sinkLocation")
    if sink_file:
        sink_line = vuln.get("sinkLine") or vuln.get("sinkLineNumber") or details.get("sinkLine")
        if sink_line:
            desc_parts.append(f"sink: {sink_file}:{sink_line}")
        else:
            desc_parts.append(f"sink: {sink_file}")

    instance_id = vuln.get("instanceId") or vuln.get("issueInstanceId") or details.get("instanceId")
    if instance_id:
        desc_parts.append(f"instanceId: {instance_id}")

    auditor = vuln.get("auditorStatus") or vuln.get("developerStatus")
    if isinstance(auditor, dict):
        auditor = auditor.get("value") or auditor.get("name")
    if auditor:
        desc_parts.append(f"auditorStatus: {auditor}")
    if vuln.get("isSuppressed") or vuln.get("suppressed"):
        desc_parts.append("suppressed: true")
    closed_status = vuln.get("closedStatus")
    if closed_status:
        desc_parts.append(f"closedStatus: {closed_status}")
    introduced = vuln.get("introducedDate") or vuln.get("dateCreated")
    if introduced:
        desc_parts.append(f"introduced: {introduced}")

    score_value = vuln.get("severity")
    return {
        "name": str(name).strip()[:200] or f"Fortify FoD {analyzer} finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(vuln.get("vulnId") or vuln.get("id") or instance_id or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": collect_refs(vuln, details),
        "cve": collect_cves(vuln, details),
        "cvss3": {"base_score": str(score_value)} if score_value not in (None, "") else {},
        "tags": ["fortify_fod", str(analyzer).lower()],
    }


def build_host(release, application, vulns):
    release_name = (
        release.get("releaseName")
        or release.get("name")
        or str(release.get("releaseId") or release.get("id") or "unknown")
    )
    app_name = (
        (application or {}).get("applicationName") or (application or {}).get("name") or release.get("applicationName")
    )
    if app_name and app_name != release_name:
        label = f"{app_name}/{release_name}"
    else:
        label = release_name
    release_id = release.get("releaseId") or release.get("id", "N/A")
    desc_parts = [f"Fortify FoD release name={label}", f"id={release_id}"]
    sdlc = release.get("sdlcStatusType") or release.get("sdlcStatus")
    if sdlc:
        desc_parts.append(f"sdlcStatus={sdlc}")
    rating = release.get("rating")
    if rating:
        desc_parts.append(f"rating={rating}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [label] if label else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("FOD_HOST", required=True).rstrip("/")
    tenant = env("FOD_TENANT", required=True)
    client_id = env("FOD_CLIENT_ID", required=True)
    client_secret = env("FOD_CLIENT_SECRET", required=True)
    release_id = env("EXECUTOR_CONFIG_FOD_RELEASE_ID")
    min_severity = (env("EXECUTOR_CONFIG_FOD_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"FOD_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"

    token = get_token(base_url, tenant, client_id, client_secret)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    releases_with_app = []
    if release_id:
        release = get_release(base_url, headers, release_id)
        if release:
            app_id = release.get("applicationId")
            application = get_page(base_url, f"/api/v3/applications/{app_id}", headers, {}) if app_id else None
            if isinstance(application, dict) and "items" in application:
                items = application.get("items") or []
                application = items[0] if items else None
            releases_with_app.append((release, application))
    else:
        applications = get_applications(base_url, headers)
        log(f"Found {len(applications)} application(s)")
        for application in applications:
            app_id = application.get("applicationId") or application.get("id")
            if not app_id:
                continue
            for release in get_app_releases(base_url, headers, app_id):
                releases_with_app.append((release, application))

    log(f"Processing {len(releases_with_app)} release(s) (release_id={release_id or 'all'})")

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    for release, application in releases_with_app:
        rid = release.get("releaseId") or release.get("id")
        if not rid:
            continue
        raw_vulns = get_vulnerabilities(base_url, headers, rid, min_severity)
        vulns = []
        for vuln in raw_vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("vulnId") or vuln.get("id")
            details = get_vuln_details(base_url, headers, rid, vuln_id) if vuln_id else {}
            resolution = get_vuln_recommendation(base_url, headers, rid, vuln_id) if vuln_id else ""
            v = build_vulnerability(vuln, details, resolution)
            if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold:
                vulns.append(v)
        if not vulns:
            continue
        hosts.append(build_host(release, application, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "fortify_fod",
            "command": "fortify_fod",
            "params": (f"release_id={release_id or 'all'} min_severity={min_severity}"),
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
