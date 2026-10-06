#!/usr/bin/env python
"""Contrast Security TeamServer REST API importer.

Pulls Interactive Application Security Testing (IAST) findings from a
Contrast Security TeamServer tenant (Contrast Assess) and emits Faraday
bulk-create JSON to stdout. Each Contrast application becomes one Faraday
host (``ip`` = synthetic ``0.0.0.0`` because Contrast findings live in
deployed applications, not on IPs); per-application traces are attached as
Faraday vulnerabilities — one per Contrast trace uuid with engine prefix
``[IAST]``.

Endpoints used:
  GET  /api/ng/{org_id}/applications                  -> list applications
      (paginated via ``offset`` / ``limit``).
  GET  /api/ng/{org_id}/applications/{app_id}         -> single application
      detail (used when CONTRAST_APP_ID is set).
  POST /api/ng/{org_id}/orgtraces/{app_id}/filter     -> per-application
      traces (paginated). Each entry carries severity, status, sub_status,
      rule_name, category, language and last_time_seen.
  GET  /api/ng/{org_id}/traces/{app_id}/trace/{uuid}  -> trace detail
      (enrichment — request, recommendation, story / risk text).

Auth: three Contrast headers travel on every API call:
  Authorization: <CONTRAST_AUTH>
      The base64-encoded ``username:service_key`` string. When CONTRAST_AUTH
      already looks like a base64 token (no ``:`` separator and base64
      charset) it is sent verbatim; otherwise it is treated as the
      username and base64-encoded together with CONTRAST_SERVICE_KEY.
  API-Key: <CONTRAST_API_KEY>
  Accept:  application/json

CONTRAST_HOST is the TeamServer base URL — both ``https://app.contrastsecurity.com``
and the same URL suffixed with ``/Contrast`` are accepted; the ``/Contrast``
context path is auto-appended when missing (the SaaS appliance and most
on-prem deployments expose the API under ``/Contrast/api/ng/...``).
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

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Contrast Assess emits severity as an upper-case enum. NOTE is Contrast's
# informational bucket. Tolerant of casing and a few synonyms surfaced by
# adjacent products that share rule names with Contrast Protect.
CONTRAST_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "note": "info",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
}

# Contrast lifecycle / triage statuses. Reported / Confirmed / Suspicious
# / Reopened keep the finding open; Not a Problem is Contrast's analyst
# false-positive marker (-> Faraday risk-accepted); Remediated / Fixed /
# Auto-Remediated close the finding.
CONTRAST_STATUS_TO_FARADAY = {
    "reported": "open",
    "confirmed": "open",
    "suspicious": "open",
    "reopened": "open",
    "open": "open",
    "active": "open",
    "untracked": "open",
    "not a problem": "risk-accepted",
    "not_a_problem": "risk-accepted",
    "notaproblem": "risk-accepted",
    "not-a-problem": "risk-accepted",
    "remediated": "closed",
    "auto-remediated": "closed",
    "auto_remediated": "closed",
    "autoremediated": "closed",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
}


def log(msg):
    print(f"{datetime.utcnow()} - ContrastSecurity: {msg}", file=sys.stderr, flush=True)


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


def normalize_base_url(value):
    """Translate CONTRAST_HOST into a TeamServer base URL.

    Accepts a bare hostname, an ``https://`` URL or the same URL with the
    ``/Contrast`` context path. The Contrast SaaS appliance and most
    on-prem deployments expose the API under ``/Contrast/api/ng/...``;
    the context path is auto-appended when missing.
    """
    text = str(value).strip().rstrip("/")
    if not text:
        return text
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    # Strip a trailing slash again in case the scheme inflation reintroduced it.
    text = text.rstrip("/")
    lowered = text.lower()
    if "/contrast" in lowered:
        return text
    return f"{text}/Contrast"


def build_auth_header(auth, service_key):
    """Build the Contrast ``Authorization`` header value.

    CONTRAST_AUTH may already be the base64-encoded ``username:service_key``
    string (which the Contrast UI prints under "Your keys"); when so it is
    forwarded verbatim. Otherwise it is treated as the username / email and
    base64-encoded together with CONTRAST_SERVICE_KEY.
    """
    text = str(auth).strip()
    if not text:
        log("CONTRAST_AUTH is required")
        sys.exit(1)
    if ":" in text:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    # Heuristic: a Contrast pre-built Authorization token is the base64
    # encoding of "<email>:<service_key>" and therefore contains "=" /
    # mixed-case characters but never raw "@" or whitespace. If the value
    # looks like an email or contains whitespace, treat it as a username.
    if "@" in text or any(ch.isspace() for ch in text):
        if not service_key:
            log("CONTRAST_AUTH looks like a username; CONTRAST_SERVICE_KEY is required to build the header")
            sys.exit(1)
        return base64.b64encode(f"{text}:{service_key}".encode("utf-8")).decode("ascii")
    # Bare opaque string: try to decode it as base64 first. If it round-trips
    # and contains a ``:`` separator after decoding, it is the pre-built
    # Contrast Authorization token and we forward it verbatim.
    try:
        decoded = base64.b64decode(text + "=" * (-len(text) % 4), validate=True).decode("utf-8", "ignore")
    except (ValueError, UnicodeDecodeError):
        decoded = ""
    if ":" in decoded:
        return text
    if service_key:
        return base64.b64encode(f"{text}:{service_key}".encode("utf-8")).decode("ascii")
    return text


def severity_from_contrast(value):
    """Map Contrast Assess's severity string to a Faraday severity bucket."""
    if value is None:
        return "info"
    if isinstance(value, bool):
        return "info"
    if isinstance(value, (int, float)):
        # Contrast does not emit numeric severities, but several integrations
        # round-trip the trace through CVSS. Bucket as a CVSS v3 score.
        score = float(value)
        if score <= 0:
            return "info"
        if score < 4:
            return "low"
        if score < 7:
            return "medium"
        if score < 9:
            return "high"
        return "critical"
    text = str(value).strip().lower()
    if text in CONTRAST_STRING_SEVERITY:
        return CONTRAST_STRING_SEVERITY[text]
    return "info"


def status_from_contrast(trace):
    """Map Contrast's lifecycle status to a Faraday status.

    Contrast surfaces ``status`` (Reported / Confirmed / Suspicious / Not a
    Problem / Remediated / Reopened / Fixed / Auto-Remediated). Some
    builds also surface ``sub_status`` (e.g. "False Positive", "Acceptable
    Risk") under a "Not a Problem" parent status; both feed risk-accepted.
    Analyst-triage signals (risk-accepted / closed) win over the parent
    lifecycle status so a "Reported" trace with a "False Positive"
    sub_status still ends up as Faraday risk-accepted.
    """
    if not isinstance(trace, dict):
        return "open"
    candidates = []
    for key in ("status", "subStatus", "sub_status", "state"):
        raw = trace.get(key)
        if not raw:
            continue
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status")
        if not raw:
            continue
        candidates.append(str(raw).strip().lower())

    # First pass: prefer analyst-triage signals (risk-accepted / closed).
    # A "Reported" lifecycle status combined with a "False Positive" sub
    # status should still land as Faraday risk-accepted.
    for text in candidates:
        if text in CONTRAST_STATUS_TO_FARADAY and CONTRAST_STATUS_TO_FARADAY[text] == "risk-accepted":
            return "risk-accepted"
        compact = text.replace(" ", "").replace("_", "").replace("-", "")
        if "falsepositive" in compact or "acceptablerisk" in compact or "acceptableuse" in compact:
            return "risk-accepted"
    for text in candidates:
        if text in CONTRAST_STATUS_TO_FARADAY and CONTRAST_STATUS_TO_FARADAY[text] == "closed":
            return "closed"
    # Second pass: lifecycle open.
    for text in candidates:
        if text in CONTRAST_STATUS_TO_FARADAY:
            return CONTRAST_STATUS_TO_FARADAY[text]
    return "open"


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
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). Check CONTRAST_AUTH / CONTRAST_API_KEY / CONTRAST_SERVICE_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the org-level scope of the API key.")
        return None
    if resp.status_code == 404:
        log(f"{method} {path} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"{method} {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        log(f"{method} {path} returned non-JSON body")
        return None


def extract_list(body, *keys):
    """Pluck a list out of a Contrast TeamServer REST response.

    Contrast wraps lists in shape-specific keys: ``applications`` /
    ``traces`` / ``items``; ``data`` / ``results`` are surfaced by a few
    legacy endpoints. Fall back to a bare list.
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
        for candidate in ("applications", "traces", "items", "data", "results"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def paginate(method, base_url, path, headers, payload=None, list_keys=()):
    """Walk TeamServer paginated endpoints via ``offset`` / ``limit``."""
    results = []
    offset = 0
    for _ in range(MAX_PAGES):
        params = {"offset": offset, "limit": PAGE_SIZE}
        body = request_json(method, base_url, path, headers, params=params, payload=payload)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("count") or body.get("total") or body.get("totalCount")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return results


def get_applications(base_url, org_id, headers, app_id):
    if app_id:
        body = request_json("GET", base_url, f"/api/ng/{org_id}/applications/{app_id}", headers)
        if isinstance(body, dict):
            # /applications/{id} returns {"application": {...}} or the app inline.
            inner = body.get("application")
            if isinstance(inner, dict):
                return [inner]
            return [body]
        return []
    return paginate("GET", base_url, f"/api/ng/{org_id}/applications", headers, list_keys=("applications",))


def get_traces(base_url, org_id, app_id, headers, min_severity):
    """Pull every trace (finding) for a single application.

    The ``filter`` endpoint accepts a JSON body to scope the request. We
    forward a minimal payload that walks every status the user might want
    to see in Faraday (open + risk-accepted + closed) and lets the
    severity floor narrow the result set when CONTRAST_MIN_SEVERITY > info.
    """
    payload = {}
    if min_severity and min_severity != "info":
        # Contrast accepts a CSV of upper-cased severity strings.
        wanted = [s.upper() for s in VALID_MIN_SEVERITY if SEVERITY_ORDER[s] >= SEVERITY_ORDER[min_severity]]
        # Translate Faraday's "info" bucket back to Contrast's "NOTE".
        wanted = ["NOTE" if w == "INFO" else w for w in wanted]
        payload["severities"] = wanted
    return paginate(
        "POST",
        base_url,
        f"/api/ng/{org_id}/orgtraces/{app_id}/filter",
        headers,
        payload=payload,
        list_keys=("traces",),
    )


def get_trace_detail(base_url, org_id, app_id, trace_uuid, headers):
    """Enrich a trace with the ``/traces/{app_id}/trace/{uuid}`` detail.

    Returns the inner ``trace`` block when present so the build code can
    treat the result identically to the listing entry.
    """
    body = request_json(
        "GET",
        base_url,
        f"/api/ng/{org_id}/traces/{app_id}/trace/{trace_uuid}",
        headers,
    )
    if not isinstance(body, dict):
        return {}
    inner = body.get("trace")
    if isinstance(inner, dict):
        return inner
    return body


def collect_refs(trace):
    refs = []
    seen = set()

    def add(name):
        if not name:
            return
        text = str(name).strip()
        if not text or text in seen:
            return
        seen.add(text)
        refs.append({"name": text, "type": "other"})

    # CWE: Contrast surfaces a single CWE id per trace.
    cwe = trace.get("cwe") or trace.get("cweId") or trace.get("cwe_id")
    if cwe:
        text = str(cwe).strip()
        text = text[4:] if text.lower().startswith("cwe-") else text
        add(f"CWE-{text}")
    # OWASP category — Contrast tags rules with the OWASP year + category.
    owasp = trace.get("owasp") or trace.get("owaspCategory")
    if owasp:
        if isinstance(owasp, (list, tuple)):
            for entry in owasp:
                if entry:
                    add(f"OWASP: {entry}")
        else:
            add(f"OWASP: {owasp}")
    # Contrast rule identifier — always present on a trace.
    rule_name = trace.get("rule_name") or trace.get("ruleName") or trace.get("rule")
    if rule_name:
        add(f"ContrastRule-{rule_name}")
    # Category surfaces the Contrast rule pack ("injection", "auth", etc.).
    category = trace.get("category") or trace.get("rule_category")
    if category:
        add(f"ContrastCategory-{category}")
    # References / links may surface CVEs and external advisory URLs.
    for entry in trace.get("references") or trace.get("links") or []:
        if isinstance(entry, str):
            add(entry)
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("name") or entry.get("value")
            add(value)
    return refs


def collect_cves(trace):
    cves = []
    seen = set()
    candidates = []
    for key in ("cve", "cveId", "cveName", "cve_id"):
        value = trace.get(key)
        if value:
            if isinstance(value, (list, tuple)):
                candidates.extend(value)
            else:
                candidates.append(value)
    for key in ("cves", "CVEs"):
        value = trace.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if isinstance(entry, str):
                    candidates.append(entry)
                elif isinstance(entry, dict):
                    inner = entry.get("name") or entry.get("id") or entry.get("value")
                    if inner:
                        candidates.append(inner)
    for value in candidates:
        text = str(value).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)
    return cves


def request_text(trace):
    """Pull the offending HTTP request out of a Contrast trace.

    Contrast surfaces the trigger request under ``request`` on the trace
    detail. Older listings expose ``http_request`` / ``last_request``.
    """
    for key in ("request", "http_request", "last_request"):
        value = trace.get(key)
        if isinstance(value, dict):
            method = value.get("method") or value.get("verb")
            url = value.get("url") or value.get("uri") or value.get("target")
            raw = value.get("raw") or value.get("request")
            if raw and isinstance(raw, str):
                return raw, method, url
            return "", method, url
        if isinstance(value, str) and value:
            return value, None, None
    return "", None, None


def build_vulnerability(trace, detail):
    """Build the Faraday vulnerability dict for a Contrast trace.

    ``trace`` is the listing entry; ``detail`` is the optional enrichment
    payload from ``/traces/{app_id}/trace/{uuid}``. Detail wins when both
    carry the same key.
    """
    merged = dict(trace) if isinstance(trace, dict) else {}
    if isinstance(detail, dict):
        for key, value in detail.items():
            if value not in (None, "", [], {}):
                merged[key] = value

    severity = severity_from_contrast(merged.get("severity") or merged.get("severityLabel"))
    status = status_from_contrast(merged)

    rule_name = merged.get("rule_name") or merged.get("ruleName") or merged.get("rule") or ""
    title = (
        merged.get("title")
        or merged.get("name")
        or merged.get("display_title")
        or merged.get("displayTitle")
        or rule_name
        or "Contrast Assess finding"
    )
    name = f"[IAST] {title}"

    desc_parts = []
    description = merged.get("description") or merged.get("summary") or merged.get("story") or merged.get("text")
    if isinstance(description, dict):
        description = description.get("text") or description.get("html") or description.get("story")
    if description:
        desc_parts.append(str(description))

    raw_request, req_method, req_url = request_text(merged)
    if req_url:
        if req_method:
            desc_parts.append(f"request: {req_method} {req_url}")
        else:
            desc_parts.append(f"url: {req_url}")
    elif req_method:
        desc_parts.append(f"method: {req_method}")

    if rule_name:
        desc_parts.append(f"rule_name: {rule_name}")
    category = merged.get("category") or merged.get("rule_category")
    if category:
        desc_parts.append(f"category: {category}")
    language = merged.get("language") or merged.get("technology")
    if language:
        desc_parts.append(f"language: {language}")

    first_seen = merged.get("first_time_seen") or merged.get("firstTimeSeen") or merged.get("firstSeen")
    if first_seen:
        desc_parts.append(f"first_time_seen: {first_seen}")
    last_seen = merged.get("last_time_seen") or merged.get("lastTimeSeen") or merged.get("lastSeen")
    if last_seen:
        desc_parts.append(f"last_time_seen: {last_seen}")

    status_raw = merged.get("status")
    if status_raw:
        desc_parts.append(f"status: {status_raw}")
    sub_status_raw = merged.get("subStatus") or merged.get("sub_status")
    if sub_status_raw:
        desc_parts.append(f"sub_status: {sub_status_raw}")

    uuid = merged.get("uuid") or merged.get("trace_uuid") or merged.get("traceUuid")
    if uuid:
        desc_parts.append(f"uuid: {uuid}")

    resolution = (
        merged.get("recommendation")
        or merged.get("recommendation_text")
        or merged.get("recommendations")
        or merged.get("remediation")
        or merged.get("howToFix")
        or ""
    )
    if isinstance(resolution, dict):
        resolution = resolution.get("text") or resolution.get("html") or resolution.get("formattedText") or ""

    external_id = str(uuid or merged.get("id") or "")

    return {
        "name": str(name).strip()[:200] or f"Contrast Assess finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": str(raw_request) if raw_request else "",
        "refs": collect_refs(merged),
        "cve": collect_cves(merged),
        "cvss3": {},
        "tags": ["contrast_security", "iast"],
    }


def build_host(application, vulns):
    """One Faraday host per Contrast application.

    Contrast findings live in deployed applications, not on IPs — the host
    is a synthetic ``0.0.0.0`` carrying the application name as a hostname
    so the data lands somewhere recognisable in the workspace.
    """
    name = (
        application.get("name")
        or application.get("application_name")
        or application.get("appName")
        or application.get("display_name")
        or application.get("id")
        or "unknown"
    )
    app_id = application.get("app_id") or application.get("id") or application.get("application_id")
    desc_parts = [f"Contrast application name={name}"]
    if app_id:
        desc_parts.append(f"id={app_id}")
    language = application.get("language") or application.get("technology")
    if language:
        desc_parts.append(f"language={language}")
    master = application.get("master")
    if master is not None:
        desc_parts.append(f"master={master}")
    importance = application.get("importance_description") or application.get("importance")
    if importance:
        desc_parts.append(f"importance={importance}")
    tags = application.get("tags")
    if isinstance(tags, list) and tags:
        desc_parts.append("tags=" + ",".join(str(t) for t in tags))
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [str(name)] if name else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"CONTRAST_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def app_id_of(application):
    if not isinstance(application, dict):
        return None
    return (
        application.get("app_id")
        or application.get("id")
        or application.get("application_id")
        or application.get("appId")
    )


def main():
    started = time.time()
    host = env("CONTRAST_HOST", required=True)
    org_id = env("CONTRAST_ORG_ID", required=True)
    auth = env("CONTRAST_AUTH", required=True)
    api_key = env("CONTRAST_API_KEY", required=True)
    service_key = env("CONTRAST_SERVICE_KEY")
    app_id = env("EXECUTOR_CONFIG_CONTRAST_APP_ID")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_CONTRAST_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    auth_header = build_auth_header(auth, service_key)
    headers = {
        "Authorization": auth_header,
        "API-Key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    applications = get_applications(base_url, org_id, headers, app_id)
    log(
        f"Found {len(applications)} application(s) "
        f"(app_id={app_id or 'all'}, org_id={org_id}, min_severity={min_severity})"
    )

    hosts = []
    for application in applications:
        if not isinstance(application, dict):
            continue
        aid = app_id_of(application)
        if not aid:
            continue
        raw_traces = get_traces(base_url, org_id, aid, headers, min_severity)
        vulns = []
        for raw in raw_traces:
            if not isinstance(raw, dict):
                continue
            trace_uuid = raw.get("uuid") or raw.get("trace_uuid")
            detail = get_trace_detail(base_url, org_id, aid, trace_uuid, headers) if trace_uuid else {}
            built = build_vulnerability(raw, detail)
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        hosts.append(build_host(application, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "contrast_security",
            "command": "contrast_security",
            "params": (f"app_id={app_id or 'all'} org_id={org_id} " f"min_severity={min_severity}"),
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
