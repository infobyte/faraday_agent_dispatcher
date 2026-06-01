#!/usr/bin/env python
"""Coverity Connect (Black Duck / Synopsys) REST API importer.

Pulls source-code findings ("defects") from a Coverity Connect server
and emits Faraday bulk-create JSON to stdout. Each Coverity project
becomes one Faraday host (``ip`` = synthetic ``0.0.0.0`` because SAST
findings live in source repos, not on IPs); per-project (or per-stream)
defects are attached as Faraday vulnerabilities — one per Coverity
merge-key (CID).

Endpoints used (REST API — Coverity Connect 2020.06+):
  GET  /api/v2/projects                              -> list of projects
      (or a single project via /api/v2/projects/{name} when
      ``COVERITY_PROJECT`` is set).
  GET  /api/v2/streams?projectName=<p>               -> list of streams
      tied to a project (used when ``COVERITY_STREAM`` is set, to
      validate the stream name and to surface stream metadata).
  GET  /api/v2/issues?projectName=<p>&streamName=<s> -> paginated list
      of merged defects (CIDs). Each entry carries the merge key
      (CID), checker name, impact, severity, type (classification),
      action, status, owner, file paths, function and CWE id.
  GET  /api/v2/issues/{cid}                          -> per-CID detail
      lookup (used for description / events / recommendation
      enrichment when not present in the list response).

SOAP fallback (Coverity Connect 9.x and earlier):
  POST /ws/v9/defectservice  with a ``getMergedDefectsForProjects`` /
      ``getMergedDefectsForStreams`` request envelope. Triggered when
      the REST projects endpoint returns 404. Authentication is HTTP
      Basic in both cases.

Auth: HTTP Basic with ``COVERITY_USER`` / ``COVERITY_PASSWORD``.
``COVERITY_HOST`` is the Coverity Connect base URL (e.g.
``https://cov.corp.example.com`` or ``https://cov.corp.example.com:8443``);
the executor accepts bare hostnames and prepends ``https://`` when no
scheme is present.
"""

import base64
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200
EVIDENCE_LIMIT = 500

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Coverity Connect's "Impact" field is the closest analogue to a
# CVSS-style severity. It maxes out at "High" (Coverity does not have
# a "Critical" bucket), but we still accept Critical in case of forward
# compatibility with future Coverity releases or third-party feeds.
COVERITY_IMPACT_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "major": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "audit": "info",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
}

# Coverity Connect classification (triage.classification) — analyst's
# verdict. "False Positive" / "Intentional" are the documented
# "won't fix" states.
CLASSIFICATION_RISK_ACCEPTED = (
    "false positive",
    "false_positive",
    "falsepositive",
    "intentional",
    "ignored",
    "accepted",
    "risk accepted",
    "risk_accepted",
)

# Coverity Connect status (triage.action / lifecycle status).
STATUS_CLOSED = (
    "fixed",
    "resolved",
    "closed",
    "dismissed",
    "remediated",
    "absent dismissed",
    "absent_dismissed",
)
STATUS_OPEN = (
    "new",
    "triaged",
    "open",
    "active",
    "various",
    "reopened",
)

NAMESPACES = {
    "soap": "http://schemas.xmlsoap.org/soap/envelope/",
    "v9": "http://ws.coverity.com/v9",
}


def log(msg):
    print(f"{datetime.utcnow()} - Coverity: {msg}", file=sys.stderr, flush=True)


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


def normalise_base_url(host):
    host = (host or "").strip().rstrip("/")
    if not host:
        return ""
    if host.startswith(("http://", "https://")):
        return host
    return f"https://{host}"


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


def severity_from_coverity(impact, cvss=None):
    if impact is not None and not isinstance(impact, bool):
        if isinstance(impact, (int, float)):
            # Coverity's impact is normally a string, but some
            # third-party shims surface a numeric CVSS-style score.
            return severity_from_cvss(impact)
        text = str(impact).strip().lower()
        if text in COVERITY_IMPACT_SEVERITY:
            return COVERITY_IMPACT_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def _norm_text(value):
    if value is None:
        return ""
    if isinstance(value, dict):
        return str(value.get("value") or value.get("name") or "").strip().lower()
    return str(value).strip().lower()


def status_from_coverity(defect):
    """Map Coverity triage / status fields to Faraday status.

    Coverity surfaces a defect's lifecycle in several overlapping
    fields depending on API version and response shape:

      - ``status`` (top-level lifecycle: New / Triaged / Fixed /
        Dismissed / Absent Dismissed).
      - ``triage.classification`` (analyst verdict: Unclassified /
        Pending / False Positive / Intentional / Bug).
      - ``triage.action`` (analyst plan: Undecided / Fix Required /
        Fix Submitted / Modeling Required / Ignore).

    Analyst overrides (False Positive / Intentional) win over the
    lifecycle status — a "Triaged" defect classified as "False
    Positive" still lands as Faraday risk-accepted.
    """
    triage = defect.get("triage") if isinstance(defect.get("triage"), dict) else {}
    classification = _norm_text(triage.get("classification") or defect.get("classification"))
    action = _norm_text(triage.get("action") or defect.get("action"))
    status = _norm_text(defect.get("status") or defect.get("statusName") or defect.get("defectStatus"))

    if classification in CLASSIFICATION_RISK_ACCEPTED:
        return "risk-accepted"
    if action in ("ignore", "ignored"):
        return "risk-accepted"
    if status in STATUS_CLOSED:
        return "closed"
    if action in ("fix submitted", "fix_submitted", "fixed"):
        return "closed"
    if status in STATUS_OPEN:
        return "open"
    return "open"


def basic_auth_header(user, password):
    raw = f"{user or ''}:{password or ''}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"GET {path} failed: {exc}")
        return None, None
    if resp.status_code == 401:
        log("Authentication rejected (401). Check COVERITY_USER / COVERITY_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check user role / scope.")
        return None, resp.status_code
    if resp.status_code == 404:
        return None, resp.status_code
    if resp.status_code >= 400:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None, resp.status_code
    try:
        return resp.json(), resp.status_code
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None, resp.status_code


def extract_list(body, *keys):
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys:
            value = body.get(key)
            if isinstance(value, list):
                return value
        for candidate in ("results", "data", "items", "value", "content"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def list_projects(base_url, headers, project_name):
    if project_name:
        body, code = get_page(base_url, f"/api/v2/projects/{project_name}", headers, {})
        if code == 404:
            return [], code
        if isinstance(body, dict) and body.get("name"):
            return [body], code
        # Some Coverity builds return a wrapper {projects:[...]} even
        # for a single name lookup.
        wrapped = extract_list(body, "projects")
        if wrapped:
            return wrapped, code
        # Fall back to a list+filter pass so the executor still works
        # against older builds that don't expose /projects/{name}.
        body, code = get_page(base_url, "/api/v2/projects", headers, {"name": project_name})
        return extract_list(body, "projects"), code
    body, code = get_page(base_url, "/api/v2/projects", headers, {})
    return extract_list(body, "projects"), code


def list_streams(base_url, headers, project_name, stream_name):
    params = {}
    if project_name:
        params["projectName"] = project_name
    if stream_name:
        params["name"] = stream_name
    body, _ = get_page(base_url, "/api/v2/streams", headers, params)
    return extract_list(body, "streams")


def get_issues(base_url, headers, params):
    results = []
    offset = 0
    for _ in range(MAX_PAGES):
        page_params = dict(params)
        page_params["offset"] = offset
        page_params["pageSize"] = PAGE_SIZE
        body, code = get_page(base_url, "/api/v2/issues", headers, page_params)
        if body is None and code != 200:
            break
        chunk = extract_list(body, "issues", "mergedDefects", "defects")
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("totalRows") or body.get("totalRecords") or body.get("totalCount") or body.get("total")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return results


def enrich_issue(base_url, headers, defect):
    """Pull /api/v2/issues/{cid} when the list response lacks events.

    The list endpoint returns a compact shape (CID, checker, file,
    severity); the per-CID endpoint returns the full event trail
    (which we surface as ``data``) and the long-form remediation
    advice (surfaced as ``resolution``).
    """
    cid = (
        defect.get("cid") or defect.get("CID") or defect.get("mergeKey") or defect.get("merge_key") or defect.get("id")
    )
    if not cid:
        return defect
    if defect.get("events") and (defect.get("remediation") or defect.get("recommendation")):
        return defect
    body, _ = get_page(base_url, f"/api/v2/issues/{cid}", headers, {})
    if not isinstance(body, dict):
        return defect
    merged = dict(defect)
    for key, value in body.items():
        # Don't blindly overwrite the compact fields that the list
        # already supplied with stable values — keep the list shape
        # authoritative and only add what's missing.
        if key not in merged or merged[key] in (None, "", [], {}):
            merged[key] = value
    return merged


def collect_refs(defect):
    refs = []
    checker_block = defect.get("checker") if isinstance(defect.get("checker"), dict) else {}
    cwe = defect.get("cwe") or defect.get("cweId") or defect.get("cwe_id") or checker_block.get("cwe")
    if cwe:
        if isinstance(cwe, list):
            for entry in cwe:
                value = entry.get("id") if isinstance(entry, dict) else entry
                if value:
                    text = str(value)
                    if not text.upper().startswith("CWE-"):
                        text = f"CWE-{text}"
                    refs.append({"name": text, "type": "other"})
        else:
            text = str(cwe)
            if not text.upper().startswith("CWE-"):
                text = f"CWE-{text}"
            refs.append({"name": text, "type": "other"})
    checker_name = None
    checker = defect.get("checker")
    if isinstance(checker, dict):
        checker_name = checker.get("name") or checker.get("checkerName")
    if not checker_name:
        checker_name = defect.get("checkerName")
    if checker_name:
        refs.append({"name": f"CoverityChecker-{checker_name}", "type": "other"})
    category = defect.get("category") or defect.get("checkerCategory")
    if isinstance(category, dict):
        category = category.get("name") or category.get("value")
    if category:
        refs.append({"name": f"CoverityCategory-{category}", "type": "other"})
    issue_kind = defect.get("issueKind") or defect.get("kind") or defect.get("type")
    if isinstance(issue_kind, dict):
        issue_kind = issue_kind.get("name") or issue_kind.get("value")
    if issue_kind and str(issue_kind).strip().upper() not in ("VARIOUS", "QUALITY"):
        refs.append({"name": f"CoverityKind-{issue_kind}", "type": "other"})
    for entry in defect.get("references") or []:
        if isinstance(entry, str) and entry:
            refs.append({"name": entry, "type": "other"})
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("name") or entry.get("value")
            if value:
                refs.append({"name": value, "type": entry.get("type", "other") or "other"})
    return refs


def collect_cves(defect):
    found = []
    seen = set()
    candidates = []
    for key in ("cve", "cveId", "cveName", "cves"):
        value = defect.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            candidates.extend(value)
        else:
            candidates.append(value)
    for entry in candidates:
        if isinstance(entry, dict):
            cve = entry.get("name") or entry.get("id") or entry.get("value") or entry.get("cve")
        else:
            cve = entry
        if not cve:
            continue
        text = str(cve).strip()
        key = text.upper()
        if key and key not in seen:
            seen.add(key)
            found.append(text)
    return found


def event_text(events):
    if not events:
        return ""
    if isinstance(events, dict):
        events = [events]
    lines = []
    for event in events:
        if not isinstance(event, dict):
            continue
        tag = event.get("eventTag") or event.get("tag") or event.get("type") or "event"
        line = event.get("filePathname") or event.get("file") or ""
        ln = event.get("lineNumber") or event.get("line")
        text = event.get("eventDescription") or event.get("description") or event.get("eventText") or ""
        location = f"{line}:{ln}" if line and ln else (line or "")
        lines.append(f"[{tag}] {location} {text}".strip())
    return "\n".join(lines)[:EVIDENCE_LIMIT]


def build_vulnerability(defect):
    defect = defect if isinstance(defect, dict) else {}
    checker = defect.get("checker") if isinstance(defect.get("checker"), dict) else {}
    cvss3 = defect.get("cvss3") if isinstance(defect.get("cvss3"), dict) else {}
    cvss = defect.get("cvssScore") or defect.get("cvss") or cvss3.get("baseScore") or cvss3.get("base_score")
    severity = severity_from_coverity(
        defect.get("impact") or defect.get("Impact") or defect.get("severity") or checker.get("impact"),
        cvss,
    )
    status = status_from_coverity(defect)

    checker_name = (
        checker.get("name")
        or checker.get("checkerName")
        or defect.get("checkerName")
        or defect.get("checker_name")
        or "CoverityChecker"
    )
    sub_category = (
        defect.get("displayType")
        or defect.get("subcategoryShortDescription")
        or defect.get("subcategory")
        or defect.get("type")
        or checker.get("subcategory")
    )
    if isinstance(sub_category, dict):
        sub_category = sub_category.get("name") or sub_category.get("value")
    name_parts = ["[SAST]", str(checker_name)]
    if sub_category and str(sub_category) != str(checker_name):
        name_parts.append(f"- {sub_category}")
    name = " ".join(part for part in name_parts if part)

    desc_parts = []
    long_desc = (
        defect.get("subcategoryLongDescription")
        or defect.get("longDescription")
        or defect.get("description")
        or checker.get("description")
    )
    if long_desc:
        desc_parts.append(str(long_desc))
    location = defect.get("location") if isinstance(defect.get("location"), dict) else {}
    file_name = defect.get("filePathname") or defect.get("file") or defect.get("filePath") or location.get("file")
    line = defect.get("lineNumber") or defect.get("line") or defect.get("mainEventLineNumber")
    if file_name:
        if line:
            desc_parts.append(f"location: {file_name}:{line}")
        else:
            desc_parts.append(f"location: {file_name}")
    function = defect.get("functionDisplayName") or defect.get("function") or defect.get("functionName")
    if function:
        desc_parts.append(f"function: {function}")
    merge_key = defect.get("mergeKey") or defect.get("merge_key")
    if merge_key:
        desc_parts.append(f"mergeKey: {merge_key}")
    cid = defect.get("cid") or defect.get("CID")
    if cid:
        desc_parts.append(f"CID: {cid}")
    occurrence_count = defect.get("occurrenceCount") or defect.get("count")
    if occurrence_count:
        desc_parts.append(f"occurrences: {occurrence_count}")
    triage = defect.get("triage") if isinstance(defect.get("triage"), dict) else {}
    classification = triage.get("classification") or defect.get("classification")
    if classification:
        desc_parts.append(f"classification: {classification}")
    action = triage.get("action") or defect.get("action")
    if action:
        desc_parts.append(f"action: {action}")
    owner = triage.get("owner") or defect.get("owner") or defect.get("ownerName")
    if owner:
        desc_parts.append(f"owner: {owner}")
    first_detected = defect.get("firstDetected") or defect.get("firstDetectedDate")
    if first_detected:
        desc_parts.append(f"first_detected: {first_detected}")
    last_detected = defect.get("lastDetected") or defect.get("lastDetectedDate")
    if last_detected:
        desc_parts.append(f"last_detected: {last_detected}")
    events_blob = event_text(defect.get("events"))
    if events_blob:
        desc_parts.append("events:\n" + events_blob)

    checker_props = defect.get("checkerProperties") if isinstance(defect.get("checkerProperties"), dict) else {}
    resolution = (
        defect.get("remediation")
        or defect.get("recommendation")
        or checker_props.get("remediation")
        or checker_props.get("recommendation")
        or ""
    )
    return {
        "name": str(name).strip()[:200] or "Coverity finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(cid or merge_key or defect.get("id") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": defect.get("eventTreeXml") or "",
        "refs": collect_refs(defect),
        "cve": collect_cves(defect),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["coverity", "sast"],
    }


def build_host(project, vulns, streams=None, scope_label=None):
    name = project.get("name") or project.get("projectName") or project.get("id") or scope_label or "coverity-project"
    desc_parts = [f"Coverity Connect project name={name}"]
    pid = project.get("id") or project.get("projectId")
    if pid:
        desc_parts.append(f"id={pid}")
    if scope_label:
        desc_parts.append(f"scope={scope_label}")
    if streams:
        names = [s.get("name") for s in streams if isinstance(s, dict) and s.get("name")]
        if names:
            desc_parts.append(f"streams={','.join(names)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [str(name)] if name else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def _local_tag(elem):
    tag = elem.tag
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _xml_find(node, tag):
    for child in node.iter():
        if _local_tag(child) == tag:
            return child
    return None


def _xml_children(node, tag):
    return [child for child in node.iter() if _local_tag(child) == tag]


def soap_envelope(operation, params_xml):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:v9="http://ws.coverity.com/v9">'
        "<soapenv:Header/>"
        "<soapenv:Body>"
        f"<v9:{operation}>{params_xml}</v9:{operation}>"
        "</soapenv:Body>"
        "</soapenv:Envelope>"
    )


def soap_call(base_url, user, password, operation, body_xml):
    url = f"{base_url}/ws/v9/defectservice"
    headers = {
        "Authorization": basic_auth_header(user, password),
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f'"{operation}"',
    }
    envelope = soap_envelope(operation, body_xml)
    try:
        resp = requests.post(url, data=envelope.encode("utf-8"), headers=headers, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"SOAP {operation} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("SOAP authentication rejected (401).")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"SOAP {operation} returned {resp.status_code}: {resp.text[:500]}")
        return None
    try:
        return ET.fromstring(resp.content)
    except ET.ParseError as exc:
        log(f"SOAP {operation} returned non-XML body: {exc}")
        return None


def soap_defect_to_dict(node):
    """Flatten a SOAP <mergedDefectDataObj> into the same shape we
    receive from the REST /api/v2/issues endpoint, so the build /
    severity / status helpers don't have to know the source format."""
    defect = {}
    mapping = {
        "cid": "cid",
        "mergeKey": "mergeKey",
        "checkerName": "checkerName",
        "displayCategory": "category",
        "displayType": "displayType",
        "displayImpact": "impact",
        "filePathname": "filePathname",
        "lineNumber": "lineNumber",
        "functionDisplayName": "functionDisplayName",
        "status": "status",
        "firstDetected": "firstDetected",
        "lastDetected": "lastDetected",
        "owner": "owner",
        "classification": "classification",
        "action": "action",
        "severity": "severity",
    }
    for soap_name, rest_name in mapping.items():
        child = _xml_find(node, soap_name)
        if child is not None and child.text:
            text = child.text.strip()
            if rest_name in ("cid", "lineNumber"):
                try:
                    defect[rest_name] = int(text)
                except ValueError:
                    defect[rest_name] = text
            else:
                defect[rest_name] = text
    return defect


def soap_get_defects(base_url, user, password, project_name, stream_name):
    if stream_name:
        body = f"<streamIds><name>{stream_name}</name></streamIds>"
        operation = "getMergedDefectsForStreams"
    else:
        if not project_name:
            log("SOAP fallback requires either COVERITY_PROJECT or COVERITY_STREAM.")
            return []
        body = f"<projectIds><name>{project_name}</name></projectIds>"
        operation = "getMergedDefectsForProjects"
    page_spec = "<filterSpec/><pageSpec><pageSize>500</pageSize><startIndex>0</startIndex></pageSpec>"
    root = soap_call(base_url, user, password, operation, body + page_spec)
    if root is None:
        return []
    return [soap_defect_to_dict(node) for node in _xml_children(root, "mergedDefects")]


def soap_get_streams(base_url, user, password, project_name):
    if not project_name:
        return []
    operation = "getStreams"
    body = "<filterSpec><namePattern>*</namePattern></filterSpec>"
    root = soap_call(base_url, user, password, operation, body)
    if root is None:
        return []
    streams = []
    for node in _xml_children(root, "return"):
        info = {}
        for child in node:
            tag = _local_tag(child)
            if tag in ("name", "primaryProjectId", "language", "description"):
                info[tag] = (child.text or "").strip()
        if info.get("name"):
            streams.append(info)
    return streams


def validate_min_severity(value):
    text = (value or "info").strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"COVERITY_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {value!r} — defaulting to info")
        return "info"
    return text


def coverity_severity_param(min_severity):
    """Forward the min-severity floor as the Coverity-side `impact`
    filter when possible. Coverity's impact ladder is Low/Medium/High,
    so anything above 'high' collapses to High and 'info' / 'low' do
    not narrow the query."""
    if min_severity in ("high", "critical"):
        return "High"
    if min_severity == "medium":
        return "Medium"
    if min_severity == "low":
        return "Low"
    return None


def main():
    started = time.time()
    host = env("COVERITY_HOST", required=True)
    user = env("COVERITY_USER", required=True)
    password = env("COVERITY_PASSWORD", required=True)
    project_name = env("EXECUTOR_CONFIG_COVERITY_PROJECT")
    stream_name = env("EXECUTOR_CONFIG_COVERITY_STREAM")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_COVERITY_MIN_SEVERITY"))

    base_url = normalise_base_url(host)
    if not base_url:
        log("COVERITY_HOST is empty")
        sys.exit(1)

    headers = {
        "Authorization": basic_auth_header(user, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    used_soap = False

    projects, projects_code = list_projects(base_url, headers, project_name)
    if projects_code == 404 and not projects:
        # REST API absent — fall back to SOAP v9 against
        # /ws/v9/defectservice.
        log("REST /api/v2/projects returned 404 — falling back to SOAP v9 defectservice.")
        used_soap = True
        soap_streams = soap_get_streams(base_url, user, password, project_name) if project_name else []
        defects = soap_get_defects(base_url, user, password, project_name, stream_name)
        vulns = [build_vulnerability(d) for d in defects if isinstance(d, dict)]
        vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
        project = {"name": project_name or stream_name or "coverity"}
        if vulns:
            hosts.append(
                build_host(
                    project,
                    vulns,
                    streams=soap_streams,
                    scope_label=f"stream={stream_name}" if stream_name else "soap",
                )
            )
    else:
        log(f"Found {len(projects)} project(s) (project={project_name or 'all'} stream={stream_name or 'all'})")
        coverity_severity_filter = coverity_severity_param(min_severity)
        for project in projects:
            if not isinstance(project, dict):
                continue
            pname = project.get("name") or project.get("projectName")
            if not pname:
                continue
            issue_params = {"projectName": pname}
            if stream_name:
                issue_params["streamName"] = stream_name
            if coverity_severity_filter:
                issue_params["impact"] = coverity_severity_filter
            raw_defects = get_issues(base_url, headers, issue_params)
            enriched = [enrich_issue(base_url, headers, d) for d in raw_defects if isinstance(d, dict)]
            vulns = [build_vulnerability(d) for d in enriched]
            vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold]
            if not vulns:
                continue
            streams = []
            if stream_name:
                streams = list_streams(base_url, headers, pname, stream_name)
            hosts.append(
                build_host(
                    project,
                    vulns,
                    streams=streams,
                    scope_label=f"stream={stream_name}" if stream_name else None,
                )
            )

    output = {
        "hosts": hosts,
        "command": {
            "tool": "coverity",
            "command": "coverity",
            "params": (
                f"project={project_name or 'all'} stream={stream_name or 'all'} "
                f"min_severity={min_severity} transport={'soap' if used_soap else 'rest'}"
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
