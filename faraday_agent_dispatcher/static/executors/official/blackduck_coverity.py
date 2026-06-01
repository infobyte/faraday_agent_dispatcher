#!/usr/bin/env python
"""Black Duck Coverity (Coverity Connect, stream-scoped) REST API importer.

Pulls source-code findings ("defects") from a single Black Duck
Coverity Connect stream and emits Faraday bulk-create JSON to stdout.
The stream becomes one Faraday host (``ip`` = synthetic ``0.0.0.0``
because SAST findings live in source repos, not on IPs); per-stream
defects (one per Coverity merge key / CID) are attached as Faraday
vulnerabilities with a ``[SAST]`` engine prefix.

This executor is intentionally narrow — it is the post-spin-off,
Black Duck-branded Coverity SAST ingest path (stream-scoped, checker
filter, REST-only). The legacy ``coverity`` executor still handles
multi-project enumeration and the SOAP fallback against Coverity
Connect 9.x and earlier; the SCA-side ingest lives in
``blackduck_sca``.

Endpoints used (REST API — Coverity Connect 2020.06+):
  GET  /api/v2/streams?name=<s>      -> stream metadata for the host
      description (primaryProjectId, language, description).
  GET  /api/v2/issues?streamId=<id>  -> paginated list of merged
      defects (CIDs) attached to the stream. ``offset`` / ``pageSize``
      pagination. ``checker`` (CSV) is forwarded to Coverity when
      ``COVERITY_CHECKER`` is set; the same list is also enforced
      client-side after pagination for older builds that ignore the
      query parameter.
  GET  /api/v2/issues/{cid}          -> per-CID detail lookup for
      description / events / recommendation enrichment when the list
      response is compact.

Auth: HTTP Basic with ``COVERITY_USER`` / ``COVERITY_PASSWORD``.
``COVERITY_HOST`` is the Coverity Connect base URL (e.g.
``https://cov.corp.example.com`` or
``https://cov.corp.example.com:8443``); bare hostnames are accepted
and prefixed with ``https://``.
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
EVIDENCE_LIMIT = 500

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Coverity Connect's "Impact" field is the closest analogue to a
# CVSS-style severity. It maxes out at "High" (Coverity has no
# "Critical" bucket); we still accept Critical for forward
# compatibility / third-party feeds.
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
    "unknown": "info",
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


def log(msg):
    print(f"{datetime.utcnow()} - BlackDuckCoverity: {msg}", file=sys.stderr, flush=True)


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


def basic_auth_header(user, password):
    raw = f"{user or ''}:{password or ''}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


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
    if score > 10:
        return "info"
    return "critical"


def severity_from_coverity(impact, cvss=None):
    """Map a Coverity impact value to a Faraday severity bucket.

    Accepts Coverity's string impact ladder (High / Medium / Low /
    Audit, also Major / Moderate / Minor / Important / Informational /
    Unspecified) and falls back to CVSS bucketing on ``cvss`` when the
    primary value is missing / unrecognised. Numeric inputs are
    interpreted as CVSS-style base scores so vendor-shaped reports
    that surface a bare score still bucket correctly.
    """
    if impact is not None and not isinstance(impact, bool):
        if isinstance(impact, (int, float)):
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
    """Map Coverity triage / lifecycle fields to Faraday status.

    Analyst overrides (classification 'False Positive' / 'Intentional'
    or action 'Ignore') win over lifecycle status — a 'Triaged' defect
    classified 'False Positive' still lands as Faraday risk-accepted.
    """
    if not isinstance(defect, dict):
        return "open"
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


def parse_checker_csv(value):
    """Parse a CSV / list of checker names into a normalised tuple.

    Tolerant of leading/trailing whitespace and empty segments. Names
    are kept verbatim (case-sensitive) because Coverity checker names
    are case-sensitive identifiers (e.g. ``NULL_RETURNS`` vs.
    ``null_returns`` are different checkers); a separate ``_norm``
    tuple of lower-cased names is exposed for the client-side filter.
    """
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = str(value).split(",")
    cleaned = []
    seen = set()
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        cleaned.append(text)
    return tuple(cleaned)


def checker_filter_matches(defect, allowed):
    """True when ``defect``'s checker name is in ``allowed`` (or empty)."""
    if not allowed:
        return True
    checker = defect.get("checker") if isinstance(defect.get("checker"), dict) else {}
    name = (
        checker.get("name")
        or checker.get("checkerName")
        or defect.get("checkerName")
        or defect.get("checker_name")
        or ""
    )
    if not name:
        return False
    text = str(name).strip()
    allowed_lower = {a.lower() for a in allowed}
    return text in allowed or text.lower() in allowed_lower


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
        return None, None
    if resp.status_code == 401:
        log("Authentication rejected (401). Check COVERITY_USER / COVERITY_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {url}. Check user role / scope.")
        return None, resp.status_code
    if resp.status_code == 404:
        return None, resp.status_code
    if resp.status_code >= 400:
        log(f"{method} {url} failed ({resp.status_code}): {resp.text[:500]}")
        return None, resp.status_code
    if not resp.content:
        return {}, resp.status_code
    try:
        return resp.json(), resp.status_code
    except ValueError:
        log(f"{method} {url} returned non-JSON body")
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


def get_stream(base_url, headers, stream_name):
    """Best-effort stream metadata fetch for the host description."""
    if not stream_name:
        return {}
    body, _ = request_json("GET", f"{base_url}/api/v2/streams", headers, params={"name": stream_name})
    streams = extract_list(body, "streams")
    for stream in streams:
        if isinstance(stream, dict) and (stream.get("name") == stream_name or stream.get("streamName") == stream_name):
            return stream
    if streams and isinstance(streams[0], dict):
        return streams[0]
    if isinstance(body, dict) and body.get("name") == stream_name:
        return body
    return {}


def get_issues(base_url, headers, stream_name, stream_id, checkers):
    """Paginate /api/v2/issues for the given stream.

    Coverity Connect's REST API accepts either ``streamId`` (numeric
    id) or ``streamName`` to scope the query; we forward both when we
    have them. Older builds reject ``streamId`` and require
    ``streamName`` — vice versa for very recent builds — so passing
    both is the most robust default.
    """
    results = []
    offset = 0
    base_params = {}
    if stream_id:
        base_params["streamId"] = stream_id
    if stream_name:
        base_params["streamName"] = stream_name
    if checkers:
        base_params["checker"] = ",".join(checkers)
    for _ in range(MAX_PAGES):
        params = dict(base_params)
        params["offset"] = offset
        params["pageSize"] = PAGE_SIZE
        body, code = request_json("GET", f"{base_url}/api/v2/issues", headers, params=params)
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
    body, _ = request_json("GET", f"{base_url}/api/v2/issues/{cid}", headers)
    if not isinstance(body, dict):
        return defect
    merged = dict(defect)
    for key, value in body.items():
        if key not in merged or merged[key] in (None, "", [], {}):
            merged[key] = value
    return merged


def collect_refs(defect):
    refs = []
    seen = set()

    def add(text, ref_type="other"):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": ref_type})

    checker_block = defect.get("checker") if isinstance(defect.get("checker"), dict) else {}
    cwe = defect.get("cwe") or defect.get("cweId") or defect.get("cwe_id") or checker_block.get("cwe")
    if cwe is not None:
        if isinstance(cwe, list):
            for entry in cwe:
                value = entry.get("id") if isinstance(entry, dict) else entry
                if value is None:
                    continue
                text = str(value).strip()
                if not text:
                    continue
                add(text if text.upper().startswith("CWE-") else f"CWE-{text}")
        elif isinstance(cwe, (int, float)) and not isinstance(cwe, bool):
            add(f"CWE-{int(cwe)}")
        else:
            text = str(cwe).strip()
            if text:
                add(text if text.upper().startswith("CWE-") else f"CWE-{text}")

    checker_name = (
        checker_block.get("name")
        or checker_block.get("checkerName")
        or defect.get("checkerName")
        or defect.get("checker_name")
    )
    if checker_name:
        add(f"CoverityChecker-{checker_name}")

    category = defect.get("category") or defect.get("checkerCategory")
    if isinstance(category, dict):
        category = category.get("name") or category.get("value")
    if category:
        add(f"CoverityCategory-{category}")

    issue_kind = defect.get("issueKind") or defect.get("kind") or defect.get("type")
    if isinstance(issue_kind, dict):
        issue_kind = issue_kind.get("name") or issue_kind.get("value")
    if issue_kind and str(issue_kind).strip().upper() not in ("VARIOUS", "QUALITY"):
        add(f"CoverityKind-{issue_kind}")

    for entry in defect.get("references") or []:
        if isinstance(entry, str) and entry:
            add(entry)
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("name") or entry.get("value")
            if value:
                add(value, entry.get("type", "other") or "other")
    return refs


def collect_cves(defect):
    if not isinstance(defect, dict):
        return []
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
        if key.startswith("CVE-") and key not in seen:
            seen.add(key)
            found.append(key)
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


def build_vulnerability(defect, stream_name=None):
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
    if stream_name:
        desc_parts.append(f"stream: {stream_name}")
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

    cvss3_out = {}
    if cvss is not None:
        try:
            cvss3_out["base_score"] = float(cvss)
        except (TypeError, ValueError):
            cvss3_out["base_score"] = str(cvss)

    return {
        "name": str(name).strip()[:200] or "Coverity finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(cid or merge_key or defect.get("id") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": defect.get("eventTreeXml") or "",
        "refs": collect_refs(defect),
        "cve": collect_cves(defect),
        "cvss3": cvss3_out,
        "tags": ["blackduck_coverity", "coverity", "sast"],
    }


def build_host(stream_name, stream, vulns, checkers=None):
    name = stream_name or (stream or {}).get("name") or (stream or {}).get("streamName") or "coverity-stream"
    desc_parts = [f"Coverity Connect stream name={name}"]
    stream = stream if isinstance(stream, dict) else {}
    primary_project = (
        stream.get("primaryProjectId")
        or stream.get("primary_project_id")
        or stream.get("projectName")
        or stream.get("project")
    )
    if isinstance(primary_project, dict):
        primary_project = primary_project.get("name") or primary_project.get("value")
    if primary_project:
        desc_parts.append(f"primaryProject={primary_project}")
    language = stream.get("language")
    if language:
        desc_parts.append(f"language={language}")
    description = stream.get("description")
    if description:
        desc_parts.append(f"description={description}")
    stream_id = stream.get("id") or stream.get("streamId")
    if stream_id:
        desc_parts.append(f"streamId={stream_id}")
    if checkers:
        desc_parts.append(f"checkers={','.join(checkers)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [str(name)] if name else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("COVERITY_HOST", required=True)
    user = env("COVERITY_USER", required=True)
    password = env("COVERITY_PASSWORD", required=True)
    stream_name = env("EXECUTOR_CONFIG_COVERITY_STREAM", required=True)
    checkers = parse_checker_csv(env("EXECUTOR_CONFIG_COVERITY_CHECKER"))

    base_url = normalise_base_url(host)
    if not base_url:
        log("COVERITY_HOST is empty")
        sys.exit(1)

    headers = {
        "Authorization": basic_auth_header(user, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    stream = get_stream(base_url, headers, stream_name)
    stream_id = None
    if isinstance(stream, dict):
        stream_id = stream.get("id") or stream.get("streamId")

    raw_defects = get_issues(base_url, headers, stream_name, stream_id, checkers)
    log(
        f"Processing {len(raw_defects)} defect(s) "
        f"(stream={stream_name}, checkers={','.join(checkers) if checkers else 'any'})"
    )
    enriched = [enrich_issue(base_url, headers, d) for d in raw_defects if isinstance(d, dict)]
    vulns = []
    for defect in enriched:
        if not checker_filter_matches(defect, checkers):
            continue
        vulns.append(build_vulnerability(defect, stream_name=stream_name))

    hosts = [build_host(stream_name, stream, vulns, checkers=checkers)] if vulns else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "blackduck_coverity",
            "command": "blackduck_coverity",
            "params": (f"stream={stream_name}," f"checker={','.join(checkers) if checkers else 'any'}"),
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
