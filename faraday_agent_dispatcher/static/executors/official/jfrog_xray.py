#!/usr/bin/env python
"""JFrog Xray REST API importer.

Pulls Software Composition Analysis findings from a JFrog Xray tenant
and emits Faraday bulk-create JSON to stdout. Each scanned artifact (or
build, when XRAY_PATH is shaped as ``build:<build_name>:<build_number>``
or ``<build_name>#<build_number>``) becomes one Faraday host (``ip`` =
synthetic ``0.0.0.0`` because SCA findings live in dependency manifests,
not on IPs); per-artifact / per-build Xray issues are attached as
Faraday vulnerabilities — one per ``(issue_id, componentDisplayName)``
pair with engine prefix ``[SCA]``.

Endpoints used:
  GET  /api/v1/binMgr/{binMgrId}/repositories
      -> list indexed / non-indexed repositories for the binary manager
      (default binMgrId = ``default``). Used to confirm XRAY_REPO is
      Xray-indexed and to surface ``packageType`` / ``isLocal`` /
      ``isRemote`` / ``isVirtual`` metadata in the host description.
  POST /api/v1/summary/build
      -> build-level summary for builds (XRAY_PATH shaped as
      ``build:<name>:<number>`` or ``<name>#<number>``). Returns
      ``builds[].issues`` with ``severity`` / ``summary`` /
      ``description`` / ``cves`` / ``impact_path``.
  POST /api/v1/vulnerabilities
      -> filter-based, paginated vulnerability list used as the primary
      source when XRAY_PATH is an artifact path. Body filters on
      ``repo`` + ``path`` for artifact-level retrieval; falls back to
      the ``/api/v1/summary/artifact`` shape when the v1 vulnerabilities
      endpoint is absent or returns a 404 (some self-hosted Xray builds
      only expose the summary endpoint).

Auth: HTTP Basic with ``XRAY_USER`` / ``XRAY_API_KEY``. JFrog Xray
accepts a classic API key, an identity token (reference token /
scoped token), or a password on the same Basic auth surface, so the
single XRAY_API_KEY env var covers each. A pre-built ``Bearer <token>``
value in XRAY_API_KEY short-circuits the Basic exchange and is sent
verbatim — useful for tenants fronted by an OAuth gateway.

XRAY_HOST is the JFrog platform base URL (e.g.
``https://yourco.jfrog.io`` or ``https://xray.corp.example.com``); when
the bare platform host is given (no ``/xray`` suffix) the executor
auto-appends ``/xray`` so the canonical ``/xray/api/v1/...`` REST path
is reached. Hosts already pointing at ``.../xray`` are accepted as-is.
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

# JFrog Xray surfaces severity as a title-cased string enum
# (Critical / High / Medium / Low / Information / Unknown) plus the
# CVSS numeric base score on the ``cvss_v3_score`` / ``cvss_v2_score``
# fields. Map the enum to a Faraday bucket; fall back to CVSS bucketing
# when only a score is available.
XRAY_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "major": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "information": "info",
    "informational": "info",
    "none": "info",
    "unspecified": "info",
    "unknown": "info",
    "pending_scan": "info",
    "pending scan": "info",
    "scan_failed": "info",
    "scan failed": "info",
}

# Xray issue lifecycle:
#   Open / New / In Progress -> open
#   Fixed / Resolved -> closed
#   Ignored / Suppressed / Not Applicable / Risk Accepted -> risk-accepted
XRAY_STATUS_TO_FARADAY = {
    "open": "open",
    "new": "open",
    "active": "open",
    "in_progress": "open",
    "inprogress": "open",
    "triaged": "open",
    "reopened": "open",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "remediated": "closed",
    "patched": "closed",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "not_applicable": "risk-accepted",
    "notapplicable": "risk-accepted",
    "not applicable": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "false positive": "risk-accepted",
    "accepted": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "waived": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - JFrogXray: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Normalise the XRAY_HOST env into a base URL ready for ``/api/v1/...``.

    Accepts bare hostnames (prefixes ``https://``), full ``http(s)://``
    URLs, and trailing slashes. When the host points at the bare
    platform domain (no ``/xray`` suffix) ``/xray`` is appended so the
    canonical Xray REST surface is reached — most JFrog Cloud tenants
    are configured this way (one host, ``/artifactory`` / ``/xray`` /
    ``/distribution`` mounted underneath).
    """
    if not host:
        return ""
    base = str(host).strip()
    if not base:
        return ""
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    base = base.rstrip("/")
    # If the operator already pointed us at /xray (or /artifactory/api,
    # the rare legacy mount), leave it alone. Otherwise append /xray.
    lowered = base.lower()
    if lowered.endswith("/xray") or "/xray/" in lowered:
        return base
    return f"{base}/xray"


def basic_auth_header(user, password):
    raw = f"{user or ''}:{password or ''}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def build_auth_header(user, api_key):
    """Build the Authorization header from XRAY_USER / XRAY_API_KEY.

    A pre-built ``Bearer <token>`` value in XRAY_API_KEY is forwarded
    verbatim (useful when the tenant is fronted by an OAuth gateway);
    anything else is wrapped as HTTP Basic — JFrog accepts API keys,
    identity tokens and local passwords on the same Basic surface.
    """
    if api_key:
        text = str(api_key).strip()
        if text.lower().startswith("bearer "):
            return text
    return basic_auth_header(user, api_key)


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"XRAY_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


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


def severity_from_xray(value, cvss=None):
    """Map a JFrog Xray severity enum to a Faraday bucket.

    Accepts Xray's string enum (Critical / High / Medium / Low /
    Information / Unknown / PendingScan). Falls back to CVSS bucketing
    on the provided ``cvss`` argument when the enum is missing or
    unrecognised. Bare numeric inputs are treated as CVSS scores.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in XRAY_STRING_SEVERITY:
            return XRAY_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_xray(issue):
    """Derive a Faraday status from a JFrog Xray issue / violation payload.

    Per-issue analyst flags win over lifecycle status — an Xray issue
    that's still ``Open`` but ``ignored`` (or marked ``false_positive``)
    surfaces as risk-accepted.
    """
    if not isinstance(issue, dict):
        return "open"
    if issue.get("ignored") is True:
        return "risk-accepted"
    if issue.get("falsePositive") is True or issue.get("false_positive") is True:
        return "risk-accepted"
    if issue.get("muted") is True or issue.get("suppressed") is True:
        return "risk-accepted"
    if issue.get("notApplicable") is True or issue.get("not_applicable") is True:
        return "risk-accepted"
    if issue.get("fixed") is True or issue.get("resolved") is True:
        return "closed"
    for key in ("status", "state", "issue_status", "issueStatus", "violation_status"):
        raw = issue.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value")
        if isinstance(raw, str):
            text = raw.strip().lower()
            if not text:
                continue
            compact_underscore = text.replace(" ", "_").replace("-", "_")
            mapped = XRAY_STATUS_TO_FARADAY.get(text)
            if mapped:
                return mapped
            mapped = XRAY_STATUS_TO_FARADAY.get(compact_underscore)
            if mapped:
                return mapped
            compact = text.replace(" ", "").replace("-", "").replace("_", "")
            mapped = XRAY_STATUS_TO_FARADAY.get(compact)
            if mapped:
                return mapped
    return "open"


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
        log("Authentication rejected (401). Check XRAY_USER / XRAY_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {url}. Check user permissions / scope.")
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


def extract_list(body, *keys):
    """Pluck a list value from common JFrog REST shapes."""
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for candidate in keys:
            value = body.get(candidate)
            if isinstance(value, list):
                return value
        for candidate in ("items", "results", "data", "values", "content"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def parse_build_path(path):
    """Recognise XRAY_PATH values that name a build instead of an artifact.

    Accepts ``build:<name>:<number>`` (canonical, distinguishes from
    paths that contain ``#``) and the convenience form
    ``<name>#<number>`` for symmetry with how JFrog UI shows builds.
    Returns ``(build_name, build_number)`` when matched, else
    ``(None, None)``.
    """
    if not isinstance(path, str):
        return None, None
    text = path.strip()
    if not text:
        return None, None
    if text.lower().startswith("build:"):
        rest = text[len("build:") :]
        if ":" in rest:
            name, number = rest.split(":", 1)
            name, number = name.strip(), number.strip()
            if name and number:
                return name, number
    if "#" in text and "/" not in text.split("#", 1)[0]:
        # Only treat ``foo#42`` as a build when the left side has no
        # path separator — artifact paths can legitimately contain ``#``
        # in their final filename component, so we keep the safer form.
        name, number = text.split("#", 1)
        name, number = name.strip(), number.strip()
        if name and number:
            return name, number
    return None, None


def get_repositories(base_url, headers, bin_mgr_id="default"):
    """Fetch the indexed / non-indexed repos for a binary manager id."""
    url = f"{base_url}/api/v1/binMgr/{bin_mgr_id}/repositories"
    body = request_json("GET", url, headers)
    if not isinstance(body, dict):
        return {}, []
    indexed = body.get("indexed_repos") or body.get("indexedRepos") or []
    non_indexed = body.get("non_indexed_repos") or body.get("nonIndexedRepos") or []
    if not isinstance(indexed, list):
        indexed = []
    if not isinstance(non_indexed, list):
        non_indexed = []
    return body, indexed + ([] if not isinstance(non_indexed, list) else non_indexed)


def find_repo(repos, repo_key):
    """Pull a single repo dict out of the binMgr/repositories response."""
    if not isinstance(repos, list) or not repo_key:
        return {}
    target = str(repo_key).strip()
    for repo in repos:
        if not isinstance(repo, dict):
            continue
        name = repo.get("name") or repo.get("repo_name") or repo.get("key") or repo.get("repoKey")
        if isinstance(name, str) and name.strip() == target:
            return repo
    return {}


def get_build_issues(base_url, headers, build_name, build_number):
    """POST /api/v1/summary/build → return the list of build issues."""
    url = f"{base_url}/api/v1/summary/build"
    body = request_json(
        "POST",
        url,
        headers,
        payload={"build_name": build_name, "build_number": build_number},
    )
    if not isinstance(body, dict):
        return [], {}
    builds = body.get("builds") if isinstance(body.get("builds"), list) else []
    issues = []
    build_meta = {}
    for entry in builds:
        if not isinstance(entry, dict):
            continue
        if not build_meta:
            build_meta = entry
        for issue in extract_list(entry, "issues", "vulnerabilities"):
            if isinstance(issue, dict):
                issues.append(issue)
    return issues, build_meta


def get_artifact_vulnerabilities(base_url, headers, repo, path):
    """POST /api/v1/vulnerabilities → paginate filter-based vuln list.

    Falls back to the ``/api/v1/summary/artifact`` endpoint when the v1
    vulnerabilities endpoint is absent or returns a 404 — some
    self-hosted Xray builds only expose the artifact summary endpoint
    (which has the same per-issue shape on its ``artifacts[].issues``
    output).
    """
    url = f"{base_url}/api/v1/vulnerabilities"
    issues = []
    page = 1
    for _ in range(MAX_PAGES):
        payload = {
            "repo": repo,
            "path": path,
            "include_ignored": True,
            "direction": "asc",
            "page_num": page,
            "num_of_rows": PAGE_SIZE,
        }
        body = request_json("POST", url, headers, payload=payload)
        if body is None:
            break
        chunk = extract_list(body, "vulnerabilities", "data", "issues")
        if not chunk:
            break
        for entry in chunk:
            if isinstance(entry, dict):
                issues.append(entry)
        total = None
        if isinstance(body, dict):
            total = (
                body.get("total_vulnerabilities")
                or body.get("totalVulnerabilities")
                or body.get("total")
                or body.get("totalItems")
            )
        if isinstance(total, int) and len(issues) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    if issues:
        return issues
    # Fallback — artifact summary endpoint.
    summary = request_json(
        "POST",
        f"{base_url}/api/v1/summary/artifact",
        headers,
        payload={"paths": [f"{repo}/{path}".lstrip("/")]},
    )
    if not isinstance(summary, dict):
        return []
    fallback = []
    for artifact in extract_list(summary, "artifacts"):
        if isinstance(artifact, dict):
            for issue in extract_list(artifact, "issues", "vulnerabilities"):
                if isinstance(issue, dict):
                    fallback.append(issue)
    return fallback


def cvss_score(issue):
    """Pull a numeric CVSS score out of a JFrog Xray issue payload.

    Xray surfaces ``cvss_v3_score`` / ``cvss_v2_score`` as the
    canonical scores plus a nested ``cves[]`` list whose entries also
    carry per-CVE scores. Walk the usual suspects and return the
    highest score found so the imported severity matches what Xray's
    UI bucketed for the same issue.
    """
    if not isinstance(issue, dict):
        return None
    best = None
    for key in (
        "cvss_v3_score",
        "cvssV3Score",
        "cvss_v3",
        "cvssV3",
        "cvss_v2_score",
        "cvssV2Score",
        "cvss_v2",
        "cvssV2",
        "score",
        "baseScore",
        "base_score",
    ):
        value = issue.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            score = float(value)
        except (TypeError, ValueError):
            continue
        if best is None or score > best:
            best = score
    cves = issue.get("cves")
    if isinstance(cves, list):
        for entry in cves:
            if not isinstance(entry, dict):
                continue
            for key in ("cvss_v3_score", "cvssV3Score", "cvss_v2_score", "cvssV2Score"):
                value = entry.get(key)
                if value is None or isinstance(value, (dict, list, bool)):
                    continue
                try:
                    score = float(value)
                except (TypeError, ValueError):
                    continue
                if best is None or score > best:
                    best = score
    return best


def cvss_vector(issue):
    """Pull a CVSS vector string out of a JFrog Xray issue payload."""
    if not isinstance(issue, dict):
        return ""
    for key in ("cvss_v3_vector", "cvssV3Vector", "cvss_v2_vector", "cvssV2Vector", "vector", "vectorString"):
        value = issue.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    cves = issue.get("cves")
    if isinstance(cves, list):
        for entry in cves:
            if not isinstance(entry, dict):
                continue
            for key in ("cvss_v3_vector", "cvssV3Vector", "cvss_v2_vector", "cvssV2Vector", "vector"):
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def collect_cves(issue):
    """Pull CVE-* ids out of a JFrog Xray issue payload."""
    if not isinstance(issue, dict):
        return []
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if not s.startswith("CVE-"):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    cves = issue.get("cves")
    if isinstance(cves, list):
        for entry in cves:
            if isinstance(entry, str):
                add(entry)
            elif isinstance(entry, dict):
                for key in ("cve", "cveId", "cve_id", "name", "id"):
                    val = entry.get(key)
                    if isinstance(val, str):
                        add(val)
    for key in ("cve", "cveId", "cve_id"):
        v = issue.get(key)
        if isinstance(v, str) and v.strip():
            add(v)
    for key in ("aliases", "references"):
        v = issue.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("name") or entry.get("id") or entry.get("value"))
    summary = issue.get("summary") or issue.get("issue_id") or issue.get("issueId")
    if isinstance(summary, str):
        add(summary)
    return found


def collect_refs(issue):
    """Walk a JFrog Xray issue for CWE / advisory / URL refs."""
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

    if not isinstance(issue, dict):
        return refs

    # CWE refs surface as single ids, lists, list-of-dicts, and nested
    # under ``cves[]`` (per-CVE CWE attribution).
    def add_cwe(raw):
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            add(f"CWE-{int(raw)}")
        elif isinstance(raw, str) and raw.strip():
            s = raw.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")

    cwe_raw = issue.get("cwe") or issue.get("cweId") or issue.get("cwe_id")
    if isinstance(cwe_raw, list):
        for it in cwe_raw:
            if isinstance(it, dict):
                cid = it.get("id") or it.get("value") or it.get("name")
                if cid is not None:
                    add_cwe(cid)
            else:
                add_cwe(it)
    else:
        add_cwe(cwe_raw)
    for key in ("cwes", "cweIds", "cwe_ids"):
        items = issue.get(key)
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    cid = it.get("id") or it.get("value") or it.get("name")
                    if cid is not None:
                        add_cwe(cid)
                else:
                    add_cwe(it)
    cves = issue.get("cves")
    if isinstance(cves, list):
        for entry in cves:
            if not isinstance(entry, dict):
                continue
            cwe_entry = entry.get("cwe") or entry.get("cweId") or entry.get("cwe_id")
            if isinstance(cwe_entry, list):
                for it in cwe_entry:
                    if isinstance(it, dict):
                        cid = it.get("id") or it.get("value") or it.get("name")
                        if cid is not None:
                            add_cwe(cid)
                    else:
                        add_cwe(it)
            else:
                add_cwe(cwe_entry)

    # External references / advisory URLs.
    for key in ("references", "external_references", "links"):
        entry = issue.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("url") or it.get("href") or it.get("name") or it.get("id")
                    if href:
                        add(href)
                elif it:
                    add(str(it))
    for key in ("url", "advisory_url", "advisoryUrl"):
        value = issue.get(key)
        if isinstance(value, str) and value.strip():
            add(value.strip())

    # XRAY-* issue id surfaces both as ``issue_id`` and ``source_id``.
    for key in ("issue_id", "issueId", "source_id", "sourceId"):
        value = issue.get(key)
        if isinstance(value, str) and value.strip():
            s = value.strip()
            if not s.upper().startswith("CVE-"):
                add(s)
    return refs


def component_label(component):
    """Build a coordinate label from one component entry.

    Xray issues attach components in three rough shapes:
      - ``component_id`` / ``componentId`` / ``sourceCompId`` — the
        canonical, already-formatted coord (e.g. ``gav://g:a:1.0``).
      - ``id`` — older / build-side shape with the same semantics.
      - ``name`` / ``package_name`` + ``version`` / ``package_version``
        — split shape used by some Xray builds; we combine into
        ``name@version`` so the title stays human-readable.
    """
    if not isinstance(component, dict):
        return ""
    for key in ("component_id", "componentId", "sourceCompId", "source_comp_id", "id"):
        value = component.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    name = component.get("name") or component.get("package_name") or component.get("packageName")
    ver = component.get("version") or component.get("package_version") or component.get("packageVersion")
    if isinstance(name, str) and name.strip():
        n = name.strip()
        if isinstance(ver, str) and ver.strip():
            return f"{n}@{ver.strip()}"
        return n
    if isinstance(ver, str) and ver.strip():
        return ver.strip()
    return ""


def collect_components(issue):
    """Return the list of component-coord labels for one Xray issue.

    Xray issues attach ``components`` (artifact-level) or
    ``impact_path`` (build-level) — both carry one entry per affected
    dependency. We collect both shapes and dedupe.
    """
    labels = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        labels.append(s)

    if not isinstance(issue, dict):
        return labels

    for key in ("components", "impacted_components", "impactedComponents"):
        entries = issue.get(key)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    add(component_label(entry))
                elif isinstance(entry, str):
                    add(entry)

    for key in ("impact_path", "impactPath", "impact_paths", "impactPaths"):
        entries = issue.get(key)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, list):
                    if entry:
                        last = entry[-1]
                        if isinstance(last, str):
                            add(last)
                        elif isinstance(last, dict):
                            add(component_label(last))
                elif isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(component_label(entry))
    return labels


def build_vulnerability(issue, repo=None, path=None, build_name=None, build_number=None):
    """Build a Faraday vulnerability dict from one JFrog Xray issue."""
    if not isinstance(issue, dict):
        return None

    score = cvss_score(issue)
    severity = severity_from_xray(issue.get("severity"), score)
    status = status_from_xray(issue)

    components = collect_components(issue)
    coord = components[0] if components else ""

    summary = (
        issue.get("summary")
        or issue.get("issue_id")
        or issue.get("issueId")
        or issue.get("source_id")
        or issue.get("sourceId")
        or "Xray finding"
    )
    raw_name = summary if not coord else f"{summary} in {coord}"
    name = f"[SCA] {raw_name}"

    desc_parts = []
    description = issue.get("description") or issue.get("provider")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if coord:
        desc_parts.append(f"component: {coord}")
    if len(components) > 1:
        desc_parts.append("components: " + ", ".join(components[:10]))
    issue_type = issue.get("issue_type") or issue.get("issueType") or issue.get("type")
    if issue_type:
        desc_parts.append(f"issueType: {issue_type}")
    provider = issue.get("provider")
    if isinstance(provider, str) and provider.strip():
        desc_parts.append(f"provider: {provider.strip()}")
    raw_severity = issue.get("severity")
    if raw_severity:
        desc_parts.append(f"severity: {raw_severity}")
    if score is not None:
        desc_parts.append(f"cvssScore: {score}")
    vector = cvss_vector(issue)
    if vector:
        desc_parts.append(f"vector: {vector}")
    raw_status = issue.get("status") or issue.get("issue_status")
    if raw_status:
        desc_parts.append(f"status: {raw_status}")
    created = issue.get("created") or issue.get("issue_created") or issue.get("createdAt")
    if created:
        desc_parts.append(f"created: {created}")
    updated = issue.get("updated") or issue.get("modified") or issue.get("updatedAt")
    if updated:
        desc_parts.append(f"updated: {updated}")
    if repo:
        desc_parts.append(f"repo: {repo}")
    if path:
        desc_parts.append(f"path: {path}")
    if build_name:
        desc_parts.append(f"build: {build_name}")
    if build_number:
        desc_parts.append(f"buildNumber: {build_number}")

    cves = collect_cves(issue)
    refs = collect_refs(issue)

    resolution_parts = []
    for key in (
        "remediation",
        "fix_resolution",
        "fixResolution",
        "fix_version",
        "fixVersion",
        "fixedVersions",
        "fixed_versions",
        "recommended_version",
        "recommendedVersion",
        "recommendation",
        "solution",
    ):
        v = issue.get(key)
        if isinstance(v, str) and v.strip():
            resolution_parts.append(v.strip())
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    resolution_parts.append(entry.strip())
                elif isinstance(entry, dict):
                    inner = entry.get("version") or entry.get("value") or entry.get("text") or entry.get("url")
                    if isinstance(inner, str) and inner.strip():
                        resolution_parts.append(inner.strip())
    # Per-component ``fixed_versions`` is the most common shape on Xray.
    comps = issue.get("components")
    if isinstance(comps, list):
        for c in comps:
            if not isinstance(c, dict):
                continue
            fv = c.get("fixed_versions") or c.get("fixedVersions")
            if isinstance(fv, list):
                for entry in fv:
                    if isinstance(entry, str) and entry.strip():
                        resolution_parts.append(entry.strip())
    resolution = " | ".join(dict.fromkeys(resolution_parts))

    external_id = (
        issue.get("issue_id")
        or issue.get("issueId")
        or issue.get("source_id")
        or issue.get("sourceId")
        or (cves[0] if cves else "")
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Xray finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id),
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["jfrog_xray", "xray", "sca"],
    }


def build_host(repo, path, repo_meta, build_name, build_number, build_meta, vulns):
    """Build the Faraday host wrapper for the imported issues."""
    if build_name and build_number:
        hostname = f"build:{build_name}#{build_number}"
    elif repo and path:
        joined = f"{repo}/{path}".lstrip("/")
        hostname = joined
    elif repo:
        hostname = repo
    else:
        hostname = path or ""

    desc_parts = []
    if repo:
        desc_parts.append(f"repo={repo}")
    if path:
        desc_parts.append(f"path={path}")
    if build_name:
        desc_parts.append(f"buildName={build_name}")
    if build_number:
        desc_parts.append(f"buildNumber={build_number}")
    if isinstance(repo_meta, dict) and repo_meta:
        pkg_type = repo_meta.get("pkg_type") or repo_meta.get("pkgType") or repo_meta.get("packageType")
        if pkg_type:
            desc_parts.append(f"packageType={pkg_type}")
        for key, label in (
            ("type", "repoType"),
            ("repo_type", "repoType"),
        ):
            v = repo_meta.get(key)
            if isinstance(v, str) and v.strip():
                desc_parts.append(f"{label}={v.strip()}")
                break
    if isinstance(build_meta, dict) and build_meta:
        for key, label in (
            ("started", "buildStarted"),
            ("startedAt", "buildStarted"),
            ("build_started", "buildStarted"),
        ):
            v = build_meta.get(key)
            if isinstance(v, str) and v.strip():
                desc_parts.append(f"{label}={v.strip()}")
                break
        artifacts = build_meta.get("artifacts")
        if isinstance(artifacts, list):
            desc_parts.append(f"buildArtifacts={len(artifacts)}")

    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("XRAY_HOST", required=True)
    user = env("XRAY_USER", required=True)
    api_key = env("XRAY_API_KEY", required=True)
    repo = env("EXECUTOR_CONFIG_XRAY_REPO", required=True)
    path = env("EXECUTOR_CONFIG_XRAY_PATH", required=True)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_XRAY_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    if not base_url:
        log("XRAY_HOST is required")
        sys.exit(1)

    headers = {
        "Authorization": build_auth_header(user, api_key),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    bin_mgr_id = os.getenv("XRAY_BIN_MGR_ID", "default") or "default"
    _repos_body, repos = get_repositories(base_url, headers, bin_mgr_id=bin_mgr_id)
    repo_meta = find_repo(repos, repo)

    build_name, build_number = parse_build_path(path)
    if build_name and build_number:
        issues, build_meta = get_build_issues(base_url, headers, build_name, build_number)
    else:
        issues = get_artifact_vulnerabilities(base_url, headers, repo, path)
        build_meta = {}

    log(
        f"Processing {len(issues)} Xray issue(s) "
        f"(repo={repo}, path={path}, min_severity={min_severity}"
        + (f", build={build_name}#{build_number}" if build_name else "")
        + ")"
    )

    vulns = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        built = build_vulnerability(
            issue,
            repo=repo,
            path=path,
            build_name=build_name,
            build_number=build_number,
        )
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)

    hosts = [build_host(repo, path, repo_meta, build_name, build_number, build_meta, vulns)] if vulns else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "jfrog_xray",
            "command": "jfrog_xray",
            "params": (f"repo={repo},path={path},min_severity={min_severity}"),
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
