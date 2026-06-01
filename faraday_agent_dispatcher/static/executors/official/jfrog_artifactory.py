#!/usr/bin/env python
"""JFrog Artifactory REST API importer (Xray-enabled).

Pulls Xray-side Software Composition Analysis findings via the
Artifactory REST surface (as opposed to the standalone Xray API used by
the sister ``jfrog_xray`` executor). Useful when operators only expose
the ``/artifactory`` mount of their JFrog platform to scanners — the
same Xray findings are reachable via Artifactory's
``/api/security/vulnerabilities`` endpoint when the tenant has Xray
enabled. Emits Faraday bulk-create JSON to stdout. The scanned artifact
becomes one Faraday host (``ip`` = synthetic ``0.0.0.0`` because SCA
findings live in dependency manifests, not on IPs); per-artifact Xray
issues are attached as Faraday vulnerabilities — one per
``(issue_id, componentDisplayName)`` pair with engine prefix ``[SCA]``.

Endpoints used:
  GET /api/repositories
      -> list configured repositories with ``key`` / ``type`` /
      ``packageType`` / ``url``. Used to confirm ARTIFACTORY_REPO exists
      and to surface ``packageType`` / repo type in the host
      description. The optional ``type`` query parameter (local / remote
      / virtual / federated) is not used — we just enumerate and filter
      client-side so a misconfigured filter doesn't hide the repo.
  GET /api/security/vulnerabilities
      -> Xray-on-Artifactory vulnerability surface. Filterable via
      ``repo`` + ``path`` query parameters. Paginated via
      ``page_num`` / ``num_of_rows`` on the same Xray issue shape (Xray
      issues, exposed through Artifactory). On 404 / missing endpoint
      the executor falls back to ``POST /api/xray/scanArtifact`` which
      returns the same ``vulnerabilities[]`` shape on tenants where the
      GET endpoint is gated by the older Xray-on-Artifactory plugin.

Auth: HTTP Basic with ``ARTIFACTORY_USER`` / ``ARTIFACTORY_API_KEY``.
Artifactory accepts a classic API key, an identity token (reference
token / scoped token), or a local password on the same Basic auth
surface, so the single ARTIFACTORY_API_KEY env var covers each. A
pre-built ``Bearer <token>`` value in ARTIFACTORY_API_KEY short-circuits
the Basic exchange and is sent verbatim — useful for tenants fronted
by an OAuth gateway. The legacy ``X-JFrog-Art-Api`` header surface is
covered by setting ARTIFACTORY_API_KEY to that key and providing any
ARTIFACTORY_USER — Artifactory accepts the API key as the password on
Basic, which is the documented forward-compatible path.

ARTIFACTORY_HOST is the JFrog platform base URL (e.g.
``https://yourco.jfrog.io`` or ``https://artifactory.corp.example.com``);
when the bare platform host is given (no ``/artifactory`` suffix) the
executor auto-appends ``/artifactory`` so the canonical
``/artifactory/api/...`` REST path is reached. Hosts already pointing
at ``.../artifactory`` are accepted as-is.
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

# Artifactory surfaces the same Xray severity enum on its
# ``/api/security/vulnerabilities`` proxy. Keep the mapping aligned with
# the sister ``jfrog_xray`` executor so the two sources normalise
# identically.
ARTIFACTORY_STRING_SEVERITY = {
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

ARTIFACTORY_STATUS_TO_FARADAY = {
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
    print(
        f"{datetime.utcnow()} - JFrogArtifactory: {msg}",
        file=sys.stderr,
        flush=True,
    )


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Normalise ARTIFACTORY_HOST into a base URL ready for ``/api/...``.

    Accepts bare hostnames (prefixes ``https://``), full ``http(s)://``
    URLs, and trailing slashes. When the host points at the bare
    platform domain (no ``/artifactory`` suffix) ``/artifactory`` is
    appended so the canonical Artifactory REST surface is reached —
    most JFrog Cloud tenants are configured this way (one host,
    ``/artifactory`` / ``/xray`` / ``/distribution`` mounted
    underneath).
    """
    if not host:
        return ""
    base = str(host).strip()
    if not base:
        return ""
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    base = base.rstrip("/")
    lowered = base.lower()
    if lowered.endswith("/artifactory") or "/artifactory/" in lowered:
        return base
    return f"{base}/artifactory"


def basic_auth_header(user, password):
    raw = f"{user or ''}:{password or ''}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def build_auth_header(user, api_key):
    """Build the Authorization header from ARTIFACTORY_USER / ARTIFACTORY_API_KEY.

    A pre-built ``Bearer <token>`` value in ARTIFACTORY_API_KEY is
    forwarded verbatim (useful when the tenant is fronted by an OAuth
    gateway); anything else is wrapped as HTTP Basic — Artifactory
    accepts API keys, identity tokens and local passwords on the same
    Basic surface.
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
        log(f"ARTIFACTORY_MIN_SEVERITY '{value}' not recognised; " "defaulting to 'info'")
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


def severity_from_artifactory(value, cvss=None):
    """Map an Xray-via-Artifactory severity to a Faraday bucket.

    Accepts Xray's string enum (Critical / High / Medium / Low /
    Information / Unknown / PendingScan). Falls back to CVSS bucketing
    on the provided ``cvss`` argument when the enum is missing or
    unrecognised. Bare numeric inputs are treated as CVSS scores.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in ARTIFACTORY_STRING_SEVERITY:
            return ARTIFACTORY_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_artifactory(issue):
    """Derive a Faraday status from an Artifactory / Xray issue payload.

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
            mapped = ARTIFACTORY_STATUS_TO_FARADAY.get(text)
            if mapped:
                return mapped
            mapped = ARTIFACTORY_STATUS_TO_FARADAY.get(compact_underscore)
            if mapped:
                return mapped
            compact = text.replace(" ", "").replace("-", "").replace("_", "")
            mapped = ARTIFACTORY_STATUS_TO_FARADAY.get(compact)
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
        log("Authentication rejected (401). " "Check ARTIFACTORY_USER / ARTIFACTORY_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {url}. " "Check user permissions / scope.")
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


def get_repositories(base_url, headers):
    """GET /api/repositories → list configured repos (any type)."""
    url = f"{base_url}/api/repositories"
    body = request_json("GET", url, headers)
    if isinstance(body, list):
        return body
    return extract_list(body, "repositories")


def find_repo(repos, repo_key):
    """Pull a single repo dict out of the /api/repositories response."""
    if not isinstance(repos, list) or not repo_key:
        return {}
    target = str(repo_key).strip()
    for repo in repos:
        if not isinstance(repo, dict):
            continue
        name = repo.get("key") or repo.get("repoKey") or repo.get("name") or repo.get("repo_name")
        if isinstance(name, str) and name.strip() == target:
            return repo
    return {}


def get_security_vulnerabilities(base_url, headers, repo, path):
    """GET /api/security/vulnerabilities → paginate the Xray-via-Artifactory list.

    Falls back to ``POST /api/xray/scanArtifact`` when the GET endpoint
    is absent / 404 — older Xray-on-Artifactory plugin builds only
    expose the POST scan endpoint, but it returns the same per-issue
    Xray shape on ``vulnerabilities[]``.
    """
    url = f"{base_url}/api/security/vulnerabilities"
    issues = []
    page = 1
    for _ in range(MAX_PAGES):
        params = {
            "repo": repo,
            "path": path,
            "page_num": page,
            "num_of_rows": PAGE_SIZE,
        }
        body = request_json("GET", url, headers, params=params)
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
    fallback = request_json(
        "POST",
        f"{base_url}/api/xray/scanArtifact",
        headers,
        payload={"repo": repo, "path": path},
    )
    if not isinstance(fallback, dict):
        return []
    fallback_issues = []
    for entry in extract_list(fallback, "vulnerabilities", "issues", "data"):
        if isinstance(entry, dict):
            fallback_issues.append(entry)
    # Some tenants wrap the issue list under ``artifacts[].issues``
    # (same shape as the /api/v1/summary/artifact response on the Xray
    # side); cover that shape too.
    if not fallback_issues:
        for artifact in extract_list(fallback, "artifacts"):
            if isinstance(artifact, dict):
                for entry in extract_list(artifact, "issues", "vulnerabilities"):
                    if isinstance(entry, dict):
                        fallback_issues.append(entry)
    return fallback_issues


def cvss_score(issue):
    """Pull a numeric CVSS score out of an Artifactory / Xray issue.

    Walks the canonical ``cvss_v3_score`` / ``cvss_v2_score`` keys plus
    a nested ``cves[]`` list (per-CVE attribution) and returns the
    highest score found so the imported severity matches what the Xray
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
            for key in (
                "cvss_v3_score",
                "cvssV3Score",
                "cvss_v2_score",
                "cvssV2Score",
            ):
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
    """Pull a CVSS vector string out of an Artifactory / Xray issue."""
    if not isinstance(issue, dict):
        return ""
    for key in (
        "cvss_v3_vector",
        "cvssV3Vector",
        "cvss_v2_vector",
        "cvssV2Vector",
        "vector",
        "vectorString",
    ):
        value = issue.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    cves = issue.get("cves")
    if isinstance(cves, list):
        for entry in cves:
            if not isinstance(entry, dict):
                continue
            for key in (
                "cvss_v3_vector",
                "cvssV3Vector",
                "cvss_v2_vector",
                "cvssV2Vector",
                "vector",
            ):
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def collect_cves(issue):
    """Pull CVE-* ids out of an Artifactory / Xray issue payload."""
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
    """Walk an Artifactory / Xray issue for CWE / advisory / URL refs."""
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

    for key in ("issue_id", "issueId", "source_id", "sourceId"):
        value = issue.get(key)
        if isinstance(value, str) and value.strip():
            s = value.strip()
            if not s.upper().startswith("CVE-"):
                add(s)
    return refs


def component_label(component):
    """Build a coordinate label from one component entry."""
    if not isinstance(component, dict):
        return ""
    for key in (
        "component_id",
        "componentId",
        "sourceCompId",
        "source_comp_id",
        "id",
    ):
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
    """Return the list of component-coord labels for one Xray issue."""
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


def build_vulnerability(issue, repo=None, path=None):
    """Build a Faraday vulnerability dict from one Artifactory / Xray issue."""
    if not isinstance(issue, dict):
        return None

    score = cvss_score(issue)
    severity = severity_from_artifactory(issue.get("severity"), score)
    status = status_from_artifactory(issue)

    components = collect_components(issue)
    coord = components[0] if components else ""

    summary = (
        issue.get("summary")
        or issue.get("issue_id")
        or issue.get("issueId")
        or issue.get("source_id")
        or issue.get("sourceId")
        or "Artifactory finding"
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
        "name": str(name).strip()[:200] or f"Artifactory finding {external_id}",
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
        "tags": ["jfrog_artifactory", "artifactory", "sca"],
    }


def build_host(repo, path, repo_meta, vulns):
    """Build the Faraday host wrapper for the imported issues."""
    if repo and path:
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
    if isinstance(repo_meta, dict) and repo_meta:
        pkg_type = repo_meta.get("packageType") or repo_meta.get("pkg_type") or repo_meta.get("pkgType")
        if pkg_type:
            desc_parts.append(f"packageType={pkg_type}")
        for key, label in (
            ("type", "repoType"),
            ("repo_type", "repoType"),
            ("rclass", "repoType"),
        ):
            v = repo_meta.get(key)
            if isinstance(v, str) and v.strip():
                desc_parts.append(f"{label}={v.strip()}")
                break
        url = repo_meta.get("url")
        if isinstance(url, str) and url.strip():
            desc_parts.append(f"repoUrl={url.strip()}")

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
    host = env("ARTIFACTORY_HOST", required=True)
    user = env("ARTIFACTORY_USER", required=True)
    api_key = env("ARTIFACTORY_API_KEY", required=True)
    repo = env("EXECUTOR_CONFIG_ARTIFACTORY_REPO", required=True)
    path = env("EXECUTOR_CONFIG_ARTIFACTORY_PATH", required=True)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_ARTIFACTORY_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    if not base_url:
        log("ARTIFACTORY_HOST is required")
        sys.exit(1)

    headers = {
        "Authorization": build_auth_header(user, api_key),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    repos = get_repositories(base_url, headers)
    repo_meta = find_repo(repos, repo)

    issues = get_security_vulnerabilities(base_url, headers, repo, path)

    log(f"Processing {len(issues)} Artifactory issue(s) " f"(repo={repo}, path={path}, min_severity={min_severity})")

    vulns = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        built = build_vulnerability(issue, repo=repo, path=path)
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)

    hosts = [build_host(repo, path, repo_meta, vulns)] if vulns else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "jfrog_artifactory",
            "command": "jfrog_artifactory",
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
