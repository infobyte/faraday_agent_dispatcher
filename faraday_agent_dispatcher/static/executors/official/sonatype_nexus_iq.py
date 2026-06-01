#!/usr/bin/env python
"""Sonatype Nexus IQ Server REST API importer.

Pulls Software Composition Analysis findings from a Sonatype Nexus IQ
application's stage-scoped policy report and emits Faraday bulk-create
JSON to stdout. Each Nexus IQ application becomes one Faraday host
(``ip`` = synthetic ``0.0.0.0`` because SCA findings live in dependency
manifests, not on IPs); per-component security issues are attached as
Faraday vulnerabilities — one per ``(componentDisplayName, securityIssue
reference)`` pair with engine prefix ``[SCA]``.

Endpoints used:
  GET /api/v2/applications
      -> list every application visible to the authenticated user
      (used as a fallback when the typed lookup is empty). The typed
      lookup ``GET /api/v2/applications?publicId=<id>`` is tried first
      so we resolve the internal application id + organization id +
      contactUser for the host description in a single round-trip.
  GET /api/v2/applications/{publicId}/reports/{stageId}/policy
      -> return the latest policy report for the given application
      public id at the requested stage (build | stage-release | release
      | operate). Each component carries ``securityData.securityIssues``
      (one entry per CVE / Sonatype advisory), ``violations`` (one per
      breached policy with policyThreatCategory + policyThreatLevel),
      ``componentIdentifier.coordinates`` and ``displayName``.

Auth: HTTP Basic with ``NEXUS_IQ_USER`` / ``NEXUS_IQ_PASSWORD`` (the
user can be a Nexus IQ local account, a SAML-mapped account or a user
token id — Nexus IQ accepts all three on the v2 REST API).
``NEXUS_IQ_HOST`` is the Nexus IQ base URL (e.g.
``https://nexus-iq.corp.example.com`` or
``https://nexus-iq.corp.example.com:8070``); bare hostnames are
accepted and prefixed with ``https://``.
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

# Nexus IQ's stage segments are kebab-case in the REST path; we accept
# the common synonyms (snake_case / camelCase / underscore-stripped)
# from operator-supplied env values and normalise to the wire format.
VALID_STAGES = {
    "build": "build",
    "stage-release": "stage-release",
    "stage_release": "stage-release",
    "stagerelease": "stage-release",
    "stage": "stage-release",
    "release": "release",
    "operate": "operate",
    "production": "operate",
    "prod": "operate",
}

# Nexus IQ's policy report exposes severity in two places:
# - ``securityIssues[].severity`` is the raw CVSS base score (0-10)
# - ``securityIssues[].threatCategory`` is Sonatype's policy bucket
#   (none / low / moderate / severe / critical), which maps to a
#   Faraday severity directly.
NEXUS_IQ_THREAT_CATEGORY = {
    "critical": "critical",
    "severe": "high",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "unknown": "info",
}

# Nexus IQ's per-security-issue ``status`` lifecycle. Analyst-triaged
# states (Not Applicable, Waived) land as risk-accepted; the explicit
# Open / Confirmed / Investigating / Acknowledged tier stays open;
# Fixed (where Nexus IQ uses it) closes.
NEXUS_IQ_STATUS_TO_FARADAY = {
    "open": "open",
    "active": "open",
    "new": "open",
    "confirmed": "open",
    "investigating": "open",
    "acknowledged": "open",
    "in_progress": "open",
    "inprogress": "open",
    "in progress": "open",
    "triaged": "open",
    "reopened": "open",
    "not_applicable": "risk-accepted",
    "notapplicable": "risk-accepted",
    "not applicable": "risk-accepted",
    "waived": "risk-accepted",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "false positive": "risk-accepted",
    "accepted": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "remediated": "closed",
}


def log(msg):
    print(f"{datetime.utcnow()} - SonatypeNexusIQ: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    if not host:
        return ""
    base = host.strip()
    if not base:
        return ""
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    return base.rstrip("/")


def basic_auth_header(user, password):
    raw = f"{user or ''}:{password or ''}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def validate_stage(value):
    """Map a user-supplied stage to the canonical Nexus IQ path segment.

    Nexus IQ documents four stages: build, stage-release, release,
    operate. We accept the kebab-case wire form plus the common
    snake_case / squashed / synonym variants (``stage_release`` ↔
    ``stage-release``, ``production`` ↔ ``operate``) so playbook
    YAMLs don't have to memorise the exact spelling.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    return VALID_STAGES.get(text)


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


def severity_from_threat_category(value):
    """Map a Nexus IQ threatCategory string to a Faraday bucket."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    return NEXUS_IQ_THREAT_CATEGORY.get(text)


def severity_from_threat_level(value):
    """Map a Nexus IQ policyThreatLevel (0-10) to a Faraday bucket.

    Nexus IQ buckets policy threat level into the same boundaries as
    the IQ UI: 8-10 critical, 4-7 severe (→ high), 2-3 moderate
    (→ medium), 1 low, 0 none / info. Numeric / numeric-string inputs
    are tolerated; out-of-range values fall back to info.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return "info"
    if n < 2:
        return "low"
    if n < 4:
        return "medium"
    if n < 8:
        return "high"
    if n > 10:
        return "info"
    return "critical"


def severity_from_nexus_issue(issue, violations=None):
    """Pick the best severity bucket for one Nexus IQ security issue.

    Priority:
      1. Issue's raw CVSS base score (``severity`` is a 0-10 float on
         the Nexus IQ payload).
      2. Issue's ``threatCategory`` (critical / severe / moderate /
         low / none).
      3. Highest matching SECURITY-category policyThreatLevel from
         the surrounding component's violations list.
    """
    if not isinstance(issue, dict):
        issue = {}
    score = issue.get("severity")
    if score is not None and not isinstance(score, bool):
        try:
            return severity_from_cvss(float(score))
        except (TypeError, ValueError):
            pass
    bucket = severity_from_threat_category(issue.get("threatCategory") or issue.get("threat_category"))
    if bucket:
        return bucket
    # Fall back to the highest SECURITY-category policy threat level on
    # the component — Nexus IQ tenants that suppress severity numbers
    # still surface a policyThreatLevel per breached policy.
    if isinstance(violations, list):
        best = None
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for v in violations:
            if not isinstance(v, dict):
                continue
            cat = v.get("policyThreatCategory") or v.get("policy_threat_category") or ""
            if isinstance(cat, str) and cat.strip().upper() not in ("SECURITY", ""):
                continue
            mapped = severity_from_threat_level(v.get("policyThreatLevel") or v.get("policy_threat_level"))
            if not mapped:
                continue
            if best is None or order[mapped] > order[best]:
                best = mapped
        if best is not None:
            return best
    return "info"


def status_from_nexus_issue(issue, violations=None):
    """Map a Nexus IQ security issue's status to a Faraday status.

    Honors per-issue analyst flags first (``waived`` / ``status`` =
    Waived / NotApplicable), then any waiver on the surrounding
    violations (``waived`` / ``grandfathered`` on the violation), then
    the issue's lifecycle status. Returns ``open`` when no signal is
    present (Nexus IQ's default for fresh findings).
    """
    if not isinstance(issue, dict):
        return "open"

    # Per-issue analyst flags
    if issue.get("waived") is True:
        return "risk-accepted"
    if issue.get("notApplicable") is True or issue.get("not_applicable") is True:
        return "risk-accepted"
    if issue.get("falsePositive") is True or issue.get("false_positive") is True:
        return "risk-accepted"
    if issue.get("fixed") is True or issue.get("resolved") is True:
        return "closed"

    for key in ("status", "state", "issueStatus", "issue_status", "lifecycleStatus"):
        raw = issue.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value")
        if isinstance(raw, str):
            text = raw.strip().lower()
            if not text:
                continue
            compact_underscore = text.replace(" ", "_").replace("-", "_")
            mapped = NEXUS_IQ_STATUS_TO_FARADAY.get(text)
            if mapped:
                return mapped
            mapped = NEXUS_IQ_STATUS_TO_FARADAY.get(compact_underscore)
            if mapped:
                return mapped
            compact = text.replace(" ", "").replace("-", "").replace("_", "")
            mapped = NEXUS_IQ_STATUS_TO_FARADAY.get(compact)
            if mapped:
                return mapped

    # Surrounding-violation waivers — a component-level waiver on the
    # SECURITY policy is Nexus IQ's main "I've accepted this risk"
    # surface, so honour it even when the issue status is blank.
    if isinstance(violations, list):
        for v in violations:
            if not isinstance(v, dict):
                continue
            cat = v.get("policyThreatCategory") or v.get("policy_threat_category") or ""
            if isinstance(cat, str) and cat.strip().upper() not in ("SECURITY", ""):
                continue
            if v.get("waived") is True or v.get("grandfathered") is True:
                return "risk-accepted"

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
        log("Authentication rejected (401). Check NEXUS_IQ_USER / NEXUS_IQ_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {url}. Check user role / scope.")
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


def extract_applications(body):
    """Pluck the applications list out of /api/v2/applications shapes.

    Nexus IQ's standard response is ``{"applications": [...]}``. Older
    builds return a bare list and a couple of internal endpoints return
    ``items`` / ``results`` / ``data`` — we tolerate each.
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for candidate in ("applications", "items", "results", "data", "values", "content"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def get_application(base_url, headers, public_id):
    """Resolve a Nexus IQ application by publicId.

    Tries the typed ``GET /api/v2/applications?publicId=<id>`` lookup
    first; falls back to walking ``GET /api/v2/applications`` and
    filtering client-side for tenants whose API gateway strips the
    publicId query parameter. Returns the empty dict when the
    application can't be located (non-fatal — the importer can still
    fetch the report by publicId, the metadata just won't be in the
    host description).
    """
    body = request_json(
        "GET",
        f"{base_url}/api/v2/applications",
        headers,
        params={"publicId": public_id},
    )
    apps = extract_applications(body)
    for app in apps:
        if isinstance(app, dict) and (app.get("publicId") == public_id or app.get("public_id") == public_id):
            return app
    if apps and isinstance(apps[0], dict):
        return apps[0]
    # Fallback — paginated walk of the full list, client-side filter.
    body = request_json("GET", f"{base_url}/api/v2/applications", headers)
    for app in extract_applications(body):
        if isinstance(app, dict) and (app.get("publicId") == public_id or app.get("public_id") == public_id):
            return app
    return {}


def get_policy_report(base_url, headers, public_id, stage):
    """Fetch the policy report for a Nexus IQ application + stage."""
    url = f"{base_url}/api/v2/applications/{public_id}/reports/{stage}/policy"
    body = request_json("GET", url, headers)
    return body if isinstance(body, dict) else {}


def coord_label(component):
    """Build a human-readable coordinate from a Nexus IQ component dict.

    Nexus IQ ships ``displayName`` (preferred), plus
    ``componentIdentifier.coordinates`` (format-specific keys —
    groupId/artifactId/version for Maven, packageId/version for NuGet,
    name/version for npm/pypi/...) and a ``hash`` (sha1) for binaries
    that don't have a coordinate.
    """
    if not isinstance(component, dict):
        return ""
    display = component.get("displayName") or component.get("display_name")
    if isinstance(display, str) and display.strip():
        return display.strip()
    ident = component.get("componentIdentifier") if isinstance(component.get("componentIdentifier"), dict) else {}
    coords = ident.get("coordinates") if isinstance(ident.get("coordinates"), dict) else {}
    fmt = ident.get("format")
    group = coords.get("groupId") or coords.get("group_id")
    artifact = (
        coords.get("artifactId")
        or coords.get("artifact_id")
        or coords.get("name")
        or coords.get("packageId")
        or coords.get("package_id")
        or coords.get("module")
    )
    version = coords.get("version")
    classifier = coords.get("classifier")
    extension = coords.get("extension")
    if group and artifact:
        coord = f"{group}:{artifact}"
    else:
        coord = artifact or ""
    if classifier:
        coord = f"{coord}:{classifier}" if coord else str(classifier)
    if extension and classifier:
        coord = f"{coord}@{extension}"
    if coord and version:
        coord = f"{coord}:{version}" if fmt and fmt.lower() == "maven" else f"{coord}@{version}"
    elif version:
        coord = version
    if not coord:
        coord = (component.get("filename") or component.get("hash") or "").strip()
    return coord


def component_meta(component):
    """Pull the component coord + format/filename/pathnames metadata."""
    if not isinstance(component, dict):
        return {}
    ident = component.get("componentIdentifier") if isinstance(component.get("componentIdentifier"), dict) else {}
    coords = ident.get("coordinates") if isinstance(ident.get("coordinates"), dict) else {}
    meta = {
        "displayName": coord_label(component),
        "format": ident.get("format") or "",
        "filename": component.get("filename") or "",
        "hash": component.get("hash") or "",
        "matchState": component.get("matchState") or component.get("match_state") or "",
        "proprietary": bool(component.get("proprietary")),
        "groupId": coords.get("groupId") or coords.get("group_id") or "",
        "artifactId": coords.get("artifactId") or coords.get("artifact_id") or "",
        "version": coords.get("version") or "",
        "name": coords.get("name") or "",
    }
    pathnames = component.get("pathnames")
    if isinstance(pathnames, list):
        meta["pathnames"] = ", ".join(str(p) for p in pathnames if p)
    return meta


def collect_refs(issue, component):
    """Walk a Nexus IQ security issue + component for advisory / CWE refs."""
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

    if isinstance(issue, dict):
        for key in ("url", "referenceUrl", "reference_url"):
            url = issue.get(key)
            if isinstance(url, str) and url.strip():
                add(url.strip())
        # CWE refs surface either as a single id or a list (depends on
        # which Nexus IQ build feeds the policy report).
        cwe_raw = issue.get("cwe") or issue.get("cweId") or issue.get("cwe_id")
        if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
            add(f"CWE-{int(cwe_raw)}")
        elif isinstance(cwe_raw, str) and cwe_raw.strip():
            s = cwe_raw.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("cwes", "cweIds", "cwe_ids"):
            items = issue.get(key)
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
        # source + reference (e.g. ``source: cve, reference: CVE-...``)
        source = issue.get("source")
        reference = issue.get("reference")
        if isinstance(source, str) and source.strip() and isinstance(reference, str) and reference.strip():
            source_text = source.strip().upper()
            if source_text != "CVE":
                add(f"{source_text}: {reference.strip()}")
    # Surface the component coordinate so analysts can pivot back to
    # the BOM in Nexus IQ's UI.
    if isinstance(component, dict):
        display = component.get("displayName") or component.get("display_name")
        if isinstance(display, str) and display.strip():
            add(f"NexusIQ-Component: {display.strip()}")
    return refs


def collect_cves(issue):
    """Pull CVE-* ids out of a Nexus IQ security issue payload."""
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

    # The primary CVE id is normally on ``reference`` when ``source ==
    # "cve"``. Some Nexus IQ builds also surface aliases / related CVEs
    # in a list when an advisory bundle maps to multiple CVEs.
    source = issue.get("source")
    reference = issue.get("reference")
    if isinstance(reference, str) and reference.strip():
        if not isinstance(source, str) or source.strip().lower() in ("cve", ""):
            add(reference)
        else:
            # Even when source != cve, some tenants put the CVE id in
            # the reference field; only accept it if it looks like one.
            add(reference)
    for key in ("cves", "cveIds", "cve_ids", "aliases", "relatedCves", "related_cves"):
        v = issue.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("name") or entry.get("id") or entry.get("value") or entry.get("reference"))
    for key in ("cve", "cveId", "cveName"):
        v = issue.get(key)
        if isinstance(v, str) and v.strip():
            add(v)
    return found


def build_vulnerability(issue, component, application=None, stage=None):
    """Build a Faraday vulnerability dict from one Nexus IQ security issue."""
    if not isinstance(issue, dict):
        return None
    cmeta = component_meta(component if isinstance(component, dict) else {})
    coord = cmeta.get("displayName") or ""
    violations = component.get("violations") if isinstance(component, dict) else None

    severity = severity_from_nexus_issue(issue, violations=violations)
    status = status_from_nexus_issue(issue, violations=violations)

    reference = issue.get("reference") or issue.get("name") or issue.get("id") or "Nexus IQ finding"
    raw_name = str(reference) if not coord else f"{reference} in {coord}"
    name = f"[SCA] {raw_name}"

    desc_parts = []
    description = issue.get("description") or issue.get("summary")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if coord:
        desc_parts.append(f"component: {coord}")
    if cmeta.get("format"):
        desc_parts.append(f"format: {cmeta['format']}")
    if cmeta.get("filename"):
        desc_parts.append(f"filename: {cmeta['filename']}")
    if cmeta.get("hash"):
        desc_parts.append(f"hash: {cmeta['hash']}")
    if cmeta.get("matchState"):
        desc_parts.append(f"matchState: {cmeta['matchState']}")
    if cmeta.get("proprietary"):
        desc_parts.append("proprietary: true")
    if cmeta.get("pathnames"):
        desc_parts.append(f"pathnames: {cmeta['pathnames']}")
    source = issue.get("source")
    if source:
        desc_parts.append(f"source: {source}")
    threat_category = issue.get("threatCategory") or issue.get("threat_category")
    if threat_category:
        desc_parts.append(f"threatCategory: {threat_category}")
    raw_severity = issue.get("severity")
    if raw_severity is not None:
        desc_parts.append(f"severity: {raw_severity}")
    severity_scores = issue.get("severityScores") or issue.get("severity_scores")
    if isinstance(severity_scores, list):
        labels = []
        for s in severity_scores:
            if isinstance(s, dict):
                src = s.get("source") or s.get("name") or ""
                val = s.get("value") or s.get("score") or s.get("baseScore")
                if val is not None:
                    labels.append(f"{src}={val}" if src else str(val))
        if labels:
            desc_parts.append("severityScores: " + ", ".join(labels))
    cvss_vector = issue.get("cvssVector") or issue.get("vector") or issue.get("vectorString")
    if cvss_vector:
        desc_parts.append(f"vector: {cvss_vector}")
    issue_status = issue.get("status")
    if issue_status:
        desc_parts.append(f"status: {issue_status}")
    if isinstance(violations, list) and violations:
        breached = []
        for v in violations:
            if not isinstance(v, dict):
                continue
            policy_name = v.get("policyName") or v.get("policy_name") or v.get("policyId")
            if policy_name:
                breached.append(str(policy_name))
        if breached:
            desc_parts.append("policies: " + ", ".join(dict.fromkeys(breached)))
    if isinstance(application, dict):
        app_name = application.get("name") or application.get("publicId") or application.get("public_id")
        if app_name:
            desc_parts.append(f"application: {app_name}")
        org_id = application.get("organizationId") or application.get("organization_id")
        if org_id:
            desc_parts.append(f"organizationId: {org_id}")
    if stage:
        desc_parts.append(f"stage: {stage}")

    cves = collect_cves(issue)
    refs = collect_refs(issue, component if isinstance(component, dict) else {})

    resolution_parts = []
    for key in ("recommendedVersion", "recommended_version", "recommendation", "remediation", "solution", "fix"):
        for src in (issue, component if isinstance(component, dict) else {}):
            if not isinstance(src, dict):
                continue
            v = src.get(key)
            if isinstance(v, str) and v.strip():
                resolution_parts.append(v.strip())
                break
            if isinstance(v, dict):
                inner = v.get("version") or v.get("value") or v.get("text")
                if isinstance(inner, str) and inner.strip():
                    resolution_parts.append(inner.strip())
                    break
    resolution = " | ".join(dict.fromkeys(resolution_parts))

    external_id = issue.get("reference") or issue.get("id") or (cves[0] if cves else "")

    cvss3 = {}
    raw_score = issue.get("severity")
    if raw_score is not None and not isinstance(raw_score, bool):
        try:
            cvss3["base_score"] = float(raw_score)
        except (TypeError, ValueError):
            pass
    if cvss_vector and isinstance(cvss_vector, str) and cvss_vector.strip():
        cvss3["vector_string"] = cvss_vector.strip()

    return {
        "name": str(name).strip()[:200] or f"Nexus IQ finding {external_id}",
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
        "tags": ["sonatype_nexus_iq", "nexus_iq", "sca"],
    }


def iter_security_issues(component):
    """Yield each security issue attached to a Nexus IQ component.

    Nexus IQ shape: ``component.securityData.securityIssues`` is the
    canonical surface; some older builds also use ``securityIssues``
    on the component itself.
    """
    if not isinstance(component, dict):
        return
    sec = component.get("securityData") or component.get("security_data")
    if isinstance(sec, dict):
        issues = sec.get("securityIssues") or sec.get("security_issues") or sec.get("issues")
        if isinstance(issues, list):
            for it in issues:
                if isinstance(it, dict):
                    yield it
    direct = component.get("securityIssues") or component.get("security_issues")
    if isinstance(direct, list):
        for it in direct:
            if isinstance(it, dict):
                yield it


def build_host(public_id, application, report, stage, vulns):
    app = application if isinstance(application, dict) else {}
    rpt = report if isinstance(report, dict) else {}
    app_name = (
        app.get("name") or rpt.get("application", {}).get("name")
        if isinstance(rpt.get("application"), dict)
        else app.get("name")
    )
    if not app_name and isinstance(rpt.get("application"), dict):
        app_name = rpt["application"].get("name")
    hostname = f"{app_name}@{public_id}" if app_name else public_id

    desc_parts = [f"publicId={public_id}"]
    if app_name:
        desc_parts.append(f"application={app_name}")
    if stage:
        desc_parts.append(f"stage={stage}")
    internal_id = app.get("id") or app.get("internalId")
    if not internal_id and isinstance(rpt.get("application"), dict):
        internal_id = rpt["application"].get("id") or rpt["application"].get("internalId")
    if internal_id:
        desc_parts.append(f"applicationId={internal_id}")
    org_id = app.get("organizationId") or app.get("organization_id")
    if not org_id and isinstance(rpt.get("application"), dict):
        org_id = rpt["application"].get("organizationId") or rpt["application"].get("organization_id")
    if org_id:
        desc_parts.append(f"organizationId={org_id}")
    contact = app.get("contactUserName") or app.get("contact_user_name")
    if contact:
        desc_parts.append(f"contact={contact}")
    report_time = rpt.get("reportTime") or rpt.get("report_time")
    if report_time:
        desc_parts.append(f"reportTime={report_time}")
    commit_hash = rpt.get("commitHash") or rpt.get("commit_hash")
    if commit_hash:
        desc_parts.append(f"commitHash={commit_hash}")
    components = rpt.get("components")
    if isinstance(components, list):
        desc_parts.append(f"components={len(components)}")
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
    host = env("NEXUS_IQ_HOST", required=True)
    user = env("NEXUS_IQ_USER", required=True)
    password = env("NEXUS_IQ_PASSWORD", required=True)
    public_id = env("EXECUTOR_CONFIG_NEXUS_IQ_PUBLIC_ID", required=True)
    raw_stage = env("EXECUTOR_CONFIG_NEXUS_IQ_STAGE", required=True)
    stage = validate_stage(raw_stage)
    if not stage:
        log(
            f"NEXUS_IQ_STAGE '{raw_stage}' is not recognised; "
            "expected one of build / stage-release / release / operate."
        )
        sys.exit(1)

    base_url = normalize_base_url(host)
    if not base_url:
        log("NEXUS_IQ_HOST is required")
        sys.exit(1)

    headers = {
        "Authorization": basic_auth_header(user, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    application = get_application(base_url, headers, public_id)
    report = get_policy_report(base_url, headers, public_id, stage)
    components = report.get("components") if isinstance(report.get("components"), list) else []

    vulns = []
    issue_count = 0
    for component in components:
        if not isinstance(component, dict):
            continue
        for issue in iter_security_issues(component):
            issue_count += 1
            built = build_vulnerability(issue, component, application=application, stage=stage)
            if built is None:
                continue
            vulns.append(built)
    log(
        f"Processing {issue_count} security issue(s) across {len(components)} component(s) "
        f"(publicId={public_id}, stage={stage})"
    )

    hosts = [build_host(public_id, application, report, stage, vulns)] if vulns else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "sonatype_nexus_iq",
            "command": "sonatype_nexus_iq",
            "params": f"public_id={public_id},stage={stage}",
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
