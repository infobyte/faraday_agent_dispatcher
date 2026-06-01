#!/usr/bin/env python
"""Wiz (Cloud-Native Application Protection Platform) GraphQL importer.

Pulls cloud-security issues from a Wiz tenant via the canonical
``POST /graphql`` ``IssuesTable`` query and emits Faraday bulk-create
JSON to stdout. Each Wiz project becomes one Faraday host (``ip`` =
synthetic ``0.0.0.0`` because CNAPP findings live on cloud resources,
not on IPs); per-project issues are attached as Faraday vulnerabilities
— one per Wiz issue id with engine prefix ``[CNAPP]``.

Endpoints used:
  POST {WIZ_HOST}/graphql
      -> single GraphQL endpoint. The ``IssuesTable`` query enumerates
      ``issuesV2`` (paginated via ``first`` / ``after`` cursor) with
      filters on status / severity / project; each node carries id /
      severity / status / sourceRule (Control or CloudConfigurationRule)
      / projects / entitySnapshot (the affected cloud resource) /
      createdAt / updatedAt / dueAt / resolvedAt / statusChangedAt /
      notes / serviceTickets.
  POST {WIZ_AUTH_HOST}/oauth/token
      -> OAuth2 client_credentials. Returns ``{"access_token": "...",
      "expires_in": N}``; subsequent calls send
      ``Authorization: Bearer <access_token>``.

Auth: Wiz exclusively uses OAuth2 client_credentials. A service account
is created in the Wiz UI, the client id / secret are stored in
``WIZ_CLIENT_ID`` / ``WIZ_CLIENT_SECRET``, and the auth tenant URL is
``WIZ_AUTH_HOST`` (e.g. ``https://auth.app.wiz.io``). The API tenant
URL is ``WIZ_HOST`` (e.g. ``https://api.us4.app.wiz.io``). The audience
defaults to ``wiz-api`` but is overridable via ``WIZ_AUDIENCE`` for
tenants that mint scope-narrowed tokens.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

VALID_WIZ_STATUS = ("OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED")

# Wiz emits severity as an upper-case enum (CRITICAL / HIGH / MEDIUM /
# LOW / INFORMATIONAL); accept a few synonyms surfaced by adjacent
# products and downstream pipelines that re-emit Wiz findings.
WIZ_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
}

# Wiz issue status enum:
#   OPEN / IN_PROGRESS / REOPENED -> open
#   RESOLVED / FIXED / CLOSED -> closed
#   REJECTED / IGNORED / WONT_FIX / RISK_ACCEPTED -> risk-accepted
WIZ_STATUS_TO_FARADAY = {
    "open": "open",
    "in_progress": "open",
    "inprogress": "open",
    "new": "open",
    "reopened": "open",
    "active": "open",
    "resolved": "closed",
    "fixed": "closed",
    "closed": "closed",
    "remediated": "closed",
    "patched": "closed",
    "rejected": "risk-accepted",
    "ignored": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "acceptedrisk": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
}


ISSUES_TABLE_QUERY = """
query IssuesTable(
  $filterBy: IssueFilters
  $first: Int
  $after: String
  $orderBy: IssueOrder
) {
  issues: issuesV2(
    filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy
  ) {
    nodes {
      id
      sourceRule {
        ... on Control {
          id
          name
          description
          resolutionRecommendation
        }
        ... on CloudConfigurationRule {
          id
          name
          description
          remediationInstructions
        }
      }
      createdAt
      updatedAt
      dueAt
      type
      resolvedAt
      statusChangedAt
      projects {
        id
        name
        slug
      }
      status
      severity
      entitySnapshot {
        id
        type
        nativeType
        name
        status
        cloudPlatform
        cloudProviderURL
        providerId
        region
        resourceGroupExternalId
        subscriptionExternalId
        subscriptionName
        externalId
      }
      serviceTickets {
        externalId
        name
        url
      }
      notes {
        createdAt
        text
      }
    }
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
""".strip()


def log(msg):
    print(f"{datetime.utcnow()} - Wiz: {msg}", file=sys.stderr, flush=True)


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
    if score > 10:
        return "info"
    return "critical"


def severity_from_wiz(value, cvss=None):
    """Map a Wiz severity to a Faraday bucket.

    Accepts Wiz's string enum (CRITICAL / HIGH / MEDIUM / LOW /
    INFORMATIONAL) and falls back to CVSS bucketing on ``cvss`` when
    the primary value is missing or unrecognised. Numeric inputs are
    interpreted as CVSS base scores so vendor-shaped reports that
    surface a bare score still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in WIZ_STRING_SEVERITY:
            return WIZ_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_wiz(issue):
    """Derive Faraday status from a Wiz issue payload.

    Wiz issues carry a top-level ``status`` enum (OPEN / IN_PROGRESS /
    RESOLVED / REJECTED). We tolerate dict-wrapped and synonym shapes
    so downstream re-emissions through generic CNAPP pipelines still
    map cleanly.
    """
    if not isinstance(issue, dict):
        return "open"
    for key in ("status", "state", "issueStatus", "issue_status"):
        raw = issue.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value")
        if isinstance(raw, str):
            mapped = WIZ_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in WIZ_STATUS_TO_FARADAY:
                return WIZ_STATUS_TO_FARADAY[compact]
    return "open"


def normalize_base_url(host):
    if not host:
        return ""
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def validate_status(value):
    """Validate WIZ_STATUS — Wiz expects OPEN | IN_PROGRESS | RESOLVED.

    None / blank -> None (no filter). Garbage is rejected with a log
    line so the operator can spot typos rather than silently scanning
    the whole tenant.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (list, tuple, set)):
        text = ",".join(str(v) for v in value)
    else:
        text = str(value)
    raw = [t.strip().upper().replace("-", "_").replace(" ", "_") for t in text.split(",") if t.strip()]
    valid = []
    for token in raw:
        if token in VALID_WIZ_STATUS:
            if token not in valid:
                valid.append(token)
        elif token == "REOPENED":
            if "OPEN" not in valid:
                valid.append("OPEN")
        else:
            log(f"WIZ_STATUS token '{token}' not recognised; ignored")
    return valid or None


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"WIZ_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


WIZ_API_SEVERITY = {
    "info": "INFORMATIONAL",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


def severities_at_or_above(min_severity):
    """Return the Wiz severity tokens at or above ``min_severity``.

    Used to build the GraphQL ``filterBy.severity`` field so the tenant
    only paginates results that survive the client-side floor. ``info``
    yields every bucket (no filter applied).
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = WIZ_API_SEVERITY.get(bucket)
            if api and api not in out:
                out.append(api)
    return out


def fetch_access_token(auth_host, client_id, client_secret, audience):
    """Exchange Wiz service-account credentials for a short-lived bearer.

    Returns the access_token string. Wiz's OAuth endpoint is
    ``POST {auth_host}/oauth/token`` with form-encoded body
    ``grant_type=client_credentials&client_id=...&client_secret=...&audience=...``
    -> ``{"access_token": "...", "expires_in": N, "token_type": "Bearer"}``.
    """
    if not auth_host or not client_id or not client_secret:
        return None
    base = normalize_base_url(auth_host)
    url = f"{base}/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience or "wiz-api",
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        resp = requests.post(url, data=payload, headers=headers, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("OAuth token request rejected (401). Check WIZ_CLIENT_ID / WIZ_CLIENT_SECRET.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"OAuth token request failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log("OAuth response was not JSON")
        return None
    token = body.get("access_token") or body.get("accessToken") or body.get("token")
    if not token:
        log("OAuth response missing access_token")
        return None
    return token


def graphql(base_url, headers, query, variables):
    """POST a GraphQL query to {base_url}/graphql and return the data envelope."""
    url = f"{base_url}/graphql"
    payload = {"query": query, "variables": variables or {}}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"POST /graphql failed: {exc}")
        return None
    if resp.status_code == 401:
        log("GraphQL request rejected (401). Bearer expired or invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log("GraphQL request rejected (403). Check service-account scopes.")
        return None
    if resp.status_code >= 400:
        log(f"GraphQL request failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log("GraphQL response was not JSON")
        return None
    if not isinstance(body, dict):
        return None
    errors = body.get("errors")
    if errors:
        first = errors[0] if isinstance(errors, list) and errors else errors
        msg = first.get("message") if isinstance(first, dict) else str(first)
        log(f"GraphQL errors: {msg}")
    data = body.get("data")
    if isinstance(data, dict):
        return data
    return None


def build_filter(project_id, statuses, severities):
    """Build the Wiz IssueFilters object."""
    flt = {}
    if project_id:
        flt["project"] = [project_id] if isinstance(project_id, str) else list(project_id)
    if statuses:
        flt["status"] = list(statuses)
    if severities and len(severities) < len(WIZ_API_SEVERITY):
        flt["severity"] = list(severities)
    return flt


def fetch_issues(base_url, headers, project_id, statuses, severities):
    """Paginate through the IssuesTable query for the supplied filters."""
    results = []
    cursor = None
    filter_by = build_filter(project_id, statuses, severities)
    for _ in range(MAX_PAGES):
        variables = {
            "first": PAGE_SIZE,
            "filterBy": filter_by,
            "orderBy": {"direction": "DESC", "field": "SEVERITY"},
        }
        if cursor:
            variables["after"] = cursor
        data = graphql(base_url, headers, ISSUES_TABLE_QUERY, variables)
        if not isinstance(data, dict):
            break
        issues = data.get("issues") or data.get("issuesV2")
        if not isinstance(issues, dict):
            break
        nodes = issues.get("nodes")
        if isinstance(nodes, list):
            results.extend(n for n in nodes if isinstance(n, dict))
        page_info = issues.get("pageInfo") or {}
        if not isinstance(page_info, dict) or not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        if not cursor:
            break
    return results


def cvss_score(issue):
    """Pull a numeric CVSS score out of a Wiz issue payload.

    Wiz doesn't carry CVSS on the issue directly, but some downstream
    re-emissions inject it (and the GraphQL schema sometimes surfaces a
    ``cvss`` block on cloudConfigurationRule). Walk the usual suspects.
    """
    if not isinstance(issue, dict):
        return None
    for key in ("cvssScore", "cvss_score", "score", "baseScore", "base_score"):
        value = issue.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = issue.get(nested_key)
        if isinstance(nested, dict):
            for k in ("score", "baseScore", "base_score", "overallScore", "overall_score"):
                score = nested.get(k)
                if score is None or isinstance(score, (dict, list, bool)):
                    continue
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
    return None


def cvss_vector(issue):
    if not isinstance(issue, dict):
        return ""
    for key in ("cvssVector", "cvss_vector", "vector"):
        value = issue.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = issue.get(nested_key)
        if isinstance(nested, dict):
            for k in ("vector", "vectorString", "vector_string"):
                v = nested.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def collect_refs(issue, rule):
    """Walk a Wiz issue + sourceRule for CWE / advisory / URL refs."""
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

    for source in (issue, rule):
        if not isinstance(source, dict):
            continue
        cwe_raw = source.get("cweId") or source.get("cwe_id") or source.get("cwe")
        if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
            add(f"CWE-{int(cwe_raw)}")
        elif isinstance(cwe_raw, str) and cwe_raw.strip():
            s = cwe_raw.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("cwes", "cweIds", "cwe_ids"):
            items = source.get(key)
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

        # Wiz puts the rule id in sourceRule.id - surface as a pivot
        rule_id = source.get("id")
        if isinstance(rule_id, str) and rule_id.strip() and source is rule:
            add(f"Wiz-Rule: {rule_id.strip()}")

        for key in ("references", "links", "externalReferences", "external_references"):
            entry = source.get(key)
            if isinstance(entry, list):
                for it in entry:
                    if isinstance(it, dict):
                        href = it.get("href") or it.get("url") or it.get("name") or it.get("value")
                        if href:
                            add(href)
                    elif it:
                        add(str(it))
            elif isinstance(entry, str) and entry.strip():
                add(entry.strip())

    # entitySnapshot.cloudProviderURL is the most actionable pivot
    snap = issue.get("entitySnapshot") if isinstance(issue, dict) else None
    if isinstance(snap, dict):
        url = snap.get("cloudProviderURL") or snap.get("cloud_provider_url")
        if isinstance(url, str) and url.strip():
            add(url.strip())

    # serviceTickets are first-class Wiz refs
    tickets = issue.get("serviceTickets") if isinstance(issue, dict) else None
    if isinstance(tickets, list):
        for ticket in tickets:
            if not isinstance(ticket, dict):
                continue
            url = ticket.get("url")
            if isinstance(url, str) and url.strip():
                add(url.strip())
            ext = ticket.get("externalId") or ticket.get("external_id")
            if isinstance(ext, str) and ext.strip():
                add(f"Ticket: {ext.strip()}")

    return refs


def collect_cves(issue, rule):
    """Pull CVE-* ids out of a Wiz issue + sourceRule payload."""
    found = []
    seen = set()

    def add_token(text):
        """Add a single CVE-shaped token; rejects descriptive strings."""
        if not text:
            return
        s = str(text).strip().upper()
        if not CVE_RE.fullmatch(s):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    def scan(text):
        """Extract every CVE-shaped token from a free-form string."""
        if not isinstance(text, str):
            return
        for match in CVE_RE.findall(text):
            add_token(match)

    def add(text):
        """Best-effort add: exact-id match first, then free-form scan."""
        if not isinstance(text, str):
            if text:
                add_token(text)
            return
        if CVE_RE.fullmatch(text.strip().upper()):
            add_token(text)
        else:
            scan(text)

    for source in (issue, rule):
        if not isinstance(source, dict):
            continue
        for key in ("name", "id", "title"):
            v = source.get(key)
            if isinstance(v, str):
                add(v)
        for key in ("cve", "cveId", "cve_id"):
            v = source.get(key)
            if isinstance(v, str) and v.strip():
                add_token(v)
        for key in ("cves", "cveIds", "cve_ids", "aliases"):
            v = source.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add_token(entry)
                    elif isinstance(entry, dict):
                        add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
    return found


def entity_label(snap):
    """Build a friendly label for the affected cloud resource."""
    if not isinstance(snap, dict):
        return ""
    name = snap.get("name") or snap.get("Name") or ""
    nat = snap.get("nativeType") or snap.get("native_type") or snap.get("type") or ""
    region = snap.get("region") or ""
    if name and nat:
        label = f"{nat} {name}"
    elif name:
        label = str(name)
    elif nat:
        label = str(nat)
    else:
        label = str(snap.get("externalId") or snap.get("providerId") or snap.get("id") or "")
    if region:
        label = f"{label} [{region}]" if label else f"[{region}]"
    return label.strip()


def rule_label(rule):
    if not isinstance(rule, dict):
        return ""
    return str(rule.get("name") or rule.get("id") or "").strip()


def build_vulnerability(issue):
    """Build a Faraday vulnerability dict from one Wiz issue."""
    if not isinstance(issue, dict):
        return None
    rule = issue.get("sourceRule") if isinstance(issue.get("sourceRule"), dict) else {}
    snap = issue.get("entitySnapshot") if isinstance(issue.get("entitySnapshot"), dict) else {}

    score = cvss_score(issue) or cvss_score(rule) or None
    severity = severity_from_wiz(issue.get("severity"), score)
    status = status_from_wiz(issue)

    rname = rule_label(rule)
    elabel = entity_label(snap)
    base_title = rname or str(issue.get("type") or issue.get("id") or "Wiz finding")
    raw_name = f"{base_title} on {elabel}" if elabel else base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = rule.get("description") or issue.get("description")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if rname:
        desc_parts.append(f"rule: {rname}")
    rule_id = rule.get("id") if isinstance(rule, dict) else None
    if rule_id:
        desc_parts.append(f"rule_id: {rule_id}")
    if elabel:
        desc_parts.append(f"resource: {elabel}")
    if isinstance(snap, dict):
        for label, key in (
            ("native_type", "nativeType"),
            ("cloud_platform", "cloudPlatform"),
            ("provider_id", "providerId"),
            ("region", "region"),
            ("subscription", "subscriptionName"),
            ("subscription_id", "subscriptionExternalId"),
            ("resource_group", "resourceGroupExternalId"),
            ("external_id", "externalId"),
        ):
            val = snap.get(key)
            if val:
                desc_parts.append(f"{label}: {val}")
        snap_status = snap.get("status")
        if snap_status:
            desc_parts.append(f"resource_status: {snap_status}")
    issue_status = issue.get("status")
    if issue_status:
        desc_parts.append(f"status: {issue_status}")
    issue_sev = issue.get("severity")
    if issue_sev:
        desc_parts.append(f"severity: {issue_sev}")
    for label, key in (
        ("created", "createdAt"),
        ("updated", "updatedAt"),
        ("due", "dueAt"),
        ("resolved", "resolvedAt"),
        ("status_changed", "statusChangedAt"),
    ):
        val = issue.get(key)
        if val:
            desc_parts.append(f"{label}: {val}")

    projects = issue.get("projects")
    if isinstance(projects, list):
        names = []
        for p in projects:
            if isinstance(p, dict):
                pn = p.get("name") or p.get("slug") or p.get("id")
                if pn:
                    names.append(str(pn))
        if names:
            desc_parts.append(f"projects: {', '.join(names)}")

    notes = issue.get("notes")
    if isinstance(notes, list) and notes:
        note_lines = []
        for n in notes:
            if not isinstance(n, dict):
                continue
            text = n.get("text")
            created = n.get("createdAt")
            if text and created:
                note_lines.append(f"  [{created}] {text}")
            elif text:
                note_lines.append(f"  {text}")
        if note_lines:
            desc_parts.append("notes:")
            desc_parts.extend(note_lines)

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(issue) or cvss_vector(rule)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(issue, rule)
    refs = collect_refs(issue, rule)

    resolution = (
        rule.get("resolutionRecommendation")
        or rule.get("remediationInstructions")
        or rule.get("remediation")
        or rule.get("recommendation")
        or rule.get("solution")
        or issue.get("resolutionRecommendation")
        or issue.get("remediation")
        or ""
    )

    external_id = str(issue.get("id") or issue.get("externalId") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Wiz finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["wiz", "cnapp", "cloud-security"],
    }


def build_host(project_id, project_meta, issues, vulns):
    project_name = ""
    if isinstance(project_meta, dict):
        project_name = project_meta.get("name") or project_meta.get("slug") or ""
    hostname = ""
    if project_name and project_id:
        hostname = f"{project_name}@{project_id}"
    else:
        hostname = project_name or project_id or ""
    desc_parts = []
    if project_id:
        desc_parts.append(f"project_id={project_id}")
    if project_name:
        desc_parts.append(f"project={project_name}")
    if isinstance(project_meta, dict):
        slug = project_meta.get("slug")
        if slug and slug != project_name:
            desc_parts.append(f"slug={slug}")
    if issues:
        desc_parts.append(f"issues={len(issues)}")
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
    host = env("WIZ_HOST", required=True)
    auth_host = env("WIZ_AUTH_HOST", required=True)
    client_id = env("WIZ_CLIENT_ID", required=True)
    client_secret = env("WIZ_CLIENT_SECRET", required=True)
    audience = env("WIZ_AUDIENCE", default="wiz-api")
    project_id = env("EXECUTOR_CONFIG_WIZ_PROJECT_ID", required=True)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_WIZ_MIN_SEVERITY"))
    statuses = validate_status(env("EXECUTOR_CONFIG_WIZ_STATUS"))
    floor = SEVERITY_ORDER[min_severity]
    severities = severities_at_or_above(min_severity)

    base_url = normalize_base_url(host)
    if not base_url:
        log("WIZ_HOST is required")
        sys.exit(1)

    token = fetch_access_token(auth_host, client_id, client_secret, audience)
    if not token:
        log("Failed to obtain Wiz access token; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    issues = fetch_issues(base_url, headers, project_id, statuses, severities)
    log(
        f"Processing {len(issues)} Wiz issues "
        f"(project={project_id}, status={statuses or 'ALL'}, min_severity={min_severity})"
    )

    project_meta = {}
    for issue in issues:
        projects = issue.get("projects")
        if isinstance(projects, list):
            for p in projects:
                if isinstance(p, dict) and p.get("id") == project_id:
                    project_meta = p
                    break
        if project_meta:
            break

    vulns = []
    for issue in issues:
        built = build_vulnerability(issue)
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)

    hosts = [build_host(project_id, project_meta, issues, vulns)] if vulns else []

    params = f"project_id={project_id},min_severity={min_severity}"
    if statuses:
        params = f"{params},status={'|'.join(statuses)}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "wiz",
            "command": "wiz",
            "params": params,
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
