#!/usr/bin/env python
"""Rapid7 InsightCloudSec (formerly DivvyCloud) CNAPP / CSPM REST importer.

Pulls insight evaluation results from an InsightCloudSec tenant via the
canonical ``POST /v2/public/insights/list`` (insight catalogue) +
``POST /v2/public/insight/{id}/evaluation/run`` (per-insight matching
resources) two-step pattern and emits Faraday bulk-create JSON to
stdout. Each cloud account becomes one Faraday host (``ip`` = synthetic
``0.0.0.0`` because CSPM findings live on cloud accounts / resources,
not on IPs); per-account insight matches are attached as Faraday
vulnerabilities — one per (insight_id, resource_id) pair with engine
prefix ``[CNAPP]``.

Endpoints used:
  POST {ICS_HOST}/v2/public/insights/list
      -> insight catalogue. Paginated via ``limit`` + ``offset`` cursor.
      Used when ``ICS_INSIGHT_ID`` is not set (importer iterates every
      visible insight). Each entry surfaces ``insight_id`` /
      ``name`` / ``description`` / ``severity`` / ``resource_types`` /
      ``tags``.
  POST {ICS_HOST}/v2/public/insight/{insight_id}/evaluation/run
      -> per-insight evaluation. Body carries ``{"scopes":
      [<resource_group_ids>], "limit": N, "offset": N}``; returns the
      matching cloud resources for that insight, paginated via
      ``limit`` + ``offset`` cursor. Each resource is one Faraday
      vulnerability.

Auth: InsightCloudSec uses a single long-lived API key minted from a
service-account user (Administration -> API Keys). The key is passed
to every call via ``Api-Key: <ICS_API_KEY>`` header (Rapid7's native
scheme). ``auth_header`` short-circuits a pre-built ``Bearer <token>``
(or ``Api-Key <token>``) value so federated / JWT-style credentials
still work. ``ICS_HOST`` is the tenant URL (e.g.
``https://my-tenant.divvycloud.com`` for self-hosted DivvyCloud
classic, ``https://insightcloudsec.rapid7.com`` for the SaaS region
endpoint, or a regional ``https://us.insight.rapid7.com`` URL).
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
PAGE_SIZE = 200
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# InsightCloudSec severity is a numeric 1-3 scale on insights (1 = low,
# 2 = medium, 3 = high) but downstream callers also re-emit Faraday-style
# string buckets, so we accept both. Critical is surfaced when CVSS / score
# bucketing fallback puts us there.
ICS_STRING_SEVERITY = {
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

# Numeric InsightCloudSec severity codes (1=low, 2=medium, 3=high)
# Anything outside that range falls through to CVSS bucketing.
ICS_NUMERIC_SEVERITY = {
    1: "low",
    2: "medium",
    3: "high",
}

# InsightCloudSec resource lifecycle / finding status synonyms.
#   open / new / active / reopened / in_progress -> open
#   closed / fixed / resolved / mitigated / remediated / patched -> closed
#   suppressed / muted / ignored / dismissed / wont_fix / risk_accepted /
#     excluded / false_positive / expired -> risk-accepted
ICS_STATUS_TO_FARADAY = {
    "open": "open",
    "new": "open",
    "active": "open",
    "reopened": "open",
    "re_opened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "closed": "closed",
    "fixed": "closed",
    "resolved": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "dismissed": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "excluded": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "expired": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - Rapid7 InsightCloudSec: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    if not host:
        return ""
    text = str(host).strip()
    if not text:
        return ""
    base = text if text.startswith(("http://", "https://")) else f"https://{text}"
    return base.rstrip("/")


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"ICS_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``.

    InsightCloudSec does not have a wire-level severity filter on
    ``/evaluation/run`` (severity is a property of the insight, not the
    matching resource), so this is only used client-side after
    bucketing. ``info`` returns the full set; everything else trims the
    floor.
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [b for b, order in SEVERITY_ORDER.items() if order >= floor]


def auth_header(api_key):
    """Build the ``Api-Key`` header for InsightCloudSec.

    Empty / None -> None (omit header so /login-style debugging surfaces
    a clear 401 instead of silently sending an empty key). Pre-built
    ``Bearer <token>`` / ``Api-Key <token>`` values short-circuit so
    federated tokens still work; scheme is normalised to canonical case.
    """
    if api_key is None:
        return None
    text = str(api_key).strip()
    if not text:
        return None
    lower = text.lower()
    if lower.startswith("bearer "):
        return "Bearer " + text.split(None, 1)[1].strip()
    if lower.startswith("api-key ") or lower.startswith("apikey ") or lower.startswith("api_key "):
        return "Api-Key " + text.split(None, 1)[1].strip()
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


def severity_from_ics(value, cvss=None):
    """Map an InsightCloudSec severity to a Faraday bucket.

    Accepts the native numeric 1/2/3 scale (1=low, 2=medium, 3=high),
    the Faraday-style string enum (critical / high / medium / low /
    informational), and CVSS base-score fallback (when only a numeric
    score is given). Falls back to ``cvss`` when the primary value is
    missing or unrecognised.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, int):
            mapped = ICS_NUMERIC_SEVERITY.get(value)
            if mapped:
                return mapped
            return severity_from_cvss(value)
        if isinstance(value, float):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in ICS_STRING_SEVERITY:
            return ICS_STRING_SEVERITY[text]
        try:
            f = float(text)
        except ValueError:
            f = None
        if f is not None:
            if f == int(f) and int(f) in ICS_NUMERIC_SEVERITY:
                return ICS_NUMERIC_SEVERITY[int(f)]
            return severity_from_cvss(f)
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_ics(resource):
    """Derive Faraday status from an InsightCloudSec evaluation match.

    InsightCloudSec evaluation responses surface the resource state via
    ``status`` / ``state`` (and a handful of alt keys); a truthy
    ``suppressed`` / ``exempted`` flag forces risk-accepted (Rapid7's
    exemption lifecycle is the standard way to silence an insight
    finding without resolving it).
    """
    if not isinstance(resource, dict):
        return "open"
    suppressed = resource.get("suppressed")
    if suppressed in (True, "true", "True", "1", 1, "yes"):
        return "risk-accepted"
    exempted = resource.get("exempted") or resource.get("exemption")
    if exempted in (True, "true", "True", "1", 1, "yes"):
        return "risk-accepted"
    for key in (
        "status",
        "state",
        "resource_status",
        "resourceStatus",
        "insight_status",
        "insightStatus",
        "finding_status",
        "findingStatus",
    ):
        raw = resource.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
        if isinstance(raw, str):
            mapped = ICS_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in ICS_STATUS_TO_FARADAY:
                return ICS_STATUS_TO_FARADAY[compact]
    return "open"


def extract_items(payload):
    """Pull the resources list out of an InsightCloudSec response envelope.

    InsightCloudSec's evaluation/run shape is
    ``{"resources": [...], "matching_count": N, "non_matching_count": N}``;
    the insights/list shape is ``{"insights": [...], "total_count": N}``;
    tolerate bare lists and a handful of alt keys.
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in (
        "resources",
        "insights",
        "data",
        "results",
        "items",
        "matching_resources",
        "matchingResources",
    ):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def extract_total(payload):
    """Pull the total-item count out of an InsightCloudSec response envelope."""
    if not isinstance(payload, dict):
        return None
    for key in (
        "total_count",
        "totalCount",
        "matching_count",
        "matchingCount",
        "total",
        "totalItems",
        "total_items",
    ):
        v = payload.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return int(v)
    return None


def request(method, url, headers, params=None, json_body=None):
    """Wrap requests with shared error handling."""
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=TIMEOUT,
            verify=False,
        )
    except requests.RequestException as exc:
        log(f"{method} {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log(f"{method} {url} rejected (401). Check ICS_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"{method} {url} rejected (403). API key lacks required scopes.")
        return None
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        log(f"{method} {url} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"{method} {url} response was not JSON")
        return None


def fetch_insights(base_url, headers):
    """Paginate through /v2/public/insights/list and return every insight."""
    insights = []
    seen = set()
    offset = 0
    for _ in range(MAX_PAGES):
        body = {"limit": PAGE_SIZE, "offset": offset}
        payload = request(
            "POST",
            f"{base_url}/v2/public/insights/list",
            headers,
            json_body=body,
        )
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for insight in chunk:
            iid = insight.get("insight_id") or insight.get("insightId") or insight.get("id") or insight.get("uuid")
            if iid in (None, ""):
                continue
            key = str(iid)
            if key in seen:
                continue
            seen.add(key)
            insights.append(insight)
            added += 1
        if added == 0:
            break
        offset += len(chunk)
        total = extract_total(payload)
        if isinstance(total, int) and offset >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
    return insights


def fetch_insight_matches(base_url, headers, insight_id, scopes):
    """Run an insight evaluation and return every matching resource.

    Posts to ``/v2/public/insight/{insight_id}/evaluation/run`` with
    ``{"scopes": [<resource_group_ids>], "limit": N, "offset": N}``;
    paginates via ``limit`` + ``offset`` cursor; honours
    ``matching_count`` / ``total_count`` for early-stop.
    """
    resources = []
    seen = set()
    offset = 0
    for _ in range(MAX_PAGES):
        body = {"limit": PAGE_SIZE, "offset": offset}
        if scopes:
            body["scopes"] = list(scopes)
        payload = request(
            "POST",
            f"{base_url}/v2/public/insight/{insight_id}/evaluation/run",
            headers,
            json_body=body,
        )
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for resource in chunk:
            rid = (
                resource.get("resource_id")
                or resource.get("resourceId")
                or resource.get("id")
                or resource.get("uuid")
                or resource.get("rid")
                or resource.get("arn")
            )
            key = str(rid) if rid not in (None, "") else None
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            resources.append(resource)
            added += 1
        if added == 0:
            break
        offset += len(chunk)
        total = extract_total(payload)
        if isinstance(total, int) and offset >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
    return resources


def cvss_score(resource):
    """Pull a numeric CVSS / severity score out of an InsightCloudSec payload.

    InsightCloudSec evaluation matches don't typically carry CVSS (CSPM
    is config-drift not a CVE scanner) but adjacent re-emissions do;
    walk the usual suspects.
    """
    if not isinstance(resource, dict):
        return None
    for key in (
        "cvss_score",
        "cvssScore",
        "score",
        "base_score",
        "baseScore",
        "severity_score",
        "severityScore",
        "risk_score",
        "riskScore",
    ):
        value = resource.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = resource.get(nested_key)
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


def cvss_vector(resource):
    if not isinstance(resource, dict):
        return ""
    for key in ("cvss_vector", "cvssVector", "vector", "vector_string", "vectorString"):
        value = resource.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = resource.get(nested_key)
        if isinstance(nested, dict):
            for k in ("vector", "vectorString", "vector_string"):
                v = nested.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def collect_cves(resource, insight=None):
    """Pull CVE-* ids out of an InsightCloudSec evaluation match.

    InsightCloudSec is CSPM (config drift), not a CVE scanner, but the
    harvest is defensive so tenants that reference CVEs in insight
    descriptions or resource tags still surface them.
    """
    found = []
    seen = set()

    def add_token(text):
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
        if not isinstance(text, str):
            return
        for match in CVE_RE.findall(text):
            add_token(match)

    def add(text):
        if not isinstance(text, str):
            if text:
                add_token(text)
            return
        if CVE_RE.fullmatch(text.strip().upper()):
            add_token(text)
        else:
            scan(text)

    sources = []
    if isinstance(resource, dict):
        sources.append(resource)
    if isinstance(insight, dict):
        sources.append(insight)

    for source in sources:
        for key in (
            "id",
            "name",
            "title",
            "description",
            "summary",
            "resource_name",
            "resourceName",
            "insight_name",
            "insightName",
        ):
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


def collect_refs(resource, insight=None):
    """Walk an InsightCloudSec payload for CWE / advisory / URL refs."""
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

    def harvest_cwe(source):
        cwe_raw = source.get("cwe_id") or source.get("cweId") or source.get("cwe")
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

    def harvest_compliance(source):
        # Compliance pivots harvested from compliance / standards / frameworks tag arrays
        # (e.g. {"name": "CIS", "section": "2.1"})
        for key in ("compliance", "compliances", "standards", "frameworks"):
            items = source.get(key)
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, dict):
                        name = it.get("name") or it.get("standard") or it.get("framework")
                        section = it.get("section") or it.get("sectionId") or it.get("section_id") or it.get("id")
                        if name and section:
                            add(f"Compliance: {name} {section}")
                        elif name:
                            add(f"Compliance: {name}")
                    elif isinstance(it, str) and it.strip():
                        add(f"Compliance: {it.strip()}")

    def harvest_urls(source):
        for key in (
            "url",
            "console_url",
            "consoleUrl",
            "cloud_provider_url",
            "cloudProviderUrl",
            "documentation_url",
            "documentationUrl",
            "insight_url",
            "insightUrl",
        ):
            url = source.get(key)
            if isinstance(url, str) and url.strip():
                add(url.strip())
        for key in ("references", "links", "external_references", "externalReferences"):
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

    sources = []
    if isinstance(resource, dict):
        sources.append(resource)
    if isinstance(insight, dict):
        sources.append(insight)

    for source in sources:
        harvest_cwe(source)

    # Pivot labels: insight id + resource id surface as stable join keys
    if isinstance(insight, dict):
        insight_id = insight.get("insight_id") or insight.get("insightId") or insight.get("id") or insight.get("uuid")
        if insight_id not in (None, ""):
            add(f"ICS-Insight: {insight_id}")
    elif isinstance(resource, dict):
        insight_id = resource.get("insight_id") or resource.get("insightId")
        if insight_id not in (None, ""):
            add(f"ICS-Insight: {insight_id}")

    if isinstance(resource, dict):
        rid = resource.get("resource_id") or resource.get("resourceId") or resource.get("rid") or resource.get("arn")
        if isinstance(rid, str) and rid.strip():
            add(f"ICS-Resource: {rid.strip()}")
        elif isinstance(rid, (int, float)) and not isinstance(rid, bool):
            add(f"ICS-Resource: {rid}")

    for source in sources:
        harvest_compliance(source)
        harvest_urls(source)

    return refs


def resource_label(resource):
    """Build a friendly label for the affected cloud resource."""
    if not isinstance(resource, dict):
        return ""
    name = resource.get("resource_name") or resource.get("resourceName") or resource.get("name") or ""
    rtype = resource.get("resource_type") or resource.get("resourceType") or resource.get("type") or ""
    region = resource.get("region") or resource.get("cloud_region") or resource.get("cloudRegion") or ""
    if not name:
        name = (
            resource.get("resource_id")
            or resource.get("resourceId")
            or resource.get("rid")
            or resource.get("arn")
            or ""
        )
    if name and rtype:
        label = f"{rtype} {name}"
    elif name:
        label = str(name)
    elif rtype:
        label = str(rtype)
    else:
        label = ""
    if region:
        label = f"{label} [{region}]" if label else f"[{region}]"
    return label.strip()


def insight_label(insight, resource=None):
    """Build a friendly label for the insight (the policy / rule violated)."""
    for source in (insight, resource):
        if not isinstance(source, dict):
            continue
        for key in (
            "insight_name",
            "insightName",
            "name",
            "title",
            "insight_title",
        ):
            v = source.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    for source in (insight, resource):
        if not isinstance(source, dict):
            continue
        iid = source.get("insight_id") or source.get("insightId") or source.get("id")
        if iid not in (None, ""):
            return str(iid).strip()
    return ""


def build_vulnerability(resource, insight=None):
    """Build a Faraday vulnerability dict from one InsightCloudSec match."""
    if not isinstance(resource, dict):
        return None

    score = cvss_score(resource)
    if score is None and isinstance(insight, dict):
        score = cvss_score(insight)
    severity_raw = (
        resource.get("severity")
        or resource.get("insight_severity")
        or (insight.get("severity") if isinstance(insight, dict) else None)
    )
    severity = severity_from_ics(severity_raw, score)
    status = status_from_ics(resource)

    ilabel = insight_label(insight, resource)
    rlabel = resource_label(resource)
    base_title = ilabel or str(
        resource.get("title") or resource.get("name") or resource.get("id") or "InsightCloudSec finding"
    )
    raw_name = f"{base_title} on {rlabel}" if rlabel else base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = (
        resource.get("description")
        or resource.get("details")
        or (insight.get("description") if isinstance(insight, dict) else None)
    )
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if ilabel:
        desc_parts.append(f"insight: {ilabel}")
    iid = (
        resource.get("insight_id")
        or resource.get("insightId")
        or (insight.get("insight_id") if isinstance(insight, dict) else None)
        or (insight.get("insightId") if isinstance(insight, dict) else None)
        or (insight.get("id") if isinstance(insight, dict) else None)
    )
    if iid not in (None, ""):
        desc_parts.append(f"insight_id: {iid}")
    if rlabel:
        desc_parts.append(f"resource: {rlabel}")
    for label, keys in (
        ("resource_type", ("resource_type", "resourceType", "type")),
        ("resource_id", ("resource_id", "resourceId", "rid", "arn")),
        ("cloud_provider", ("cloud", "cloud_provider", "cloudProvider")),
        ("cloud_account_id", ("account_id", "accountId", "cloud_account_id", "cloudAccountId")),
        ("cloud_account_name", ("account_name", "accountName", "cloud_account_name", "cloudAccountName")),
        ("region", ("region", "cloud_region", "cloudRegion")),
        ("resource_group", ("resource_group", "resourceGroup", "resource_group_id", "resourceGroupId")),
        ("organization_service_id", ("organization_service_id", "organizationServiceId")),
    ):
        for k in keys:
            v = resource.get(k)
            if v not in (None, ""):
                desc_parts.append(f"{label}: {v}")
                break

    status_raw = resource.get("status") or resource.get("state")
    if status_raw:
        desc_parts.append(f"status: {status_raw}")
    if severity_raw not in (None, ""):
        desc_parts.append(f"severity: {severity_raw}")
    if resource.get("suppressed"):
        desc_parts.append("suppressed: true")

    for label, keys in (
        ("created", ("created_at", "createdAt", "creation_time", "creationTime", "create_time")),
        ("updated", ("updated_at", "updatedAt", "modified_time", "modifiedTime")),
        ("first_seen", ("first_seen", "firstSeen", "first_seen_timestamp")),
        (
            "last_seen",
            ("last_seen", "lastSeen", "last_seen_timestamp", "scan_time", "scanTime", "evaluated_at", "evaluatedAt"),
        ),
        ("closed", ("closed_at", "closedAt", "remediated_at", "remediatedAt")),
        ("exempted_at", ("exempted_at", "exemptedAt", "exemption_expires_at", "exemptionExpiresAt")),
    ):
        for k in keys:
            v = resource.get(k)
            if v:
                desc_parts.append(f"{label}: {v}")
                break

    tags_raw = resource.get("tags") or resource.get("resource_tags")
    if isinstance(tags_raw, list):
        flat = []
        for t in tags_raw:
            if isinstance(t, dict):
                tv = t.get("name") or t.get("value") or t.get("id")
                if tv:
                    flat.append(str(tv))
            elif t:
                flat.append(str(t))
        if flat:
            desc_parts.append(f"tags: {', '.join(flat)}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(resource) or (cvss_vector(insight) if isinstance(insight, dict) else "")
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(resource, insight)
    refs = collect_refs(resource, insight)

    resolution = (
        resource.get("remediation")
        or resource.get("recommendation")
        or resource.get("resolution")
        or resource.get("solution")
        or resource.get("fix")
        or (insight.get("remediation_steps") if isinstance(insight, dict) else None)
        or (insight.get("remediationSteps") if isinstance(insight, dict) else None)
        or (insight.get("remediation") if isinstance(insight, dict) else None)
        or (insight.get("recommendation") if isinstance(insight, dict) else None)
        or (insight.get("resolution") if isinstance(insight, dict) else None)
        or ""
    )
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    rid_for_ext = (
        resource.get("resource_id")
        or resource.get("resourceId")
        or resource.get("rid")
        or resource.get("arn")
        or resource.get("id")
        or resource.get("uuid")
    )
    iid_for_ext = (
        resource.get("insight_id")
        or resource.get("insightId")
        or (insight.get("insight_id") if isinstance(insight, dict) else None)
        or (insight.get("insightId") if isinstance(insight, dict) else None)
        or (insight.get("id") if isinstance(insight, dict) else None)
    )
    if iid_for_ext and rid_for_ext:
        external_id = f"{iid_for_ext}@{rid_for_ext}"
    elif iid_for_ext:
        external_id = str(iid_for_ext)
    elif rid_for_ext:
        external_id = str(rid_for_ext)
    else:
        external_id = cves[0] if cves else ""

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"InsightCloudSec match {external_id}",
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
        "tags": ["rapid7_insightcloudsec", "cnapp", "cloud-security"],
    }


def host_bucket_key(resource):
    """Return the cloud-account bucket key for one evaluation match."""
    if not isinstance(resource, dict):
        return "__unknown__"
    for key in (
        "account_id",
        "accountId",
        "cloud_account_id",
        "cloudAccountId",
        "organization_service_id",
        "organizationServiceId",
        "subscription_id",
        "subscriptionId",
        "project_id",
        "projectId",
    ):
        v = resource.get(key)
        if v not in (None, ""):
            return str(v)
    return "__unknown__"


def build_host(account_id, meta, resources, vulns):
    """Build a Faraday host shell from an InsightCloudSec cloud-account bucket."""
    name = ""
    vendor = ""
    region = ""
    if isinstance(meta, dict):
        name = (
            meta.get("account_name")
            or meta.get("accountName")
            or meta.get("cloud_account_name")
            or meta.get("cloudAccountName")
            or ""
        )
        vendor = meta.get("cloud") or meta.get("cloud_provider") or meta.get("cloudProvider") or ""
        region = meta.get("region") or meta.get("cloud_region") or meta.get("cloudRegion") or ""
    if (not name or not vendor or not region) and resources:
        first = resources[0]
        if isinstance(first, dict):
            if not name:
                name = (
                    first.get("account_name")
                    or first.get("accountName")
                    or first.get("cloud_account_name")
                    or first.get("cloudAccountName")
                    or ""
                )
            if not vendor:
                vendor = first.get("cloud") or first.get("cloud_provider") or first.get("cloudProvider") or ""
            if not region:
                region = first.get("region") or first.get("cloud_region") or first.get("cloudRegion") or ""
    hostname = ""
    if name and account_id:
        hostname = f"{name}@{account_id}"
    else:
        hostname = name or account_id or ""
    desc_parts = []
    if account_id:
        desc_parts.append(f"cloud_account_id={account_id}")
    if name:
        desc_parts.append(f"account={name}")
    if vendor:
        desc_parts.append(f"cloud_provider={vendor}")
    if region:
        desc_parts.append(f"region={region}")
    if resources:
        desc_parts.append(f"matches={len(resources)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def parse_scopes(value):
    """Parse ICS_RESOURCE_GROUP_ID — accepts CSV / single value / list."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = str(value).split(",")
    out = []
    seen = set()
    for entry in items:
        if entry is None:
            continue
        text = str(entry).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def main():
    started = time.time()
    host = env("ICS_HOST", required=True)
    api_key = env("ICS_API_KEY", required=True)
    insight_id = env("EXECUTOR_CONFIG_ICS_INSIGHT_ID")
    scopes = parse_scopes(env("EXECUTOR_CONFIG_ICS_RESOURCE_GROUP_ID"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_ICS_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    if not base_url:
        log("ICS_HOST is required")
        sys.exit(1)

    auth = auth_header(api_key)
    if not auth:
        log("ICS_API_KEY is required")
        sys.exit(1)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if auth.lower().startswith("bearer "):
        # Pre-built bearer token (e.g. federated SSO short-circuit)
        headers["Authorization"] = auth
    elif auth.lower().startswith("api-key "):
        # Pre-built scheme — surface as both header conventions so
        # tenants on either dispatch path accept it.
        headers["Authorization"] = auth
        headers["Api-Key"] = auth.split(None, 1)[1]
    else:
        # Bare key — InsightCloudSec's native Api-Key header carries the
        # raw token (no scheme prefix).
        headers["Api-Key"] = auth

    # Resolve the insight catalogue: when ICS_INSIGHT_ID is set, scope
    # to that one insight (avoid the listing call so a restricted-scope
    # API key still works); otherwise enumerate every visible insight.
    if insight_id:
        insights = [{"insight_id": str(insight_id).strip()}]
    else:
        insights = fetch_insights(base_url, headers)
        log(f"Resolved {len(insights)} InsightCloudSec insights from catalogue")

    # Evaluate each insight, group matches by cloud account, build hosts
    buckets = {}
    insight_meta = {}
    total_matches = 0
    for insight in insights:
        iid = insight.get("insight_id") or insight.get("insightId") or insight.get("id") or insight.get("uuid")
        if iid in (None, ""):
            continue
        key = str(iid)
        matches = fetch_insight_matches(base_url, headers, key, scopes)
        total_matches += len(matches)
        for resource in matches:
            bk = host_bucket_key(resource)
            buckets.setdefault(bk, []).append((resource, insight))
            insight_meta.setdefault(bk, resource)
    log(f"Resolved {total_matches} InsightCloudSec evaluation matches across {len(buckets)} cloud accounts")

    hosts = []
    for key, bucket in buckets.items():
        vulns = []
        for resource, insight in bucket:
            built = build_vulnerability(resource, insight)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        host_id = "" if key == "__unknown__" else key
        resources = [r for r, _ in bucket]
        meta = insight_meta.get(key, {})
        hosts.append(build_host(host_id, meta, resources, vulns))

    params_parts = [f"min_severity={min_severity}"]
    if insight_id:
        params_parts.insert(0, f"insight_id={insight_id}")
    if scopes:
        params_parts.append(f"scopes={','.join(scopes)}")
    params = ",".join(params_parts)

    output = {
        "hosts": hosts,
        "command": {
            "tool": "rapid7_insightcloudsec",
            "command": "rapid7_insightcloudsec",
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
