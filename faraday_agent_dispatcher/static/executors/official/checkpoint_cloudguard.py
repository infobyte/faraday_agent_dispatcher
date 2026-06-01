#!/usr/bin/env python
"""Check Point CloudGuard (CNAPP / CSPM) REST importer.

Pulls cloud-security findings from a CloudGuard tenant via the
canonical ``GET /v1/findings`` endpoint and emits Faraday bulk-create
JSON to stdout. Each CloudGuard cloud account becomes one Faraday host
(``ip`` = synthetic ``0.0.0.0`` because CSPM findings live on cloud
accounts / resources, not on IPs); per-account findings are attached
as Faraday vulnerabilities — one per CloudGuard finding id with engine
prefix ``[CNAPP]``.

Endpoints used:
  GET {CG_HOST}/v1/findings
      -> primary listing endpoint. Paginated via ``pageNumber`` +
      ``pageSize`` cursor. Filters on ``cloudAccountId`` and
      ``severity``. The tenant's response is tolerated in both bare
      list and envelope (``items`` / ``data`` / ``results`` /
      ``findings``) shapes.
  GET {CG_HOST}/v1/cloud-accounts
      -> optional cloud-account enrichment. Looked up by id to surface
      account name / vendor / region metadata when the finding payload
      is compact. Tolerant to 404 / missing.

Auth: CloudGuard uses HTTP Basic with an API key / secret pair tied to
a service account; ``Authorization: Basic base64(<CG_API_KEY>:<CG_API_SECRET>)``
on every call. A pre-built ``Bearer <token>`` value in ``CG_API_KEY``
short-circuits the scheme so federated / JWT-style credentials still
work.
"""

import base64
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

CG_STRING_SEVERITY = {
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

CG_STATUS_TO_FARADAY = {
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
    "mitigated": "closed",
    "remediated": "closed",
    "patched": "closed",
    "remediated_externally": "closed",
    "remediatedexternally": "closed",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
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

CG_API_SEVERITY = {
    "info": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - CloudGuard: {msg}", file=sys.stderr, flush=True)


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
        log(f"CG_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def severities_at_or_above(min_severity):
    """Return the CloudGuard severity tokens at or above ``min_severity``.

    Used to build the ``severity`` query parameter so the tenant only
    paginates results that survive the client-side floor. ``info``
    yields every bucket (no filter applied).
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = CG_API_SEVERITY.get(bucket)
            if api and api not in out:
                out.append(api)
    return out


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


def severity_from_cloudguard(value, cvss=None):
    """Map a CloudGuard severity to a Faraday bucket.

    Accepts CloudGuard's string enum (Critical / High / Medium / Low /
    Informational) and falls back to CVSS bucketing on ``cvss`` when
    the primary value is missing or unrecognised. Numeric inputs are
    interpreted as CVSS base scores so vendor-shaped reports that
    surface a bare ``score`` still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in CG_STRING_SEVERITY:
            return CG_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_cloudguard(finding):
    """Derive Faraday status from a CloudGuard finding payload.

    CloudGuard surfaces ``status`` (Open / Closed / Suppressed /
    Remediated / Excluded / etc). We tolerate dict-wrapped values and
    a handful of alt keys so downstream re-emissions still map cleanly.
    """
    if not isinstance(finding, dict):
        return "open"
    for key in ("status", "state", "alertStatus", "findingStatus", "finding_status"):
        raw = finding.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
        if isinstance(raw, str):
            text = raw.strip().lower().replace(" ", "_").replace("-", "_")
            mapped = CG_STATUS_TO_FARADAY.get(text)
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in CG_STATUS_TO_FARADAY:
                return CG_STATUS_TO_FARADAY[compact]
    return "open"


def auth_header(api_key, api_secret):
    """Build the Authorization header.

    A pre-built ``Bearer <token>`` value in ``api_key`` short-circuits
    Basic auth so federated / JWT-style credentials still work;
    otherwise CloudGuard's native HTTP Basic scheme is used.
    """
    if not api_key:
        return None
    key = str(api_key).strip()
    if not key:
        return None
    lower = key.lower()
    if lower.startswith(("bearer ", "basic ")):
        parts = key.split(None, 1)
        scheme = parts[0][0].upper() + parts[0][1:].lower()
        return f"{scheme} {parts[1].strip()}"
    secret = str(api_secret or "").strip()
    token = base64.b64encode(f"{key}:{secret}".encode()).decode()
    return f"Basic {token}"


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
        log(f"{method} {url} rejected (401). Check CG_API_KEY / CG_API_SECRET.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"{method} {url} rejected (403). Credentials lack required scopes.")
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


def extract_items(payload):
    """Pull the finding / cloud-account list out of a CloudGuard response envelope."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("findings", "items", "data", "results", "cloudAccounts", "cloud_accounts"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def fetch_findings(base_url, headers, cloud_account_id, severities):
    """Paginate through /v1/findings for the supplied filters."""
    results = []
    seen_ids = set()
    page = 1
    for _ in range(MAX_PAGES):
        params = {
            "pageNumber": page,
            "pageSize": PAGE_SIZE,
        }
        if cloud_account_id:
            params["cloudAccountId"] = cloud_account_id
        if severities:
            params["severity"] = ",".join(severities)
        payload = request("GET", f"{base_url}/v1/findings", headers, params=params)
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for finding in chunk:
            fid = finding.get("id") or finding.get("findingId") or finding.get("finding_id")
            if isinstance(fid, str) and fid in seen_ids:
                continue
            if isinstance(fid, str):
                seen_ids.add(fid)
            results.append(finding)
            added += 1
        if added == 0:
            break
        total = None
        if isinstance(payload, dict):
            total = (
                payload.get("totalCount")
                or payload.get("totalItems")
                or payload.get("total")
                or payload.get("totalRows")
            )
        if isinstance(total, (int, float)) and len(results) >= int(total):
            break
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def fetch_cloud_account(base_url, headers, cloud_account_id):
    """Look up a cloud account by id; tolerant to 404 / missing."""
    if not cloud_account_id:
        return None
    payload = request(
        "GET",
        f"{base_url}/v1/cloud-accounts/{cloud_account_id}",
        headers,
    )
    if isinstance(payload, dict):
        for key in ("data", "result", "cloudAccount", "cloud_account"):
            nested = payload.get(key)
            if isinstance(nested, dict):
                return nested
        return payload
    items = extract_items(payload)
    return items[0] if items else None


def cvss_score(finding):
    """Pull a numeric CVSS / score out of a CloudGuard finding payload."""
    if not isinstance(finding, dict):
        return None
    for key in (
        "cvss_score",
        "cvssScore",
        "score",
        "base_score",
        "baseScore",
        "riskScore",
        "risk_score",
        "severityScore",
        "severity_score",
    ):
        value = finding.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = finding.get(nested_key)
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


def cvss_vector(finding):
    if not isinstance(finding, dict):
        return ""
    for key in ("cvss_vector", "cvssVector", "vector", "vector_string", "vectorString"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = finding.get(nested_key)
        if isinstance(nested, dict):
            for k in ("vector", "vectorString", "vector_string"):
                v = nested.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def collect_cves(finding):
    """Pull CVE-* ids out of a CloudGuard finding payload."""
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

    if not isinstance(finding, dict):
        return found
    for key in (
        "id",
        "findingId",
        "ruleId",
        "rule_id",
        "ruleName",
        "rule_name",
        "name",
        "title",
        "description",
        "summary",
    ):
        v = finding.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cve", "cveId", "cve_id"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            add_token(v)
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = finding.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add_token(entry)
                elif isinstance(entry, dict):
                    add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
    rule = finding.get("rule")
    if isinstance(rule, dict):
        for key in ("name", "title", "description", "id", "ruleId"):
            v = rule.get(key)
            if isinstance(v, str):
                add(v)
    return found


def collect_refs(finding, cloud_account=None):
    """Walk a CloudGuard finding + cloud account for CWE / advisory / URL refs."""
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

    sources = []
    if isinstance(finding, dict):
        sources.append(finding)
        rule = finding.get("rule")
        if isinstance(rule, dict):
            sources.append(rule)
    if isinstance(cloud_account, dict):
        sources.append(cloud_account)

    for source in sources:
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

    if isinstance(finding, dict):
        rule_id = finding.get("ruleId") or finding.get("rule_id")
        if rule_id:
            add(f"CloudGuard-Rule: {rule_id}")
        rule = finding.get("rule")
        if isinstance(rule, dict):
            rid = rule.get("id") or rule.get("ruleId")
            if rid:
                add(f"CloudGuard-Rule: {rid}")
        compliance = finding.get("complianceTags") or finding.get("compliance_tags") or finding.get("compliance")
        if isinstance(compliance, list):
            for c in compliance:
                if isinstance(c, dict):
                    name = c.get("name") or c.get("standard") or c.get("framework")
                    section = c.get("sectionId") or c.get("section_id") or c.get("section")
                    if name and section:
                        add(f"Compliance: {name} {section}")
                    elif name:
                        add(f"Compliance: {name}")
                elif isinstance(c, str) and c.strip():
                    add(f"Compliance: {c.strip()}")
        for key in ("entityExternalId", "entity_external_id"):
            v = finding.get(key)
            if isinstance(v, str) and v.strip():
                add(f"CloudGuard-Entity: {v.strip()}")
        for key in ("magellanUrl", "magellan_url", "url", "consoleUrl", "console_url"):
            v = finding.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    if isinstance(cloud_account, dict):
        for key in ("url", "consoleUrl", "console_url"):
            v = cloud_account.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def entity_label(finding, cloud_account=None):
    """Build a friendly label for the affected cloud resource."""
    name = ""
    nat = ""
    region = ""
    if isinstance(finding, dict):
        name = (
            finding.get("entityName")
            or finding.get("entity_name")
            or finding.get("resourceName")
            or finding.get("resource_name")
            or ""
        )
        nat = (
            finding.get("entityType")
            or finding.get("entity_type")
            or finding.get("resourceType")
            or finding.get("resource_type")
            or ""
        )
        region = finding.get("region") or finding.get("cloudRegion") or finding.get("cloud_region") or ""
    if isinstance(cloud_account, dict):
        if not region:
            region = cloud_account.get("region") or ""
    if not name and isinstance(finding, dict):
        name = (
            finding.get("entityExternalId")
            or finding.get("entity_external_id")
            or finding.get("entityId")
            or finding.get("entity_id")
            or ""
        )
    if name and nat:
        label = f"{nat} {name}"
    elif name:
        label = str(name)
    elif nat:
        label = str(nat)
    else:
        label = ""
    if region:
        label = f"{label} [{region}]" if label else f"[{region}]"
    return label.strip()


def rule_label(finding):
    if not isinstance(finding, dict):
        return ""
    label = (
        finding.get("ruleName")
        or finding.get("rule_name")
        or finding.get("alertType")
        or finding.get("alert_type")
        or finding.get("name")
        or finding.get("title")
    )
    if not label:
        rule = finding.get("rule")
        if isinstance(rule, dict):
            label = rule.get("name") or rule.get("title") or rule.get("id")
    if not label:
        label = finding.get("ruleId") or finding.get("rule_id") or ""
    return str(label).strip()


def build_vulnerability(finding, cloud_account=None):
    """Build a Faraday vulnerability dict from one CloudGuard finding."""
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding)
    severity = severity_from_cloudguard(finding.get("severity"), score)
    status = status_from_cloudguard(finding)

    rlabel = rule_label(finding)
    elabel = entity_label(finding, cloud_account)
    base_title = rlabel or str(finding.get("title") or finding.get("id") or "CloudGuard finding")
    raw_name = f"{base_title} on {elabel}" if elabel else base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = finding.get("description") or finding.get("details")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if rlabel:
        desc_parts.append(f"rule: {rlabel}")
    rule_id = finding.get("ruleId") or finding.get("rule_id")
    if rule_id:
        desc_parts.append(f"rule_id: {rule_id}")
    rule = finding.get("rule")
    if isinstance(rule, dict):
        rule_desc = rule.get("description")
        if rule_desc:
            desc_parts.append(f"rule_description: {rule_desc}")
    if elabel:
        desc_parts.append(f"resource: {elabel}")

    snap_sources = [s for s in (finding, cloud_account) if isinstance(s, dict)]
    surfaced = set()
    for label, keys in (
        ("entity_type", ("entityType", "entity_type", "resourceType", "resource_type")),
        ("entity_id", ("entityId", "entity_id", "entityExternalId", "entity_external_id")),
        ("cloud_vendor", ("cloudVendor", "cloud_vendor", "vendor", "platform")),
        (
            "cloud_account_id",
            (
                "cloudAccountId",
                "cloud_account_id",
                "accountId",
                "account_id",
                "externalAccountNumber",
                "externalCloudAccountNumber",
            ),
        ),
        ("cloud_account_name", ("cloudAccountName", "cloud_account_name", "accountName", "account_name", "name")),
        ("region", ("region", "cloudRegion", "cloud_region")),
        (
            "organizational_unit",
            ("organizationalUnitName", "organizational_unit_name", "organizationalUnitId", "organizational_unit_id"),
        ),
    ):
        for s in snap_sources:
            v = s.get(keys[0])
            for k in keys[1:]:
                if v in (None, ""):
                    v = s.get(k)
            if v not in (None, "") and label not in surfaced:
                desc_parts.append(f"{label}: {v}")
                surfaced.add(label)
                break

    state = finding.get("status") or finding.get("state")
    if state:
        desc_parts.append(f"status: {state}")
    sev_raw = finding.get("severity")
    if sev_raw:
        desc_parts.append(f"severity: {sev_raw}")
    for label, keys in (
        ("created", ("createdTime", "created_time", "createdAt", "created_at")),
        ("updated", ("updatedTime", "updated_time", "updatedAt", "updated_at", "lastSeenTime", "last_seen_time")),
        ("first_seen", ("firstSeenTime", "first_seen_time", "firstSeen", "first_seen")),
        ("acknowledged", ("acknowledgedTime", "acknowledged_time")),
        ("remediation_time", ("remediationTime", "remediation_time")),
    ):
        for k in keys:
            v = finding.get(k)
            if v:
                desc_parts.append(f"{label}: {v}")
                break

    tags = finding.get("tags") or finding.get("labels")
    if isinstance(tags, list):
        flat = []
        for t in tags:
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
    vector = cvss_vector(finding)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(finding)
    refs = collect_refs(finding, cloud_account)

    resolution = (
        finding.get("remediation")
        or finding.get("remediationSteps")
        or finding.get("remediation_steps")
        or finding.get("recommendation")
        or finding.get("resolution")
        or finding.get("solution")
        or finding.get("fix")
        or ""
    )
    if not resolution and isinstance(rule, dict):
        resolution = (
            rule.get("remediation")
            or rule.get("remediationSteps")
            or rule.get("remediation_steps")
            or rule.get("recommendation")
            or rule.get("resolution")
            or ""
        )
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    external_id = str(
        finding.get("id") or finding.get("findingId") or finding.get("finding_id") or (cves[0] if cves else "")
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"CloudGuard finding {external_id}",
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
        "tags": ["checkpoint_cloudguard", "cnapp", "cloud-security"],
    }


def host_bucket_key(finding):
    """Pick the most stable cloud-account identifier in a finding."""
    if not isinstance(finding, dict):
        return "__unknown__"
    for key in (
        "cloudAccountId",
        "cloud_account_id",
        "accountId",
        "account_id",
        "externalAccountNumber",
        "externalCloudAccountNumber",
        "cloudAccountExternalId",
    ):
        v = finding.get(key)
        if v not in (None, ""):
            return str(v)
    return "__unknown__"


def build_host(account_id, cloud_account, findings, vulns):
    """Build a Faraday host shell from a CloudGuard cloud-account bucket."""
    name = ""
    vendor = ""
    external_number = ""
    region = ""
    org_unit = ""
    if isinstance(cloud_account, dict):
        name = cloud_account.get("name") or cloud_account.get("accountName") or ""
        vendor = cloud_account.get("vendor") or cloud_account.get("cloudVendor") or cloud_account.get("platform") or ""
        external_number = (
            cloud_account.get("externalAccountNumber") or cloud_account.get("externalCloudAccountNumber") or ""
        )
        region = cloud_account.get("region") or ""
        org_unit = cloud_account.get("organizationalUnitName") or cloud_account.get("organizational_unit_name") or ""
    if not name and findings:
        first = findings[0]
        if isinstance(first, dict):
            name = (
                first.get("cloudAccountName")
                or first.get("cloud_account_name")
                or first.get("accountName")
                or first.get("account_name")
                or ""
            )
            if not vendor:
                vendor = first.get("cloudVendor") or first.get("cloud_vendor") or first.get("vendor") or ""
            if not external_number:
                external_number = first.get("externalAccountNumber") or first.get("externalCloudAccountNumber") or ""
            if not region:
                region = first.get("region") or first.get("cloudRegion") or ""
    hostname = ""
    if name and account_id and account_id != "__unknown__":
        hostname = f"{name}@{account_id}"
    elif account_id and account_id != "__unknown__":
        hostname = account_id
    else:
        hostname = name
    desc_parts = []
    if account_id and account_id != "__unknown__":
        desc_parts.append(f"cloud_account_id={account_id}")
    if name:
        desc_parts.append(f"account={name}")
    if vendor:
        desc_parts.append(f"vendor={vendor}")
    if external_number:
        desc_parts.append(f"external_account_number={external_number}")
    if region:
        desc_parts.append(f"region={region}")
    if org_unit:
        desc_parts.append(f"organizational_unit={org_unit}")
    if findings:
        desc_parts.append(f"findings={len(findings)}")
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
    host = env("CG_HOST", required=True)
    api_key = env("CG_API_KEY", required=True)
    api_secret = env("CG_API_SECRET", required=True)
    cloud_account_id = env("EXECUTOR_CONFIG_CG_CLOUD_ACCOUNT_ID")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_CG_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]
    severities = severities_at_or_above(min_severity)
    if severities and len(severities) == len(CG_API_SEVERITY):
        severities = None

    base_url = normalize_base_url(host)
    if not base_url:
        log("CG_HOST is required")
        sys.exit(1)

    auth = auth_header(api_key, api_secret)
    if not auth:
        log("Failed to build Authorization header from CG_API_KEY / CG_API_SECRET; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": auth,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    findings = fetch_findings(base_url, headers, cloud_account_id, severities)
    log(
        f"Processing {len(findings)} CloudGuard findings "
        f"(cloud_account_id={cloud_account_id or 'ALL'}, min_severity={min_severity})"
    )

    # Group findings by cloud account (one Faraday host per cloud account)
    account_buckets = {}
    account_meta = {}
    for finding in findings:
        key = host_bucket_key(finding)
        account_buckets.setdefault(key, []).append(finding)

    # Best-effort cloud-account enrichment per unique account id
    for key in list(account_buckets.keys()):
        if key == "__unknown__":
            continue
        account = fetch_cloud_account(base_url, headers, key)
        if account:
            account_meta[key] = account

    hosts = []
    for key, bucket in account_buckets.items():
        account = account_meta.get(key)
        vulns = []
        for finding in bucket:
            built = build_vulnerability(finding, account)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        host_id = "" if key == "__unknown__" else key
        hosts.append(build_host(host_id, account, bucket, vulns))

    params = f"min_severity={min_severity}"
    if cloud_account_id:
        params = f"{params},cloud_account_id={cloud_account_id}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "checkpoint_cloudguard",
            "command": "checkpoint_cloudguard",
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
