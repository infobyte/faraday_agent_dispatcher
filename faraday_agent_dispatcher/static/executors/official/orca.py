#!/usr/bin/env python
"""Orca Security (CNAPP / CSPM) REST importer.

Pulls cloud-security alerts from an Orca tenant via the canonical
``GET /api/alerts`` endpoint and emits Faraday bulk-create JSON to
stdout. Each Orca asset (cloud resource — ``asset_unique_id``) becomes
one Faraday host (``ip`` = synthetic ``0.0.0.0`` because CNAPP
findings live on cloud resources, not on IPs); per-asset alerts are
attached as Faraday vulnerabilities — one per Orca alert id with
engine prefix ``[CNAPP]``.

Endpoints used:
  GET {ORCA_HOST}/api/alerts
      -> primary listing endpoint. Paginated via ``start_at_index`` +
      ``limit`` cursor. Filters on ``state[]`` and ``severity[]``;
      ``group_by_type`` collapses duplicate alerts so each alert_type
      surfaces once with an aggregate ``count``.
  GET {ORCA_HOST}/api/assets
      -> optional asset enrichment. Looked up by ``asset_unique_id``
      to surface cloud_account / region / cloud_provider metadata when
      the alert payload is compact. Tolerant to 404 / missing.

Auth: Orca uses a long-lived API token. The token is sent as
``Authorization: Token <ORCA_API_TOKEN>`` (Orca's native scheme); a
pre-built ``Bearer <token>`` value in ``ORCA_API_TOKEN`` short-circuits
the scheme so SaaS / Cloud Service Provider tenants that mint
JWT-style tokens still work.
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

# Orca state lifecycle:
#   open / in_progress / re_opened -> open
#   closed / fixed / resolved / mitigated / remediated -> closed
#   snoozed / dismissed / ignored / suppressed / muted / wont_fix /
#   risk_accepted / false_positive / expired -> risk-accepted
VALID_ORCA_STATUS = ("OPEN", "IN_PROGRESS", "CLOSED", "SNOOZED", "DISMISSED")

ORCA_STRING_SEVERITY = {
    "critical": "critical",
    "imminent_compromise": "critical",
    "imminentcompromise": "critical",
    "hazardous": "critical",
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

ORCA_STATUS_TO_FARADAY = {
    "open": "open",
    "in_progress": "open",
    "inprogress": "open",
    "new": "open",
    "active": "open",
    "re_opened": "open",
    "reopened": "open",
    "closed": "closed",
    "fixed": "closed",
    "resolved": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "snoozed": "risk-accepted",
    "dismissed": "risk-accepted",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "expired": "risk-accepted",
}

ORCA_API_SEVERITY = {
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - Orca: {msg}", file=sys.stderr, flush=True)


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


def normalize_base_url(host):
    if not host:
        return ""
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def parse_bool(value, default=False):
    """Parse a truthy CLI/env value with the usual suspects."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    text = str(value).strip().lower()
    if not text:
        return default
    if text in ("1", "true", "yes", "y", "on", "t"):
        return True
    if text in ("0", "false", "no", "n", "off", "f"):
        return False
    return default


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"ORCA_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def validate_status(value):
    """Validate ORCA_STATUS — Orca expects open/in_progress/closed/snoozed/dismissed.

    None / blank -> None (no filter). Garbage is rejected with a log
    line so the operator can spot typos rather than silently scanning
    the whole tenant. Returns upper-case canonical tokens for use as
    Orca query params.
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
        if token in VALID_ORCA_STATUS:
            if token not in valid:
                valid.append(token)
        elif token in ("REOPENED", "RE_OPENED", "NEW", "ACTIVE"):
            if "OPEN" not in valid:
                valid.append("OPEN")
        elif token in ("RESOLVED", "FIXED", "REMEDIATED", "MITIGATED", "PATCHED"):
            if "CLOSED" not in valid:
                valid.append("CLOSED")
        elif token in (
            "IGNORED",
            "SUPPRESSED",
            "MUTED",
            "WONT_FIX",
            "RISK_ACCEPTED",
            "ACCEPTED",
            "FALSE_POSITIVE",
            "EXPIRED",
        ):
            if "DISMISSED" not in valid:
                valid.append("DISMISSED")
        else:
            log(f"ORCA_STATUS token '{token}' not recognised; ignored")
    return valid or None


def severities_at_or_above(min_severity):
    """Return the Orca severity tokens at or above ``min_severity``.

    Used to build the ``severity`` query parameter so the tenant only
    paginates results that survive the client-side floor. ``info``
    yields every bucket (no filter applied).
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = ORCA_API_SEVERITY.get(bucket)
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


def severity_from_orca(value, cvss=None):
    """Map an Orca severity to a Faraday bucket.

    Accepts Orca's string enum (critical / high / medium / low /
    informational) and falls back to CVSS bucketing on ``cvss`` when
    the primary value is missing or unrecognised. Numeric inputs are
    interpreted as CVSS base scores so vendor-shaped reports that
    surface a bare ``severity_score`` still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in ORCA_STRING_SEVERITY:
            return ORCA_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_orca(alert):
    """Derive Faraday status from an Orca alert payload.

    Orca carries a top-level ``state`` enum (open / in_progress /
    closed / snoozed / dismissed). We tolerate dict-wrapped and
    synonym shapes so downstream re-emissions through generic CNAPP
    pipelines still map cleanly.
    """
    if not isinstance(alert, dict):
        return "open"
    for key in ("state", "status", "alert_state", "alertState"):
        raw = alert.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("state") or raw.get("status")
        if isinstance(raw, str):
            mapped = ORCA_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in ORCA_STATUS_TO_FARADAY:
                return ORCA_STATUS_TO_FARADAY[compact]
    return "open"


def auth_header(token):
    """Build the Authorization header.

    A pre-built ``Bearer <token>`` short-circuits the scheme; otherwise
    Orca's native ``Token <api_key>`` scheme is used.
    """
    if not token:
        return None
    text = str(token).strip()
    if not text:
        return None
    lower = text.lower()
    if lower.startswith(("token ", "bearer ")):
        parts = text.split(None, 1)
        return f"{parts[0][0].upper() + parts[0][1:].lower()} {parts[1].strip()}"
    return f"Token {text}"


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
        log(f"{method} {url} rejected (401). Check ORCA_API_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"{method} {url} rejected (403). Token lacks required scopes.")
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
    """Pull the alert/asset list out of an Orca response envelope.

    Orca returns ``{"data": [...], "next_page_token": "...",
    "total_items": N}`` for paginated lists and sometimes a bare list;
    tolerate both shapes plus a handful of seen alt keys (``results``,
    ``items``, ``alerts``, ``assets``).
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "results", "items", "alerts", "assets"):
        items = payload.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def fetch_alerts(base_url, headers, statuses, severities, group_by_type):
    """Paginate through /api/alerts for the supplied filters."""
    results = []
    seen_ids = set()
    index = 0
    for _ in range(MAX_PAGES):
        params = {
            "start_at_index": index,
            "limit": PAGE_SIZE,
        }
        if statuses:
            params["state"] = ",".join(s.lower() for s in statuses)
        if severities:
            params["severity"] = ",".join(severities)
        if group_by_type:
            params["group_by_type"] = "true"
        payload = request("GET", f"{base_url}/api/alerts", headers, params=params)
        if payload is None:
            break
        chunk = extract_items(payload)
        if not chunk:
            break
        added = 0
        for alert in chunk:
            aid = alert.get("alert_id") or alert.get("id") or alert.get("alertId")
            if isinstance(aid, str) and aid in seen_ids:
                continue
            if isinstance(aid, str):
                seen_ids.add(aid)
            results.append(alert)
            added += 1
        if added == 0:
            break
        index += len(chunk)
        total = None
        if isinstance(payload, dict):
            total = payload.get("total_items") or payload.get("totalItems") or payload.get("total")
        if isinstance(total, (int, float)) and index >= int(total):
            break
        if len(chunk) < PAGE_SIZE:
            break
    return results


def fetch_asset(base_url, headers, asset_unique_id):
    """Look up an asset by asset_unique_id; tolerant to 404 / missing."""
    if not asset_unique_id:
        return None
    payload = request(
        "GET",
        f"{base_url}/api/assets",
        headers,
        params={"asset_unique_id": asset_unique_id},
    )
    items = extract_items(payload)
    return items[0] if items else None


def cvss_score(alert):
    """Pull a numeric CVSS / severity score out of an Orca alert payload."""
    if not isinstance(alert, dict):
        return None
    for key in (
        "cvss_score",
        "cvssScore",
        "score",
        "base_score",
        "baseScore",
        "severity_score",
        "severityScore",
    ):
        value = alert.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = alert.get(nested_key)
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


def cvss_vector(alert):
    if not isinstance(alert, dict):
        return ""
    for key in ("cvss_vector", "cvssVector", "vector", "vector_string", "vectorString"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = alert.get(nested_key)
        if isinstance(nested, dict):
            for k in ("vector", "vectorString", "vector_string"):
                v = nested.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def collect_cves(alert):
    """Pull CVE-* ids out of an Orca alert payload."""
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

    if not isinstance(alert, dict):
        return found
    for key in ("alert_id", "type", "alert_type", "title", "description", "name"):
        v = alert.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cve", "cveId", "cve_id"):
        v = alert.get(key)
        if isinstance(v, str) and v.strip():
            add_token(v)
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = alert.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add_token(entry)
                elif isinstance(entry, dict):
                    add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
    findings = alert.get("findings")
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            for key in ("cve", "cve_id", "cveId", "name", "id"):
                v = f.get(key)
                if isinstance(v, str):
                    add(v)
    return found


def collect_refs(alert, asset=None):
    """Walk an Orca alert + asset for CWE / advisory / URL refs."""
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
    if isinstance(alert, dict):
        sources.append(alert)
    if isinstance(asset, dict):
        sources.append(asset)

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

    # Orca surfaces the alert type as the stable rule identifier
    if isinstance(alert, dict):
        atype = alert.get("type") or alert.get("alert_type")
        if isinstance(atype, str) and atype.strip():
            add(f"Orca-Alert-Type: {atype.strip()}")
        url = alert.get("alert_url") or alert.get("alertUrl") or alert.get("url")
        if isinstance(url, str) and url.strip():
            add(url.strip())
        provider_url = alert.get("cloud_provider_url") or alert.get("cloudProviderURL")
        if isinstance(provider_url, str) and provider_url.strip():
            add(provider_url.strip())
        findings = alert.get("findings")
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                for key in ("url", "href", "link"):
                    v = f.get(key)
                    if isinstance(v, str) and v.strip():
                        add(v.strip())

    if isinstance(asset, dict):
        url = asset.get("cloud_provider_url") or asset.get("cloudProviderURL") or asset.get("url")
        if isinstance(url, str) and url.strip():
            add(url.strip())

    return refs


def asset_label(asset, alert=None):
    """Build a friendly label for the affected cloud resource."""
    name = ""
    nat = ""
    region = ""
    if isinstance(asset, dict):
        name = asset.get("asset_name") or asset.get("name") or ""
        nat = asset.get("asset_type") or asset.get("type") or asset.get("native_type") or ""
        region = asset.get("cloud_provider_region") or asset.get("region") or ""
    if isinstance(alert, dict):
        if not name:
            name = alert.get("asset_name") or alert.get("resource_name") or ""
        if not nat:
            nat = alert.get("asset_type") or alert.get("resource_type") or ""
        if not region:
            region = alert.get("cloud_provider_region") or alert.get("region") or ""
    if name and nat:
        label = f"{nat} {name}"
    elif name:
        label = str(name)
    elif nat:
        label = str(nat)
    else:
        if isinstance(alert, dict):
            label = str(alert.get("asset_unique_id") or "")
        else:
            label = ""
    if region:
        label = f"{label} [{region}]" if label else f"[{region}]"
    return label.strip()


def alert_type_label(alert):
    if not isinstance(alert, dict):
        return ""
    return str(alert.get("type") or alert.get("alert_type") or alert.get("name") or alert.get("title") or "").strip()


def build_vulnerability(alert, asset=None):
    """Build a Faraday vulnerability dict from one Orca alert."""
    if not isinstance(alert, dict):
        return None

    score = cvss_score(alert)
    severity = severity_from_orca(alert.get("severity"), score)
    status = status_from_orca(alert)

    atype = alert_type_label(alert)
    elabel = asset_label(asset, alert)
    base_title = atype or str(alert.get("title") or alert.get("alert_id") or alert.get("id") or "Orca finding")
    raw_name = f"{base_title} on {elabel}" if elabel else base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = alert.get("description") or alert.get("details")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if atype:
        desc_parts.append(f"alert_type: {atype}")
    category = alert.get("category") or alert.get("alert_category")
    if category:
        desc_parts.append(f"category: {category}")
    asset_unique_id = alert.get("asset_unique_id") or alert.get("assetUniqueId")
    if asset_unique_id:
        desc_parts.append(f"asset_unique_id: {asset_unique_id}")
    if elabel:
        desc_parts.append(f"resource: {elabel}")

    snap_sources = [s for s in (alert, asset) if isinstance(s, dict)]
    surfaced = set()
    for label, keys in (
        ("native_type", ("asset_type", "resource_type", "native_type")),
        ("cloud_provider", ("cloud_provider", "cloudProvider")),
        ("cloud_account", ("cloud_account_id", "cloudAccountId", "account_id", "accountId")),
        ("cloud_account_name", ("cloud_account_name", "account_name", "accountName")),
        ("region", ("cloud_provider_region", "region")),
        ("provider_id", ("provider_id", "providerId", "cloud_provider_id", "cloudProviderId")),
        ("subscription", ("subscription_name", "subscriptionName")),
        ("subscription_id", ("subscription_id", "subscriptionId", "subscription_external_id")),
        ("resource_group", ("resource_group", "resourceGroup", "resource_group_external_id")),
        ("cluster", ("cluster_name", "clusterName")),
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

    state = alert.get("state") or alert.get("status")
    if state:
        desc_parts.append(f"state: {state}")
    sev_raw = alert.get("severity")
    if sev_raw:
        desc_parts.append(f"severity: {sev_raw}")
    sev_score = alert.get("severity_score") or alert.get("severityScore")
    if sev_score not in (None, ""):
        desc_parts.append(f"severity_score: {sev_score}")
    if alert.get("count"):
        desc_parts.append(f"count: {alert.get('count')}")
    for label, keys in (
        ("created", ("created_at", "createdAt")),
        ("updated", ("updated_at", "updatedAt", "last_seen", "lastSeen")),
        ("first_seen", ("first_seen", "firstSeen")),
        ("closed", ("closed_at", "closedAt")),
        ("snoozed_until", ("snoozed_until", "snoozedUntil")),
    ):
        for k in keys:
            v = alert.get(k)
            if v:
                desc_parts.append(f"{label}: {v}")
                break

    tags = alert.get("tags")
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
    vector = cvss_vector(alert)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(alert)
    refs = collect_refs(alert, asset)

    resolution = (
        alert.get("recommendation")
        or alert.get("remediation")
        or alert.get("resolution")
        or alert.get("solution")
        or alert.get("fix")
        or ""
    )
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    external_id = str(alert.get("alert_id") or alert.get("id") or alert.get("alertId") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Orca finding {external_id}",
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
        "tags": ["orca", "cnapp", "cloud-security"],
    }


def build_host(asset_unique_id, asset, alerts, vulns):
    """Build a Faraday host shell from an Orca asset bucket."""
    name = ""
    nat = ""
    cloud_provider = ""
    cloud_account = ""
    region = ""
    if isinstance(asset, dict):
        name = asset.get("asset_name") or asset.get("name") or ""
        nat = asset.get("asset_type") or asset.get("type") or asset.get("native_type") or ""
        cloud_provider = asset.get("cloud_provider") or asset.get("cloudProvider") or ""
        cloud_account = asset.get("cloud_account_id") or asset.get("account_id") or ""
        region = asset.get("cloud_provider_region") or asset.get("region") or ""
    if not name and alerts:
        first = alerts[0]
        if isinstance(first, dict):
            name = first.get("asset_name") or first.get("resource_name") or ""
            if not nat:
                nat = first.get("asset_type") or first.get("resource_type") or ""
            if not cloud_provider:
                cloud_provider = first.get("cloud_provider") or ""
            if not cloud_account:
                cloud_account = first.get("cloud_account_id") or first.get("account_id") or ""
            if not region:
                region = first.get("cloud_provider_region") or first.get("region") or ""
    hostname = ""
    if name and asset_unique_id:
        hostname = f"{name}@{asset_unique_id}"
    else:
        hostname = name or asset_unique_id or ""
    desc_parts = []
    if asset_unique_id:
        desc_parts.append(f"asset_unique_id={asset_unique_id}")
    if name:
        desc_parts.append(f"asset={name}")
    if nat:
        desc_parts.append(f"type={nat}")
    if cloud_provider:
        desc_parts.append(f"cloud_provider={cloud_provider}")
    if cloud_account:
        desc_parts.append(f"cloud_account={cloud_account}")
    if region:
        desc_parts.append(f"region={region}")
    if alerts:
        desc_parts.append(f"alerts={len(alerts)}")
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
    host = env("ORCA_HOST", required=True)
    token = env("ORCA_API_TOKEN", required=True)
    group_by_type = parse_bool(env("EXECUTOR_CONFIG_ORCA_GROUP_BY_TYPE"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_ORCA_MIN_SEVERITY"))
    statuses = validate_status(env("EXECUTOR_CONFIG_ORCA_STATUS"))
    floor = SEVERITY_ORDER[min_severity]
    severities = severities_at_or_above(min_severity)
    if severities and len(severities) == len(ORCA_API_SEVERITY):
        severities = None

    base_url = normalize_base_url(host)
    if not base_url:
        log("ORCA_HOST is required")
        sys.exit(1)

    auth = auth_header(token)
    if not auth:
        log("Failed to build Authorization header from ORCA_API_TOKEN; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": auth,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    alerts = fetch_alerts(base_url, headers, statuses, severities, group_by_type)
    log(
        f"Processing {len(alerts)} Orca alerts "
        f"(group_by_type={group_by_type}, status={statuses or 'ALL'}, min_severity={min_severity})"
    )

    # Group alerts by asset_unique_id (one Faraday host per cloud asset)
    asset_buckets = {}
    asset_meta = {}
    for alert in alerts:
        aid = alert.get("asset_unique_id") or alert.get("assetUniqueId") or alert.get("asset_id") or ""
        key = str(aid) if aid else "__unknown__"
        asset_buckets.setdefault(key, []).append(alert)

    # Best-effort asset enrichment for the first chunk of unique assets
    for key in list(asset_buckets.keys()):
        if key == "__unknown__":
            continue
        asset = fetch_asset(base_url, headers, key)
        if asset:
            asset_meta[key] = asset

    hosts = []
    for key, bucket in asset_buckets.items():
        asset = asset_meta.get(key)
        vulns = []
        for alert in bucket:
            built = build_vulnerability(alert, asset)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        host_id = "" if key == "__unknown__" else key
        hosts.append(build_host(host_id, asset, bucket, vulns))

    params = f"group_by_type={'true' if group_by_type else 'false'},min_severity={min_severity}"
    if statuses:
        params = f"{params},status={'|'.join(statuses)}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "orca",
            "command": "orca",
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
