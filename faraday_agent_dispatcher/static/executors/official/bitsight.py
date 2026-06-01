#!/usr/bin/env python
"""BitSight Security Ratings REST importer.

Pulls the company-level rating record and the open finding catalogue
from a BitSight tenant and emits Faraday bulk-create JSON to stdout.
Each monitored company becomes one Faraday host (keyed by the
company's GUID — the BitSight surface is company-scoped, not
asset-scoped, so the host record is a synthetic per-company bucket
rather than an IP-keyed asset); the company's open findings attach as
Faraday vulnerabilities with the engine prefix ``[SECURITY-RATING]``.
The synthetic host carries ``host.os`` = the BitSight rating + grade
("BitSight 750 (Advanced)") so the rating itself is visible alongside
the per-risk-category findings.

Endpoints used:
  GET https://api.bitsighttech.com/ratings/v2/companies/{guid}
      -> the monitored company's metadata (name, industry, primary
      domain, ipv4 count, employee count, rating + grade, per
      risk-category grade breakdown).  Used to build the host
      record + host.description enrichment + host.os string.
  GET https://api.bitsighttech.com/ratings/v2/companies/{guid}/findings
      -> paginated open findings (each finding = one risk-vector
      observation tied to one or more assets).  Pagination is
      ``limit`` + ``offset`` cursor with ``links.next`` / ``count``
      exhaustion detection.  Each finding maps onto a Faraday
      vulnerability — severity bucketed from the freeform
      ``severity_category`` string enum (severe / material / moderate
      / minor / neutral) with the numeric ``severity`` (0-10) used as
      a CVSS-style fallback.

Auth: BitSight uses HTTP Basic auth where the username is the API
token and the password is empty — the dispatcher carries
``Authorization: Basic <base64(BITSIGHT_TOKEN:)>`` plus
``Accept: application/json`` on every call.  ``BITSIGHT_TOKEN`` is
the API token created in the BitSight console under
``Account -> Settings -> API Token``.
"""

import base64
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

BITSIGHT_HOST = "https://api.bitsighttech.com"
TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# BitSight surfaces ``severity_category`` as a freeform string enum
# (severe / material / moderate / minor / neutral / informational) plus
# a numeric ``severity`` 0-10.  The string enum buckets onto Faraday
# tiers; numeric bucketing is used as a fallback when the string is
# missing / unrecognised.
BITSIGHT_STRING_SEVERITY = {
    "severe": "critical",
    "critical": "critical",
    "material": "high",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "minor": "low",
    "low": "low",
    "neutral": "info",
    "informational": "info",
    "info": "info",
    "none": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# BitSight finding lifecycle is exposed through ``remediation_status``
# (open / resolved / in_progress / etc).  Open / detected / new map
# onto Faraday open; resolved / fixed map onto closed; risk_accepted /
# false_positive / will_not_fix map onto risk-accepted.
BITSIGHT_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "active": "open",
    "detected": "open",
    "in_progress": "open",
    "inprogress": "open",
    "investigating": "open",
    "triaging": "open",
    "remediated": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "patched": "closed",
    "mitigated": "closed",
    "closed": "closed",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "waived": "risk-accepted",
    "will_not_fix": "risk-accepted",
    "willnotfix": "risk-accepted",
    "wontfix": "risk-accepted",
    "won't_fix": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "suppressed": "risk-accepted",
    "dismissed": "risk-accepted",
}


# BitSight company ratings translate into a coarse letter grade.  The
# grade ranges are documented in the BitSight Security Ratings glossary
# (https://help.bitsighttech.com/hc/en-us/articles/360006681214) and
# are reproduced here so the host.description / host.os carry the
# grade label even when the API only returned the numeric rating.
def _grade_from_rating(rating):
    try:
        n = int(round(float(rating)))
    except (TypeError, ValueError):
        return ""
    if n >= 740:
        return "Advanced"
    if n >= 670:
        return "Intermediate"
    if n >= 590:
        return "Basic"
    return "Limited"


def log(msg):
    print(f"{datetime.utcnow()} - BitSight: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
    """Bucket a numeric severity (0-10 CVSS-style) onto a Faraday tier."""
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


def severity_from_bitsight(value, numeric=None):
    """Map a BitSight severity_category string onto a Faraday bucket.

    Accepts the freeform string enum (severe / material / moderate /
    minor / neutral), Faraday-side synonyms, numeric inputs (0-10
    CVSS-style), numeric strings, and falls back to numeric bucketing
    on ``numeric`` when the primary value is missing or unrecognised.
    """
    if isinstance(value, bool):
        if numeric is not None:
            return severity_from_cvss(numeric)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower()
        if text in BITSIGHT_STRING_SEVERITY:
            return BITSIGHT_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def status_from_bitsight(item):
    """Derive Faraday status from a BitSight finding payload.

    Walks ``remediation_status`` / ``status`` / ``state`` and falls
    back to ``first_seen_after_resolution`` / ``rolledup_observation
    _id`` for re-emitted shapes.
    """
    if not isinstance(item, dict):
        return "open"
    for key in ("remediation_status", "status", "state", "Status", "State"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in BITSIGHT_STATUS_BY_STATE:
                return BITSIGHT_STATUS_BY_STATE[compact]
            if squashed in BITSIGHT_STATUS_BY_STATE:
                return BITSIGHT_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in BITSIGHT_STATUS_BY_STATE:
                        return BITSIGHT_STATUS_BY_STATE[compact]
                    if squashed in BITSIGHT_STATUS_BY_STATE:
                        return BITSIGHT_STATUS_BY_STATE[squashed]
    return "open"


def validate_min_severity(value):
    """Validate BITSIGHT_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus BitSight-side synonyms
    (severe -> critical, material -> high, moderate -> medium, minor
    -> low, neutral / informational -> info) plus numeric-string
    input bucketed via severity_from_cvss.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = BITSIGHT_STRING_SEVERITY.get(text)
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"BITSIGHT_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_company_guid(value):
    """Validate BITSIGHT_COMPANY_GUID.

    None / blank -> sys.exit(1).  BitSight company GUIDs are uuid4
    strings (8-4-4-4-12 hex groups) and we hard-enforce the shape
    client-side so a typo can't fan out into "/ratings/v2/companies/
    None" / "/ratings/v2/companies/bad" calls.
    """
    if value is None or value == "":
        log("BITSIGHT_COMPANY_GUID is required")
        sys.exit(1)
    text = str(value).strip()
    if not text:
        log("BITSIGHT_COMPANY_GUID is required")
        sys.exit(1)
    if not GUID_RE.match(text):
        log(f"BITSIGHT_COMPANY_GUID '{text}' is not a uuid4 (8-4-4-4-12 hex groups)")
        sys.exit(1)
    return text.lower()


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(token):
    """BitSight expects HTTP Basic with the token as the username."""
    raw = f"{token or ''}:".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return {
        "Authorization": f"Basic {encoded}",
        "Accept": "application/json",
    }


def build_company_url(guid):
    return f"{BITSIGHT_HOST}/ratings/v2/companies/{guid}"


def build_findings_url(guid):
    return f"{BITSIGHT_HOST}/ratings/v2/companies/{guid}/findings"


def build_findings_params(offset, limit):
    """BitSight finding pagination is ``limit`` + ``offset`` cursor.

    ``expand=attributed_companies,assets`` requests the per-finding
    asset enrichment in the same response so we don't need a second
    call per finding.
    """
    return {
        "limit": int(limit),
        "offset": int(offset),
        "expand": "attributed_companies,assets",
    }


def extract_results(body):
    """Pull the result list out of a BitSight pagination envelope.

    BitSight uses ``{"results": [...], "links": {...}, "count": N}``
    on /findings — accept ``data`` / ``items`` as alt-keys for
    federated stacks.
    """
    if not isinstance(body, dict):
        return []
    for key in ("results", "data", "items", "findings"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_count(body):
    """Pull the total record count from a BitSight envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("count", "total", "total_count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def extract_next_link(body):
    """Pull the ``links.next`` URL from a BitSight envelope (None if exhausted)."""
    if not isinstance(body, dict):
        return None
    links = body.get("links")
    if isinstance(links, dict):
        nxt = links.get("next")
        if isinstance(nxt, str) and nxt.strip():
            return nxt.strip()
    return None


def _serialise(obj):
    if obj is None:
        return ""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (str, int, float)):
        return str(obj)
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(obj)


def collect_cves(item):
    """Walk a BitSight finding payload for CVE-* ids.

    BitSight publishes CVE references on the ``details`` /
    ``remediations`` blocks plus inline in the description on a
    handful of risk vectors (patching cadence + vulnerable services).
    """
    found = []
    seen = set()

    def add(text):
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
        for m in CVE_RE.findall(text):
            add(m)

    if not isinstance(item, dict):
        return found

    for key in ("cve", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "cve_ids"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    details = item.get("details") if isinstance(item, dict) else None
    if isinstance(details, dict):
        for key in ("cve", "cves", "cve_id", "cve_ids"):
            v = details.get(key)
            if isinstance(v, str):
                add(v)
            elif isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add(entry)

    for key in ("description", "details_description", "evidence", "summary", "name"):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
    if isinstance(details, dict):
        for key in ("description", "evidence", "summary"):
            v = details.get(key)
            if isinstance(v, str):
                scan(v)

    return found


def collect_refs(item):
    """Walk a BitSight finding payload for advisory URLs and BitSight pivots."""
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

    if not isinstance(item, dict):
        return refs

    temp_id = item.get("temporary_id") or item.get("temporaryId") or item.get("id")
    if temp_id is not None:
        s = str(temp_id).strip()
        if s:
            add(f"BitSight-Finding: {s}")

    rolledup_id = item.get("rolledup_observation_id") or item.get("rolledupObservationId")
    if rolledup_id is not None:
        s = str(rolledup_id).strip()
        if s:
            add(f"BitSight-Observation: {s}")

    risk_vector = item.get("risk_vector") or item.get("riskVector")
    if isinstance(risk_vector, str) and risk_vector.strip():
        add(f"BitSight-RiskVector: {risk_vector.strip()}")

    risk_category = item.get("risk_category") or item.get("riskCategory")
    if isinstance(risk_category, str) and risk_category.strip():
        add(f"BitSight-RiskCategory: {risk_category.strip()}")

    assets = item.get("assets") or item.get("attributed_assets")
    if isinstance(assets, list):
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            label = asset.get("asset") or asset.get("hostname") or asset.get("name") or asset.get("ip")
            if isinstance(label, str) and label.strip():
                add(f"BitSight-Asset: {label.strip()}")

    for key in ("references", "remediations", "links"):
        entry = item.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("link") or it.get("help_text") or it.get("name")
                    if href:
                        add(href)
                elif isinstance(it, str):
                    add(it)
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def finding_label(item):
    """Build the leading title fragment for a BitSight finding."""
    if not isinstance(item, dict):
        return ""
    for key in ("risk_vector_label", "riskVectorLabel"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("risk_vector", "riskVector"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().replace("_", " ").title()
    for key in ("name", "title", "summary"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    details = item.get("details")
    if isinstance(details, dict):
        for key in ("description", "summary", "grade"):
            v = details.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return "BitSight finding"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from a BitSight finding record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    raw_numeric = item.get("severity")
    if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
        severity_numeric = float(raw_numeric)
    elif isinstance(raw_numeric, str) and raw_numeric.strip():
        try:
            severity_numeric = float(raw_numeric.strip())
        except ValueError:
            severity_numeric = None

    severity_category = item.get("severity_category") or item.get("severityCategory") or item.get("severity_label")
    severity = severity_from_bitsight(severity_category, severity_numeric)
    status = status_from_bitsight(item)

    label = finding_label(item)
    name = f"[SECURITY-RATING] {label}" if label else "[SECURITY-RATING] BitSight finding"

    desc_parts = []
    description = item.get("description") or item.get("Description") or item.get("details_description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("temporary_id", "temporary_id"),
        ("rolledup_observation_id", "rolledup_observation_id"),
        ("first_seen", "first_seen"),
        ("last_seen", "last_seen"),
        ("evidence_key", "evidence_key"),
        ("grade", "grade"),
        ("risk_vector", "risk_vector"),
        ("risk_vector_label", "risk_vector_label"),
        ("risk_category", "risk_category"),
        ("severity_category", "severity_category"),
        ("remediation_status", "remediation_status"),
        ("comments", "comments"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if severity_numeric is not None:
        desc_parts.append(f"severity_score: {severity_numeric}")

    details = item.get("details")
    if isinstance(details, dict):
        for label_key, key in (
            ("grade", "grade"),
            ("rollup_start_date", "rollup_start_date"),
            ("rollup_end_date", "rollup_end_date"),
            ("infection", "infection"),
            ("observed_ips", "observed_ips"),
            ("dest_ips", "dest_ips"),
        ):
            v = details.get(key)
            if v in (None, ""):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"details.{label_key}: {_serialise(v)}")
            else:
                desc_parts.append(f"details.{label_key}: {v}")

    assets = item.get("assets") or item.get("attributed_assets")
    if isinstance(assets, list) and assets:
        labels = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            tag = asset.get("asset") or asset.get("hostname") or asset.get("name") or asset.get("ip")
            if tag:
                labels.append(str(tag).strip())
        if labels:
            desc_parts.append(f"assets: {', '.join(labels[:20])}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    remediations = item.get("remediations") or (details.get("remediations") if isinstance(details, dict) else None)
    if isinstance(remediations, list):
        bits = []
        for r in remediations:
            if isinstance(r, dict):
                txt = r.get("help_text") or r.get("description") or r.get("name") or r.get("solution")
                if isinstance(txt, str) and txt.strip():
                    bits.append(txt.strip())
            elif isinstance(r, str) and r.strip():
                bits.append(r.strip())
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(remediations, str) and remediations.strip():
        resolution = remediations.strip()
    if not resolution:
        resolution = (
            "Investigate the finding in the BitSight portal "
            "(My Companies -> Findings -> select the risk vector) and "
            "drive remediation through the affected asset owner; if "
            "the underlying asset cannot be re-graded, accept the risk "
            "via BitSight's Risk Acceptance workflow so the rating "
            "impact is acknowledged."
        )

    external_id = str(
        item.get("temporary_id")
        or item.get("temporaryId")
        or item.get("rolledup_observation_id")
        or item.get("id")
        or (cves[0] if cves else "")
    )

    return {
        "name": str(name).strip()[:200] or f"BitSight finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["bitsight", "security-rating", "security-ratings"],
    }


def company_hostname(company):
    """Pick the canonical hostname for a BitSight company record."""
    if not isinstance(company, dict):
        return ""
    for key in ("primary_domain", "primaryDomain", "name", "shortname"):
        v = company.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def company_os(company):
    """Build the host.os string from a BitSight company record.

    BitSight is rating-scoped, not asset-scoped, so host.os carries
    the rating + grade label (e.g. "BitSight 750 (Advanced)") rather
    than an operating system.  Falls back to the literal "BitSight"
    if the rating is unknown.
    """
    if not isinstance(company, dict):
        return "BitSight"
    rating = company.get("rating")
    grade = company.get("rating_category") or company.get("ratingCategory")
    if not grade:
        grade = _grade_from_rating(rating)
    try:
        rating_int = int(round(float(rating))) if rating is not None else None
    except (TypeError, ValueError):
        rating_int = None
    if rating_int is not None and grade:
        return f"BitSight {rating_int} ({grade})"
    if rating_int is not None:
        return f"BitSight {rating_int}"
    if grade:
        return f"BitSight ({grade})"
    return "BitSight"


def build_host(guid, company, vulns):
    """Build a Faraday host record for the monitored BitSight company."""
    if not isinstance(company, dict):
        company = {}
    hostname = company_hostname(company)
    os_str = company_os(company)

    desc_parts = [f"company_guid={guid}"]
    for label_key, key in (
        ("company_name", "name"),
        ("primary_domain", "primary_domain"),
        ("industry", "industry"),
        ("sub_industry", "sub_industry"),
        ("rating", "rating"),
        ("rating_industry_median", "rating_industry_median"),
        ("rating_industry_percentile", "rating_industry_percentile"),
        ("ipv4_count", "ipv4_count"),
        ("people_count", "people_count"),
        ("subscription_type", "subscription_type"),
    ):
        v = company.get(key)
        if v not in (None, ""):
            desc_parts.append(f"{label_key}={v}")

    rating_details = company.get("rating_details") or company.get("ratingDetails")
    if isinstance(rating_details, dict):
        for cat, blob in rating_details.items():
            if not isinstance(blob, dict):
                continue
            grade = blob.get("grade") or blob.get("rating") or blob.get("score")
            if grade not in (None, ""):
                desc_parts.append(f"category[{cat}]={grade}")

    if vulns:
        desc_parts.append(f"findings={len(vulns)}")

    return {
        "ip": "0.0.0.0",
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_company(requests_module, guid, headers):
    """GET the BitSight company metadata record."""
    url = build_company_url(guid)
    try:
        resp = requests_module.get(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return {}
    if resp.status_code == 401:
        log("BitSight request rejected (401). Check BITSIGHT_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log("BitSight request rejected (403). Check the token's role / scope.")
        return {}
    if resp.status_code == 404:
        log(f"BitSight company {guid} not found (404).")
        return {}
    if resp.status_code >= 400:
        log(f"BitSight request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return {}
    try:
        payload = resp.json()
    except ValueError:
        log(f"BitSight response was not JSON ({url})")
        return {}
    if isinstance(payload, dict):
        return payload
    return {}


def fetch_findings(requests_module, guid, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk the BitSight findings catalogue for ``guid`` via limit/offset."""
    out = []
    url = build_findings_url(guid)
    offset = 0
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_findings_params(offset, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("BitSight request rejected (401). Check BITSIGHT_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("BitSight request rejected (403). Check the token's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"BitSight findings endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"BitSight findings request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"BitSight findings response was not JSON ({url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < page_size:
            break
        total = extract_count(payload)
        if isinstance(total, int) and (offset + len(results)) >= total:
            break
        if not extract_next_link(payload):
            # links.next is the canonical exhaustion marker — if it's
            # missing we trust it and stop even if `count` lied.
            if total is None:
                break
        offset += page_size
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    guid = validate_company_guid(env("EXECUTOR_CONFIG_BITSIGHT_COMPANY_GUID"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_BITSIGHT_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    token = env("BITSIGHT_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    company = fetch_company(requests, guid, headers)
    findings = fetch_findings(requests, guid, headers)

    log(f"Processing {len(findings)} BitSight findings for company {guid} " f"(min_severity={min_severity})")

    vulns = []
    for finding in findings:
        built = build_vulnerability(finding)
        if built is None:
            continue
        if allowed_severities and built["severity"] not in allowed_severities:
            continue
        vulns.append(built)

    host = build_host(guid, company, vulns)

    params_bits = [f"company_guid={guid}", f"min_severity={min_severity}"]

    output = {
        "hosts": [host],
        "command": {
            "tool": "bitsight",
            "command": "bitsight",
            "params": ",".join(params_bits),
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
