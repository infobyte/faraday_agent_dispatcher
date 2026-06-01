#!/usr/bin/env python
"""SecurityScorecard REST importer.

Pulls the company-level rating record (score + grade + per-factor
breakdown) and the open issue catalogue from a SecurityScorecard
tenant and emits Faraday bulk-create JSON to stdout.  Each monitored
company becomes one Faraday host (keyed by the company's primary
domain — the SecurityScorecard surface is company/domain-scoped, not
asset-scoped, so the host record is a synthetic per-company bucket
rather than an IP-keyed asset); the company's open issues attach as
Faraday vulnerabilities with the engine prefix ``[SECURITY-RATING]``.
The synthetic host carries ``host.os`` = the SSC score + grade label
("SecurityScorecard 87 (B)") so the rating itself is visible
alongside the per-factor issue findings.

Endpoints used:
  GET https://api.securityscorecard.io/companies/{domain}
      -> the monitored company's metadata (name, industry, primary
      domain, ipv4 count, employee count, score + grade, per
      factor grade breakdown).  Used to build the host
      record + host.description enrichment + host.os string.
  GET https://api.securityscorecard.io/companies/{domain}/factors
      -> the per-factor score / grade breakdown (network_security,
      dns_health, patching_cadence, endpoint_security, ip_reputation,
      application_security, cubit_score, hacker_chatter,
      leaked_information, social_engineering).  Folded into the host
      description so the factor grades are visible at a glance.
  GET https://api.securityscorecard.io/companies/{domain}/issues/{type}
  GET https://api.securityscorecard.io/companies/{domain}/issues
      -> paginated open issues (each issue = one finding tied to one
      asset / port / DNS record).  Pagination is ``page`` cursor with
      ``links.next`` / ``total`` exhaustion detection.  Each issue
      maps onto a Faraday vulnerability — severity bucketed from the
      freeform ``severity`` string enum (positive / info / low /
      medium / high) with the numeric ``severity_score`` (1-10) used
      as a CVSS-style fallback.

Auth: SecurityScorecard uses a token header where the value carries
the ``Token`` prefix — the dispatcher carries
``Authorization: Token <SSC_TOKEN>`` plus ``Accept: application/json``
on every call.  ``SSC_TOKEN`` is the API token created in the
SecurityScorecard portal under ``My Settings -> API`` (or via the
``/users/me/api-tokens`` POST).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Lenient FQDN/IP recogniser used to validate SSC_DOMAIN client-side.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
# SecurityScorecard issue-type slugs are lowercase snake_case (e.g.
# ``patching_cadence_low``, ``service_open_port``) — restrict to the
# documented shape so a typo can't fan out into a 400.
ISSUE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*$")

SSC_HOST = "https://api.securityscorecard.io"
TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# SecurityScorecard surfaces ``severity`` as a freeform string enum
# (high / medium / low / info / positive) plus a numeric
# ``severity_score`` 1-10.  The string enum buckets onto Faraday
# tiers; numeric bucketing is used as a fallback when the string is
# missing / unrecognised.  ``positive`` (an indicator of good posture,
# not a finding) is squashed to ``info`` so it ends up below any
# realistic severity floor.
SSC_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "positive": "info",
    "neutral": "info",
    "none": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# SecurityScorecard issue lifecycle is exposed through ``status`` /
# ``issue_status`` / ``state``.  Active / open map onto Faraday open;
# resolved / fixed map onto closed; risk_accepted / waived /
# false_positive / wont_fix map onto risk-accepted.
SSC_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "active": "open",
    "detected": "open",
    "current": "open",
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
    "ignored": "risk-accepted",
}


# SecurityScorecard company ratings translate into a letter grade
# A-F.  The grade ranges are documented in SSC's scoring methodology
# (https://securityscorecard.com/company/grading-methodology) and are
# reproduced here so the host.description / host.os carry the grade
# label even when the API only returned the numeric score.
def _grade_from_score(score):
    try:
        n = int(round(float(score)))
    except (TypeError, ValueError):
        return ""
    if n >= 90:
        return "A"
    if n >= 80:
        return "B"
    if n >= 70:
        return "C"
    if n >= 60:
        return "D"
    return "F"


def log(msg):
    print(f"{datetime.utcnow()} - SecurityScorecard: {msg}", file=sys.stderr, flush=True)


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


def severity_from_ssc(value, numeric=None):
    """Map a SecurityScorecard severity string onto a Faraday bucket.

    Accepts the freeform string enum (high / medium / low / info /
    positive), Faraday-side synonyms, numeric inputs (1-10
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
        if text in SSC_STRING_SEVERITY:
            return SSC_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def status_from_ssc(item):
    """Derive Faraday status from a SecurityScorecard issue payload.

    Walks ``status`` / ``issue_status`` / ``state`` and falls back to
    ``last_seen_time`` / ``first_seen_time`` for re-emitted shapes.
    """
    if not isinstance(item, dict):
        return "open"
    for key in ("status", "issue_status", "state", "Status", "State"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in SSC_STATUS_BY_STATE:
                return SSC_STATUS_BY_STATE[compact]
            if squashed in SSC_STATUS_BY_STATE:
                return SSC_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in SSC_STATUS_BY_STATE:
                        return SSC_STATUS_BY_STATE[compact]
                    if squashed in SSC_STATUS_BY_STATE:
                        return SSC_STATUS_BY_STATE[squashed]
    return "open"


def validate_min_severity(value):
    """Validate SSC_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus SSC-side synonyms
    (positive / neutral / informational -> info, moderate -> medium,
    minor -> low) plus numeric-string input bucketed via
    severity_from_cvss.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = SSC_STRING_SEVERITY.get(text)
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"SSC_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_domain(value):
    """Validate SSC_DOMAIN.

    None / blank -> sys.exit(1).  SecurityScorecard companies are
    keyed by primary domain (FQDN) or an IP literal — we hard-enforce
    the FQDN / IPv4 shape client-side so a typo can't fan out into
    "/companies/None" / "/companies/bad" calls.
    """
    if value is None or value == "":
        log("SSC_DOMAIN is required")
        sys.exit(1)
    text = str(value).strip().lower()
    if not text:
        log("SSC_DOMAIN is required")
        sys.exit(1)
    if IPV4_RE.match(text):
        return text
    if DOMAIN_RE.match(text):
        return text
    log(f"SSC_DOMAIN '{text}' is not a valid FQDN or IPv4 literal")
    sys.exit(1)


def validate_issue_type(value):
    """Validate SSC_ISSUE_TYPE (optional issue-type filter).

    None / blank -> "" (no filter; the dispatcher queries
    /companies/{domain}/issues for every type).  When set, the value
    must match the documented slug shape (lowercase snake_case);
    garbage is rejected client-side rather than fanned out into a
    400.
    """
    if value is None or value == "":
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    if not ISSUE_TYPE_RE.match(text):
        log(f"SSC_ISSUE_TYPE '{value}' is not a SecurityScorecard slug " "(lowercase snake_case); ignoring")
        return ""
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(token):
    """SecurityScorecard expects ``Authorization: Token <token>``."""
    return {
        "Authorization": f"Token {token or ''}",
        "Accept": "application/json",
    }


def build_company_url(domain):
    return f"{SSC_HOST}/companies/{domain}"


def build_factors_url(domain):
    return f"{SSC_HOST}/companies/{domain}/factors"


def build_issues_url(domain, issue_type=""):
    if issue_type:
        return f"{SSC_HOST}/companies/{domain}/issues/{issue_type}"
    return f"{SSC_HOST}/companies/{domain}/issues"


def build_issues_params(page, page_size):
    """SecurityScorecard issue pagination is ``page`` + ``page_size``."""
    return {
        "page": int(page),
        "page_size": int(page_size),
    }


def extract_results(body):
    """Pull the result list out of a SecurityScorecard pagination envelope.

    SecurityScorecard uses ``{"entries": [...], "total": N}`` on
    /issues — accept ``results`` / ``data`` / ``items`` /  ``issues``
    as alt-keys for federated stacks.
    """
    if not isinstance(body, dict):
        return []
    for key in ("entries", "results", "data", "items", "issues"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_count(body):
    """Pull the total record count from a SecurityScorecard envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("total", "count", "total_count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def extract_next_link(body):
    """Pull the ``links.next`` URL from a SecurityScorecard envelope."""
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
    """Walk a SecurityScorecard issue payload for CVE-* ids.

    SSC publishes CVE references on the ``cve`` / ``cves`` fields on
    the patching-cadence and vulnerable-services issue types plus
    inline in the description / finding details.
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

    for key in (
        "description",
        "finding_description",
        "details_description",
        "evidence",
        "summary",
        "name",
        "title",
    ):
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
    """Walk a SecurityScorecard issue payload for advisory URLs and SSC pivots."""
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

    issue_id = item.get("id") or item.get("issue_id") or item.get("issueId")
    if issue_id is not None:
        s = str(issue_id).strip()
        if s:
            add(f"SecurityScorecard-Issue: {s}")

    issue_type = item.get("issue_type") or item.get("issueType") or item.get("type")
    if isinstance(issue_type, str) and issue_type.strip():
        add(f"SecurityScorecard-IssueType: {issue_type.strip()}")

    factor = item.get("factor") or item.get("factor_name") or item.get("factorName")
    if isinstance(factor, str) and factor.strip():
        add(f"SecurityScorecard-Factor: {factor.strip()}")

    group = item.get("group") or item.get("group_name") or item.get("groupName")
    if isinstance(group, str) and group.strip():
        add(f"SecurityScorecard-Group: {group.strip()}")

    for key in ("target", "asset", "ip", "ip_address", "hostname", "domain", "subdomain"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            add(f"SecurityScorecard-Target: {v.strip()}")

    targets = item.get("targets") or item.get("assets")
    if isinstance(targets, list):
        for target in targets:
            if not isinstance(target, dict):
                if isinstance(target, str) and target.strip():
                    add(f"SecurityScorecard-Target: {target.strip()}")
                continue
            label = (
                target.get("target")
                or target.get("ip")
                or target.get("hostname")
                or target.get("domain")
                or target.get("name")
            )
            if isinstance(label, str) and label.strip():
                add(f"SecurityScorecard-Target: {label.strip()}")

    for key in ("references", "remediations", "links", "advisory_urls"):
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


def issue_label(item):
    """Build the leading title fragment for a SecurityScorecard issue."""
    if not isinstance(item, dict):
        return ""
    for key in ("issue_type_title", "issueTypeTitle", "title"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("issue_type", "issueType", "type"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().replace("_", " ").title()
    for key in ("name", "summary", "finding_description"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    details = item.get("details")
    if isinstance(details, dict):
        for key in ("description", "summary", "title"):
            v = details.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return "SecurityScorecard issue"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from an SSC issue record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    raw_numeric = item.get("severity_score") or item.get("severityScore")
    if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
        severity_numeric = float(raw_numeric)
    elif isinstance(raw_numeric, str) and raw_numeric.strip():
        try:
            severity_numeric = float(raw_numeric.strip())
        except ValueError:
            severity_numeric = None

    severity_string = item.get("severity") or item.get("severity_label") or item.get("severityLabel")
    severity = severity_from_ssc(severity_string, severity_numeric)
    status = status_from_ssc(item)

    label = issue_label(item)
    name = f"[SECURITY-RATING] {label}" if label else "[SECURITY-RATING] SecurityScorecard issue"

    desc_parts = []
    description = (
        item.get("description")
        or item.get("Description")
        or item.get("finding_description")
        or item.get("details_description")
    )
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("id", "id"),
        ("issue_id", "issue_id"),
        ("issue_type", "issue_type"),
        ("issue_type_title", "issue_type_title"),
        ("factor", "factor"),
        ("factor_name", "factor_name"),
        ("group", "group"),
        ("first_seen_time", "first_seen_time"),
        ("last_seen_time", "last_seen_time"),
        ("severity", "severity"),
        ("severity_score", "severity_score"),
        ("status", "status"),
        ("count", "count"),
        ("port", "port"),
        ("protocol", "protocol"),
        ("ip_address", "ip_address"),
        ("hostname", "hostname"),
        ("domain", "domain"),
        ("subdomain", "subdomain"),
        ("target", "target"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    details = item.get("details")
    if isinstance(details, dict):
        for label_key, key in (
            ("grade", "grade"),
            ("evidence", "evidence"),
            ("observed_ips", "observed_ips"),
            ("malware_family", "malware_family"),
            ("infection_type", "infection_type"),
            ("final_url", "final_url"),
        ):
            v = details.get(key)
            if v in (None, ""):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"details.{label_key}: {_serialise(v)}")
            else:
                desc_parts.append(f"details.{label_key}: {v}")

    targets = item.get("targets") or item.get("assets")
    if isinstance(targets, list) and targets:
        labels = []
        for target in targets:
            if isinstance(target, dict):
                tag = (
                    target.get("target")
                    or target.get("ip")
                    or target.get("hostname")
                    or target.get("domain")
                    or target.get("name")
                )
                if tag:
                    labels.append(str(tag).strip())
            elif isinstance(target, str) and target.strip():
                labels.append(target.strip())
        if labels:
            desc_parts.append(f"targets: {', '.join(labels[:20])}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    remediations = (
        item.get("remediations")
        or item.get("recommendation")
        or (details.get("remediations") if isinstance(details, dict) else None)
    )
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
            "Investigate the issue in the SecurityScorecard portal "
            "(Companies -> select company -> Issues -> select issue) "
            "and drive remediation through the affected asset owner; "
            "if the underlying asset cannot be re-graded, dispute the "
            "issue via SecurityScorecard's Issue Resolution workflow "
            "so the score impact is acknowledged."
        )

    external_id = str(item.get("id") or item.get("issue_id") or item.get("issueId") or (cves[0] if cves else ""))

    return {
        "name": str(name).strip()[:200] or f"SecurityScorecard issue {external_id}",
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
        "tags": ["securityscorecard", "security-rating", "security-ratings"],
    }


def company_hostname(company, fallback):
    """Pick the canonical hostname for a SecurityScorecard company record."""
    if isinstance(company, dict):
        for key in ("domain", "primary_domain", "primaryDomain", "name", "short_name"):
            v = company.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return ""


def company_os(company):
    """Build the host.os string from a SecurityScorecard company record.

    SSC is rating-scoped, not asset-scoped, so host.os carries the
    score + grade label (e.g. "SecurityScorecard 87 (B)") rather than
    an operating system.  Falls back to the literal "SecurityScorecard"
    if the score is unknown.
    """
    if not isinstance(company, dict):
        return "SecurityScorecard"
    score = company.get("score")
    grade = company.get("grade") or company.get("grade_letter") or company.get("gradeLetter")
    if not grade:
        grade = _grade_from_score(score)
    try:
        score_int = int(round(float(score))) if score is not None else None
    except (TypeError, ValueError):
        score_int = None
    if score_int is not None and grade:
        return f"SecurityScorecard {score_int} ({grade})"
    if score_int is not None:
        return f"SecurityScorecard {score_int}"
    if grade:
        return f"SecurityScorecard ({grade})"
    return "SecurityScorecard"


def build_host(domain, company, factors, vulns):
    """Build a Faraday host record for the monitored SSC company."""
    if not isinstance(company, dict):
        company = {}
    hostname = company_hostname(company, domain)
    os_str = company_os(company)

    desc_parts = [f"domain={domain}"]
    for label_key, key in (
        ("company_name", "name"),
        ("primary_domain", "domain"),
        ("industry", "industry"),
        ("sub_industry", "sub_industry"),
        ("score", "score"),
        ("grade", "grade"),
        ("industry_average", "industry_average"),
        ("ipv4_count", "ipv4_count"),
        ("size", "size"),
        ("employees", "employees"),
        ("subscription_type", "subscription_type"),
    ):
        v = company.get(key)
        if v not in (None, ""):
            desc_parts.append(f"{label_key}={v}")

    if isinstance(factors, list):
        for blob in factors:
            if not isinstance(blob, dict):
                continue
            name = blob.get("name") or blob.get("factor")
            grade = blob.get("grade") or blob.get("score")
            if name and grade not in (None, ""):
                desc_parts.append(f"factor[{name}]={grade}")
    elif isinstance(factors, dict):
        for name, blob in factors.items():
            if isinstance(blob, dict):
                grade = blob.get("grade") or blob.get("score")
            else:
                grade = blob
            if grade not in (None, ""):
                desc_parts.append(f"factor[{name}]={grade}")

    if vulns:
        desc_parts.append(f"issues={len(vulns)}")

    return {
        "ip": "0.0.0.0",
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_company(requests_module, domain, headers):
    """GET the SecurityScorecard company metadata record."""
    url = build_company_url(domain)
    try:
        resp = requests_module.get(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return {}
    if resp.status_code == 401:
        log("SecurityScorecard request rejected (401). Check SSC_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log("SecurityScorecard request rejected (403). Check the token's role / scope.")
        return {}
    if resp.status_code == 404:
        log(f"SecurityScorecard company {domain} not found (404).")
        return {}
    if resp.status_code >= 400:
        log(f"SecurityScorecard request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return {}
    try:
        payload = resp.json()
    except ValueError:
        log(f"SecurityScorecard response was not JSON ({url})")
        return {}
    if isinstance(payload, dict):
        return payload
    return {}


def fetch_factors(requests_module, domain, headers):
    """GET the SecurityScorecard per-factor breakdown."""
    url = build_factors_url(domain)
    try:
        resp = requests_module.get(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return []
    if resp.status_code == 401:
        log("SecurityScorecard request rejected (401). Check SSC_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log("SecurityScorecard request rejected (403). Check the token's role / scope.")
        return []
    if resp.status_code == 404:
        log(f"SecurityScorecard factors endpoint 404 for {url}")
        return []
    if resp.status_code >= 400:
        log(f"SecurityScorecard factors request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return []
    try:
        payload = resp.json()
    except ValueError:
        log(f"SecurityScorecard factors response was not JSON ({url})")
        return []
    if isinstance(payload, dict):
        for key in ("entries", "factors", "results", "data"):
            v = payload.get(key)
            if isinstance(v, list):
                return v
        return payload
    if isinstance(payload, list):
        return payload
    return []


def fetch_issues(requests_module, domain, issue_type, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk the SSC issue catalogue for ``domain`` (optionally filtered to ``issue_type``)."""
    out = []
    url = build_issues_url(domain, issue_type)
    page = 1
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_issues_params(page, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("SecurityScorecard request rejected (401). Check SSC_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("SecurityScorecard request rejected (403). Check the token's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"SecurityScorecard issues endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"SecurityScorecard issues request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"SecurityScorecard issues response was not JSON ({url})")
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
        if isinstance(total, int) and len(out) >= total:
            break
        if not extract_next_link(payload):
            # links.next is the canonical exhaustion marker — if it's
            # missing we trust it and stop even if `total` lied.
            if total is None:
                break
        page += 1
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    domain = validate_domain(env("EXECUTOR_CONFIG_SSC_DOMAIN"))
    issue_type = validate_issue_type(env("EXECUTOR_CONFIG_SSC_ISSUE_TYPE"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_SSC_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    token = env("SSC_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    company = fetch_company(requests, domain, headers)
    factors = fetch_factors(requests, domain, headers)
    issues = fetch_issues(requests, domain, issue_type, headers)

    log(
        f"Processing {len(issues)} SecurityScorecard issues for {domain} "
        f"(issue_type={issue_type or 'ALL'}, min_severity={min_severity})"
    )

    vulns = []
    for issue in issues:
        built = build_vulnerability(issue)
        if built is None:
            continue
        if allowed_severities and built["severity"] not in allowed_severities:
            continue
        vulns.append(built)

    host = build_host(domain, company, factors, vulns)

    params_bits = [
        f"domain={domain}",
        f"issue_type={issue_type or 'ALL'}",
        f"min_severity={min_severity}",
    ]

    output = {
        "hosts": [host],
        "command": {
            "tool": "securityscorecard",
            "command": "securityscorecard",
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
