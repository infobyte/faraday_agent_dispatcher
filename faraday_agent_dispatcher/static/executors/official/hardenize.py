#!/usr/bin/env python
"""Hardenize EASM importer.

Pulls the latest TLS / email-security assessment reports for an
organisation from the Hardenize REST API and emits Faraday bulk-create
JSON to stdout.  Each Hardenize report becomes one Faraday host
(``ip`` = the report's first public IP, or the synthetic ``0.0.0.0``
sentinel for hostname-only reports — Hardenize is primarily
hostname-keyed); per-report TLS / email-security findings (DNS,
DNSSEC, MTA-STS, DKIM, SPF, DMARC, TLS-RPT, HTTPS, certificate
checks, etc.) attach as one Faraday vulnerability per finding with
the ``[EASM]`` engine prefix so the data lands in the Faraday
workspace alongside the other attack-surface management feeds.

Endpoints used:
  GET {HARDENIZE_HOST}/api/v0/orgs/{org}/reports/latest
      -> the canonical Hardenize EASM pivot.  Returns the latest
      assessment report for every host registered in the
      organisation.  Each report carries the host's domain / IP +
      per-check verdicts (pass / fail / warn / info) across the TLS
      configuration, certificate validity, email authentication
      (SPF / DKIM / DMARC), DNSSEC, MTA-STS and TLS-RPT surfaces.
      Pagination is offset-based: ``limit=100`` per page, advanced
      via the envelope's ``next_offset`` cursor (or current_offset +
      page_size when the envelope is silent — Hardenize's exact
      pagination shape is documented loosely; the executor walks
      either shape).  When the API returns the full report set in a
      single response the offset walk stops after page 1.

Auth: Hardenize uses HTTP Basic with the API user as the username
and the API key as the password — the operator creates an API key
pair in the Hardenize / Red Sift console (Settings -> API Keys ->
New) and the dispatcher carries the credentials in the standard
``Authorization: Basic <base64(USER:API_KEY)>`` header on every
``/api/v0/`` call.  ``HARDENIZE_HOST`` defaults to
``https://www.hardenize.com`` and is settable for federated
deployments without surfacing it as a canonical mandatory env var
(the playbook only mandates the user + api key pair plus the org
slug).
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

TIMEOUT = 60
PER_PAGE = 100  # Hardenize v0 caps limit at 100 on reports/latest.
DEFAULT_PAGES = 5
MAX_PAGES = 50
DEFAULT_HOST = "https://www.hardenize.com"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

HARDENIZE_STRING_SEVERITY = {
    "critical": "critical",
    "crit": "critical",
    "fail": "critical",
    "failure": "critical",
    "failed": "critical",
    "error": "critical",
    "sev1": "critical",
    "severity_1": "critical",
    "p1": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "danger": "high",
    "sev2": "high",
    "severity_2": "high",
    "p2": "high",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "warn": "medium",
    "warning": "medium",
    "sev3": "medium",
    "severity_3": "medium",
    "p3": "medium",
    "low": "low",
    "minor": "low",
    "notice": "low",
    "sev4": "low",
    "severity_4": "low",
    "p4": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "pass": "info",
    "passed": "info",
    "ok": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
    "neutral": "info",
    "sev5": "info",
    "severity_5": "info",
    "p5": "info",
}

HARDENIZE_STATUS = {
    "new": "open",
    "open": "open",
    "active": "open",
    "fail": "open",
    "failed": "open",
    "failure": "open",
    "warn": "open",
    "warning": "open",
    "in_progress": "open",
    "inprogress": "open",
    "reopened": "open",
    "investigating": "open",
    "under_investigation": "open",
    "pending": "open",
    "triaged": "open",
    "pass": "closed",
    "passed": "closed",
    "ok": "closed",
    "resolved": "closed",
    "closed": "closed",
    "remediated": "closed",
    "fixed": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "fp": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "dismissed": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "skipped": "risk-accepted",
    "n/a": "risk-accepted",
    "na": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - Hardenize: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host, default=DEFAULT_HOST):
    """Trim trailing slash + tolerate operator typos on HARDENIZE_HOST.

    None / blank / non-string -> ``default`` (the public
    ``https://www.hardenize.com`` SaaS host).  Whitespace-trims,
    strips trailing slashes and adds ``https://`` when the operator
    pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return default or ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_org(value):
    """Validate HARDENIZE_ORG (the organisation slug).

    Mandatory at the ``main()`` boundary — ``sys.exit(1)`` on blank.
    Anything else whitespace-trimmed and forwarded verbatim.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_host_filter(value):
    """Validate HARDENIZE_HOST_FILTER (optional client-side hostname filter).

    None / blank -> ``""`` (no narrowing; every host in the org is
    emitted).  Anything else whitespace-trimmed and lower-cased for
    case-insensitive matching.  Hardenize's reports/latest surface
    does not have a documented server-side hostname filter so this
    is applied client-side as a substring match against the report's
    hostname / domain / target fields.
    """
    if value is None:
        return ""
    return str(value).strip().lower()


def validate_min_severity(value):
    """Validate HARDENIZE_MIN_SEVERITY (optional severity floor).

    None / blank -> ``""`` (no client-side filter; we emit the full
    findings surface).  Accepts the canonical Faraday severity enum
    (info / low / medium / high / critical) plus the Hardenize-side
    aliases (pass / warn / fail / Important / Major / Moderate /
    Informational / Negligible / Sev1..Sev5 / P1..P5).  Garbage ->
    ``""`` with a log line.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    if text in VALID_MIN_SEVERITY:
        return text
    bucket = HARDENIZE_STRING_SEVERITY.get(text)
    if bucket is not None:
        return bucket
    log(f"HARDENIZE_MIN_SEVERITY '{value}' not recognised; ignoring filter")
    return ""


def validate_pages(value):
    """Validate HARDENIZE_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Hardenize API.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"HARDENIZE_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"HARDENIZE_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_reports_url(host, org):
    return f"{normalize_base_url(host)}/api/v0/orgs/{org}/reports/latest"


def build_paged_params(offset, limit=PER_PAGE):
    """Build the query-param dict for a Hardenize v0 reports surface."""
    return {"limit": int(limit), "offset": int(offset) if offset is not None else 0}


def auth_credentials(user, api_key):
    """Return the HTTP Basic credential tuple for requests.get(auth=...)."""
    return (str(user) if user is not None else "", str(api_key) if api_key is not None else "")


def auth_headers():
    """Return the static header set (Accept + Content-Type).

    HTTP Basic credentials are passed via ``requests.get(auth=...)``
    rather than a pre-baked Authorization header so requests'
    standard credential handling kicks in (urllib3 redirect handling
    will strip a manually-built Authorization header on cross-host
    redirects, which we don't want).
    """
    return {"Accept": "application/json", "Content-Type": "application/json"}


def basic_auth_header(user, api_key):
    """Build the canonical Authorization: Basic header string.

    Exposed for tests + for callers that need to send the credential
    inline (e.g. fixture replays that don't honour ``auth=``).
    """
    raw = f"{user or ''}:{api_key or ''}".encode("utf-8")
    return f"Basic {base64.b64encode(raw).decode('ascii')}"


def extract_hits(body):
    """Pull the hits list from a Hardenize v0 envelope.

    Hardenize returns ``{"reports": [...]}`` on the canonical
    ``reports/latest`` surface; we also accept ``data`` / ``results``
    / ``items`` / ``hits`` / ``hosts`` fallbacks for federated /
    legacy / future shapes plus root-list passthrough.
    """
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("reports", "data", "results", "items", "hits", "hosts"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_next_offset(body, current_offset, page_size):
    """Pull the next-page offset from a Hardenize v0 envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("next_offset", "nextOffset", "next"):
        v = body.get(key)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.strip().lstrip("-").isdigit():
            return int(v.strip())
    pagination = body.get("pagination")
    if isinstance(pagination, dict):
        for key in ("next_offset", "nextOffset", "next", "offset"):
            v = pagination.get(key)
            if isinstance(v, int):
                return v
            if isinstance(v, str) and v.strip().lstrip("-").isdigit():
                return int(v.strip())
    return None


def extract_total(body):
    if not isinstance(body, dict):
        return None
    for key in ("total", "total_count", "totalCount", "totalResults", "count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def severity_from_hardenize(item, cvss=None):
    """Bucket a Hardenize item shape onto a Faraday severity.

    Walks the canonical string ``severity`` field first; falls back
    to the Hardenize check-verdict alt fields (``verdict`` / ``status``
    / ``result`` / ``grade``); falls back to ``priority`` /
    ``risk_rating`` / ``risk_score`` (alias / score fields); falls
    back to CVSS when nothing else lands.  Default is ``info`` (most
    Hardenize check verdicts are pass / informational).
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            text = item.strip().lower()
            if text in HARDENIZE_STRING_SEVERITY:
                return HARDENIZE_STRING_SEVERITY[text]
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    for key in ("severity", "Severity", "issue_severity", "finding_severity"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in HARDENIZE_STRING_SEVERITY:
                return HARDENIZE_STRING_SEVERITY[text]

    for key in ("verdict", "result", "grade", "outcome"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in HARDENIZE_STRING_SEVERITY:
                return HARDENIZE_STRING_SEVERITY[text]

    for key in ("priority", "risk_rating", "riskRating"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in HARDENIZE_STRING_SEVERITY:
                return HARDENIZE_STRING_SEVERITY[text]

    risk_score = item.get("risk_score") or item.get("riskScore")
    if risk_score is not None:
        try:
            score = float(risk_score)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            # Hardenize doesn't publish a canonical risk-score scale;
            # we bucket on a 0..10 scale matching the other EASM
            # executors.
            if score >= 8:
                return "critical"
            if score >= 6:
                return "high"
            if score >= 4:
                return "medium"
            if score >= 2:
                return "low"
            if score > 0:
                return "info"

    for key in ("cvss_score", "cvssScore", "cvss"):
        v = item.get(key)
        if v is not None:
            return severity_from_cvss(v)

    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


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


def status_from_hardenize(item):
    """Map a Hardenize finding payload to a Faraday status."""
    if not isinstance(item, dict):
        return "open"
    for key in ("status", "Status", "issue_status", "finding_status", "state", "verdict", "result"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower().replace(" ", "_").replace("-", "_")
            if text in HARDENIZE_STATUS:
                return HARDENIZE_STATUS[text]
    return "open"


def passes_min_severity(severity, min_severity):
    """Client-side severity floor for non-server-filtered shapes."""
    if not min_severity:
        return True
    floor = SEVERITY_ORDER.get(min_severity, 0)
    have = SEVERITY_ORDER.get(severity, 0)
    return have >= floor


def passes_host_filter(report, host_filter):
    """Client-side hostname substring filter.

    Walks the canonical Hardenize hostname fields (``hostname`` /
    ``host`` / ``domain`` / ``name`` / ``target`` / ``fqdn``); empty
    filter -> True.  Match is case-insensitive substring (filter is
    already lower-cased by ``validate_host_filter``).
    """
    if not host_filter:
        return True
    if not isinstance(report, dict):
        return False
    for key in ("hostname", "host", "domain", "name", "target", "fqdn"):
        v = report.get(key)
        if isinstance(v, str) and host_filter in v.strip().lower():
            return True
    return False


def collect_cves(item):
    """Walk a Hardenize item for CVE-* ids."""
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

    for list_key in ("cves", "cve_ids", "matched_vulnerabilities", "vulnerabilities"):
        v = item.get(list_key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("cveId") or entry.get("id"))
                elif isinstance(entry, str):
                    add(entry)

    for key in ("name", "title", "description", "summary", "details", "remediation", "message"):
        scan(item.get(key))
    return found


def collect_refs(report, item=None):
    """Walk a Hardenize report + finding for advisory URLs / pivots."""
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

    if isinstance(report, dict):
        rid = report.get("report_id") or report.get("id") or report.get("uuid")
        if rid:
            add(f"Hardenize-Report: {rid}")
        for key in ("hostname", "host", "domain", "name", "target", "fqdn"):
            v = report.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Hardenize-Host: {v.strip()}")
                break
        org = report.get("org") or report.get("organization") or report.get("org_slug")
        if isinstance(org, str) and org.strip():
            add(f"Hardenize-Org: {org.strip()}")

    if isinstance(item, dict):
        check_id = (
            item.get("check_id") or item.get("checkId") or item.get("id") or item.get("finding_id") or item.get("name")
        )
        if check_id:
            add(f"Hardenize-Check: {check_id}")
        for key in ("category", "section", "group", "module", "check_type", "type"):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Hardenize-Category: {v.strip()}")
                break
        for url_key in ("url", "reference_url", "external_url", "evidence_url", "documentation_url", "doc_url"):
            v = item.get(url_key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def report_ip(report):
    """Pick the IP from a Hardenize report.

    Hardenize is primarily hostname-keyed; reports may carry a
    resolved ``ip`` / ``ipv4`` / ``ipv6`` (or a list of resolved
    addresses).  Loopback / zero are explicitly skipped because
    Hardenize would not return them in real data.  Defaults to the
    synthetic ``0.0.0.0`` sentinel when no IP is present.
    """
    if not isinstance(report, dict):
        return "0.0.0.0"
    for key in ("ip", "ip_address", "ipAddress", "ipv4", "ipv6"):
        v = report.get(key)
        if isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1", "::1"):
            return v.strip()
    for key in ("ips", "ip_addresses", "ipAddresses", "addresses", "resolved_ips"):
        v = report.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip() and entry.strip() not in ("0.0.0.0", "127.0.0.1", "::1"):
                    return entry.strip()
                if isinstance(entry, dict):
                    sub = entry.get("ip") or entry.get("address") or entry.get("ipv4") or entry.get("ipv6")
                    if isinstance(sub, str) and sub.strip() and sub.strip() not in ("0.0.0.0", "127.0.0.1", "::1"):
                        return sub.strip()
    return "0.0.0.0"


def report_hostnames(report):
    """Walk a Hardenize report for hostname candidates."""
    out = []
    seen = set()

    def add(text):
        if not isinstance(text, str):
            return
        s = text.strip()
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if not isinstance(report, dict):
        return out

    for key in ("hostname", "host", "domain", "name", "target", "fqdn"):
        add(report.get(key))

    for list_key in ("hostnames", "domains", "fqdns", "names", "aliases", "subdomains"):
        v = report.get(list_key)
        if isinstance(v, list):
            for n in v:
                if isinstance(n, str):
                    add(n)
                elif isinstance(n, dict):
                    add(n.get("name") or n.get("domain") or n.get("hostname"))
    return out


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


def iter_findings(report):
    """Walk a Hardenize report for per-check finding payloads.

    Hardenize reports group per-check verdicts under several list /
    dict keys: ``findings`` / ``issues`` / ``problems`` (the
    canonical attention-worthy entries) and ``checks`` / ``results``
    / ``sections`` (the full check catalogue).  We walk all of them
    so callers can pick the shape that matches their tenant — and
    flatten any nested ``children`` / ``items`` / ``issues`` /
    ``findings`` arrays so per-section sub-findings surface as
    standalone Faraday vulns.
    """
    out = []
    if not isinstance(report, dict):
        return out
    seen = set()

    def collect(node):
        if isinstance(node, list):
            for entry in node:
                collect(entry)
            return
        if not isinstance(node, dict):
            return
        marker = id(node)
        if marker in seen:
            return
        seen.add(marker)
        out.append(node)
        for child_key in ("children", "items", "issues", "findings", "subchecks", "sub_checks"):
            child = node.get(child_key)
            if isinstance(child, list):
                for entry in child:
                    collect(entry)

    for list_key in (
        "findings",
        "issues",
        "problems",
        "alerts",
        "checks",
        "results",
        "sections",
        "tests",
    ):
        v = report.get(list_key)
        if isinstance(v, list):
            for entry in v:
                collect(entry)
    return out


def build_finding_vulnerability(report, finding):
    """Build a Faraday vulnerability dict for one Hardenize finding."""
    if not isinstance(finding, dict):
        return None
    name = (
        finding.get("name")
        or finding.get("title")
        or finding.get("check_name")
        or finding.get("check_id")
        or finding.get("id")
        or finding.get("category")
        or "Hardenize finding"
    )
    label = f"[EASM] Hardenize {str(name).strip()}"

    desc_parts = []
    for key in (
        "check_id",
        "checkId",
        "id",
        "finding_id",
        "name",
        "title",
        "category",
        "section",
        "group",
        "module",
        "check_type",
        "description",
        "summary",
        "details",
        "message",
        "rationale",
        "verdict",
        "result",
        "grade",
        "outcome",
        "status",
        "hostname",
        "host",
        "domain",
        "target",
        "ip",
        "port",
        "protocol",
        "url",
        "first_seen",
        "last_seen",
        "first_observed",
        "last_observed",
        "evidence",
        "expected",
        "actual",
    ):
        v = finding.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{key}: {v}")

    severity = severity_from_hardenize(
        finding,
        cvss=finding.get("cvss") or finding.get("cvssScore") or finding.get("cvss_score"),
    )
    status = status_from_hardenize(finding)
    cves = collect_cves(finding)
    if not cves:
        cves = collect_cves(report)
    refs = collect_refs(report, finding)

    fid = finding.get("check_id") or finding.get("checkId") or finding.get("id") or finding.get("finding_id")
    external_id = str(fid) if fid else str(label)

    resolution = (
        finding.get("remediation")
        or finding.get("remediation_guidance")
        or finding.get("recommendation")
        or finding.get("fix")
        or (
            "Review the finding in the Hardenize console (Org -> "
            "Reports -> the target host).  Remediate the underlying "
            "TLS / email-security misconfiguration (rotate the "
            "certificate, harden the TLS profile, fix the DMARC / "
            "SPF / DKIM record, enable DNSSEC / MTA-STS / TLS-RPT) "
            "or accept the risk."
        )
    )

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["hardenize", "easm"],
    }


def is_attention_finding(finding):
    """Return True when a finding represents a non-passing verdict.

    Hardenize reports include both the failing / warning checks and
    the passing / informational ones; we only emit a Faraday
    vulnerability for the attention-worthy entries to avoid drowning
    the workspace in pass=info noise.  Anything without a recognised
    pass / ok verdict is treated as attention-worthy so unfamiliar
    shapes still surface rather than being silently dropped.
    """
    if not isinstance(finding, dict):
        return False
    for key in ("verdict", "result", "status", "outcome"):
        raw = finding.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in ("pass", "passed", "ok", "success", "succeeded", "info", "informational"):
                return False
    return True


def build_host_from_report(report, min_severity="", host_filter=""):
    """Build a Faraday host dict from a Hardenize report."""
    if not isinstance(report, dict):
        return None
    if not passes_host_filter(report, host_filter):
        return None

    ip = report_ip(report)
    hostnames = report_hostnames(report)

    desc_parts = []
    for key in (
        "report_id",
        "id",
        "uuid",
        "org",
        "organization",
        "org_slug",
        "asset_type",
        "grade",
        "score",
        "risk_score",
        "created_at",
        "updated_at",
        "first_seen",
        "last_seen",
        "scanned_at",
        "last_assessed",
        "verdict",
        "result",
        "outcome",
        "category",
        "tags",
    ):
        v = report.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    findings = [f for f in iter_findings(report) if is_attention_finding(f)]
    if findings:
        desc_parts.append(f"findings={len(findings)}")

    vulns = []
    for f in findings:
        v = build_finding_vulnerability(report, f)
        if v is not None and passes_min_severity(v.get("severity", "info"), min_severity):
            vulns.append(v)

    return {
        "ip": ip,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def synthesise_report(hostname=None, ip=None, org=None):
    """Build a synthetic report envelope for orphaned findings."""
    report = {}
    if hostname:
        report["hostname"] = hostname
    if ip:
        report["ip"] = ip
    if org:
        report["org"] = org
    return report


def fetch_pages(requests_module, url, auth, headers, params_builder, max_pages):
    """Walk a Hardenize v0 search envelope (offset-based pagination).

    Mirrors the Hadrian executor's offset walk shape because the two
    APIs share the same general envelope.  Stops on empty page,
    short page (< page size), cycle (next_offset == current_offset
    or <= 0), or when ``max_pages`` is reached.
    """
    out = []
    offset = 0
    walked = 0
    last_offset = -1
    hits = []
    while walked < max_pages:
        params = params_builder(offset)
        try:
            resp = requests_module.get(
                url,
                headers=headers,
                params=params,
                auth=auth,
                timeout=TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Hardenize request rejected (401). Check HARDENIZE_USER / HARDENIZE_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Hardenize request rejected (403). Check the API key's org scope.")
            return out
        if resp.status_code == 429:
            log("Hardenize rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Hardenize request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Hardenize response was not JSON ({url})")
            return out
        hits = extract_hits(payload)
        for entry in hits:
            if isinstance(entry, dict):
                out.append(entry)
        nxt = extract_next_offset(payload, offset, PER_PAGE)
        walked += 1
        if not hits:
            break
        if len(hits) < PER_PAGE:
            break
        if nxt is None:
            offset = offset + PER_PAGE
        elif nxt == offset or nxt == last_offset or nxt <= 0:
            break
        else:
            offset = nxt
        if offset == last_offset:
            break
        last_offset = offset
    if walked >= max_pages and hits:
        log(f"hit HARDENIZE_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    org = validate_org(env("EXECUTOR_CONFIG_HARDENIZE_ORG"))
    host_filter = validate_host_filter(env("EXECUTOR_CONFIG_HARDENIZE_HOST_FILTER"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_HARDENIZE_MIN_SEVERITY"))
    pages = validate_pages(env("EXECUTOR_CONFIG_HARDENIZE_PAGES"))

    if not org:
        log("HARDENIZE_ORG is required")
        sys.exit(1)

    host = env("HARDENIZE_HOST") or DEFAULT_HOST
    user = env("HARDENIZE_USER", required=True)
    api_key = env("HARDENIZE_API_KEY", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers()
    auth = auth_credentials(user, api_key)
    reports_url = build_reports_url(host, org)

    report_hits = fetch_pages(
        requests,
        reports_url,
        auth,
        headers,
        lambda offset: build_paged_params(offset),
        max_pages=pages,
    )

    log(
        f"Processing {len(report_hits)} Hardenize reports "
        f"(org={org!r}, host_filter={host_filter!r}, "
        f"min_severity={min_severity!r}, pages={pages})"
    )

    hosts_out = []
    for report in report_hits:
        built = build_host_from_report(
            report,
            min_severity=min_severity,
            host_filter=host_filter,
        )
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "hardenize",
            "command": "hardenize",
            "params": (f"org={org}," f"host_filter={host_filter}," f"min_severity={min_severity}," f"pages={pages}"),
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
