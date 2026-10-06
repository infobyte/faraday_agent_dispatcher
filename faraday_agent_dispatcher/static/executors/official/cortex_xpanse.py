#!/usr/bin/env python
"""Palo Alto Cortex Xpanse Expander EASM importer.

Pulls externally-discovered services, assets and issues that match
a Cortex Xpanse Expander tenant from the Xpanse REST API and emits
Faraday bulk-create JSON to stdout.  Each Xpanse asset becomes one
Faraday host (``ip`` = the asset's first public IP, or the synthetic
``0.0.0.0`` sentinel for domain-keyed assets); per-asset services
attach as one Faraday vulnerability per exposed port + protocol,
and per-asset issues attach as one Faraday vulnerability per
``issue_id`` with engine prefix ``[EASM]`` so the data lands in the
Faraday workspace alongside the other attack-surface management
feeds.

Endpoints used:
  GET {XPANSE_HOST}/api/v1/services
      -> paginated external-service inventory. Query params carry
      ``business_unit`` (the operator-supplied filter, omitted when
      blank — Xpanse interprets a missing filter as "all business
      units the API key has access to"), ``offset`` (integer cursor,
      0 on the first request), ``limit=100`` (Xpanse's per-page
      cap on the v1 surface) and ``min_severity`` (optional
      server-side severity floor).  Response envelope is
      ``{"data": [...], "total": N, "next_offset": M}`` walked
      page-by-page until the envelope stops advancing the offset or
      ``XPANSE_PAGES`` is reached.
  GET {XPANSE_HOST}/api/v1/assets
      -> paginated external-asset inventory. Same paging shape as
      the services surface, minus the ``min_severity`` filter
      (asset records are not severity-keyed).  Assets are the
      canonical Xpanse pivot: every service / issue is joined to an
      asset_id, and the asset's ip / hostname / business-unit
      enrichment populates Faraday's host index.
  GET {XPANSE_HOST}/api/v1/issues
      -> paginated issue / finding inventory. Same paging shape as
      the services surface; issues carry severity / category /
      asset_id / cves and become Faraday vulnerabilities directly.

Auth: Cortex Xpanse uses the same Standard API Key auth flow as
the broader Cortex platform.  The operator creates an API Key in
the Xpanse console (Settings -> Configurations -> API Keys -> New)
with Security Level set to ``Standard`` (the recommended posture
for read-only data ingestion) and pastes the returned API Key Id +
API Key pair into ``XPANSE_API_KEY_ID`` + ``XPANSE_API_KEY``.
The dispatcher carries those values on every request as
``Authorization: <XPANSE_API_KEY>`` plus
``x-xdr-auth-id: <XPANSE_API_KEY_ID>`` headers (the canonical
Standard auth shape; the Advanced HMAC-signed flow is intentionally
not implemented because Standard auth is sufficient for read-only
data ingestion).  ``XPANSE_HOST`` is the FQDN-style tenant host
shown in the API Key dialog (e.g.
``api-mytenant.xpanse.paloaltonetworks.com``).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

TIMEOUT = 60
PER_PAGE = 100  # Xpanse v1 caps per_page at 100 on /services, /assets, /issues.
DEFAULT_PAGES = 5
MAX_PAGES = 50

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Xpanse uses string severities on the issues surface. Aliases collapse
# operator-friendly inputs (Important / Major / Moderate / etc.) onto
# the canonical Faraday bucket so a hand-curated Xpanse rule that
# carries a non-canonical label still pivots correctly.
XPANSE_STRING_SEVERITY = {
    "critical": "critical",
    "crit": "critical",
    "sev1": "critical",
    "severity_1": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "sev2": "high",
    "severity_2": "high",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "sev3": "medium",
    "severity_3": "medium",
    "low": "low",
    "minor": "low",
    "sev4": "low",
    "severity_4": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
    "sev5": "info",
    "severity_5": "info",
}

# Xpanse issue.status -> Faraday status. ``new`` / ``in_progress`` map
# onto Faraday ``open`` (the issue is still active). ``resolved`` /
# ``closed`` map onto Faraday ``closed`` (the analyst neutralised the
# finding). ``risk_accepted`` / ``false_positive`` / ``wont_fix`` map
# onto Faraday ``risk-accepted`` (analyst dispositioned the finding as
# a non-issue).
XPANSE_STATUS = {
    "new": "open",
    "open": "open",
    "active": "open",
    "in_progress": "open",
    "inprogress": "open",
    "reopened": "open",
    "investigating": "open",
    "under_investigation": "open",
    "resolved": "closed",
    "closed": "closed",
    "remediated": "closed",
    "fixed": "closed",
    "mitigated": "closed",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "fp": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "dismissed": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - Cortex Xpanse: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on XPANSE_HOST.

    No default — the Xpanse tenant host is operator-specific (each
    tenant has its own FQDN) so we sys.exit(1) upstream in ``main``
    when the env var is missing.  Here we just whitespace-trim,
    strip trailing slashes and add ``https://`` when the operator
    pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_business_unit(value):
    """Validate XPANSE_BUSINESS_UNIT (optional asset/issue scope filter).

    None / blank -> ``""`` (no filter; Xpanse returns the union of
    all business units the API key has access to).  Anything else is
    forwarded verbatim — Xpanse interprets the filter as a free-form
    name match against the asset's ``business_unit`` field.
    """
    if value is None:
        return ""
    text = str(value).strip()
    return text


def validate_min_severity(value):
    """Validate XPANSE_MIN_SEVERITY (optional severity floor).

    None / blank -> ``""`` (no server-side filter; we still emit the
    full hits surface).  Accepts the canonical Faraday severity enum
    (info / low / medium / high / critical) plus the Xpanse-side
    aliases (Important / Major / Moderate / Informational / etc.).
    Garbage -> ``""`` with a log line.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    if text in VALID_MIN_SEVERITY:
        return text
    bucket = XPANSE_STRING_SEVERITY.get(text)
    if bucket is not None:
        return bucket
    log(f"XPANSE_MIN_SEVERITY '{value}' not recognised; ignoring filter")
    return ""


def validate_pages(value):
    """Validate XPANSE_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Xpanse API (which is rate-limited per tenant).
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"XPANSE_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"XPANSE_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_services_url(host):
    return f"{normalize_base_url(host)}/api/v1/services"


def build_assets_url(host):
    return f"{normalize_base_url(host)}/api/v1/assets"


def build_issues_url(host):
    return f"{normalize_base_url(host)}/api/v1/issues"


def build_paged_params(business_unit, min_severity, offset, include_severity):
    """Build the GET query params for an Xpanse v1 search surface.

    ``business_unit`` filters the result set to a named BU when
    non-empty; ``min_severity`` is the server-side severity floor on
    severity-keyed surfaces (services + issues); ``offset`` is the
    integer cursor (0 on the first request); ``include_severity`` is
    a boolean — the /assets surface ignores severity so we omit the
    param there to keep the URL clean.
    """
    params = {"limit": PER_PAGE, "offset": int(offset) if offset is not None else 0}
    if business_unit:
        params["business_unit"] = business_unit
    if include_severity and min_severity:
        params["min_severity"] = min_severity
    return params


def auth_headers(api_key_id, api_key):
    """Return the Standard Cortex Xpanse auth header pair."""
    return {
        "Authorization": str(api_key),
        "x-xdr-auth-id": str(api_key_id),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_hits(body):
    """Pull the hits list from an Xpanse v1 search envelope.

    Xpanse uses ``{"data": [...], "total": N, "next_offset": M}`` on
    every v1 search surface.  Some federated / legacy stacks expose
    the hits at the envelope root or under ``results`` / ``items`` /
    ``reply.data`` — accept all three for resilience.
    """
    if not isinstance(body, dict):
        return []
    reply = body.get("reply")
    if isinstance(reply, dict):
        data = reply.get("data")
        if isinstance(data, list):
            return data
        for key in ("services", "assets", "issues", "results", "items"):
            v = reply.get(key)
            if isinstance(v, list):
                return v
    for key in ("data", "results", "items", "hits", "services", "assets", "issues"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_next_offset(body, current_offset, page_size):
    """Pull the next-page offset from an Xpanse v1 search envelope.

    Xpanse's canonical shape is ``{"data": [...], "next_offset": M}``.
    Some shapes carry the cursor as ``offset`` / ``next`` / under the
    ``reply`` envelope; we walk all of those.  Falls back to
    ``current_offset + page_size`` when the envelope is silent and
    the current page is full (the cursor is implicit on Xpanse's
    older surfaces).
    """
    if isinstance(body, dict):
        reply = body.get("reply")
        if isinstance(reply, dict):
            for key in ("next_offset", "nextOffset", "next"):
                v = reply.get(key)
                if isinstance(v, int):
                    return v
                if isinstance(v, str) and v.strip().lstrip("-").isdigit():
                    return int(v.strip())
        for key in ("next_offset", "nextOffset", "next"):
            v = body.get(key)
            if isinstance(v, int):
                return v
            if isinstance(v, str) and v.strip().lstrip("-").isdigit():
                return int(v.strip())
    return None


def extract_total(body):
    if not isinstance(body, dict):
        return None
    reply = body.get("reply")
    if isinstance(reply, dict):
        for key in ("total", "total_count", "totalCount", "totalResults"):
            v = reply.get(key)
            if isinstance(v, int):
                return v
    for key in ("total", "total_count", "totalCount", "totalResults"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def severity_from_xpanse(item, cvss=None):
    """Bucket an Xpanse item shape onto a Faraday severity.

    Walks the canonical string ``severity`` field first; falls back
    to ``priority`` / ``risk_rating`` (Xpanse-side alias fields);
    falls back to CVSS when nothing else lands.  Default is ``info``
    (Xpanse surfaces attack-surface discoveries, not vulnerability
    findings).
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            text = item.strip().lower()
            if text in XPANSE_STRING_SEVERITY:
                return XPANSE_STRING_SEVERITY[text]
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    for key in ("severity", "Severity", "issue_severity"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in XPANSE_STRING_SEVERITY:
                return XPANSE_STRING_SEVERITY[text]

    for key in ("priority", "risk_rating", "riskRating"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in XPANSE_STRING_SEVERITY:
                return XPANSE_STRING_SEVERITY[text]

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


def status_from_xpanse(item):
    """Map an Xpanse issue payload to a Faraday status."""
    if not isinstance(item, dict):
        return "open"
    for key in ("status", "Status", "issue_status", "state"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower().replace(" ", "_").replace("-", "_")
            if text in XPANSE_STATUS:
                return XPANSE_STATUS[text]
    return "open"


def passes_min_severity(severity, min_severity):
    """Client-side severity floor for non-server-filtered shapes."""
    if not min_severity:
        return True
    floor = SEVERITY_ORDER.get(min_severity, 0)
    have = SEVERITY_ORDER.get(severity, 0)
    return have >= floor


def collect_cves(item):
    """Walk an Xpanse item for CVE-* ids."""
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

    for key in ("name", "title", "description", "summary", "details", "remediation"):
        scan(item.get(key))
    return found


def collect_refs(asset, item=None):
    """Walk an Xpanse asset + item for advisory URLs / pivots."""
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

    if isinstance(asset, dict):
        aid = asset.get("asset_id") or asset.get("id") or asset.get("assetId")
        if aid:
            add(f"Xpanse-Asset: {aid}")
        for key in ("asset_name", "name", "domain", "hostname"):
            v = asset.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Xpanse-AssetName: {v.strip()}")
                break
        for key in ("business_unit", "business_units"):
            v = asset.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Xpanse-BusinessUnit: {v.strip()}")
            elif isinstance(v, list):
                for bu in v:
                    if isinstance(bu, str) and bu.strip():
                        add(f"Xpanse-BusinessUnit: {bu.strip()}")

    if isinstance(item, dict):
        iid = item.get("issue_id") or item.get("id") or item.get("service_id")
        if iid:
            add(f"Xpanse-Id: {iid}")
        for key in ("category", "issue_type", "service_type"):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Xpanse-Category: {v.strip()}")
                break
        port = item.get("port")
        proto = item.get("protocol") or item.get("transport_protocol")
        if port is not None:
            add(f"Xpanse-Port: {port}/{(proto or 'tcp').lower()}")
        for url_key in ("url", "reference_url", "external_url"):
            v = item.get(url_key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def asset_ip(asset):
    """Pick the asset IP from an Xpanse asset.

    Xpanse assets carry ``ip`` at the top level on IP-keyed shapes
    and ``ips`` (a list) on multi-IP shapes; domain-keyed assets
    have no IP at all (they're CNAME / NS / MX records).  Loopback
    / zero are explicitly skipped because Xpanse would not return
    them in real data.
    """
    if not isinstance(asset, dict):
        return "0.0.0.0"
    for key in ("ip", "ip_address", "ipAddress"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1"):
            return v.strip()
    for key in ("ips", "ip_addresses", "ipAddresses"):
        v = asset.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip() and entry.strip() not in ("0.0.0.0", "127.0.0.1"):
                    return entry.strip()
                if isinstance(entry, dict):
                    sub = entry.get("ip") or entry.get("address")
                    if isinstance(sub, str) and sub.strip() and sub.strip() not in ("0.0.0.0", "127.0.0.1"):
                        return sub.strip()
    return "0.0.0.0"


def asset_hostnames(asset):
    """Walk an Xpanse asset for hostname candidates."""
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

    if not isinstance(asset, dict):
        return out

    for key in ("asset_name", "name", "domain", "hostname", "fqdn"):
        add(asset.get(key))

    for list_key in ("domains", "hostnames", "fqdns", "names"):
        v = asset.get(list_key)
        if isinstance(v, list):
            for n in v:
                if isinstance(n, str):
                    add(n)
                elif isinstance(n, dict):
                    add(n.get("name") or n.get("domain") or n.get("hostname"))
    return out


def service_to_faraday_service(service):
    """Build a Faraday service dict from an Xpanse service block."""
    if not isinstance(service, dict):
        return None
    try:
        port = int(service.get("port"))
    except (TypeError, ValueError):
        return None
    proto = service.get("protocol") or service.get("transport_protocol") or "tcp"
    name = (
        service.get("service_type")
        or service.get("serviceType")
        or service.get("name")
        or service.get("service_name")
        or "unknown"
    )
    return {
        "name": str(name).lower(),
        "protocol": str(proto).lower(),
        "port": port,
        "status": "open",
    }


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


def build_service_vulnerability(asset, service):
    """Build a Faraday vulnerability dict for one Xpanse service exposure."""
    if not isinstance(service, dict):
        return None
    name = (
        service.get("service_type")
        or service.get("serviceType")
        or service.get("name")
        or service.get("service_name")
        or "unknown service"
    )
    port = service.get("port")
    proto = (service.get("protocol") or service.get("transport_protocol") or "tcp").lower()
    label = f"[EASM] Xpanse exposed {str(name).strip()} on {port}/{proto}"

    desc_parts = []
    for key in (
        "service_id",
        "service_type",
        "service_name",
        "protocol",
        "transport_protocol",
        "port",
        "tls_version",
        "banner",
        "first_observed",
        "last_observed",
        "discovery_type",
        "cloud_provider",
        "ip",
        "domain",
    ):
        v = service.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{key}: {v}")

    severity = severity_from_xpanse(service)
    cves = collect_cves(service)
    if not cves:
        cves = collect_cves(asset)
    refs = collect_refs(asset, service)

    external_id_bits = []
    ip = asset_ip(asset)
    if ip and ip != "0.0.0.0":
        external_id_bits.append(ip)
    sid = service.get("service_id") or service.get("id")
    if sid:
        external_id_bits.append(str(sid))
    elif port is not None:
        external_id_bits.append(f"{port}/{proto}")
    external_id = ":".join(external_id_bits) if external_id_bits else label

    resolution = (
        "Verify whether this service should be reachable from the public "
        "internet.  If not, restrict access via firewall rules / security "
        "groups or shut down the listener.  If the exposure is intentional, "
        "confirm the service is patched + authentication-gated and that the "
        "underlying TLS certificate is trusted."
    )

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["cortex_xpanse", "easm"],
    }


def build_issue_vulnerability(asset, issue):
    """Build a Faraday vulnerability dict for one Xpanse issue."""
    if not isinstance(issue, dict):
        return None
    name = issue.get("name") or issue.get("title") or issue.get("issue_type") or "Xpanse issue"
    label = f"[EASM] Xpanse {str(name).strip()}"

    desc_parts = []
    for key in (
        "issue_id",
        "issue_type",
        "category",
        "description",
        "summary",
        "details",
        "asset_id",
        "asset_name",
        "business_unit",
        "first_observed",
        "last_observed",
        "port",
        "protocol",
        "service_id",
        "ip",
        "domain",
        "cloud_provider",
    ):
        v = issue.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{key}: {v}")

    severity = severity_from_xpanse(issue, cvss=issue.get("cvss") or issue.get("cvssScore"))
    status = status_from_xpanse(issue)
    cves = collect_cves(issue)
    if not cves:
        cves = collect_cves(asset)
    refs = collect_refs(asset, issue)

    iid = issue.get("issue_id") or issue.get("id")
    external_id = str(iid) if iid else str(label)

    resolution = (
        issue.get("remediation")
        or issue.get("remediation_guidance")
        or issue.get("recommendation")
        or (
            "Review the issue in the Cortex Xpanse console (Incidents -> "
            "Issues).  Remediate the underlying exposure (close the port, "
            "patch the service, rotate the credential) or accept the risk."
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
        "tags": ["cortex_xpanse", "easm"],
    }


def build_host_from_asset(asset, services=None, issues=None, min_severity=""):
    """Build a Faraday host dict from an Xpanse asset hit."""
    if not isinstance(asset, dict):
        return None

    ip = asset_ip(asset)
    hostnames = asset_hostnames(asset)

    desc_parts = []
    for key in ("asset_id", "asset_type", "business_unit", "cloud_provider", "first_observed", "last_observed"):
        v = asset.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    svc_list = (
        services
        if isinstance(services, list)
        else (asset.get("services") if isinstance(asset.get("services"), list) else [])
    )
    iss_list = (
        issues if isinstance(issues, list) else (asset.get("issues") if isinstance(asset.get("issues"), list) else [])
    )
    if svc_list:
        desc_parts.append(f"services={len(svc_list)}")
    if iss_list:
        desc_parts.append(f"issues={len(iss_list)}")

    vulns = []
    faraday_services = []
    for svc in svc_list:
        v = build_service_vulnerability(asset, svc)
        if v is not None and passes_min_severity(v.get("severity", "info"), min_severity):
            vulns.append(v)
        fs = service_to_faraday_service(svc)
        if fs is not None:
            faraday_services.append(fs)
    for iss in iss_list:
        v = build_issue_vulnerability(asset, iss)
        if v is not None and passes_min_severity(v.get("severity", "info"), min_severity):
            vulns.append(v)

    host = {
        "ip": ip,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }
    if faraday_services:
        host["services"] = faraday_services
    return host


def synthesise_asset(asset_id=None, asset_name=None, ip=None, business_unit=None):
    """Build a synthetic asset envelope for orphaned services / issues."""
    asset = {}
    if asset_id:
        asset["asset_id"] = asset_id
    if asset_name:
        asset["asset_name"] = asset_name
    if ip:
        asset["ip"] = ip
    if business_unit:
        asset["business_unit"] = business_unit
    return asset


def fetch_pages(requests_module, url, headers, params_builder, max_pages):
    """Walk an Xpanse v1 search envelope (offset-based pagination)."""
    out = []
    offset = 0
    walked = 0
    last_offset = -1
    while walked < max_pages:
        params = params_builder(offset)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Xpanse request rejected (401). Check XPANSE_API_KEY_ID / XPANSE_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Xpanse request rejected (403). Check the key's tier / scope.")
            return out
        if resp.status_code == 429:
            log("Xpanse rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Xpanse request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Xpanse response was not JSON ({url})")
            return out
        hits = extract_hits(payload)
        for entry in hits:
            if isinstance(entry, dict):
                out.append(entry)
        nxt = extract_next_offset(payload, offset, PER_PAGE)
        walked += 1
        # End-of-stream signals:
        # - explicit next_offset == current_offset or 0 (Xpanse stops advancing)
        # - empty page (Xpanse exhausted the result set)
        # - shorter-than-page-size payload (Xpanse implicit final page)
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
        log(f"hit XPANSE_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    business_unit = validate_business_unit(env("EXECUTOR_CONFIG_XPANSE_BUSINESS_UNIT"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_XPANSE_MIN_SEVERITY"))
    pages = validate_pages(env("EXECUTOR_CONFIG_XPANSE_PAGES"))

    host = env("XPANSE_HOST", required=True)
    api_key_id = env("XPANSE_API_KEY_ID", required=True)
    api_key = env("XPANSE_API_KEY", required=True)

    if not normalize_base_url(host):
        log("XPANSE_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(api_key_id, api_key)
    services_url = build_services_url(host)
    assets_url = build_assets_url(host)
    issues_url = build_issues_url(host)

    asset_hits = fetch_pages(
        requests,
        assets_url,
        headers,
        lambda offset: build_paged_params(business_unit, min_severity, offset, include_severity=False),
        max_pages=pages,
    )
    service_hits = fetch_pages(
        requests,
        services_url,
        headers,
        lambda offset: build_paged_params(business_unit, min_severity, offset, include_severity=True),
        max_pages=pages,
    )
    issue_hits = fetch_pages(
        requests,
        issues_url,
        headers,
        lambda offset: build_paged_params(business_unit, min_severity, offset, include_severity=True),
        max_pages=pages,
    )

    log(
        f"Processing {len(asset_hits)} Xpanse assets + {len(service_hits)} services "
        f"+ {len(issue_hits)} issues "
        f"(business_unit={business_unit!r}, min_severity={min_severity!r}, pages={pages})"
    )

    # Group services + issues by asset_id so each Faraday host carries
    # the union of its services + issues; orphans land on a synthetic
    # 0.0.0.0 host so they aren't silently dropped.
    by_asset_id = {}
    for asset in asset_hits:
        if not isinstance(asset, dict):
            continue
        aid = asset.get("asset_id") or asset.get("id") or asset.get("assetId")
        if aid:
            by_asset_id[str(aid)] = {"asset": asset, "services": [], "issues": []}

    orphan_services = []
    for svc in service_hits:
        if not isinstance(svc, dict):
            continue
        aid = svc.get("asset_id") or svc.get("assetId")
        if aid and str(aid) in by_asset_id:
            by_asset_id[str(aid)]["services"].append(svc)
        else:
            orphan_services.append(svc)

    orphan_issues = []
    for iss in issue_hits:
        if not isinstance(iss, dict):
            continue
        aid = iss.get("asset_id") or iss.get("assetId")
        if aid and str(aid) in by_asset_id:
            by_asset_id[str(aid)]["issues"].append(iss)
        else:
            orphan_issues.append(iss)

    hosts_out = []
    for bucket in by_asset_id.values():
        built = build_host_from_asset(
            bucket["asset"],
            services=bucket["services"],
            issues=bucket["issues"],
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)

    if orphan_services or orphan_issues:
        # Group orphans on a synthetic asset so they still pivot in
        # Faraday even though the /assets surface didn't return a
        # matching record (Xpanse occasionally lags its asset
        # inventory behind the services + issues feeds).
        synthetic = synthesise_asset(asset_name="(unattached)")
        built = build_host_from_asset(
            synthetic,
            services=orphan_services,
            issues=orphan_issues,
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "cortex_xpanse",
            "command": "cortex_xpanse",
            "params": (f"business_unit={business_unit}," f"min_severity={min_severity}," f"pages={pages}"),
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
