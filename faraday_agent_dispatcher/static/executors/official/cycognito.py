#!/usr/bin/env python
"""CyCognito EASM importer.

Pulls externally-discovered assets and issues that match a CyCognito
realm (organisation) from the CyCognito REST API and emits Faraday
bulk-create JSON to stdout.  Each CyCognito asset becomes one Faraday
host (``ip`` = the asset's first public IP, or the synthetic
``0.0.0.0`` sentinel for domain-keyed assets); per-asset issues
attach as one Faraday vulnerability per ``issue_id`` with engine
prefix ``[EASM]`` so the data lands in the Faraday workspace
alongside the other attack-surface management feeds.

Endpoints used:
  POST {CYCOG_HOST}/v1/assets
      -> paginated external-asset inventory. JSON body carries
      ``realm`` (the operator-supplied organisation identifier),
      ``offset`` (integer cursor, 0 on the first request),
      ``count=100`` (CyCognito's per-page cap on the v1 search
      surface) and ``filter`` (the operator-supplied JSON filter,
      forwarded verbatim; CyCognito interprets a missing filter as
      "no filter").  Response envelope is ``{"data": [...], "total":
      N, "next_offset": M}`` walked page-by-page until the envelope
      stops advancing the offset or ``CYCOG_PAGES`` is reached.
  POST {CYCOG_HOST}/v1/issues
      -> paginated external-issue inventory. Same paging shape as
      the assets surface; issues carry severity / status / asset_id
      / cves / remediation and become Faraday vulnerabilities
      directly.  CyCognito issues are the canonical EASM finding —
      they join to assets via ``asset_id``.

Auth: CyCognito uses a single long-lived API token created in the
CyCognito console under Settings -> API.  The dispatcher carries the
token on every request as the ``Authorization: <CYCOG_TOKEN>``
header.  ``CYCOG_HOST`` is the CyCognito tenant host (e.g.
``api.platform.cycognito.com``) and ``CYCOG_REALM`` is the
organisation identifier scoping the search.
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
PER_PAGE = 100  # CyCognito v1 caps count at 100 on /assets, /issues.
DEFAULT_PAGES = 5
MAX_PAGES = 50

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

CYCOG_STRING_SEVERITY = {
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

CYCOG_STATUS = {
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
    "accepted": "risk-accepted",
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
    print(f"{datetime.utcnow()} - CyCognito: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on CYCOG_HOST.

    No default — the CyCognito tenant host is operator-specific so
    we sys.exit(1) upstream in ``main`` when the env var is missing.
    Here we just whitespace-trim, strip trailing slashes and add
    ``https://`` when the operator pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_filter(value):
    """Validate CYCOG_FILTER (optional JSON filter forwarded in the body).

    None / blank -> ``{}`` (no filter; CyCognito returns the full
    inventory the API token has access to).  Accepts a JSON-encoded
    string (object or list — CyCognito's filter grammar allows
    either) or a Python dict / list / int passed through verbatim.
    Garbage -> ``{}`` with a log line so a stray operator typo
    doesn't tank the run.
    """
    if value is None or value == "":
        return {}
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        log(f"CYCOG_FILTER {type(value).__name__!r} not a string / dict / list; ignoring")
        return {}
    text = value.strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        log(f"CYCOG_FILTER '{value}' not valid JSON; ignoring filter")
        return {}
    if not isinstance(parsed, (dict, list)):
        log(f"CYCOG_FILTER '{value}' decoded to {type(parsed).__name__}; ignoring filter")
        return {}
    return parsed


def validate_realm(value):
    """Validate CYCOG_REALM (organisation identifier).

    None / blank -> ``""`` (no realm scope; CyCognito returns
    findings the token has cross-realm access to — uncommon but
    valid for service-account tokens).  Anything else is forwarded
    verbatim — CyCognito interprets the realm as a free-form name
    match against the organisation's identifier.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_min_severity(value):
    """Validate CYCOG_MIN_SEVERITY (optional severity floor).

    None / blank -> ``""`` (no client-side filter; we emit the full
    hits surface).  Accepts the canonical Faraday severity enum
    (info / low / medium / high / critical) plus the CyCognito-side
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
    bucket = CYCOG_STRING_SEVERITY.get(text)
    if bucket is not None:
        return bucket
    log(f"CYCOG_MIN_SEVERITY '{value}' not recognised; ignoring filter")
    return ""


def validate_pages(value):
    """Validate CYCOG_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    CyCognito API.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"CYCOG_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"CYCOG_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_assets_url(host):
    return f"{normalize_base_url(host)}/v1/assets"


def build_issues_url(host):
    return f"{normalize_base_url(host)}/v1/issues"


def build_paged_body(realm, filter_spec, offset):
    """Build the POST body for a CyCognito v1 search surface.

    ``realm`` filters the result set to a named organisation when
    non-empty; ``filter_spec`` is the operator-supplied JSON filter
    forwarded verbatim; ``offset`` is the integer cursor (0 on the
    first request).  ``count`` is the per-page cap.
    """
    body = {"count": PER_PAGE, "offset": int(offset) if offset is not None else 0}
    if realm:
        body["realm"] = realm
    if isinstance(filter_spec, dict) and filter_spec:
        body["filter"] = filter_spec
    elif isinstance(filter_spec, list) and filter_spec:
        body["filter"] = filter_spec
    return body


def auth_headers(token):
    """Return the CyCognito auth header set."""
    return {
        "Authorization": str(token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_hits(body):
    """Pull the hits list from a CyCognito v1 search envelope."""
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("data", "results", "items", "hits", "assets", "issues"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_next_offset(body, current_offset, page_size):
    """Pull the next-page offset from a CyCognito v1 search envelope."""
    if not isinstance(body, dict):
        return None
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
    for key in ("total", "total_count", "totalCount", "totalResults"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def severity_from_cycognito(item, cvss=None):
    """Bucket a CyCognito item shape onto a Faraday severity.

    Walks the canonical string ``severity`` field first; falls back
    to ``priority`` / ``risk_rating`` / ``risk_score`` (CyCognito-
    side alias fields); falls back to CVSS when nothing else lands.
    Default is ``info`` (CyCognito surfaces attack-surface
    discoveries, not vulnerability findings).
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            text = item.strip().lower()
            if text in CYCOG_STRING_SEVERITY:
                return CYCOG_STRING_SEVERITY[text]
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    for key in ("severity", "Severity", "issue_severity"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in CYCOG_STRING_SEVERITY:
                return CYCOG_STRING_SEVERITY[text]

    for key in ("priority", "risk_rating", "riskRating"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in CYCOG_STRING_SEVERITY:
                return CYCOG_STRING_SEVERITY[text]

    risk_score = item.get("risk_score") or item.get("riskScore")
    if risk_score is not None:
        try:
            score = float(risk_score)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            # CyCognito risk_score is 0..10 on the issues surface.
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


def status_from_cycognito(item):
    """Map a CyCognito issue payload to a Faraday status."""
    if not isinstance(item, dict):
        return "open"
    for key in ("status", "Status", "issue_status", "state", "investigation_status"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower().replace(" ", "_").replace("-", "_")
            if text in CYCOG_STATUS:
                return CYCOG_STATUS[text]
    return "open"


def passes_min_severity(severity, min_severity):
    """Client-side severity floor for non-server-filtered shapes."""
    if not min_severity:
        return True
    floor = SEVERITY_ORDER.get(min_severity, 0)
    have = SEVERITY_ORDER.get(severity, 0)
    return have >= floor


def collect_cves(item):
    """Walk a CyCognito item for CVE-* ids."""
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
    """Walk a CyCognito asset + item for advisory URLs / pivots."""
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
            add(f"CyCognito-Asset: {aid}")
        for key in ("asset_name", "name", "domain", "hostname"):
            v = asset.get(key)
            if isinstance(v, str) and v.strip():
                add(f"CyCognito-AssetName: {v.strip()}")
                break
        asset_type = asset.get("asset_type") or asset.get("type")
        if isinstance(asset_type, str) and asset_type.strip():
            add(f"CyCognito-AssetType: {asset_type.strip()}")
        for key in ("organization", "organisation", "org"):
            v = asset.get(key)
            if isinstance(v, str) and v.strip():
                add(f"CyCognito-Org: {v.strip()}")
                break

    if isinstance(item, dict):
        iid = item.get("issue_id") or item.get("id")
        if iid:
            add(f"CyCognito-Id: {iid}")
        for key in ("category", "issue_type", "type"):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                add(f"CyCognito-Category: {v.strip()}")
                break
        port = item.get("port")
        proto = item.get("protocol") or item.get("transport_protocol")
        if port is not None:
            add(f"CyCognito-Port: {port}/{(proto or 'tcp').lower()}")
        for url_key in ("url", "reference_url", "external_url", "evidence_url"):
            v = item.get(url_key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def asset_ip(asset):
    """Pick the asset IP from a CyCognito asset.

    CyCognito assets carry ``ip`` at the top level on IP-keyed
    shapes and ``ips`` (a list) on multi-IP shapes; domain-keyed
    assets have no IP at all.  Loopback / zero are explicitly
    skipped because CyCognito would not return them in real data.
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
    """Walk a CyCognito asset for hostname candidates."""
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


def build_issue_vulnerability(asset, issue):
    """Build a Faraday vulnerability dict for one CyCognito issue."""
    if not isinstance(issue, dict):
        return None
    name = issue.get("name") or issue.get("title") or issue.get("issue_type") or "CyCognito issue"
    label = f"[EASM] CyCognito {str(name).strip()}"

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
        "organization",
        "first_observed",
        "last_observed",
        "port",
        "protocol",
        "ip",
        "domain",
        "exploit_complexity",
        "potential_impact",
        "investigation_status",
    ):
        v = issue.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{key}: {v}")

    severity = severity_from_cycognito(issue, cvss=issue.get("cvss") or issue.get("cvssScore"))
    status = status_from_cycognito(issue)
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
            "Review the issue in the CyCognito console (Issues -> All "
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
        "tags": ["cycognito", "easm"],
    }


def build_host_from_asset(asset, issues=None, min_severity=""):
    """Build a Faraday host dict from a CyCognito asset hit."""
    if not isinstance(asset, dict):
        return None

    ip = asset_ip(asset)
    hostnames = asset_hostnames(asset)

    desc_parts = []
    for key in (
        "asset_id",
        "asset_type",
        "organization",
        "first_observed",
        "last_observed",
        "discovery_source",
        "criticality",
        "platform",
    ):
        v = asset.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    iss_list = (
        issues if isinstance(issues, list) else (asset.get("issues") if isinstance(asset.get("issues"), list) else [])
    )
    if iss_list:
        desc_parts.append(f"issues={len(iss_list)}")

    vulns = []
    for iss in iss_list:
        v = build_issue_vulnerability(asset, iss)
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


def synthesise_asset(asset_id=None, asset_name=None, ip=None, organization=None):
    """Build a synthetic asset envelope for orphaned issues."""
    asset = {}
    if asset_id:
        asset["asset_id"] = asset_id
    if asset_name:
        asset["asset_name"] = asset_name
    if ip:
        asset["ip"] = ip
    if organization:
        asset["organization"] = organization
    return asset


def fetch_pages(requests_module, url, headers, body_builder, max_pages):
    """Walk a CyCognito v1 search envelope (offset-based pagination)."""
    out = []
    offset = 0
    walked = 0
    last_offset = -1
    hits = []
    while walked < max_pages:
        body = body_builder(offset)
        try:
            resp = requests_module.post(url, headers=headers, json=body, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"POST {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("CyCognito request rejected (401). Check CYCOG_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("CyCognito request rejected (403). Check the token's realm / scope.")
            return out
        if resp.status_code == 429:
            log("CyCognito rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"CyCognito request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"CyCognito response was not JSON ({url})")
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
        log(f"hit CYCOG_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    filter_spec = validate_filter(env("EXECUTOR_CONFIG_CYCOG_FILTER"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_CYCOG_MIN_SEVERITY"))
    pages = validate_pages(env("EXECUTOR_CONFIG_CYCOG_PAGES"))

    host = env("CYCOG_HOST", required=True)
    realm = validate_realm(env("CYCOG_REALM"))
    token = env("CYCOG_TOKEN", required=True)

    if not normalize_base_url(host):
        log("CYCOG_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    assets_url = build_assets_url(host)
    issues_url = build_issues_url(host)

    asset_hits = fetch_pages(
        requests,
        assets_url,
        headers,
        lambda offset: build_paged_body(realm, filter_spec, offset),
        max_pages=pages,
    )
    issue_hits = fetch_pages(
        requests,
        issues_url,
        headers,
        lambda offset: build_paged_body(realm, filter_spec, offset),
        max_pages=pages,
    )

    log(
        f"Processing {len(asset_hits)} CyCognito assets + {len(issue_hits)} issues "
        f"(realm={realm!r}, min_severity={min_severity!r}, pages={pages})"
    )

    by_asset_id = {}
    for asset in asset_hits:
        if not isinstance(asset, dict):
            continue
        aid = asset.get("asset_id") or asset.get("id") or asset.get("assetId")
        if aid:
            by_asset_id[str(aid)] = {"asset": asset, "issues": []}

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
            issues=bucket["issues"],
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)

    if orphan_issues:
        synthetic = synthesise_asset(asset_name="(unattached)")
        built = build_host_from_asset(
            synthetic,
            issues=orphan_issues,
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "cycognito",
            "command": "cycognito",
            "params": (f"realm={realm}," f"min_severity={min_severity}," f"pages={pages}"),
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
