#!/usr/bin/env python
"""Ionix EASM importer.

Pulls externally-discovered assets and findings from the Ionix REST
API and emits Faraday bulk-create JSON to stdout.  Each Ionix asset
becomes one Faraday host (``ip`` = the asset's first public IP, or
the synthetic ``0.0.0.0`` sentinel for domain-keyed assets); per-asset
findings attach as one Faraday vulnerability per ``finding_id`` with
the ``[EASM]`` engine prefix so the data lands in the Faraday
workspace alongside the other attack-surface management feeds.

Endpoints used:
  GET {IONIX_HOST}/api/v1/assets
      -> paginated external-asset inventory.  Query string carries
      ``limit=100`` (Ionix's per-page cap) and ``offset`` (integer
      cursor, 0 on the first request).  Response envelope is
      ``{"data": [...], "total": N, "next_offset": M}`` walked
      page-by-page until the envelope stops advancing the offset or
      ``IONIX_PAGES`` is reached.  Ionix assets are the canonical
      EASM pivot — every finding joins by ``asset_id``.
  GET {IONIX_HOST}/api/v1/findings
      -> paginated finding inventory.  Same paging shape as the
      assets surface; findings carry ``severity`` / ``status`` /
      ``asset_id`` / ``cves`` / ``remediation`` and become Faraday
      vulnerabilities directly.  Query string also carries the
      operator-supplied ``status`` floor (when ``IONIX_STATUS`` is
      set) so Ionix narrows the findings server-side rather than
      relying on the client-side filter alone.

Auth: Ionix uses a single long-lived API key created in the Ionix
console under Settings -> API Keys -> New.  The dispatcher carries
the key on every request as the ``Authorization: Bearer
<IONIX_API_KEY>`` header.  ``IONIX_HOST`` is the Ionix tenant host
(e.g. ``api.ionix.io``) — service-account keys carry the tenant
scope so no workspace param is required.
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
PER_PAGE = 100  # Ionix v1 caps limit at 100 on /assets, /findings.
DEFAULT_PAGES = 5
MAX_PAGES = 50

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

IONIX_STRING_SEVERITY = {
    "critical": "critical",
    "crit": "critical",
    "sev1": "critical",
    "severity_1": "critical",
    "p1": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "sev2": "high",
    "severity_2": "high",
    "p2": "high",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "sev3": "medium",
    "severity_3": "medium",
    "p3": "medium",
    "low": "low",
    "minor": "low",
    "sev4": "low",
    "severity_4": "low",
    "p4": "low",
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
    "p5": "info",
}

IONIX_STATUS = {
    "new": "open",
    "open": "open",
    "active": "open",
    "in_progress": "open",
    "inprogress": "open",
    "reopened": "open",
    "investigating": "open",
    "under_investigation": "open",
    "pending": "open",
    "triaged": "open",
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
}

# Valid IONIX_STATUS arg values — server-side filter accepts the
# Faraday canonical buckets + Ionix-side passthrough.  Anything else
# is logged and ignored.
VALID_STATUS = ("open", "closed", "risk-accepted")


def log(msg):
    print(f"{datetime.utcnow()} - Ionix: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on IONIX_HOST.

    No default — the Ionix tenant host is operator-specific so we
    sys.exit(1) upstream in ``main`` when the env var is missing.
    Here we just whitespace-trim, strip trailing slashes and add
    ``https://`` when the operator pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_min_severity(value):
    """Validate IONIX_MIN_SEVERITY (optional severity floor).

    None / blank -> ``""`` (no client-side filter; we emit the full
    hits surface).  Accepts the canonical Faraday severity enum
    (info / low / medium / high / critical) plus the Ionix-side
    aliases (Important / Major / Moderate / Informational / Sev1..
    Sev5 / P1..P5).  Garbage -> ``""`` with a log line.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    if text in VALID_MIN_SEVERITY:
        return text
    bucket = IONIX_STRING_SEVERITY.get(text)
    if bucket is not None:
        return bucket
    log(f"IONIX_MIN_SEVERITY '{value}' not recognised; ignoring filter")
    return ""


def validate_status(value):
    """Validate IONIX_STATUS (optional finding status filter).

    None / blank -> ``""`` (no narrowing; Ionix returns every
    finding regardless of status).  Accepts the canonical Faraday
    enum (open / closed / risk-accepted) plus the Ionix-side
    aliases (new / active / in_progress / investigating / triaged ->
    open; resolved / remediated / fixed / mitigated / patched ->
    closed; false_positive / wont_fix / dismissed -> risk-accepted).
    Garbage -> ``""`` with a log line.
    """
    if value is None:
        return ""
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return ""
    if text == "risk_accepted":
        return "risk-accepted"
    if text in VALID_STATUS:
        return text
    bucket = IONIX_STATUS.get(text)
    if bucket is not None:
        return bucket
    log(f"IONIX_STATUS '{value}' not recognised; ignoring filter")
    return ""


def validate_pages(value):
    """Validate IONIX_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Ionix API.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"IONIX_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"IONIX_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_assets_url(host):
    return f"{normalize_base_url(host)}/api/v1/assets"


def build_findings_url(host):
    return f"{normalize_base_url(host)}/api/v1/findings"


def build_paged_params(offset, status="", limit=PER_PAGE):
    """Build the query-param dict for an Ionix v1 search surface.

    ``offset`` is the integer cursor (0 on the first request);
    ``status`` scopes the result set to a named status floor when
    non-empty (the assets surface ignores ``status`` so callers may
    pass ``""`` there); ``limit`` is the per-page cap.
    """
    params = {"limit": int(limit), "offset": int(offset) if offset is not None else 0}
    if status:
        params["status"] = status
    return params


def auth_headers(api_key):
    """Return the Ionix auth header set (Bearer API key)."""
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_hits(body):
    """Pull the hits list from an Ionix v1 search envelope."""
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("data", "results", "items", "hits", "assets", "findings"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_next_offset(body, current_offset, page_size):
    """Pull the next-page offset from an Ionix v1 search envelope."""
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


def severity_from_ionix(item, cvss=None):
    """Bucket an Ionix item shape onto a Faraday severity.

    Walks the canonical string ``severity`` field first; falls back
    to ``priority`` / ``risk_rating`` / ``risk_score`` (Ionix-side
    alias fields); falls back to CVSS when nothing else lands.
    Default is ``info`` (Ionix surfaces attack-surface discoveries
    + findings — most are informational).
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            text = item.strip().lower()
            if text in IONIX_STRING_SEVERITY:
                return IONIX_STRING_SEVERITY[text]
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    for key in ("severity", "Severity", "finding_severity", "issue_severity"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in IONIX_STRING_SEVERITY:
                return IONIX_STRING_SEVERITY[text]

    for key in ("priority", "risk_rating", "riskRating"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in IONIX_STRING_SEVERITY:
                return IONIX_STRING_SEVERITY[text]

    risk_score = item.get("risk_score") or item.get("riskScore")
    if risk_score is not None:
        try:
            score = float(risk_score)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            # Ionix risk_score is 0..10 on the findings surface.
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


def status_from_ionix(item):
    """Map an Ionix finding payload to a Faraday status."""
    if not isinstance(item, dict):
        return "open"
    for key in ("status", "Status", "finding_status", "issue_status", "state"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower().replace(" ", "_").replace("-", "_")
            if text in IONIX_STATUS:
                return IONIX_STATUS[text]
    return "open"


def passes_min_severity(severity, min_severity):
    """Client-side severity floor for non-server-filtered shapes."""
    if not min_severity:
        return True
    floor = SEVERITY_ORDER.get(min_severity, 0)
    have = SEVERITY_ORDER.get(severity, 0)
    return have >= floor


def passes_status(finding, status_filter):
    """Client-side status filter (defensive — server already narrows).

    Ionix narrows the findings surface server-side via the ``status``
    query param but a federated tenant may ignore the param; we
    enforce it again client-side so the operator's filter is honoured
    regardless.  Empty filter -> True.
    """
    if not status_filter:
        return True
    have = status_from_ionix(finding) if isinstance(finding, dict) else "open"
    return have == status_filter


def collect_cves(item):
    """Walk an Ionix item for CVE-* ids."""
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
    """Walk an Ionix asset + item for advisory URLs / pivots."""
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
            add(f"Ionix-Asset: {aid}")
        for key in ("asset_name", "name", "domain", "hostname", "fqdn"):
            v = asset.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Ionix-AssetName: {v.strip()}")
                break
        asset_type = asset.get("asset_type") or asset.get("type")
        if isinstance(asset_type, str) and asset_type.strip():
            add(f"Ionix-AssetType: {asset_type.strip()}")
        for key in ("organization", "org", "tenant", "tenant_id"):
            v = asset.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Ionix-Tenant: {v.strip()}")
                break

    if isinstance(item, dict):
        iid = item.get("finding_id") or item.get("id") or item.get("issue_id")
        if iid:
            add(f"Ionix-Id: {iid}")
        for key in ("category", "finding_type", "issue_type", "type"):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Ionix-Category: {v.strip()}")
                break
        port = item.get("port")
        proto = item.get("protocol") or item.get("transport_protocol")
        if port is not None:
            add(f"Ionix-Port: {port}/{(proto or 'tcp').lower()}")
        for url_key in ("url", "reference_url", "external_url", "evidence_url"):
            v = item.get(url_key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def asset_ip(asset):
    """Pick the asset IP from an Ionix asset.

    Ionix assets carry ``ip`` at the top level on IP-keyed shapes
    and ``ips`` (a list) on multi-IP shapes; domain-keyed assets
    have no IP at all.  Loopback / zero are explicitly skipped
    because Ionix would not return them in real data.
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
    """Walk an Ionix asset for hostname candidates."""
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

    for list_key in ("domains", "hostnames", "fqdns", "names", "subdomains"):
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


def build_finding_vulnerability(asset, finding):
    """Build a Faraday vulnerability dict for one Ionix finding."""
    if not isinstance(finding, dict):
        return None
    name = (
        finding.get("name")
        or finding.get("title")
        or finding.get("finding_type")
        or finding.get("issue_type")
        or "Ionix finding"
    )
    label = f"[EASM] Ionix {str(name).strip()}"

    desc_parts = []
    for key in (
        "finding_id",
        "issue_id",
        "finding_type",
        "issue_type",
        "category",
        "description",
        "summary",
        "details",
        "asset_id",
        "asset_name",
        "first_observed",
        "last_observed",
        "first_seen",
        "last_seen",
        "port",
        "protocol",
        "ip",
        "domain",
        "url",
        "exploit_complexity",
        "potential_impact",
        "investigation_status",
        "confidence",
    ):
        v = finding.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{key}: {v}")

    severity = severity_from_ionix(
        finding,
        cvss=finding.get("cvss") or finding.get("cvssScore") or finding.get("cvss_score"),
    )
    status = status_from_ionix(finding)
    cves = collect_cves(finding)
    if not cves:
        cves = collect_cves(asset)
    refs = collect_refs(asset, finding)

    fid = finding.get("finding_id") or finding.get("id") or finding.get("issue_id")
    external_id = str(fid) if fid else str(label)

    resolution = (
        finding.get("remediation")
        or finding.get("remediation_guidance")
        or finding.get("recommendation")
        or (
            "Review the finding in the Ionix console (Findings -> All "
            "Findings).  Remediate the underlying exposure (close the "
            "port, patch the service, rotate the credential, harden "
            "the configuration) or accept the risk."
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
        "tags": ["ionix", "easm"],
    }


def build_host_from_asset(asset, findings=None, min_severity="", status_filter=""):
    """Build a Faraday host dict from an Ionix asset hit."""
    if not isinstance(asset, dict):
        return None

    ip = asset_ip(asset)
    hostnames = asset_hostnames(asset)

    desc_parts = []
    for key in (
        "asset_id",
        "asset_type",
        "tenant",
        "first_observed",
        "last_observed",
        "discovery_source",
        "criticality",
        "platform",
        "tags",
    ):
        v = asset.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    find_list = (
        findings
        if isinstance(findings, list)
        else (asset.get("findings") if isinstance(asset.get("findings"), list) else [])
    )
    if find_list:
        desc_parts.append(f"findings={len(find_list)}")

    vulns = []
    for f in find_list:
        if not passes_status(f, status_filter):
            continue
        v = build_finding_vulnerability(asset, f)
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


def synthesise_asset(asset_id=None, asset_name=None, ip=None):
    """Build a synthetic asset envelope for orphaned findings."""
    asset = {}
    if asset_id:
        asset["asset_id"] = asset_id
    if asset_name:
        asset["asset_name"] = asset_name
    if ip:
        asset["ip"] = ip
    return asset


def fetch_pages(requests_module, url, headers, params_builder, max_pages):
    """Walk an Ionix v1 search envelope (offset-based pagination)."""
    out = []
    offset = 0
    walked = 0
    last_offset = -1
    hits = []
    while walked < max_pages:
        params = params_builder(offset)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Ionix request rejected (401). Check IONIX_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Ionix request rejected (403). Check the API key's tenant scope.")
            return out
        if resp.status_code == 429:
            log("Ionix rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Ionix request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Ionix response was not JSON ({url})")
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
        log(f"hit IONIX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_IONIX_MIN_SEVERITY"))
    status_filter = validate_status(env("EXECUTOR_CONFIG_IONIX_STATUS"))
    pages = validate_pages(env("EXECUTOR_CONFIG_IONIX_PAGES"))

    host = env("IONIX_HOST", required=True)
    api_key = env("IONIX_API_KEY", required=True)

    if not normalize_base_url(host):
        log("IONIX_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(api_key)
    assets_url = build_assets_url(host)
    findings_url = build_findings_url(host)

    asset_hits = fetch_pages(
        requests,
        assets_url,
        headers,
        lambda offset: build_paged_params(offset),
        max_pages=pages,
    )
    finding_hits = fetch_pages(
        requests,
        findings_url,
        headers,
        lambda offset: build_paged_params(offset, status=status_filter),
        max_pages=pages,
    )

    log(
        f"Processing {len(asset_hits)} Ionix assets + {len(finding_hits)} findings "
        f"(min_severity={min_severity!r}, status={status_filter!r}, pages={pages})"
    )

    by_asset_id = {}
    for asset in asset_hits:
        if not isinstance(asset, dict):
            continue
        aid = asset.get("asset_id") or asset.get("id") or asset.get("assetId")
        if aid:
            by_asset_id[str(aid)] = {"asset": asset, "findings": []}

    orphan_findings = []
    for f in finding_hits:
        if not isinstance(f, dict):
            continue
        aid = f.get("asset_id") or f.get("assetId")
        if aid and str(aid) in by_asset_id:
            by_asset_id[str(aid)]["findings"].append(f)
        else:
            orphan_findings.append(f)

    hosts_out = []
    for bucket in by_asset_id.values():
        built = build_host_from_asset(
            bucket["asset"],
            findings=bucket["findings"],
            min_severity=min_severity,
            status_filter=status_filter,
        )
        if built is not None:
            hosts_out.append(built)

    if orphan_findings:
        synthetic = synthesise_asset(asset_name="(unattached)")
        built = build_host_from_asset(
            synthetic,
            findings=orphan_findings,
            min_severity=min_severity,
            status_filter=status_filter,
        )
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "ionix",
            "command": "ionix",
            "params": (f"min_severity={min_severity}," f"status={status_filter}," f"pages={pages}"),
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
