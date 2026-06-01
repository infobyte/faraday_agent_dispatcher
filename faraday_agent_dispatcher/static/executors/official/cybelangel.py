#!/usr/bin/env python
"""CybelAngel EASM importer.

Pulls externally-discovered assets and threats (digital-risk
findings) from the CybelAngel platform and emits Faraday
bulk-create JSON to stdout.  Each CybelAngel asset becomes one
Faraday host (``ip`` = the asset's first public IP, or the
synthetic ``0.0.0.0`` sentinel for domain-keyed assets); per-asset
threats attach as one Faraday vulnerability per ``threat_id`` /
``id`` with engine prefix ``[EASM]`` so the data lands in the
Faraday workspace alongside the other attack-surface management
feeds.

Endpoints used:
  POST {CYBELANGEL_AUTH_HOST}/oauth/token
      -> OAuth2 client_credentials token exchange. JSON body
      carries ``client_id`` + ``client_secret`` +
      ``audience=https://platform.cybelangel.com/`` +
      ``grant_type=client_credentials``.  Response carries
      ``{"access_token": "<jwt>", "expires_in": 86400, "token_type":
      "Bearer"}``.  Token is cached for the duration of the
      executor run.
  GET {CYBELANGEL_HOST}/api/2.0/threats?limit=100&offset=<n>
      -> paginated digital-risk threats inventory (the canonical
      CybelAngel finding surface — credentials, leaked code,
      exposed PII, brand abuse, fraud sites, etc).  When
      ``CYBELANGEL_FROM_DATE`` is non-empty it is forwarded as
      ``created_after=<ISO>`` (CybelAngel's canonical date-range
      filter on the threats surface).  ``limit=100`` is
      CybelAngel's per-page cap on the v2.0 surface.
  GET {CYBELANGEL_HOST}/api/2.0/assets?limit=100&offset=<n>
      -> paginated external-asset inventory.  Assets are the
      canonical pivot — every threat joins to an asset via
      ``asset_id`` and the asset's ip / hostname / domain
      enrichment populates Faraday's host index.

Auth: CybelAngel uses OAuth2 client_credentials.  The operator
creates an API client in the CybelAngel console (Settings -> API
Keys -> New Client) and pastes the returned client ID + client
secret into ``CYBELANGEL_CLIENT_ID`` + ``CYBELANGEL_CLIENT_SECRET``.
The dispatcher exchanges those for a short-lived JWT access token
at ``{CYBELANGEL_AUTH_HOST}/oauth/token`` (defaults to
``https://auth.cybelangel.com``) and carries the token on every
``/api/2.0/`` request as ``Authorization: Bearer <access_token>``.
The API host defaults to ``https://platform.cybelangel.com`` and
the audience defaults to ``https://platform.cybelangel.com/``
(both settable for on-prem / federated deployments via
``CYBELANGEL_HOST`` / ``CYBELANGEL_AUDIENCE`` env vars).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$")

TIMEOUT = 60
PER_PAGE = 100  # CybelAngel v2.0 caps limit at 100 on /threats, /assets.
DEFAULT_PAGES = 5
MAX_PAGES = 50

DEFAULT_API_HOST = "https://platform.cybelangel.com"
DEFAULT_AUTH_HOST = "https://auth.cybelangel.com"
DEFAULT_AUDIENCE = "https://platform.cybelangel.com/"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# CybelAngel surfaces string severities on the threats surface.
# Aliases collapse operator-friendly inputs (Important / Major /
# Moderate / etc.) plus CybelAngel's own labels (critical / high /
# medium / low / negligible / informational) onto the canonical
# Faraday bucket.
CYBELANGEL_STRING_SEVERITY = {
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

# CybelAngel threat.status -> Faraday status.  CybelAngel's
# threat-status taxonomy covers open / in_progress / resolved /
# false_positive / risk_accepted (and a few legacy / SaaS-tier
# synonyms).
CYBELANGEL_STATUS = {
    "new": "open",
    "open": "open",
    "active": "open",
    "in_progress": "open",
    "inprogress": "open",
    "reopened": "open",
    "investigating": "open",
    "under_investigation": "open",
    "pending": "open",
    "resolved": "closed",
    "closed": "closed",
    "remediated": "closed",
    "fixed": "closed",
    "mitigated": "closed",
    "takedown": "closed",
    "taken_down": "closed",
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
    print(f"{datetime.utcnow()} - CybelAngel: {msg}", file=sys.stderr, flush=True)


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


def normalize_base_url(host, default=None):
    """Trim trailing slash + tolerate operator typos on a host URL.

    Whitespace-trims, strips trailing slashes and adds ``https://``
    when the operator pasted in a bare FQDN.  When ``host`` is None
    / blank a ``default`` URL is returned (caller passes
    ``DEFAULT_API_HOST`` / ``DEFAULT_AUTH_HOST`` for the platform
    surfaces; ``CYBELANGEL_AUDIENCE`` uses ``DEFAULT_AUDIENCE``).
    """
    if not isinstance(host, str) or not host.strip():
        return default or ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_from_date(value):
    """Validate CYBELANGEL_FROM_DATE (optional ISO 8601 date filter).

    None / blank -> ``""`` (no filter; CybelAngel returns the full
    threats surface the token has access to).  Accepts ``YYYY-MM-DD``
    or full RFC 3339 / ISO 8601 timestamp (``2024-01-01T00:00:00Z``,
    ``2024-01-01T00:00:00+00:00``).  Garbage -> ``""`` with a log line
    so a stray operator typo doesn't tank the run.
    """
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if ISO_DATE_RE.match(text):
        return text
    log(f"CYBELANGEL_FROM_DATE '{value}' not ISO 8601 (YYYY-MM-DD or RFC 3339); ignoring filter")
    return ""


def validate_min_severity(value):
    """Validate CYBELANGEL_MIN_SEVERITY (optional severity floor).

    None / blank -> ``""`` (no client-side filter; we emit the full
    hits surface).  Accepts the canonical Faraday severity enum
    (info / low / medium / high / critical) plus CybelAngel-side
    aliases (Important / Major / Moderate / Informational /
    Negligible / Sev1..Sev5 / P1..P5).  Garbage -> ``""`` with a log
    line.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    if text in VALID_MIN_SEVERITY:
        return text
    bucket = CYBELANGEL_STRING_SEVERITY.get(text)
    if bucket is not None:
        return bucket
    log(f"CYBELANGEL_MIN_SEVERITY '{value}' not recognised; ignoring filter")
    return ""


def validate_pages(value):
    """Validate CYBELANGEL_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    CybelAngel API.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"CYBELANGEL_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"CYBELANGEL_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_token_url(auth_host):
    return f"{normalize_base_url(auth_host, default=DEFAULT_AUTH_HOST)}/oauth/token"


def build_threats_url(host):
    return f"{normalize_base_url(host, default=DEFAULT_API_HOST)}/api/2.0/threats"


def build_assets_url(host):
    return f"{normalize_base_url(host, default=DEFAULT_API_HOST)}/api/2.0/assets"


def build_paged_params(offset, from_date="", include_from_date=False):
    """Build the GET query params for a CybelAngel v2.0 search surface.

    ``offset`` is the integer cursor (0 on the first request);
    ``from_date`` is the operator-supplied ISO 8601 date forwarded
    as ``created_after`` on the threats surface only (the /assets
    surface doesn't accept a date filter so we omit it there).
    """
    params = {"limit": PER_PAGE, "offset": int(offset) if offset is not None else 0}
    if include_from_date and from_date:
        params["created_after"] = from_date
    return params


def build_token_body(client_id, client_secret, audience):
    """Build the OAuth2 client_credentials token-exchange body."""
    return {
        "client_id": str(client_id),
        "client_secret": str(client_secret),
        "audience": str(audience or DEFAULT_AUDIENCE),
        "grant_type": "client_credentials",
    }


def bearer_headers(access_token):
    """Return the bearer-token header set for /api/2.0/ requests."""
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_access_token(body):
    """Pull the access_token from an OAuth2 token-exchange response."""
    if not isinstance(body, dict):
        return ""
    for key in ("access_token", "accessToken", "token", "id_token"):
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def fetch_access_token(requests_module, token_url, client_id, client_secret, audience):
    """Run the OAuth2 client_credentials exchange and return the JWT.

    Posts the canonical Auth0-style body
    ``{client_id, client_secret, audience, grant_type=client_credentials}``
    to ``token_url`` and pulls ``access_token`` from the response.
    Returns ``""`` on any failure; ``main`` ``sys.exit(1)`` upstream
    when the token comes back empty so a bad client_id / secret pair
    surfaces cleanly.
    """
    body = build_token_body(client_id, client_secret, audience)
    try:
        resp = requests_module.post(
            token_url,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json=body,
            timeout=TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"OAuth token exchange failed: {exc}")
        return ""
    if resp.status_code == 401:
        log("OAuth token exchange rejected (401). Check CYBELANGEL_CLIENT_ID / CYBELANGEL_CLIENT_SECRET.")
        return ""
    if resp.status_code == 403:
        log("OAuth token exchange rejected (403). Check the client's scope / audience.")
        return ""
    if resp.status_code >= 400:
        log(f"OAuth token exchange failed ({resp.status_code}): {resp.text[:500]}")
        return ""
    try:
        payload = resp.json()
    except ValueError:
        log("OAuth token exchange response was not JSON")
        return ""
    return extract_access_token(payload)


def extract_hits(body):
    """Pull the hits list from a CybelAngel v2.0 search envelope.

    CybelAngel's canonical shape is
    ``{"data": [...], "total": N, "next_offset": M}`` on every v2.0
    search surface.  Some federated stacks expose the hits at the
    root or under ``results`` / ``items`` / ``threats`` / ``assets``
    — accept all of those for resilience.
    """
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("data", "results", "items", "hits", "threats", "assets"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_next_offset(body, current_offset, page_size):
    """Pull the next-page offset from a CybelAngel v2.0 search envelope."""
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


def severity_from_cybelangel(item, cvss=None):
    """Bucket a CybelAngel item shape onto a Faraday severity.

    Walks the canonical string ``severity`` field first; falls back
    to ``priority`` / ``risk_rating`` / ``risk_score`` (CybelAngel
    surfaces a 0..100 risk_score on some threats); falls back to
    CVSS when nothing else lands.  Default is ``info`` (CybelAngel
    surfaces attack-surface / digital-risk discoveries, not CVSS-
    keyed findings).
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            text = item.strip().lower()
            if text in CYBELANGEL_STRING_SEVERITY:
                return CYBELANGEL_STRING_SEVERITY[text]
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    for key in ("severity", "Severity", "threat_severity", "issue_severity"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in CYBELANGEL_STRING_SEVERITY:
                return CYBELANGEL_STRING_SEVERITY[text]

    for key in ("priority", "risk_rating", "riskRating"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in CYBELANGEL_STRING_SEVERITY:
                return CYBELANGEL_STRING_SEVERITY[text]

    risk_score = item.get("risk_score") or item.get("riskScore")
    if risk_score is not None:
        try:
            score = float(risk_score)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            # CybelAngel risk_score is 0..100 on the threats surface.
            if score >= 80:
                return "critical"
            if score >= 60:
                return "high"
            if score >= 40:
                return "medium"
            if score >= 20:
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


def status_from_cybelangel(item):
    """Map a CybelAngel threat payload to a Faraday status."""
    if not isinstance(item, dict):
        return "open"
    for key in ("status", "Status", "threat_status", "issue_status", "state"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower().replace(" ", "_").replace("-", "_")
            if text in CYBELANGEL_STATUS:
                return CYBELANGEL_STATUS[text]
    return "open"


def passes_min_severity(severity, min_severity):
    """Client-side severity floor for non-server-filtered shapes."""
    if not min_severity:
        return True
    floor = SEVERITY_ORDER.get(min_severity, 0)
    have = SEVERITY_ORDER.get(severity, 0)
    return have >= floor


def collect_cves(item):
    """Walk a CybelAngel item for CVE-* ids."""
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
    """Walk a CybelAngel asset + threat for advisory URLs / pivots."""
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
            add(f"CybelAngel-Asset: {aid}")
        for key in ("asset_name", "name", "domain", "hostname"):
            v = asset.get(key)
            if isinstance(v, str) and v.strip():
                add(f"CybelAngel-AssetName: {v.strip()}")
                break
        asset_type = asset.get("asset_type") or asset.get("type")
        if isinstance(asset_type, str) and asset_type.strip():
            add(f"CybelAngel-AssetType: {asset_type.strip()}")

    if isinstance(item, dict):
        tid = item.get("threat_id") or item.get("id") or item.get("issue_id")
        if tid:
            add(f"CybelAngel-Id: {tid}")
        for key in ("category", "threat_type", "issue_type", "type"):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                add(f"CybelAngel-Category: {v.strip()}")
                break
        for key in ("source", "source_name", "channel"):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                add(f"CybelAngel-Source: {v.strip()}")
                break
        for url_key in ("url", "reference_url", "external_url", "evidence_url", "source_url"):
            v = item.get(url_key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def asset_ip(asset):
    """Pick the asset IP from a CybelAngel asset."""
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
    """Walk a CybelAngel asset for hostname candidates."""
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


def build_threat_vulnerability(asset, threat):
    """Build a Faraday vulnerability dict for one CybelAngel threat."""
    if not isinstance(threat, dict):
        return None
    name = (
        threat.get("name")
        or threat.get("title")
        or threat.get("threat_type")
        or threat.get("category")
        or "CybelAngel threat"
    )
    label = f"[EASM] CybelAngel {str(name).strip()}"

    desc_parts = []
    for key in (
        "threat_id",
        "id",
        "threat_type",
        "category",
        "description",
        "summary",
        "details",
        "asset_id",
        "asset_name",
        "source",
        "source_url",
        "channel",
        "created_at",
        "updated_at",
        "first_seen",
        "last_seen",
        "url",
        "domain",
        "ip",
        "risk_score",
        "confidence",
    ):
        v = threat.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{key}: {v}")

    severity = severity_from_cybelangel(threat, cvss=threat.get("cvss") or threat.get("cvssScore"))
    status = status_from_cybelangel(threat)
    cves = collect_cves(threat)
    if not cves:
        cves = collect_cves(asset)
    refs = collect_refs(asset, threat)

    tid = threat.get("threat_id") or threat.get("id") or threat.get("issue_id")
    external_id = str(tid) if tid else str(label)

    resolution = (
        threat.get("remediation")
        or threat.get("remediation_guidance")
        or threat.get("recommendation")
        or (
            "Review the threat in the CybelAngel console (Threats -> "
            "All Threats).  Investigate the underlying exposure (initiate "
            "a takedown, rotate the leaked credential, revoke the leaked "
            "key) or accept the risk."
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
        "tags": ["cybelangel", "easm"],
    }


def build_host_from_asset(asset, threats=None, min_severity=""):
    """Build a Faraday host dict from a CybelAngel asset hit."""
    if not isinstance(asset, dict):
        return None

    ip = asset_ip(asset)
    hostnames = asset_hostnames(asset)

    desc_parts = []
    for key in (
        "asset_id",
        "asset_type",
        "criticality",
        "first_seen",
        "last_seen",
        "discovery_source",
        "platform",
        "owner",
    ):
        v = asset.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    threat_list = (
        threats
        if isinstance(threats, list)
        else (asset.get("threats") if isinstance(asset.get("threats"), list) else [])
    )
    if threat_list:
        desc_parts.append(f"threats={len(threat_list)}")

    vulns = []
    for t in threat_list:
        v = build_threat_vulnerability(asset, t)
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
    """Build a synthetic asset envelope for orphaned threats."""
    asset = {}
    if asset_id:
        asset["asset_id"] = asset_id
    if asset_name:
        asset["asset_name"] = asset_name
    if ip:
        asset["ip"] = ip
    return asset


def fetch_pages(requests_module, url, headers, params_builder, max_pages):
    """Walk a CybelAngel v2.0 search envelope (offset-based pagination)."""
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
            log("CybelAngel request rejected (401). Token may have expired.")
            return out
        if resp.status_code == 403:
            log("CybelAngel request rejected (403). Check the client's scope.")
            return out
        if resp.status_code == 429:
            log("CybelAngel rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"CybelAngel request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"CybelAngel response was not JSON ({url})")
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
        log(f"hit CYBELANGEL_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_CYBELANGEL_MIN_SEVERITY"))
    from_date = validate_from_date(env("EXECUTOR_CONFIG_CYBELANGEL_FROM_DATE"))
    pages = validate_pages(env("EXECUTOR_CONFIG_CYBELANGEL_PAGES"))

    client_id = env("CYBELANGEL_CLIENT_ID", required=True)
    client_secret = env("CYBELANGEL_CLIENT_SECRET", required=True)
    host = env("CYBELANGEL_HOST", default=DEFAULT_API_HOST)
    auth_host = env("CYBELANGEL_AUTH_HOST", default=DEFAULT_AUTH_HOST)
    audience = env("CYBELANGEL_AUDIENCE", default=DEFAULT_AUDIENCE)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token_url = build_token_url(auth_host)
    access_token = fetch_access_token(requests, token_url, client_id, client_secret, audience)
    if not access_token:
        log("OAuth token exchange returned empty access_token; aborting")
        sys.exit(1)

    headers = bearer_headers(access_token)
    threats_url = build_threats_url(host)
    assets_url = build_assets_url(host)

    asset_hits = fetch_pages(
        requests,
        assets_url,
        headers,
        lambda offset: build_paged_params(offset, from_date=from_date, include_from_date=False),
        max_pages=pages,
    )
    threat_hits = fetch_pages(
        requests,
        threats_url,
        headers,
        lambda offset: build_paged_params(offset, from_date=from_date, include_from_date=True),
        max_pages=pages,
    )

    log(
        f"Processing {len(asset_hits)} CybelAngel assets + {len(threat_hits)} threats "
        f"(from_date={from_date!r}, min_severity={min_severity!r}, pages={pages})"
    )

    by_asset_id = {}
    for asset in asset_hits:
        if not isinstance(asset, dict):
            continue
        aid = asset.get("asset_id") or asset.get("id") or asset.get("assetId")
        if aid:
            by_asset_id[str(aid)] = {"asset": asset, "threats": []}

    orphan_threats = []
    for t in threat_hits:
        if not isinstance(t, dict):
            continue
        aid = t.get("asset_id") or t.get("assetId")
        if aid and str(aid) in by_asset_id:
            by_asset_id[str(aid)]["threats"].append(t)
        else:
            orphan_threats.append(t)

    hosts_out = []
    for bucket in by_asset_id.values():
        built = build_host_from_asset(
            bucket["asset"],
            threats=bucket["threats"],
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)

    if orphan_threats:
        synthetic = synthesise_asset(asset_name="(unattached)")
        built = build_host_from_asset(
            synthetic,
            threats=orphan_threats,
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "cybelangel",
            "command": "cybelangel",
            "params": (f"from_date={from_date}," f"min_severity={min_severity}," f"pages={pages}"),
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
