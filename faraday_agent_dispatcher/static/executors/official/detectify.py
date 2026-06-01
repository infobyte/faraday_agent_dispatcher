#!/usr/bin/env python
"""Detectify EASM importer.

Pulls externally-discovered domains (assets) and findings
(vulnerabilities) from the Detectify platform's v3 REST API and
emits Faraday bulk-create JSON to stdout.  Each Detectify domain
becomes one Faraday host (``ip`` = the synthetic ``0.0.0.0``
sentinel since Detectify is domain-keyed); per-domain findings
attach as one Faraday vulnerability per ``uuid`` / ``id`` with
engine prefix ``[EASM]`` so the data lands in the Faraday
workspace alongside the other attack-surface management feeds.

Endpoints used:
  GET {DETECTIFY_HOST}/rest/v3/teams/{team_token}/domains/
      -> paginated domain inventory for the team.  Detectify is
      domain-keyed (no IP pivot) so the domain ``token`` + ``name``
      populate Faraday's host index.  ``marker`` query parameter
      walks the cursor on subsequent pages.
  GET {DETECTIFY_HOST}/rest/v3/teams/{team_token}/findings/
      -> paginated finding inventory at team scope (every domain
      surfaced by the API key).  When ``DETECTIFY_DOMAIN_TOKEN`` is
      set the URL narrows to
      ``/rest/v3/teams/{team_token}/domains/{domain_token}/findings/``
      so only findings on that single domain are pulled.

Auth: Detectify uses HMAC-SHA256 signed requests.  The operator
creates an API key + secret pair in the Detectify console (Team
Settings -> API Keys -> New) and pastes the returned values into
``DETECTIFY_API_KEY`` + ``DETECTIFY_SECRET``.  The dispatcher
constructs the canonical request string
``<METHOD>;<URL>;<API_KEY>;<TIMESTAMP>;<BODY>``, computes
``base64(HMAC-SHA256(base64_decode(secret), canonical))`` and
sends ``X-Detectify-Key`` + ``X-Detectify-Timestamp`` +
``X-Detectify-Signature`` headers on every request.  The API host
defaults to ``https://api.detectify.com`` and is settable via the
optional ``DETECTIFY_HOST`` env var for on-prem / federated
deployments.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

TIMEOUT = 60
PER_PAGE = 100  # Detectify v3 caps results per page at 100.
DEFAULT_PAGES = 5
MAX_PAGES = 50

DEFAULT_API_HOST = "https://api.detectify.com"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Detectify surfaces string severities on the findings surface.
# Aliases collapse operator-friendly inputs (Important / Major /
# Moderate / etc.) plus Detectify's own labels onto the canonical
# Faraday bucket.
DETECTIFY_STRING_SEVERITY = {
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

# Detectify finding.status -> Faraday status.  Detectify's
# finding-status taxonomy covers open / fixed / accepted_risk /
# false_positive (with a few SaaS-tier synonyms).
DETECTIFY_STATUS = {
    "new": "open",
    "open": "open",
    "active": "open",
    "in_progress": "open",
    "inprogress": "open",
    "reopened": "open",
    "investigating": "open",
    "under_investigation": "open",
    "pending": "open",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "accepted_risk": "risk-accepted",
    "acceptedrisk": "risk-accepted",
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
    print(f"{datetime.utcnow()} - Detectify: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host, default=None):
    """Trim trailing slash + tolerate operator typos on a host URL.

    Whitespace-trims, strips trailing slashes and adds ``https://``
    when the operator pasted in a bare FQDN.  When ``host`` is None
    / blank a ``default`` URL is returned.
    """
    if not isinstance(host, str) or not host.strip():
        return default or ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_team_token(value):
    """Whitespace-trim ``DETECTIFY_TEAM_TOKEN`` (mandatory)."""
    if value is None:
        return ""
    return str(value).strip()


def validate_domain_token(value):
    """Whitespace-trim ``DETECTIFY_DOMAIN_TOKEN`` (optional)."""
    if value is None:
        return ""
    return str(value).strip()


def validate_min_severity(value):
    """Validate DETECTIFY_MIN_SEVERITY (optional severity floor).

    None / blank -> ``""`` (no client-side filter; we emit the full
    findings surface).  Accepts the canonical Faraday severity enum
    (info / low / medium / high / critical) plus Detectify-side
    aliases (Important / Major / Moderate / Informational /
    Negligible / Sev1..Sev5 / P1..P5).  Garbage -> ``""`` with a
    log line.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    if text in VALID_MIN_SEVERITY:
        return text
    bucket = DETECTIFY_STRING_SEVERITY.get(text)
    if bucket is not None:
        return bucket
    log(f"DETECTIFY_MIN_SEVERITY '{value}' not recognised; ignoring filter")
    return ""


def validate_pages(value):
    """Validate DETECTIFY_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Detectify API.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"DETECTIFY_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"DETECTIFY_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_domains_url(host, team_token):
    """Build the team-domains inventory URL."""
    base = normalize_base_url(host, default=DEFAULT_API_HOST)
    return f"{base}/rest/v3/teams/{team_token}/domains/"


def build_findings_url(host, team_token, domain_token=""):
    """Build the findings inventory URL.

    When ``domain_token`` is non-empty the URL narrows to the
    per-domain findings surface
    ``/rest/v3/teams/{team_token}/domains/{domain_token}/findings/``;
    otherwise the team-level findings surface
    ``/rest/v3/teams/{team_token}/findings/`` is returned.
    """
    base = normalize_base_url(host, default=DEFAULT_API_HOST)
    if domain_token:
        return f"{base}/rest/v3/teams/{team_token}/domains/" f"{domain_token}/findings/"
    return f"{base}/rest/v3/teams/{team_token}/findings/"


def build_paged_params(marker="", limit=PER_PAGE):
    """Build the GET query params for a Detectify v3 search surface.

    Detectify v3 uses cursor-based pagination via a ``marker`` query
    parameter.  ``marker`` is empty on the first request and carries
    the response envelope's ``next_marker`` / ``marker`` token on
    every subsequent request.
    """
    params = {"limit": int(limit) if limit else PER_PAGE}
    if marker:
        params["marker"] = str(marker)
    return params


def url_path_and_query(url, params):
    """Build the path-and-query string used in the HMAC canonical.

    Detectify's HMAC canonical request includes the full URL
    (scheme + host + path + query) so we render the query string in
    a stable order (alphabetical by key) to keep the signature
    deterministic.  ``params`` is the dict passed to ``requests.get``
    via the ``params`` kwarg; an empty / None dict produces no query
    component.
    """
    if not params:
        return url
    pieces = []
    for k in sorted(params.keys()):
        v = params[k]
        if v is None:
            continue
        pieces.append(f"{k}={v}")
    if not pieces:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{'&'.join(pieces)}"


def build_canonical(method, url, api_key, timestamp, body=""):
    """Build the canonical request string Detectify signs.

    Format is ``<METHOD>;<URL>;<API_KEY>;<TIMESTAMP>;<BODY>``.
    The URL field carries the full request URL (scheme + host +
    path + query) per Detectify's API reference.
    """
    return f"{method.upper()};{url};{api_key};{timestamp};{body or ''}"


def decode_secret(secret):
    """Base64-decode the Detectify API secret.

    Detectify hands the operator a base64-encoded shared secret in
    the console; the canonical signing path decodes it before using
    it as the HMAC key.  If the secret isn't valid base64 (operator
    pasted in a raw hex / opaque blob), fall back to the raw bytes
    so a misformatted secret surfaces as a 401 from the API rather
    than a local crash.
    """
    if secret is None:
        return b""
    if isinstance(secret, bytes):
        raw = secret
    else:
        raw = str(secret).encode("utf-8")
    try:
        return base64.b64decode(raw, validate=False)
    except Exception:  # noqa: BLE001 — fall back to raw secret
        return raw


def sign_request(method, url, api_key, secret, timestamp, body=""):
    """Compute the X-Detectify-Signature for one request.

    ``base64(HMAC-SHA256(base64_decode(secret), canonical))`` per
    the Detectify v3 reference.
    """
    key = decode_secret(secret)
    canonical = build_canonical(method, url, api_key, timestamp, body)
    digest = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def signed_headers(method, url, api_key, secret, body="", now=None):
    """Return the signed-header set for one Detectify request.

    ``X-Detectify-Key`` + ``X-Detectify-Timestamp`` +
    ``X-Detectify-Signature`` are the canonical three; ``Accept``
    and ``Content-Type`` are passed for completeness.  ``now`` is
    overridable for deterministic tests; defaults to the current
    unix timestamp.
    """
    ts = str(int(now if now is not None else time.time()))
    signature = sign_request(method, url, api_key, secret, ts, body)
    return {
        "X-Detectify-Key": str(api_key),
        "X-Detectify-Timestamp": ts,
        "X-Detectify-Signature": signature,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_hits(body):
    """Pull the hits list from a Detectify v3 search envelope.

    Detectify's canonical shape carries the hits at the root
    (``[{}, {}]``) or under ``items`` / ``data`` / ``results`` /
    ``findings`` / ``domains``.  Some federated stacks include the
    list at the root - accept all of those for resilience.
    """
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("items", "data", "results", "hits", "findings", "domains"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_next_marker(body):
    """Pull the next-page marker from a Detectify v3 search envelope.

    Walks the canonical ``next_marker`` field plus the common
    ``nextMarker`` camelCase / ``marker`` / ``next`` / ``cursor`` /
    ``next_cursor`` aliases.  Empty string is Detectify's
    end-of-stream sentinel — caller treats both ``None`` and
    ``""`` as stop-paginating.
    """
    if not isinstance(body, dict):
        return ""
    for key in ("next_marker", "nextMarker", "marker", "next", "cursor", "next_cursor"):
        v = body.get(key)
        if isinstance(v, str):
            return v.strip()
        if isinstance(v, dict):
            # Some envelopes nest the marker under "pagination" /
            # "page" dicts — walk one level.
            for inner in ("marker", "next_marker", "next", "cursor"):
                iv = v.get(inner)
                if isinstance(iv, str):
                    return iv.strip()
    pagination = body.get("pagination") if isinstance(body.get("pagination"), dict) else None
    if pagination:
        for key in ("next_marker", "nextMarker", "marker", "next", "cursor"):
            v = pagination.get(key)
            if isinstance(v, str):
                return v.strip()
    return ""


def extract_total(body):
    if not isinstance(body, dict):
        return None
    for key in ("total", "total_count", "totalCount", "totalResults", "count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def severity_from_detectify(item, cvss=None):
    """Bucket a Detectify item shape onto a Faraday severity.

    Walks the canonical string ``severity`` field first; falls back
    to ``score`` (Detectify's CVSS surface) and ``risk_score``
    (Detectify's 0..10 risk-rating scale on some findings); falls
    back to ``priority`` / ``risk_rating`` for hand-rolled rules.
    Default is ``info`` (Detectify surfaces attack-surface
    discoveries as well as CVSS-keyed findings).
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            text = item.strip().lower()
            if text in DETECTIFY_STRING_SEVERITY:
                return DETECTIFY_STRING_SEVERITY[text]
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    for key in ("severity", "Severity", "finding_severity", "issue_severity"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in DETECTIFY_STRING_SEVERITY:
                return DETECTIFY_STRING_SEVERITY[text]

    for key in ("priority", "risk_rating", "riskRating"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in DETECTIFY_STRING_SEVERITY:
                return DETECTIFY_STRING_SEVERITY[text]

    # Detectify surfaces both `score` (CVSS) and `risk_score` on
    # different finding types.  Prefer `score` (always CVSS) before
    # the operator-supplied cvss kwarg.
    for key in ("score", "cvss_score", "cvssScore", "cvss"):
        raw = item.get(key)
        if raw is not None:
            return severity_from_cvss(raw)

    risk_score = item.get("risk_score") or item.get("riskScore")
    if risk_score is not None:
        try:
            score = float(risk_score)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            # Detectify's risk_score is 0..10 on the findings surface.
            if score >= 9:
                return "critical"
            if score >= 7:
                return "high"
            if score >= 4:
                return "medium"
            if score >= 1:
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


def status_from_detectify(item):
    """Map a Detectify finding payload to a Faraday status."""
    if not isinstance(item, dict):
        return "open"
    for key in ("status", "Status", "finding_status", "issue_status", "state"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower().replace(" ", "_").replace("-", "_")
            if text in DETECTIFY_STATUS:
                return DETECTIFY_STATUS[text]
    return "open"


def passes_min_severity(severity, min_severity):
    """Client-side severity floor for non-server-filtered shapes."""
    if not min_severity:
        return True
    floor = SEVERITY_ORDER.get(min_severity, 0)
    have = SEVERITY_ORDER.get(severity, 0)
    return have >= floor


def collect_cves(item):
    """Walk a Detectify item for CVE-* ids."""
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


def collect_refs(domain, item=None):
    """Walk a Detectify domain + finding for advisory URLs / pivots."""
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

    if isinstance(domain, dict):
        dtoken = domain.get("token") or domain.get("domain_token") or domain.get("id")
        if dtoken:
            add(f"Detectify-Domain: {dtoken}")
        for key in ("name", "domain", "hostname", "fqdn"):
            v = domain.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Detectify-DomainName: {v.strip()}")
                break

    if isinstance(item, dict):
        fid = item.get("uuid") or item.get("id") or item.get("finding_id")
        if fid:
            add(f"Detectify-Finding: {fid}")
        for key in ("category", "type", "finding_type", "rule"):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Detectify-Category: {v.strip()}")
                break
        # OWASP / CWE pivots
        cwe = item.get("cwe") or item.get("cweId") or item.get("cwe_id")
        if isinstance(cwe, str) and cwe.strip():
            add(f"Detectify-CWE: {cwe.strip()}")
        elif isinstance(cwe, (list, tuple)):
            for c in cwe:
                if isinstance(c, str) and c.strip():
                    add(f"Detectify-CWE: {c.strip()}")
                elif isinstance(c, dict):
                    cv = c.get("id") or c.get("cwe") or c.get("cwe_id")
                    if isinstance(cv, str) and cv.strip():
                        add(f"Detectify-CWE: {cv.strip()}")
        # references list / single
        for list_key in ("references", "external_references"):
            v = item.get(list_key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add(entry)
                    elif isinstance(entry, dict):
                        url = entry.get("url") or entry.get("href") or entry.get("link")
                        if isinstance(url, str) and url.strip():
                            add(url.strip())
        for url_key in ("url", "reference_url", "external_url", "evidence_url"):
            v = item.get(url_key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    return refs


def domain_hostnames(domain):
    """Walk a Detectify domain for hostname candidates."""
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

    if not isinstance(domain, dict):
        return out

    for key in ("name", "domain", "hostname", "fqdn"):
        add(domain.get(key))

    for list_key in ("subdomains", "domains", "hostnames", "fqdns", "names"):
        v = domain.get(list_key)
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


def build_finding_vulnerability(domain, finding):
    """Build a Faraday vulnerability dict for one Detectify finding."""
    if not isinstance(finding, dict):
        return None
    name = (
        finding.get("title")
        or finding.get("name")
        or finding.get("finding_type")
        or finding.get("category")
        or finding.get("rule")
        or "Detectify finding"
    )
    label = f"[EASM] Detectify {str(name).strip()}"

    desc_parts = []
    for key in (
        "uuid",
        "id",
        "finding_id",
        "finding_type",
        "category",
        "rule",
        "description",
        "summary",
        "details",
        "domain",
        "subdomain",
        "url",
        "endpoint",
        "target",
        "ip",
        "port",
        "protocol",
        "method",
        "score",
        "risk_score",
        "cvss",
        "cvss_score",
        "confidence",
        "found_at",
        "first_seen",
        "last_seen",
        "added_at",
        "updated_at",
    ):
        v = finding.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{key}: {v}")

    severity = severity_from_detectify(
        finding,
        cvss=finding.get("cvss") or finding.get("cvssScore") or finding.get("cvss_score"),
    )
    status = status_from_detectify(finding)
    cves = collect_cves(finding)
    if not cves:
        cves = collect_cves(domain)
    refs = collect_refs(domain, finding)

    fid = finding.get("uuid") or finding.get("id") or finding.get("finding_id")
    external_id = str(fid) if fid else str(label)

    resolution = (
        finding.get("remediation")
        or finding.get("remediation_guidance")
        or finding.get("recommendation")
        or (
            "Review the finding in the Detectify console (Findings -> "
            "All Findings).  Remediate the underlying issue (patch the "
            "vulnerable component, harden the configuration, restrict "
            "exposure) or mark the finding as accepted_risk / "
            "false_positive."
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
        "tags": ["detectify", "easm"],
    }


def build_host_from_domain(domain, findings=None, min_severity=""):
    """Build a Faraday host dict from a Detectify domain.

    Detectify is domain-keyed (no canonical IP pivot) so ``ip`` is
    always the synthetic ``0.0.0.0`` sentinel and the domain
    ``name`` / ``token`` lands in ``hostnames`` + ``description``.
    """
    if not isinstance(domain, dict):
        return None

    hostnames = domain_hostnames(domain)

    desc_parts = []
    for key in (
        "token",
        "domain_token",
        "name",
        "monitored",
        "verified",
        "created",
        "added",
        "added_at",
        "monitored_since",
        "asset_type",
        "platform",
    ):
        v = domain.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    finding_list = (
        findings
        if isinstance(findings, list)
        else (domain.get("findings") if isinstance(domain.get("findings"), list) else [])
    )
    if finding_list:
        desc_parts.append(f"findings={len(finding_list)}")

    vulns = []
    for f in finding_list:
        v = build_finding_vulnerability(domain, f)
        if v is not None and passes_min_severity(v.get("severity", "info"), min_severity):
            vulns.append(v)

    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def synthesise_domain(token=None, name=None):
    """Build a synthetic domain envelope for orphaned findings."""
    domain = {}
    if token:
        domain["token"] = token
    if name:
        domain["name"] = name
    return domain


def fetch_pages(requests_module, url, api_key, secret, params_builder, max_pages, now_fn=None):
    """Walk a Detectify v3 search envelope (marker-based pagination).

    Detectify's pagination is cursor-based via the ``marker`` query
    parameter; the response envelope's ``next_marker`` carries the
    cursor for the next page.  Empty ``next_marker`` is the
    end-of-stream sentinel.  Each page is HMAC-signed independently
    via ``signed_headers`` so the timestamp + signature stay valid
    across long walks.
    """
    out = []
    marker = ""
    walked = 0
    seen_markers = set()
    hits = []
    while walked < max_pages:
        params = params_builder(marker)
        signed_url = url_path_and_query(url, params)
        headers = signed_headers(
            "GET",
            signed_url,
            api_key,
            secret,
            body="",
            now=(now_fn() if callable(now_fn) else None),
        )
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Detectify request rejected (401). Check DETECTIFY_API_KEY / DETECTIFY_SECRET.")
            return out
        if resp.status_code == 403:
            log("Detectify request rejected (403). Check the key's scope.")
            return out
        if resp.status_code == 404:
            log(f"Detectify endpoint not found (404) for {url}.")
            return out
        if resp.status_code == 429:
            log("Detectify rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Detectify request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Detectify response was not JSON ({url})")
            return out
        hits = extract_hits(payload)
        for entry in hits:
            if isinstance(entry, dict):
                out.append(entry)
        nxt = extract_next_marker(payload)
        walked += 1
        if not hits:
            break
        if not nxt:
            break
        if nxt in seen_markers:
            break
        seen_markers.add(nxt)
        marker = nxt
    if walked >= max_pages and hits:
        log(f"hit DETECTIFY_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    team_token = validate_team_token(env("EXECUTOR_CONFIG_DETECTIFY_TEAM_TOKEN"))
    if not team_token:
        log("DETECTIFY_TEAM_TOKEN is required")
        sys.exit(1)
    domain_token = validate_domain_token(env("EXECUTOR_CONFIG_DETECTIFY_DOMAIN_TOKEN"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_DETECTIFY_MIN_SEVERITY"))
    pages = validate_pages(env("EXECUTOR_CONFIG_DETECTIFY_PAGES"))

    api_key = env("DETECTIFY_API_KEY", required=True)
    secret = env("DETECTIFY_SECRET", required=True)
    host = env("DETECTIFY_HOST", default=DEFAULT_API_HOST)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    domains_url = build_domains_url(host, team_token)
    findings_url = build_findings_url(host, team_token, domain_token=domain_token)

    domain_hits = fetch_pages(
        requests,
        domains_url,
        api_key,
        secret,
        lambda marker: build_paged_params(marker=marker),
        max_pages=pages,
    )
    finding_hits = fetch_pages(
        requests,
        findings_url,
        api_key,
        secret,
        lambda marker: build_paged_params(marker=marker),
        max_pages=pages,
    )

    log(
        f"Processing {len(domain_hits)} Detectify domains + {len(finding_hits)} findings "
        f"(team={team_token!r}, domain={domain_token!r}, min_severity={min_severity!r}, pages={pages})"
    )

    by_domain_token = {}
    by_domain_name = {}
    for domain in domain_hits:
        if not isinstance(domain, dict):
            continue
        dtoken = domain.get("token") or domain.get("domain_token") or domain.get("id")
        dname = domain.get("name") or domain.get("domain")
        bucket = {"domain": domain, "findings": []}
        if dtoken:
            by_domain_token[str(dtoken)] = bucket
        if dname:
            by_domain_name[str(dname)] = bucket

    orphan_findings = []
    for f in finding_hits:
        if not isinstance(f, dict):
            continue
        dtoken = f.get("domain_token") or f.get("domainToken")
        dname = f.get("domain") or f.get("domain_name") or f.get("subdomain")
        if dtoken and str(dtoken) in by_domain_token:
            by_domain_token[str(dtoken)]["findings"].append(f)
        elif dname and str(dname) in by_domain_name:
            by_domain_name[str(dname)]["findings"].append(f)
        else:
            orphan_findings.append(f)

    hosts_out = []
    emitted_buckets = set()
    for bucket in by_domain_token.values():
        bid = id(bucket)
        if bid in emitted_buckets:
            continue
        emitted_buckets.add(bid)
        built = build_host_from_domain(
            bucket["domain"],
            findings=bucket["findings"],
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)
    for bucket in by_domain_name.values():
        bid = id(bucket)
        if bid in emitted_buckets:
            continue
        emitted_buckets.add(bid)
        built = build_host_from_domain(
            bucket["domain"],
            findings=bucket["findings"],
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)

    if orphan_findings:
        synthetic = synthesise_domain(name="(unattached)")
        built = build_host_from_domain(
            synthetic,
            findings=orphan_findings,
            min_severity=min_severity,
        )
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "detectify",
            "command": "detectify",
            "params": (
                f"team_token={team_token},"
                f"domain_token={domain_token},"
                f"min_severity={min_severity},"
                f"pages={pages}"
            ),
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
