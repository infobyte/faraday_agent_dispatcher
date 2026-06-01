#!/usr/bin/env python
"""Patrowl vulnerability-management importer.

Pulls findings from a Patrowl SOC stack (open-source
vulnerability-management platform — https://patrowl.io/)
and emits Faraday bulk-create JSON to stdout.  Patrowl
orchestrates a fleet of scanner engines (nmap, nessus,
nuclei, owl_dns, owl_code, ...) and stores their output
as ``Finding`` records keyed by ``Asset`` (host / URL /
domain).  This executor surfaces those findings under
the operator's existing Faraday workspace so the SOC
team's view of vulnerabilities joins the dispatcher's
other engine output.

Endpoints used:
  POST {PATROWL_HOST}/api/auth/login
      -> Exchanges ``{PATROWL_USER, PATROWL_PASSWORD}``
      for a Django REST Framework token.  Canonical
      response envelope is ``{"token": "<40-char hex>"}``;
      federated / on-prem mirrors also expose ``{"key":
      "..."}`` (the upstream rest_auth shape) and
      ``{"access_token": "..."}`` (the SimpleJWT shape)
      — all three are tolerated.

  GET {PATROWL_HOST}/findings/api/v1/findings/?page=N&page_size=N
      -> Paginated finding inventory.  The canonical
      envelope is the standard DRF pagination shape
      ``{"count": N, "next": "...", "previous": "...",
      "results": [...]}``.  Federated mirrors collapse
      this into a bare list or ``{"findings": [...]}`` /
      ``{"data": [...]}`` / ``{"items": [...]}`` — all
      four shapes are accepted.  Each finding carries
      ``id``, ``title``, ``description``, ``solution``,
      ``severity`` (``info`` / ``low`` / ``medium`` /
      ``high`` / ``critical``), ``status`` (``new`` /
      ``ack`` / ``assigned`` / ``patched`` / ``closed``
      / ``false-positive`` / ``undone``), ``asset`` (an
      asset id or nested ``{id, value, name, type}``
      dict — ``type`` is one of ``ip`` / ``domain`` /
      ``url`` / ``fqdn`` / ``keyword``), ``asset_name``
      / ``asset_value`` (operator-facing strings),
      ``engine_type`` / ``engine_name`` (the scanner
      that emitted the finding), ``vuln_refs`` (dict of
      ``{"CVE": [...], "CWE": [...], "BID": [...],
      "VPR": "...", ...}`` cross-references), ``risk``
      (optional numeric severity bucket), ``cvss``
      base score, ``cvss_vector``, ``created_at`` /
      ``updated_at`` / ``found_at`` ISO timestamps, and
      ``tags`` (Patrowl's operator-applied tag list).

Auth: Patrowl exposes Django REST Framework's
``TokenAuthentication`` scheme.  The dispatcher POSTs
``{"username": PATROWL_USER, "password":
PATROWL_PASSWORD}`` to ``/api/auth/login`` and receives a
40-character hex token, which is then sent as
``Authorization: Token <token>`` on every subsequent
request.  Patrowl supports session-cookie auth as a
fallback but the dispatcher unconditionally uses the
token path so a stale cookie can't silently impersonate
the operator.

Args:
  ``PATROWL_MIN_SEVERITY`` (optional) — minimum finding
  severity to fetch (``info`` / ``low`` / ``medium`` /
  ``high`` / ``critical``).  When supplied, the
  executor forwards every severity at-or-above the
  floor as the canonical Patrowl ``severity`` filter
  list in the query string so the API itself does the
  server-side narrowing — e.g.
  ``PATROWL_MIN_SEVERITY=medium`` sends
  ``severity=medium&severity=high&severity=critical``.
  Blank / missing / unparseable input keeps every
  finding (the typical operational mode).  Operator-
  friendly aliases (``crit`` / ``Critical`` ->
  ``critical``; ``hi`` / ``High`` -> ``high``;
  ``med`` / ``moderate`` -> ``medium``;
  ``informational`` / ``Info`` -> ``info``) are
  normalised onto the canonical lowercase Patrowl
  vocabulary.

Env vars:
  ``PATROWL_HOST`` (mandatory) — the Patrowl base URL
  (e.g.  ``https://patrowl.acme.lan`` or the canonical
  SaaS host ``https://patrowl.io``).  Patrowl is a
  tenant-keyed product (every install runs on a unique
  hostname) so there is no global default — the
  executor exits cleanly when ``PATROWL_HOST`` is
  missing.  Whitespace is trimmed and ``https://`` is
  added when the operator pasted in a bare FQDN.

  ``PATROWL_USER`` + ``PATROWL_PASSWORD`` (both
  mandatory) — the Patrowl portal credentials.
  ``PATROWL_USER`` is the username (Patrowl supports
  both local accounts + LDAP-mapped accounts);
  ``PATROWL_PASSWORD`` is the matching password.
  Forwarded only to the ``/api/auth/login`` endpoint
  for the initial token exchange — the password never
  leaves the dispatcher's process memory after the
  token is returned.  The executor exits cleanly when
  either is missing.

Each Patrowl finding becomes one Faraday vulnerability
under a single synthetic ``0.0.0.0`` host with hostname
``patrowl``.  Patrowl findings are asset-keyed not host-
keyed in the Faraday sense (Patrowl's ``asset`` field
can be a URL / domain / keyword) — collapsing into a
single synthetic host keeps the import shape consistent
across the rest of the threat-intel group; the actual
asset value is surfaced verbatim in the description +
refs list so operators can pivot back.  The
vulnerability carries ``tags: ['patrowl']`` and
surfaces the title + description + solution + severity
+ status + asset value + engine + risk + CVSS + every
``vuln_refs`` (CVE / CWE / BID / VPR / ...) in both the
description and the refs list so the operator can
pivot from a Faraday finding back to the exact Patrowl
finding record.

Severity is bucketed from Patrowl's published
``severity`` field directly (Patrowl uses Faraday's
exact vocabulary — ``info`` / ``low`` / ``medium`` /
``high`` / ``critical``).  Operator-friendly aliases
are normalised.  Findings whose ``status`` is in the
terminal ``patched`` / ``closed`` / ``false-positive``
states are floored to ``info`` regardless of the
published severity (the finding is no longer live).
Records with no parseable severity default to ``info``
— we don't synthesise a ranking Patrowl hasn't
published.

Status is always ``open`` (a Patrowl finding can be
``patched`` / ``closed`` / ``false-positive`` in the
console but the underlying asset-side risk lives on;
Faraday surfaces the finding as open so the operator's
remediation workflow takes over — the Patrowl state is
preserved via the info-severity floor + an explicit
``Patrowl-Status:`` pivot in the refs).

Resolution defaults to the Patrowl analyst-authored
``solution`` text when present, falling back to a
generic "Triage the finding in the Patrowl portal,
attach the appropriate remediation and update the
finding status." text otherwise.  Findings in terminal
states surface a "Patrowl has marked this finding as
{status}; verify the remediation is reflected on the
affected asset before closing the Faraday finding."
resolution.

Refs include the Patrowl portal deep-link for the
finding (``/findings/details/{id}`` — the operator-
facing finding-detail-page URL), the canonical NVD CVE
permalink for any CVE ids surfaced in ``vuln_refs`` or
the free-text description, and explicit
``Patrowl-FindingID`` / ``Patrowl-Title`` /
``Patrowl-Severity`` / ``Patrowl-Status`` /
``Patrowl-Engine`` / ``Patrowl-EngineType`` /
``Patrowl-Asset`` / ``Patrowl-AssetType`` /
``Patrowl-Risk`` / ``Patrowl-CvssScore`` /
``Patrowl-CvssVector`` / ``Patrowl-CVE`` /
``Patrowl-CWE`` / ``Patrowl-BID`` / ``Patrowl-VPR`` /
``Patrowl-Tag`` / ``Patrowl-Found`` / ``Patrowl-Created``
/ ``Patrowl-Updated`` pivots so operators can pivot
from a Faraday finding back to the exact Patrowl
finding record.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

TIMEOUT = 60

LOGIN_PATH = "/api/auth/login"
FINDINGS_PATH = "/findings/api/v1/findings/"

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
MIN_PAGE_SIZE = 1
MAX_PAGES = 200
MAX_RESULTS = 10000
INTER_REQUEST_SLEEP = 0.3

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ALIASES = {
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "low": "low",
    "lo": "low",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "high": "high",
    "hi": "high",
    "elevated": "high",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
}

SEVERITY_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

VALID_SEVERITY = ALLOWED_SEVERITIES

# Patrowl status vocabulary — terminal states are floored
# to info severity regardless of the published bucket
# (the finding is no longer actively in play).
CLOSED_STATUSES = {
    "patched",
    "closed",
    "false-positive",
    "false_positive",
    "falsepositive",
    "fp",
    "mitigated",
    "resolved",
}


def log(msg):
    print(f"{datetime.utcnow()} - Patrowl: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on PATROWL_HOST.

    Patrowl is a tenant-keyed product (every install runs
    on a unique hostname) so there is no global default —
    empty / missing / non-string inputs return ``""`` (the
    caller hard-fails with a helpful error).  Whitespace
    is trimmed and ``https://`` is added automatically
    when the operator pasted in a bare FQDN (on-prem
    Patrowl stacks typically use raw hostnames).
    """
    if not host:
        return ""
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_min_severity(value):
    """Coerce PATROWL_MIN_SEVERITY into a canonical lowercase severity.

    Returns one of ``info`` / ``low`` / ``medium`` /
    ``high`` / ``critical`` (Patrowl's published
    vocabulary) or ``None`` for missing / blank /
    unknown inputs (no filter — every finding returned
    by Patrowl passes through).  Operator-friendly
    aliases are normalised onto the canonical
    lowercase vocabulary.
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    alias = SEVERITY_ALIASES.get(text.lower())
    if alias is not None:
        return alias
    log(f"PATROWL_MIN_SEVERITY {value!r} is not a known severity; ignoring (no filter)")
    return None


def severities_at_or_above(min_severity):
    """Return the list of Patrowl severities >= ``min_severity``.

    Patrowl's findings endpoint accepts a repeated
    ``severity`` query-string parameter (multiple values
    per request); we surface that as a Python list so a
    ``min_severity=medium`` request carries
    ``severity=medium&severity=high&severity=critical``.
    Returns an empty list when ``min_severity`` is
    ``None`` (no filter applied) so the caller emits
    no ``severity`` key at all in the query string.
    """
    if min_severity is None:
        return []
    floor = SEVERITY_ORDER.get(min_severity)
    if floor is None:
        return []
    return [s for s in ALLOWED_SEVERITIES if SEVERITY_ORDER[s] >= floor]


def validate_page_size(value):
    """Coerce PATROWL_PAGE_SIZE into a clamped integer.

    Defaults to ``DEFAULT_PAGE_SIZE`` (100) when missing /
    blank / unparseable.  Values < ``MIN_PAGE_SIZE`` (1)
    are floored to 1; values > ``MAX_PAGE_SIZE`` (500)
    are capped at the documented DRF page-size ceiling.
    Booleans are rejected (Python booleans are ints but
    coercing ``True`` -> 1 silently masks a manifest
    mis-binding).
    """
    if value is None or isinstance(value, bool):
        return DEFAULT_PAGE_SIZE
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return DEFAULT_PAGE_SIZE
        try:
            n = int(text)
        except ValueError:
            try:
                n = int(float(text))
            except ValueError:
                return DEFAULT_PAGE_SIZE
    else:
        try:
            n = int(value)
        except (TypeError, ValueError):
            return DEFAULT_PAGE_SIZE
    if n < MIN_PAGE_SIZE:
        return MIN_PAGE_SIZE
    if n > MAX_PAGE_SIZE:
        return MAX_PAGE_SIZE
    return n


def build_login_url(host):
    """Build the /api/auth/login URL for the token exchange."""
    base = normalize_base_url(host)
    return f"{base}{LOGIN_PATH}"


def build_findings_url(host, page=1, page_size=DEFAULT_PAGE_SIZE, min_severity=None):
    """Build the paginated /findings/api/v1/findings/ URL.

    Patrowl's findings endpoint uses standard DRF
    pagination with one-based page indices (``page=N``)
    plus a ``page_size=N`` knob.  Severity filtering is
    forwarded as a repeated ``severity`` parameter (DRF
    drf-filter-by-multiple-fields convention).  Bad
    inputs are coerced to safe defaults so a typo
    never crashes the dispatcher.
    """
    base = normalize_base_url(host)
    try:
        p = int(page)
    except (TypeError, ValueError):
        p = 1
    if p < 1:
        p = 1
    try:
        s = int(page_size)
    except (TypeError, ValueError):
        s = DEFAULT_PAGE_SIZE
    if s < MIN_PAGE_SIZE:
        s = MIN_PAGE_SIZE
    if s > MAX_PAGE_SIZE:
        s = MAX_PAGE_SIZE
    params = [("page", p), ("page_size", s)]
    for sev in severities_at_or_above(min_severity):
        params.append(("severity", sev))
    query = urlencode(params)
    return f"{base}{FINDINGS_PATH}?{query}"


def login_payload(username, password):
    """Build the JSON body for the /api/auth/login token exchange.

    Patrowl follows the upstream rest_auth / DRF
    convention: ``{"username": "...", "password":
    "..."}``.  ``None`` / non-string inputs are coerced
    to empty strings so the request still goes through
    and the server can return a useful 400.
    """
    u = username.strip() if isinstance(username, str) else ""
    p = password if isinstance(password, str) else ""
    return {"username": u, "password": p}


def extract_token(body):
    """Pull the auth token from a Patrowl login response.

    Canonical envelope is ``{"token": "<40-char hex>"}``
    (DRF's ``TokenAuthentication`` default).  Federated /
    on-prem mirrors also expose ``{"key": "..."}`` (the
    upstream rest_auth shape) and ``{"access_token":
    "..."}`` (the SimpleJWT shape) — both are tolerated.
    Returns ``""`` (empty string) for missing / non-dict
    / non-string inputs so the caller can hard-fail.
    """
    if not isinstance(body, dict):
        return ""
    for key in ("token", "key", "access_token", "access", "auth_token"):
        v = body.get(key)
        if isinstance(v, str):
            text = v.strip()
            if text:
                return text
    return ""


def request_headers(token):
    """Build the request-header dict for one Patrowl GET.

    DRF's documented ``TokenAuthentication`` header is
    ``Authorization: Token <token>``.  ``Accept:
    application/json`` is always sent.  Missing / blank
    tokens are coerced to an empty string and the
    ``Authorization`` header is omitted entirely (so a
    misconfigured token surfaces as an explicit 401 from
    the server rather than as an empty-header request
    that some Patrowl middleware silently accepts).
    """
    token_str = ""
    if isinstance(token, str):
        token_str = token.strip()
    elif token not in (None, False, True):
        token_str = str(token).strip()
    headers = {"Accept": "application/json"}
    if token_str:
        headers["Authorization"] = f"Token {token_str}"
    return headers


def login_headers():
    """Build the request-header dict for the /api/auth/login POST.

    The login request does not (yet) carry an auth
    token — only ``Accept`` + ``Content-Type``.  Kept as
    a discrete helper so tests can verify the header
    shape independently of the credentialed GETs.
    """
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def parse_iso_datetime(value):
    """Parse an ISO-8601 timestamp into a UTC datetime.

    Patrowl emits ``created_at`` / ``updated_at`` /
    ``found_at`` as ``YYYY-MM-DDTHH:MM:SSZ`` (or with a
    numeric offset on federated mirrors).  Returns
    ``None`` for missing / malformed inputs.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_findings(body):
    """Pull the finding list from a Patrowl findings envelope.

    Canonical envelope is the standard DRF pagination
    shape ``{"count": N, "next": "...", "previous":
    "...", "results": [...]}``.  Federated / mirror
    stacks also expose bare-list, ``{"findings": [...]}``,
    ``{"data": [...]}``, and ``{"items": [...]}`` — all
    four shapes are accepted so the caller doesn't care
    about envelope drift.  Non-dict entries are dropped
    (no shape can recover from a record that isn't a
    dict).
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("results", "findings", "data", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_envelope_meta(body):
    """Pull pagination metadata from a Patrowl envelope.

    Returns ``{"count": int|None, "next": str|None,
    "previous": str|None}`` with missing fields left as
    ``None``.  ``count`` is the canonical DRF total-
    records counter; ``next`` is the URL of the next
    page (``None`` when the walk is complete — that's
    the caller's pagination-stop signal).
    """
    out = {"count": None, "next": None, "previous": None}
    if not isinstance(body, dict):
        return out
    count = body.get("count")
    if count is not None and not isinstance(count, bool):
        try:
            out["count"] = int(count)
        except (TypeError, ValueError):
            out["count"] = None
    nxt = body.get("next")
    if isinstance(nxt, str) and nxt.strip():
        out["next"] = nxt.strip()
    prev = body.get("previous")
    if isinstance(prev, str) and prev.strip():
        out["previous"] = prev.strip()
    return out


def extract_finding_id(finding):
    """Pull the canonical Patrowl finding id (integer / string)."""
    if not isinstance(finding, dict):
        return ""
    for key in ("id", "pk", "finding_id"):
        v = finding.get(key)
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, str):
            text = v.strip()
            if text:
                return text
        else:
            return str(v)
    return ""


def extract_title(finding):
    """Pull the finding display title."""
    if not isinstance(finding, dict):
        return ""
    for key in ("title", "name", "summary"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_description(finding):
    """Pull the free-text analyst description."""
    if not isinstance(finding, dict):
        return ""
    for key in ("description", "details", "summary"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_solution(finding):
    """Pull the analyst-authored remediation text."""
    if not isinstance(finding, dict):
        return ""
    for key in ("solution", "remediation", "recommendation"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_severity(finding):
    """Pull the canonical lowercase Patrowl severity (or '').

    Tolerates case + whitespace + aliasing onto the
    canonical lowercase label.  Returns ``''`` (not
    None) for missing / unknown inputs so the caller
    can treat unscored findings as ``info`` uniformly.
    """
    if not isinstance(finding, dict):
        return ""
    for key in ("severity", "criticality"):
        v = finding.get(key)
        if v is None or isinstance(v, bool):
            continue
        text = str(v).strip()
        if not text:
            continue
        alias = SEVERITY_ALIASES.get(text.lower())
        if alias is not None:
            return alias
    return ""


def extract_status(finding):
    """Pull the Patrowl status (new / ack / patched / closed / ...)."""
    if not isinstance(finding, dict):
        return ""
    v = finding.get("status")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ""


def is_closed_status(value):
    """True when a Patrowl status is terminally closed."""
    if value is None or isinstance(value, bool):
        return False
    if not isinstance(value, str):
        return False
    return value.strip().lower() in CLOSED_STATUSES


def extract_asset(finding):
    """Pull the asset value + type from a Patrowl finding.

    Patrowl's ``asset`` field is variable — it may be an
    integer id, a string value, or a nested ``{id,
    value, name, type}`` dict.  Operator-facing names
    are also surfaced via ``asset_value`` / ``asset_name``
    when present.  Returns ``(value, atype)`` strings,
    both possibly empty.
    """
    if not isinstance(finding, dict):
        return "", ""

    value = ""
    atype = ""

    asset = finding.get("asset")
    if isinstance(asset, dict):
        for key in ("value", "name", "id"):
            v = asset.get(key)
            if isinstance(v, str) and v.strip():
                value = v.strip()
                break
            if isinstance(v, int) and not isinstance(v, bool):
                value = str(v)
                break
        t = asset.get("type")
        if isinstance(t, str) and t.strip():
            atype = t.strip()
    elif isinstance(asset, str) and asset.strip():
        value = asset.strip()
    elif isinstance(asset, int) and not isinstance(asset, bool):
        value = str(asset)

    if not value:
        for key in ("asset_value", "asset_name"):
            v = finding.get(key)
            if isinstance(v, str) and v.strip():
                value = v.strip()
                break

    if not atype:
        for key in ("asset_type", "type"):
            v = finding.get(key)
            if isinstance(v, str) and v.strip():
                atype = v.strip()
                break

    return value, atype


def extract_engine(finding):
    """Pull the engine name + type from a Patrowl finding.

    Patrowl associates findings with the scanner engine
    that emitted them via ``engine_name`` / ``engine_type``
    (e.g. ``nmap`` / ``nessus`` / ``nuclei`` / ``owl_dns``).
    Returns ``(name, etype)`` strings, both possibly
    empty.
    """
    if not isinstance(finding, dict):
        return "", ""
    name = ""
    etype = ""
    for key in ("engine_name", "engine"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            name = v.strip()
            break
        if isinstance(v, dict):
            for k2 in ("name", "title"):
                vv = v.get(k2)
                if isinstance(vv, str) and vv.strip():
                    name = vv.strip()
                    break
            if name:
                break
    v = finding.get("engine_type")
    if isinstance(v, str) and v.strip():
        etype = v.strip()
    return name, etype


def parse_risk_score(value):
    """Parse a Patrowl numeric risk / CVSS score into a float.

    Patrowl emits ``cvss_base_score`` / ``risk`` /
    ``cvss`` as either a float (``7.5``) or a string
    (``"7.5"``).  Returns ``None`` for missing / non-
    numeric / bool inputs.  Negative values are clamped
    to 0.0; values above 10 are clamped to 10.0 (CVSS's
    documented 0..10 range).
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        rating = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if rating != rating:  # NaN check
        return None
    if rating < 0.0:
        return 0.0
    if rating > 10.0:
        return 10.0
    return rating


def extract_cvss(finding):
    """Pull CVSS base-score + vector from a Patrowl finding.

    Returns ``{"score": float|None, "vector": str|None}``
    with missing fields left as ``None``.  Both the
    canonical ``cvss_base_score`` + ``cvss_vector`` pair
    and the bare-``cvss`` shape are accepted.
    """
    out = {"score": None, "vector": None}
    if not isinstance(finding, dict):
        return out
    for key in ("cvss_base_score", "cvss", "cvss_score"):
        v = finding.get(key)
        rating = parse_risk_score(v)
        if rating is not None:
            out["score"] = rating
            break
    vec = finding.get("cvss_vector")
    if isinstance(vec, str) and vec.strip():
        out["vector"] = vec.strip()
    else:
        vec2 = finding.get("cvss_vector_string")
        if isinstance(vec2, str) and vec2.strip():
            out["vector"] = vec2.strip()
    return out


def collect_vuln_refs(finding):
    """Pull cross-reference ids (CVE / CWE / BID / VPR / ...) from a finding.

    Patrowl emits cross-references under ``vuln_refs``
    as a dict keyed by category (``{"CVE": [...],
    "CWE": [...], "BID": [...], "VPR": "..."}``) or as
    a flat list of strings on older mirrors.  Returns a
    list of ``(category, value)`` tuples preserving the
    discovery order.
    """
    out = []
    seen = set()
    if not isinstance(finding, dict):
        return out
    refs = finding.get("vuln_refs")

    def add(category, value):
        if value is None or isinstance(value, bool):
            return
        text = str(value).strip()
        if not text:
            return
        cat = str(category or "").strip().upper() or "REF"
        key = (cat, text.upper())
        if key in seen:
            return
        seen.add(key)
        out.append((cat, text))

    if isinstance(refs, dict):
        for cat, value in refs.items():
            if isinstance(value, list):
                for entry in value:
                    add(cat, entry)
            elif isinstance(value, (str, int, float)):
                add(cat, value)
    elif isinstance(refs, list):
        for entry in refs:
            if isinstance(entry, dict):
                for k, v in entry.items():
                    if isinstance(v, list):
                        for ee in v:
                            add(k, ee)
                    else:
                        add(k, v)
            elif isinstance(entry, str):
                m = CVE_RE.fullmatch(entry.strip())
                if m:
                    add("CVE", entry.strip())
                else:
                    add("REF", entry)
    return out


def collect_cves(finding):
    """Pull CVE ids from the finding refs + title + description + solution.

    Patrowl optionally carries a structured ``vuln_refs.CVE``
    list and additionally surfaces CVEs in the free-text
    title / description / solution.  Returns a deduped
    uppercase list preserving discovery order.
    """
    out = []
    seen = set()
    if not isinstance(finding, dict):
        return out

    for cat, value in collect_vuln_refs(finding):
        if cat != "CVE":
            continue
        m = CVE_RE.fullmatch(value.strip())
        if not m:
            continue
        cve = value.strip().upper()
        if cve in seen:
            continue
        seen.add(cve)
        out.append(cve)

    def harvest(text):
        if not isinstance(text, str):
            return
        for match in CVE_RE.findall(text):
            cve = match.upper()
            if cve in seen:
                continue
            seen.add(cve)
            out.append(cve)

    harvest(extract_title(finding))
    harvest(extract_description(finding))
    harvest(extract_solution(finding))
    return out


def collect_cwes(finding):
    """Pull CWE ids from the structured ``vuln_refs.CWE`` list.

    Returns a deduped list of ``CWE-N`` strings
    preserving discovery order.
    """
    out = []
    seen = set()
    if not isinstance(finding, dict):
        return out
    for cat, value in collect_vuln_refs(finding):
        if cat != "CWE":
            continue
        match = CWE_RE.search(str(value))
        if match:
            cwe = f"CWE-{match.group(1)}"
        else:
            try:
                num = int(str(value).strip())
                cwe = f"CWE-{num}"
            except (TypeError, ValueError):
                continue
        if cwe in seen:
            continue
        seen.add(cwe)
        out.append(cwe)
    return out


def collect_tags(finding):
    """Pull the operator-applied tag list from a Patrowl finding.

    Patrowl's ``tags`` field is a list of strings or
    ``{"name": "..."}`` dicts.  Returns a deduped list
    preserving discovery order.
    """
    out = []
    seen = set()
    if not isinstance(finding, dict):
        return out
    block = finding.get("tags")
    if not isinstance(block, list):
        return out
    for entry in block:
        text = None
        if isinstance(entry, dict):
            n = entry.get("name") or entry.get("value")
            if isinstance(n, str):
                text = n.strip()
        elif isinstance(entry, str):
            text = entry.strip()
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append(text)
    return out


def severity_for_finding(finding):
    """Final Faraday severity for one Patrowl finding.

    Maps the published lowercase severity directly
    (Patrowl uses Faraday's exact vocabulary).  Floors
    closed / patched / false-positive findings to
    ``info`` regardless of the published severity.
    Defaults to ``info`` when the record carries no
    parseable severity — we don't synthesise a ranking
    Patrowl hasn't published.
    """
    sev = extract_severity(finding)
    status = extract_status(finding)
    if is_closed_status(status):
        return "info"
    if not sev:
        return "info"
    return sev if sev in ALLOWED_SEVERITIES else "info"


def finding_portal_url(host, finding_id):
    """Build a best-effort Patrowl portal deep-link for a finding.

    Patrowl's console UI surfaces findings under
    ``/findings/details/{id}`` (the operator-facing
    finding-detail-page URL).  Returns ``""`` for
    missing host / id so the caller can decide whether
    to add the link.
    """
    base = normalize_base_url(host)
    if not base or finding_id in (None, "", False):
        return ""
    return f"{base}/findings/details/{finding_id}"


def collect_refs(finding, host):
    """Build the refs list for one Patrowl finding.

    Includes the Patrowl portal deep-link, the canonical
    NVD CVE permalink for any CVE ids surfaced in the
    structured ``vuln_refs.CVE`` list or the free-text
    description, and explicit ``Patrowl-*`` pivots so
    operators can pivot from a Faraday finding back to
    the exact Patrowl finding record.
    """
    refs = []
    seen = set()

    def add(text, ref_type="other"):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": ref_type})

    if not isinstance(finding, dict):
        return refs

    fid = extract_finding_id(finding)
    if fid:
        portal = finding_portal_url(host, fid)
        if portal:
            add(portal)
        add(f"Patrowl-FindingID: {fid}")

    title = extract_title(finding)
    if title:
        add(f"Patrowl-Title: {title}")

    sev = extract_severity(finding)
    if sev:
        add(f"Patrowl-Severity: {sev}")

    status = extract_status(finding)
    if status:
        add(f"Patrowl-Status: {status}")

    engine_name, engine_type = extract_engine(finding)
    if engine_name:
        add(f"Patrowl-Engine: {engine_name}")
    if engine_type:
        add(f"Patrowl-EngineType: {engine_type}")

    asset_value, asset_type = extract_asset(finding)
    if asset_value:
        add(f"Patrowl-Asset: {asset_value}")
    if asset_type:
        add(f"Patrowl-AssetType: {asset_type}")

    risk = parse_risk_score(finding.get("risk"))
    if risk is not None:
        add(f"Patrowl-Risk: {risk}")

    cvss = extract_cvss(finding)
    if cvss.get("score") is not None:
        add(f"Patrowl-CvssScore: {cvss['score']}")
    if cvss.get("vector"):
        add(f"Patrowl-CvssVector: {cvss['vector']}")

    for cat, value in collect_vuln_refs(finding):
        add(f"Patrowl-{cat.title()}: {value}")
        if cat == "CVE" and CVE_RE.fullmatch(value):
            add(f"https://nvd.nist.gov/vuln/detail/{value.upper()}")

    # CVEs surfaced only in the free-text description still get
    # the NVD permalink (collect_cves walks title + desc + sol).
    for cve in collect_cves(finding):
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    for tag in collect_tags(finding):
        add(f"Patrowl-Tag: {tag}")

    for key, label in (
        ("found_at", "Found"),
        ("created_at", "Created"),
        ("updated_at", "Updated"),
    ):
        dt = parse_iso_datetime(finding.get(key))
        if dt is not None:
            add(f"Patrowl-{label}: {dt.isoformat()}")

    return refs


def resolution_for_finding(finding):
    """Per-finding analyst recommendation.

    Prefers the Patrowl analyst-authored ``solution``
    text when present.  Falls back to a closed-state
    summary for terminal findings, then a generic
    "Triage in the Patrowl portal" text otherwise.
    """
    if not isinstance(finding, dict):
        return "Triage in the Patrowl portal and apply the " "analyst-recommended remediation."
    status = extract_status(finding)
    if is_closed_status(status):
        return (
            f"Patrowl has marked this finding as {status}; verify the "
            "remediation is reflected on the affected asset before "
            "closing the Faraday finding."
        )
    solution = extract_solution(finding)
    if solution:
        return solution
    return (
        "Triage in the Patrowl portal, attach the appropriate "
        "remediation, and update the finding status from new -> ack "
        "-> patched once the affected asset has been remediated."
    )


def build_vulnerability(finding, host):
    """Build a Faraday vulnerability dict for one Patrowl finding."""
    if not isinstance(finding, dict):
        return None

    title = extract_title(finding)
    fid = extract_finding_id(finding)
    if not title and not fid:
        return None

    severity = severity_for_finding(finding)
    sev_label = extract_severity(finding)
    status = extract_status(finding)
    engine_name, engine_type = extract_engine(finding)
    asset_value, asset_type = extract_asset(finding)
    cvss = extract_cvss(finding)
    risk = parse_risk_score(finding.get("risk"))
    cwes = collect_cwes(finding)
    cves = collect_cves(finding)
    description = extract_description(finding)

    name_parts = ["[Patrowl]"]
    if engine_name:
        name_parts.append(f"[{engine_name}]")
    if title:
        name_parts.append(title)
    elif fid:
        name_parts.append(f"finding-{fid}")
    if asset_value:
        name_parts.append(f"on {asset_value}")
    raw_name = " ".join(name_parts)

    desc_parts = []
    if fid:
        desc_parts.append(f"findingID: {fid}")
    if title:
        desc_parts.append(f"title: {title}")
    if sev_label:
        desc_parts.append(f"severity: {sev_label}")
    if status:
        desc_parts.append(f"status: {status}")
    if engine_name:
        desc_parts.append(f"engine: {engine_name}")
    if engine_type:
        desc_parts.append(f"engineType: {engine_type}")
    if asset_value:
        desc_parts.append(f"asset: {asset_value}")
    if asset_type:
        desc_parts.append(f"assetType: {asset_type}")
    if risk is not None:
        desc_parts.append(f"risk: {risk}")
    if cvss.get("score") is not None:
        desc_parts.append(f"cvssScore: {cvss['score']}")
    if cvss.get("vector"):
        desc_parts.append(f"cvssVector: {cvss['vector']}")
    if cwes:
        desc_parts.append(f"cwe: {', '.join(cwes)}")
    if cves:
        desc_parts.append(f"cve: {', '.join(cves)}")
    tags = collect_tags(finding)
    if tags:
        desc_parts.append(f"tags: {', '.join(tags[:20])}")
    found = parse_iso_datetime(finding.get("found_at"))
    if found is not None:
        desc_parts.append(f"found_at: {found.isoformat()}")
    created = parse_iso_datetime(finding.get("created_at"))
    if created is not None:
        desc_parts.append(f"created_at: {created.isoformat()}")
    updated = parse_iso_datetime(finding.get("updated_at"))
    if updated is not None:
        desc_parts.append(f"updated_at: {updated.isoformat()}")
    if description:
        desc_parts.append(f"description: {description}")

    external_id = fid or title[:200] or raw_name
    resolution = resolution_for_finding(finding)

    return {
        "name": str(raw_name).strip()[:200] or "Patrowl finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(finding, host),
        "cve": cves,
        "cwe": cwes,
        "cvss3": {},
        "tags": ["patrowl"],
    }


def build_host(vulns, host, min_severity, meta):
    """Build the single synthetic host that carries every Patrowl vuln.

    Patrowl findings are asset-keyed not host-keyed in
    the Faraday sense (Patrowl's ``asset`` field can be
    a URL / domain / keyword) so we collapse the whole
    fetch under one synthetic ``0.0.0.0`` host with
    hostname ``patrowl``.  The host description carries
    the canonical host URL + min_severity + Patrowl's
    server-reported ``count`` so operators can pivot
    from the host page back to the exact Patrowl fetch.
    """
    desc_parts = ["source=patrowl"]
    base = normalize_base_url(host)
    if base:
        desc_parts.append(f"host={base}")
    if min_severity:
        desc_parts.append(f"min_severity={min_severity}")
    if isinstance(meta, dict):
        count = meta.get("count")
        if count is not None:
            desc_parts.append(f"patrowl_total={count}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["patrowl"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_token(requests_module, host, username, password):
    """POST /api/auth/login and return the auth token string.

    Network / HTTP / JSON errors are logged but never
    raised upstream so a misconfigured Patrowl can't
    crash the dispatcher.  Returns ``""`` on any
    failure (the caller hard-fails after the token
    exchange).
    """
    url = build_login_url(host)
    payload = login_payload(username, password)
    try:
        body_str = json.dumps(payload)
    except (TypeError, ValueError):
        log("login payload was not JSON-serialisable")
        return ""
    try:
        resp = requests_module.post(
            url,
            timeout=TIMEOUT,
            headers=login_headers(),
            data=body_str,
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        return ""
    if resp.status_code == 401 or resp.status_code == 403:
        log(f"Patrowl login rejected ({resp.status_code}) — " "check PATROWL_USER / PATROWL_PASSWORD")
        return ""
    if resp.status_code >= 400:
        log(f"Patrowl login failed ({resp.status_code}): " f"{getattr(resp, 'text', '')[:500]}")
        return ""
    try:
        body = resp.json()
    except ValueError:
        log("Patrowl login response was not JSON")
        return ""
    token = extract_token(body)
    if not token:
        log("Patrowl login response did not carry a token")
    return token


def fetch_url(requests_module, url, headers):
    """GET a single Patrowl URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never
    raised upstream so a transient Patrowl outage
    doesn't crash the dispatcher.  Returns ``None`` on
    any failure; the caller is expected to treat that
    as "no records" and break the pagination loop.
    """
    try:
        resp = requests_module.get(url, timeout=TIMEOUT, headers=headers)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"Patrowl record not found at {url} (404)")
        return None
    if resp.status_code == 401 or resp.status_code == 403:
        log(f"Patrowl auth failed ({resp.status_code}) for {url}: " "check PATROWL_USER / PATROWL_PASSWORD")
        return None
    if resp.status_code >= 400:
        log(f"Patrowl request failed ({resp.status_code}) for {url}: " f"{getattr(resp, 'text', '')[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"Patrowl response was not JSON ({url})")
        return None


def fetch_findings(
    requests_module,
    host,
    headers,
    min_severity=None,
    page_size=DEFAULT_PAGE_SIZE,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    max_results=MAX_RESULTS,
):
    """Page through /findings/api/v1/findings/ and return the records.

    Pagination follows DRF's standard ``page=N&page_size=N``
    pattern.  We break when (1) the page comes back
    empty, (2) the envelope's ``next`` URL is ``None``
    (DRF's documented end-of-list signal), (3)
    ``max_results`` (10000) is hit, or (4) ``max_pages``
    (200) is hit.  ``sleep_fn`` is injectable to keep
    unit tests fast.
    """
    records = []
    last_meta = {"count": None, "next": None, "previous": None}
    for page in range(1, max_pages + 1):
        if page > 1 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        url = build_findings_url(
            host,
            page=page,
            page_size=page_size,
            min_severity=min_severity,
        )
        body = fetch_url(requests_module, url, headers)
        if body is None:
            break
        meta = extract_envelope_meta(body)
        if meta:
            last_meta = meta
        batch = extract_findings(body)
        if not batch:
            break
        for entry in batch:
            records.append(entry)
            if len(records) >= max_results:
                break
        if len(records) >= max_results:
            log(f"Patrowl finding walk hit max_results={max_results}; " "truncating")
            break
        if not last_meta.get("next"):
            break
    return records, last_meta


def main():
    started = time.time()

    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_PATROWL_MIN_SEVERITY"))
    page_size = validate_page_size(env("EXECUTOR_CONFIG_PATROWL_PAGE_SIZE"))
    host = env("PATROWL_HOST", required=True)
    username = env("PATROWL_USER", required=True)
    password = env("PATROWL_PASSWORD", required=True)

    if not normalize_base_url(host):
        log("PATROWL_HOST is not a valid URL")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_token(requests, host, username, password)
    if not token:
        log("Patrowl token exchange failed; aborting")
        sys.exit(1)

    headers = request_headers(token)

    findings, last_meta = fetch_findings(
        requests,
        host,
        headers,
        min_severity=min_severity,
        page_size=page_size,
    )

    vulns = []
    for entry in findings:
        vuln = build_vulnerability(entry, host)
        if vuln is not None:
            vulns.append(vuln)

    total = last_meta.get("count") if isinstance(last_meta, dict) else None
    log(
        f"Processed {len(vulns)} Patrowl findings "
        f"(server_total={total if total is not None else '?'}, "
        f"min_severity={min_severity or 'none'}, page_size={page_size})"
    )

    hosts_out = [build_host(vulns, host, min_severity, last_meta)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "patrowl",
            "command": "patrowl",
            "params": f"min_severity={min_severity or ''} page_size={page_size}",
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
