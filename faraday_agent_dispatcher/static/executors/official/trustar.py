#!/usr/bin/env python
"""TruSTAR / Splunk Intelligence Management importer.

Pulls indicator records from the TruSTAR Station REST API
(rebranded as Splunk Intelligence Management after the 2021
Splunk acquisition and folded into Splunk SOAR) and emits
Faraday bulk-create JSON to stdout.  TruSTAR is an
intelligence-correlation platform that ingests vendor +
analyst-curated feeds into operator-scoped ``enclaves`` and
re-emits a normalised indicator record per IOC tagged with
``priorityLevel`` (LOW / MEDIUM / HIGH / NOT_FOUND),
``correlationCount`` (how many enclave reports referenced the
IOC), and analyst-attached ``attributes`` / ``tags``.

Endpoints used:
  GET {TRUSTAR_HOST}/api/1.3/enclaves
      -> List the enclaves the operator's API key has access
      to.  Used as a discovery step when ``TRUSTAR_ENCLAVE_IDS``
      is blank so first-time imports walk every readable
      enclave without forcing the operator to enumerate ids
      by hand.  The canonical envelope is a bare-list (older
      Station mirrors wrap in ``{"items": [...]}``); both
      shapes are accepted via ``extract_enclaves()``.

  POST {TRUSTAR_HOST}/api/1.3/indicators/search
      ?pageNumber=N&pageSize=N
      -> Paginated indicator search.  Body is the canonical
      filter shape ``{"enclaveIds": [...], "priorityScores":
      [...]}``; both keys are omitted when the corresponding
      filter is empty.  Response is the canonical Spring
      Pageable envelope
      ``{"items": [...], "pageNumber": N, "pageSize": N,
      "totalElements": N, "hasNext": bool}`` (with bare-list /
      ``data`` / ``results`` / ``indicators`` fallbacks for
      federated mirrors).  Each indicator record carries
      ``indicatorId`` (or ``id``), ``value`` (the IOC value),
      ``indicatorType`` (``MD5`` / ``SHA1`` / ``SHA256`` /
      ``IP4`` / ``IP6`` / ``URL`` / ``DOMAIN`` / ``EMAIL_ADDRESS``
      / ``CIDR_BLOCK`` / ``CVE`` / ``MALWARE`` /
      ``BITCOIN_ADDRESS``), ``priorityLevel``,
      ``correlationCount``, ``enclaveIds``, ``tags``,
      ``attributes``, ``notes``, ``firstSeen`` / ``lastSeen``
      (ms-epoch or ISO-8601).

Auth: OAuth2 ``client_credentials`` — ``TRUSTAR_API_KEY`` +
``TRUSTAR_API_SECRET`` are both mandatory env vars exchanged
at ``POST {TRUSTAR_HOST}/oauth/token`` with HTTP Basic +
form-encoded ``grant_type=client_credentials`` body
(RFC 6749) for a short-lived (~1h) Bearer token sent as
``Authorization: Bearer ...`` on every subsequent v1.3
request.  ``requests`` is lazy-imported inside ``main()`` so
the module loads (and all helpers exercise) without
``requests`` installed; the executor exits cleanly when
``requests`` is missing at runtime.

Args:
  ``TRUSTAR_ENCLAVE_IDS`` (optional, CSV) — comma-separated
  enclave UUIDs the executor should scope the search to.
  When blank / missing (the typical operational mode for
  first-time imports), the executor calls
  ``/api/1.3/enclaves`` first to discover every readable
  enclave the API key has access to.  Whitespace is trimmed
  and dedupe is case-insensitive.

  ``TRUSTAR_PRIORITY`` (optional, one of ``LOW`` / ``MEDIUM``
  / ``HIGH``) — analyst-judgement priority floor.  Forwarded
  server-side via the ``priorityScores`` body field as the
  at-or-above slice (so ``MEDIUM`` sends
  ``["MEDIUM", "HIGH"]``).  Operator-friendly aliases are
  accepted (``low`` / ``medium`` / ``high`` case-insensitive,
  plus ``critical`` / ``crit`` -> ``HIGH``, ``moderate`` /
  ``med`` -> ``MEDIUM``).  Blank / missing keeps every
  indicator (the typical operational mode); unknown values
  are rejected client-side with a hard error so a typo
  doesn't silently widen the result set.

Env vars:
  ``TRUSTAR_API_KEY`` + ``TRUSTAR_API_SECRET`` (both
  mandatory) — the OAuth2 client credential pair issued by
  the Station console at API-key-creation time.  The
  executor exits cleanly when either is missing.

  ``TRUSTAR_HOST`` (optional, not in the manifest's declared
  env vars) — defaults to ``https://api.trustar.co`` (the
  canonical Station REST host on the Splunk-hosted Trust /
  US cloud).  EU / on-prem / Splunk-SOAR-bundled tenants are
  tolerated and ``https://`` is added when the operator
  pasted in a bare FQDN.

Each indicator becomes one Faraday vulnerability under a
single synthetic ``0.0.0.0`` host with hostname ``trustar``
(TruSTAR indicators are IOC-keyed not host-keyed — the
operator's other agents emit the host-side findings this
feed is correlated against).  The vulnerability carries
``tags: ['trustar']``, the ``[TruSTAR]`` engine prefix, the
canonical indicator type + value + priority + correlation
count in the name, and the Station record id in
``external_id``.

Severity is bucketed from the published priority label:
``HIGH`` -> ``high``, ``MEDIUM`` -> ``medium``, ``LOW`` ->
``low``, ``NOT_FOUND`` / missing -> ``info`` (we don't
synthesise a ranking Station hasn't published).  HIGH
records with ``correlationCount >= 10`` (the IOC is
corroborated across 10+ unrelated enclave reports) are
bumped to ``critical`` — heavy cross-enclave correlation is
analyst-strong evidence the IOC is live in the operator's
threat landscape.  CVE-typed indicators are passed through
to the ``cve`` list verbatim.

Status is always ``open`` (a TruSTAR indicator cannot be
'fixed' in the catalog — it can only be blocked on the
operator's perimeter / EDR).

Resolution defaults to a type-appropriate blocking
recommendation (MD5 / SHA1 / SHA256 -> EDR + AV + endpoint
prevention; IP4 / IP6 / CIDR_BLOCK -> firewall + egress
proxy + EDR containment; URL -> egress proxy + endpoint
web-filter; DOMAIN -> DNS sinkhole + perimeter blocklist;
EMAIL_ADDRESS -> mail-server blocklist + DMARC quarantine;
CVE -> NVD lookup + patch operator-side affected assets;
MALWARE / BITCOIN_ADDRESS -> SOC / threat-hunting triage).

Refs include the canonical Station web-UI permalink
(``/constellation/indicator?id=<id>`` — the human-facing
console URL), the canonical NVD CVE permalink for any CVE
ids surfaced in the indicator value (when type == CVE) or
in the free-text ``notes`` / ``tags`` (each with an explicit
``Trustar-CVE:`` pivot), and explicit ``Trustar-ID`` /
``Trustar-Type`` / ``Trustar-Value`` / ``Trustar-Priority``
/ ``Trustar-Correlation`` / ``Trustar-EnclaveID`` /
``Trustar-Tag`` / ``Trustar-Attribute`` /
``Trustar-FirstSeen`` / ``Trustar-LastSeen`` pivots so
operators can pivot from a Faraday finding back to the
Station record.
"""

import base64
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

TIMEOUT = 60

DEFAULT_HOST = "https://api.trustar.co"
TOKEN_PATH = "/oauth/token"
ENCLAVES_PATH = "/api/1.3/enclaves"
INDICATORS_SEARCH_PATH = "/api/1.3/indicators/search"

DEFAULT_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 1000
MAX_PAGES = 100
MAX_RESULTS = 5000
INTER_REQUEST_SLEEP = 0.4

CORRELATION_BUMP_THRESHOLD = 10

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

ALLOWED_PRIORITIES = ("LOW", "MEDIUM", "HIGH")
PRIORITY_ALIASES = {
    "low": "LOW",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "med": "MEDIUM",
    "high": "HIGH",
    "critical": "HIGH",
    "crit": "HIGH",
}

PRIORITY_SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Type-grouped resolution recommendations.  Indicator types
# are TruSTAR's canonical uppercased vocabulary; aliases /
# unknown types fall through to a generic SOC-triage text.
HASH_TYPES = {"MD5", "SHA1", "SHA256", "SHA512", "IMPHASH", "SSDEEP"}
IP_TYPES = {"IP4", "IP6", "IP_ADDRESS", "IPV4", "IPV6", "CIDR_BLOCK"}
URL_TYPES = {"URL", "URI"}
DOMAIN_TYPES = {"DOMAIN", "HOST", "FQDN"}
EMAIL_TYPES = {"EMAIL_ADDRESS", "EMAIL"}
CVE_TYPES = {"CVE", "CVE_ID"}


def log(msg):
    print(
        f"{datetime.utcnow()} - TruSTAR: {msg}",
        file=sys.stderr,
        flush=True,
    )


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
    """Trim trailing slash + tolerate operator typos on TRUSTAR_HOST.

    Defaults to ``https://api.trustar.co`` (the canonical
    Splunk-hosted Station REST host) when the env override is
    missing / blank.  Whitespace is trimmed and ``https://``
    is added automatically when the operator pasted in a bare
    FQDN.
    """
    if not host:
        return DEFAULT_HOST
    if not isinstance(host, str):
        return DEFAULT_HOST
    text = host.strip().rstrip("/")
    if not text:
        return DEFAULT_HOST
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def parse_enclave_ids(value):
    """Split a CSV of TRUSTAR_ENCLAVE_IDS into a clean list.

    Whitespace is trimmed, blank entries dropped, and
    deduplication is case-insensitive while preserving the
    operator-supplied order.  Returns ``[]`` for None / blank
    / non-string / bool inputs.
    """
    if value is None or isinstance(value, bool):
        return []
    if not isinstance(value, str):
        try:
            text = str(value)
        except Exception:  # noqa: BLE001
            return []
    else:
        text = value
    out = []
    seen = set()
    for raw in text.split(","):
        token = raw.strip()
        if not token:
            continue
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(token)
    return out


def validate_priority(value):
    """Coerce TRUSTAR_PRIORITY into one of LOW / MEDIUM / HIGH.

    Operator-friendly aliases (``critical`` / ``crit`` ->
    ``HIGH``, ``moderate`` / ``med`` -> ``MEDIUM``) are
    normalised onto the canonical uppercased name.  Returns
    ``None`` for blank / missing / unknown inputs so the
    caller can either keep every indicator (blank input) or
    hard-fail with a helpful error (unknown input).
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    upper = text.upper()
    if upper in ALLOWED_PRIORITIES:
        return upper
    alias = PRIORITY_ALIASES.get(text.lower())
    if alias is not None:
        return alias
    return None


def priorities_at_or_above(priority):
    """Return the at-or-above slice of priorities for a floor.

    LOW -> [LOW, MEDIUM, HIGH]; MEDIUM -> [MEDIUM, HIGH]; HIGH
    -> [HIGH]; None -> [] (no server-side filtering).
    """
    if priority not in ALLOWED_PRIORITIES:
        return []
    idx = ALLOWED_PRIORITIES.index(priority)
    return list(ALLOWED_PRIORITIES[idx:])


def validate_page_size(value):
    """Coerce a per-request page size into [MIN_PAGE_SIZE, MAX_PAGE_SIZE].

    None / blank / bool / unparseable falls back to the
    default (100).  Values below the floor are bumped to 1;
    values above MAX_PAGE_SIZE are capped (TruSTAR documents
    1000 as the ceiling on ``/api/1.3/indicators/search``).
    """
    if value is None or value == "":
        return DEFAULT_PAGE_SIZE
    if isinstance(value, bool):
        return DEFAULT_PAGE_SIZE
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return DEFAULT_PAGE_SIZE
    if n < MIN_PAGE_SIZE:
        return MIN_PAGE_SIZE
    if n > MAX_PAGE_SIZE:
        return MAX_PAGE_SIZE
    return n


def build_token_url(host):
    """Build the OAuth2 token-exchange URL for Station."""
    return f"{normalize_base_url(host)}{TOKEN_PATH}"


def build_enclaves_url(host):
    """Build the enclaves-list URL for Station."""
    return f"{normalize_base_url(host)}{ENCLAVES_PATH}"


def build_search_url(host, page_number=0, page_size=DEFAULT_PAGE_SIZE):
    """Build the paginated indicators-search URL."""
    try:
        pn = int(page_number)
    except (TypeError, ValueError):
        pn = 0
    if pn < 0:
        pn = 0
    try:
        ps = int(page_size)
    except (TypeError, ValueError):
        ps = DEFAULT_PAGE_SIZE
    if ps < MIN_PAGE_SIZE:
        ps = MIN_PAGE_SIZE
    if ps > MAX_PAGE_SIZE:
        ps = MAX_PAGE_SIZE
    qs = urlencode([("pageNumber", pn), ("pageSize", ps)])
    return f"{normalize_base_url(host)}{INDICATORS_SEARCH_PATH}?{qs}"


def build_search_body(enclave_ids, priority_floor):
    """Build the canonical indicators-search request body.

    Both keys are omitted entirely when the corresponding
    filter is empty.  This matches Station's documented
    behaviour where missing keys are treated as 'no filter'
    instead of being forwarded as empty arrays.
    """
    body = {}
    if isinstance(enclave_ids, list):
        cleaned = [eid for eid in enclave_ids if isinstance(eid, str) and eid.strip()]
        if cleaned:
            body["enclaveIds"] = cleaned
    priorities = priorities_at_or_above(priority_floor) if priority_floor else []
    if priorities:
        body["priorityScores"] = priorities
    return body


def basic_auth_header(api_key, api_secret):
    """Build the HTTP Basic auth header used by the OAuth token call.

    Station base64-encodes ``api_key:api_secret`` and sends
    it as the ``Authorization`` header on the token exchange.
    Missing / non-string inputs are coerced to empty strings
    so the signing call never raises locally — the server can
    still reject the bad credentials with a useful 401.
    """
    k = str(api_key or "").strip()
    s = str(api_secret or "").strip()
    raw = f"{k}:{s}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return f"Basic {encoded}"


def token_request_headers(api_key, api_secret):
    """Headers for the OAuth2 token-exchange POST."""
    return {
        "Accept": "application/json",
        "Authorization": basic_auth_header(api_key, api_secret),
        "Content-Type": "application/x-www-form-urlencoded",
    }


def request_headers(token):
    """Build the standard authenticated header dict for v1.3 calls.

    ``Accept: application/json`` is always present;
    ``Content-Type: application/json`` is included so the
    indicators-search POST body is parsed correctly server
    side; ``Authorization: Bearer <token>`` is sent when a
    token has been exchanged (None / blank tokens are
    skipped so the server's 401 is the operator's signal
    rather than an opaque local TypeError).
    """
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if isinstance(token, str):
        stripped = token.strip()
        if stripped:
            headers["Authorization"] = f"Bearer {stripped}"
    return headers


def parse_iso_datetime(value):
    """Parse an ISO-8601 or ms-epoch timestamp into a UTC datetime.

    Station emits ``firstSeen`` / ``lastSeen`` as either a
    millisecond epoch int (the historical TruSTAR form) or an
    ISO-8601 string (the post-Splunk Station rewrite).  We
    accept both.  Returns ``None`` for missing / malformed
    inputs.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        if value <= 0:
            return None
        try:
            return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    # Integer-as-string ms epoch
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text) / 1000.0, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
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


def extract_access_token(body):
    """Pull the ``access_token`` string from a Station OAuth2 response.

    Returns ``None`` for non-dict / missing-key / blank /
    non-string values so the caller can hard-fail without
    forwarding a malformed token to the v1.3 surface.
    """
    if not isinstance(body, dict):
        return None
    token = body.get("access_token")
    if not isinstance(token, str):
        return None
    stripped = token.strip()
    return stripped or None


def extract_enclaves(body):
    """Pull the enclaves list from a Station enclaves response.

    The canonical Station response is a bare-list; older
    Station mirrors wrap in ``{"items": [...]}`` and some
    federated stacks use ``{"data": [...]}`` /
    ``{"enclaves": [...]}``.  All are accepted; non-dict
    entries are dropped silently.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("items", "data", "results", "enclaves"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_indicators(body):
    """Pull the indicator-record list from a search response.

    Canonical envelope is ``{"items": [...], "pageNumber": N,
    "pageSize": N, "totalElements": N, "hasNext": bool}``.
    Bare-list / ``data`` / ``results`` / ``indicators``
    fallbacks are accepted for federated mirrors.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("items", "data", "results", "indicators"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_envelope_meta(body):
    """Pull pagination + count metadata from a search envelope.

    Returns ``{"pageNumber": int|None, "pageSize": int|None,
    "totalElements": int|None, "hasNext": bool|None}`` with
    missing fields left as ``None`` and bool-typed fields
    surfaced verbatim.
    """
    out = {
        "pageNumber": None,
        "pageSize": None,
        "totalElements": None,
        "hasNext": None,
    }
    if not isinstance(body, dict):
        return out
    for key in ("pageNumber", "pageSize", "totalElements"):
        v = body.get(key)
        if v is None or isinstance(v, bool):
            continue
        try:
            out[key] = int(v)
        except (TypeError, ValueError):
            continue
    hn = body.get("hasNext")
    if isinstance(hn, bool):
        out["hasNext"] = hn
    elif isinstance(hn, str):
        if hn.strip().lower() == "true":
            out["hasNext"] = True
        elif hn.strip().lower() == "false":
            out["hasNext"] = False
    return out


def extract_indicator_id(record):
    """Pull the canonical Station indicator id.

    Tolerates ``indicatorId`` (the v1.3 field), ``id`` (the
    older Station form), and ``_id`` for federated mirrors.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("indicatorId", "id", "_id", "recordId"):
        v = record.get(key)
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, str):
            text = v.strip()
            if text:
                return text
        else:
            return str(v)
    return ""


def extract_indicator_type(record):
    """Pull the indicator type (e.g. ``MD5`` / ``IP4`` / ``URL``).

    Uppercased so the caller can match against
    ``HASH_TYPES`` / ``IP_TYPES`` / ``URL_TYPES`` /
    ``DOMAIN_TYPES`` etc. without a per-call ``.upper()``.
    Tolerates both ``indicatorType`` (the v1.3 field) and
    ``type`` (the older form) for federated mirrors.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("indicatorType", "type"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().upper()
    return ""


def extract_indicator_value(record):
    """Pull the indicator value (the hash / IP / URL / domain)."""
    if not isinstance(record, dict):
        return ""
    for key in ("value", "indicatorValue"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_priority_label(record):
    """Pull the canonical priority label (HIGH / MEDIUM / LOW / NOT_FOUND).

    Tolerates case + whitespace + the ``priorityLevel`` (v1.3)
    + ``priority`` / ``priorityScore`` fallback fields used by
    older mirrors.  Returns ``''`` (not ``None``) for missing
    / unknown / NOT_FOUND inputs so the caller can treat
    unscored records as ``info`` uniformly.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("priorityLevel", "priority", "priorityScore"):
        v = record.get(key)
        if v is None or isinstance(v, bool):
            continue
        text = str(v).strip()
        if not text:
            continue
        upper = text.upper()
        if upper in ALLOWED_PRIORITIES:
            return upper
        if upper in ("NOT_FOUND", "NOT-FOUND", "NOTFOUND", "NONE"):
            return ""
    return ""


def extract_correlation_count(record):
    """Pull the correlation count (number of enclave reports the IOC appears in).

    Tolerates ``correlationCount`` (v1.3) and
    ``reportCount`` / ``observations`` for federated mirrors.
    Returns ``None`` for missing / non-numeric inputs so the
    caller can omit the field from the description rather
    than emitting a misleading ``0``.
    """
    if not isinstance(record, dict):
        return None
    for key in ("correlationCount", "reportCount", "observations"):
        v = record.get(key)
        if v is None or isinstance(v, bool):
            continue
        try:
            n = int(v)
        except (TypeError, ValueError):
            continue
        if n < 0:
            continue
        return n
    return None


def extract_enclave_ids(record):
    """Pull the enclave-id list the indicator was observed in."""
    if not isinstance(record, dict):
        return []
    raw = record.get("enclaveIds")
    if isinstance(raw, list):
        return [eid.strip() for eid in raw if isinstance(eid, str) and eid.strip()]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return []


def extract_tags(record):
    """Pull the analyst-attached tag list.

    Station emits tags as either a list of dicts
    ``[{"name": "..."}]`` or a list of bare strings
    depending on the API version.  We accept both and dedupe
    case-insensitively while preserving order.
    """
    if not isinstance(record, dict):
        return []
    raw = record.get("tags")
    if not isinstance(raw, list):
        return []
    out = []
    seen = set()
    for entry in raw:
        if isinstance(entry, str):
            text = entry.strip()
        elif isinstance(entry, dict):
            inner = entry.get("name") or entry.get("value") or entry.get("tag")
            text = inner.strip() if isinstance(inner, str) else ""
        else:
            text = ""
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def extract_attributes(record):
    """Pull the analyst-attached attribute pairs.

    Station attributes are typed metadata (``{"type":
    "MALWARE_FAMILY", "value": "Emotet"}``).  We return a
    deduped list of ``"<type>: <value>"`` strings for the
    refs builder.
    """
    if not isinstance(record, dict):
        return []
    raw = record.get("attributes")
    if not isinstance(raw, list):
        return []
    out = []
    seen = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        a_type = entry.get("type") or entry.get("name") or ""
        a_value = entry.get("value") or ""
        if not isinstance(a_type, str) or not isinstance(a_value, str):
            continue
        a_type = a_type.strip()
        a_value = a_value.strip()
        if not a_value:
            continue
        if a_type:
            text = f"{a_type}: {a_value}"
        else:
            text = a_value
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def extract_notes(record):
    """Pull the free-text analyst notes for a record."""
    if not isinstance(record, dict):
        return ""
    for key in ("notes", "note", "description"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def severity_for_record(record):
    """Final Faraday severity for an indicator record.

    Maps the published priority label onto Faraday's high /
    medium / low ladder; bumps HIGH records to ``critical``
    when ``correlationCount >= CORRELATION_BUMP_THRESHOLD``
    (the IOC is corroborated across many unrelated enclave
    reports — analyst-strong evidence of live activity in
    the operator's threat landscape).  Records without a
    parseable priority default to ``info`` — we don't
    synthesise a ranking Station hasn't published.
    """
    if not isinstance(record, dict):
        return "info"
    label = extract_priority_label(record)
    base = PRIORITY_SEVERITY_MAP.get(label, "info")
    if base == "high":
        count = extract_correlation_count(record)
        if count is not None and count >= CORRELATION_BUMP_THRESHOLD:
            return "critical"
    return base


def collect_cves(record):
    """Pull CVE ids from a Station record.

    A CVE-typed indicator surfaces its CVE id verbatim in
    the ``value`` field.  Free-text ``notes`` /
    ``description`` / ``tags`` / ``attributes`` may also
    embed CVE ids — we extract via regex sweep.  Returns a
    deduped uppercase list.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out

    def add(cve):
        if not isinstance(cve, str):
            return
        upper = cve.strip().upper()
        if not upper or upper in seen:
            return
        if not CVE_RE.match(upper):
            return
        seen.add(upper)
        out.append(upper)

    indicator_type = extract_indicator_type(record)
    indicator_value = extract_indicator_value(record)
    if indicator_type in CVE_TYPES:
        add(indicator_value)
    # Sometimes CVE ids are surfaced even when type is generic
    if isinstance(indicator_value, str):
        for match in CVE_RE.findall(indicator_value):
            add(match)

    for tag in extract_tags(record):
        for match in CVE_RE.findall(tag):
            add(match)
    for attr in extract_attributes(record):
        for match in CVE_RE.findall(attr):
            add(match)

    notes = extract_notes(record)
    if isinstance(notes, str):
        for match in CVE_RE.findall(notes):
            add(match)
    return out


def web_link_for_indicator(host, indicator_id):
    """Build the Station web-UI permalink for an indicator.

    The Station console runs at the same host as the API
    (``api.trustar.co`` reverse-proxies the
    ``station.trustar.co`` UI on the Splunk-hosted cloud
    tenant).  The indicator-detail path is
    ``/constellation/indicator?id=<id>``.  Returns the bare
    Station root when the indicator id is unknown.
    """
    base = normalize_base_url(host)
    if not indicator_id:
        return base
    return f"{base}/constellation/indicator?id={indicator_id}"


def collect_refs(record, host=None):
    """Build the refs list for one indicator record."""
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

    if not isinstance(record, dict):
        return refs

    rid = extract_indicator_id(record)
    if rid:
        add(f"Trustar-ID: {rid}")

    itype = extract_indicator_type(record)
    if itype:
        add(f"Trustar-Type: {itype}")

    ivalue = extract_indicator_value(record)
    if ivalue:
        add(f"Trustar-Value: {ivalue}")

    label = extract_priority_label(record)
    if label:
        add(f"Trustar-Priority: {label}")

    cc = extract_correlation_count(record)
    if cc is not None:
        add(f"Trustar-Correlation: {cc}")

    for eid in extract_enclave_ids(record):
        add(f"Trustar-EnclaveID: {eid}")

    for tag in extract_tags(record):
        add(f"Trustar-Tag: {tag}")

    for attr in extract_attributes(record):
        add(f"Trustar-Attribute: {attr}")

    fs = parse_iso_datetime(record.get("firstSeen"))
    if fs is not None:
        add(f"Trustar-FirstSeen: {fs.isoformat()}")
    ls = parse_iso_datetime(record.get("lastSeen"))
    if ls is not None:
        add(f"Trustar-LastSeen: {ls.isoformat()}")

    for cve in collect_cves(record):
        add(f"Trustar-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    if rid:
        add(web_link_for_indicator(host, rid))

    return refs


def resolution_for_record(record):
    """Type-appropriate blocking / mitigation recommendation."""
    if not isinstance(record, dict):
        return (
            "Triage the indicator in the operator's SOC workflow, "
            "correlate it with EDR / SIEM telemetry, and apply "
            "perimeter / endpoint controls per the operator's "
            "incident-response runbook."
        )
    itype = extract_indicator_type(record)
    if itype in HASH_TYPES:
        return (
            "Add the file hash to the operator's EDR / AV / "
            "endpoint-prevention deny-list, hunt for prior "
            "executions in SIEM / EDR telemetry, and verify any "
            "hits against the impacted host's process / parent "
            "chain before triggering response."
        )
    if itype in IP_TYPES:
        return (
            "Block the IP on the perimeter firewall + egress "
            "proxy, add to EDR network-containment / DNS-RPZ "
            "policies, and review SIEM netflow for prior inbound "
            "/ outbound traffic against the impacted assets."
        )
    if itype in URL_TYPES:
        return (
            "Add the URL to the operator's egress proxy + "
            "endpoint web-filter deny-list, sinkhole the parent "
            "domain on corporate DNS, and review browser / "
            "proxy logs for prior fetches by impacted users."
        )
    if itype in DOMAIN_TYPES:
        return (
            "Sinkhole the domain on the corporate DNS resolver, "
            "add to perimeter + egress proxy blocklist, and "
            "review DNS / proxy logs for prior resolutions by "
            "impacted hosts."
        )
    if itype in EMAIL_TYPES:
        return (
            "Add the email address to the mail-server blocklist "
            "/ DMARC quarantine policy, search the mail-archive "
            "for prior deliveries, and review the impacted "
            "recipients' inbox-rule audit logs."
        )
    if itype in CVE_TYPES:
        return (
            "Cross-reference the CVE id against the operator's "
            "asset inventory + vulnerability scanner output, "
            "apply vendor patches per the NVD reference, and "
            "verify remediation on the affected hosts."
        )
    return (
        "Triage the indicator in the operator's SOC workflow, "
        "correlate it with EDR / SIEM telemetry, and apply "
        "perimeter / endpoint controls per the operator's "
        "incident-response runbook."
    )


def build_vulnerability(record, host=None):
    """Build a Faraday vulnerability dict for one indicator record."""
    if not isinstance(record, dict):
        return None

    rid = extract_indicator_id(record)
    itype = extract_indicator_type(record)
    ivalue = extract_indicator_value(record)
    if not rid and not ivalue:
        return None

    severity = severity_for_record(record)
    label = extract_priority_label(record)
    cc = extract_correlation_count(record)

    name_parts = ["[TruSTAR]"]
    if itype:
        name_parts.append(itype)
    if ivalue:
        name_parts.append(ivalue)
    if label:
        name_parts.append(f"({label})")
    if cc is not None and cc > 0:
        name_parts.append(f"x{cc}")
    name = " ".join(name_parts)

    desc_parts = []
    if rid:
        desc_parts.append(f"indicatorID: {rid}")
    if itype:
        desc_parts.append(f"indicatorType: {itype}")
    if ivalue:
        desc_parts.append(f"indicatorValue: {ivalue}")
    if label:
        desc_parts.append(f"priorityLevel: {label}")
    else:
        desc_parts.append("priorityLevel: NOT_FOUND")
    if cc is not None:
        desc_parts.append(f"correlationCount: {cc}")
    enclaves = extract_enclave_ids(record)
    if enclaves:
        desc_parts.append(f"enclaveIds: {', '.join(enclaves)}")
    tags = extract_tags(record)
    if tags:
        desc_parts.append(f"tags: {', '.join(tags)}")
    attrs = extract_attributes(record)
    if attrs:
        desc_parts.append(f"attributes: {'; '.join(attrs)}")
    fs = parse_iso_datetime(record.get("firstSeen"))
    if fs is not None:
        desc_parts.append(f"firstSeen: {fs.isoformat()}")
    ls = parse_iso_datetime(record.get("lastSeen"))
    if ls is not None:
        desc_parts.append(f"lastSeen: {ls.isoformat()}")
    notes = extract_notes(record)
    if notes:
        desc_parts.append(f"notes: {notes}")

    external_id = rid or (f"{itype}:{ivalue}" if itype and ivalue else ivalue or name)
    resolution = resolution_for_record(record)

    return {
        "name": str(name).strip()[:200] or "TruSTAR indicator",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record, host=host),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["trustar"],
    }


def build_host(vulns, enclave_ids, priority_floor, meta):
    """Build the single synthetic host that carries every TruSTAR vuln."""
    desc_parts = ["source=trustar"]
    if isinstance(enclave_ids, list) and enclave_ids:
        desc_parts.append(f"enclaves={len(enclave_ids)}")
    else:
        desc_parts.append("enclaves=all-readable")
    if priority_floor:
        desc_parts.append(f"priority>={priority_floor}")
    else:
        desc_parts.append("priority=any")
    if isinstance(meta, dict):
        total = meta.get("totalElements")
        if total is not None:
            desc_parts.append(f"trustar_total={total}")
        page = meta.get("pageNumber")
        if page is not None:
            desc_parts.append(f"lastPage={page}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["trustar"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_token(requests_module, host, api_key, api_secret):
    """Exchange Station API credentials for an OAuth2 Bearer token.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient Station outage doesn't crash the
    dispatcher.  Returns ``None`` on any failure.
    """
    url = build_token_url(host)
    try:
        resp = requests_module.post(
            url,
            data={"grant_type": "client_credentials"},
            headers=token_request_headers(api_key, api_secret),
            timeout=TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001
        log(f"OAuth2 token POST {url} failed: {exc}")
        return None
    if resp.status_code >= 400:
        log(f"OAuth2 token request failed ({resp.status_code}): " f"{resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log("OAuth2 token response was not JSON")
        return None
    token = extract_access_token(body)
    if not token:
        log("OAuth2 token response did not include access_token")
        return None
    return token


def fetch_url(requests_module, url, token, method="GET", body=None):
    """Fetch a single Station URL with the Bearer token.

    Supports both GET (enclaves) and POST (indicators/search)
    via the ``method`` arg.  Network / HTTP / JSON errors are
    logged but never raised upstream so a transient Station
    outage doesn't crash the dispatcher.  Returns ``None`` on
    any failure.
    """
    try:
        if method.upper() == "POST":
            resp = requests_module.post(
                url,
                json=body if body is not None else {},
                headers=request_headers(token),
                timeout=TIMEOUT,
            )
        else:
            resp = requests_module.get(
                url,
                headers=request_headers(token),
                timeout=TIMEOUT,
            )
    except Exception as exc:  # noqa: BLE001
        log(f"{method} {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"Station record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"Station request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"Station response was not JSON ({url})")
        return None


def fetch_enclaves(requests_module, host, token):
    """Pull every enclave the operator's API key has access to.

    Used as a discovery step when ``TRUSTAR_ENCLAVE_IDS`` is
    blank.  Returns ``[]`` on any failure so the caller can
    fall back to an unfiltered search (Station's documented
    behaviour when ``enclaveIds`` is omitted from the search
    body is to search every readable enclave server-side).
    """
    url = build_enclaves_url(host)
    body = fetch_url(requests_module, url, token, method="GET")
    if body is None:
        return []
    return extract_enclaves(body)


def fetch_indicators(
    requests_module,
    host,
    token,
    enclave_ids,
    priority_floor,
    page_size=DEFAULT_PAGE_SIZE,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    max_results=MAX_RESULTS,
):
    """Page through ``/api/1.3/indicators/search`` accumulating records.

    Walks ``pageNumber`` forward, accumulating records across
    pages until either the result set is exhausted
    (``hasNext`` flips to False, the server returned an empty
    page, or ``pageNumber * pageSize >= totalElements``),
    MAX_RESULTS is hit, or MAX_PAGES is hit.  Returns
    ``(records, last_meta)``.
    """
    records = []
    last_meta = {
        "pageNumber": None,
        "pageSize": None,
        "totalElements": None,
        "hasNext": None,
    }
    body_filter = build_search_body(enclave_ids, priority_floor)
    page = 0
    while page < max_pages and len(records) < max_results:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        remaining = max_results - len(records)
        page_limit = min(page_size, remaining)
        if page_limit <= 0:
            break
        url = build_search_url(host, page_number=page, page_size=page_limit)
        body = fetch_url(requests_module, url, token, method="POST", body=body_filter)
        if body is None:
            break
        meta = extract_envelope_meta(body)
        if any(meta.get(k) is not None for k in ("pageNumber", "pageSize", "totalElements", "hasNext")):
            last_meta = meta
        page_records = extract_indicators(body)
        if not page_records:
            break
        for entry in page_records:
            records.append(entry)
            if len(records) >= max_results:
                break
        # Stop conditions
        if meta.get("hasNext") is False:
            break
        total = meta.get("totalElements")
        if total is not None and len(records) >= total:
            break
        page += 1
    return records, last_meta


def main():
    started = time.time()

    raw_enclaves = env("EXECUTOR_CONFIG_TRUSTAR_ENCLAVE_IDS")
    enclave_ids = parse_enclave_ids(raw_enclaves)

    raw_priority = env("EXECUTOR_CONFIG_TRUSTAR_PRIORITY")
    priority_floor = validate_priority(raw_priority)
    if raw_priority and priority_floor is None:
        log("TRUSTAR_PRIORITY must be one of " f"{list(ALLOWED_PRIORITIES)} (aliases: critical / moderate / med)")
        sys.exit(1)

    host = env("TRUSTAR_HOST", default=DEFAULT_HOST)
    api_key = env("TRUSTAR_API_KEY", required=True)
    api_secret = env("TRUSTAR_API_SECRET", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_token(requests, host, api_key, api_secret)
    if not token:
        sys.exit(1)

    if not enclave_ids:
        # Discovery step — surface every enclave the key can
        # see so the operator sees an honest count in the host
        # description rather than a silent fallback to
        # ``all-readable``.
        discovered = fetch_enclaves(requests, host, token)
        for entry in discovered:
            eid = (entry.get("id") if isinstance(entry, dict) else None) or ""
            if isinstance(eid, str) and eid.strip():
                enclave_ids.append(eid.strip())
        # Dedupe + preserve order
        seen = set()
        deduped = []
        for eid in enclave_ids:
            key = eid.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(eid)
        enclave_ids = deduped

    records, meta = fetch_indicators(requests, host, token, enclave_ids, priority_floor)

    vulns = []
    for entry in records:
        vuln = build_vulnerability(entry, host=host)
        if vuln is not None:
            vulns.append(vuln)

    total = meta.get("totalElements") if isinstance(meta, dict) else None
    log(
        f"Processed {len(vulns)} TruSTAR indicators "
        f"(enclaves={len(enclave_ids) or 'all-readable'}, "
        f"priority={priority_floor or 'any'}, "
        f"trustar_total={total if total is not None else '?'})"
    )

    hosts_out = [build_host(vulns, enclave_ids, priority_floor, meta)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "trustar",
            "command": "trustar",
            "params": (f"enclaves={len(enclave_ids) or 'all'} " f"priority={priority_floor or 'any'}"),
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
