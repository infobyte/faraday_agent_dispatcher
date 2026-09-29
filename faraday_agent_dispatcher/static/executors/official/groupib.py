#!/usr/bin/env python
"""Group-IB Threat Intelligence importer.

Pulls compromised-credential and phishing-attack records from
the Group-IB Threat Intelligence (formerly TAP — Threat
Analytics Platform) REST API and emits Faraday bulk-create
JSON to stdout.  Group-IB is a commercial threat-intelligence
vendor that publishes per-record telemetry covering
credential leaks observed in underground markets, exposed
account dumps, brand-impersonating phishing kits, and live
phishing infrastructure tied to the operator's brand /
domain / IP space.

Endpoints used:
  GET {GROUPIB_HOST}/api/v2/compromised/account
      ?seqUpdate=N&limit=100
      -> Paginated compromised-credential inventory.  The
      canonical Group-IB envelope is
      ``{"items": [...], "count": N, "seqUpdate": N}``
      (the next ``seqUpdate`` is forwarded into the next
      request to walk forward through the feed); federated /
      mirror stacks may use bare-list / ``data`` /
      ``results`` / ``accounts`` — all are accepted.  Each
      compromised-account record carries ``id``, ``login``,
      ``password`` (or ``passwordHash``), ``service``
      (the breached service URL / brand), ``cnc`` (the C2
      domain the credential leaked through), ``client``
      (operator-side asset the credential pivots on),
      ``source`` (analyst-curated origin), ``foundTime`` /
      ``updateTime``, and an optional ``cve`` list of CVE
      ids tied to the exploited vector.

  GET {GROUPIB_HOST}/api/v2/attacks/phishing
      ?seqUpdate=N&limit=100
      -> Paginated phishing-attack inventory.  Each
      phishing record carries ``id``, ``url`` (the
      phishing URL), ``domain`` (the impersonating
      domain), ``ip`` (the hosting IP), ``targetBrand``
      (operator-side brand the kit targets), ``status``
      (``Active`` / ``Blocked`` / ``TakenDown`` /
      ``Investigation``), ``severity`` (``Low`` / ``Medium``
      / ``High`` — Group-IB's analyst label), ``kit``
      (the phishing kit family if fingerprinted),
      ``dateDetected`` / ``dateBlocked`` /
      ``dateUpdated``, and an optional ``screenshot`` URL.

Auth: Group-IB Threat Intelligence uses HTTP Basic auth —
the operator creates an API key in the Group-IB TI console
(Profile -> API -> Generate) and pastes the issued
``user`` + ``key`` values into ``GROUPIB_USER`` +
``GROUPIB_API_KEY``.  The dispatcher base64-encodes
``{USER}:{API_KEY}`` and sends the
``Authorization: Basic ...`` header on every request.

Args:
  ``GROUPIB_FEED_TYPE`` (mandatory) — one of
  ``compromised_account`` (also ``accounts`` / ``credentials``
  / ``creds`` / ``compromised``) OR ``phishing`` (also
  ``phish`` / ``attack`` / ``attacks``).  Selects which
  Group-IB feed to walk.  Operator-friendly aliases are
  normalised onto the canonical lowercase name.  Anything
  else is rejected client-side with a hard error so a typo
  doesn't silently pull the wrong feed.

  ``GROUPIB_LIMIT`` (optional, default 100, clamped
  ``[1, 500]``) — per-request page size.  Group-IB's
  documented ceiling is 500 records per page on both feeds;
  the executor pages ``seqUpdate`` forward until the result
  set is exhausted, MAX_RESULTS (5000) is hit, or MAX_PAGES
  (100) is hit.  ``<=0`` / blank / unparseable falls back to
  the default; ``> 500`` is clamped to 500.

Env vars:
  ``GROUPIB_USER`` + ``GROUPIB_API_KEY`` (both mandatory) —
  the HTTP Basic credential pair issued by Group-IB at
  API-key-creation time.  The executor exits cleanly when
  either is missing.

  ``GROUPIB_HOST`` (optional, not in the manifest's declared
  env vars) — defaults to ``https://tap.group-ib.com`` (the
  canonical Group-IB Threat Intelligence host).  Settable
  to a regional tenant URL or to a self-hosted offline
  cache.  Whitespace is trimmed and ``https://`` is added
  when the operator pasted in a bare FQDN.

Each compromised-account / phishing record becomes one
Faraday vulnerability under a single synthetic ``0.0.0.0``
host with hostname ``groupib``.  Group-IB records are
brand-keyed / credential-keyed not host-keyed — the
operator's other agents emit the host-side findings this
feed is correlated against.  The vulnerability carries
``tags: ['groupib']`` and surfaces the record id + value +
status + severity + targetBrand + source + timestamps in
both the description and the refs list so operators can
pivot from a Faraday finding back to the Group-IB record.

Severity bucketing differs by feed:
  - ``compromised_account``: defaults to ``high`` (a leaked
    credential is an actionable finding by definition); is
    bumped to ``critical`` when the leak carries a
    plaintext password (no ``passwordHash`` salt /
    wrapping) AND the credential is tied to an operator
    asset (``client`` present); is floored to ``info``
    when the record is marked ``mitigated`` / ``revoked``
    (the credential has already been rotated).  Records
    with no parseable login default to ``info``.
  - ``phishing``: maps Group-IB's published Low / Medium /
    High label onto Faraday's low / medium / high; bumps to
    ``critical`` when the record is ``Active`` AND a target
    brand is named (live, brand-impersonating phishing);
    floors to ``info`` when the status is ``Blocked`` /
    ``TakenDown`` (the threat is no longer live).  Unscored
    records default to ``info`` — we don't synthesise a
    ranking Group-IB hasn't published.

Status is always ``open`` (a Group-IB record can transition
to ``Blocked`` / ``TakenDown`` in the portal but the
underlying credential / phishing campaign lives on; Faraday
surfaces the finding as open so the operator's remediation
workflow takes over).

Resolution defaults to a feed-appropriate analyst
recommendation: compromised-account -> force-reset the
credential, audit the affected service for unauthorised
use, notify the impacted user, and rotate any reused
secrets; phishing -> submit takedown via the Group-IB
Anti-Piracy / Anti-Phishing service, block the URL on the
operator's egress proxy and endpoint web-filter, sinkhole
the impersonating domain, and notify the impacted brand
owners.
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

DEFAULT_HOST = "https://tap.group-ib.com"
COMPROMISED_ACCOUNT_PATH = "/api/v2/compromised/account"
PHISHING_PATH = "/api/v2/attacks/phishing"

DEFAULT_LIMIT = 100
MIN_LIMIT = 1
MAX_LIMIT = 500
MAX_PAGES = 100
MAX_RESULTS = 5000
INTER_REQUEST_SLEEP = 0.4

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

ALLOWED_FEED_TYPES = ("compromised_account", "phishing")

FEED_TYPE_ALIASES = {
    "compromised_account": "compromised_account",
    "compromisedaccount": "compromised_account",
    "compromised-account": "compromised_account",
    "compromised": "compromised_account",
    "account": "compromised_account",
    "accounts": "compromised_account",
    "credential": "compromised_account",
    "credentials": "compromised_account",
    "creds": "compromised_account",
    "phishing": "phishing",
    "phish": "phishing",
    "phishing_attack": "phishing",
    "phishing-attack": "phishing",
    "attack": "phishing",
    "attacks": "phishing",
}

GROUPIB_SEVERITY_LABELS = ("Low", "Medium", "High")
SEVERITY_ALIASES = {
    "low": "Low",
    "medium": "Medium",
    "moderate": "Medium",
    "med": "Medium",
    "high": "High",
    "critical": "High",
}

SEVERITY_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
}

# Phishing terminal states — records in these statuses are
# floored to ``info`` (the threat has already been neutralised
# upstream — usually by Group-IB's own Anti-Phishing /
# Anti-Piracy team).
PHISHING_CLOSED_STATUSES = {"blocked", "takendown", "taken_down", "taken-down", "removed", "dead", "down"}

# Compromised-account terminal states — credentials in these
# states have already been rotated by the operator.
ACCOUNT_CLOSED_STATUSES = {"mitigated", "revoked", "rotated", "resolved", "closed", "fixed"}


def log(msg):
    print(
        f"{datetime.utcnow()} - GroupIB: {msg}",
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
    """Trim trailing slash + tolerate operator typos on GROUPIB_HOST.

    Defaults to ``https://tap.group-ib.com`` (the canonical
    Group-IB Threat Intelligence host) when the env override
    is missing / blank.  Whitespace is trimmed and
    ``https://`` is added automatically when the operator
    pasted in a bare FQDN.
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


def validate_feed_type(value):
    """Coerce GROUPIB_FEED_TYPE into a canonical feed name.

    Returns ``compromised_account`` / ``phishing`` (the
    canonical lowercase names) or ``None`` for missing /
    blank / unknown inputs so the caller can hard-fail with a
    helpful error rather than picking a feed silently.
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    alias = FEED_TYPE_ALIASES.get(text.lower())
    if alias is not None:
        return alias
    if text.lower() in ALLOWED_FEED_TYPES:
        return text.lower()
    return None


def validate_limit(value):
    """Coerce GROUPIB_LIMIT into an int clamped to [MIN_LIMIT, MAX_LIMIT].

    None / blank / bool / unparseable falls back to
    DEFAULT_LIMIT (100).  Values below MIN_LIMIT (1) are
    floored to MIN_LIMIT; values above MAX_LIMIT (500) are
    capped at MAX_LIMIT (Group-IB's documented per-page
    ceiling on both feeds).
    """
    if value is None or value == "":
        return DEFAULT_LIMIT
    if isinstance(value, bool):
        log(f"GROUPIB_LIMIT {value!r} is a bool, not an int; " f"using default ({DEFAULT_LIMIT})")
        return DEFAULT_LIMIT
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"GROUPIB_LIMIT {value!r} is not an int; " f"using default ({DEFAULT_LIMIT})")
        return DEFAULT_LIMIT
    if n < MIN_LIMIT:
        return MIN_LIMIT
    if n > MAX_LIMIT:
        return MAX_LIMIT
    return n


def feed_path(feed_type):
    """Return the API path for a canonical feed name."""
    if feed_type == "compromised_account":
        return COMPROMISED_ACCOUNT_PATH
    if feed_type == "phishing":
        return PHISHING_PATH
    return ""


def build_feed_url(host, feed_type, seq_update=0, limit=DEFAULT_LIMIT):
    """Build the Group-IB feed URL for one page."""
    base = normalize_base_url(host)
    path = feed_path(feed_type)
    if not path:
        return ""
    try:
        seq = int(seq_update)
    except (TypeError, ValueError):
        seq = 0
    try:
        lim = int(limit)
    except (TypeError, ValueError):
        lim = DEFAULT_LIMIT
    params = [("seqUpdate", seq), ("limit", lim)]
    return f"{base}{path}?{urlencode(params)}"


def basic_auth_header(user, api_key):
    """Build the HTTP Basic auth header value for Group-IB.

    Group-IB base64-encodes ``user:api_key`` and sends it as
    ``Authorization: Basic ...``.  Missing / non-string
    inputs are coerced to empty strings so the signing call
    never raises locally — the server can still reject the
    bad credentials with a useful 401.
    """
    u = str(user or "").strip()
    k = str(api_key or "").strip()
    raw = f"{u}:{k}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return f"Basic {encoded}"


def request_headers(user, api_key):
    """Build the request-header dict for a single Group-IB GET.

    ``Accept: application/json`` is always sent;
    ``Authorization: Basic ...`` is included with the
    operator-supplied credentials.
    """
    return {
        "Accept": "application/json",
        "Authorization": basic_auth_header(user, api_key),
    }


def parse_iso_datetime(value):
    """Parse an ISO-8601 timestamp into a UTC datetime.

    Group-IB emits ``foundTime`` / ``updateTime`` /
    ``dateDetected`` / ``dateUpdated`` as
    ``YYYY-MM-DDTHH:MM:SSZ`` (or with a numeric offset on
    some regional mirrors).  Returns ``None`` for missing /
    malformed inputs.
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


def extract_items(body):
    """Pull the records list from a Group-IB feed envelope.

    Canonical envelope is ``{"items": [...], "count": N,
    "seqUpdate": N}``.  Federated / mirror stacks may use
    bare-list / ``data`` / ``results`` / ``accounts`` /
    ``attacks`` / ``records`` — all are accepted so the
    caller doesn't care about envelope drift.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("items", "data", "results", "accounts", "attacks", "records", "list"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_envelope_meta(body):
    """Pull pagination + count metadata from a Group-IB envelope.

    Returns ``{"count": int|None, "seqUpdate": int|None}``
    with missing fields left as ``None``.  Used both to walk
    pagination forward (the ``seqUpdate`` cursor) and to
    surface a catalog-version-style breadcrumb on the
    synthetic host so operators can pivot from a Faraday
    finding back to the response that produced it.
    """
    out = {"count": None, "seqUpdate": None}
    if not isinstance(body, dict):
        return out
    for key in ("count", "seqUpdate"):
        v = body.get(key)
        if v is None or isinstance(v, bool):
            continue
        try:
            out[key] = int(v)
        except (TypeError, ValueError):
            continue
    return out


def extract_record_id(record):
    """Pull the canonical Group-IB record id (``id``)."""
    if not isinstance(record, dict):
        return ""
    for key in ("id", "_id", "recordId"):
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


def extract_login(record):
    """Pull the leaked login / email for a compromised-account record."""
    if not isinstance(record, dict):
        return ""
    for key in ("login", "email", "username", "user"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_service(record):
    """Pull the breached service / brand for a compromised-account record."""
    if not isinstance(record, dict):
        return ""
    for key in ("service", "site", "domain", "url"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_password_info(record):
    """Pull the (presence-of-)plaintext-password flag for a credential record.

    Group-IB surfaces the leaked password verbatim in
    ``password`` when it was sourced in plaintext, and as a
    hash digest in ``passwordHash`` when it was sourced
    pre-hashed.  We return ``("plaintext" | "hash" | "")``
    so the caller can bucket severity without exposing the
    raw credential value in Faraday's UI.
    """
    if not isinstance(record, dict):
        return ""
    pwd = record.get("password")
    if isinstance(pwd, str) and pwd.strip():
        return "plaintext"
    pwd_hash = record.get("passwordHash")
    if isinstance(pwd_hash, str) and pwd_hash.strip():
        return "hash"
    return ""


def extract_account_status(record):
    """Pull the operator-side status for a compromised-account record."""
    if not isinstance(record, dict):
        return ""
    for key in ("status", "state", "mitigationStatus"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_client(record):
    """Pull the operator-side ``client`` asset the credential pivots on."""
    if not isinstance(record, dict):
        return ""
    v = record.get("client")
    if isinstance(v, str) and v.strip():
        return v.strip()
    if isinstance(v, dict):
        for key in ("name", "id", "title"):
            inner = v.get(key)
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
    return ""


def extract_phishing_url(record):
    """Pull the phishing URL for a phishing record."""
    if not isinstance(record, dict):
        return ""
    for key in ("url", "phishingUrl", "phishing_url"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_phishing_domain(record):
    """Pull the impersonating domain for a phishing record."""
    if not isinstance(record, dict):
        return ""
    for key in ("domain", "phishingDomain", "host"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_phishing_ip(record):
    """Pull the hosting IP for a phishing record."""
    if not isinstance(record, dict):
        return ""
    for key in ("ip", "ipAddress", "ip_address"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_target_brand(record):
    """Pull the target brand for a phishing record."""
    if not isinstance(record, dict):
        return ""
    for key in ("targetBrand", "brand", "targetCompany"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_phishing_status(record):
    """Pull the phishing-record status (Active / Blocked / ...)."""
    if not isinstance(record, dict):
        return ""
    v = record.get("status")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ""


def extract_severity_label(record):
    """Pull the canonical Group-IB severity label (or '').

    Tolerates case + whitespace + aliasing onto the
    title-cased label.  Returns ``''`` (not ``None``) for
    missing / unknown inputs so the caller can treat
    unscored records as ``info`` uniformly.
    """
    if not isinstance(record, dict):
        return ""
    v = record.get("severity")
    if v is None or isinstance(v, bool):
        return ""
    text = str(v).strip()
    if not text:
        return ""
    alias = SEVERITY_ALIASES.get(text.lower())
    if alias is not None:
        return alias
    if text in GROUPIB_SEVERITY_LABELS:
        return text
    return ""


def extract_source(record):
    """Pull the analyst-curated origin / source for a record."""
    if not isinstance(record, dict):
        return ""
    for key in ("source", "origin", "sourceName"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_kit(record):
    """Pull the fingerprinted phishing-kit family for a phishing record."""
    if not isinstance(record, dict):
        return ""
    v = record.get("kit")
    if isinstance(v, str) and v.strip():
        return v.strip()
    if isinstance(v, dict):
        for key in ("name", "family"):
            inner = v.get(key)
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
    return ""


def is_phishing_closed(record):
    """Return True when the phishing record is in a terminal closed state."""
    status = extract_phishing_status(record)
    if not status:
        return False
    return status.strip().lower().replace(" ", "") in PHISHING_CLOSED_STATUSES


def is_account_closed(record):
    """Return True when the credential record is in a terminal closed state."""
    status = extract_account_status(record)
    if not status:
        return False
    return status.strip().lower() in ACCOUNT_CLOSED_STATUSES


def severity_for_account(record):
    """Final Faraday severity for a compromised-account record.

    Defaults to ``high`` (a leaked credential is actionable
    by definition); bumps to ``critical`` when the password
    is plaintext AND the credential is tied to an operator
    asset (``client`` present); floors to ``info`` when the
    record is mitigated / revoked / rotated.  Records with no
    parseable login default to ``info``.
    """
    if not isinstance(record, dict):
        return "info"
    if is_account_closed(record):
        return "info"
    login = extract_login(record)
    if not login:
        return "info"
    if extract_password_info(record) == "plaintext" and extract_client(record):
        return "critical"
    return "high"


def severity_for_phishing(record):
    """Final Faraday severity for a phishing record.

    Maps the published Low / Medium / High label onto
    Faraday's low / medium / high; bumps to ``critical``
    when the record is ``Active`` AND a target brand is
    named (live, brand-impersonating phishing); floors to
    ``info`` when the status is ``Blocked`` / ``TakenDown``.
    Records with no parseable severity default to ``info``.
    """
    if not isinstance(record, dict):
        return "info"
    if is_phishing_closed(record):
        return "info"
    label = extract_severity_label(record)
    status = extract_phishing_status(record).lower()
    base = SEVERITY_MAP.get(label, "info")
    if status == "active" and extract_target_brand(record):
        return "critical"
    return base


def collect_cves(record):
    """Pull CVE ids from a Group-IB record.

    Compromised-account records carry an optional structured
    ``cve`` list (each entry is either a bare CVE id string
    or a dict with a ``cveId`` key); phishing records do not
    carry structured CVEs but analysts sometimes surface
    them in the free-text ``description`` / ``kit`` /
    ``targetBrand`` fields.  Returns a deduped uppercase
    list.
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

    structured = record.get("cve")
    if isinstance(structured, str):
        add(structured)
    elif isinstance(structured, list):
        for entry in structured:
            if isinstance(entry, str):
                add(entry)
            elif isinstance(entry, dict):
                add(str(entry.get("cveId") or entry.get("id") or ""))

    def harvest(text):
        if not isinstance(text, str):
            return
        for match in CVE_RE.findall(text):
            add(match)

    for key in ("description", "kit", "targetBrand", "service", "source"):
        harvest(record.get(key) if isinstance(record.get(key), str) else "")
    return out


def web_link_for_record(host, feed_type, record_id):
    """Build the Group-IB web-UI permalink for a record.

    The Group-IB Threat Intelligence portal lives at the
    same host as the API (the UI is reverse-proxied through
    the API host on the standard cloud tenant).  Returns the
    feed-list permalink when the record id is unknown so
    operators always get a clickable pivot.
    """
    base = normalize_base_url(host)
    if feed_type == "compromised_account":
        return (
            f"{base}/profile/compromised/account/{record_id}" if record_id else f"{base}/profile/compromised/account"
        )
    if feed_type == "phishing":
        return f"{base}/profile/attacks/phishing/{record_id}" if record_id else f"{base}/profile/attacks/phishing"
    return base


def collect_account_refs(record, host=None):
    """Build the refs list for one compromised-account record."""
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

    rid = extract_record_id(record)
    if rid:
        add(f"Groupib-ID: {rid}")

    login = extract_login(record)
    if login:
        add(f"Groupib-Login: {login}")
    service = extract_service(record)
    if service:
        add(f"Groupib-Service: {service}")
    pwd_info = extract_password_info(record)
    if pwd_info:
        add(f"Groupib-PasswordType: {pwd_info}")
    client = extract_client(record)
    if client:
        add(f"Groupib-Client: {client}")
    source = extract_source(record)
    if source:
        add(f"Groupib-Source: {source}")
    status = extract_account_status(record)
    if status:
        add(f"Groupib-Status: {status}")

    cnc = record.get("cnc")
    if isinstance(cnc, str) and cnc.strip():
        add(f"Groupib-CnC: {cnc.strip()}")

    for cve in collect_cves(record):
        add(f"Groupib-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    for key, label in (
        ("foundTime", "FoundTime"),
        ("updateTime", "UpdateTime"),
        ("leakDate", "LeakDate"),
    ):
        dt = parse_iso_datetime(record.get(key))
        if dt is not None:
            add(f"Groupib-{label}: {dt.isoformat()}")

    if rid:
        add(web_link_for_record(host, "compromised_account", rid))

    return refs


def collect_phishing_refs(record, host=None):
    """Build the refs list for one phishing record."""
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

    rid = extract_record_id(record)
    if rid:
        add(f"Groupib-ID: {rid}")

    url = extract_phishing_url(record)
    if url:
        add(f"Groupib-Url: {url}")
        add(url)
    domain = extract_phishing_domain(record)
    if domain:
        add(f"Groupib-Domain: {domain}")
    ip = extract_phishing_ip(record)
    if ip:
        add(f"Groupib-IP: {ip}")
    brand = extract_target_brand(record)
    if brand:
        add(f"Groupib-TargetBrand: {brand}")
    status = extract_phishing_status(record)
    if status:
        add(f"Groupib-Status: {status}")
    sev_label = extract_severity_label(record)
    if sev_label:
        add(f"Groupib-Severity: {sev_label}")
    kit = extract_kit(record)
    if kit:
        add(f"Groupib-Kit: {kit}")

    screenshot = record.get("screenshot")
    if isinstance(screenshot, str) and screenshot.strip():
        add(f"Groupib-Screenshot: {screenshot.strip()}")
        add(screenshot.strip())

    for cve in collect_cves(record):
        add(f"Groupib-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    for key, label in (
        ("dateDetected", "Detected"),
        ("dateBlocked", "Blocked"),
        ("dateUpdated", "Updated"),
    ):
        dt = parse_iso_datetime(record.get(key))
        if dt is not None:
            add(f"Groupib-{label}: {dt.isoformat()}")

    if rid:
        add(web_link_for_record(host, "phishing", rid))

    return refs


def resolution_for_account(record):
    """Type-appropriate analyst recommendation for a compromised-account."""
    if not isinstance(record, dict) or is_account_closed(record):
        return (
            "Group-IB has already mitigated this credential leak; "
            "verify the affected account rotation has propagated "
            "and audit the service's auth logs for any "
            "pre-rotation abuse."
        )
    return (
        "Force-reset the leaked credential in the affected "
        "service, audit the service's auth logs for any "
        "unauthorised access since the leak date, notify the "
        "impacted user, and rotate any reused secrets (SSO "
        "tokens, API keys, OAuth refresh tokens)."
    )


def resolution_for_phishing(record):
    """Type-appropriate analyst recommendation for a phishing record."""
    if not isinstance(record, dict) or is_phishing_closed(record):
        return (
            "Group-IB / the registrar has already taken this "
            "phishing infrastructure down; verify the URL no "
            "longer resolves and add the domain to the "
            "operator's permanent blocklist."
        )
    return (
        "Submit takedown via the Group-IB Anti-Phishing service, "
        "block the phishing URL on the operator's egress proxy "
        "and endpoint web-filter, sinkhole the impersonating "
        "domain on the corporate DNS resolver, and notify the "
        "impacted brand owners + customer-support team to "
        "expect a wave of user reports."
    )


def build_account_vulnerability(record, host=None):
    """Build a Faraday vulnerability dict for one compromised-account record."""
    if not isinstance(record, dict):
        return None

    rid = extract_record_id(record)
    login = extract_login(record)
    service = extract_service(record)
    if not login and not service and not rid:
        return None

    severity = severity_for_account(record)
    pwd_info = extract_password_info(record)
    client = extract_client(record)
    status = extract_account_status(record)
    source = extract_source(record)

    name_parts = ["[GroupIB][Credential]"]
    if login:
        name_parts.append(login)
    if service:
        name_parts.append(f"@ {service}")
    if pwd_info:
        name_parts.append(f"({pwd_info})")
    name = " ".join(name_parts)

    desc_parts = []
    if rid:
        desc_parts.append(f"recordID: {rid}")
    if login:
        desc_parts.append(f"login: {login}")
    if service:
        desc_parts.append(f"service: {service}")
    if pwd_info:
        desc_parts.append(f"passwordType: {pwd_info}")
    if client:
        desc_parts.append(f"client: {client}")
    if source:
        desc_parts.append(f"source: {source}")
    if status:
        desc_parts.append(f"status: {status}")
    cnc = record.get("cnc")
    if isinstance(cnc, str) and cnc.strip():
        desc_parts.append(f"cnc: {cnc.strip()}")
    ft = parse_iso_datetime(record.get("foundTime"))
    if ft is not None:
        desc_parts.append(f"foundTime: {ft.isoformat()}")
    ut = parse_iso_datetime(record.get("updateTime"))
    if ut is not None:
        desc_parts.append(f"updateTime: {ut.isoformat()}")

    external_id = rid or (login + "@" + service if login and service else login or service or name)
    resolution = resolution_for_account(record)

    return {
        "name": str(name).strip()[:200] or "Group-IB compromised account",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_account_refs(record, host=host),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["groupib"],
    }


def build_phishing_vulnerability(record, host=None):
    """Build a Faraday vulnerability dict for one phishing record."""
    if not isinstance(record, dict):
        return None

    rid = extract_record_id(record)
    url = extract_phishing_url(record)
    domain = extract_phishing_domain(record)
    brand = extract_target_brand(record)
    if not rid and not url and not domain:
        return None

    severity = severity_for_phishing(record)
    status = extract_phishing_status(record)
    sev_label = extract_severity_label(record)
    kit = extract_kit(record)
    ip = extract_phishing_ip(record)

    name_parts = ["[GroupIB][Phishing]"]
    if brand:
        name_parts.append(brand)
    if url:
        name_parts.append(url)
    elif domain:
        name_parts.append(domain)
    if sev_label:
        name_parts.append(f"({sev_label})")
    name = " ".join(name_parts)

    desc_parts = []
    if rid:
        desc_parts.append(f"recordID: {rid}")
    if url:
        desc_parts.append(f"url: {url}")
    if domain:
        desc_parts.append(f"domain: {domain}")
    if ip:
        desc_parts.append(f"ip: {ip}")
    if brand:
        desc_parts.append(f"targetBrand: {brand}")
    if sev_label:
        desc_parts.append(f"severity: {sev_label}")
    if status:
        desc_parts.append(f"status: {status}")
    if kit:
        desc_parts.append(f"kit: {kit}")
    dd = parse_iso_datetime(record.get("dateDetected"))
    if dd is not None:
        desc_parts.append(f"dateDetected: {dd.isoformat()}")
    db = parse_iso_datetime(record.get("dateBlocked"))
    if db is not None:
        desc_parts.append(f"dateBlocked: {db.isoformat()}")
    du = parse_iso_datetime(record.get("dateUpdated"))
    if du is not None:
        desc_parts.append(f"dateUpdated: {du.isoformat()}")

    external_id = rid or url or domain or name
    resolution = resolution_for_phishing(record)

    return {
        "name": str(name).strip()[:200] or "Group-IB phishing record",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_phishing_refs(record, host=host),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["groupib"],
    }


def build_host(vulns, feed_type, limit, meta):
    """Build the single synthetic host that carries every Group-IB vuln."""
    desc_parts = ["source=groupib", f"feed={feed_type or '?'}"]
    try:
        desc_parts.append(f"limit={int(limit)}")
    except (TypeError, ValueError):
        desc_parts.append("limit=?")
    if isinstance(meta, dict):
        count = meta.get("count")
        if count is not None:
            desc_parts.append(f"groupib_total={count}")
        seq = meta.get("seqUpdate")
        if seq is not None:
            desc_parts.append(f"seqUpdate={seq}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["groupib"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url, user, api_key):
    """GET a single Group-IB URL with HTTP Basic auth.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient Group-IB outage doesn't crash
    the dispatcher.  Returns ``None`` on any failure.
    """
    try:
        resp = requests_module.get(
            url,
            timeout=TIMEOUT,
            headers=request_headers(user, api_key),
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"Group-IB record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"Group-IB request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"Group-IB response was not JSON ({url})")
        return None


def fetch_feed(
    requests_module,
    host,
    user,
    api_key,
    feed_type,
    limit,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    max_results=MAX_RESULTS,
):
    """Page through a Group-IB feed via the ``seqUpdate`` cursor.

    Walks ``seqUpdate`` forward, accumulating records across
    pages until either the result set is exhausted (the
    server returned an empty page or did not advance the
    ``seqUpdate`` cursor), MAX_RESULTS is hit, or MAX_PAGES
    is hit.  Returns ``(records, last_meta)``.
    """
    records = []
    last_meta = {"count": None, "seqUpdate": None}
    seq_update = 0
    page = 0
    seen_seq = set()
    while page < max_pages and len(records) < max_results:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        remaining = max_results - len(records)
        page_limit = min(limit, remaining)
        if page_limit <= 0:
            break
        url = build_feed_url(host, feed_type, seq_update=seq_update, limit=page_limit)
        if not url:
            break
        body = fetch_url(requests_module, url, user, api_key)
        if body is None:
            break
        meta = extract_envelope_meta(body)
        if meta.get("count") is not None or meta.get("seqUpdate") is not None:
            last_meta = meta
        page_records = extract_items(body)
        if not page_records:
            break
        for entry in page_records:
            records.append(entry)
            if len(records) >= max_results:
                break
        next_seq = meta.get("seqUpdate")
        if next_seq is None or next_seq == seq_update or next_seq in seen_seq:
            # Server failed to advance the cursor — break to
            # avoid an infinite loop on a malformed mirror.
            break
        seen_seq.add(seq_update)
        seq_update = next_seq
        page += 1
    return records, last_meta


def main():
    started = time.time()

    feed_type = validate_feed_type(env("EXECUTOR_CONFIG_GROUPIB_FEED_TYPE", required=True))
    if feed_type is None:
        log(
            "GROUPIB_FEED_TYPE must be one of "
            f"{list(ALLOWED_FEED_TYPES)} (aliases: accounts / credentials "
            "/ creds / phish / attack)"
        )
        sys.exit(1)
    limit = validate_limit(env("EXECUTOR_CONFIG_GROUPIB_LIMIT"))
    host = env("GROUPIB_HOST", default=DEFAULT_HOST)
    user = env("GROUPIB_USER", required=True)
    api_key = env("GROUPIB_API_KEY", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    records, meta = fetch_feed(requests, host, user, api_key, feed_type, limit)

    vulns = []
    if feed_type == "compromised_account":
        builder = build_account_vulnerability
    else:
        builder = build_phishing_vulnerability
    for entry in records:
        vuln = builder(entry, host=host)
        if vuln is not None:
            vulns.append(vuln)

    total = meta.get("count") if isinstance(meta, dict) else None
    log(
        f"Processed {len(vulns)} Group-IB records "
        f"(feed={feed_type}, limit={limit}, "
        f"groupib_total={total if total is not None else '?'})"
    )

    hosts_out = [build_host(vulns, feed_type, limit, meta)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "groupib",
            "command": "groupib",
            "params": f"feed={feed_type} limit={limit}",
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
