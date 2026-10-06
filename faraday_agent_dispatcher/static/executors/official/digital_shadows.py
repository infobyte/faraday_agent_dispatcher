#!/usr/bin/env python
"""Digital Shadows / Reliaquest SearchLight importer.

Pulls incident + intel-incident records from the
Digital Shadows / Reliaquest SearchLight REST API and
emits Faraday bulk-create JSON to stdout.  Digital
Shadows (acquired by Reliaquest and now also marketed
as the Reliaquest GreyMatter Digital Risk Protection
service) is a commercial external digital-risk-
protection platform — analysts curate incidents around
an operator's named brand / domain / email / executive
footprint and publish intel incidents tied to wider
threat-actor campaigns the platform tracks.

Endpoints used:
  POST {DS_HOST}/incidents/find
      -> Paginated tenant-side incident inventory.  The
      canonical response envelope is the SearchLight
      v1 shape ``{"content": [...], "total": N,
      "offset": 0, "limit": M}``; some federated /
      regional mirrors collapse this into a bare list
      or ``{"data": [...]}`` / ``{"results": [...]}``
      / ``{"items": [...]}`` / ``{"incidents":
      [...]}`` — all of which are tolerated.  Each
      incident record carries ``id``, ``title``,
      ``severity`` (None / Very-Low / Low / Medium /
      High / Very-High), ``type`` (Data Loss
      Detection / Brand Protection / VIP / Cyber
      Threat / Infrastructure / Phishing / etc.),
      ``raised`` / ``modified`` / ``occurred`` /
      ``published`` ISO timestamps, ``status`` (open /
      closed / read / unread / resolved), ``summary``
      / ``description`` (analyst free-text),
      ``mitigation`` (operator-actionable
      remediation), ``entities`` (operator-side
      assets / domains / IPs / email addresses the
      incident is correlated against), ``cve`` (an
      optional structured CVE id list — many incidents
      surface CVEs only in the summary text), and
      ``portal_url`` / ``link`` (the SearchLight
      portal permalink).

  POST {DS_HOST}/intel-incidents/find
      -> Paginated analyst-published intel incidents
      tied to wider threat-actor campaigns.  Same
      envelope as ``/incidents/find``.  Intel
      incidents carry the additional ``actors`` (named
      threat-actor / APT group list), ``threat_level``
      (None / Very-Low / Low / Medium / High / Very-
      High), ``tags`` (campaign + TTP tags), and
      ``references`` (analyst-curated URLs) fields on
      top of the incident-shape fields.

Auth: Digital Shadows / Reliaquest SearchLight uses an
HMAC-SHA256 signing scheme.  The operator creates an
API key + secret pair in the SearchLight portal
(Settings -> API -> Generate Key) and pastes the
returned values into ``DS_KEY`` + ``DS_SECRET``.  For
each request the dispatcher computes
``string_to_sign = "{epoch_ms}{HTTP_VERB}{path}{body}"``
(epoch milliseconds + HTTP verb + URL path + JSON body
or empty string), HMAC-SHA256 signs that with the
operator's secret, base64-encodes the signature, and
sends:

  Authorization: hmac {DS_KEY}:{signature}
  searchlight-timestamp: {epoch_ms}

on every request.  The portal also accepts the legacy
``X-DS-Timestamp`` / ``X-DS-Signature`` header pair
which we also emit for compatibility with older
on-prem SearchLight installs.

Args:
  ``DS_MIN_SEVERITY`` (optional) — minimum analyst
  severity to fetch (``Very-Low`` / ``Low`` /
  ``Medium`` / ``High`` / ``Very-High``).  When
  supplied, every severity at-or-above the floor is
  forwarded in the request body as the canonical
  SearchLight ``filter.severity`` list so the API
  itself does the server-side narrowing — e.g.
  ``DS_MIN_SEVERITY=Medium`` sends ``severity:
  ["Medium", "High", "Very-High"]``.  Blank /
  missing / unparseable input keeps every incident
  (the typical operational mode).  Operator-friendly
  aliases (``critical`` / ``crit`` -> ``Very-High``;
  ``high`` / ``elevated`` -> ``High``; ``moderate`` /
  ``med`` -> ``Medium``; ``vlow`` / ``very_low`` ->
  ``Very-Low``) are normalised onto the canonical
  title-cased SearchLight severity vocabulary.

  ``DS_LIMIT`` (optional, default 100, ceiling 500) —
  maximum number of incidents to pull in a single
  page.  Forwarded into the request body as ``limit:
  <int>``.  Pagination walks ``offset`` / ``limit``
  until either the result set is exhausted,
  ``MAX_RESULTS`` (5000) is reached, or ``MAX_PAGES``
  (100) is hit.  Operator can request both incident
  and intel-incident inventories — the executor walks
  ``/incidents/find`` first then ``/intel-incidents
  /find`` and unions the two record sets.  Values
  below 1 / above the documented 500 ceiling are
  clamped.

Env vars:
  ``DS_HOST`` (mandatory) — the SearchLight REST host
  (e.g.  ``https://api.searchlight.app``).  The
  executor exits cleanly when this is missing.  We
  require ``DS_HOST`` (rather than defaulting) because
  the SearchLight product has multiple regional
  tenants (api.searchlight.app, api.eu.searchlight.app,
  on-prem mirrors) and silently defaulting to one
  would mask a tenant-mismatch from the operator.

  ``DS_KEY`` + ``DS_SECRET`` (both mandatory) — the
  HMAC credential pair issued by SearchLight at API-
  user-creation time.  ``DS_KEY`` is the public
  identifier appended to the ``Authorization`` header;
  ``DS_SECRET`` is the HMAC-SHA256 signing secret and
  never leaves the dispatcher's process memory.  The
  executor exits cleanly when either is missing.

Each incident / intel-incident becomes one Faraday
vulnerability under a single synthetic ``0.0.0.0``
host with hostname ``digital-shadows``.  SearchLight
records are brand-keyed / actor-keyed not host-keyed —
the operator's other agents emit the host-side
findings this feed is correlated against.  The
vulnerability carries ``tags: ['digital-shadows']``
and surfaces the title + type + severity + status +
mitigation + entities + actors (intel mode) + tags
(intel mode) + portal link in both the description
and the refs list so operators can pivot from a
Faraday finding back to the SearchLight portal.

Severity bucketing — SearchLight publishes its own
explicit Very-Low / Low / Medium / High / Very-High
ladder (no proprietary numeric score for the typical
incident) so we map directly:
  - ``Very-High`` -> critical
  - ``High``      -> high
  - ``Medium``    -> medium
  - ``Low``       -> low
  - ``Very-Low``  -> info
Closed / resolved incidents (status ``Closed`` /
``Resolved``) are floored to ``info`` regardless of
severity — SearchLight operators only close incidents
after analyst confirmation.  Records with no
parseable severity default to ``info`` — we don't
synthesise a ranking SearchLight hasn't published.

Status is always ``open`` (a SearchLight incident can
be closed in the SearchLight portal but the
underlying external risk lives on; Faraday surfaces
the finding as open so the operator's remediation
workflow takes over).

Resolution defaults to the SearchLight analyst-
authored ``mitigation`` text when present, falling
back to a type-appropriate generic recommendation:
Phishing -> Takedown via the SearchLight Takedown
service; Data Loss Detection -> credential reset +
forensics; Brand Protection -> trademark counsel +
domain-registrar takedown; Cyber Threat -> perimeter
+ EDR blocklist; VIP -> notify the affected executive
+ expand monitoring; Infrastructure -> rotate exposed
secrets / keys.
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
from urllib.parse import urlsplit

TIMEOUT = 60

INCIDENTS_PATH = "/incidents/find"
INTEL_INCIDENTS_PATH = "/intel-incidents/find"

DEFAULT_LIMIT = 100
MAX_LIMIT = 500
MIN_LIMIT = 1
MAX_PAGES = 100
MAX_RESULTS = 5000
INTER_REQUEST_SLEEP = 0.5

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

ALLOWED_SEVERITIES = ("Very-Low", "Low", "Medium", "High", "Very-High")
SEVERITY_ALIASES = {
    "very-low": "Very-Low",
    "very_low": "Very-Low",
    "verylow": "Very-Low",
    "vlow": "Very-Low",
    "low": "Low",
    "medium": "Medium",
    "moderate": "Medium",
    "med": "Medium",
    "high": "High",
    "elevated": "High",
    "very-high": "Very-High",
    "very_high": "Very-High",
    "veryhigh": "Very-High",
    "vhigh": "Very-High",
    "critical": "Very-High",
    "crit": "Very-High",
}

SEVERITY_MAP = {
    "Very-High": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Very-Low": "info",
}

SEVERITY_ORDER = {"Very-Low": 1, "Low": 2, "Medium": 3, "High": 4, "Very-High": 5}

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")

CLOSED_STATUSES = {"closed", "resolved", "dismissed", "rejected"}


def log(msg):
    print(
        f"{datetime.utcnow()} - DigitalShadows: {msg}",
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
    """Trim trailing slash + tolerate operator typos on DS_HOST.

    Unlike most sibling executors there is NO default
    here: SearchLight runs in multiple regions
    (api.searchlight.app / api.eu.searchlight.app) and
    silently defaulting to one would mask a tenant-
    mismatch.  Returns ``''`` (empty string, not None)
    when the input is unusable so the caller can hard-
    fail with a useful error.  ``https://`` is added
    automatically when the operator pasted in a bare
    FQDN.
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
    """Coerce DS_MIN_SEVERITY into a SearchLight severity label.

    Returns one of ``Very-Low`` / ``Low`` / ``Medium`` /
    ``High`` / ``Very-High`` (the canonical SearchLight
    title-cased labels) or ``None`` for missing / blank
    / unknown inputs (no filter — every incident
    returned by SearchLight passes through).
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    alias = SEVERITY_ALIASES.get(text.lower())
    if alias is not None:
        return alias
    if text in ALLOWED_SEVERITIES:
        return text
    log(f"DS_MIN_SEVERITY {value!r} is not a known severity; ignoring (no filter)")
    return None


def severities_at_or_above(min_severity):
    """Return the list of SearchLight severities >= ``min_severity``.

    SearchLight's filter body accepts a ``severity``
    list (multiple values per request); we surface
    that as a Python list so a ``min_severity=Medium``
    request body carries ``severity: ["Medium",
    "High", "Very-High"]``.  Returns an empty list
    when ``min_severity`` is ``None`` (no filter
    applied) so the caller emits no ``severity`` key
    at all in the body.
    """
    if min_severity is None:
        return []
    floor = SEVERITY_ORDER.get(min_severity)
    if floor is None:
        return []
    return [s for s in ALLOWED_SEVERITIES if SEVERITY_ORDER[s] >= floor]


def validate_limit(value):
    """Coerce DS_LIMIT into a clamped integer in ``[MIN_LIMIT, MAX_LIMIT]``.

    Defaults to ``DEFAULT_LIMIT`` (100) when missing /
    blank / unparseable.  Values < ``MIN_LIMIT`` (1)
    are floored to 1; values > ``MAX_LIMIT`` (500) are
    capped at the SearchLight documented page-size
    ceiling.  Booleans are rejected (Python booleans
    are ints but coercing ``True`` -> 1 silently masks
    a manifest mis-binding).
    """
    if value is None or isinstance(value, bool):
        return DEFAULT_LIMIT
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return DEFAULT_LIMIT
        try:
            n = int(text)
        except ValueError:
            try:
                n = int(float(text))
            except ValueError:
                return DEFAULT_LIMIT
    else:
        try:
            n = int(value)
        except (TypeError, ValueError):
            return DEFAULT_LIMIT
    if n < MIN_LIMIT:
        return MIN_LIMIT
    if n > MAX_LIMIT:
        return MAX_LIMIT
    return n


def build_filter_body(min_severity=None, limit=DEFAULT_LIMIT, offset=0):
    """Build the JSON request body for /incidents/find."""
    body = {
        "limit": int(limit),
        "offset": int(offset),
    }
    severities = severities_at_or_above(min_severity)
    if severities:
        body["filter"] = {"severity": severities}
    return body


def url_path(base, path):
    """Build a full URL + return the canonical path-only portion for signing."""
    base = normalize_base_url(base)
    return f"{base}{path}"


def signing_path(url):
    """Pull the path (+ optional query string) out of a full URL for the HMAC string."""
    if not isinstance(url, str) or not url:
        return ""
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return path


def epoch_ms(now=None):
    """Return the current epoch in milliseconds."""
    if now is None:
        now = time.time()
    try:
        return str(int(float(now) * 1000))
    except (TypeError, ValueError):
        return "0"


def canonicalise_body(body):
    """Serialise ``body`` to the canonical JSON string used in the signature.

    SearchLight's HMAC scheme signs the literal request
    body (UTF-8 bytes).  ``None`` and the empty string
    both serialise to ``""`` (an empty body — typical
    for GETs).  Dicts / lists are serialised with
    ``json.dumps`` using sorted keys + no whitespace so
    the dispatcher and the server agree on the exact
    bytes signed.
    """
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return ""


def build_string_to_sign(timestamp_ms, method, path, body=None):
    """Build the canonical string used as the HMAC input.

    Format: ``"{epoch_ms}{HTTP_VERB}{path}{body}"`` —
    timestamp in ms, uppercased HTTP verb, URL path
    (with query string when present), and the canonical
    body string (or empty for GETs).  All five inputs
    are coerced to ``str`` so callers don't need to
    pre-coerce.
    """
    ts = str(timestamp_ms or "")
    verb = str(method or "").upper()
    p = str(path or "")
    b = canonicalise_body(body)
    return f"{ts}{verb}{p}{b}"


def hmac_signature(secret, string_to_sign):
    """Compute the base64-encoded HMAC-SHA256 of ``string_to_sign``.

    ``secret`` / ``string_to_sign`` are coerced to
    bytes (empty / non-string inputs become empty
    bytes) so the signing call never raises locally —
    the server can still reject a bad signature with
    a useful 401.
    """
    if isinstance(secret, str):
        key = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        key = bytes(secret)
    else:
        key = b""
    if isinstance(string_to_sign, str):
        msg = string_to_sign.encode("utf-8")
    elif isinstance(string_to_sign, (bytes, bytearray)):
        msg = bytes(string_to_sign)
    else:
        msg = b""
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def request_headers(key, secret, method, url, body=None, timestamp_ms=None):
    """Build the request-header dict for a single SearchLight request.

    ``Accept: application/json`` and ``Content-Type:
    application/json`` are always sent;
    ``Authorization: hmac {key}:{sig}`` and
    ``searchlight-timestamp: {ts}`` carry the HMAC
    credential pair; the legacy ``X-DS-Timestamp`` /
    ``X-DS-Signature`` header pair is emitted in
    parallel for compatibility with older on-prem
    SearchLight installs.
    """
    if timestamp_ms is None:
        timestamp_ms = epoch_ms()
    path = signing_path(url)
    string_to_sign = build_string_to_sign(timestamp_ms, method, path, body)
    sig = hmac_signature(secret, string_to_sign)
    key_text = str(key or "").strip()
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"hmac {key_text}:{sig}",
        "searchlight-timestamp": str(timestamp_ms),
        "X-DS-Timestamp": str(timestamp_ms),
        "X-DS-Signature": sig,
    }


def parse_iso_datetime(value):
    """Parse an ISO-8601 timestamp into a UTC datetime.

    SearchLight emits ``raised`` / ``modified`` /
    ``occurred`` / ``published`` as
    ``YYYY-MM-DDTHH:MM:SSZ`` (or with a numeric offset
    on some federated mirrors).  Returns ``None`` for
    missing / malformed inputs.
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


def extract_incidents(body):
    """Pull the incident list from a SearchLight find-incidents envelope.

    Canonical envelope is ``{"content": [...]}`` (a
    bare list under ``content`` — same shape for
    ``/incidents/find`` and ``/intel-incidents/find``).
    Federated / on-prem mirrors collapse this into a
    bare top-level list or
    ``{"incidents": [...]}`` / ``{"intel_incidents":
    [...]}`` / ``{"data": [...]}`` / ``{"results":
    [...]}`` / ``{"items": [...]}`` — all six shapes
    are accepted so the caller doesn't care about
    envelope drift.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    content = body.get("content")
    if isinstance(content, list):
        return [entry for entry in content if isinstance(entry, dict)]
    if isinstance(content, dict):
        for key in ("incidents", "intel_incidents", "intel-incidents", "results", "items", "data"):
            v = content.get(key)
            if isinstance(v, list):
                return [entry for entry in v if isinstance(entry, dict)]
    for key in ("incidents", "intel_incidents", "intel-incidents", "results", "items", "data"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_envelope_meta(body):
    """Pull pagination metadata from a SearchLight envelope.

    Returns ``{"total": int|None, "offset": int|None,
    "limit": int|None}`` with missing fields left as
    ``None``.  Both the bare-root keys and the
    ``content.*`` nested keys are accepted.
    """
    out = {"total": None, "offset": None, "limit": None}
    if not isinstance(body, dict):
        return out
    sources = [body]
    content = body.get("content")
    if isinstance(content, dict):
        sources.insert(0, content)
    for src in sources:
        for key in ("total", "offset", "limit", "totalCount", "totalResults"):
            target = key
            if key == "totalCount" or key == "totalResults":
                target = "total"
            if out.get(target) is not None:
                continue
            v = src.get(key)
            if v is None or isinstance(v, bool):
                continue
            try:
                out[target] = int(v)
            except (TypeError, ValueError):
                out[target] = None
    return out


def extract_record_id(record):
    """Pull the canonical SearchLight record id (``id`` or ``identifier``)."""
    if not isinstance(record, dict):
        return ""
    for key in ("id", "identifier", "incident_id", "_id"):
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


def extract_title(record):
    """Pull the incident display title."""
    if not isinstance(record, dict):
        return ""
    for key in ("title", "name", "summary"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_severity(record):
    """Pull the canonical SearchLight severity label (or '').

    Tolerates case + whitespace + aliasing onto the
    title-cased label.  Returns ``''`` (not None) for
    missing / unknown inputs so the caller can treat
    unscored incidents as ``info`` uniformly.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("severity", "threat_level", "threatLevel"):
        v = record.get(key)
        if v is None or isinstance(v, bool):
            continue
        text = str(v).strip()
        if not text:
            continue
        alias = SEVERITY_ALIASES.get(text.lower())
        if alias is not None:
            return alias
        if text in ALLOWED_SEVERITIES:
            return text
    return ""


def extract_status(record):
    """Pull the incident status (Open / Closed / Resolved / ...)."""
    if not isinstance(record, dict):
        return ""
    v = record.get("status")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ""


def is_closed(record):
    """Return True when the incident is in a closed / resolved state."""
    status = extract_status(record)
    if not status:
        return False
    return status.strip().lower() in CLOSED_STATUSES


def extract_type(record):
    """Pull the incident type string."""
    if not isinstance(record, dict):
        return ""
    for key in ("type", "incident_type", "incidentType", "category"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_summary(record):
    """Pull the free-text analyst summary for an incident."""
    if not isinstance(record, dict):
        return ""
    for key in ("description", "summary", "details"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_mitigation(record):
    """Pull the analyst-authored mitigation text."""
    if not isinstance(record, dict):
        return ""
    for key in ("mitigation", "recommendation", "remediation"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_portal_url(record):
    """Pull the SearchLight portal permalink for the incident."""
    if not isinstance(record, dict):
        return ""
    for key in ("portal_url", "portalUrl", "link", "url"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_entities(record):
    """Pull the operator-side entities the incident is correlated against.

    SearchLight emits ``entities`` as a list of
    ``{"type": "domain" | "ip" | "email" | "url" /
    "credential" / "executive", "value": "..."}``
    dicts.  Bare-string entries are surfaced as
    ``{"type": "", "value": "..."}``.  Returns a
    deduped list of ``{"type": str, "value": str}``.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("entities")
    if not isinstance(block, list):
        return out
    for entry in block:
        if isinstance(entry, dict):
            type_raw = entry.get("type") or entry.get("entity_type") or entry.get("entityType")
            value_raw = entry.get("value") or entry.get("name") or entry.get("identifier")
            t = type_raw.strip() if isinstance(type_raw, str) else ""
            v = value_raw.strip() if isinstance(value_raw, str) else ""
            if not v:
                continue
            key = (t.lower(), v.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": t, "value": v})
        elif isinstance(entry, str) and entry.strip():
            v = entry.strip()
            key = ("", v.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": "", "value": v})
    return out


def extract_actors(record):
    """Pull the named threat-actor / APT group list (intel-incidents only)."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("actors") or record.get("threat_actors") or record.get("threatActors")
    if not isinstance(block, list):
        return out
    for entry in block:
        name = None
        if isinstance(entry, dict):
            n = entry.get("name") or entry.get("title") or entry.get("alias")
            if isinstance(n, str):
                name = n.strip()
        elif isinstance(entry, str):
            name = entry.strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        out.append(name)
    return out


def extract_tags(record):
    """Pull the campaign + TTP tag list (intel-incidents only)."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("tags")
    if not isinstance(block, list):
        return out
    for entry in block:
        if isinstance(entry, dict):
            n = entry.get("name") or entry.get("value")
            if isinstance(n, str):
                text = n.strip()
            else:
                continue
        elif isinstance(entry, str):
            text = entry.strip()
        else:
            continue
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append(text)
    return out


def extract_references(record):
    """Pull the analyst-curated references URL list (intel-incidents only)."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("references") or record.get("refs")
    if not isinstance(block, list):
        return out
    for entry in block:
        url = None
        if isinstance(entry, dict):
            u = entry.get("url") or entry.get("link") or entry.get("href")
            if isinstance(u, str):
                url = u.strip()
        elif isinstance(entry, str):
            url = entry.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out


def severity_for_record(record):
    """Final Faraday severity for a SearchLight record.

    Maps the published Very-Low / Low / Medium / High
    / Very-High label onto Faraday's severity ladder;
    floors closed / resolved incidents to ``info``
    regardless of the ladder; defaults to ``info``
    when the record carries no parseable severity.
    """
    sev = extract_severity(record)
    if not sev:
        return "info"
    if is_closed(record):
        return "info"
    return SEVERITY_MAP.get(sev, "info")


def collect_cves(record):
    """Pull CVE ids from the incident title / summary / mitigation / structured cve field.

    SearchLight optionally carries a structured ``cve``
    field (list of CVE ids) and additionally surfaces
    CVEs in the free-text title / summary / mitigation.
    Returns a deduped uppercase list.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out

    structured = record.get("cve")
    if isinstance(structured, list):
        for entry in structured:
            if isinstance(entry, str):
                m = CVE_RE.fullmatch(entry.strip())
                if m:
                    cve = entry.strip().upper()
                    if cve not in seen:
                        seen.add(cve)
                        out.append(cve)
    elif isinstance(structured, str):
        if CVE_RE.fullmatch(structured.strip()):
            cve = structured.strip().upper()
            if cve not in seen:
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

    harvest(extract_title(record))
    harvest(extract_summary(record))
    harvest(extract_mitigation(record))
    return out


def collect_refs(record, is_intel=False):
    """Build the refs list for one SearchLight record.

    Surfaces the record id, title, type, severity,
    status, mitigation, entities, actors (intel mode),
    tags (intel mode), references (intel mode), the
    SearchLight portal permalink, and timestamps so
    operators can pivot from a Faraday finding back to
    the SearchLight portal.
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

    if not isinstance(record, dict):
        return refs

    prefix = "DsIntel" if is_intel else "Ds"

    rid = extract_record_id(record)
    if rid:
        add(f"{prefix}-ID: {rid}")

    title = extract_title(record)
    if title:
        add(f"{prefix}-Title: {title}")

    type_text = extract_type(record)
    if type_text:
        add(f"{prefix}-Type: {type_text}")

    sev = extract_severity(record)
    if sev:
        add(f"{prefix}-Severity: {sev}")

    status = extract_status(record)
    if status:
        add(f"{prefix}-Status: {status}")

    for entity in extract_entities(record):
        etype = entity.get("type") or ""
        evalue = entity.get("value") or ""
        if etype:
            add(f"{prefix}-Entity: {etype}: {evalue}")
        else:
            add(f"{prefix}-Entity: {evalue}")

    if is_intel:
        for actor in extract_actors(record):
            add(f"{prefix}-Actor: {actor}")
        for tag in extract_tags(record):
            add(f"{prefix}-Tag: {tag}")
        for ref_url in extract_references(record):
            add(ref_url)
            add(f"{prefix}-Reference: {ref_url}")

    portal = extract_portal_url(record)
    if portal:
        add(portal)
        add(f"{prefix}-Portal: {portal}")

    for cve in collect_cves(record):
        add(f"{prefix}-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    for key, label in (
        ("raised", "Raised"),
        ("modified", "Modified"),
        ("occurred", "Occurred"),
        ("published", "Published"),
    ):
        dt = parse_iso_datetime(record.get(key))
        if dt is not None:
            add(f"{prefix}-{label}: {dt.isoformat()}")

    return refs


def resolution_for_record(record, is_intel=False):
    """Type-appropriate analyst recommendation.

    Prefers the SearchLight analyst-authored
    ``mitigation`` text when present.  Falls back to a
    canned per-type recommendation otherwise.
    """
    if not isinstance(record, dict):
        return "Triage in the SearchLight portal and apply " "the analyst-recommended remediation."
    mit = extract_mitigation(record)
    if mit:
        return mit
    type_text = extract_type(record).lower()
    if "phish" in type_text:
        return (
            "Submit takedown via the SearchLight Takedown "
            "service; block the phishing URL on the "
            "operator's egress proxy and endpoint web-"
            "filter; notify the impersonated brand owners."
        )
    if "data loss" in type_text or "credential" in type_text or "leak" in type_text:
        return (
            "Rotate exposed credentials, force-reset "
            "affected accounts, and notify the data-"
            "protection officer for forensic review."
        )
    if "brand" in type_text:
        return "Engage trademark counsel and request domain-" "registrar takedown of the impersonating " "asset."
    if "infrastructure" in type_text or "exposed" in type_text:
        return (
            "Rotate the exposed secrets / API keys and "
            "audit for unauthorised use in the "
            "corresponding service logs."
        )
    if "cyber threat" in type_text or "attack" in type_text or "malware" in type_text:
        return (
            "Add the indicators of compromise to the "
            "operator's perimeter blocklist, EDR exclusion / "
            "containment rules, and SIEM correlation queries."
        )
    if "vip" in type_text or "executive" in type_text:
        return (
            "Notify the affected executive and expand "
            "monitoring scope on their digital footprint "
            "per the operator's VIP-protection playbook."
        )
    if is_intel:
        return (
            "Triage the SearchLight intel incident, "
            "correlate the surfaced TTPs / IOCs against "
            "the operator's telemetry, and update "
            "perimeter / EDR blocklists per analyst "
            "guidance."
        )
    return "Triage in the SearchLight portal and apply the " "analyst-recommended remediation."


def build_vulnerability(record, is_intel=False):
    """Build a Faraday vulnerability dict for one SearchLight record."""
    if not isinstance(record, dict):
        return None

    title = extract_title(record)
    type_text = extract_type(record)
    if not title and not type_text:
        return None

    severity = severity_for_record(record)
    rid = extract_record_id(record)
    sev_label = extract_severity(record)
    status = extract_status(record)

    prefix = "[DigitalShadows][Intel]" if is_intel else "[DigitalShadows]"
    name_parts = [prefix]
    if type_text:
        name_parts.append(type_text)
    if title:
        name_parts.append(title)
    if sev_label:
        name_parts.append(f"({sev_label})")
    name = " ".join(name_parts)

    desc_parts = []
    if rid:
        desc_parts.append(f"incidentID: {rid}")
    if title:
        desc_parts.append(f"title: {title}")
    if type_text:
        desc_parts.append(f"type: {type_text}")
    if sev_label:
        desc_parts.append(f"severity: {sev_label}")
    if status:
        desc_parts.append(f"status: {status}")
    entities = extract_entities(record)
    if entities:
        desc_parts.append(
            "entities: " + ", ".join(f"{e.get('type') or 'Entity'}={e.get('value')}" for e in entities[:20])
        )
    if is_intel:
        actors = extract_actors(record)
        if actors:
            desc_parts.append("actors: " + ", ".join(actors[:20]))
        tags = extract_tags(record)
        if tags:
            desc_parts.append("tags: " + ", ".join(tags[:20]))
    raised = parse_iso_datetime(record.get("raised"))
    if raised is not None:
        desc_parts.append(f"raised: {raised.isoformat()}")
    modified = parse_iso_datetime(record.get("modified"))
    if modified is not None:
        desc_parts.append(f"modified: {modified.isoformat()}")
    occurred = parse_iso_datetime(record.get("occurred"))
    if occurred is not None:
        desc_parts.append(f"occurred: {occurred.isoformat()}")
    published = parse_iso_datetime(record.get("published"))
    if published is not None:
        desc_parts.append(f"published: {published.isoformat()}")
    portal = extract_portal_url(record)
    if portal:
        desc_parts.append(f"portal: {portal}")
    summary = extract_summary(record)
    if summary:
        desc_parts.append(f"summary: {summary}")

    external_id = rid or title[:200] or name
    resolution = resolution_for_record(record, is_intel=is_intel)

    return {
        "name": str(name).strip()[:200] or "Digital Shadows incident",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record, is_intel=is_intel),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["digital-shadows"],
    }


def build_host(vulns, min_severity, limit, meta):
    """Build the single synthetic host that carries every SearchLight vuln."""
    desc_parts = ["source=digital-shadows"]
    if min_severity:
        desc_parts.append(f"min_severity={min_severity}")
    if limit:
        desc_parts.append(f"limit={limit}")
    if isinstance(meta, dict):
        total = meta.get("total")
        if total is not None:
            desc_parts.append(f"ds_total={total}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["digital-shadows"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url, key, secret, body=None, method="POST", timestamp_ms=None):
    """POST / GET a single SearchLight URL with HMAC auth.

    Network / HTTP / JSON errors are logged but never
    raised upstream so a transient SearchLight outage
    doesn't crash the dispatcher.  Returns ``None`` on
    any failure.
    """
    headers = request_headers(
        key,
        secret,
        method,
        url,
        body=body,
        timestamp_ms=timestamp_ms,
    )
    payload = canonicalise_body(body) if body is not None else None
    try:
        if method.upper() == "GET":
            resp = requests_module.get(url, timeout=TIMEOUT, headers=headers)
        else:
            resp = requests_module.post(
                url,
                timeout=TIMEOUT,
                headers=headers,
                data=payload,
            )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"{method} {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"SearchLight record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"SearchLight request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"SearchLight response was not JSON ({url})")
        return None


def fetch_collection(
    requests_module,
    host,
    key,
    secret,
    path,
    min_severity,
    limit,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    max_results=MAX_RESULTS,
):
    """Page through one of the /incidents/find endpoints."""
    records = []
    last_meta = {"total": None, "offset": None, "limit": None}
    offset = 0
    page = 0
    while page < max_pages and len(records) < max_results:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        remaining = max_results - len(records)
        page_limit = min(limit, remaining)
        if page_limit <= 0:
            break
        url = url_path(host, path)
        body = build_filter_body(
            min_severity=min_severity,
            limit=page_limit,
            offset=offset,
        )
        resp = fetch_url(
            requests_module,
            url,
            key,
            secret,
            body=body,
            method="POST",
        )
        if resp is None:
            break
        meta = extract_envelope_meta(resp)
        if meta:
            last_meta = meta
        page_records = extract_incidents(resp)
        if not page_records:
            break
        for entry in page_records:
            records.append(entry)
            if len(records) >= max_results:
                break
        offset += len(page_records)
        total = last_meta.get("total")
        if total is not None and offset >= total:
            break
        # If the server returned fewer than we asked for, we're done.
        if len(page_records) < page_limit:
            break
        page += 1
    return records, last_meta


def main():
    started = time.time()

    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_DS_MIN_SEVERITY"))
    limit = validate_limit(env("EXECUTOR_CONFIG_DS_LIMIT"))
    host = env("DS_HOST", required=True)
    key = env("DS_KEY", required=True)
    secret = env("DS_SECRET", required=True)

    if not normalize_base_url(host):
        log("DS_HOST is not a valid URL")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    incidents, incidents_meta = fetch_collection(
        requests,
        host,
        key,
        secret,
        INCIDENTS_PATH,
        min_severity=min_severity,
        limit=limit,
    )
    intel_incidents, intel_meta = fetch_collection(
        requests,
        host,
        key,
        secret,
        INTEL_INCIDENTS_PATH,
        min_severity=min_severity,
        limit=limit,
    )

    vulns = []
    for entry in incidents:
        vuln = build_vulnerability(entry, is_intel=False)
        if vuln is not None:
            vulns.append(vuln)
    for entry in intel_incidents:
        vuln = build_vulnerability(entry, is_intel=True)
        if vuln is not None:
            vulns.append(vuln)

    incidents_total = incidents_meta.get("total") if isinstance(incidents_meta, dict) else None
    intel_total = intel_meta.get("total") if isinstance(intel_meta, dict) else None
    log(
        f"Processed {len(vulns)} SearchLight records "
        f"(incidents={len(incidents)}/total={incidents_total if incidents_total is not None else '?'}, "
        f"intel_incidents={len(intel_incidents)}/total={intel_total if intel_total is not None else '?'}, "
        f"min_severity={min_severity or 'none'}, limit={limit})"
    )

    combined_meta = {
        "total": (
            (incidents_total or 0) + (intel_total or 0)
            if (incidents_total is not None or intel_total is not None)
            else None
        ),
    }
    hosts_out = [build_host(vulns, min_severity, limit, combined_meta)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "digital_shadows",
            "command": "digital_shadows",
            "params": (f"min_severity={min_severity or ''} limit={limit}"),
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
