#!/usr/bin/env python
"""ThreatConnect Threat Intelligence importer.

Pulls indicator-of-compromise (IOC) records from the
ThreatConnect Threat Intelligence Platform REST API (v3) and
emits Faraday bulk-create JSON to stdout.  ThreatConnect is a
commercial TIP — operators curate IOCs (Address / EmailAddress
/ File / Host / URL) under named "owners" (organisation /
community / source) and surface them to downstream tools via
the v3 REST API.

Endpoints used:
  GET {TC_HOST}/api/v3/indicators
      ?tql=<TQL>&fields=<...>&resultStart=N&resultLimit=N
      -> paginated indicator inventory under a named owner.
      ``tql`` is ThreatConnect's documented query language —
      we construct a filter that pins ``ownerName`` and
      ``typeName`` and sort by ``lastModified`` desc so the
      newest IOCs are at the head of the result set.  The
      response envelope is the canonical TC v3 shape
      ``{"data": [...], "status": "Success", "resultCount":
      N, "resultStart": N, "resultLimit": N, "next": "..."}``.
      Each record carries ``id``, ``ownerName``, ``type``,
      ``summary`` (the canonical indicator value), ``dateAdded``,
      ``lastModified``, ``rating`` (1..5 — TC analyst rating),
      ``confidence`` (0..100), ``threatAssessRating``,
      ``threatAssessConfidence``, ``threatAssessScore``,
      ``active`` (bool), ``description`` (free-text), optional
      ``tags`` (list of objects with ``name``), optional
      ``attributes`` (typed key/value pairs), optional
      ``associatedGroups`` (linked threat groups), optional
      ``associatedIndicators`` (linked IOCs), and the typed
      indicator-specific fields (``ip``, ``hostName``, ``address``,
      ``md5`` / ``sha1`` / ``sha256``, ``text`` (URLs)).
  GET {TC_HOST}/api/v3/groups
      ?tql=<TQL>&fields=<...>&resultStart=N&resultLimit=N
      -> paginated group inventory (Threat / Campaign / Adversary
      / Incident / IntrusionSet / Malware / Tool / Vulnerability /
      Report / Document / Email / Signature / Tactic / Course of
      Action).  Used opportunistically to enrich per-indicator
      group-name labels when the indicator response only carries
      group ids; failure is non-fatal — the IOC is still emitted
      with the bare group id.

Auth: ThreatConnect uses HMAC-SHA256 signed requests.  The
operator creates an API key + secret pair in the TC console
(Account Settings -> Memberships -> Create API User -> save the
``access_id`` + ``secret_key`` pair) and pastes the returned
values into ``TC_ACCESS_ID`` + ``TC_SECRET_KEY``.  The
dispatcher constructs the canonical signing string
``<URI_PATH>:<HTTP_METHOD>:<UNIX_TIMESTAMP>`` (where URI_PATH
is the request path + query string starting with ``/`` per the
TC v3 reference), computes
``base64(HMAC-SHA256(secret_key, canonical))`` and sends the
``Authorization: TC <access_id>:<signature>`` + ``Timestamp:
<unix_timestamp>`` headers on every request.

Args:
  ``TC_OWNER`` (mandatory) — the ThreatConnect "owner" name to
  pull indicators under.  Operators typically pin a single
  organisation / community / source ("Common Community", "My
  Org", "vendor X feed") so the executor only emits IOCs the
  operator has access to under that owner.  Forwarded into the
  TQL filter as ``ownerName = "..."``.

  ``TC_INDICATOR_TYPE`` (mandatory) — one of ``Address`` (IPv4
  / IPv6), ``EmailAddress``, ``File`` (hashes), ``Host`` (FQDN),
  ``URL``.  Forwarded into the TQL filter as ``typeName =
  "..."`` so the API itself does the type-narrowing.  Anything
  else is rejected client-side with a hard error so a typo
  doesn't silently pull every indicator type.

Env vars:
  ``TC_HOST`` (optional) — defaults to
  ``https://api.threatconnect.com`` (the canonical TC cloud
  host).  Settable to a regional / dedicated-tenant URL or to
  a self-hosted on-prem TC instance.

  ``TC_ACCESS_ID`` + ``TC_SECRET_KEY`` (both mandatory) — the
  HMAC credential pair issued by TC at API-user-creation time.

Each indicator becomes one Faraday vulnerability under a single
synthetic ``0.0.0.0`` host with hostname ``threatconnect``.
ThreatConnect IOCs are IOC-keyed not host-keyed — the operator's
other agents emit the host-side findings this feed is
correlated against.  The vulnerability carries
``tags: ['threatconnect']`` and surfaces the indicator value +
type + rating + confidence + threatAssessScore + tags +
associated groups in both the description and the refs list so
operators can pivot from a Faraday finding back to the TC
record.

Severity is bucketed from TC's ``threatAssessScore`` (0..1000
proprietary CAL score; higher = more malicious) — when present:
  - ``>= 800`` -> critical
  - ``>= 500`` -> high
  - ``>= 200`` -> medium
  - ``>= 50``  -> low
  - ``< 50``   -> info
Falls back to the ``rating`` (1..5) ladder when threatAssess is
absent: 5 -> critical / 4 -> high / 3 -> medium / 2 -> low /
1 -> info.  Inactive indicators (``active: false``) are floored
to ``info`` regardless of score — TC operators only mark IOCs
inactive after analyst review confirms they're stale.  Records
with no parseable score and ``rating`` missing default to
``info`` — we don't synthesise a ranking TC hasn't published.

Status is always ``open`` (a TC IOC cannot be 'fixed' in the
catalog — it can only be blocked on the operator's perimeter /
EDR).  Resolution defaults to a type-appropriate blocking
recommendation: Address -> firewall + egress proxy + EDR;
EmailAddress -> mail-server blocklist + DMARC/quarantine; File
-> EDR / AV / endpoint-prevention; Host -> sinkhole + DNS
blocklist; URL -> egress proxy + endpoint web-filter.
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
from urllib.parse import quote, urlencode

TIMEOUT = 60

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

DEFAULT_HOST = "https://api.threatconnect.com"
INDICATORS_PATH = "/api/v3/indicators"
GROUPS_PATH = "/api/v3/groups"

# TC v3 caps each page at 10000 records via resultLimit; we
# default to 500 per page to keep individual responses small
# and recoverable on flaky links, and cap the executor at a
# total of MAX_RESULTS (10000) across the paginated walk —
# enough for any realistic operational mode without giving the
# operator the rope to spin the dispatcher for hours on chatty
# tenants.
PAGE_LIMIT = 500
MAX_PAGES = 50
MAX_RESULTS = 10000

# TC documents a per-tenant ~75 req/min ceiling on the v3
# endpoints — pacing at 0.4s between pages keeps a single
# executor invocation well under the ceiling without burning
# more than ~0.4s of wall-clock per page.
INTER_REQUEST_SLEEP = 0.4

# ThreatConnect's allowed indicator type vocabulary for this
# executor's contract.  TC supports more types in the platform
# (CIDR, ASN, Mutex, Registry Key, User Agent, ...) but the
# per-task spec narrows this executor's contract to these five.
ALLOWED_INDICATOR_TYPES = (
    "Address",
    "EmailAddress",
    "File",
    "Host",
    "URL",
)

# Map operator-friendly aliases to canonical TC type names so a
# user typing "ip" or "fqdn" still works.
INDICATOR_TYPE_ALIASES = {
    "address": "Address",
    "ip": "Address",
    "ipv4": "Address",
    "ipv6": "Address",
    "emailaddress": "EmailAddress",
    "email": "EmailAddress",
    "email_address": "EmailAddress",
    "file": "File",
    "hash": "File",
    "host": "Host",
    "fqdn": "Host",
    "domain": "Host",
    "url": "URL",
    "uri": "URL",
}

# TC rating ladder (1..5).  Maps the explicit 1..5 integer
# analyst rating onto Faraday's severity ladder when the
# numeric threatAssessScore is missing.
RATING_SEVERITY_MAP = {
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: "info",
}

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")


def log(msg):
    print(f"{datetime.utcnow()} - ThreatConnect: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on TC_HOST.

    Defaults to ``https://api.threatconnect.com`` (the canonical
    TC cloud host) when the env override is missing / blank.
    Whitespace is trimmed and ``https://`` is added
    automatically when the operator pasted in a bare FQDN
    (self-hosted TC instances are typically copied as raw
    hostnames from the console).
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


def validate_indicator_type(value):
    """Coerce TC_INDICATOR_TYPE into one of the allowed types.

    TC's TQL grammar is case-sensitive on the value side
    (``typeName = "Address"`` works, ``typeName = "address"``
    does not) so we normalise via ``INDICATOR_TYPE_ALIASES``
    onto the canonical title-cased TC type name.  Returns
    ``None`` for missing / blank / unknown inputs so the caller
    can hard-fail with a helpful error rather than pulling every
    indicator type.
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    canonical = INDICATOR_TYPE_ALIASES.get(text.lower())
    if canonical is not None:
        return canonical
    if text in ALLOWED_INDICATOR_TYPES:
        return text
    return None


def validate_owner(value):
    """Coerce TC_OWNER into a non-empty string."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return text or None


def tql_quote(value):
    """Quote a string value for embedding in a TC TQL filter.

    TC TQL string values are double-quoted; embedded double
    quotes are escaped by doubling.  Returns the bare quoted
    form so the caller can compose with ``and`` / ``or``.
    """
    text = "" if value is None else str(value)
    return '"' + text.replace('"', '""') + '"'


def build_indicators_tql(owner, indicator_type):
    """Build the TQL filter pinning ``ownerName`` + ``typeName``."""
    return f"ownerName EQ {tql_quote(owner)} " f"AND typeName EQ {tql_quote(indicator_type)}"


def build_groups_tql(owner):
    """Build the TQL filter pinning ``ownerName`` for /groups."""
    return f"ownerName EQ {tql_quote(owner)}"


# Comma-separated field list forwarded to TC via ``fields=`` so
# the response includes the analyst metadata we surface in
# Faraday.  TC's v3 default response is a sparse projection; we
# explicitly opt in to the full set.
INDICATOR_FIELDS = (
    "tags",
    "attributes",
    "associatedGroups",
    "associatedIndicators",
    "observationCount",
    "threatAssess",
    "description",
)


def build_indicators_url(host, owner, indicator_type, result_start=0, result_limit=PAGE_LIMIT):
    """Build the /api/v3/indicators URL with TQL + pagination."""
    base = normalize_base_url(host)
    params = [
        ("tql", build_indicators_tql(owner, indicator_type)),
        ("resultStart", int(result_start)),
        ("resultLimit", int(result_limit)),
        ("sorting", "lastModified desc"),
    ]
    for field in INDICATOR_FIELDS:
        params.append(("fields", field))
    return f"{base}{INDICATORS_PATH}?{urlencode(params)}"


def build_groups_url(host, owner, result_start=0, result_limit=PAGE_LIMIT):
    """Build the /api/v3/groups URL for opportunistic enrichment."""
    base = normalize_base_url(host)
    params = [
        ("tql", build_groups_tql(owner)),
        ("resultStart", int(result_start)),
        ("resultLimit", int(result_limit)),
        ("sorting", "lastModified desc"),
    ]
    return f"{base}{GROUPS_PATH}?{urlencode(params)}"


def request_path_for_signing(url):
    """Pull the path+query component from a full TC URL.

    TC's HMAC canonical includes the path-and-query portion of
    the URL starting with ``/``.  Falls back to ``/`` when the
    URL is malformed so signing still produces something the
    server can reject with a useful 401 rather than crashing
    locally.
    """
    if not isinstance(url, str) or not url:
        return "/"
    # Strip scheme.
    text = url
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix) :]
            break
    # Strip host (everything up to first ``/``).
    idx = text.find("/")
    if idx == -1:
        return "/"
    return text[idx:]


def build_canonical(uri_path, method, timestamp):
    """Build the canonical signing string TC v3 signs.

    Format is ``<URI_PATH>:<HTTP_METHOD>:<UNIX_TIMESTAMP>`` per
    the TC v3 API reference.
    """
    return f"{uri_path}:{str(method).upper()}:{int(timestamp)}"


def sign_request(secret_key, uri_path, method, timestamp):
    """Compute the base64(HMAC-SHA256(secret, canonical)) signature."""
    key = (str(secret_key) if secret_key is not None else "").encode("utf-8")
    canonical = build_canonical(uri_path, method, timestamp)
    digest = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def signed_headers(access_id, secret_key, method, url, now=None):
    """Return the signed-header set for one TC request.

    ``Authorization: TC <access_id>:<signature>`` + ``Timestamp:
    <unix_timestamp>`` are the canonical pair; ``Accept`` is
    passed for completeness.  ``now`` is overridable for
    deterministic tests; defaults to the current unix
    timestamp.
    """
    ts = int(now if now is not None else time.time())
    uri_path = request_path_for_signing(url)
    signature = sign_request(secret_key, uri_path, method, ts)
    return {
        "Authorization": f"TC {str(access_id or '').strip()}:{signature}",
        "Timestamp": str(ts),
        "Accept": "application/json",
    }


def fetch_url(requests_module, url, access_id, secret_key, method="GET", now=None):
    """GET a single TC URL with HMAC signing.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient TC outage doesn't crash the
    dispatcher.  Returns ``None`` on any failure; the caller is
    expected to treat that as "no records" and continue.
    """
    try:
        resp = requests_module.get(
            url,
            timeout=TIMEOUT,
            headers=signed_headers(access_id, secret_key, method, url, now=now),
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"TC record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"TC request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"TC response was not JSON ({url})")
        return None


def extract_data(body):
    """Pull the ``data`` list from a TC v3 envelope.

    TC wraps every response under ``{"data": [...], "status":
    "Success", "resultCount": N, "resultStart": N, "resultLimit":
    N, "next": "..."}``.  Pre-unwrapped payloads from federated
    mirrors and bare-list / ``results`` / ``items`` /
    ``indicators`` fallbacks are accepted too for robustness.
    """
    if isinstance(body, dict):
        for key in ("data", "results", "items", "indicators", "groups"):
            v = body.get(key)
            if isinstance(v, list):
                return [entry for entry in v if isinstance(entry, dict)]
        return []
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    return []


def extract_envelope_meta(body):
    """Pull pagination + status metadata from a TC v3 envelope.

    Returns ``{"status": str|None, "resultCount": int|None,
    "resultStart": int|None, "resultLimit": int|None,
    "next": str|None}``; missing fields stay ``None``.
    """
    out = {
        "status": None,
        "resultCount": None,
        "resultStart": None,
        "resultLimit": None,
        "next": None,
    }
    if not isinstance(body, dict):
        return out
    s = body.get("status")
    if isinstance(s, str) and s.strip():
        out["status"] = s.strip()
    for key in ("resultCount", "resultStart", "resultLimit"):
        v = body.get(key)
        if v is None:
            continue
        try:
            out[key] = int(v)
        except (TypeError, ValueError):
            out[key] = None
    nxt = body.get("next")
    if isinstance(nxt, str) and nxt.strip():
        out["next"] = nxt.strip()
    return out


def parse_iso_datetime(value):
    """Parse an ISO-8601 timestamp into a UTC datetime.

    TC emits ``dateAdded`` / ``lastModified`` as
    ``YYYY-MM-DDTHH:MM:SSZ`` (or with a numeric offset on some
    self-hosted instances).  Returns ``None`` for missing /
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
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def extract_indicator_value(record):
    """Pull the canonical indicator value from a TC indicator record.

    TC carries the canonical value in ``summary`` for all types;
    typed fields (``ip``, ``hostName``, ``address``, ``md5`` /
    ``sha1`` / ``sha256``, ``text``) are also accepted as
    fallbacks for federated mirrors that strip ``summary``.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("summary", "ip", "hostName", "address", "md5", "sha256", "sha1", "text"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_rating(record):
    """Pull the TC 1..5 analyst rating from an indicator record.

    Returns an integer in ``1..5`` when set, ``None`` otherwise.
    Booleans / out-of-range / non-numeric inputs return ``None``.
    """
    if not isinstance(record, dict):
        return None
    v = record.get("rating")
    if v is None or isinstance(v, bool):
        return None
    try:
        r = int(float(v))
    except (TypeError, ValueError):
        return None
    if r < 1 or r > 5:
        return None
    return r


def extract_confidence(record):
    """Pull the TC 0..100 confidence score from an indicator record.

    Returns an integer in ``0..100`` when set, ``None``
    otherwise.  Booleans / out-of-range / non-numeric inputs
    return ``None``.
    """
    if not isinstance(record, dict):
        return None
    v = record.get("confidence")
    if v is None or isinstance(v, bool):
        return None
    try:
        c = int(float(v))
    except (TypeError, ValueError):
        return None
    if c < 0:
        return 0
    if c > 100:
        return 100
    return c


def extract_threat_assess_score(record):
    """Pull the TC 0..1000 threatAssessScore from an indicator record.

    Returns a float in ``0..1000`` when set, ``None`` otherwise.
    The threatAssess block can be either flat (``threatAssessScore``
    at the record root) or nested under ``threatAssess`` — both
    shapes are accepted for federated-mirror robustness.
    """
    if not isinstance(record, dict):
        return None
    val = record.get("threatAssessScore")
    if val is None:
        block = record.get("threatAssess")
        if isinstance(block, dict):
            val = block.get("score")
    if val is None or isinstance(val, bool):
        return None
    try:
        score = float(val)
    except (TypeError, ValueError):
        return None
    if score < 0:
        return 0.0
    if score > 1000:
        return 1000.0
    return score


def is_active(record):
    """Return True when the indicator is marked active.

    TC operators flag IOCs as inactive after analyst review
    confirms they're stale.  Missing / non-bool ``active`` is
    treated as active (TC's default) for backward compatibility.
    """
    if not isinstance(record, dict):
        return True
    v = record.get("active")
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() not in ("false", "no", "0", "")
    return True


def severity_from_score(score):
    """Map a TC threatAssessScore (0..1000) onto a Faraday severity."""
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 800:
        return "critical"
    if s >= 500:
        return "high"
    if s >= 200:
        return "medium"
    if s >= 50:
        return "low"
    return "info"


def severity_from_rating(rating):
    """Map a TC 1..5 analyst rating onto a Faraday severity."""
    if rating is None:
        return None
    try:
        r = int(rating)
    except (TypeError, ValueError):
        return None
    return RATING_SEVERITY_MAP.get(r)


def severity_for_record(record):
    """Final severity for a TC indicator after all overrides.

    Prefers threatAssessScore over rating; floors inactive IOCs
    to ``info`` regardless of score (TC operators only mark IOCs
    inactive after analyst review confirms they're stale).
    Defaults to ``info`` when neither score nor rating is
    parseable.
    """
    score = extract_threat_assess_score(record)
    severity = severity_from_score(score)
    if severity is None:
        severity = severity_from_rating(extract_rating(record))
    if severity is None:
        severity = "info"
    if not is_active(record):
        return "info"
    if severity not in VALID_SEVERITY:
        return "info"
    return severity


def extract_tag_names(record):
    """Pull tag names from a TC indicator record.

    TC emits tags as ``{"data": [{"name": "...", ...}, ...]}``
    under the indicator's ``tags`` field.  We also accept bare
    list shapes for federated-mirror robustness.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    tags = record.get("tags")
    items = []
    if isinstance(tags, dict):
        data = tags.get("data")
        if isinstance(data, list):
            items = data
    elif isinstance(tags, list):
        items = tags
    for entry in items:
        if isinstance(entry, dict):
            name = entry.get("name")
        elif isinstance(entry, str):
            name = entry
        else:
            continue
        if not isinstance(name, str):
            continue
        text = name.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def extract_associated_groups(record):
    """Pull associated-group names from a TC indicator record.

    TC emits associated groups as ``{"data": [{"id": N, "name":
    "...", "type": "Threat" | "Campaign" | ...}, ...]}`` under
    the indicator's ``associatedGroups`` field.  Returns a list
    of ``{"id": int|None, "name": str, "type": str}`` dicts —
    the caller surfaces them in both the description and the
    refs list.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("associatedGroups")
    items = []
    if isinstance(block, dict):
        data = block.get("data")
        if isinstance(data, list):
            items = data
    elif isinstance(block, list):
        items = block
    for entry in items:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        gtype_raw = entry.get("type")
        gtype = gtype_raw.strip() if isinstance(gtype_raw, str) else ""
        gid_raw = entry.get("id")
        try:
            gid = int(gid_raw) if gid_raw is not None else None
        except (TypeError, ValueError):
            gid = None
        key = (name.strip().lower(), gtype.lower(), gid)
        if key in seen:
            continue
        seen.add(key)
        out.append({"id": gid, "name": name.strip(), "type": gtype})
    return out


def extract_attribute_pairs(record):
    """Pull attribute key/value pairs from a TC indicator record.

    TC emits attributes as ``{"data": [{"type": "Source", "value":
    "..."}, ...]}`` under the indicator's ``attributes`` field.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("attributes")
    items = []
    if isinstance(block, dict):
        data = block.get("data")
        if isinstance(data, list):
            items = data
    elif isinstance(block, list):
        items = block
    for entry in items:
        if not isinstance(entry, dict):
            continue
        type_raw = entry.get("type")
        value_raw = entry.get("value")
        if not isinstance(type_raw, str) or not type_raw.strip():
            continue
        if not isinstance(value_raw, str) or not value_raw.strip():
            continue
        key = (type_raw.strip(), value_raw.strip())
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": type_raw.strip(), "value": value_raw.strip()})
    return out


def extract_description(record):
    """Pull the free-text description from a TC indicator record."""
    if not isinstance(record, dict):
        return ""
    desc = record.get("description")
    if isinstance(desc, str) and desc.strip():
        return desc.strip()
    return ""


def extract_indicator_id(record):
    """Pull the canonical TC indicator id."""
    if not isinstance(record, dict):
        return None
    v = record.get("id")
    if v is None or isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        if isinstance(v, str) and v.strip():
            return v.strip()
        return None


def web_link_for_indicator(host, indicator_id, indicator_type):
    """Build the TC web-UI permalink for an indicator record.

    TC's web UI surfaces indicators at
    ``{host}/auth/indicators/details/{type}.xhtml?indicator={id}``;
    falls back to the API permalink when the type isn't known.
    """
    base = normalize_base_url(host)
    # Web UI lives at the bare host without /api.  Strip the
    # /api prefix when the operator pointed TC_HOST at the API
    # host (api.threatconnect.com); leave it alone otherwise.
    web = base
    for suffix in ("/api",):
        if web.endswith(suffix):
            web = web[: -len(suffix)]
    if indicator_id is None:
        return f"{web}/auth/indicators/"
    if not indicator_type:
        return f"{base}{INDICATORS_PATH}/{quote(str(indicator_id))}"
    return (
        f"{web}/auth/indicators/details/"
        f"{quote(str(indicator_type).lower())}.xhtml"
        f"?indicator={quote(str(indicator_id))}"
    )


def collect_cves(record):
    """TC indicators are IOC-keyed, not CVE-keyed.

    A small number of TC analyst-curated records do carry CVE
    references in the attribute list — surface those when
    present.  Returns a deduped list of uppercase ``CVE-...``
    ids.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    for attr in extract_attribute_pairs(record):
        value = attr.get("value") or ""
        if not isinstance(value, str):
            continue
        for match in CVE_RE.findall(value):
            cve = match.upper()
            if cve in seen:
                continue
            seen.add(cve)
            out.append(cve)
    description = extract_description(record)
    if description:
        for match in CVE_RE.findall(description):
            cve = match.upper()
            if cve in seen:
                continue
            seen.add(cve)
            out.append(cve)
    return out


def collect_refs(record, host=None):
    """Build the refs list for one TC indicator record.

    Includes the indicator value, type, owner, rating,
    confidence, threatAssess score, tags, associated groups,
    attribute pairs, the canonical TC record id, the TC web-UI
    permalink, and timestamps so operators can pivot from a
    Faraday finding back to the TC record.
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

    rid = extract_indicator_id(record)
    if rid is not None:
        add(f"Tc-IndicatorID: {rid}")

    value = extract_indicator_value(record)
    if value:
        add(f"Tc-Indicator: {value}")

    type_raw = record.get("type")
    if isinstance(type_raw, str) and type_raw.strip():
        add(f"Tc-Type: {type_raw.strip()}")

    owner_raw = record.get("ownerName")
    if isinstance(owner_raw, str) and owner_raw.strip():
        add(f"Tc-Owner: {owner_raw.strip()}")

    rating = extract_rating(record)
    if rating is not None:
        add(f"Tc-Rating: {rating}")

    confidence = extract_confidence(record)
    if confidence is not None:
        add(f"Tc-Confidence: {confidence}")

    score = extract_threat_assess_score(record)
    if score is not None:
        add(f"Tc-ThreatAssessScore: {score}")

    if not is_active(record):
        add("Tc-Active: false")

    for tag in extract_tag_names(record):
        add(f"Tc-Tag: {tag}")

    for grp in extract_associated_groups(record):
        gtype = grp.get("type") or ""
        gname = grp.get("name") or ""
        if gtype:
            add(f"Tc-Group: {gtype}: {gname}")
        else:
            add(f"Tc-Group: {gname}")

    for attr in extract_attribute_pairs(record):
        add(f"Tc-Attr: {attr.get('type')}: {attr.get('value')}")

    for cve in collect_cves(record):
        add(f"Tc-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    da = parse_iso_datetime(record.get("dateAdded"))
    if da is not None:
        add(f"Tc-DateAdded: {da.isoformat()}")
    lm = parse_iso_datetime(record.get("lastModified"))
    if lm is not None:
        add(f"Tc-LastModified: {lm.isoformat()}")

    obs = record.get("observationCount")
    if isinstance(obs, (int, float)) and not isinstance(obs, bool):
        add(f"Tc-ObservationCount: {int(obs)}")

    if host is not None and rid is not None:
        link = web_link_for_indicator(
            host,
            rid,
            type_raw if isinstance(type_raw, str) else "",
        )
        add(link)

    return refs


def resolution_for_record(record):
    """Type-appropriate blocking recommendation for a TC indicator."""
    if not isinstance(record, dict):
        return "Block this indicator on the operator's perimeter " "controls per ThreatConnect analyst guidance."
    type_raw = record.get("type")
    type_text = type_raw.strip() if isinstance(type_raw, str) else ""
    type_lower = type_text.lower()
    if type_lower == "address":
        return (
            "Block this IP on the operator's perimeter firewall, "
            "egress proxy, and EDR network containment policies."
        )
    if type_lower == "emailaddress":
        return (
            "Block this email address on the operator's mail "
            "server / secure-email gateway and quarantine "
            "inbound messages from this sender."
        )
    if type_lower == "file":
        return "Block this file hash in the operator's EDR / AV / " "endpoint prevention policy."
    if type_lower == "host":
        return "Sinkhole this host / domain on the operator's DNS " "resolver and add to the perimeter blocklist."
    if type_lower == "url":
        return "Block this URL on the operator's egress proxy and " "endpoint web-filter policy."
    return "Block this indicator on the operator's perimeter " "controls per ThreatConnect analyst guidance."


def build_vulnerability(record, host=None):
    """Build a Faraday vulnerability dict for one TC indicator.

    Returns ``None`` when ``record`` is not a dict or carries
    no indicator value (defensive — the API only returns
    records with both ``id`` and ``summary`` populated but we
    don't want to emit a vuln we can't even name).
    """
    if not isinstance(record, dict):
        return None

    value = extract_indicator_value(record)
    type_raw = record.get("type")
    type_text = type_raw.strip() if isinstance(type_raw, str) else ""

    if not value and not type_text:
        return None

    severity = severity_for_record(record)
    score = extract_threat_assess_score(record)
    rating = extract_rating(record)
    confidence = extract_confidence(record)

    rid = extract_indicator_id(record)
    rid_text = str(rid) if rid is not None else ""

    name_parts = ["[TC]"]
    if type_text:
        name_parts.append(type_text)
    if value:
        name_parts.append(value)
    if score is not None:
        name_parts.append(f"score={score}")
    elif rating is not None:
        name_parts.append(f"rating={rating}")
    name = " ".join(name_parts)

    desc_parts = []
    if rid_text:
        desc_parts.append(f"indicatorID: {rid_text}")
    if value:
        desc_parts.append(f"indicator: {value}")
    if type_text:
        desc_parts.append(f"type: {type_text}")
    owner_raw = record.get("ownerName")
    if isinstance(owner_raw, str) and owner_raw.strip():
        desc_parts.append(f"owner: {owner_raw.strip()}")
    if score is not None:
        desc_parts.append(f"threatAssessScore: {score}")
    if rating is not None:
        desc_parts.append(f"rating: {rating}")
    if confidence is not None:
        desc_parts.append(f"confidence: {confidence}")
    desc_parts.append(f"active: {is_active(record)}")
    desc_parts.append(f"severity: {severity}")
    tags = extract_tag_names(record)
    if tags:
        desc_parts.append("tags: " + ", ".join(tags))
    groups = extract_associated_groups(record)
    if groups:
        desc_parts.append(
            "associatedGroups: " + ", ".join(f"{g.get('type') or 'Group'}={g.get('name')}" for g in groups[:20])
        )
    attrs = extract_attribute_pairs(record)
    if attrs:
        desc_parts.append("attributes: " + ", ".join(f"{a.get('type')}={a.get('value')}" for a in attrs[:20]))
    da = parse_iso_datetime(record.get("dateAdded"))
    if da is not None:
        desc_parts.append(f"dateAdded: {da.isoformat()}")
    lm = parse_iso_datetime(record.get("lastModified"))
    if lm is not None:
        desc_parts.append(f"lastModified: {lm.isoformat()}")
    obs = record.get("observationCount")
    if isinstance(obs, (int, float)) and not isinstance(obs, bool):
        desc_parts.append(f"observationCount: {int(obs)}")
    description = extract_description(record)
    if description:
        desc_parts.append(f"description: {description}")

    external_id = rid_text or value or name
    resolution = resolution_for_record(record)

    return {
        "name": str(name).strip()[:200] or "ThreatConnect indicator",
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
        "tags": ["threatconnect"],
    }


def build_host(vulns, owner, indicator_type, meta):
    """Build the single synthetic host that carries every IOC vuln.

    TC indicators are IOC-keyed not host-keyed — the operator's
    other agents emit the host-side findings this feed is
    correlated against — so we collapse the whole feed under
    one synthetic ``0.0.0.0`` host with hostname
    ``threatconnect``.
    """
    desc_parts = ["source=threatconnect"]
    if owner:
        desc_parts.append(f"owner={owner}")
    if indicator_type:
        desc_parts.append(f"type={indicator_type}")
    if isinstance(meta, dict):
        total = meta.get("resultCount")
        if total is not None:
            desc_parts.append(f"tc_total={total}")
        status = meta.get("status")
        if status:
            desc_parts.append(f"tc_status={status}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["threatconnect"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_indicators(
    requests_module,
    host,
    access_id,
    secret_key,
    owner,
    indicator_type,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    page_limit=PAGE_LIMIT,
    max_results=MAX_RESULTS,
):
    """Page through /api/v3/indicators up to max_results.

    Returns ``(records, last_meta)`` where ``records`` is the
    accumulated indicator list and ``last_meta`` is the
    most-recent response's envelope metadata (status +
    resultCount + resultStart + resultLimit + next).  Stops
    when ``max_results`` is hit, when TC returns no resources,
    when the running ``resultStart`` >= ``resultCount``, or
    when ``max_pages`` is exhausted.
    """
    records = []
    last_meta = {"status": None, "resultCount": None, "resultStart": None, "resultLimit": None, "next": None}
    result_start = 0
    page = 0
    while page < max_pages and len(records) < max_results:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        remaining = max_results - len(records)
        limit = min(page_limit, remaining)
        if limit <= 0:
            break
        url = build_indicators_url(
            host,
            owner,
            indicator_type,
            result_start=result_start,
            result_limit=limit,
        )
        body = fetch_url(requests_module, url, access_id, secret_key)
        if body is None:
            break
        meta = extract_envelope_meta(body)
        if meta:
            last_meta = meta
        page_records = extract_data(body)
        if not page_records:
            break
        for entry in page_records:
            records.append(entry)
            if len(records) >= max_results:
                break
        result_start += len(page_records)
        total = last_meta.get("resultCount")
        if total is not None and result_start >= total:
            break
        page += 1
    return records, last_meta


def main():
    started = time.time()

    owner = validate_owner(env("EXECUTOR_CONFIG_TC_OWNER", required=True))
    if owner is None:
        log("TC_OWNER must be a non-empty string")
        sys.exit(1)
    indicator_type = validate_indicator_type(env("EXECUTOR_CONFIG_TC_INDICATOR_TYPE", required=True))
    if indicator_type is None:
        log("TC_INDICATOR_TYPE must be one of " f"{list(ALLOWED_INDICATOR_TYPES)}")
        sys.exit(1)
    host = env("TC_HOST", default=DEFAULT_HOST)
    access_id = env("TC_ACCESS_ID", required=True)
    secret_key = env("TC_SECRET_KEY", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    records, meta = fetch_indicators(
        requests,
        host,
        access_id,
        secret_key,
        owner,
        indicator_type,
    )

    vulns = []
    for entry in records:
        vuln = build_vulnerability(entry, host=host)
        if vuln is not None:
            vulns.append(vuln)

    total = meta.get("resultCount") if isinstance(meta, dict) else None
    log(
        f"Processed {len(vulns)} TC indicators "
        f"(owner={owner}, type={indicator_type}, "
        f"tc_total={total if total is not None else '?'})"
    )

    hosts_out = [build_host(vulns, owner, indicator_type, meta)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "threatconnect",
            "command": "threatconnect",
            "params": (f"owner={owner} type={indicator_type}"),
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
