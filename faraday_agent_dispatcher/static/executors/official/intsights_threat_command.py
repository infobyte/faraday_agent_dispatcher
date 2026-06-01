#!/usr/bin/env python
"""Rapid7 Threat Command (formerly IntSights) importer.

Pulls alert + threat-indicator records from the Rapid7 Threat
Command REST API (the product previously sold as IntSights;
the API still uses the legacy ``ti.insight.rapid7.com`` host
and the ``/public/v1/...`` path prefix) and emits Faraday
bulk-create JSON to stdout.  Threat Command is a commercial
external-threat-intelligence platform — analysts curate alerts
around an operator's named brand / domain / IP space and
publish IOC-level indicators tied to those alerts.

Endpoints used:
  GET {TC_HOST}/public/v1/data/alerts/alerts-list
      ?severity=Low&severity=Medium&severity=High
      &type=AttackIndication&limit=50&skip=N
      -> Paginated alert inventory under the operator's
      account.  The canonical response envelope is the
      Threat Command public-v1 shape
      ``{"content": {"alerts": [...], "remainingTotal": N,
      "totalAlerts": N}, "status": "Success"}`` (some
      regional / federated mirrors collapse the wrapper into
      ``{"alerts": [...]}`` or a bare list — we tolerate
      both).  Each alert record carries ``_id``, ``title``,
      ``type`` (AttackIndication / DataLeakage / Phishing /
      BrandSecurity / ExploitableData / VIP / ...),
      ``subType``, ``severity`` (Low / Medium / High),
      ``status``, ``foundDate``, ``updateDate``, ``assets``
      (operator-side assets the alert pivots on),
      ``details`` (free-text), ``relatedIocs`` (linked
      indicators), and ``sourceURL`` (analyst-curated URL).

  GET {TC_HOST}/public/v1/iocs/threat-indicators
      ?severity=Low&severity=Medium&severity=High
      &type=IpAddresses&limit=100&skip=N
      -> Paginated indicator inventory.  Canonical envelope
      is ``{"content": [...]}`` (a bare list of IOC records
      under ``content``) — we also accept the alert-style
      wrapper and a bare top-level list for federated
      mirrors.  Each IOC carries ``_id`` (Threat Command's
      natural key), ``value`` (the canonical IOC value),
      ``type`` (IpAddresses / Urls / Domains / Hashes),
      ``severity`` (Low / Medium / High), ``firstSeen``,
      ``lastSeen``, ``sourceFeeds`` (vendor / analyst
      sources), ``relatedAlerts`` (linked alert ids), and
      optional ``description``.

Auth: Threat Command uses HTTP Basic auth — the operator
creates an API user in the Threat Command console
(Automation -> Integrations -> API Credentials -> save the
returned ``Account ID`` + ``API Key`` pair) and pastes the
returned values into ``TC_ACCOUNT_ID`` + ``TC_API_KEY``.
The dispatcher base64-encodes ``{ACCOUNT_ID}:{API_KEY}`` and
sends the ``Authorization: Basic ...`` header on every
request.

Args:
  ``TC_ALERT_TYPE`` (mandatory) — one of the Threat Command
  alert types (``AttackIndication`` / ``DataLeakage`` /
  ``Phishing`` / ``BrandSecurity`` / ``ExploitableData`` /
  ``VIP`` / ``ReputationLeakage``) OR the special value
  ``iocs`` to switch to the threat-indicators endpoint OR
  ``all`` to pull every alert type without a server-side
  ``type`` filter.  Operator-friendly aliases (``ioc`` /
  ``indicators`` / ``threat_indicators``) map onto ``iocs``;
  ``phish`` -> ``Phishing``; ``leak`` -> ``DataLeakage``;
  ``brand`` -> ``BrandSecurity``; ``attack`` ->
  ``AttackIndication``; ``exploit`` -> ``ExploitableData``;
  ``reputation`` -> ``ReputationLeakage``.  Forwarded into
  the ``type=`` query string when the alerts endpoint is in
  effect.  Anything else is rejected client-side with a hard
  error so a typo doesn't silently pull every alert type.

  ``TC_MIN_SEVERITY`` (optional) — minimum analyst severity
  to fetch (``Low`` / ``Medium`` / ``High``).  Forwarded
  to the API as a repeated ``severity=`` query string
  parameter (Threat Command's API accepts multiple
  ``severity`` values per request) so the API itself does
  the severity-narrowing.  Blank / missing / unparseable
  input keeps every alert (the typical operational mode).
  Aliases (``critical`` -> ``High``, ``medium`` /
  ``moderate`` -> ``Medium``, ``low`` -> ``Low``) are
  normalised onto the canonical title-cased Threat Command
  severity vocabulary.

Env vars:
  ``TC_ACCOUNT_ID`` + ``TC_API_KEY`` (both mandatory) — the
  HTTP Basic credential pair issued by Threat Command at
  API-user-creation time.  The executor exits cleanly when
  either is missing.

  ``INTSIGHTS_HOST`` (optional, not in the manifest's
  declared env vars) — defaults to
  ``https://api.ti.insight.rapid7.com`` (the canonical
  Threat Command host).  Settable to a regional / dedicated
  EU/APAC tenant URL or to a self-hosted offline cache.  We
  use ``INTSIGHTS_HOST`` (not ``TC_HOST``) to avoid colliding
  with the sibling ``threatconnect`` executor which already
  claims ``TC_HOST`` for ThreatConnect-the-product.

Each alert / indicator becomes one Faraday vulnerability
under a single synthetic ``0.0.0.0`` host with hostname
``intsights-threat-command``.  Threat Command records are
brand-keyed not host-keyed — the operator's other agents
emit the host-side findings this feed is correlated against.
The vulnerability carries ``tags: ['intsights-threat-command']``
and surfaces the title + type + subType + severity + status +
related IOCs / alerts + source URL + assets in both the
description and the refs list so operators can pivot from a
Faraday finding back to the Threat Command record.

Severity bucketing — Threat Command publishes its own
explicit Low / Medium / High ladder (no proprietary numeric
score for the typical alert) so we map directly:
  - ``High``   -> high
  - ``Medium`` -> medium
  - ``Low``    -> low
Closed / dismissed alerts (status ``Closed`` or
``Acknowledged``) are floored to ``info`` regardless of
severity — Threat Command operators only close alerts after
analyst confirmation.  Records with no parseable severity
default to ``info`` — we don't synthesise a ranking Threat
Command hasn't published.

Status is always ``open`` (a Threat Command alert can be
closed in the Threat Command console but the underlying
external threat lives on; Faraday surfaces the finding as
open so the operator's remediation workflow takes over).

Resolution defaults to a type-appropriate analyst
recommendation: Phishing -> takedown via the Threat Command
takedown service; DataLeakage -> credential reset +
forensics; BrandSecurity -> trademark counsel +
domain-registrar takedown; AttackIndication -> blocklist on
perimeter + EDR; ExploitableData -> rotate exposed
secrets / keys; VIP -> notify the affected executive +
update monitoring scope; threat-indicator IOCs ->
type-appropriate blocking on the operator's perimeter /
EDR / DNS resolver.
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

DEFAULT_HOST = "https://api.ti.insight.rapid7.com"
ALERTS_PATH = "/public/v1/data/alerts/alerts-list"
IOCS_PATH = "/public/v1/iocs/threat-indicators"

# Threat Command's public-v1 alert / IOC endpoints cap each
# response at 50 / 100 records respectively; we page in those
# default sizes via ``skip`` / ``limit`` until the result set
# is exhausted, MAX_RESULTS (5000) is reached, or MAX_PAGES
# (100) is hit.  Threat Command documents a 30 req/min
# ceiling on the public-v1 surface — pacing at 0.6s between
# pages keeps a single executor invocation well under the
# ceiling.
ALERT_PAGE_LIMIT = 50
IOC_PAGE_LIMIT = 100
MAX_PAGES = 100
MAX_RESULTS = 5000
INTER_REQUEST_SLEEP = 0.6

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Canonical Threat Command alert-type vocabulary.  The
# special ``iocs`` value swaps to the threat-indicators
# endpoint; ``all`` pulls every alert type without a
# server-side ``type`` filter.
ALLOWED_ALERT_TYPES = (
    "AttackIndication",
    "DataLeakage",
    "Phishing",
    "BrandSecurity",
    "ExploitableData",
    "VIP",
    "ReputationLeakage",
)

ALERT_TYPE_ALIASES = {
    "attackindication": "AttackIndication",
    "attack": "AttackIndication",
    "attack_indication": "AttackIndication",
    "dataleakage": "DataLeakage",
    "leak": "DataLeakage",
    "data_leak": "DataLeakage",
    "data_leakage": "DataLeakage",
    "phishing": "Phishing",
    "phish": "Phishing",
    "brandsecurity": "BrandSecurity",
    "brand": "BrandSecurity",
    "brand_security": "BrandSecurity",
    "exploitabledata": "ExploitableData",
    "exploit": "ExploitableData",
    "exploitable_data": "ExploitableData",
    "vip": "VIP",
    "reputationleakage": "ReputationLeakage",
    "reputation": "ReputationLeakage",
    "reputation_leakage": "ReputationLeakage",
    "iocs": "iocs",
    "ioc": "iocs",
    "indicators": "iocs",
    "threat_indicators": "iocs",
    "threat-indicators": "iocs",
    "all": "all",
    "any": "all",
}

# Threat Command IOC types — surfaced in the IOC-mode URL as
# the optional ``type=`` filter.  We default to "all types"
# (no type filter) for the IOC mode since the operator
# already opted in via ``TC_ALERT_TYPE=iocs``.
IOC_TYPE_VOCAB = ("IpAddresses", "Urls", "Domains", "Hashes")

# Severity ladder.  Threat Command uses Low / Medium / High
# in the public-v1 surface; we accept operator-friendly
# aliases too.
ALLOWED_SEVERITIES = ("Low", "Medium", "High")
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

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3}

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")

# Threat Command's "closed" terminal states — alerts in
# these statuses are floored to ``info`` regardless of the
# published severity ladder.
CLOSED_STATUSES = {"closed", "acknowledged", "dismissed"}


def log(msg):
    print(
        f"{datetime.utcnow()} - IntSightsThreatCommand: {msg}",
        file=sys.stderr,
        flush=True,
    )


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on INTSIGHTS_HOST.

    Defaults to ``https://api.ti.insight.rapid7.com`` (the
    canonical Threat Command host) when the env override is
    missing / blank.  Whitespace is trimmed and ``https://``
    is added automatically when the operator pasted in a
    bare FQDN.
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


def validate_alert_type(value):
    """Coerce TC_ALERT_TYPE into a canonical Threat Command type.

    Returns one of the canonical alert-type names, the
    sentinel ``iocs`` (switch to the threat-indicators
    endpoint), the sentinel ``all`` (no server-side type
    filter on the alerts endpoint), or ``None`` for
    missing / blank / unknown inputs so the caller can
    hard-fail with a helpful error rather than pulling every
    alert type silently.
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    alias = ALERT_TYPE_ALIASES.get(text.lower())
    if alias is not None:
        return alias
    if text in ALLOWED_ALERT_TYPES:
        return text
    if text.lower() == "iocs":
        return "iocs"
    if text.lower() == "all":
        return "all"
    return None


def validate_min_severity(value):
    """Coerce TC_MIN_SEVERITY into a Threat Command severity label.

    Returns one of ``Low`` / ``Medium`` / ``High`` (the
    canonical Threat Command title-cased labels) or ``None``
    for missing / blank / unknown inputs (no filter — every
    alert returned by Threat Command passes through).
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
    log(f"TC_MIN_SEVERITY {value!r} is not a known severity; ignoring (no filter)")
    return None


def severities_at_or_above(min_severity):
    """Return the list of severities >= ``min_severity``.

    Threat Command's public-v1 surface accepts a repeated
    ``severity=`` query param (multiple values per request);
    we surface that as a list so a ``min_severity=Medium``
    request sends ``severity=Medium&severity=High``.
    Returns an empty list when ``min_severity`` is ``None``
    (no filter applied) so the caller emits no
    ``severity=`` parameter at all.
    """
    if min_severity is None:
        return []
    floor = SEVERITY_ORDER.get(min_severity)
    if floor is None:
        return []
    return [s for s in ALLOWED_SEVERITIES if SEVERITY_ORDER[s] >= floor]


def build_alerts_url(host, alert_type=None, min_severity=None, skip=0, limit=ALERT_PAGE_LIMIT):
    """Build the /public/v1/data/alerts/alerts-list URL."""
    base = normalize_base_url(host)
    params = [
        ("skip", int(skip)),
        ("limit", int(limit)),
    ]
    for sev in severities_at_or_above(min_severity):
        params.append(("severity", sev))
    if alert_type and alert_type not in ("all", "iocs"):
        params.append(("type", alert_type))
    return f"{base}{ALERTS_PATH}?{urlencode(params)}"


def build_iocs_url(host, min_severity=None, skip=0, limit=IOC_PAGE_LIMIT, ioc_type=None):
    """Build the /public/v1/iocs/threat-indicators URL."""
    base = normalize_base_url(host)
    params = [
        ("skip", int(skip)),
        ("limit", int(limit)),
    ]
    for sev in severities_at_or_above(min_severity):
        params.append(("severity", sev))
    if ioc_type and ioc_type in IOC_TYPE_VOCAB:
        params.append(("type", ioc_type))
    return f"{base}{IOCS_PATH}?{urlencode(params)}"


def basic_auth_header(account_id, api_key):
    """Build the HTTP Basic auth header value for Threat Command.

    Threat Command base64-encodes ``account_id:api_key`` and
    sends it as ``Authorization: Basic ...``.  Missing /
    non-string inputs are coerced to empty strings so the
    signing call never raises locally — the server can still
    reject the bad credentials with a useful 401.
    """
    aid = str(account_id or "").strip()
    key = str(api_key or "").strip()
    raw = f"{aid}:{key}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return f"Basic {encoded}"


def request_headers(account_id, api_key):
    """Build the request-header dict for a single Threat Command GET.

    ``Accept: application/json`` is always sent;
    ``Authorization: Basic ...`` is included with the
    operator-supplied credentials.
    """
    headers = {
        "Accept": "application/json",
        "Authorization": basic_auth_header(account_id, api_key),
    }
    return headers


def parse_iso_datetime(value):
    """Parse an ISO-8601 timestamp into a UTC datetime.

    Threat Command emits ``foundDate`` / ``updateDate`` /
    ``firstSeen`` / ``lastSeen`` as ``YYYY-MM-DDTHH:MM:SSZ``
    (or with a numeric offset on some federated mirrors).
    Returns ``None`` for missing / malformed inputs.
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


def extract_alerts(body):
    """Pull the alerts list from a Threat Command alerts envelope.

    Canonical envelope is ``{"content": {"alerts": [...],
    "remainingTotal": N, "totalAlerts": N}, "status":
    "Success"}``.  Some federated mirrors collapse this into
    ``{"alerts": [...]}``, ``{"content": [...]}``, or a bare
    list — all four shapes are accepted so the caller doesn't
    care about envelope drift.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    content = body.get("content")
    if isinstance(content, dict):
        for key in ("alerts", "results", "items", "data"):
            v = content.get(key)
            if isinstance(v, list):
                return [entry for entry in v if isinstance(entry, dict)]
    if isinstance(content, list):
        return [entry for entry in content if isinstance(entry, dict)]
    for key in ("alerts", "results", "items", "data"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_iocs(body):
    """Pull the IOC list from a Threat Command threat-indicators envelope.

    Canonical envelope is ``{"content": [...]}`` (a bare
    list under ``content``).  Falls back through the
    alert-style wrapper + bare-list / ``iocs`` / ``data`` /
    ``results`` / ``items`` shapes for federated-mirror
    robustness.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    content = body.get("content")
    if isinstance(content, list):
        return [entry for entry in content if isinstance(entry, dict)]
    if isinstance(content, dict):
        for key in ("iocs", "indicators", "results", "items", "data"):
            v = content.get(key)
            if isinstance(v, list):
                return [entry for entry in v if isinstance(entry, dict)]
    for key in ("iocs", "indicators", "results", "items", "data"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_envelope_meta(body):
    """Pull pagination + status metadata from a Threat Command envelope.

    Returns ``{"status": str|None, "totalAlerts": int|None,
    "remainingTotal": int|None}`` with missing fields left
    as ``None``.  Both the bare-root keys and the
    ``content.*`` nested keys are accepted.
    """
    out = {"status": None, "totalAlerts": None, "remainingTotal": None}
    if not isinstance(body, dict):
        return out
    s = body.get("status")
    if isinstance(s, str) and s.strip():
        out["status"] = s.strip()
    sources = []
    content = body.get("content")
    if isinstance(content, dict):
        sources.append(content)
    sources.append(body)
    for src in sources:
        for key in ("totalAlerts", "remainingTotal"):
            if out[key] is not None:
                continue
            v = src.get(key)
            if v is None or isinstance(v, bool):
                continue
            try:
                out[key] = int(v)
            except (TypeError, ValueError):
                out[key] = None
    return out


def extract_record_id(record):
    """Pull the canonical Threat Command record id (``_id`` or ``id``)."""
    if not isinstance(record, dict):
        return ""
    for key in ("_id", "id"):
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
    """Pull the alert / IOC display title."""
    if not isinstance(record, dict):
        return ""
    for key in ("title", "name", "value"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_severity(record):
    """Pull the canonical Threat Command severity label (or '').

    Tolerates case + whitespace + aliasing onto the
    title-cased label.  Returns ``''`` (not None) for
    missing / unknown inputs so the caller can treat
    unscored alerts as ``info`` uniformly.
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
    if text in ALLOWED_SEVERITIES:
        return text
    return ""


def extract_status(record):
    """Pull the alert status (Open / Closed / Acknowledged / ...)."""
    if not isinstance(record, dict):
        return ""
    v = record.get("status")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ""


def is_closed(record):
    """Return True when the alert is in a closed / dismissed state."""
    status = extract_status(record)
    if not status:
        return False
    return status.strip().lower() in CLOSED_STATUSES


def extract_type(record):
    """Pull the alert / IOC type string."""
    if not isinstance(record, dict):
        return ""
    for key in ("type", "alertType", "iocType"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_sub_type(record):
    """Pull the alert ``subType`` (free-text)."""
    if not isinstance(record, dict):
        return ""
    v = record.get("subType")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ""


def extract_assets(record):
    """Pull the operator-side assets the alert pivots on.

    Threat Command emits ``assets`` as a list of
    ``{"type": "Domain" | "IP" | ...,  "value": "..."}``
    dicts.  Returns a list of ``{"type": str, "value": str}``
    dicts with empty defaults; bare-string entries are
    surfaced as ``{"type": "", "value": "..."}``.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("assets")
    if not isinstance(block, list):
        return out
    for entry in block:
        if isinstance(entry, dict):
            type_raw = entry.get("type")
            value_raw = entry.get("value")
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


def extract_related_iocs(record):
    """Pull the alert's related IOC values.

    Threat Command emits ``relatedIocs`` as a list of
    ``{"type": "Hashes" | "Urls" | ..., "value": "..."}``
    dicts; bare strings are accepted too.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("relatedIocs")
    if not isinstance(block, list):
        block = record.get("iocs") if isinstance(record.get("iocs"), list) else []
    for entry in block:
        if isinstance(entry, dict):
            type_raw = entry.get("type")
            value_raw = entry.get("value")
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


def extract_related_alerts(record):
    """Pull the IOC's related alert ids (deduped)."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("relatedAlerts")
    if not isinstance(block, list):
        return out
    for entry in block:
        if isinstance(entry, str) and entry.strip():
            text = entry.strip()
        elif isinstance(entry, dict):
            rid = entry.get("_id") or entry.get("id")
            if rid is None:
                continue
            text = str(rid).strip()
        else:
            continue
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def extract_source_feeds(record):
    """Pull the IOC's source-feed names (deduped)."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("sourceFeeds")
    if not isinstance(block, list):
        return out
    for entry in block:
        name = None
        if isinstance(entry, dict):
            n = entry.get("name") or entry.get("source")
            if isinstance(n, str):
                name = n.strip()
        elif isinstance(entry, str):
            name = entry.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def extract_source_url(record):
    """Pull the analyst-curated source URL for an alert."""
    if not isinstance(record, dict):
        return ""
    for key in ("sourceURL", "sourceUrl", "source_url"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_details(record):
    """Pull the free-text analyst details for an alert."""
    if not isinstance(record, dict):
        return ""
    for key in ("details", "description", "summary"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def web_link_for_alert(host, alert_id):
    """Build the Threat Command web-UI permalink for an alert."""
    base = normalize_base_url(host)
    web = base
    # The Threat Command web UI lives at the ``ti.insight.rapid7.com``
    # host without the ``api.`` prefix.
    if "://api." in web:
        web = web.replace("://api.", "://", 1)
    if not alert_id:
        return f"{web}/main/alerts"
    return f"{web}/main/alerts/alert-details/{alert_id}"


def severity_for_record(record):
    """Final Faraday severity for a Threat Command record.

    Maps the published Low/Medium/High label onto Faraday's
    severity ladder; floors closed / dismissed alerts to
    ``info`` regardless of the ladder; defaults to ``info``
    when the record carries no parseable severity.
    """
    sev = extract_severity(record)
    if not sev:
        return "info"
    if is_closed(record):
        return "info"
    return SEVERITY_MAP.get(sev, "info")


def collect_cves(record):
    """Pull CVE ids from the alert title / details / related IOCs.

    Threat Command alerts do not carry a structured CVE
    field; analysts surface CVEs in the free-text title /
    details / related IOCs.  Returns a deduped uppercase
    list.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out

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
    harvest(extract_details(record))
    for ioc in extract_related_iocs(record):
        harvest(ioc.get("value", ""))
    for asset in extract_assets(record):
        harvest(asset.get("value", ""))
    return out


def collect_refs(record, host=None, is_ioc=False):
    """Build the refs list for one Threat Command record.

    Surfaces the record id, title, type, subType, severity,
    status, assets, related IOCs / alerts, source feeds,
    source URL, the canonical web-UI permalink, and
    timestamps so operators can pivot from a Faraday finding
    back to the Threat Command console.
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

    prefix = "Ioc" if is_ioc else "Tc"

    rid = extract_record_id(record)
    if rid:
        add(f"{prefix}-ID: {rid}")

    title = extract_title(record)
    if title:
        add(f"{prefix}-Title: {title}")

    type_text = extract_type(record)
    if type_text:
        add(f"{prefix}-Type: {type_text}")

    sub_type = extract_sub_type(record)
    if sub_type:
        add(f"{prefix}-SubType: {sub_type}")

    sev = extract_severity(record)
    if sev:
        add(f"{prefix}-Severity: {sev}")

    status = extract_status(record)
    if status:
        add(f"{prefix}-Status: {status}")

    for asset in extract_assets(record):
        atype = asset.get("type") or ""
        avalue = asset.get("value") or ""
        if atype:
            add(f"{prefix}-Asset: {atype}: {avalue}")
        else:
            add(f"{prefix}-Asset: {avalue}")

    for ioc in extract_related_iocs(record):
        itype = ioc.get("type") or ""
        ivalue = ioc.get("value") or ""
        if itype:
            add(f"{prefix}-Ioc: {itype}: {ivalue}")
        else:
            add(f"{prefix}-Ioc: {ivalue}")

    for related in extract_related_alerts(record):
        add(f"{prefix}-RelatedAlert: {related}")

    for feed in extract_source_feeds(record):
        add(f"{prefix}-SourceFeed: {feed}")

    source_url = extract_source_url(record)
    if source_url:
        add(source_url)
        add(f"{prefix}-SourceURL: {source_url}")

    for cve in collect_cves(record):
        add(f"{prefix}-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    for key, label in (
        ("foundDate", "FoundDate"),
        ("updateDate", "UpdateDate"),
        ("firstSeen", "FirstSeen"),
        ("lastSeen", "LastSeen"),
    ):
        dt = parse_iso_datetime(record.get(key))
        if dt is not None:
            add(f"{prefix}-{label}: {dt.isoformat()}")

    if not is_ioc and rid:
        add(web_link_for_alert(host, rid))

    return refs


def resolution_for_record(record, is_ioc=False):
    """Type-appropriate analyst recommendation."""
    if not isinstance(record, dict):
        return "Triage in the Threat Command console and apply " "the analyst-recommended remediation."
    type_text = extract_type(record).lower()
    if is_ioc:
        if type_text == "ipaddresses" or type_text == "ip":
            return (
                "Block this IP on the operator's perimeter "
                "firewall, egress proxy, and EDR network "
                "containment policies."
            )
        if type_text == "urls" or type_text == "url":
            return "Block this URL on the operator's egress proxy " "and endpoint web-filter policy."
        if type_text == "domains" or type_text == "domain":
            return "Sinkhole this domain on the operator's DNS " "resolver and add to the perimeter blocklist."
        if type_text == "hashes" or type_text == "hash":
            return "Block this file hash in the operator's EDR / " "AV / endpoint prevention policy."
        return "Block this indicator on the operator's perimeter " "controls per Threat Command analyst guidance."
    if type_text == "phishing":
        return (
            "Submit takedown via the Threat Command Takedown "
            "service; block the phishing URL on the operator's "
            "egress proxy and endpoint web-filter; notify the "
            "impersonated brand owners."
        )
    if type_text == "dataleakage":
        return (
            "Rotate exposed credentials, force-reset affected "
            "accounts, and notify the data-protection officer "
            "for forensic review."
        )
    if type_text == "brandsecurity":
        return "Engage trademark counsel and request domain-" "registrar takedown of the impersonating asset."
    if type_text == "attackindication":
        return (
            "Add the indicators of compromise to the operator's "
            "perimeter blocklist, EDR exclusion / containment "
            "rules, and SIEM correlation queries."
        )
    if type_text == "exploitabledata":
        return (
            "Rotate the exposed secrets / API keys and audit "
            "for unauthorised use in the corresponding service "
            "logs."
        )
    if type_text == "vip":
        return (
            "Notify the affected executive and expand monitoring "
            "scope on their digital footprint per the operator's "
            "VIP-protection playbook."
        )
    if type_text == "reputationleakage":
        return (
            "Engage corporate communications and brand counsel; " "monitor the surfaced channels for further exposure."
        )
    return "Triage in the Threat Command console and apply the " "analyst-recommended remediation."


def build_alert_vulnerability(record, host=None):
    """Build a Faraday vulnerability dict for one Threat Command alert."""
    if not isinstance(record, dict):
        return None

    title = extract_title(record)
    type_text = extract_type(record)
    if not title and not type_text:
        return None

    severity = severity_for_record(record)
    rid = extract_record_id(record)
    sev_label = extract_severity(record)
    sub_type = extract_sub_type(record)
    status = extract_status(record)

    name_parts = ["[ThreatCommand]"]
    if type_text:
        name_parts.append(type_text)
    if sub_type:
        name_parts.append(f"/ {sub_type}")
    if title:
        name_parts.append(title)
    if sev_label:
        name_parts.append(f"({sev_label})")
    name = " ".join(name_parts)

    desc_parts = []
    if rid:
        desc_parts.append(f"alertID: {rid}")
    if title:
        desc_parts.append(f"title: {title}")
    if type_text:
        desc_parts.append(f"type: {type_text}")
    if sub_type:
        desc_parts.append(f"subType: {sub_type}")
    if sev_label:
        desc_parts.append(f"severity: {sev_label}")
    if status:
        desc_parts.append(f"status: {status}")
    assets = extract_assets(record)
    if assets:
        desc_parts.append("assets: " + ", ".join(f"{a.get('type') or 'Asset'}={a.get('value')}" for a in assets[:20]))
    iocs = extract_related_iocs(record)
    if iocs:
        desc_parts.append("relatedIocs: " + ", ".join(f"{i.get('type') or 'Ioc'}={i.get('value')}" for i in iocs[:20]))
    fd = parse_iso_datetime(record.get("foundDate"))
    if fd is not None:
        desc_parts.append(f"foundDate: {fd.isoformat()}")
    ud = parse_iso_datetime(record.get("updateDate"))
    if ud is not None:
        desc_parts.append(f"updateDate: {ud.isoformat()}")
    source_url = extract_source_url(record)
    if source_url:
        desc_parts.append(f"sourceURL: {source_url}")
    details = extract_details(record)
    if details:
        desc_parts.append(f"details: {details}")

    external_id = rid or title[:200] or name
    resolution = resolution_for_record(record)

    return {
        "name": str(name).strip()[:200] or "Threat Command alert",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record, host=host, is_ioc=False),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["intsights-threat-command"],
    }


def build_ioc_vulnerability(record, host=None):
    """Build a Faraday vulnerability dict for one Threat Command IOC."""
    if not isinstance(record, dict):
        return None

    value = extract_title(record)
    type_text = extract_type(record)
    if not value and not type_text:
        return None

    severity = severity_for_record(record)
    rid = extract_record_id(record)
    sev_label = extract_severity(record)
    status = extract_status(record)

    name_parts = ["[ThreatCommand][IOC]"]
    if type_text:
        name_parts.append(type_text)
    if value:
        name_parts.append(value)
    if sev_label:
        name_parts.append(f"({sev_label})")
    name = " ".join(name_parts)

    desc_parts = []
    if rid:
        desc_parts.append(f"iocID: {rid}")
    if value:
        desc_parts.append(f"value: {value}")
    if type_text:
        desc_parts.append(f"type: {type_text}")
    if sev_label:
        desc_parts.append(f"severity: {sev_label}")
    if status:
        desc_parts.append(f"status: {status}")
    feeds = extract_source_feeds(record)
    if feeds:
        desc_parts.append("sourceFeeds: " + ", ".join(feeds[:20]))
    related = extract_related_alerts(record)
    if related:
        desc_parts.append("relatedAlerts: " + ", ".join(related[:20]))
    fs = parse_iso_datetime(record.get("firstSeen"))
    if fs is not None:
        desc_parts.append(f"firstSeen: {fs.isoformat()}")
    ls = parse_iso_datetime(record.get("lastSeen"))
    if ls is not None:
        desc_parts.append(f"lastSeen: {ls.isoformat()}")
    details = extract_details(record)
    if details:
        desc_parts.append(f"description: {details}")

    external_id = rid or value[:200] or name
    resolution = resolution_for_record(record, is_ioc=True)

    return {
        "name": str(name).strip()[:200] or "Threat Command indicator",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record, host=host, is_ioc=True),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["intsights-threat-command"],
    }


def build_host(vulns, mode, alert_type, min_severity, meta):
    """Build the single synthetic host that carries every TC vuln."""
    desc_parts = ["source=intsights-threat-command", f"mode={mode}"]
    if alert_type:
        desc_parts.append(f"type={alert_type}")
    if min_severity:
        desc_parts.append(f"min_severity={min_severity}")
    if isinstance(meta, dict):
        total = meta.get("totalAlerts")
        if total is not None:
            desc_parts.append(f"tc_total={total}")
        status = meta.get("status")
        if status:
            desc_parts.append(f"tc_status={status}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["intsights-threat-command"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url, account_id, api_key):
    """GET a single Threat Command URL with HTTP Basic auth.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient Threat Command outage doesn't
    crash the dispatcher.  Returns ``None`` on any failure.
    """
    try:
        resp = requests_module.get(
            url,
            timeout=TIMEOUT,
            headers=request_headers(account_id, api_key),
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"Threat Command record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"Threat Command request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"Threat Command response was not JSON ({url})")
        return None


def fetch_alerts(
    requests_module,
    host,
    account_id,
    api_key,
    alert_type,
    min_severity,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    page_limit=ALERT_PAGE_LIMIT,
    max_results=MAX_RESULTS,
):
    """Page through /public/v1/data/alerts/alerts-list."""
    records = []
    last_meta = {"status": None, "totalAlerts": None, "remainingTotal": None}
    skip = 0
    page = 0
    while page < max_pages and len(records) < max_results:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        remaining = max_results - len(records)
        limit = min(page_limit, remaining)
        if limit <= 0:
            break
        url = build_alerts_url(
            host,
            alert_type=alert_type,
            min_severity=min_severity,
            skip=skip,
            limit=limit,
        )
        body = fetch_url(requests_module, url, account_id, api_key)
        if body is None:
            break
        meta = extract_envelope_meta(body)
        if meta:
            last_meta = meta
        page_records = extract_alerts(body)
        if not page_records:
            break
        for entry in page_records:
            records.append(entry)
            if len(records) >= max_results:
                break
        skip += len(page_records)
        total = last_meta.get("totalAlerts")
        if total is not None and skip >= total:
            break
        remaining_total = last_meta.get("remainingTotal")
        if remaining_total is not None and remaining_total <= 0:
            break
        page += 1
    return records, last_meta


def fetch_iocs(
    requests_module,
    host,
    account_id,
    api_key,
    min_severity,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    page_limit=IOC_PAGE_LIMIT,
    max_results=MAX_RESULTS,
):
    """Page through /public/v1/iocs/threat-indicators."""
    records = []
    last_meta = {"status": None, "totalAlerts": None, "remainingTotal": None}
    skip = 0
    page = 0
    while page < max_pages and len(records) < max_results:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        remaining = max_results - len(records)
        limit = min(page_limit, remaining)
        if limit <= 0:
            break
        url = build_iocs_url(
            host,
            min_severity=min_severity,
            skip=skip,
            limit=limit,
        )
        body = fetch_url(requests_module, url, account_id, api_key)
        if body is None:
            break
        meta = extract_envelope_meta(body)
        if meta:
            last_meta = meta
        page_records = extract_iocs(body)
        if not page_records:
            break
        for entry in page_records:
            records.append(entry)
            if len(records) >= max_results:
                break
        skip += len(page_records)
        page += 1
    return records, last_meta


def main():
    started = time.time()

    alert_type = validate_alert_type(env("EXECUTOR_CONFIG_TC_ALERT_TYPE", required=True))
    if alert_type is None:
        log("TC_ALERT_TYPE must be one of " f"{list(ALLOWED_ALERT_TYPES)} (or 'iocs' / 'all')")
        sys.exit(1)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_TC_MIN_SEVERITY"))
    host = env("INTSIGHTS_HOST", default=DEFAULT_HOST)
    account_id = env("TC_ACCOUNT_ID", required=True)
    api_key = env("TC_API_KEY", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    if alert_type == "iocs":
        mode = "iocs"
        records, meta = fetch_iocs(
            requests,
            host,
            account_id,
            api_key,
            min_severity,
        )
        vulns = []
        for entry in records:
            vuln = build_ioc_vulnerability(entry, host=host)
            if vuln is not None:
                vulns.append(vuln)
    else:
        mode = "alerts"
        records, meta = fetch_alerts(
            requests,
            host,
            account_id,
            api_key,
            alert_type,
            min_severity,
        )
        vulns = []
        for entry in records:
            vuln = build_alert_vulnerability(entry, host=host)
            if vuln is not None:
                vulns.append(vuln)

    total = meta.get("totalAlerts") if isinstance(meta, dict) else None
    log(
        f"Processed {len(vulns)} Threat Command records "
        f"(mode={mode}, type={alert_type}, "
        f"min_severity={min_severity or 'none'}, "
        f"tc_total={total if total is not None else '?'})"
    )

    hosts_out = [build_host(vulns, mode, alert_type, min_severity, meta)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "intsights_threat_command",
            "command": "intsights_threat_command",
            "params": (f"mode={mode} type={alert_type} " f"min_severity={min_severity or ''}"),
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
