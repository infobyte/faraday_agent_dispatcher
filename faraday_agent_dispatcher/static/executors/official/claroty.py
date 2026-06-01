#!/usr/bin/env python
"""Claroty Continuous Threat Detection (CTD) OT asset + alert importer.

Pulls device inventory and security alerts from a Claroty
Continuous Threat Detection appliance via its v1 REST API
and emits Faraday bulk-create JSON to stdout.  Claroty CTD
is a passive OT / ICS network-monitoring appliance — it
fingerprints industrial endpoints (PLCs, RTUs, HMIs,
historians, jump hosts, IT-side endpoints that touch the
OT segment) from mirrored / SPAN traffic and surfaces both
the resulting asset inventory and rule-based / anomaly
alerts via a REST surface.  This executor surfaces both
streams under the operator's existing Faraday workspace so
the OT-side findings join the dispatcher's IT-side scanner
output.

Endpoints used:
  POST {CLAROTY_HOST}/api/v1/auth/login
      -> Exchanges ``{CLAROTY_USER, CLAROTY_PASSWORD}`` for
      a session token.  Canonical response envelope is
      ``{"token": "..."}`` (Claroty's documented v1
      shape); federated / on-prem mirrors also expose
      ``{"access_token": "..."}`` and ``{"key": "..."}``
      — all three are tolerated by ``extract_token``.

  GET {CLAROTY_HOST}/api/v1/assets?site_id=<id>&page=N&page_size=M
      -> Paginated OT asset inventory.  The canonical
      envelope is ``{"objects": [...], "count": N, "next":
      "...", "previous": "..."}``; federated mirrors
      collapse this into bare lists or
      ``{"results": [...]}`` / ``{"data": [...]}`` /
      ``{"items": [...]}`` / ``{"assets": [...]}`` — all
      shapes are accepted.  Each record carries ``id``,
      ``name``, ``ip``, ``mac``, ``vendor``, ``model``,
      ``firmware``, ``os``, ``asset_type`` / ``type``,
      ``criticality`` (informational / low / medium /
      high / critical, sometimes 0..4 numeric),
      ``site_id`` / ``site_name``, ``first_seen`` /
      ``last_seen``, ``risk_score`` (0..100), and an
      optional ``cve_list`` / ``vulnerabilities`` list of
      attributed CVE strings.

  GET {CLAROTY_HOST}/api/v1/alerts?site_id=<id>&page=N&page_size=M
      -> Paginated security alert feed.  Same envelope
      shape; each record carries ``id``, ``name`` /
      ``title``, ``description``, ``severity``
      (``Critical`` / ``High`` / ``Medium`` / ``Low`` /
      ``Info``, or 0..10 numeric on some firmwares),
      ``category`` (``Configuration Changes`` /
      ``Known Threats`` / ``Policy Violations`` /
      ``Anomalies`` — Claroty's published alert
      taxonomy), ``status`` (``Open`` / ``Resolved`` /
      ``Muted``), ``created_at`` / ``updated_at``,
      ``site_id`` / ``site_name``, and ``related_assets``
      (list of asset ids or scalar ip strings the alert
      is keyed on).

Auth: Claroty CTD's v1 surface uses a session-token flow.
The dispatcher POSTs ``{"username": CLAROTY_USER,
"password": CLAROTY_PASSWORD}`` to ``/api/v1/auth/login``
and receives a session token, which is then sent as
``Authorization: Bearer <token>`` on every subsequent
``/api/v1/`` request.  Claroty also supports HTTP Basic
auth as a fallback for headless integrations but the
dispatcher unconditionally uses the token path so a stale
basic-auth credential can't silently authorise a request.

Args:
  ``CLAROTY_SITE_ID`` (optional) — server-side site
  predicate forwarded as ``site_id=<value>`` on both
  ``/api/v1/assets`` and ``/api/v1/alerts``.  Empty /
  missing walks the entire appliance's inventory across
  every site (the operator's token scope still applies).
  Whitespace is trimmed.  Useful for sharding inventory
  pulls across multiple discovery profiles so each
  dispatcher agent only walks one OT site's worth of
  inventory per run.

  ``CLAROTY_MIN_SEVERITY`` (optional) — Faraday severity
  floor (case-insensitive ``info`` / ``low`` / ``medium``
  / ``high`` / ``critical``).  Records whose mapped
  severity is strictly below the floor are dropped
  client-side after the fetch.  Operator-friendly
  aliases (``informational`` -> ``info``, ``moderate`` ->
  ``medium``, ``crit`` -> ``critical``) are normalised.
  Asset records (no severity of their own) are bucketed
  from the ``criticality`` field; alerts use the
  published ``severity`` field directly.  Blank /
  missing input keeps every record.

Env vars:
  ``CLAROTY_HOST`` (mandatory) — the appliance base URL
  (e.g.  ``https://ctd.acme.lan``).  Claroty CTD is an
  on-prem appliance so there is no global default — the
  executor exits cleanly when ``CLAROTY_HOST`` is
  missing.  Whitespace is trimmed; ``https://`` is added
  when the operator pasted in a bare FQDN.

  ``CLAROTY_USER`` + ``CLAROTY_PASSWORD`` (both
  mandatory) — the appliance portal credentials.
  Forwarded only to ``/api/v1/auth/login`` for the
  initial token exchange; the password never leaves the
  dispatcher's process memory after the token is
  returned.

Each Claroty record becomes one Faraday host.  Asset
records project ``ip`` onto ``host.ip`` (loopback /
0.0.0.0 / ::1 are skipped, falling back to the ``0.0.0.0``
sentinel when no usable IP is present), ``name`` onto
``host.hostnames``, ``mac`` onto ``host.mac``, and the
``vendor`` / ``model`` / ``firmware`` / ``os`` chain
joins onto ``host.os``.  The asset itself becomes one
Faraday vulnerability with the ``[ASSET-INVENTORY]``
engine prefix.  Alert records are keyed on the first
``related_assets`` IP (falling back to the alert's own
``src_ip`` / ``dst_ip`` / ``ip`` field, then the
``0.0.0.0`` sentinel for policy-shaped alerts not keyed
on any single asset).

Severity bucketing:
  - Assets: ``criticality`` is the canonical
    ``critical`` / ``high`` / ``medium`` / ``low`` /
    ``info`` label (or 0..4 / 0..10 numeric ladder).
    Missing / unparseable -> ``info``.
  - Alerts: ``severity`` is the canonical label or 0..10
    numeric; the alert ``risk_score`` is used as a
    fallback when only a numeric score is published.

Tags: ``[claroty, ot-security, asset|alert]``.  Status is
always ``open`` (Claroty's terminal ``Resolved`` /
``Muted`` states are preserved via the info-severity
floor + an explicit ``Claroty-Status`` pivot in the refs).
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

LOGIN_PATH = "/api/v1/auth/login"
ASSETS_PATH = "/api/v1/assets"
ALERTS_PATH = "/api/v1/alerts"

DEFAULT_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 500
DEFAULT_PAGES = 10
MAX_PAGES = 100
INTER_REQUEST_SLEEP = 0.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(ALLOWED_SEVERITIES)}

# Claroty's published label vocabulary covers Critical /
# High / Medium / Low / Info / Informational on both the
# alert ``severity`` and the asset ``criticality`` fields.
# Operator-friendly aliases are normalised to Faraday's
# canonical lowercase ladder.
SEVERITY_ALIASES = {
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "high": "high",
    "elevated": "high",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
}

# Numeric 0..4 criticality ladder surfaced by some Claroty
# firmwares (Critical=4 .. Info=0).
CRITICALITY_NUMERIC_ALIASES = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# Claroty alert terminal states — preserved via an
# explicit Claroty-Status pivot ref but floored to ``info``
# severity (the alert is no longer live).
CLOSED_ALERT_STATES = {
    "resolved",
    "closed",
    "muted",
    "suppressed",
    "dismissed",
    "false-positive",
    "false_positive",
    "falsepositive",
}


def log(msg):
    print(f"{datetime.utcnow()} - Claroty: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on CLAROTY_HOST.

    Claroty CTD is an on-prem appliance (every install
    runs on a unique hostname) so there is no global
    default — empty / missing / non-string inputs return
    ``""`` (the caller hard-fails with a helpful error).
    Whitespace is trimmed and ``https://`` is added when
    the operator pasted in a bare FQDN.
    """
    if not host or not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_site_id(value):
    """Validate CLAROTY_SITE_ID (operator-supplied site predicate).

    None / blank -> ``""`` (no site narrowing; walk the
    full appliance).  Whitespace is trimmed.  Forwarded
    verbatim as the ``site_id=<value>`` query parameter on
    both surfaces — Claroty accepts both numeric site ids
    and the literal site name in the slot depending on
    appliance configuration.
    """
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip()


def normalize_severity_label(value):
    """Coerce a Claroty severity / criticality label to Faraday's ladder.

    Returns ``None`` for missing / non-string / unknown
    inputs so the caller can fall back to numeric
    bucketing.
    """
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    return SEVERITY_ALIASES.get(text)


def parse_min_severity(value):
    """Parse CLAROTY_MIN_SEVERITY into a canonical Faraday severity.

    Accepts the canonical labels + the operator-friendly
    aliases (``informational`` / ``moderate`` / ``crit`` /
    ``elevated`` / ``severe`` / ``none``).  Returns
    ``None`` for missing / blank / unparseable inputs so
    the caller treats the run as 'keep every record'.
    """
    return normalize_severity_label(value)


def severity_from_alert(value):
    """Bucket Faraday severity from a Claroty alert ``severity`` value.

    Accepts labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Info``) or 0..10 numeric
    score (some Claroty firmwares emit a raw risk score).
    Returns ``"info"`` for missing / unparseable inputs.
    """
    label = normalize_severity_label(value) if isinstance(value, str) else None
    if label is not None:
        return label
    if isinstance(value, bool) or value is None:
        return "info"
    try:
        if isinstance(value, str):
            num = float(value.strip())
        else:
            num = float(value)
    except (TypeError, ValueError):
        return "info"
    if num != num:  # NaN
        return "info"
    if num < 0:
        return "info"
    if num >= 9.0:
        return "critical"
    if num >= 7.0:
        return "high"
    if num >= 4.0:
        return "medium"
    if num > 0.0:
        return "low"
    return "info"


def severity_from_criticality(value):
    """Bucket Faraday severity from a Claroty asset ``criticality`` value.

    Accepts the labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Info``) and the numeric 0..4
    form (4=critical .. 0=info).  Falls back to the 0..10
    bucketing for federated mirrors that surface
    criticality as a raw score.  Missing / unparseable
    inputs default to ``info``.
    """
    label = normalize_severity_label(value) if isinstance(value, str) else None
    if label is not None:
        return label
    if isinstance(value, bool) or value is None:
        return "info"
    try:
        if isinstance(value, str):
            num = float(value.strip())
        else:
            num = float(value)
    except (TypeError, ValueError):
        return "info"
    if num != num:  # NaN
        return "info"
    if num < 0:
        return "info"
    int_val = int(num) if num == int(num) else None
    if int_val is not None and int_val in CRITICALITY_NUMERIC_ALIASES:
        return CRITICALITY_NUMERIC_ALIASES[int_val]
    return severity_from_alert(num)


def severity_meets_threshold(severity, min_severity):
    """True when ``severity`` >= ``min_severity`` in Faraday's ladder.

    ``min_severity is None`` keeps every record.  Unknown
    severity strings are dropped when a threshold is set
    (conservative — we cannot prove the record meets the
    bar).
    """
    if min_severity is None:
        return True
    if severity not in SEVERITY_ORDER or min_severity not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[min_severity]


def is_closed_alert(value):
    """True when a Claroty alert ``status`` is terminally closed."""
    if not isinstance(value, str):
        return False
    return value.strip().lower() in CLOSED_ALERT_STATES


def build_login_url(host):
    return f"{normalize_base_url(host)}{LOGIN_PATH}"


def build_assets_url(host):
    return f"{normalize_base_url(host)}{ASSETS_PATH}"


def build_alerts_url(host):
    return f"{normalize_base_url(host)}{ALERTS_PATH}"


def build_query(page, page_size=DEFAULT_PAGE_SIZE, site_id=""):
    """Build the canonical Claroty paging query string.

    Claroty's v1 surface uses one-based ``page=N`` +
    ``page_size=M`` pagination.  ``site_id`` is forwarded
    verbatim when non-empty.  Bad inputs are coerced to
    safe defaults so a typo never crashes the dispatcher.
    """
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
    if site_id:
        text = str(site_id).strip()
        if text:
            params.append(("site_id", text))
    return urlencode(params)


def login_payload(username, password):
    """Build the JSON body for the /api/v1/auth/login token exchange.

    Claroty follows the documented v1 contract:
    ``{"username": "...", "password": "..."}``.  None /
    non-string inputs are coerced to empty strings so the
    server can return a useful 400.
    """
    u = username.strip() if isinstance(username, str) else ""
    p = password if isinstance(password, str) else ""
    return {"username": u, "password": p}


def login_headers():
    """Build the request-header dict for the login POST."""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def request_headers(token):
    """Build the request-header dict for a credentialed GET.

    Claroty v1 documents ``Authorization: Bearer <token>``
    for the session-token flow.  Missing / blank tokens
    are coerced to an empty string and the
    ``Authorization`` header is omitted entirely (so a
    misconfigured token surfaces as an explicit 401 rather
    than as an empty-header request that some Claroty
    middleware silently accepts).
    """
    token_str = ""
    if isinstance(token, str):
        token_str = token.strip()
    elif token not in (None, False, True):
        token_str = str(token).strip()
    headers = {"Accept": "application/json"}
    if token_str:
        headers["Authorization"] = f"Bearer {token_str}"
    return headers


def extract_token(body):
    """Pull the session token from a Claroty login response.

    Canonical envelope is ``{"token": "..."}``; federated
    mirrors also expose ``{"access_token": "..."}`` and
    ``{"key": "..."}``.  Returns ``""`` for missing /
    non-dict / non-string inputs so the caller can
    hard-fail.
    """
    if not isinstance(body, dict):
        return ""
    for key in ("token", "access_token", "key", "session_token", "auth_token"):
        v = body.get(key)
        if isinstance(v, str):
            text = v.strip()
            if text:
                return text
    return ""


def extract_records(body):
    """Pull the record list from a Claroty v1 response envelope.

    Canonical envelope wraps the record list under
    ``objects`` (Claroty's documented v1 shape).
    Federated / mirror stacks also expose bare-list /
    ``results`` / ``data`` / ``items`` / ``assets`` /
    ``alerts`` — all shapes are tolerated.  Non-dict
    entries are silently dropped.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("objects", "results", "data", "items", "assets", "alerts"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def asset_ip(asset):
    """Pick the asset's primary IP (skipping loopback / zero).

    Claroty exposes the primary IP via ``ip``; federated
    shapes also surface ``ip_address`` / ``primary_ip`` /
    a list under ``ips``.  Falls back to the ``0.0.0.0``
    sentinel when nothing usable is present.
    """
    if not isinstance(asset, dict):
        return "0.0.0.0"
    candidates = []
    for key in ("ip", "ip_address", "primary_ip"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            candidates.append(v.strip())
    for key in ("ips", "ip_addresses"):
        v = asset.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    candidates.append(entry.strip())
                elif isinstance(entry, dict):
                    addr = entry.get("ip") or entry.get("address") or entry.get("value")
                    if isinstance(addr, str) and addr.strip():
                        candidates.append(addr.strip())
    for ip in candidates:
        if ip not in ("0.0.0.0", "127.0.0.1", "::1"):
            return ip
    return "0.0.0.0"


def asset_hostnames(asset):
    """Collect hostname candidates for a Claroty asset."""
    if not isinstance(asset, dict):
        return []
    out = []
    seen = set()
    for key in ("name", "hostname", "host_name", "fqdn", "label"):
        v = asset.get(key)
        if isinstance(v, str):
            s = v.strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    return out


def asset_mac(asset):
    if not isinstance(asset, dict):
        return ""
    for key in ("mac", "mac_address"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def asset_os(asset):
    """Build the ``host.os`` string from Claroty's asset fields."""
    if not isinstance(asset, dict):
        return ""
    bits = []
    for key in ("vendor", "manufacturer"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
            break
    for key in ("model",):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
    for key in ("os", "operating_system"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
            break
    for key in ("firmware", "firmware_version"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(f"firmware={v.strip()}")
            break
    return " ".join(bits)


def alert_ip(alert):
    """Pick the alert's keyed IP (from related_assets / src_ip / dst_ip)."""
    if not isinstance(alert, dict):
        return "0.0.0.0"
    related = alert.get("related_assets") or alert.get("relatedAssets")
    if isinstance(related, list):
        for entry in related:
            if isinstance(entry, str) and entry.strip():
                s = entry.strip()
                if s not in ("0.0.0.0", "127.0.0.1", "::1"):
                    return s
            elif isinstance(entry, dict):
                for key in ("ip", "ip_address", "primary_ip", "value"):
                    v = entry.get(key)
                    if isinstance(v, str) and v.strip():
                        s = v.strip()
                        if s not in ("0.0.0.0", "127.0.0.1", "::1"):
                            return s
    for key in ("src_ip", "source_ip", "dst_ip", "destination_ip", "ip"):
        v = alert.get(key)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            if s not in ("0.0.0.0", "127.0.0.1", "::1"):
                return s
    return "0.0.0.0"


def collect_cves(record):
    """Walk a Claroty record for CVE ids.

    Claroty surfaces CVE attribution on assets via
    ``cve_list`` / ``vulnerabilities`` (list of CVE
    strings or dicts) and embeds CVE refs in alert
    descriptions / titles.  All occurrences are
    deduplicated and uppercased to NVD's canonical form.
    """
    out = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if CVE_RE.fullmatch(s) and s not in seen:
            seen.add(s)
            out.append(s)

    def scan(text):
        if not isinstance(text, str):
            return
        for m in CVE_RE.findall(text):
            add(m)

    if not isinstance(record, dict):
        return out

    for key in ("cve_list", "cves", "vulnerabilities", "vulnerability_list"):
        raw = record.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("id"))

    for key in ("name", "title", "description", "summary"):
        scan(record.get(key))

    return out


def collect_refs(record, entity_type):
    """Build the refs list for a Claroty asset / alert record."""
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

    if not isinstance(record, dict):
        return refs

    rec_id = record.get("id") or record.get("uuid")
    if rec_id is not None and str(rec_id).strip():
        if entity_type == "asset":
            add(f"Claroty-AssetID: {str(rec_id).strip()}")
        else:
            add(f"Claroty-AlertID: {str(rec_id).strip()}")

    site_name = record.get("site_name") or record.get("siteName")
    site_id = record.get("site_id") or record.get("siteId")
    if isinstance(site_name, str) and site_name.strip():
        add(f"Claroty-Site: {site_name.strip()}")
    elif site_id is not None and str(site_id).strip():
        add(f"Claroty-Site: {str(site_id).strip()}")

    if entity_type == "asset":
        for key, label in (
            ("asset_type", "Claroty-Type"),
            ("type", "Claroty-Type"),
            ("criticality", "Claroty-Criticality"),
            ("vendor", "Claroty-Vendor"),
            ("model", "Claroty-Model"),
            ("firmware", "Claroty-Firmware"),
            ("risk_score", "Claroty-RiskScore"),
            ("first_seen", "Claroty-FirstSeen"),
            ("last_seen", "Claroty-LastSeen"),
        ):
            v = record.get(key)
            if v in (None, ""):
                continue
            add(f"{label}: {v}")
    else:
        for key, label in (
            ("severity", "Claroty-Severity"),
            ("category", "Claroty-Category"),
            ("status", "Claroty-Status"),
            ("risk_score", "Claroty-RiskScore"),
            ("created_at", "Claroty-CreatedAt"),
            ("updated_at", "Claroty-UpdatedAt"),
        ):
            v = record.get(key)
            if v in (None, ""):
                continue
            add(f"{label}: {v}")

    for cve in collect_cves(record):
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    return refs


def _serialise(value):
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def build_asset_vulnerability(asset, site_id, min_severity=None):
    """Build a Faraday vulnerability dict for one Claroty asset.

    Returns ``None`` when the asset's mapped severity is
    below ``min_severity``.  The asset is surfaced as a
    Faraday vulnerability with the ``[ASSET-INVENTORY]``
    engine prefix so OT inventory entries land alongside
    the other CMDB-class feeds (Armis, Axonius, Device42).
    """
    if not isinstance(asset, dict):
        return None
    severity = severity_from_criticality(asset.get("criticality"))
    if not severity_meets_threshold(severity, min_severity):
        return None

    hostnames = asset_hostnames(asset)
    primary = hostnames[0] if hostnames else (asset_ip(asset) if asset_ip(asset) != "0.0.0.0" else "unknown asset")
    name = f"[ASSET-INVENTORY] Claroty asset: {primary}"

    desc_parts = []
    for key in sorted(asset.keys()):
        v = asset.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if site_id:
        desc_parts.append(f"claroty_site_id: {site_id}")

    asset_id = str(asset.get("id") or asset.get("uuid") or name)

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"asset::{asset_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Claroty CTD asset records are OT inventory entries — "
            "cross-check the asset against the operator's other "
            "agents (EDR / vuln scanners / EASM) for live exposures, "
            "and verify the device's segmentation against the Purdue "
            "model in the Claroty console.  Decommission or merge "
            "the asset in Claroty if it should no longer appear in "
            "the inventory."
        ),
        "data": "",
        "refs": collect_refs(asset, "asset"),
        "cve": collect_cves(asset),
        "cwe": [],
        "cvss3": {},
        "tags": ["claroty", "ot-security", "asset"],
    }


def build_alert_vulnerability(alert, site_id, min_severity=None):
    """Build a Faraday vulnerability dict for one Claroty alert.

    Returns ``None`` when the alert's mapped severity is
    below ``min_severity``.  Terminal Claroty states
    (``Resolved`` / ``Muted`` / ``Suppressed`` /
    ``Dismissed``) floor the severity to ``info``
    regardless of the published bucket.
    """
    if not isinstance(alert, dict):
        return None
    status = alert.get("status") if isinstance(alert.get("status"), str) else None
    severity_val = alert.get("severity")
    if severity_val is None:
        severity_val = alert.get("risk_score")
    severity = severity_from_alert(severity_val)
    if is_closed_alert(status):
        severity = "info"
    if not severity_meets_threshold(severity, min_severity):
        return None

    title = alert.get("name") or alert.get("title") or alert.get("id") or "Claroty alert"
    name = f"[Claroty Alert] {str(title).strip()}"

    desc_parts = []
    description = alert.get("description") or alert.get("summary") or ""
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    for key in sorted(alert.keys()):
        if key in ("description", "summary"):
            continue
        v = alert.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if site_id:
        desc_parts.append(f"claroty_site_id: {site_id}")

    alert_id = str(alert.get("id") or alert.get("uuid") or name)

    if is_closed_alert(status):
        resolution = (
            f"Claroty has marked this alert as {status}; verify the "
            "underlying condition is resolved on the affected OT "
            "asset before closing the Faraday finding."
        )
    else:
        resolution = (
            "Triage this Claroty CTD alert in the Claroty console, "
            "correlate against the related_assets list to identify "
            "the affected OT device, and apply mitigations per the "
            "operator's incident-response runbook for the alert "
            "category (Configuration Change / Known Threat / Policy "
            "Violation / Anomaly)."
        )

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"alert::{alert_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(alert, "alert"),
        "cve": collect_cves(alert),
        "cwe": [],
        "cvss3": {},
        "tags": ["claroty", "ot-security", "alert"],
    }


def build_host_from_asset(asset, site_id, min_severity=None):
    """Build a Faraday host dict from a Claroty asset record."""
    if not isinstance(asset, dict):
        return None
    vuln = build_asset_vulnerability(asset, site_id, min_severity)
    if vuln is None:
        return None
    desc_parts = []
    for key in (
        "asset_type",
        "type",
        "vendor",
        "model",
        "firmware",
        "site_name",
        "criticality",
        "risk_score",
        "first_seen",
        "last_seen",
    ):
        v = asset.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}={_serialise(v)}")
    return {
        "ip": asset_ip(asset),
        "os": asset_os(asset),
        "hostnames": asset_hostnames(asset),
        "mac": asset_mac(asset),
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln],
    }


def build_host_from_alert(alert, site_id, min_severity=None):
    """Build a Faraday host dict from a Claroty alert record."""
    if not isinstance(alert, dict):
        return None
    vuln = build_alert_vulnerability(alert, site_id, min_severity)
    if vuln is None:
        return None
    hostnames = []
    title = alert.get("name") or alert.get("title")
    if isinstance(title, str) and title.strip():
        hostnames.append(title.strip())
    return {
        "ip": alert_ip(alert),
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Claroty CTD alert",
        "vulnerabilities": [vuln],
    }


def fetch_token(requests_module, host, username, password):
    """Exchange Claroty credentials for a session Bearer token."""
    url = build_login_url(host)
    body = json.dumps(login_payload(username, password))
    try:
        resp = requests_module.post(url, data=body, headers=login_headers(), timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"login POST {url} failed: {exc}")
        return ""
    if resp.status_code in (401, 403):
        log(f"Claroty login rejected ({resp.status_code}); check CLAROTY_USER / CLAROTY_PASSWORD")
        return ""
    if resp.status_code >= 400:
        log(f"Claroty login failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return ""
    try:
        payload = resp.json()
    except ValueError:
        log(f"Claroty login response was not JSON ({url})")
        return ""
    token = extract_token(payload)
    if not token:
        log("Claroty login response had no session token")
    return token


def fetch_pages(requests_module, url, headers, site_id, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk a Claroty v1 paginated surface.

    Pagination is one-based via ``page=N`` + ``page_size=M``.
    Walks until either ``len(records) < page_size`` or
    ``max_pages`` is reached.  401 short-circuits the whole
    executor (token is wrong); 403 / 429 / 5xx stop
    pagination on this surface and return what we have.
    """
    out = []
    page = 1
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(page, page_size=page_size, site_id=site_id)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Claroty request rejected (401); session token expired or invalid.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Claroty request rejected (403); check the token's scope.")
            return out
        if resp.status_code == 429:
            log("Claroty rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Claroty request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Claroty response was not JSON ({full_url})")
            return out
        records = extract_records(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < page_size:
            break
        page += 1
    if walked >= max_pages and len(records) >= page_size:
        log(f"hit CLAROTY_PAGES={max_pages}; stopping pagination")
    return out


def validate_pages(value):
    """Coerce CLAROTY_PAGES into a clamped integer.

    Env-only knob (not a manifest argument).  Defaults to
    ``DEFAULT_PAGES`` (10) when missing / blank /
    unparseable.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into thousands of
    requests against the appliance.
    """
    if value is None or value == "" or isinstance(value, bool):
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        return MAX_PAGES
    return n


def main():
    started = time.time()

    site_id = validate_site_id(env("EXECUTOR_CONFIG_CLAROTY_SITE_ID"))
    min_severity = parse_min_severity(env("EXECUTOR_CONFIG_CLAROTY_MIN_SEVERITY"))
    pages = validate_pages(env("CLAROTY_PAGES"))

    host = env("CLAROTY_HOST", required=True)
    username = env("CLAROTY_USER", required=True)
    password = env("CLAROTY_PASSWORD", required=True)

    if not normalize_base_url(host):
        log("CLAROTY_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_token(requests, host, username, password)
    if not token:
        log("Could not obtain Claroty session token; aborting")
        sys.exit(1)

    headers = request_headers(token)

    assets = fetch_pages(requests, build_assets_url(host), headers, site_id, max_pages=pages)
    log(f"Claroty discovered {len(assets)} assets (site_id={site_id!r})")
    time.sleep(INTER_REQUEST_SLEEP)
    alerts = fetch_pages(requests, build_alerts_url(host), headers, site_id, max_pages=pages)
    log(f"Claroty discovered {len(alerts)} alerts (site_id={site_id!r})")

    hosts_out = []
    for record in assets:
        built = build_host_from_asset(record, site_id, min_severity)
        if built is not None:
            hosts_out.append(built)
    for record in alerts:
        built = build_host_from_alert(record, site_id, min_severity)
        if built is not None:
            hosts_out.append(built)

    log(
        f"Processed {len(hosts_out)} Claroty hosts "
        f"(assets={len(assets)}, alerts={len(alerts)}, "
        f"min_severity={min_severity or '(none)'})"
    )

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "claroty",
            "command": "claroty",
            "params": (
                f"site_id={site_id} "
                f"min_severity={min_severity or ''} "
                f"assets={len(assets)} "
                f"alerts={len(alerts)} "
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
