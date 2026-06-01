#!/usr/bin/env python
"""Nozomi Networks Guardian / CMC OT asset + alert + vulnerability importer.

Pulls device inventory, security alerts, and CVE-attributed
vulnerability findings from a Nozomi Networks Guardian
appliance (or a federated Central Management Console / CMC
fan-out) via its Open Query REST API and emits Faraday
bulk-create JSON to stdout.  Nozomi Guardian is a passive
OT / ICS network-monitoring platform — it fingerprints
industrial endpoints (PLCs, RTUs, HMIs, historians, jump
hosts, IT-side endpoints that touch the OT segment) from
mirrored / SPAN traffic and surfaces the resulting asset
inventory, rule-based / anomaly alerts, and CVE-attributed
vulnerability findings via a single Open Query REST surface
keyed on a Nozomi-specific query language (``assets`` /
``alerts`` / ``vulnerabilities`` — each appended with the
``| head N | skip M`` pagination operators).

Endpoints used:
  GET {NOZOMI_HOST}/api/open/query/do?query=assets | head N | skip M
      -> Paginated OT asset inventory.  The canonical
      envelope is ``{"result": [...], "total": N}`` (Nozomi
      Guardian's documented Open Query shape — note the
      singular ``result`` key); federated / CMC mirrors
      collapse this into bare lists or ``{"results": [...]}``
      / ``{"data": [...]}`` / ``{"items": [...]}`` /
      ``{"assets": [...]}`` — all shapes are accepted.  Each
      record carries ``id``, ``name``, ``ip``,
      ``mac_address``, ``vendor``, ``product_name`` (model),
      ``firmware_version``, ``os``, ``type`` (``PLC`` /
      ``RTU`` / ``HMI`` / ``Historian`` / ``Engineering
      Workstation`` / ``IT`` — Nozomi's published asset
      taxonomy), ``level`` (numeric 0..4 Purdue level),
      ``criticality`` (``critical`` / ``high`` / ``medium``
      / ``low`` / ``none`` label or 0..4 numeric), ``zone_id``
      / ``zone_name``, ``site_id`` / ``site_name``,
      ``first_activity_time`` / ``last_activity_time``,
      ``risk`` (0..10 score), and an optional ``cve_list`` /
      ``vulnerabilities`` list of attributed CVE strings.

  GET {NOZOMI_HOST}/api/open/query/do?query=alerts | head N | skip M
      -> Paginated security alert feed.  Same envelope
      shape; each record carries ``id``, ``name`` /
      ``type_name``, ``description``, ``severity``
      (``Critical`` / ``High`` / ``Medium`` / ``Low`` /
      ``Info``, or 0..10 numeric on some firmwares),
      ``type_id`` (Nozomi's published alert taxonomy:
      ``SIGN:NETWORK:MALWARE`` / ``SIGN:PROTOCOL:ANOMALY`` /
      ``VI:UNAUTHORIZED-COMMAND`` / etc), ``status``
      (``open`` / ``acknowledged`` / ``closed`` / ``muted``
      / ``resolved``), ``record_created_at`` /
      ``record_updated_at``, ``src_ip`` / ``dst_ip``,
      ``risk`` (0..10), and ``zone_id`` / ``zone_name``.

  GET {NOZOMI_HOST}/api/open/query/do?query=vulnerabilities | head N | skip M
      -> Paginated CVE-attributed vulnerability findings.
      Same envelope shape; each record carries ``id``,
      ``cve_id`` / ``cve``, ``name`` / ``title``,
      ``description``, ``severity`` (label) /
      ``cvss_score`` (0..10), ``node_id`` (asset id keyed
      on the finding), ``node_label`` (asset name), ``node_ip``
      (asset IP), ``zone_id`` / ``zone_name``,
      ``record_created_at`` / ``record_updated_at``, and an
      optional ``status`` (``open`` / ``resolved`` /
      ``mitigated`` / ``accepted_risk``).

Auth: Nozomi Guardian's Open Query surface uses HTTP Basic
Auth — the dispatcher sends ``Authorization: Basic
<base64(NOZOMI_USER:NOZOMI_PASSWORD)>`` on every
``/api/open/`` request, with no separate login round-trip.
(Guardian also supports an ``/api/open/sign_in``
session-cookie flow but the dispatcher unconditionally uses
Basic Auth so a stale session cookie can't silently authorise
a request, and so the same code path covers federated CMC
fan-outs and on-prem Guardian appliances.)

Args:
  ``NOZOMI_QUERY_SCOPE`` (optional) — query-surface selector
  (case-insensitive ``assets`` / ``alerts`` / ``vulns`` /
  ``vulnerabilities`` / ``all``).  Empty / blank / unknown
  values walk all three surfaces (the typical operational
  mode for first-time imports).  ``vulns`` is an
  operator-friendly alias for the canonical Nozomi query
  keyword ``vulnerabilities``.

  ``NOZOMI_MIN_SEVERITY`` (optional) — Faraday severity floor
  (case-insensitive ``info`` / ``low`` / ``medium`` /
  ``high`` / ``critical``).  Records whose mapped severity
  is strictly below the floor are dropped client-side after
  the fetch.  Operator-friendly aliases (``informational`` ->
  ``info``, ``moderate`` -> ``medium``, ``crit`` ->
  ``critical``) are normalised.  Asset records (no severity
  of their own) are bucketed from the ``criticality`` field;
  alerts use the published ``severity`` field directly with
  a fallback to ``risk``; vulnerabilities use ``severity``
  directly with a fallback to ``cvss_score`` / ``score``.
  Blank / missing input keeps every record.

Env vars:
  ``NOZOMI_HOST`` (mandatory) — the appliance base URL
  (e.g.  ``https://guardian.acme.lan`` or the CMC
  ``https://cmc.acme.lan``).  Nozomi Guardian / CMC is an
  on-prem appliance so there is no global default — the
  executor exits cleanly when ``NOZOMI_HOST`` is missing.
  Whitespace is trimmed; ``https://`` is added when the
  operator pasted in a bare FQDN.

  ``NOZOMI_USER`` + ``NOZOMI_PASSWORD`` (both mandatory) —
  the appliance portal credentials.  Forwarded on every
  ``/api/open/`` request as ``Authorization: Basic
  <base64(user:pass)>``.  The credentials never leave the
  dispatcher process — Basic Auth is computed locally
  before each request.

Each Nozomi record becomes one Faraday host.  Asset records
project ``ip`` onto ``host.ip`` (loopback / 0.0.0.0 / ::1
are skipped, falling back to the ``0.0.0.0`` sentinel when
no usable IP is present), ``name`` / ``label`` onto
``host.hostnames``, ``mac_address`` onto ``host.mac``, and
the ``vendor`` / ``product_name`` / ``os`` /
``firmware_version`` chain joins onto ``host.os``.  The
asset itself becomes one Faraday vulnerability with the
``[ASSET-INVENTORY]`` engine prefix.  Alert records are
keyed on the first usable ``src_ip`` / ``source_ip`` /
``dst_ip`` / ``destination_ip`` / ``ip`` field (then the
``0.0.0.0`` sentinel for policy-shaped alerts not keyed on
any single asset).  Vulnerability records are keyed on
``node_ip`` (falling back to ``ip`` / ``asset_ip``, then the
``0.0.0.0`` sentinel).

Severity bucketing:
  - Assets: ``criticality`` is the canonical
    ``critical`` / ``high`` / ``medium`` / ``low`` /
    ``info`` label (or 0..4 / 0..10 numeric ladder).
    Missing / unparseable -> ``info``.
  - Alerts: ``severity`` is the canonical label or 0..10
    numeric; the alert ``risk`` is used as a fallback when
    only a numeric score is published.
  - Vulnerabilities: ``severity`` is the canonical label or
    0..10 numeric; ``cvss_score`` / ``score`` is used as a
    fallback when only a CVSS number is published.

Tags: ``[nozomi_guardian, ot-security, asset|alert|vuln]``.
Status is always ``open`` (Nozomi's terminal ``resolved`` /
``muted`` / ``closed`` / ``suppressed`` / ``dismissed`` /
``acknowledged`` / ``accepted_risk`` states are preserved
via the info-severity floor + an explicit ``Nozomi-Status``
pivot in the refs).
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

QUERY_PATH = "/api/open/query/do"

DEFAULT_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 500
DEFAULT_PAGES = 10
MAX_PAGES = 100
INTER_REQUEST_SLEEP = 0.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(ALLOWED_SEVERITIES)}

# Nozomi Guardian's published label vocabulary covers
# Critical / High / Medium / Low / Info / Informational on
# the alert ``severity``, the asset ``criticality``, and the
# vulnerability ``severity`` fields.  Operator-friendly
# aliases are normalised to Faraday's canonical lowercase
# ladder.
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

# Numeric 0..4 criticality ladder surfaced by some Guardian
# firmwares (Critical=4 .. Info=0).
CRITICALITY_NUMERIC_ALIASES = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# Nozomi alert / vulnerability terminal states — preserved
# via an explicit Nozomi-Status pivot ref but floored to
# ``info`` severity (the record is no longer live).
CLOSED_ALERT_STATES = {
    "resolved",
    "closed",
    "muted",
    "suppressed",
    "dismissed",
    "false-positive",
    "false_positive",
    "falsepositive",
    "acknowledged",
    "ack",
    "mitigated",
    "accepted_risk",
    "accepted-risk",
    "acceptedrisk",
}

# Canonical Nozomi Open Query keyword for each surface.  The
# operator's NOZOMI_QUERY_SCOPE maps onto this set via
# parse_scope().
SURFACE_ASSETS = "assets"
SURFACE_ALERTS = "alerts"
SURFACE_VULNS = "vulnerabilities"
ALL_SURFACES = (SURFACE_ASSETS, SURFACE_ALERTS, SURFACE_VULNS)

SCOPE_ALIASES = {
    "asset": SURFACE_ASSETS,
    "assets": SURFACE_ASSETS,
    "inventory": SURFACE_ASSETS,
    "devices": SURFACE_ASSETS,
    "device": SURFACE_ASSETS,
    "alert": SURFACE_ALERTS,
    "alerts": SURFACE_ALERTS,
    "incidents": SURFACE_ALERTS,
    "incident": SURFACE_ALERTS,
    "vuln": SURFACE_VULNS,
    "vulns": SURFACE_VULNS,
    "vulnerability": SURFACE_VULNS,
    "vulnerabilities": SURFACE_VULNS,
    "cve": SURFACE_VULNS,
    "cves": SURFACE_VULNS,
}


def log(msg):
    print(f"{datetime.utcnow()} - Nozomi: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on NOZOMI_HOST.

    Nozomi Guardian / CMC is an on-prem appliance (every
    install runs on a unique hostname) so there is no global
    default — empty / missing / non-string inputs return
    ``""`` (the caller hard-fails with a helpful error).
    Whitespace is trimmed and ``https://`` is added when the
    operator pasted in a bare FQDN.
    """
    if not host or not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def parse_scope(value):
    """Parse NOZOMI_QUERY_SCOPE into a tuple of canonical surface keywords.

    None / blank / ``all`` / unknown -> walk all three
    surfaces.  ``assets`` / ``alerts`` / ``vulns`` (and
    operator-friendly aliases) narrow the walk to a single
    surface.  Returns a tuple of canonical Nozomi query
    keywords (``assets`` / ``alerts`` / ``vulnerabilities``)
    in the order they should be walked.
    """
    if value is None or isinstance(value, bool):
        return ALL_SURFACES
    if not isinstance(value, str):
        return ALL_SURFACES
    text = value.strip().lower()
    if not text or text == "all":
        return ALL_SURFACES
    surface = SCOPE_ALIASES.get(text)
    if surface is None:
        return ALL_SURFACES
    return (surface,)


def normalize_severity_label(value):
    """Coerce a Nozomi severity / criticality label to Faraday's ladder.

    Returns ``None`` for missing / non-string / unknown
    inputs so the caller can fall back to numeric bucketing.
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
    """Parse NOZOMI_MIN_SEVERITY into a canonical Faraday severity.

    Accepts the canonical labels + the operator-friendly
    aliases (``informational`` / ``moderate`` / ``crit`` /
    ``elevated`` / ``severe`` / ``none``).  Returns ``None``
    for missing / blank / unparseable inputs so the caller
    treats the run as 'keep every record'.
    """
    return normalize_severity_label(value)


def severity_from_alert(value):
    """Bucket Faraday severity from a Nozomi alert ``severity`` value.

    Accepts labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Info``) or 0..10 numeric score
    (Guardian's ``risk`` field).  Returns ``"info"`` for
    missing / unparseable inputs.
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
    """Bucket Faraday severity from a Nozomi asset ``criticality`` value.

    Accepts the labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Info``) and the numeric 0..4
    form (4=critical .. 0=info).  Falls back to the 0..10
    bucketing for federated mirrors that surface criticality
    as a raw score.  Missing / unparseable inputs default to
    ``info``.
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
    """True when a Nozomi alert / vuln ``status`` is terminally closed."""
    if not isinstance(value, str):
        return False
    return value.strip().lower() in CLOSED_ALERT_STATES


def build_query_url(host):
    return f"{normalize_base_url(host)}{QUERY_PATH}"


def build_query(surface, page, page_size=DEFAULT_PAGE_SIZE):
    """Build the canonical Nozomi Open Query string for a surface.

    Nozomi's Open Query API is a pipe-delimited DSL:
    ``<surface> | head <N> | skip <M>``.  The dispatcher
    walks each surface page-by-page with one-based pagination
    (``page=1`` -> ``skip=0``; ``page=2`` -> ``skip=N``).
    Bad inputs are coerced to safe defaults so a typo never
    crashes the dispatcher.  Unknown surfaces fall back to
    the canonical ``assets`` surface (defensive — only
    ``parse_scope`` is allowed to emit surfaces and it only
    emits the canonical three).
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
    if surface not in ALL_SURFACES:
        surface = SURFACE_ASSETS
    skip = (p - 1) * s
    query_text = f"{surface} | head {s} | skip {skip}"
    return urlencode([("query", query_text)])


def basic_auth_header(username, password):
    """Build the ``Authorization: Basic <base64(user:pass)>`` value.

    None / non-string inputs are coerced to empty strings so
    the server can return a useful 401.  The credentials are
    never logged or stored on the dispatcher.
    """
    u = username.strip() if isinstance(username, str) else ""
    p = password if isinstance(password, str) else ""
    token = base64.b64encode(f"{u}:{p}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def request_headers(username, password):
    """Build the request-header dict for a credentialed Open Query GET.

    Nozomi Guardian's Open API documents HTTP Basic Auth on
    every ``/api/open/`` request.  Missing / blank
    credentials still produce a (well-formed but
    unauthorised) Basic header so the server's 401 surfaces
    as a clear error rather than a silently-skipped header.
    """
    return {
        "Accept": "application/json",
        "Authorization": basic_auth_header(username, password),
    }


def extract_records(body):
    """Pull the record list from a Nozomi Open Query response envelope.

    Canonical envelope wraps the record list under
    ``result`` (Nozomi's documented Open Query shape — note
    the singular ``result`` key).  Federated / CMC mirror
    stacks also expose bare-list / ``results`` / ``data`` /
    ``items`` / ``assets`` / ``alerts`` / ``vulnerabilities``
    — all shapes are tolerated.  Non-dict entries are
    silently dropped.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in (
        "result",
        "results",
        "data",
        "items",
        "assets",
        "alerts",
        "vulnerabilities",
    ):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def asset_ip(asset):
    """Pick the asset's primary IP (skipping loopback / zero).

    Nozomi exposes the primary IP via ``ip``; federated /
    CMC shapes also surface ``ip_address`` / ``primary_ip``
    / a list under ``ips`` / ``ip_addresses``.  Falls back
    to the ``0.0.0.0`` sentinel when nothing usable is
    present.
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
    """Collect hostname candidates for a Nozomi asset."""
    if not isinstance(asset, dict):
        return []
    out = []
    seen = set()
    for key in ("name", "label", "hostname", "host_name", "fqdn"):
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
    for key in ("mac_address", "mac"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def asset_os(asset):
    """Build the ``host.os`` string from Nozomi's asset fields.

    Nozomi exposes the vendor under ``vendor``, the model
    under ``product_name`` (the documented Guardian field —
    federated mirrors also surface ``model``), the OS under
    ``os`` / ``operating_system``, and the firmware under
    ``firmware_version`` / ``firmware``.
    """
    if not isinstance(asset, dict):
        return ""
    bits = []
    for key in ("vendor", "manufacturer"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
            break
    for key in ("product_name", "model"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
            break
    for key in ("os", "operating_system"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
            break
    for key in ("firmware_version", "firmware"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(f"firmware={v.strip()}")
            break
    return " ".join(bits)


def alert_ip(alert):
    """Pick the alert's keyed IP (from src_ip / dst_ip / ip)."""
    if not isinstance(alert, dict):
        return "0.0.0.0"
    for key in ("src_ip", "source_ip", "dst_ip", "destination_ip", "ip", "node_ip"):
        v = alert.get(key)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            if s not in ("0.0.0.0", "127.0.0.1", "::1"):
                return s
    related = alert.get("related_assets") or alert.get("relatedAssets") or alert.get("related_devices")
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
    return "0.0.0.0"


def vuln_ip(vuln):
    """Pick the vulnerability's keyed IP (from node_ip / ip / asset_ip)."""
    if not isinstance(vuln, dict):
        return "0.0.0.0"
    for key in ("node_ip", "ip", "ip_address", "asset_ip", "primary_ip"):
        v = vuln.get(key)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            if s not in ("0.0.0.0", "127.0.0.1", "::1"):
                return s
    return "0.0.0.0"


def collect_cves(record):
    """Walk a Nozomi record for CVE ids.

    Nozomi surfaces CVE attribution on assets via
    ``cve_list`` / ``vulnerabilities`` (list of CVE strings
    or dicts), on vulnerability records via the canonical
    ``cve_id`` / ``cve`` scalar plus ``cve_list``, and embeds
    CVE refs in alert / vulnerability descriptions and
    titles.  All occurrences are deduplicated and uppercased
    to NVD's canonical form.
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

    for key in ("cve_id", "cve"):
        v = record.get(key)
        if isinstance(v, str):
            add(v)

    for key in ("cve_list", "cves", "vulnerabilities", "vulnerability_list"):
        raw = record.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("id"))

    for key in ("name", "title", "description", "summary", "type_name"):
        scan(record.get(key))

    return out


def collect_refs(record, entity_type):
    """Build the refs list for a Nozomi asset / alert / vuln record."""
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
            add(f"Nozomi-AssetID: {str(rec_id).strip()}")
        elif entity_type == "alert":
            add(f"Nozomi-AlertID: {str(rec_id).strip()}")
        else:
            add(f"Nozomi-VulnID: {str(rec_id).strip()}")

    zone_name = record.get("zone_name") or record.get("zoneName")
    zone_id = record.get("zone_id") or record.get("zoneId")
    if isinstance(zone_name, str) and zone_name.strip():
        add(f"Nozomi-Zone: {zone_name.strip()}")
    elif zone_id is not None and str(zone_id).strip():
        add(f"Nozomi-Zone: {str(zone_id).strip()}")

    site_name = record.get("site_name") or record.get("siteName")
    site_id = record.get("site_id") or record.get("siteId")
    if isinstance(site_name, str) and site_name.strip():
        add(f"Nozomi-Site: {site_name.strip()}")
    elif site_id is not None and str(site_id).strip():
        add(f"Nozomi-Site: {str(site_id).strip()}")

    if entity_type == "asset":
        for key, label in (
            ("type", "Nozomi-Type"),
            ("asset_type", "Nozomi-Type"),
            ("level", "Nozomi-Level"),
            ("criticality", "Nozomi-Criticality"),
            ("vendor", "Nozomi-Vendor"),
            ("product_name", "Nozomi-Model"),
            ("model", "Nozomi-Model"),
            ("firmware_version", "Nozomi-Firmware"),
            ("firmware", "Nozomi-Firmware"),
            ("risk", "Nozomi-Risk"),
            ("risk_score", "Nozomi-Risk"),
            ("first_activity_time", "Nozomi-FirstSeen"),
            ("last_activity_time", "Nozomi-LastSeen"),
        ):
            v = record.get(key)
            if v in (None, ""):
                continue
            add(f"{label}: {v}")
    elif entity_type == "alert":
        for key, label in (
            ("severity", "Nozomi-Severity"),
            ("type_id", "Nozomi-TypeID"),
            ("type_name", "Nozomi-TypeName"),
            ("category", "Nozomi-Category"),
            ("status", "Nozomi-Status"),
            ("risk", "Nozomi-Risk"),
            ("record_created_at", "Nozomi-CreatedAt"),
            ("record_updated_at", "Nozomi-UpdatedAt"),
            ("created_at", "Nozomi-CreatedAt"),
            ("updated_at", "Nozomi-UpdatedAt"),
        ):
            v = record.get(key)
            if v in (None, ""):
                continue
            add(f"{label}: {v}")
    else:
        for key, label in (
            ("severity", "Nozomi-Severity"),
            ("cvss_score", "Nozomi-CVSS"),
            ("score", "Nozomi-CVSS"),
            ("status", "Nozomi-Status"),
            ("node_id", "Nozomi-NodeID"),
            ("node_label", "Nozomi-NodeLabel"),
            ("node_ip", "Nozomi-NodeIP"),
            ("record_created_at", "Nozomi-CreatedAt"),
            ("record_updated_at", "Nozomi-UpdatedAt"),
            ("created_at", "Nozomi-CreatedAt"),
            ("updated_at", "Nozomi-UpdatedAt"),
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


def build_asset_vulnerability(asset, scope, min_severity=None):
    """Build a Faraday vulnerability dict for one Nozomi asset.

    Returns ``None`` when the asset's mapped severity is
    below ``min_severity``.  The asset is surfaced as a
    Faraday vulnerability with the ``[ASSET-INVENTORY]``
    engine prefix so OT inventory entries land alongside the
    other CMDB-class feeds (Armis, Axonius, Device42).
    """
    if not isinstance(asset, dict):
        return None
    severity = severity_from_criticality(asset.get("criticality"))
    if not severity_meets_threshold(severity, min_severity):
        return None

    hostnames = asset_hostnames(asset)
    primary = hostnames[0] if hostnames else (asset_ip(asset) if asset_ip(asset) != "0.0.0.0" else "unknown asset")
    name = f"[ASSET-INVENTORY] Nozomi asset: {primary}"

    desc_parts = []
    for key in sorted(asset.keys()):
        v = asset.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if scope:
        desc_parts.append(f"nozomi_scope: {scope}")

    asset_id = str(asset.get("id") or asset.get("uuid") or name)

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"asset::{asset_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Nozomi Guardian asset records are OT inventory "
            "entries — cross-check the asset against the "
            "operator's other agents (EDR / vuln scanners / "
            "EASM) for live exposures, and verify the "
            "device's segmentation against the Purdue model "
            "in the Guardian console.  Decommission or merge "
            "the asset in Guardian / CMC if it should no "
            "longer appear in the inventory."
        ),
        "data": "",
        "refs": collect_refs(asset, "asset"),
        "cve": collect_cves(asset),
        "cwe": [],
        "cvss3": {},
        "tags": ["nozomi_guardian", "ot-security", "asset"],
    }


def build_alert_vulnerability(alert, scope, min_severity=None):
    """Build a Faraday vulnerability dict for one Nozomi alert.

    Returns ``None`` when the alert's mapped severity is
    below ``min_severity``.  Terminal Nozomi states
    (``resolved`` / ``muted`` / ``closed`` / ``suppressed``
    / ``dismissed`` / ``acknowledged``) floor the severity
    to ``info`` regardless of the published bucket.
    """
    if not isinstance(alert, dict):
        return None
    status = alert.get("status") if isinstance(alert.get("status"), str) else None
    severity_val = alert.get("severity")
    if severity_val is None:
        severity_val = alert.get("risk")
    if severity_val is None:
        severity_val = alert.get("risk_score")
    severity = severity_from_alert(severity_val)
    if is_closed_alert(status):
        severity = "info"
    if not severity_meets_threshold(severity, min_severity):
        return None

    title = alert.get("name") or alert.get("type_name") or alert.get("title") or alert.get("id") or "Nozomi alert"
    name = f"[Nozomi Alert] {str(title).strip()}"

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
    if scope:
        desc_parts.append(f"nozomi_scope: {scope}")

    alert_id = str(alert.get("id") or alert.get("uuid") or name)

    if is_closed_alert(status):
        resolution = (
            f"Nozomi has marked this alert as {status}; "
            "verify the underlying condition is resolved on "
            "the affected OT asset before closing the "
            "Faraday finding."
        )
    else:
        resolution = (
            "Triage this Nozomi Guardian alert in the "
            "Guardian / CMC console, correlate against the "
            "src_ip / dst_ip and zone_name to identify the "
            "affected OT asset, and apply mitigations per "
            "the operator's incident-response runbook for "
            "the alert type_id (SIGN: signature-based, VI: "
            "variable-integrity, anomaly, protocol)."
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
        "tags": ["nozomi_guardian", "ot-security", "alert"],
    }


def build_vuln_vulnerability(vuln, scope, min_severity=None):
    """Build a Faraday vulnerability dict for one Nozomi vulnerability finding.

    Returns ``None`` when the finding's mapped severity is
    below ``min_severity``.  Terminal Nozomi states
    (``resolved`` / ``mitigated`` / ``accepted_risk``) floor
    the severity to ``info`` regardless of the published
    bucket.
    """
    if not isinstance(vuln, dict):
        return None
    status = vuln.get("status") if isinstance(vuln.get("status"), str) else None
    severity_val = vuln.get("severity")
    if severity_val is None:
        severity_val = vuln.get("cvss_score")
    if severity_val is None:
        severity_val = vuln.get("score")
    severity = severity_from_alert(severity_val)
    if is_closed_alert(status):
        severity = "info"
    if not severity_meets_threshold(severity, min_severity):
        return None

    title = (
        vuln.get("cve_id")
        or vuln.get("cve")
        or vuln.get("name")
        or vuln.get("title")
        or vuln.get("id")
        or "Nozomi vulnerability"
    )
    name = f"[Nozomi Vuln] {str(title).strip()}"

    desc_parts = []
    description = vuln.get("description") or vuln.get("summary") or ""
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    for key in sorted(vuln.keys()):
        if key in ("description", "summary"):
            continue
        v = vuln.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if scope:
        desc_parts.append(f"nozomi_scope: {scope}")

    vuln_id = str(vuln.get("id") or vuln.get("uuid") or vuln.get("cve_id") or vuln.get("cve") or name)

    if is_closed_alert(status):
        resolution = (
            f"Nozomi has marked this vulnerability as "
            f"{status}; verify the underlying CVE is patched "
            "or the risk has been formally accepted before "
            "closing the Faraday finding."
        )
    else:
        resolution = (
            "Triage this Nozomi Guardian vulnerability "
            "finding in the Guardian / CMC console, "
            "correlate against the node_id / node_label / "
            "node_ip to identify the affected OT asset, and "
            "apply the vendor patch or compensating control "
            "per the operator's OT patching runbook (mind "
            "the maintenance-window constraints typical to "
            "ICS environments)."
        )

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"vuln::{vuln_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(vuln, "vuln"),
        "cve": collect_cves(vuln),
        "cwe": [],
        "cvss3": {},
        "tags": ["nozomi_guardian", "ot-security", "vuln"],
    }


def build_host_from_asset(asset, scope, min_severity=None):
    """Build a Faraday host dict from a Nozomi asset record."""
    if not isinstance(asset, dict):
        return None
    vuln = build_asset_vulnerability(asset, scope, min_severity)
    if vuln is None:
        return None
    desc_parts = []
    for key in (
        "type",
        "vendor",
        "product_name",
        "firmware_version",
        "zone_name",
        "site_name",
        "level",
        "criticality",
        "risk",
        "first_activity_time",
        "last_activity_time",
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


def build_host_from_alert(alert, scope, min_severity=None):
    """Build a Faraday host dict from a Nozomi alert record."""
    if not isinstance(alert, dict):
        return None
    vuln = build_alert_vulnerability(alert, scope, min_severity)
    if vuln is None:
        return None
    hostnames = []
    title = alert.get("name") or alert.get("type_name") or alert.get("title")
    if isinstance(title, str) and title.strip():
        hostnames.append(title.strip())
    return {
        "ip": alert_ip(alert),
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Nozomi Guardian alert",
        "vulnerabilities": [vuln],
    }


def build_host_from_vuln(vuln_rec, scope, min_severity=None):
    """Build a Faraday host dict from a Nozomi vulnerability record."""
    if not isinstance(vuln_rec, dict):
        return None
    vuln = build_vuln_vulnerability(vuln_rec, scope, min_severity)
    if vuln is None:
        return None
    hostnames = []
    label = vuln_rec.get("node_label") or vuln_rec.get("asset_name")
    if isinstance(label, str) and label.strip():
        hostnames.append(label.strip())
    return {
        "ip": vuln_ip(vuln_rec),
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Nozomi Guardian vulnerability",
        "vulnerabilities": [vuln],
    }


def fetch_pages(requests_module, url, headers, surface, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk a Nozomi Open Query surface page-by-page.

    Pagination is one-based and emitted into the Open Query
    DSL as ``| head N | skip M`` where M = (page-1)*N.
    Walks until either ``len(records) < page_size`` or
    ``max_pages`` is reached.  401 short-circuits the whole
    executor (credentials are wrong); 403 / 429 / 5xx stop
    pagination on this surface and return what we have.
    """
    out = []
    page = 1
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(surface, page, page_size=page_size)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Nozomi request rejected (401); check NOZOMI_USER / NOZOMI_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Nozomi request rejected (403); check the account's API scope.")
            return out
        if resp.status_code == 429:
            log("Nozomi rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Nozomi request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Nozomi response was not JSON ({full_url})")
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
        log(f"hit NOZOMI_PAGES={max_pages}; stopping pagination on {surface}")
    return out


def validate_pages(value):
    """Coerce NOZOMI_PAGES into a clamped integer.

    Env-only knob (not a manifest argument).  Defaults to
    ``DEFAULT_PAGES`` (10) when missing / blank /
    unparseable.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into thousands of requests
    against the appliance.
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


SURFACE_BUILDERS = {
    SURFACE_ASSETS: build_host_from_asset,
    SURFACE_ALERTS: build_host_from_alert,
    SURFACE_VULNS: build_host_from_vuln,
}


def main():
    started = time.time()

    scope = parse_scope(env("EXECUTOR_CONFIG_NOZOMI_QUERY_SCOPE"))
    min_severity = parse_min_severity(env("EXECUTOR_CONFIG_NOZOMI_MIN_SEVERITY"))
    pages = validate_pages(env("NOZOMI_PAGES"))

    host = env("NOZOMI_HOST", required=True)
    username = env("NOZOMI_USER", required=True)
    password = env("NOZOMI_PASSWORD", required=True)

    if not normalize_base_url(host):
        log("NOZOMI_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = request_headers(username, password)
    query_url = build_query_url(host)

    counts = {surface: 0 for surface in ALL_SURFACES}
    hosts_out = []
    for idx, surface in enumerate(scope):
        if idx > 0:
            time.sleep(INTER_REQUEST_SLEEP)
        records = fetch_pages(requests, query_url, headers, surface, max_pages=pages)
        counts[surface] = len(records)
        log(f"Nozomi discovered {len(records)} {surface} (scope={','.join(scope)})")
        builder = SURFACE_BUILDERS[surface]
        for record in records:
            built = builder(record, surface, min_severity)
            if built is not None:
                hosts_out.append(built)

    log(
        f"Processed {len(hosts_out)} Nozomi hosts "
        f"(assets={counts[SURFACE_ASSETS]}, "
        f"alerts={counts[SURFACE_ALERTS]}, "
        f"vulns={counts[SURFACE_VULNS]}, "
        f"min_severity={min_severity or '(none)'})"
    )

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "nozomi_guardian",
            "command": "nozomi_guardian",
            "params": (
                f"scope={','.join(scope)} "
                f"min_severity={min_severity or ''} "
                f"assets={counts[SURFACE_ASSETS]} "
                f"alerts={counts[SURFACE_ALERTS]} "
                f"vulns={counts[SURFACE_VULNS]} "
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
