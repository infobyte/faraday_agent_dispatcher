#!/usr/bin/env python
"""Ordr Core OT / IoT / IoMT device + alert importer.

Pulls device inventory and security alerts from an Ordr
Core tenant via its v1 REST API and emits Faraday
bulk-create JSON to stdout.  Ordr is a connected-device
security platform that fingerprints OT / IoT / IoMT /
IT endpoints (medical devices, building-automation
controllers, manufacturing PLCs, clinical IT endpoints,
IT-side jump hosts that touch the connected-device
segment) from passive collector traffic and surfaces
both the resulting device inventory and rule-based /
anomaly alerts via a REST surface.  This executor
surfaces both streams under the operator's existing
Faraday workspace so the connected-device findings join
the dispatcher's IT-side scanner output.

Endpoints used:
  GET {ORDR_HOST}/api/v1/devices?category=<cat>&page=N&page_size=M
      -> Paginated connected-device inventory.  The
      canonical envelope is ``{"results": [...], "count":
      N, "next": "...", "previous": "..."}`` (Ordr's
      Django-REST style); federated mirrors collapse this
      into bare lists or ``{"objects": [...]}`` /
      ``{"data": [...]}`` / ``{"items": [...]}`` /
      ``{"devices": [...]}`` — all shapes are accepted.
      Each record carries ``id``, ``name``, ``ip``,
      ``mac``, ``manufacturer`` / ``vendor``, ``model``,
      ``firmware`` / ``firmware_version``, ``os`` /
      ``operating_system``, ``category`` / ``device_type``
      (``medical`` / ``iot`` / ``ot`` / ``it``),
      ``criticality`` (Critical / High / Medium / Low /
      Info label, sometimes 0..4 numeric), ``location`` /
      ``site_name``, ``first_seen`` / ``last_seen``,
      ``risk_score`` (0..100), and an optional
      ``cve_list`` / ``vulnerabilities`` list of
      attributed CVE strings.

  GET {ORDR_HOST}/api/v1/alerts?category=<cat>&page=N&page_size=M
      -> Paginated security alert feed.  Same envelope
      shape; each record carries ``id``, ``title`` /
      ``name``, ``description``, ``severity`` (``Critical``
      / ``High`` / ``Medium`` / ``Low`` / ``Info``, or
      0..10 numeric on some firmwares), ``category``
      (``Anomaly`` / ``Policy Violation`` / ``Known
      Threat`` / ``Vulnerability`` — Ordr's published
      alert taxonomy), ``status`` (``Open`` / ``Resolved``
      / ``Muted`` / ``Suppressed``), ``created_at`` /
      ``updated_at`` (or ``created`` / ``updated`` on
      older firmwares), ``device_id`` /
      ``related_devices`` (list of device ids or scalar
      ip strings the alert is keyed on), ``device_type``
      / ``device_category``, and ``risk_score``.

Auth: Ordr Core's v1 surface uses a long-lived API token
flow.  The token is provisioned in the Ordr console and
passed verbatim as ``Authorization: Bearer <token>`` on
every ``/api/v1/`` request — there is no login exchange.
The token never leaves the dispatcher's process memory.

Args:
  ``ORDR_CATEGORY`` (optional) — server-side device
  category predicate forwarded as ``category=<value>`` on
  both ``/api/v1/devices`` and ``/api/v1/alerts``.  Empty
  / missing walks the entire tenant's inventory across
  every device class (the operator's token scope still
  applies).  Whitespace is trimmed.  Useful for sharding
  inventory pulls across multiple discovery profiles so
  each dispatcher agent only walks one device-class
  worth of inventory per run (e.g.  ``medical``,
  ``iot``, ``ot``, ``it``).  Ordr accepts both the
  literal category label and the numeric category id in
  this slot depending on tenant configuration.

  ``ORDR_MIN_SEVERITY`` (optional) — Faraday severity
  floor (case-insensitive ``info`` / ``low`` / ``medium``
  / ``high`` / ``critical``).  Records whose mapped
  severity is strictly below the floor are dropped
  client-side after the fetch.  Operator-friendly
  aliases (``informational`` -> ``info``, ``moderate`` ->
  ``medium``, ``crit`` -> ``critical``) are normalised.
  Device records (no severity of their own) are bucketed
  from the ``criticality`` field; alerts use the
  published ``severity`` field directly.  Blank /
  missing input keeps every record.

Env vars:
  ``ORDR_HOST`` (mandatory) — the Ordr Core tenant base
  URL (e.g.  ``https://ordr.example.com``).  Ordr is
  deployed both as on-prem and as SaaS so there is no
  global default — the executor exits cleanly when
  ``ORDR_HOST`` is missing.  Whitespace is trimmed;
  ``https://`` is added when the operator pasted in a
  bare FQDN.

  ``ORDR_TOKEN`` (mandatory) — the tenant API token
  provisioned in the Ordr console.  Forwarded as
  ``Authorization: Bearer <token>`` on every request;
  the token never leaves the dispatcher's process
  memory.

Each Ordr record becomes one Faraday host.  Device
records project ``ip`` onto ``host.ip`` (loopback /
0.0.0.0 / ::1 are skipped, falling back to the ``0.0.0.0``
sentinel when no usable IP is present), ``name`` onto
``host.hostnames``, ``mac`` onto ``host.mac``, and the
``manufacturer`` / ``model`` / ``firmware`` / ``os``
chain joins onto ``host.os``.  The device itself becomes
one Faraday vulnerability with the ``[ASSET-INVENTORY]``
engine prefix.  Alert records are keyed on the first
``related_devices`` IP (falling back to the alert's own
``src_ip`` / ``dst_ip`` / ``ip`` field, then the
``0.0.0.0`` sentinel for policy-shaped alerts not keyed
on any single device).

Severity bucketing:
  - Devices: ``criticality`` is the canonical
    ``critical`` / ``high`` / ``medium`` / ``low`` /
    ``info`` label (or 0..4 / 0..10 numeric ladder).
    Missing / unparseable -> ``info``.
  - Alerts: ``severity`` is the canonical label or 0..10
    numeric; the alert ``risk_score`` is used as a
    fallback when only a numeric score is published.

Tags: ``[ordr, ot-security, device|alert]``.
Status is always ``open`` (Ordr's terminal ``Resolved``
/ ``Muted`` / ``Suppressed`` states are preserved via
the info-severity floor + an explicit ``Ordr-Status``
pivot in the refs).
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

DEVICES_PATH = "/api/v1/devices"
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

# Ordr's published label vocabulary covers Critical /
# High / Medium / Low / Info / Informational on both the
# alert ``severity`` and the device ``criticality`` fields.
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

# Numeric 0..4 criticality ladder surfaced by some Ordr
# tenants (Critical=4 .. Info=0).
CRITICALITY_NUMERIC_ALIASES = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# Ordr alert terminal states — preserved via an explicit
# Ordr-Status pivot ref but floored to ``info`` severity
# (the alert is no longer live).
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
    print(f"{datetime.utcnow()} - Ordr: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on ORDR_HOST.

    Ordr is deployed both as on-prem and as SaaS (every
    tenant runs on a unique URL) so there is no global
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


def validate_category(value):
    """Validate ORDR_CATEGORY (operator-supplied predicate).

    None / blank -> ``""`` (no category narrowing; walk
    the full tenant).  Whitespace is trimmed.  Forwarded
    verbatim as the ``category=<value>`` query parameter
    on both surfaces — Ordr accepts both the literal
    category label (``medical`` / ``iot`` / ``ot`` /
    ``it``) and the numeric category id depending on
    tenant configuration.
    """
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip()


def normalize_severity_label(value):
    """Coerce an Ordr severity / criticality label to Faraday's ladder.

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
    """Parse ORDR_MIN_SEVERITY into a canonical Faraday severity.

    Accepts the canonical labels + the operator-friendly
    aliases (``informational`` / ``moderate`` / ``crit`` /
    ``elevated`` / ``severe`` / ``none``).  Returns
    ``None`` for missing / blank / unparseable inputs so
    the caller treats the run as 'keep every record'.
    """
    return normalize_severity_label(value)


def severity_from_alert(value):
    """Bucket Faraday severity from an Ordr alert ``severity`` value.

    Accepts labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Info``) or 0..10 numeric
    score (some Ordr tenants emit a raw risk score).
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
    """Bucket Faraday severity from an Ordr device ``criticality`` value.

    Accepts the labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Info``) and the numeric 0..4
    form (4=critical .. 0=info).  Falls back to the 0..10
    bucketing for tenants that surface criticality as a
    raw score.  Missing / unparseable inputs default to
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
    """True when an Ordr alert ``status`` is terminally closed."""
    if not isinstance(value, str):
        return False
    return value.strip().lower() in CLOSED_ALERT_STATES


def build_devices_url(host):
    return f"{normalize_base_url(host)}{DEVICES_PATH}"


def build_alerts_url(host):
    return f"{normalize_base_url(host)}{ALERTS_PATH}"


def build_query(page, page_size=DEFAULT_PAGE_SIZE, category=""):
    """Build the canonical Ordr paging query string.

    Ordr's v1 surface uses one-based ``page=N`` +
    ``page_size=M`` pagination.  ``category`` is
    forwarded verbatim when non-empty.  Bad inputs are
    coerced to safe defaults so a typo never crashes the
    dispatcher.
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
    if category:
        text = str(category).strip()
        if text:
            params.append(("category", text))
    return urlencode(params)


def request_headers(token):
    """Build the request-header dict for a credentialed GET.

    Ordr v1 documents ``Authorization: Bearer <token>``
    for the API-token flow.  Missing / blank tokens are
    coerced to an empty string and the ``Authorization``
    header is omitted entirely (so a misconfigured token
    surfaces as an explicit 401 rather than as an
    empty-header request that some Ordr middleware
    silently accepts).
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


def extract_records(body):
    """Pull the record list from an Ordr v1 response envelope.

    Canonical envelope wraps the record list under
    ``results`` (Ordr's Django-REST style).  Federated /
    mirror stacks also expose bare-list / ``objects`` /
    ``data`` / ``items`` / ``devices`` / ``alerts`` — all
    shapes are tolerated.  Non-dict entries are silently
    dropped.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("results", "objects", "data", "items", "devices", "alerts"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def device_ip(device):
    """Pick the device's primary IP (skipping loopback / zero).

    Ordr exposes the primary IP via ``ip``; federated
    shapes also surface ``ip_address`` / ``primary_ip`` /
    a list under ``ips``.  Falls back to the ``0.0.0.0``
    sentinel when nothing usable is present.
    """
    if not isinstance(device, dict):
        return "0.0.0.0"
    candidates = []
    for key in ("ip", "ip_address", "primary_ip"):
        v = device.get(key)
        if isinstance(v, str) and v.strip():
            candidates.append(v.strip())
    for key in ("ips", "ip_addresses"):
        v = device.get(key)
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


def device_hostnames(device):
    """Collect hostname candidates for an Ordr device."""
    if not isinstance(device, dict):
        return []
    out = []
    seen = set()
    for key in ("name", "hostname", "host_name", "fqdn", "label"):
        v = device.get(key)
        if isinstance(v, str):
            s = v.strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    return out


def device_mac(device):
    if not isinstance(device, dict):
        return ""
    for key in ("mac", "mac_address"):
        v = device.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def device_os(device):
    """Build the ``host.os`` string from Ordr's device fields."""
    if not isinstance(device, dict):
        return ""
    bits = []
    for key in ("manufacturer", "vendor"):
        v = device.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
            break
    for key in ("model",):
        v = device.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
    for key in ("os", "operating_system"):
        v = device.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
            break
    for key in ("firmware", "firmware_version"):
        v = device.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(f"firmware={v.strip()}")
            break
    return " ".join(bits)


def alert_ip(alert):
    """Pick the alert's keyed IP (from related_devices / src_ip / dst_ip)."""
    if not isinstance(alert, dict):
        return "0.0.0.0"
    related = alert.get("related_devices") or alert.get("relatedDevices") or alert.get("related_assets")
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
    """Walk an Ordr record for CVE ids.

    Ordr surfaces CVE attribution on devices via
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
    """Build the refs list for an Ordr device / alert record."""
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
        if entity_type == "device":
            add(f"Ordr-DeviceID: {str(rec_id).strip()}")
        else:
            add(f"Ordr-AlertID: {str(rec_id).strip()}")

    location = record.get("location") or record.get("site_name") or record.get("siteName")
    site_id = record.get("site_id") or record.get("siteId") or record.get("location_id")
    if isinstance(location, str) and location.strip():
        add(f"Ordr-Location: {location.strip()}")
    elif site_id is not None and str(site_id).strip():
        add(f"Ordr-Location: {str(site_id).strip()}")

    if entity_type == "device":
        for key, label in (
            ("category", "Ordr-Category"),
            ("device_category", "Ordr-Category"),
            ("device_type", "Ordr-Type"),
            ("type", "Ordr-Type"),
            ("criticality", "Ordr-Criticality"),
            ("manufacturer", "Ordr-Manufacturer"),
            ("vendor", "Ordr-Manufacturer"),
            ("model", "Ordr-Model"),
            ("firmware", "Ordr-Firmware"),
            ("firmware_version", "Ordr-Firmware"),
            ("os", "Ordr-OS"),
            ("operating_system", "Ordr-OS"),
            ("risk_score", "Ordr-RiskScore"),
            ("first_seen", "Ordr-FirstSeen"),
            ("last_seen", "Ordr-LastSeen"),
        ):
            v = record.get(key)
            if v in (None, ""):
                continue
            add(f"{label}: {v}")
    else:
        for key, label in (
            ("severity", "Ordr-Severity"),
            ("category", "Ordr-Category"),
            ("device_category", "Ordr-Category"),
            ("status", "Ordr-Status"),
            ("device_type", "Ordr-Type"),
            ("risk_score", "Ordr-RiskScore"),
            ("created_at", "Ordr-CreatedAt"),
            ("created", "Ordr-CreatedAt"),
            ("updated_at", "Ordr-UpdatedAt"),
            ("updated", "Ordr-UpdatedAt"),
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


def build_device_vulnerability(device, category, min_severity=None):
    """Build a Faraday vulnerability dict for one Ordr device.

    Returns ``None`` when the device's mapped severity is
    below ``min_severity``.  The device is surfaced as a
    Faraday vulnerability with the ``[ASSET-INVENTORY]``
    engine prefix so connected-device inventory entries
    land alongside the other CMDB-class feeds (Armis,
    Axonius, Device42).
    """
    if not isinstance(device, dict):
        return None
    severity = severity_from_criticality(device.get("criticality"))
    if not severity_meets_threshold(severity, min_severity):
        return None

    hostnames = device_hostnames(device)
    primary = (
        hostnames[0] if hostnames else (device_ip(device) if device_ip(device) != "0.0.0.0" else "unknown device")
    )
    name = f"[ASSET-INVENTORY] Ordr device: {primary}"

    desc_parts = []
    for key in sorted(device.keys()):
        v = device.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if category:
        desc_parts.append(f"ordr_category: {category}")

    device_id = str(device.get("id") or device.get("uuid") or name)

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"device::{device_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Ordr device records are connected-device "
            "inventory entries — cross-check the device against "
            "the operator's other agents (EDR / vuln scanners / "
            "EASM) for live exposures, and verify the device's "
            "segmentation against the network policy in the Ordr "
            "console.  Decommission or merge the device in Ordr "
            "if it should no longer appear in the inventory."
        ),
        "data": "",
        "refs": collect_refs(device, "device"),
        "cve": collect_cves(device),
        "cwe": [],
        "cvss3": {},
        "tags": ["ordr", "ot-security", "device"],
    }


def build_alert_vulnerability(alert, category, min_severity=None):
    """Build a Faraday vulnerability dict for one Ordr alert.

    Returns ``None`` when the alert's mapped severity is
    below ``min_severity``.  Terminal Ordr states
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

    title = alert.get("title") or alert.get("name") or alert.get("id") or "Ordr alert"
    name = f"[Ordr Alert] {str(title).strip()}"

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
    if category:
        desc_parts.append(f"ordr_category: {category}")

    alert_id = str(alert.get("id") or alert.get("uuid") or name)

    if is_closed_alert(status):
        resolution = (
            f"Ordr has marked this alert as {status}; verify the "
            "underlying condition is resolved on the affected "
            "device before closing the Faraday finding."
        )
    else:
        resolution = (
            "Triage this Ordr alert in the Ordr console, "
            "correlate against the related_devices list to identify "
            "the affected connected device, and apply mitigations "
            "per the operator's incident-response runbook for the "
            "alert category (Anomaly / Policy Violation / Known "
            "Threat / Vulnerability)."
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
        "tags": ["ordr", "ot-security", "alert"],
    }


def build_host_from_device(device, category, min_severity=None):
    """Build a Faraday host dict from an Ordr device record."""
    if not isinstance(device, dict):
        return None
    vuln = build_device_vulnerability(device, category, min_severity)
    if vuln is None:
        return None
    desc_parts = []
    for key in (
        "category",
        "device_category",
        "device_type",
        "type",
        "manufacturer",
        "vendor",
        "model",
        "firmware",
        "location",
        "criticality",
        "risk_score",
        "first_seen",
        "last_seen",
    ):
        v = device.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}={_serialise(v)}")
    return {
        "ip": device_ip(device),
        "os": device_os(device),
        "hostnames": device_hostnames(device),
        "mac": device_mac(device),
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln],
    }


def build_host_from_alert(alert, category, min_severity=None):
    """Build a Faraday host dict from an Ordr alert record."""
    if not isinstance(alert, dict):
        return None
    vuln = build_alert_vulnerability(alert, category, min_severity)
    if vuln is None:
        return None
    hostnames = []
    title = alert.get("title") or alert.get("name")
    if isinstance(title, str) and title.strip():
        hostnames.append(title.strip())
    return {
        "ip": alert_ip(alert),
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Ordr alert",
        "vulnerabilities": [vuln],
    }


def fetch_pages(requests_module, url, headers, category, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk an Ordr v1 paginated surface.

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
        qs = build_query(page, page_size=page_size, category=category)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Ordr request rejected (401); API token expired or invalid.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Ordr request rejected (403); check the token's scope.")
            return out
        if resp.status_code == 429:
            log("Ordr rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Ordr request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Ordr response was not JSON ({full_url})")
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
        log(f"hit ORDR_PAGES={max_pages}; stopping pagination")
    return out


def validate_pages(value):
    """Coerce ORDR_PAGES into a clamped integer.

    Env-only knob (not a manifest argument).  Defaults to
    ``DEFAULT_PAGES`` (10) when missing / blank /
    unparseable.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into thousands of
    requests against the tenant.
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

    category = validate_category(env("EXECUTOR_CONFIG_ORDR_CATEGORY"))
    min_severity = parse_min_severity(env("EXECUTOR_CONFIG_ORDR_MIN_SEVERITY"))
    pages = validate_pages(env("ORDR_PAGES"))

    host = env("ORDR_HOST", required=True)
    token = env("ORDR_TOKEN", required=True)

    if not normalize_base_url(host):
        log("ORDR_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = request_headers(token)

    devices = fetch_pages(requests, build_devices_url(host), headers, category, max_pages=pages)
    log(f"Ordr discovered {len(devices)} devices (category={category!r})")
    time.sleep(INTER_REQUEST_SLEEP)
    alerts = fetch_pages(requests, build_alerts_url(host), headers, category, max_pages=pages)
    log(f"Ordr discovered {len(alerts)} alerts (category={category!r})")

    hosts_out = []
    for record in devices:
        built = build_host_from_device(record, category, min_severity)
        if built is not None:
            hosts_out.append(built)
    for record in alerts:
        built = build_host_from_alert(record, category, min_severity)
        if built is not None:
            hosts_out.append(built)

    log(
        f"Processed {len(hosts_out)} Ordr hosts "
        f"(devices={len(devices)}, alerts={len(alerts)}, "
        f"min_severity={min_severity or '(none)'})"
    )

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "ordr",
            "command": "ordr",
            "params": (
                f"category={category} "
                f"min_severity={min_severity or ''} "
                f"devices={len(devices)} "
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
