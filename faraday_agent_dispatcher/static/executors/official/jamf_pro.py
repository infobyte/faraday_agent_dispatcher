#!/usr/bin/env python
"""Jamf Pro asset-inventory importer.

Pulls managed Apple endpoints (macOS computers + iOS / iPadOS /
tvOS mobile devices) from a Jamf Pro tenant and emits Faraday
bulk-create JSON to stdout.  Jamf Pro is the MDM authority of
record for the Apple fleet, so this executor is the CMDB-class
feed Faraday operators correlate the EDR / vuln-scanner agents'
findings against to confirm an exposed host is, in fact, a known
managed Apple endpoint.  Each Jamf Pro computer becomes one
Faraday host — the modern Jamf Pro API's ``general.lastIpAddress``
(with ``general.lastReportedIp`` as a fallback) maps onto
``host.ip`` (loopback / ``0.0.0.0`` / ``::1`` are explicitly
skipped; we fall back to the ``0.0.0.0`` sentinel when nothing
usable is found), the ``general.name`` / ``hardware.modelIdentifier``
/ ``hardware.serialNumber`` projection lands on ``host.hostnames``,
``hardware.macAddress`` (with ``hardware.altMacAddress`` as a
fallback) lands on ``host.mac``, the ``operatingSystem.name`` /
``operatingSystem.version`` / ``operatingSystem.build`` /
``hardware.model`` chain joins onto ``host.os``, and the asset
itself becomes one Faraday vulnerability with the
``[ASSET-INVENTORY]`` engine prefix.  Each Jamf Pro mobile device
becomes one Faraday host keyed on the ``ip_address`` / ``wifi_ip``
field when present (mobile devices CAN expose their last-known IP
under the Classic API's mobile-device record) or the ``0.0.0.0``
sentinel otherwise; the ``name`` / ``device_name`` / ``udid``
projection lands on ``host.hostnames``, ``wifi_mac_address`` lands
on ``host.mac``, and the ``model`` / ``model_display`` /
``model_identifier`` chain joins onto ``host.os``.

Endpoints used:
  GET {JAMF_HOST}/JSSResource/computers
      -> the Jamf Pro Classic API's lightweight computer list.
      Returns ``{"computers": [{"id": N, "name": "..."}]}`` — the
      records are deliberately thin (only id + name) because the
      Classic API expects operators to walk each ``id`` separately
      via ``/JSSResource/computers/id/N`` for full detail; the
      modern Jamf Pro API exposes the richer record in a single
      paginated walk, so we use the Classic list as a belt-and-
      suspenders fallback for tenants where the modern API hasn't
      been enabled and de-dup against the modern walk via the
      shared ``id`` key.
  GET {JAMF_HOST}/api/v1/computers-inventory?page=N&page-size=100&section=GENERAL&section=HARDWARE&section=OPERATING_SYSTEM&section=USER_AND_LOCATION  # noqa: E501
      -> the modern Jamf Pro API's full computer inventory.
      Returns ``{"totalCount": N, "results": [...]}`` with each
      record carrying ``id``, ``udid``, plus the requested sections
      (``general`` / ``hardware`` / ``operatingSystem`` /
      ``userAndLocation``).  The dispatcher always requests the
      same four sections so the field projection is deterministic.
  GET {JAMF_HOST}/JSSResource/mobiledevices
      -> the Jamf Pro Classic API's mobile-device list.  Returns
      ``{"mobile_devices": [{"id": N, "name": "...", "device_name":
      "...", "udid": "...", "wifi_mac_address": "...",
      "serial_number": "...", "model": "...", "model_identifier":
      "...", "model_display": "...", "username": "..."}]}`` — the
      Classic API IS rich enough here because mobile records
      historically don't carry the same depth as computer records,
      so a single list call is the canonical mobile walk (no
      separate ``/JSSResource/mobiledevices/id/N`` enrichment
      needed for the asset-inventory use case).

``JAMF_DEVICE_TYPE`` selects which surfaces to walk
(``computer`` -> Classic ``/computers`` + modern
``/computers-inventory``; ``mobile`` -> Classic
``/mobiledevices``; ``both`` -> all three).  Default is ``both``
so a fresh playbook pulls the full Apple fleet without further
config; invalid values fall back to ``both`` with a warning rather
than aborting (the dispatcher tolerates operator typos here
because ``computer`` / ``mobile`` are the only narrowing knobs).

Pagination is per-surface.  ``/api/v1/computers-inventory`` is
page-based (``page`` + ``page-size`` query params, both 0-indexed)
and walked page-by-page until ``len(results) < page-size`` or the
env-only ``JAMF_PAGES`` cap is reached (default 5, clamped to
[1, 50]).  ``page-size`` is fixed at 100 (Jamf Pro's documented
default; the hard cap is 2000 but smaller pages keep response
sizes manageable).  The Classic API list endpoints don't
paginate — they return the whole tenant's records in a single
call — so we issue one GET per Classic surface and walk the
returned list directly.

Auth: Jamf Pro uses OAuth2 client-credentials.  Operators register
an API role + client in the Jamf Pro console under
``Settings -> System -> API roles and clients`` to obtain
``JAMF_CLIENT_ID`` + ``JAMF_CLIENT_SECRET``.  On every executor
run ``exchange_oauth_token()`` POSTs
``client_id=<id>&client_secret=<secret>&grant_type=client_credentials``
form data to ``{JAMF_HOST}/api/oauth/token`` and pulls the short-
lived access token out of the ``access_token`` field.  The token
travels on every subsequent ``/JSSResource/`` or ``/api/v1/``
request as the standard ``Authorization: Bearer <token>`` header,
built inline via ``bearer_auth_header()`` so the wire format is
unit-testable.  ``JAMF_HOST`` is the operator's Jamf Pro tenant
host (e.g. ``mycorp.jamfcloud.com``); on-prem Jamf Pro deployments
are tolerated and ``https://`` is added automatically when the
operator pasted in a bare FQDN.

Severity is always ``info`` because Jamf Pro hits are MDM
inventory entries, not vulnerability findings — operators
correlate against the other agents' findings via the
``Jamf-Id`` / ``Jamf-Udid`` / ``Jamf-Serial`` / ``Jamf-Model`` /
``Jamf-Platform`` / ``Jamf-LastContact`` / ``Jamf-User`` /
``Jamf-Department`` / ``Jamf-Building`` / ``Jamf-Site`` refs on
computer hits, and the ``Jamf-Id`` / ``Jamf-Udid`` / ``Jamf-Serial``
/ ``Jamf-Model`` / ``Jamf-User`` / ``Jamf-Type`` refs on mobile
hits.  Tags: [jamf_pro, asset-inventory, computer|mobile].
"""

import json
import os
import re
import socket
import sys
import time
import urllib.parse
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

TIMEOUT = 60
PER_PAGE = 100  # Jamf Pro's documented default page-size.
DEFAULT_PAGES = 5
MAX_PAGES = 50

DEFAULT_SECTIONS = (
    "GENERAL",
    "HARDWARE",
    "OPERATING_SYSTEM",
    "USER_AND_LOCATION",
)

VALID_DEVICE_TYPES = ("computer", "mobile", "both")
DEFAULT_DEVICE_TYPE = "both"


def log(msg):
    print(f"{datetime.utcnow()} - JamfPro: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on JAMF_HOST.

    No default — the Jamf Pro tenant host is operator-specific so
    we ``sys.exit(1)`` upstream in ``main`` when the env var is
    missing.  Here we just whitespace-trim, strip trailing slashes
    and add ``https://`` when the operator pasted in a bare FQDN
    (on-prem Jamf Pro deployments commonly use raw hostnames).
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_device_type(value):
    """Validate JAMF_DEVICE_TYPE (the surface-selection knob).

    None / blank / invalid -> ``DEFAULT_DEVICE_TYPE`` (``both``).
    Whitespace is trimmed and the value is lowercased so operator
    typos like ``Computer`` / ``MOBILE`` round-trip correctly.
    Invalid values fall back to ``both`` with a warning rather than
    aborting (the dispatcher tolerates operator typos here because
    ``computer`` / ``mobile`` are the only narrowing knobs and
    walking too much is preferable to walking nothing).
    """
    if value is None or value == "":
        return DEFAULT_DEVICE_TYPE
    text = str(value).strip().lower()
    if not text:
        return DEFAULT_DEVICE_TYPE
    if text not in VALID_DEVICE_TYPES:
        log(f"JAMF_DEVICE_TYPE {value!r} not in {VALID_DEVICE_TYPES}; " f"defaulting to {DEFAULT_DEVICE_TYPE}")
        return DEFAULT_DEVICE_TYPE
    return text


def validate_pages(value):
    """Validate JAMF_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Jamf Pro tenant.  Not exposed as a manifest argument (the
    playbook only lists JAMF_DEVICE_TYPE) but read from the env so
    a tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"JAMF_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"JAMF_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_oauth_token_url(host):
    return f"{normalize_base_url(host)}/api/oauth/token"


def build_classic_computers_url(host):
    return f"{normalize_base_url(host)}/JSSResource/computers"


def build_classic_mobiledevices_url(host):
    return f"{normalize_base_url(host)}/JSSResource/mobiledevices"


def build_modern_computers_inventory_url(host):
    return f"{normalize_base_url(host)}/api/v1/computers-inventory"


def build_modern_query(page, page_size=PER_PAGE, sections=DEFAULT_SECTIONS, extra=None):
    """Build the canonical /api/v1/computers-inventory query string.

    The modern Jamf Pro API uses page-based pagination via ``page``
    (0-indexed) + ``page-size`` plus repeated ``section`` query
    params to control which sub-records are inlined.  Repeated
    keys (``section=GENERAL&section=HARDWARE&...``) are emitted
    via the (k, v) tuple list so ``urllib.parse.urlencode`` will
    NOT collapse them into a single comma-joined value (Jamf Pro
    rejects ``section=GENERAL,HARDWARE`` as a 400).  ``extra`` is
    an optional dict of additional filter params; blanks are
    silently dropped so the resulting query string never carries
    a value-less key.
    """
    params = [
        ("page", str(int(page))),
        ("page-size", str(int(page_size))),
    ]
    for section in sections or ():
        s = str(section).strip()
        if s:
            params.append(("section", s))
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            s = str(v).strip()
            if not s:
                continue
            params.append((str(k), s))
    return urllib.parse.urlencode(params)


def bearer_auth_header(token):
    """Build the canonical Jamf Pro ``Authorization`` header value.

    Jamf Pro uses the standard ``Authorization: Bearer <token>``
    header on both the Classic and modern APIs.  We build the
    header inline (rather than relying on a third-party library)
    so test fixtures + unit checks can assert on the exact wire
    format and ``requests`` won't strip a manually-built
    Authorization header on cross-host redirects.
    """
    token_str = str(token or "").strip()
    if not token_str:
        return ""
    return f"Bearer {token_str}"


def auth_headers(token):
    return {
        "Authorization": bearer_auth_header(token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_modern_records(body):
    """Pull the record list from a /api/v1/computers-inventory reply.

    The modern Jamf Pro API wraps records under ``results`` (the
    documented v1 shape).  Federated / future shapes may use
    bare-list, top-level ``data`` / ``items`` / ``computers`` —
    accept all for resilience.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("results", "computers", "data", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_classic_computers(body):
    """Pull the computer list from a /JSSResource/computers reply.

    The Classic API wraps records under ``computers`` (the
    documented shape).  Bare-list / ``data`` / ``items`` / ``results``
    are accepted for resilience.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("computers", "Computers", "data", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_classic_mobiledevices(body):
    """Pull the mobile-device list from a /JSSResource/mobiledevices reply.

    The Classic API wraps records under ``mobile_devices`` (the
    documented shape).  Bare-list / ``mobiledevices`` /
    ``mobileDevices`` / ``data`` / ``items`` / ``results`` are
    accepted for resilience.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in (
        "mobile_devices",
        "mobiledevices",
        "mobileDevices",
        "data",
        "results",
        "items",
    ):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_total(body):
    if not isinstance(body, dict):
        return None
    for key in ("totalCount", "total_count", "total", "count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def extract_access_token(body):
    """Pull the OAuth access token from a /api/oauth/token reply.

    Jamf Pro returns ``{"access_token": "...", "expires_in": N,
    "scope": "...", "token_type": "Bearer"}``.  Federated stacks may
    nest the token under ``data.access_token`` — accept both.
    """
    if not isinstance(body, dict):
        return ""
    for key in ("access_token", "accessToken", "token"):
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    data = body.get("data")
    if isinstance(data, dict):
        for key in ("access_token", "accessToken", "token"):
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


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


def _flatten_string(value):
    """Coerce a single Jamf Pro attribute value into a printable string."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        for entry in value:
            scalar = _flatten_string(entry)
            if scalar:
                return scalar
        return ""
    if isinstance(value, dict):
        for key in ("ip", "address", "mac", "name", "value", "id"):
            v = value.get(key)
            if v:
                return _flatten_string(v)
    return ""


def _flatten_strings(value):
    """Coerce a Jamf Pro attribute value into a deduped string list."""
    out = []
    seen = set()

    def add(text):
        if text is None:
            return
        if isinstance(text, str):
            s = text.strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
            return
        if isinstance(text, (int, float)):
            s = str(text)
            if s not in seen:
                seen.add(s)
                out.append(s)
            return
        if isinstance(text, list):
            for entry in text:
                add(entry)
            return
        if isinstance(text, dict):
            for key in ("ip", "address", "mac", "name", "value", "id"):
                v = text.get(key)
                if v is not None:
                    add(v)

    add(value)
    return out


def _general(computer):
    if not isinstance(computer, dict):
        return {}
    g = computer.get("general")
    return g if isinstance(g, dict) else {}


def _hardware(computer):
    if not isinstance(computer, dict):
        return {}
    h = computer.get("hardware")
    return h if isinstance(h, dict) else {}


def _operating_system(computer):
    if not isinstance(computer, dict):
        return {}
    o = computer.get("operatingSystem") or computer.get("operating_system")
    return o if isinstance(o, dict) else {}


def _user_and_location(computer):
    if not isinstance(computer, dict):
        return {}
    u = computer.get("userAndLocation") or computer.get("user_and_location")
    return u if isinstance(u, dict) else {}


def computer_ips(computer):
    """Walk a Jamf Pro computer record for IP candidates.

    Modern Jamf Pro projects the last-known IP under
    ``general.lastIpAddress`` (and a ``general.lastReportedIp``
    fallback).  Classic ``/JSSResource/computers`` records only
    carry ``id`` + ``name``, so this returns ``[]`` for that
    shape.  Loopback / zero are explicitly skipped.
    """
    if not isinstance(computer, dict):
        return []
    candidates = []
    general = _general(computer)
    for key in ("lastIpAddress", "last_ip_address", "lastReportedIp", "last_reported_ip", "reportedIp", "reported_ip"):
        v = general.get(key)
        if v:
            candidates.extend(_flatten_strings(v))
    for key in ("ip_address", "ipAddress", "lastIpAddress", "lastReportedIp", "ip"):
        v = computer.get(key)
        if v:
            candidates.extend(_flatten_strings(v))
    out = []
    seen = set()
    for ip in candidates:
        s = ip.strip()
        if not s or s in seen:
            continue
        if s in ("0.0.0.0", "127.0.0.1", "::1"):
            continue
        seen.add(s)
        out.append(s)
    return out


def computer_ip(computer):
    """Pick the first non-loopback IP for a Jamf Pro computer record."""
    ips = computer_ips(computer)
    return ips[0] if ips else "0.0.0.0"


def computer_hostnames(computer):
    """Walk a Jamf Pro computer record for hostname candidates.

    Modern records expose ``general.name`` plus the
    ``hardware.serialNumber`` / ``hardware.modelIdentifier``
    projection (operators often pivot on the serial as a
    secondary hostname-like key).  Classic records only carry
    ``name``; fall back to that when the modern sections are
    absent.
    """
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

    if not isinstance(computer, dict):
        return out

    general = _general(computer)
    for key in ("name", "displayName", "computerName"):
        add(_flatten_string(general.get(key)))
    for key in ("name", "computer_name", "displayName"):
        add(_flatten_string(computer.get(key)))

    hardware = _hardware(computer)
    for key in ("serialNumber", "serial_number"):
        add(_flatten_string(hardware.get(key)))
    for key in ("serial_number", "serialNumber"):
        add(_flatten_string(computer.get(key)))
    for key in ("modelIdentifier", "model_identifier"):
        add(_flatten_string(hardware.get(key)))

    return out


def computer_mac(computer):
    if not isinstance(computer, dict):
        return ""
    hardware = _hardware(computer)
    for key in ("macAddress", "mac_address", "altMacAddress", "alt_mac_address"):
        v = hardware.get(key)
        if v:
            s = _flatten_string(v)
            if s:
                return s
    for key in ("mac_address", "macAddress", "wifi_mac_address", "wifiMacAddress"):
        v = computer.get(key)
        if v:
            s = _flatten_string(v)
            if s:
                return s
    return ""


def computer_os(computer):
    """Build the ``host.os`` string from Jamf Pro's OS projection."""
    if not isinstance(computer, dict):
        return ""
    bits = []
    os_section = _operating_system(computer)
    for key in ("name", "osName"):
        v = _flatten_string(os_section.get(key))
        if v:
            bits.append(v)
            break
    for key in ("version", "osVersion"):
        v = _flatten_string(os_section.get(key))
        if v:
            bits.append(v)
            break
    for key in ("build", "osBuild"):
        v = _flatten_string(os_section.get(key))
        if v:
            bits.append(v)
            break
    hardware = _hardware(computer)
    for key in ("make", "manufacturer"):
        v = _flatten_string(hardware.get(key))
        if v:
            bits.append(v)
            break
    for key in ("model",):
        v = _flatten_string(hardware.get(key))
        if v:
            bits.append(v)
            break
    if not bits:
        general = _general(computer)
        for key in ("platform",):
            v = _flatten_string(general.get(key))
            if v:
                bits.append(v)
                break
    return " ".join(bits)


def computer_id(computer):
    if not isinstance(computer, dict):
        return ""
    for key in ("id", "computerId"):
        v = computer.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    general = _general(computer)
    for key in ("id",):
        v = general.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def mobile_id(device):
    if not isinstance(device, dict):
        return ""
    for key in ("id", "mobileDeviceId", "mobile_device_id"):
        v = device.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def mobile_ip(device):
    """Pick the first non-loopback IP for a Jamf Pro mobile-device record.

    Mobile devices CAN expose their last-known IP under the
    Classic API's record (``ip_address`` / ``wifi_ip`` /
    ``cellular_ip``); when none are present we fall back to the
    ``0.0.0.0`` sentinel — mobile records aren't always IP-keyed.
    """
    if not isinstance(device, dict):
        return "0.0.0.0"
    for key in (
        "ip_address",
        "ipAddress",
        "wifi_ip",
        "wifiIp",
        "cellular_ip",
        "cellularIp",
        "lastReportedIp",
    ):
        v = _flatten_string(device.get(key))
        if v and v not in ("0.0.0.0", "127.0.0.1", "::1"):
            return v
    return "0.0.0.0"


def mobile_hostnames(device):
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

    if not isinstance(device, dict):
        return out

    for key in ("name", "device_name", "deviceName", "displayName", "udid"):
        add(_flatten_string(device.get(key)))
    for key in ("serial_number", "serialNumber"):
        add(_flatten_string(device.get(key)))
    return out


def mobile_mac(device):
    if not isinstance(device, dict):
        return ""
    for key in (
        "wifi_mac_address",
        "wifiMacAddress",
        "mac_address",
        "macAddress",
        "bluetooth_mac_address",
        "bluetoothMacAddress",
    ):
        v = device.get(key)
        if v:
            s = _flatten_string(v)
            if s:
                return s
    return ""


def mobile_os(device):
    """Build the ``host.os`` string for a Jamf Pro mobile-device record."""
    if not isinstance(device, dict):
        return ""
    bits = []
    for key in ("os_type", "osType", "model_display", "modelDisplay", "model", "model_identifier", "modelIdentifier"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    for key in ("os_version", "osVersion", "model_identifier", "modelIdentifier"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    for key in ("model", "model_display", "modelDisplay"):
        v = _flatten_string(device.get(key))
        if v and v not in bits:
            bits.append(v)
            break
    return " ".join(bits)


def collect_cves(item):
    """Walk a Jamf Pro item for CVE-* ids.

    Jamf Pro doesn't ship CVE attribution natively on inventory
    records (it's an MDM, not a vuln scanner) but operators
    occasionally paste CVEs into notes / asset tag / extension
    attribute strings to track patching state — we scan the
    common free-text projections plus any nested extension-
    attribute dicts for refs.
    """
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

    general = _general(item) if "general" in item else {}
    for source in (item, general):
        if not isinstance(source, dict):
            continue
        for key in (
            "notes",
            "name",
            "assetTag",
            "asset_tag",
            "barcode1",
            "barcode2",
            "remoteManagement",
            "siteName",
            "site_name",
            "comments",
            "displayName",
            "description",
        ):
            scan(source.get(key))

    for key in ("extensionAttributes", "extension_attributes"):
        attrs = item.get(key)
        if isinstance(attrs, list):
            for entry in attrs:
                if not isinstance(entry, dict):
                    continue
                for v in entry.values():
                    if isinstance(v, str):
                        scan(v)
                    elif isinstance(v, list):
                        for sub in v:
                            scan(sub)

    return found


def collect_refs(item, entity_type):
    """Walk a Jamf Pro record for advisory URLs / pivots."""
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

    if not isinstance(item, dict):
        return refs

    if entity_type == "computer":
        cid = computer_id(item)
        if cid:
            add(f"Jamf-Id: {cid}")
        general = _general(item)
        hardware = _hardware(item)
        ul = _user_and_location(item)

        udid = _flatten_string(item.get("udid") or general.get("udid"))
        if udid:
            add(f"Jamf-Udid: {udid}")
        serial = _flatten_string(
            hardware.get("serialNumber")
            or hardware.get("serial_number")
            or item.get("serial_number")
            or item.get("serialNumber")
        )
        if serial:
            add(f"Jamf-Serial: {serial}")
        model = _flatten_string(hardware.get("model") or hardware.get("modelIdentifier"))
        if model:
            add(f"Jamf-Model: {model}")
        platform = _flatten_string(general.get("platform") or item.get("platform"))
        if platform:
            add(f"Jamf-Platform: {platform}")
        for key in ("lastContactTime", "last_contact_time", "lastReportDateUtc", "last_report_date_utc"):
            v = _flatten_string(general.get(key))
            if v:
                add(f"Jamf-LastContact: {v}")
                break
        user = _flatten_string(ul.get("username") or ul.get("realname") or ul.get("email"))
        if user:
            add(f"Jamf-User: {user}")
        dept = _flatten_string(
            ul.get("departmentId") or ul.get("department_id") or ul.get("departmentName") or ul.get("department")
        )
        if dept:
            add(f"Jamf-Department: {dept}")
        building = _flatten_string(
            ul.get("buildingId") or ul.get("building_id") or ul.get("buildingName") or ul.get("building")
        )
        if building:
            add(f"Jamf-Building: {building}")
        site = _flatten_string(
            general.get("site") or general.get("siteName") or general.get("site_name") or item.get("site")
        )
        if site:
            add(f"Jamf-Site: {site}")
    else:
        mid = mobile_id(item)
        if mid:
            add(f"Jamf-Id: {mid}")
        udid = _flatten_string(item.get("udid"))
        if udid:
            add(f"Jamf-Udid: {udid}")
        serial = _flatten_string(item.get("serial_number") or item.get("serialNumber"))
        if serial:
            add(f"Jamf-Serial: {serial}")
        model = _flatten_string(
            item.get("model")
            or item.get("model_display")
            or item.get("modelDisplay")
            or item.get("model_identifier")
            or item.get("modelIdentifier")
        )
        if model:
            add(f"Jamf-Model: {model}")
        user = _flatten_string(
            item.get("username") or item.get("user") or item.get("real_name") or item.get("realName")
        )
        if user:
            add(f"Jamf-User: {user}")
        dev_type = _flatten_string(item.get("os_type") or item.get("osType") or item.get("type"))
        if dev_type:
            add(f"Jamf-Type: {dev_type}")
        for key in ("last_inventory_update", "lastInventoryUpdate", "last_backup_time", "lastBackupTime"):
            v = _flatten_string(item.get(key))
            if v:
                add(f"Jamf-LastContact: {v}")
                break

    return refs


def build_asset_vulnerability(item, entity_type, device_type_arg):
    """Build a Faraday vulnerability dict for one Jamf Pro record."""
    if entity_type == "computer":
        hostnames = computer_hostnames(item)
        primary = (
            hostnames[0]
            if hostnames
            else (computer_ip(item) if computer_ip(item) != "0.0.0.0" else "unknown computer")
        )
        label = f"[ASSET-INVENTORY] Jamf Pro computer: {primary}"
    else:
        if isinstance(item, dict):
            primary = (
                _flatten_string(item.get("name"))
                or _flatten_string(item.get("device_name"))
                or _flatten_string(item.get("udid"))
                or "unknown mobile device"
            )
        else:
            primary = "unknown mobile device"
        label = f"[ASSET-INVENTORY] Jamf Pro mobile device: {primary}"

    desc_parts = []
    if isinstance(item, dict):
        for key in sorted(item.keys()):
            v = item.get(key)
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"{key}: {_serialise(v)}")
            else:
                desc_parts.append(f"{key}: {v}")
    if device_type_arg:
        desc_parts.append(f"jamf_device_type: {device_type_arg}")

    cves = collect_cves(item) if isinstance(item, dict) else []
    refs = collect_refs(item, entity_type)

    external_id = ""
    if isinstance(item, dict):
        if entity_type == "computer":
            external_id = computer_id(item)
        else:
            external_id = mobile_id(item)
    if not external_id:
        external_id = label

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Jamf Pro records are MDM inventory entries, not actionable "
            "vulnerabilities.  Cross-check the device against the other "
            "agents' findings (EDR / EASM / vuln scanners) — anything "
            "reported against this Jamf Pro id / udid / serial indicates "
            "a real exposure on a known managed endpoint.  Decommission "
            "or unenroll the device in Jamf Pro if it should no longer "
            "appear in the managed fleet."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["jamf_pro", "asset-inventory", entity_type],
    }


def build_host_from_computer(computer_record, device_type_arg):
    """Build a Faraday host dict from a Jamf Pro computer record."""
    if computer_record is None or not isinstance(computer_record, dict):
        return None

    ip = computer_ip(computer_record)
    hostnames = computer_hostnames(computer_record)
    mac = computer_mac(computer_record)
    os_str = computer_os(computer_record)

    desc_parts = []
    general = _general(computer_record)
    hardware = _hardware(computer_record)
    ul = _user_and_location(computer_record)
    for key in ("platform", "assetTag", "lastContactTime", "lastEnrolledDate", "siteName", "site"):
        v = general.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")
    for key in ("make", "model", "modelIdentifier", "totalRamMegabytes"):
        v = hardware.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")
    for key in ("username", "department", "building", "room"):
        v = ul.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")
    if not desc_parts:
        for key in sorted(computer_record.keys()):
            v = computer_record.get(key)
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"{key}={_serialise(v)}")
            else:
                desc_parts.append(f"{key}={v}")

    vuln = build_asset_vulnerability(computer_record, "computer", device_type_arg)
    return {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln] if vuln else [],
    }


def build_host_from_mobile(mobile_record, device_type_arg):
    """Build a Faraday host dict from a Jamf Pro mobile-device record."""
    if mobile_record is None or not isinstance(mobile_record, dict):
        return None

    ip = mobile_ip(mobile_record)
    hostnames = mobile_hostnames(mobile_record)
    mac = mobile_mac(mobile_record)
    os_str = mobile_os(mobile_record)

    desc_parts = []
    for key in (
        "device_name",
        "udid",
        "serial_number",
        "model",
        "model_display",
        "model_identifier",
        "os_type",
        "os_version",
        "username",
        "phone_number",
        "last_inventory_update",
    ):
        v = mobile_record.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    vuln = build_asset_vulnerability(mobile_record, "mobile", device_type_arg)
    return {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln] if vuln else [],
    }


def merge_computers(modern_records, classic_records):
    """De-duplicate the modern + classic computer walks by id.

    Modern ``/api/v1/computers-inventory`` records carry the rich
    payload (general / hardware / operatingSystem / userAndLocation
    sections); classic ``/JSSResource/computers`` records only
    carry id + name.  We keep the modern record when both surfaces
    return the same id (modern is strictly richer) and fall through
    to the classic record only when the modern walk missed it
    (older Jamf Pro tenants where the modern API isn't enabled).
    The walk-order is stable so the output is deterministic across
    runs.
    """
    seen = set()
    out = []
    for record in modern_records or []:
        if not isinstance(record, dict):
            continue
        cid = computer_id(record)
        if cid:
            seen.add(cid)
        out.append(record)
    for record in classic_records or []:
        if not isinstance(record, dict):
            continue
        cid = computer_id(record)
        if cid and cid in seen:
            continue
        if cid:
            seen.add(cid)
        out.append(record)
    return out


def exchange_oauth_token(requests_module, host, client_id, client_secret):
    """Swap OAuth2 client credentials for a Bearer access token.

    Jamf Pro uses OAuth2 client-credentials.  POST
    ``/api/oauth/token`` with
    ``client_id=<id>&client_secret=<secret>&grant_type=client_credentials``
    form data returns ``{"access_token": "...", "expires_in": N,
    "scope": "...", "token_type": "Bearer"}``.  Returns the empty
    string on auth failure so the caller can ``sys.exit(1)`` with
    a descriptive log message.
    """
    url = build_oauth_token_url(host)
    headers = {"Accept": "application/json"}
    data = {
        "client_id": client_id or "",
        "client_secret": client_secret or "",
        "grant_type": "client_credentials",
    }
    try:
        resp = requests_module.post(
            url,
            data=data,
            headers=headers,
            timeout=TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        return ""
    if resp.status_code == 401:
        log("Jamf Pro OAuth rejected (401). Check JAMF_CLIENT_ID / JAMF_CLIENT_SECRET.")
        return ""
    if resp.status_code == 403:
        log("Jamf Pro OAuth rejected (403). Check the OAuth client's role / scope.")
        return ""
    if resp.status_code >= 400:
        log(f"Jamf Pro OAuth failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return ""
    try:
        payload = resp.json()
    except ValueError:
        log(f"Jamf Pro OAuth response was not JSON ({url})")
        return ""
    token = extract_access_token(payload)
    if not token:
        log("Jamf Pro OAuth response had no access_token field")
    return token


def fetch_modern_pages(
    requests_module, url, headers, page_size, max_pages, sections=DEFAULT_SECTIONS, extra_params=None
):
    """Walk a /api/v1/computers-inventory envelope page-by-page.

    Pagination is page-based via ``page`` (0-indexed) + ``page-size``
    query parameters.  We page until either ``len(results) <
    page-size`` or ``max_pages`` is reached.  401 short-circuits the
    whole executor (token is invalid); 403 / 429 / 5xx stop
    pagination on the surface and return what we have.
    """
    out = []
    page = 0
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_modern_query(
            page,
            page_size=page_size,
            sections=sections,
            extra=extra_params,
        )
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Jamf Pro request rejected (401). Access token expired or invalid.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Jamf Pro request rejected (403). Check the OAuth client's role / scope.")
            return out
        if resp.status_code == 429:
            log("Jamf Pro rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Jamf Pro request failed ({resp.status_code}) for {full_url}: " f"{resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Jamf Pro response was not JSON ({full_url})")
            return out
        records = extract_modern_records(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < page_size:
            break
        page += 1
    if walked >= max_pages and len(records) >= page_size:
        log(f"hit JAMF_PAGES={max_pages}; stopping pagination on /computers-inventory")
    return out


def fetch_classic(requests_module, url, headers, extractor):
    """Issue one GET against a Classic /JSSResource/ list endpoint.

    The Classic API doesn't paginate the list endpoints — a single
    GET returns the whole tenant's records.  401 short-circuits the
    whole executor (token is invalid); 403 / 429 / 5xx return an
    empty list (the dispatcher tolerates one surface failing without
    aborting the whole run).
    """
    try:
        resp = requests_module.get(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return []
    if resp.status_code == 401:
        log("Jamf Pro Classic request rejected (401). Access token expired or invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Jamf Pro Classic request rejected (403) for {url}.")
        return []
    if resp.status_code == 429:
        log(f"Jamf Pro Classic rate-limited (429) for {url}.")
        return []
    if resp.status_code >= 400:
        log(f"Jamf Pro Classic request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return []
    try:
        payload = resp.json()
    except ValueError:
        log(f"Jamf Pro Classic response was not JSON ({url})")
        return []
    return extractor(payload)


def main():
    started = time.time()

    device_type = validate_device_type(env("EXECUTOR_CONFIG_JAMF_DEVICE_TYPE"))
    pages = validate_pages(env("JAMF_PAGES"))

    host = env("JAMF_HOST", required=True)
    client_id = env("JAMF_CLIENT_ID", required=True)
    client_secret = env("JAMF_CLIENT_SECRET", required=True)

    if not normalize_base_url(host):
        log("JAMF_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    access_token = exchange_oauth_token(requests, host, client_id, client_secret)
    if not access_token:
        log("Could not obtain Jamf Pro access token; aborting")
        sys.exit(1)

    headers = auth_headers(access_token)

    computer_records = []
    mobile_records = []

    if device_type in ("computer", "both"):
        modern_records = fetch_modern_pages(
            requests,
            build_modern_computers_inventory_url(host),
            headers,
            PER_PAGE,
            max_pages=pages,
        )
        classic_computers = fetch_classic(
            requests,
            build_classic_computers_url(host),
            headers,
            extract_classic_computers,
        )
        computer_records = merge_computers(modern_records, classic_computers)

    if device_type in ("mobile", "both"):
        mobile_records = fetch_classic(
            requests,
            build_classic_mobiledevices_url(host),
            headers,
            extract_classic_mobiledevices,
        )

    log(
        f"Processing {len(computer_records)} Jamf Pro computers + "
        f"{len(mobile_records)} mobile devices "
        f"(device_type={device_type!r}, pages={pages})"
    )

    hosts_out = []
    for record in computer_records:
        built = build_host_from_computer(record, device_type)
        if built is not None:
            hosts_out.append(built)
    for record in mobile_records:
        built = build_host_from_mobile(record, device_type)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "jamf_pro",
            "command": "jamf_pro",
            "params": f"device_type={device_type},pages={pages}",
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
