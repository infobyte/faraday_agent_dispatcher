#!/usr/bin/env python
"""Device42 CMDB asset-inventory importer.

Pulls managed devices and tracked IP records from a Device42 CMDB
appliance via the Device42 v1 REST API and emits Faraday bulk-create
JSON to stdout.  Each Device42 ``device`` becomes one Faraday host —
the device's first non-loopback IP from ``ip_addresses`` maps onto
``host.ip`` (loopback / ``0.0.0.0`` / ``::1`` are explicitly skipped),
the ``name`` / ``serial_no`` / ``fqdn`` projection lands on
``host.hostnames``, ``mac_addresses`` lands on ``host.mac``, the
``os`` / ``hardware`` / ``manufacturer`` chain joins onto ``host.os``,
and the asset itself becomes one Faraday vulnerability with the
``[ASSET-INVENTORY]`` engine prefix.  Each tracked IP record from
``/api/1.0/ips/`` that doesn't already pivot off a device id seen in
``/api/1.0/devices/all/`` becomes one synthetic host (the IP itself
maps to ``host.ip``, the label or attached subnet lands on
``host.hostnames``, and the record carries one ``[ASSET-INVENTORY]``
vulnerability tagged ``[device42, asset-inventory, ip]``).

Endpoints used:
  GET {D42_HOST}/api/1.0/devices/all/?limit=100&offset=N(&building=...)
      -> the canonical Device42 device inventory.  Returns the JSON
      envelope ``{"Devices": [...], "total_count": N, "limit": M,
      "offset": K}`` (Device42 keeps the ``Devices`` key uppercased
      for historic reasons; we also accept ``devices`` /
      ``data`` / ``results`` / ``items`` for federated / future
      shapes).  Each device record carries ``device_id``, ``name``,
      ``serial_no``, ``manufacturer``, ``hardware``, ``os``,
      ``service_level``, ``type``, ``tags``, ``customer``,
      ``building``, ``room``, ``rack``, ``last_updated``, ``notes``,
      ``ip_addresses`` (list of {ip, subnet, label, mac_address}),
      and ``mac_addresses`` (list of {mac, port}).  ``D42_BUILDING``
      is forwarded as a server-side ``building`` query-string filter
      so the dispatcher only walks one location's worth of inventory
      per agent run.
  GET {D42_HOST}/api/1.0/ips/?limit=100&offset=N
      -> the IP / address-tracking surface.  Returns
      ``{"ips": [...], "total_count": N, "limit": M, "offset": K}``.
      Each record carries ``ip``, ``subnet``, ``subnet_id``,
      ``device``, ``device_id``, ``mac_address``, ``type``,
      ``label``, ``notes``, ``last_updated``.  IPs that already
      pivot off a ``device_id`` returned by the devices surface are
      skipped (Device42 emits the same IP under both surfaces) — the
      remainder become synthetic hosts so the workspace still
      surfaces loose IP records (reservations, DHCP, etc.).

Pagination is offset-based on both surfaces (``limit`` + ``offset``
in the query string); walked page-by-page until ``len(records) <
limit`` or the env-only ``D42_PAGES`` cap is reached (default 5,
clamped to [1, 50]).  ``D42_LIMIT`` is the per-page record cap (1
to MAX_PER_PAGE=1000; default 100).

Auth: Device42's v1 REST API uses HTTP Basic Authentication — the
dispatcher carries the credentials in the standard
``Authorization: Basic <base64(D42_USER:D42_PASSWORD)>`` header on
every ``/api/1.0/`` call.  ``D42_HOST`` is the Device42 appliance
host (e.g. ``cmdb.mycorp.local`` or ``https://cmdb.mycorp.com``);
on-prem self-signed deployments are common so the executor warns
(but does not retry) on TLS failures.

Severity is always ``info`` because Device42 hits are inventory
entries, not vulnerability findings — operators correlate against
the EDR / EASM / vuln-scanner agents' findings via the
``Device42-Id`` / ``Device42-Serial`` / ``Device42-Type`` /
``Device42-Building`` / ``Device42-Customer`` / ``Device42-LastUpdated``
refs.  Tags: [device42, asset-inventory, device|ip].
"""

import base64
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
DEFAULT_PER_PAGE = 100
MAX_PER_PAGE = 1000
DEFAULT_PAGES = 5
MAX_PAGES = 50


def log(msg):
    print(f"{datetime.utcnow()} - Device42: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on D42_HOST.

    No default — the Device42 appliance host is operator-specific so
    we sys.exit(1) upstream in ``main`` when the env var is missing.
    Here we just whitespace-trim, strip trailing slashes and add
    ``https://`` when the operator pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_building(value):
    """Validate D42_BUILDING (the operator-supplied building filter).

    None / blank -> ``""`` (no narrowing; every device in the
    appliance is walked).  Whitespace is trimmed.  Anything else is
    forwarded verbatim as a ``?building=<value>`` query-string filter
    on ``/api/1.0/devices/all/``.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_limit(value):
    """Validate D42_LIMIT (the per-page record cap).

    None / blank -> DEFAULT_PER_PAGE.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PER_PAGE] so a stray
    operator input can't either ask Device42 for absurd page sizes or
    flat-line the walk with limit=0.
    """
    if value is None or value == "":
        return DEFAULT_PER_PAGE
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"D42_LIMIT '{value}' not numeric; defaulting to {DEFAULT_PER_PAGE}")
        return DEFAULT_PER_PAGE
    if n < 1:
        return 1
    if n > MAX_PER_PAGE:
        log(f"D42_LIMIT {n} above MAX_PER_PAGE={MAX_PER_PAGE}; clamping")
        return MAX_PER_PAGE
    return n


def validate_pages(value):
    """Validate D42_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Device42 appliance.  Not exposed as a manifest argument (the
    playbook only lists D42_BUILDING + D42_LIMIT) but read from the
    env so a tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"D42_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"D42_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_devices_url(host):
    return f"{normalize_base_url(host)}/api/1.0/devices/all/"


def build_ips_url(host):
    return f"{normalize_base_url(host)}/api/1.0/ips/"


def build_query(limit, offset, extra=None):
    """Build the canonical Device42 paging query string.

    ``extra`` is an optional dict of additional filter params (e.g.
    ``{"building": "DC-East"}``).  Values are URL-encoded and
    blanks are dropped so the resulting query string never carries
    ``building=`` with an empty value (Device42 rejects that as a
    400).
    """
    params = [("limit", str(int(limit))), ("offset", str(int(offset)))]
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            s = str(v).strip()
            if not s:
                continue
            params.append((str(k), s))
    return urllib.parse.urlencode(params)


def basic_auth_header(user, password):
    """Build the canonical Authorization: Basic header string.

    Device42's v1 REST API uses HTTP Basic Auth — we build the
    header inline rather than relying on ``requests.auth.HTTPBasicAuth``
    so test fixtures + unit checks can assert on the exact wire
    format (requests will strip a manually-built Authorization
    header on cross-host redirects, which we don't want).
    """
    raw = f"{user or ''}:{password or ''}".encode("utf-8")
    return f"Basic {base64.b64encode(raw).decode('ascii')}"


def auth_headers(user, password):
    return {
        "Authorization": basic_auth_header(user, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_devices(body):
    """Pull the device list from a Device42 v1 envelope.

    Device42's ``/devices/all/`` returns ``{"Devices": [...], ...}``
    with the historic capitalised key.  Federated / future stacks may
    use ``devices`` / ``data`` / ``results`` / ``items`` — accept all
    of them for resilience plus root-list passthrough.
    """
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("Devices", "devices", "data", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_ips(body):
    """Pull the ip-record list from a Device42 v1 envelope."""
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("ips", "IPs", "ip_addresses", "data", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_total(body):
    if not isinstance(body, dict):
        return None
    for key in ("total_count", "totalCount", "total", "count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


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
    """Coerce a single Device42 attribute value into a printable string."""
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
        for key in ("ip", "address", "mac", "name", "value"):
            v = value.get(key)
            if v:
                return _flatten_string(v)
    return ""


def _flatten_strings(value):
    """Coerce a Device42 attribute value into a deduped string list."""
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
            for key in ("ip", "address", "mac", "name", "value"):
                v = text.get(key)
                if v is not None:
                    add(v)

    add(value)
    return out


def device_ips(device):
    """Walk a Device42 device record for IP candidates.

    Device42 projects IPs through ``ip_addresses`` (a list of
    {ip, subnet, label, mac_address} dicts) on the canonical
    ``/devices/all/`` surface; some legacy responses surface a flat
    ``ip`` / ``ip_address`` string.  Loopback / zero are skipped.
    """
    if not isinstance(device, dict):
        return []
    candidates = []
    raw = device.get("ip_addresses")
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                v = entry.get("ip") or entry.get("address") or entry.get("ip_address")
                if v:
                    candidates.extend(_flatten_strings(v))
            elif isinstance(entry, str):
                candidates.extend(_flatten_strings(entry))
    for key in ("ip", "ip_address", "primary_ip", "management_ip"):
        v = device.get(key)
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


def device_ip(device):
    """Pick the first non-loopback IP for a Device42 device."""
    ips = device_ips(device)
    return ips[0] if ips else "0.0.0.0"


def device_hostnames(device):
    """Walk a Device42 device for hostname candidates."""
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

    for key in ("name", "fqdn", "device_name", "hostname"):
        for n in _flatten_strings(device.get(key)):
            add(n)
    serial = _flatten_string(device.get("serial_no") or device.get("serial"))
    if serial:
        add(serial)
    return out


def device_mac(device):
    if not isinstance(device, dict):
        return ""
    raw = device.get("mac_addresses")
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                v = entry.get("mac") or entry.get("address") or entry.get("mac_address")
                if v:
                    s = _flatten_string(v)
                    if s:
                        return s
            elif isinstance(entry, str):
                s = entry.strip()
                if s:
                    return s
    raw_ips = device.get("ip_addresses")
    if isinstance(raw_ips, list):
        for entry in raw_ips:
            if isinstance(entry, dict):
                v = entry.get("mac_address") or entry.get("mac")
                if v:
                    s = _flatten_string(v)
                    if s:
                        return s
    for key in ("mac", "mac_address", "primary_mac"):
        v = device.get(key)
        if v:
            s = _flatten_string(v)
            if s:
                return s
    return ""


def device_os(device):
    """Build the ``host.os`` string from Device42's OS projection."""
    if not isinstance(device, dict):
        return ""
    bits = []
    for key in ("os", "os_name", "operating_system"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    for key in ("os_version", "os_version_no", "os_release"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    for key in ("hardware", "hardware_name", "model"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    for key in ("manufacturer", "vendor"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    return " ".join(bits)


def collect_cves(item):
    """Walk a Device42 item for CVE-* ids.

    Device42 doesn't surface CVE-keyed findings on the canonical
    devices/ips endpoints, but operators sometimes paste CVEs into
    ``notes`` / ``tags`` so we still scan those for completeness.
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

    for key in ("notes", "label", "name", "description"):
        scan(item.get(key))

    tags = item.get("tags")
    if isinstance(tags, list):
        for entry in tags:
            if isinstance(entry, str):
                scan(entry)
    elif isinstance(tags, str):
        for chunk in tags.split(","):
            scan(chunk)

    return found


def collect_refs(item, entity_type):
    """Walk a Device42 record for advisory URLs / pivots."""
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

    if entity_type == "device":
        did = item.get("device_id") or item.get("id")
        if did is not None and str(did).strip():
            add(f"Device42-Id: {str(did).strip()}")
        serial = _flatten_string(item.get("serial_no") or item.get("serial"))
        if serial:
            add(f"Device42-Serial: {serial}")
        dtype = _flatten_string(item.get("type") or item.get("device_type"))
        if dtype:
            add(f"Device42-Type: {dtype}")
        building = _flatten_string(item.get("building"))
        if building:
            add(f"Device42-Building: {building}")
        customer = _flatten_string(item.get("customer"))
        if customer:
            add(f"Device42-Customer: {customer}")
        last_updated = _flatten_string(item.get("last_updated"))
        if last_updated:
            add(f"Device42-LastUpdated: {last_updated}")
        tags = item.get("tags")
        if isinstance(tags, list) and tags:
            joined = ",".join(str(t) for t in tags if t)
            if joined:
                add(f"Device42-Tags: {joined}")
    else:
        iid = item.get("id") or item.get("ip_id")
        if iid is not None and str(iid).strip():
            add(f"Device42-IpId: {str(iid).strip()}")
        subnet = _flatten_string(item.get("subnet"))
        if subnet:
            add(f"Device42-Subnet: {subnet}")
        ip_type = _flatten_string(item.get("type"))
        if ip_type:
            add(f"Device42-IpType: {ip_type}")
        label = _flatten_string(item.get("label"))
        if label:
            add(f"Device42-Label: {label}")
        last_updated = _flatten_string(item.get("last_updated"))
        if last_updated:
            add(f"Device42-LastUpdated: {last_updated}")

    return refs


def build_asset_vulnerability(item, entity_type, building):
    """Build a Faraday vulnerability dict for one Device42 record."""
    if entity_type == "device":
        hostnames = device_hostnames(item)
        primary = (
            hostnames[0] if hostnames else (device_ip(item) if device_ip(item) != "0.0.0.0" else "unknown device")
        )
        label = f"[ASSET-INVENTORY] Device42 device: {primary}"
    else:
        ip = _flatten_string(item.get("ip") or item.get("address")) if isinstance(item, dict) else ""
        label_subject = ip or (_flatten_string(item.get("label")) if isinstance(item, dict) else "")
        label = f"[ASSET-INVENTORY] Device42 ip: {label_subject or 'unknown ip'}"

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
    if building:
        desc_parts.append(f"d42_building: {building}")

    cves = collect_cves(item) if isinstance(item, dict) else []
    refs = collect_refs(item, entity_type)

    external_id = ""
    if isinstance(item, dict):
        if entity_type == "device":
            external_id = str(item.get("device_id") or item.get("id") or "")
        else:
            external_id = str(item.get("id") or item.get("ip_id") or item.get("ip") or "")
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
            "Device42 records are CMDB inventory entries, not "
            "vulnerabilities.  Cross-check the asset against the "
            "other agents' findings (EDR / EASM / vuln scanners) — "
            "anything reported against this asset id indicates a "
            "real exposure on a known managed device.  Decommission "
            "or reclassify the asset in Device42 if it should no "
            "longer appear in the inventory."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["device42", "asset-inventory", entity_type],
    }


def build_host_from_device(device, building):
    """Build a Faraday host dict from a Device42 device record."""
    if device is None or not isinstance(device, dict):
        return None

    ip = device_ip(device)
    hostnames = device_hostnames(device)
    mac = device_mac(device)
    os_str = device_os(device)

    desc_parts = []
    for key in ("type", "service_level", "building", "room", "rack", "customer", "tags", "last_updated"):
        v = device.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    vuln = build_asset_vulnerability(device, "device", building)
    return {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln] if vuln else [],
    }


def build_host_from_ip(record, building):
    """Build a Faraday host dict for a loose Device42 IP record.

    Used for IPs in ``/api/1.0/ips/`` that don't already pivot off a
    device id we've already mapped — typically reservations, DHCP
    pool entries, and VIPs that don't carry a device association.
    """
    if record is None or not isinstance(record, dict):
        return None
    ip = _flatten_string(record.get("ip") or record.get("address"))
    if not ip:
        ip = "0.0.0.0"
    hostnames = []
    label = _flatten_string(record.get("label"))
    if label:
        hostnames.append(label)
    subnet = _flatten_string(record.get("subnet"))
    if subnet and subnet not in hostnames:
        hostnames.append(subnet)
    mac = _flatten_string(record.get("mac_address") or record.get("mac"))
    vuln = build_asset_vulnerability(record, "ip", building)
    return {
        "ip": ip,
        "os": "",
        "hostnames": hostnames,
        "mac": mac,
        "description": "Device42 IP record",
        "vulnerabilities": [vuln] if vuln else [],
    }


def device_id_of(device):
    """Return a stable id for the device, if any."""
    if not isinstance(device, dict):
        return None
    for key in ("device_id", "id"):
        v = device.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return None


def fetch_pages(requests_module, url, headers, extractor, limit, max_pages, extra_params=None):
    """Walk a Device42 v1 ``/devices/all/`` or ``/ips/`` envelope.

    Pagination is offset-based via ``limit`` + ``offset`` query
    parameters.  We page until either ``len(records) < limit`` or
    ``max_pages`` is reached.  401 short-circuits the whole executor
    (credentials are wrong); 403 / 429 / 5xx stop pagination on the
    surface and return what we have.
    """
    out = []
    offset = 0
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(limit, offset, extra=extra_params)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Device42 request rejected (401). Check D42_USER / D42_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Device42 request rejected (403). Check the user's role/scope.")
            return out
        if resp.status_code == 429:
            log("Device42 rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Device42 request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Device42 response was not JSON ({full_url})")
            return out
        records = extractor(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < limit:
            break
        offset += limit
    if walked >= max_pages and len(records) >= limit:
        log(f"hit D42_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    building = validate_building(env("EXECUTOR_CONFIG_D42_BUILDING"))
    limit = validate_limit(env("EXECUTOR_CONFIG_D42_LIMIT"))
    pages = validate_pages(env("D42_PAGES"))

    host = env("D42_HOST", required=True)
    user = env("D42_USER", required=True)
    password = env("D42_PASSWORD", required=True)

    if not normalize_base_url(host):
        log("D42_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(user, password)
    devices_url = build_devices_url(host)
    ips_url = build_ips_url(host)

    extra = {"building": building} if building else None
    device_records = fetch_pages(
        requests,
        devices_url,
        headers,
        extract_devices,
        limit,
        max_pages=pages,
        extra_params=extra,
    )
    ip_records = fetch_pages(
        requests,
        ips_url,
        headers,
        extract_ips,
        limit,
        max_pages=pages,
    )

    log(
        f"Processing {len(device_records)} Device42 devices + {len(ip_records)} IPs "
        f"(building={building!r}, limit={limit}, pages={pages})"
    )

    seen_device_ids = set()
    hosts_out = []
    for device in device_records:
        built = build_host_from_device(device, building)
        if built is not None:
            hosts_out.append(built)
            did = device_id_of(device)
            if did:
                seen_device_ids.add(did)

    for record in ip_records:
        ref_did = record.get("device_id") if isinstance(record, dict) else None
        if ref_did is not None and str(ref_did).strip() in seen_device_ids:
            continue
        built = build_host_from_ip(record, building)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "device42",
            "command": "device42",
            "params": (f"building={building}," f"limit={limit}," f"pages={pages}"),
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
