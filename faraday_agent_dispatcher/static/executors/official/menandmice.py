#!/usr/bin/env python
"""Men&Mice (BlueCat Micetro) DDI importer.

Pulls managed device inventory and IPAM records from a Men&Mice
Web Services (mmws) appliance via the Men&Mice REST API and
emits Faraday bulk-create JSON to stdout.  Men&Mice — now
shipped as BlueCat Micetro — is an enterprise DDI (DNS, DHCP,
IPAM) management platform that sits in front of Microsoft DNS,
ISC BIND, Microsoft DHCP, ISC DHCP and a handful of cloud-DNS
backends and presents one unified REST surface for the whole
estate.  The Web Services component (``mmws``) is the HTTPS
front-end the REST API binds to; ``/mmws/api/...`` is the
canonical resource prefix.  So this executor is the network-
management cross-reference feed Faraday operators correlate
the EDR / EASM / vuln-scanner agents' findings against to
confirm whether a vulnerable IP is a Men&Mice-tracked managed
endpoint (and therefore an in-scope IPAM record the network
team owns) or an unmanaged stray that wandered onto a tracked
range.  Sibling to the :mod:`infoblox_ddi` executor (Infoblox
NIOS Grid Master) and the :mod:`infoblox_netmri` executor
(Infoblox NetMRI NCM appliance); the three together cover the
major enterprise DDI / NCM platforms feeding the
``network-mgmt`` group.

Each Men&Mice device becomes one Faraday host — device records
ARE network-keyed (every discovered device carries an
``addresses`` projection anchoring the record to one or more
tracked IP endpoints) so the executor lifts the first
``addresses[].address`` onto ``host.ip`` when present, falls
back to the bare ``address`` slot for legacy single-address
projections, and falls back to the ``0.0.0.0`` sentinel for
the rare placeholder records that slipped past discovery
without a usable management address.  The ``name`` projection
lands on ``host.hostnames``; the ``vendor`` / ``model`` /
``firmwareVersion`` chain joins onto ``host.os``;
``serialNumber`` / ``deviceType`` / ``customProperties``
enrichment lands on ``host.description``; the device record
itself becomes one Faraday vulnerability with the
``[NETWORK]`` engine prefix.  Severity for devices is always
``info`` (managed-inventory entries, not findings).

Each Men&Mice IPAM record becomes one Faraday host on the
record's ``address`` slot when present (IPAM records ARE the
canonical IP-keyed projection — an IPAM record IS an IP
endpoint with DNS / DHCP / discovery metadata bolted on) and
falls back to the ``0.0.0.0`` sentinel for placeholder records
that don't carry an address.  The ``name`` / DNS-record
projections land on ``host.hostnames``; ``state``
(``Assigned`` | ``Free`` | ``Reserved`` | ``Claimed``) /
``lastSeen`` / ``lastDiscoveryDate`` enrichment lands on
``host.description``; the record itself becomes one Faraday
vulnerability with the ``[NETWORK]`` engine prefix.  Severity
is always ``info`` (IPAM inventory entries, not findings).

Endpoints used:
  GET {MM_HOST}/mmws/api/devices?offset=M&limit=N[&filter=...]
      -> the canonical Men&Mice managed-device inventory.
      Returns the Men&Mice envelope
      ``{"result": {"totalResults": N, "devices": [...]}}``
      walked page-by-page via the ``offset`` + ``limit``
      cursor (next request increments ``offset`` by the page
      size) until the returned ``devices`` list is shorter
      than the page size (Men&Mice's documented "no more
      pages" signal — the ``totalResults`` field is
      informational and not load-bearing here) or the env-
      only ``MM_PAGES`` cap is reached (default 5, clamped to
      [1, 50]).  Each record carries ``ref``, ``name``,
      ``type`` (the device's high-level role),
      ``deviceType`` (the SNMP / vendor type label),
      ``vendor`` / ``model`` / ``firmwareVersion``,
      ``serialNumber``, ``addresses`` (list of nested
      ``{address, interfaceName, mac, ...}`` projections —
      one entry per discovered interface), and
      ``customProperties`` (the operator-defined extension
      dictionary).  ``MM_NETWORK`` is NOT forwarded to the
      devices surface — Men&Mice devices don't have a clean
      network-membership filter (device addresses live under
      the ``addresses[]`` projection rather than as a top-
      level field), so the operator's CIDR filter applies to
      the IPAM surface only.
  GET {MM_HOST}/mmws/api/IPAMRecords?offset=M&limit=N[&filter=range=<MM_NETWORK>]
      -> the canonical Men&Mice IPAM record feed.  Same
      envelope shape; each record carries ``ref``,
      ``address`` (the dotted-quad / v6 string anchoring the
      record), ``name``, ``type`` (the IPAM record type),
      ``state`` (``Assigned`` | ``Free`` | ``Reserved`` |
      ``Claimed`` | ``Held``), ``dnsRecords`` (list of nested
      ``{name, type, ttl, data}`` projections — the A / AAAA
      / CNAME records anchored to this address), ``dhcp``
      reservation flag + assigned MAC under
      ``dhcpReservations``, ``lastSeen`` /
      ``lastDiscoveryDate`` discovery timestamps, the
      ``rangeRef`` foreign key into the parent IPAM range,
      and ``customProperties``.  When ``MM_NETWORK`` is set
      the dispatcher forwards it as
      ``?filter=range=<CIDR>`` (Men&Mice's documented IPAM
      filter syntax — operators see the same expression in
      the Web Interface under ``IPAM -> IPAM`` when they
      narrow the address grid to a single range).

Pagination is offset-based via Men&Mice's ``offset`` +
``limit`` cursors.  The first request carries
``?offset=0&limit=100``; each subsequent request increments
``offset`` by the page size until the returned ``<resource>``
list is shorter than the page size (Men&Mice's documented
"no more pages" signal — the ``totalResults`` field is
informational and not load-bearing here) or the env-only
``MM_PAGES`` cap is reached.  ``limit`` is fixed at 100 (a
conservative default; Men&Mice accepts larger pages but smaller
ones keep response sizes manageable for the dispatcher event
loop).

Auth: Men&Mice's REST API supports HTTP Basic Auth.  Operators
provision a service account in the Web Interface under
``Tools -> User Management -> Users`` with a read-only role
(the built-in ``Administrators`` role works, but a custom role
with read access on Devices and IPAM is the least-privilege
fit).  The dispatcher carries credentials on every request as
``Authorization: Basic <base64(user:pass)>``.  ``MM_HOST`` is
the operator's mmws appliance host (e.g.
``mmws.mycorp.com``); ``https://`` is added automatically when
the operator pasted in a bare FQDN.  TLS verification is left
to ``requests`` defaults (operators with self-signed appliance
certs should set ``REQUESTS_CA_BUNDLE`` in the dispatcher env
to point at the appliance CA bundle).

Severity for devices / IPAM records is always ``info`` —
Men&Mice surfaces inventory state, not findings; the value is
the cross-reference signal, not a vulnerability score.  Tags:
[menandmice, network, ddi, ipam, device|ipam-record].
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

TIMEOUT = 60
PER_PAGE = 100  # Men&Mice default page size; appliance accepts larger.
DEFAULT_PAGES = 5
MAX_PAGES = 50

SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - MenAndMice: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on MM_HOST.

    No default — the Men&Mice mmws host is operator-specific so
    we ``sys.exit(1)`` upstream in ``main`` when the env var is
    missing.  Here we just whitespace-trim, strip trailing
    slashes and add ``https://`` when the operator pasted in a
    bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_network(value):
    """Validate MM_NETWORK (operator-supplied IPAM range filter).

    None / blank -> ``""`` (no narrowing; every IPAM record the
    credentials can read is walked).  Whitespace is trimmed.
    Forwarded into the ``?filter=range=<value>`` query
    parameter on the IPAMRecords surface only — Men&Mice IPAM
    ranges are CIDR-keyed (``10.0.0.0/24`` etc.) and the
    filter expression is the canonical "scope to this range"
    pattern operators see in the Web Interface under
    ``IPAM -> IPAM`` when they narrow the address grid.  Not
    forwarded into the devices surface (devices don't have a
    clean network-membership filter — device addresses live
    under the nested ``addresses[]`` projection rather than as
    a top-level field).
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_pages(value):
    """Validate MM_PAGES (per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-
    string; floats are floored.  Clamped to [1, MAX_PAGES] so
    a stray operator input can't fan out into 100k+ requests
    against the Men&Mice mmws.  Not exposed as a manifest
    argument (the playbook only lists MM_NETWORK) but read
    from the env so a tenant-side override can still tune the
    walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"MM_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"MM_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_devices_url(host, network, offset=0):
    """Build the /mmws/api/devices walk URL.

    ``MM_NETWORK`` is intentionally not forwarded here — see
    :func:`validate_network` for the reasoning.  The ``network``
    parameter is accepted for API symmetry with
    :func:`build_ipam_records_url` so ``fetch_all`` can pass
    the same ``build_kwargs`` to both surfaces.
    """
    del network  # accepted for symmetry; not forwarded.
    base = f"{normalize_base_url(host)}" f"/mmws/api/devices"
    params = [f"offset={int(offset)}", f"limit={PER_PAGE}"]
    return f"{base}?{'&'.join(params)}"


def build_ipam_records_url(host, network, offset=0):
    """Build the /mmws/api/IPAMRecords walk URL.

    When ``MM_NETWORK`` is set, forwards it as
    ``?filter=range=<value>`` — Men&Mice's documented IPAM
    filter syntax for scoping to a single range.
    """
    base = f"{normalize_base_url(host)}" f"/mmws/api/IPAMRecords"
    params = [f"offset={int(offset)}", f"limit={PER_PAGE}"]
    if network:
        params.append(f"filter={quote(f'range={network}', safe='=')}")
    return f"{base}?{'&'.join(params)}"


def _str(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value)


def _serialise(obj):
    if obj is None:
        return ""
    if isinstance(obj, (str, int, float)):
        return str(obj)
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(obj)


def _flatten_custom_properties(props):
    """Flatten Men&Mice ``customProperties`` projection.

    Men&Mice surfaces extension attributes either as a flat
    ``{name: value}`` dict or as a list of
    ``{"name": ..., "value": ...}`` entries depending on the
    appliance version.  Both shapes flatten to a
    ``{name: value}`` dict here so the downstream description
    builder can render a uniform ``key=value`` line.
    """
    if isinstance(props, dict):
        return {str(k): v for k, v in props.items()}
    out = {}
    if isinstance(props, list):
        for entry in props:
            if isinstance(entry, dict):
                key = entry.get("name")
                if key is None:
                    continue
                out[str(key)] = entry.get("value")
    return out


def _device_ip(device):
    """Pick a primary IP for a Men&Mice device record.

    Men&Mice surfaces device addresses as a list of nested
    ``{address, interfaceName, mac, ...}`` projections under
    ``addresses``.  We prefer the first non-empty entry and
    fall back to a bare top-level ``address`` slot (some
    legacy projections expose a single address there) and
    then to the sentinel.
    """
    if not isinstance(device, dict):
        return SENTINEL_IP
    slots = device.get("addresses")
    if isinstance(slots, list):
        for entry in slots:
            if isinstance(entry, dict):
                addr = _str(entry.get("address"))
                if addr:
                    return addr
            elif isinstance(entry, str):
                addr = _str(entry)
                if addr:
                    return addr
    addr = _str(device.get("address"))
    if addr:
        return addr
    return SENTINEL_IP


def _device_mac(device):
    """Lift the first ``addresses[].mac`` value when present."""
    if not isinstance(device, dict):
        return ""
    slots = device.get("addresses")
    if isinstance(slots, list):
        for entry in slots:
            if isinstance(entry, dict):
                mac = _str(entry.get("mac"))
                if mac:
                    return mac
    mac = _str(device.get("mac"))
    if mac:
        return mac
    return ""


def device_hostnames(device):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(device, dict):
        add(device.get("name"))
        add(device.get("hostname"))
    return out


def device_os(device):
    """Build the ``host.os`` string from the Men&Mice vendor / model chain.

    Men&Mice exposes ``vendor`` (e.g. ``Cisco``), ``model``
    (e.g. ``ISR4451``) and ``firmwareVersion`` (the running OS
    release).  We join them with a space when present so the
    Faraday host card reads like ``Cisco ISR4451 16.9.5``.
    """
    if not isinstance(device, dict):
        return ""
    bits = []
    vendor = _str(device.get("vendor"))
    if vendor:
        bits.append(vendor)
    model = _str(device.get("model"))
    if model:
        bits.append(model)
    version = _str(device.get("firmwareVersion"))
    if version:
        bits.append(version)
    return " ".join(bits)


def collect_device_refs(device):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(device, dict):
        return refs
    ref = _str(device.get("ref"))
    if ref:
        add(f"MenAndMice-Ref: {ref}")
    name = _str(device.get("name"))
    if name:
        add(f"MenAndMice-Name: {name}")
    dtype = _str(device.get("type"))
    if dtype:
        add(f"MenAndMice-Type: {dtype}")
    devtype = _str(device.get("deviceType"))
    if devtype:
        add(f"MenAndMice-DeviceType: {devtype}")
    vendor = _str(device.get("vendor"))
    if vendor:
        add(f"MenAndMice-Vendor: {vendor}")
    model = _str(device.get("model"))
    if model:
        add(f"MenAndMice-Model: {model}")
    version = _str(device.get("firmwareVersion"))
    if version:
        add(f"MenAndMice-Firmware: {version}")
    serial = _str(device.get("serialNumber"))
    if serial:
        add(f"MenAndMice-Serial: {serial}")
    last_seen = _str(device.get("lastSeen"))
    if last_seen:
        add(f"MenAndMice-LastSeen: {last_seen}")

    slots = device.get("addresses")
    if isinstance(slots, list):
        for entry in slots:
            if isinstance(entry, dict):
                addr = _str(entry.get("address"))
                if addr:
                    add(f"MenAndMice-Address: {addr}")
                mac = _str(entry.get("mac"))
                if mac:
                    add(f"MenAndMice-MAC: {mac}")
                iface = _str(entry.get("interfaceName"))
                if iface:
                    add(f"MenAndMice-Interface: {iface}")

    props = _flatten_custom_properties(device.get("customProperties"))
    for key, val in props.items():
        sv = _str(val)
        if sv:
            add(f"MenAndMice-CP-{key}: {sv}")
    return refs


def build_device_host(device, network_filter):
    """Build a Faraday host dict for a Men&Mice device record."""
    if not isinstance(device, dict):
        return None
    hostnames = device_hostnames(device)
    primary = hostnames[0] if hostnames else (_str(device.get("ref")) or "unknown device")

    desc_parts = []
    for key in (
        "ref",
        "name",
        "type",
        "deviceType",
        "vendor",
        "model",
        "firmwareVersion",
        "serialNumber",
        "addresses",
        "lastSeen",
        "customProperties",
    ):
        v = device.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if network_filter:
        desc_parts.append(f"mm_network: {network_filter}")

    vuln = {
        "name": f"[NETWORK] Men&Mice device: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(device.get("ref"))[:200] or f"menandmice-device-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Men&Mice devices are DDI inventory entries, not "
            "vulnerabilities.  Cross-check the device against "
            "the other agents' findings — anything reported "
            "against this device's address indicates a real "
            "exposure on a managed endpoint the network team "
            "owns.  Decommission or re-classify the device in "
            "the Men&Mice Web Interface (Devices) if it should "
            "no longer appear in the inventory."
        ),
        "data": "",
        "refs": collect_device_refs(device),
        "cve": [],
        "cvss3": {},
        "tags": ["menandmice", "network", "ddi", "ipam", "device"],
    }
    return {
        "ip": _device_ip(device),
        "os": device_os(device),
        "hostnames": hostnames,
        "mac": _device_mac(device),
        "description": f"Men&Mice device {primary}",
        "vulnerabilities": [vuln],
    }


def _ipam_record_ip(record):
    """Pick the IP for a Men&Mice IPAM record.

    Men&Mice IPAM records anchor on a single ``address`` slot
    (the dotted-quad / v6 string the record is keyed on).  We
    surface the bare slot and fall back to the sentinel for
    placeholder records that don't carry an address.
    """
    if not isinstance(record, dict):
        return SENTINEL_IP
    addr = _str(record.get("address"))
    if addr:
        return addr
    return SENTINEL_IP


def ipam_record_hostnames(record):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(record, dict):
        add(record.get("name"))
        dns_records = record.get("dnsRecords")
        if isinstance(dns_records, list):
            for entry in dns_records:
                if isinstance(entry, dict):
                    add(entry.get("name"))
    return out


def _ipam_record_mac(record):
    """Lift the first DHCP-reservation MAC when present."""
    if not isinstance(record, dict):
        return ""
    reservations = record.get("dhcpReservations")
    if isinstance(reservations, list):
        for entry in reservations:
            if isinstance(entry, dict):
                mac = _str(entry.get("clientIdentifier")) or _str(entry.get("mac"))
                if mac:
                    return mac
    return ""


def collect_ipam_record_refs(record):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(record, dict):
        return refs
    ref = _str(record.get("ref"))
    if ref:
        add(f"MenAndMice-Ref: {ref}")
    addr = _str(record.get("address"))
    if addr:
        add(f"MenAndMice-Address: {addr}")
    name = _str(record.get("name"))
    if name:
        add(f"MenAndMice-Name: {name}")
    rtype = _str(record.get("type"))
    if rtype:
        add(f"MenAndMice-Type: {rtype}")
    state = _str(record.get("state"))
    if state:
        add(f"MenAndMice-State: {state}")
    range_ref = _str(record.get("rangeRef"))
    if range_ref:
        add(f"MenAndMice-RangeRef: {range_ref}")
    last_seen = _str(record.get("lastSeen"))
    if last_seen:
        add(f"MenAndMice-LastSeen: {last_seen}")
    last_disc = _str(record.get("lastDiscoveryDate"))
    if last_disc:
        add(f"MenAndMice-LastDiscoveryDate: {last_disc}")

    dns_records = record.get("dnsRecords")
    if isinstance(dns_records, list):
        for entry in dns_records:
            if isinstance(entry, dict):
                rn = _str(entry.get("name"))
                rt = _str(entry.get("type"))
                rd = _str(entry.get("data"))
                bits = [b for b in (rn, rt, rd) if b]
                if bits:
                    add(f"MenAndMice-DNS: {' '.join(bits)}")

    reservations = record.get("dhcpReservations")
    if isinstance(reservations, list):
        for entry in reservations:
            if isinstance(entry, dict):
                mac = _str(entry.get("clientIdentifier")) or _str(entry.get("mac"))
                if mac:
                    add(f"MenAndMice-DHCPMAC: {mac}")

    props = _flatten_custom_properties(record.get("customProperties"))
    for key, val in props.items():
        sv = _str(val)
        if sv:
            add(f"MenAndMice-CP-{key}: {sv}")
    return refs


def build_ipam_record_host(record, network_filter):
    """Build a Faraday host dict for a Men&Mice IPAM record."""
    if not isinstance(record, dict):
        return None
    hostnames = ipam_record_hostnames(record)
    primary = (
        _str(record.get("address"))
        or (hostnames[0] if hostnames else "")
        or _str(record.get("ref"))
        or "unknown ipam record"
    )

    desc_parts = []
    for key in (
        "ref",
        "address",
        "name",
        "type",
        "state",
        "rangeRef",
        "dnsRecords",
        "dhcpReservations",
        "lastSeen",
        "lastDiscoveryDate",
        "customProperties",
    ):
        v = record.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if network_filter:
        desc_parts.append(f"mm_network: {network_filter}")

    vuln = {
        "name": f"[NETWORK] Men&Mice IPAM record: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(record.get("ref"))[:200] or f"menandmice-ipam-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Men&Mice IPAM records are DDI inventory entries, "
            "not vulnerabilities.  Cross-check the record "
            "against the other agents' findings — anything "
            "reported against this address indicates a real "
            "exposure on a managed IPAM endpoint the network "
            "team owns.  Reclaim or re-classify the record in "
            "the Men&Mice Web Interface (IPAM) if it should no "
            "longer appear in the inventory."
        ),
        "data": "",
        "refs": collect_ipam_record_refs(record),
        "cve": [],
        "cvss3": {},
        "tags": ["menandmice", "network", "ddi", "ipam", "ipam-record"],
    }
    return {
        "ip": _ipam_record_ip(record),
        "os": "",
        "hostnames": hostnames,
        "mac": _ipam_record_mac(record),
        "description": f"Men&Mice IPAM record {primary}",
        "vulnerabilities": [vuln],
    }


def fetch_all(client, build_url, host, auth, max_pages, surface_name, results_key, **build_kwargs):
    """Walk a Men&Mice ``offset`` + ``limit`` paged envelope.

    First request sends the surface URL with ``?offset=0&limit=100``
    (plus operator filters).  Each subsequent request rebuilds
    the URL with the next offset.  Stops when the returned
    ``<results_key>`` list is shorter than the page size
    (Men&Mice's documented "no more pages" signal — the
    ``totalResults`` field is informational and not load-
    bearing here) or ``max_pages`` is reached.  401 short-
    circuits the whole executor because the operator
    credentials are wrong.  403 / 429 / 404 just stop
    pagination on the surface we're walking and return what we
    have.
    """
    out = []
    offset = 0
    pages = 0
    while pages < max_pages:
        url = build_url(host, offset=offset, **build_kwargs)
        try:
            resp = client.get(
                url,
                auth=auth,
                headers={
                    "Accept": "application/json",
                },
                timeout=TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Men&Mice request rejected (401). " "Check MM_USER / MM_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"Men&Mice {surface_name} request rejected (403). " f"Check the user role's object-level permissions.")
            return out
        if resp.status_code == 429:
            log(f"Men&Mice rate-limited (429) on {surface_name}; " f"stopping pagination.")
            return out
        if resp.status_code == 404:
            log(f"Men&Mice {surface_name} returned 404 — endpoint " f"missing on this mmws version.")
            return out
        if resp.status_code >= 400:
            log(f"Men&Mice {surface_name} failed " f"({resp.status_code}): " f"{getattr(resp, 'text', '')[:500]}")
            return out
        try:
            body = resp.json()
        except ValueError:
            log(f"Men&Mice {surface_name} response was not JSON")
            return out
        results = []
        if isinstance(body, dict):
            envelope = body.get("result")
            raw = None
            if isinstance(envelope, dict):
                raw = envelope.get(results_key)
            if not isinstance(raw, list):
                raw = body.get(results_key)
            if isinstance(raw, list):
                results = [r for r in raw if isinstance(r, dict)]
        elif isinstance(body, list):
            results = [r for r in body if isinstance(r, dict)]
        out.extend(results)
        if len(results) < PER_PAGE:
            return out
        offset += PER_PAGE
        pages += 1
    if pages >= max_pages:
        log(f"hit MM_PAGES={max_pages} on {surface_name}; " f"stopping pagination")
    return out


def main():
    started = time.time()

    network = validate_network(env("EXECUTOR_CONFIG_MM_NETWORK"))
    pages = validate_pages(env("MM_PAGES"))

    host = env("MM_HOST", required=True)
    user = env("MM_USER", required=True)
    password = env("MM_PASSWORD", required=True)

    if not normalize_base_url(host):
        log("MM_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    auth = (user, password)

    device_hits = fetch_all(
        requests,
        build_devices_url,
        host,
        auth,
        pages,
        "/mmws/api/devices",
        "devices",
        network=network,
    )
    ipam_hits = fetch_all(
        requests,
        build_ipam_records_url,
        host,
        auth,
        pages,
        "/mmws/api/IPAMRecords",
        "ipamRecords",
        network=network,
    )

    log(
        f"Processing {len(device_hits)} Men&Mice devices + "
        f"{len(ipam_hits)} IPAM records "
        f"(network={network!r}, pages={pages})"
    )

    hosts_out = []
    for d in device_hits:
        built = build_device_host(d, network)
        if built is not None:
            hosts_out.append(built)
    for r in ipam_hits:
        built = build_ipam_record_host(r, network)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "menandmice",
            "command": "menandmice",
            "params": (f"network={network}," f"pages={pages}"),
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
