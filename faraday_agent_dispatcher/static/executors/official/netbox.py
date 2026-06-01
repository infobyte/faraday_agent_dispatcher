#!/usr/bin/env python
"""NetBox importer.

Pulls managed devices and tracked IP records from a NetBox DCIM /
IPAM appliance via the NetBox REST API and emits Faraday
bulk-create JSON to stdout.  NetBox is the open-source
source-of-truth for network operations — a single
opinionated CMDB that models DCIM (data-center / rack / device
inventory), IPAM (subnets, prefixes, IP assignments) and the
relationships between them (a device has interfaces, interfaces
have IPs, IPs sit in prefixes, prefixes belong to VRFs, etc.) —
so this executor is the network-management cross-reference feed
Faraday operators correlate the EDR / EASM / vuln-scanner agents'
findings against to confirm whether a vulnerable IP is a known
managed device on a tracked subnet (and therefore in-scope for
the network team) or an unmanaged stray on someone else's range.

Each NetBox device becomes one Faraday host — DCIM device
records ARE network-keyed (a device with a primary IP
configured is anchored to a tracked endpoint) so the executor
lifts the device's ``primary_ip`` / ``primary_ip4`` /
``primary_ip6`` address onto ``host.ip`` (stripping the
canonical NetBox ``/<prefix-length>`` CIDR suffix that NetBox
appends to every address it stores) when present, and falls
back to the ``0.0.0.0`` sentinel for racks / chassis / virtual
devices that don't carry an assigned IP.  The ``name`` /
``display`` / ``serial`` / ``asset_tag`` projection lands on
``host.hostnames``; the ``platform`` / ``device_type`` chain
joins onto ``host.os``; ``id`` / ``site`` / ``role`` / ``status``
/ ``tenant`` enrichment lands on ``host.description``; the
device record itself becomes one Faraday vulnerability with the
``[NETWORK]`` engine prefix so the finding lands in the workspace
alongside the other network-management feeds.  Each NetBox IP
record becomes one Faraday host — IPAM records ARE
network-keyed (the IP itself IS the host coordinate) so
``address`` (CIDR-stripped) lands on ``host.ip``; ``dns_name``
lands on ``host.hostnames``; ``vrf`` / ``tenant`` / ``status`` /
``role`` enrichment lands on ``host.description``; the IP record
itself becomes one Faraday vulnerability with the ``[NETWORK]``
engine prefix.

Endpoints used:
  GET {NETBOX_HOST}/api/dcim/devices/?limit=N&offset=M[&site=<slug>][&role=<slug>]
      -> the canonical NetBox DCIM device inventory.  Returns
      the Django-REST-Framework ``{"count": N, "next": "...",
      "previous": "...", "results": [...]}`` envelope walked
      page-by-page via the absolute ``next`` URL until the
      next-link is absent or the env-only ``NETBOX_PAGES`` cap
      is reached (default 5, clamped to [1, 50]).  Each record
      carries ``id``, ``name``, ``display``, ``device_type``
      (nested ``{id, model, manufacturer}``), ``role`` (newer
      NetBox >= 3.6) or ``device_role`` (legacy), ``platform``,
      ``serial``, ``asset_tag``, ``site`` (nested), ``rack``,
      ``status`` (nested ``{value, label}``), ``primary_ip``
      (nested with ``address`` field carrying the
      CIDR-formatted ``a.b.c.d/PFX`` string), ``primary_ip4``,
      ``primary_ip6``, ``tenant``, ``cluster``, ``tags``,
      ``created``, ``last_updated``, ``custom_fields``.  When
      ``NETBOX_SITE`` is set the dispatcher forwards it as the
      ``?site=<slug>`` query parameter; when ``NETBOX_ROLE`` is
      set it forwards as ``?role=<slug>`` (modern NetBox role
      filter — NetBox renamed ``device_role`` to ``role`` in
      v3.6 but kept the old name as a synonym).
  GET {NETBOX_HOST}/api/ipam/ip-addresses/?limit=N&offset=M[&interface__device__site=<slug>]
      -> the canonical NetBox IPAM IP-address inventory.  Same
      DRF envelope; each record carries ``id``, ``family``
      (``{value: 4|6, label}``), ``address`` (CIDR
      ``a.b.c.d/PFX``), ``vrf`` (nested), ``tenant`` (nested),
      ``status`` (nested), ``role`` (nested role enum:
      ``loopback|secondary|anycast|vip|vrrp|hsrp|glbp|carp``),
      ``assigned_object_type`` (e.g. ``dcim.interface``),
      ``assigned_object_id``, ``assigned_object`` (nested
      interface record, which itself has a nested ``device``),
      ``dns_name``, ``description``, ``tags``, ``created``,
      ``last_updated``, ``custom_fields``.  When
      ``NETBOX_SITE`` is set the dispatcher forwards it as the
      ``?interface__device__site=<slug>`` cross-relation query
      parameter so the walk only returns IPs whose owning
      interface belongs to a device in that site (the NetBox
      IPAM surface doesn't carry a site field directly because
      IPs are conceptually network-routable across sites — the
      site relation is reached transitively through the
      assigned interface and device).  ``NETBOX_ROLE`` is NOT
      forwarded into the IPAM surface (the role enum there
      labels IP semantics like ``loopback`` / ``vip``, not
      device roles, so the operator's device-role filter would
      collide).

Pagination is offset-based via NetBox's absolute ``next`` URL
(NetBox returns fully-qualified next links, identical pattern
to Microsoft Graph's ``@odata.nextLink``).  We walk
page-by-page until the next-link is absent or the env-only
``NETBOX_PAGES`` cap is reached.  ``limit`` is fixed at 100
(NetBox's documented default; the hard cap is configurable per
deployment but 100 keeps response sizes manageable for the
dispatcher event loop).

Auth: NetBox uses the ``Token`` header scheme.  Operators
create an API token in the NetBox admin under
``Admin -> Users -> Tokens`` (write-access can be toggled off
to mint a read-only token, which is the recommended scope for
the dispatcher).  The dispatcher carries it on every request
as ``Authorization: Token <NETBOX_TOKEN>``.  ``NETBOX_HOST`` is
the operator's NetBox appliance host (e.g.
``netbox.mycorp.com``); ``https://`` is added automatically
when the operator pasted in a bare FQDN.

Severity for devices / IPs is always ``info`` (they're
network-management inventory entries, not findings — the value
is the cross-reference signal, not a vulnerability score).
Tags: [netbox, network, ipam, device|ip].
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

TIMEOUT = 60
PER_PAGE = 100  # NetBox DRF default page size.
DEFAULT_PAGES = 5
MAX_PAGES = 50

SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - NetBox: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on NETBOX_HOST.

    No default — the NetBox appliance host is operator-specific
    so we ``sys.exit(1)`` upstream in ``main`` when the env var
    is missing.  Here we just whitespace-trim, strip trailing
    slashes and add ``https://`` when the operator pasted in a
    bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_site(value):
    """Validate NETBOX_SITE (the operator-supplied site filter).

    None / blank -> ``""`` (no narrowing; every device / IP the
    token can read is walked).  Whitespace is trimmed.  Forwarded
    into the ``?site=`` query parameter on the devices surface
    and the ``?interface__device__site=`` cross-relation on the
    IPAM surface.  NetBox site filters are slug-based (the
    URL-safe identifier shown next to the site name in the admin)
    so the executor URL-encodes whatever the operator pasted in.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_role(value):
    """Validate NETBOX_ROLE (the operator-supplied device-role filter).

    None / blank -> ``""`` (no narrowing; every device role is
    walked).  Whitespace is trimmed.  Forwarded into the
    ``?role=`` query parameter on the devices surface only —
    NetBox renamed ``device_role`` to ``role`` in v3.6 but kept
    the old name as a server-side synonym, so the modern slug
    works on every supported NetBox version.  Not forwarded into
    the IPAM surface (the IPAM ``role`` enum labels IP semantics
    like ``loopback`` / ``vip``, not device roles).
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_pages(value):
    """Validate NETBOX_PAGES (per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    NetBox API.  Not exposed as a manifest argument (the playbook
    only lists NETBOX_SITE + NETBOX_ROLE) but read from the env
    so a tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"NETBOX_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"NETBOX_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def auth_headers(token):
    """Return the NetBox Token auth header set.

    NetBox uses the ``Authorization: Token <token>`` scheme (not
    Bearer).  We assemble the value defensively (a missing token
    produces a header that surfaces a clean 401 rather than a
    malformed value the appliance silently drops).
    """
    return {
        "Authorization": f"Token {token or ''}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def build_devices_url(host, site, role):
    base = f"{normalize_base_url(host)}/api/dcim/devices/"
    params = [f"limit={PER_PAGE}"]
    if site:
        params.append(f"site={quote(site, safe='')}")
    if role:
        params.append(f"role={quote(role, safe='')}")
    return f"{base}?{'&'.join(params)}"


def build_ips_url(host, site):
    base = f"{normalize_base_url(host)}/api/ipam/ip-addresses/"
    params = [f"limit={PER_PAGE}"]
    if site:
        params.append(f"interface__device__site={quote(site, safe='')}")
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


def _strip_cidr(address):
    """Strip the trailing ``/<prefix-length>`` from a NetBox address.

    NetBox stores every IP as a CIDR string (``10.0.0.1/24``)
    because IPAM records always carry their prefix length.
    Faraday's ``host.ip`` wants the bare address so we split on
    the first ``/`` and return the host portion.  Handles bare
    IPs (no ``/``) by returning them verbatim.
    """
    if not address:
        return ""
    text = _str(address)
    if not text:
        return ""
    return text.split("/", 1)[0].strip()


def _nested_label(value):
    """Extract a printable label from a NetBox nested object.

    NetBox embeds related objects as either bare ids, brief
    nested dicts (``{id, url, display, name|slug}``), or
    enum-valued dicts (``{value, label}``).  We try the most
    operator-friendly field first.
    """
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("display", "name", "label", "slug", "value", "id"):
            v = value.get(key)
            if isinstance(v, (int, float)):
                return str(v)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _device_primary_ip(device):
    """Pick a primary IP for a NetBox device record.

    NetBox surfaces three nested IP slots on a device record:
    ``primary_ip`` (the active address — points at either v4 or
    v6 depending on which is configured), ``primary_ip4`` and
    ``primary_ip6``.  Each nested slot carries the CIDR-formatted
    ``address`` field.  We prefer the canonical ``primary_ip``
    field and fall back to v4 / v6 in order.  Returns the bare
    address (CIDR stripped) or the sentinel when no slot is set.
    """
    if not isinstance(device, dict):
        return SENTINEL_IP
    for key in ("primary_ip", "primary_ip4", "primary_ip6"):
        slot = device.get(key)
        if isinstance(slot, dict):
            addr = _strip_cidr(slot.get("address"))
            if addr:
                return addr
        elif isinstance(slot, str):
            addr = _strip_cidr(slot)
            if addr:
                return addr
    return SENTINEL_IP


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
        add(device.get("display"))
        add(device.get("serial"))
        add(device.get("asset_tag"))
    return out


def device_os(device):
    """Build the ``host.os`` string from the NetBox platform + type chain.

    NetBox doesn't model a free-form OS field — ``platform``
    carries the device's OS family (``Cisco IOS XE``,
    ``Junos``, ``Linux``) and ``device_type`` carries the
    hardware model (``ISR4451``, ``EX4300``).  We join them
    with a space when both are present so the Faraday host card
    reads like ``Cisco IOS XE ISR4451``.
    """
    if not isinstance(device, dict):
        return ""
    bits = []
    platform = _nested_label(device.get("platform"))
    if platform:
        bits.append(platform)
    dtype = _nested_label(device.get("device_type"))
    if dtype:
        bits.append(dtype)
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
    did = _str(device.get("id"))
    if did:
        add(f"NetBox-DeviceId: {did}")
    name = _str(device.get("name"))
    if name:
        add(f"NetBox-Name: {name}")
    serial = _str(device.get("serial"))
    if serial:
        add(f"NetBox-Serial: {serial}")
    asset_tag = _str(device.get("asset_tag"))
    if asset_tag:
        add(f"NetBox-AssetTag: {asset_tag}")
    site = _nested_label(device.get("site"))
    if site:
        add(f"NetBox-Site: {site}")
    # NetBox renamed device_role to role in v3.6; surface either.
    role = _nested_label(device.get("role")) or _nested_label(device.get("device_role"))
    if role:
        add(f"NetBox-Role: {role}")
    dtype = _nested_label(device.get("device_type"))
    if dtype:
        add(f"NetBox-DeviceType: {dtype}")
    platform = _nested_label(device.get("platform"))
    if platform:
        add(f"NetBox-Platform: {platform}")
    status = _nested_label(device.get("status"))
    if status:
        add(f"NetBox-Status: {status}")
    tenant = _nested_label(device.get("tenant"))
    if tenant:
        add(f"NetBox-Tenant: {tenant}")
    rack = _nested_label(device.get("rack"))
    if rack:
        add(f"NetBox-Rack: {rack}")
    cluster = _nested_label(device.get("cluster"))
    if cluster:
        add(f"NetBox-Cluster: {cluster}")
    updated = _str(device.get("last_updated"))
    if updated:
        add(f"NetBox-LastUpdated: {updated}")
    return refs


def build_device_host(device, site_filter, role_filter):
    """Build a Faraday host dict for a NetBox device record."""
    if not isinstance(device, dict):
        return None
    hostnames = device_hostnames(device)
    primary = hostnames[0] if hostnames else (_str(device.get("id")) or "unknown device")

    desc_parts = []
    for key in (
        "id",
        "name",
        "display",
        "device_type",
        "role",
        "device_role",
        "platform",
        "serial",
        "asset_tag",
        "site",
        "rack",
        "status",
        "primary_ip",
        "primary_ip4",
        "primary_ip6",
        "tenant",
        "cluster",
        "tags",
        "created",
        "last_updated",
    ):
        v = device.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if site_filter:
        desc_parts.append(f"netbox_site: {site_filter}")
    if role_filter:
        desc_parts.append(f"netbox_role: {role_filter}")

    vuln = {
        "name": f"[NETWORK] NetBox device: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(device.get("id"))[:200] or f"netbox-device-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "NetBox devices are DCIM inventory entries, not "
            "vulnerabilities.  Cross-check the device against the "
            "other agents' findings — anything reported against "
            "this device's primary IP indicates a real exposure "
            "on a managed network endpoint that the network team "
            "owns.  Decommission or re-classify the device in "
            "NetBox if it should no longer appear in the inventory."
        ),
        "data": "",
        "refs": collect_device_refs(device),
        "cve": [],
        "cvss3": {},
        "tags": ["netbox", "network", "ipam", "device"],
    }
    return {
        "ip": _device_primary_ip(device),
        "os": device_os(device),
        "hostnames": hostnames,
        "mac": "",
        "description": f"NetBox device {primary}",
        "vulnerabilities": [vuln],
    }


def ip_hostnames(record):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(record, dict):
        add(record.get("dns_name"))
        # Pull the assigned device's name when the IP belongs to
        # an interface (NetBox nests `assigned_object` ->
        # `device` -> {id, name, display}).
        assigned = record.get("assigned_object")
        if isinstance(assigned, dict):
            device = assigned.get("device")
            if isinstance(device, dict):
                add(device.get("name"))
                add(device.get("display"))
            add(assigned.get("name"))
    return out


def collect_ip_refs(record):
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
    iid = _str(record.get("id"))
    if iid:
        add(f"NetBox-IpId: {iid}")
    addr = _str(record.get("address"))
    if addr:
        add(f"NetBox-Address: {addr}")
    family = _nested_label(record.get("family"))
    if family:
        add(f"NetBox-Family: {family}")
    vrf = _nested_label(record.get("vrf"))
    if vrf:
        add(f"NetBox-Vrf: {vrf}")
    tenant = _nested_label(record.get("tenant"))
    if tenant:
        add(f"NetBox-Tenant: {tenant}")
    status = _nested_label(record.get("status"))
    if status:
        add(f"NetBox-Status: {status}")
    role = _nested_label(record.get("role"))
    if role:
        add(f"NetBox-IpRole: {role}")
    dns = _str(record.get("dns_name"))
    if dns:
        add(f"NetBox-Dns: {dns}")
    assigned_type = _str(record.get("assigned_object_type"))
    if assigned_type:
        add(f"NetBox-AssignedType: {assigned_type}")
    assigned = record.get("assigned_object")
    if isinstance(assigned, dict):
        device = assigned.get("device")
        if isinstance(device, dict):
            d_name = _nested_label(device)
            if d_name:
                add(f"NetBox-AssignedDevice: {d_name}")
        iface = _nested_label(assigned)
        if iface:
            add(f"NetBox-AssignedInterface: {iface}")
    updated = _str(record.get("last_updated"))
    if updated:
        add(f"NetBox-LastUpdated: {updated}")
    return refs


def build_ip_host(record, site_filter):
    """Build a Faraday host dict for a NetBox IP-address record."""
    if not isinstance(record, dict):
        return None
    address = _strip_cidr(record.get("address"))
    if not address:
        address = SENTINEL_IP
    hostnames = ip_hostnames(record)
    primary = hostnames[0] if hostnames else address

    desc_parts = []
    for key in (
        "id",
        "address",
        "family",
        "vrf",
        "tenant",
        "status",
        "role",
        "assigned_object_type",
        "assigned_object_id",
        "assigned_object",
        "dns_name",
        "description",
        "tags",
        "created",
        "last_updated",
    ):
        v = record.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if site_filter:
        desc_parts.append(f"netbox_site: {site_filter}")

    vuln = {
        "name": f"[NETWORK] NetBox ip: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(record.get("id"))[:200] or f"netbox-ip-{address}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "NetBox IP addresses are IPAM inventory entries, not "
            "vulnerabilities.  Cross-check the IP against the "
            "other agents' findings — anything reported against "
            "this address indicates a real exposure on an IP the "
            "network team tracks (and therefore knows the "
            "subnet, VRF and assigned-interface for).  Reclaim or "
            "deprecate the IP in NetBox if the assignment is "
            "stale."
        ),
        "data": "",
        "refs": collect_ip_refs(record),
        "cve": [],
        "cvss3": {},
        "tags": ["netbox", "network", "ipam", "ip"],
    }
    return {
        "ip": address,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"NetBox ip {primary}",
        "vulnerabilities": [vuln],
    }


def fetch_all(client, url, headers, max_pages, surface_name):
    """Walk a NetBox DRF-paged ``{count, next, previous, results}`` envelope.

    NetBox returns absolute ``next`` URLs (fully-qualified
    ``https://...?limit=N&offset=M``) so we follow them
    directly, identical pattern to Microsoft Graph's
    ``@odata.nextLink``.  Pages until the next-link is absent or
    ``max_pages`` is reached.  401 short-circuits the whole
    executor because the operator credentials are wrong.  403 /
    429 / 404 just stop pagination on the surface and return
    what we have.
    """
    out = []
    next_url = url
    pages = 0
    while next_url and pages < max_pages:
        try:
            resp = client.get(next_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {next_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("NetBox request rejected (401). " "Check NETBOX_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"NetBox {surface_name} request rejected (403). " f"Check the token's object-level permissions.")
            return out
        if resp.status_code == 429:
            log(f"NetBox rate-limited (429) on {surface_name}; " f"stopping pagination.")
            return out
        if resp.status_code == 404:
            log(f"NetBox {surface_name} returned 404 — endpoint " f"missing on this NetBox version.")
            return out
        if resp.status_code >= 400:
            log(f"NetBox {surface_name} failed " f"({resp.status_code}): {resp.text[:500]}")
            return out
        try:
            body = resp.json()
        except ValueError:
            log(f"NetBox {surface_name} response was not JSON")
            return out
        if isinstance(body, list):
            out.extend(r for r in body if isinstance(r, dict))
            return out
        if not isinstance(body, dict):
            return out
        results = body.get("results")
        if isinstance(results, list):
            out.extend(r for r in results if isinstance(r, dict))
        next_url = body.get("next") or None
        pages += 1
    if pages >= max_pages and next_url:
        log(f"hit NETBOX_PAGES={max_pages} on {surface_name}; stopping pagination")
    return out


def main():
    started = time.time()

    site = validate_site(env("EXECUTOR_CONFIG_NETBOX_SITE"))
    role = validate_role(env("EXECUTOR_CONFIG_NETBOX_ROLE"))
    pages = validate_pages(env("NETBOX_PAGES"))

    host = env("NETBOX_HOST", required=True)
    token = env("NETBOX_TOKEN", required=True)

    if not normalize_base_url(host):
        log("NETBOX_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    devices_url = build_devices_url(host, site, role)
    ips_url = build_ips_url(host, site)

    device_hits = fetch_all(
        requests,
        devices_url,
        headers,
        pages,
        "/api/dcim/devices/",
    )
    ip_hits = fetch_all(
        requests,
        ips_url,
        headers,
        pages,
        "/api/ipam/ip-addresses/",
    )

    log(
        f"Processing {len(device_hits)} NetBox devices + "
        f"{len(ip_hits)} IPs "
        f"(site={site!r}, role={role!r}, pages={pages})"
    )

    hosts_out = []
    for d in device_hits:
        built = build_device_host(d, site, role)
        if built is not None:
            hosts_out.append(built)
    for ip in ip_hits:
        built = build_ip_host(ip, site)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "netbox",
            "command": "netbox",
            "params": (f"site={site}," f"role={role}," f"pages={pages}"),
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
