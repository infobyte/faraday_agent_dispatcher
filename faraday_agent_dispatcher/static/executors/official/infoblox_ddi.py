#!/usr/bin/env python
"""Infoblox DDI (NIOS) importer.

Pulls DNS host records and IPAM subnet records from an Infoblox
NIOS Grid Master via the WAPI REST surface and emits Faraday
bulk-create JSON to stdout.  Infoblox NIOS is the enterprise
DDI (DNS, DHCP, IPAM) appliance suite — the Grid Master is the
authoritative source-of-truth for DNS namespace, DHCP scope
configuration and the IPAM tree of network containers, networks
and IP-address objects — so this executor is the network-
management cross-reference feed Faraday operators correlate
the EDR / EASM / vuln-scanner agents' findings against to
confirm whether a vulnerable IP is a known Infoblox-tracked
host record on a managed subnet (and therefore in-scope for
the network team) or an unmanaged stray on someone else's
range.

Each Infoblox ``record:host`` becomes one Faraday host — DNS
host records ARE network-keyed (each host record carries an
``ipv4addrs`` / ``ipv6addrs`` projection anchoring the record
to one or more tracked IP endpoints) so the executor lifts the
first ``ipv4addrs[].ipv4addr`` (or ``ipv6addrs[].ipv6addr`` as
fallback) onto ``host.ip`` when present, and falls back to the
``0.0.0.0`` sentinel for placeholder host records that don't
carry an assigned address.  The ``name`` / ``aliases``
projection lands on ``host.hostnames``; ``view`` /
``network_view`` / ``comment`` / ``extattrs`` enrichment lands
on ``host.description``; the host record itself becomes one
Faraday vulnerability with the ``[NETWORK]`` engine prefix so
the finding lands in the workspace alongside the other
network-management feeds.  Each Infoblox ``network`` becomes
one Faraday host on the ``0.0.0.0`` sentinel — IPAM network
containers describe a subnet range, not a single IP endpoint,
so the CIDR lives in ``host.description`` and the network
record itself becomes one Faraday vulnerability with the
``[NETWORK]`` engine prefix.

Endpoints used:
  GET {INFOBLOX_HOST}/wapi/v2.12/record:host?_paging=1&_max_results=N&_return_as_object=1[&view=<INFOBLOX_VIEW>]
      -> the canonical Infoblox DNS host-record inventory.
      Returns the WAPI paging envelope
      ``{"result": [...], "next_page_id": "..."}`` walked
      page-by-page via the opaque ``next_page_id`` cursor (next
      request sends ``?_page_id=<id>``) until the cursor is
      absent or the env-only ``INFOBLOX_PAGES`` cap is reached
      (default 5, clamped to [1, 50]).  Each record carries
      ``_ref``, ``name``, ``view`` (the DNS view this record
      lives in), ``ipv4addrs`` (list of nested
      ``{ipv4addr, configure_for_dhcp, mac}`` objects),
      ``ipv6addrs`` (analogous), ``aliases``, ``comment``,
      ``network_view``, ``zone``, ``extattrs``.  When
      ``INFOBLOX_VIEW`` is set the dispatcher forwards it as
      the ``?view=<name>`` query parameter so the walk only
      returns host records living in that DNS view (Infoblox
      DNS views are namespace scopes for split-DNS / multi-
      tenancy — the operator names them in the Grid Manager
      under ``Data Management -> DNS -> Zones``).
  GET {INFOBLOX_HOST}/wapi/v2.12/network?_paging=1&_max_results=N&_return_as_object=1[&network_view=<INFOBLOX_VIEW>][&network=<INFOBLOX_NETWORK_FILTER>]  # noqa: E501
      -> the canonical Infoblox IPAM network-container
      inventory.  Same WAPI paging envelope; each record
      carries ``_ref``, ``network`` (the CIDR
      ``a.b.c.d/PFX``), ``network_view`` (the network view
      this subnet lives in — Infoblox separates DNS views and
      network views; DNS views govern name resolution,
      network views govern address-space partitioning),
      ``comment``, ``extattrs``, ``members`` (the grid
      members handing out DHCP on this range), ``options``,
      ``ipv4addr_count``, ``utilization``.  When
      ``INFOBLOX_VIEW`` is set the dispatcher forwards it as
      ``?network_view=<name>`` (the network surface doesn't
      carry a DNS view field — the closest analogue is the
      network view, which is also what the operator means
      when they want their "view" filter to narrow the IPAM
      walk).  When ``INFOBLOX_NETWORK_FILTER`` is set the
      dispatcher forwards it as ``?network=<value>`` (exact
      CIDR match — WAPI supports the ``~=`` and ``:=`` modifier
      suffixes for regex / contains matches but exact match is
      the safest default for an operator-supplied playbook
      argument).

Pagination is opaque-cursor via WAPI's ``next_page_id``
response field.  The first request carries
``?_paging=1&_max_results=100&_return_as_object=1``; each
subsequent request carries the same ``_paging`` /
``_return_as_object`` toggles plus ``?_page_id=<cursor>``.
We walk page-by-page until the cursor is absent or the env-
only ``INFOBLOX_PAGES`` cap is reached.  ``_max_results`` is
fixed at 100 (a conservative default; WAPI accepts up to 1000
but smaller pages keep response sizes manageable for the
dispatcher event loop).

Auth: Infoblox NIOS WAPI uses HTTP Basic Auth.  Operators
provision a service account in the Grid Manager under
``Administration -> Administrators -> Admins`` with the
``API`` permission group attached (read-only is sufficient
for the dispatcher).  The dispatcher carries credentials on
every request as ``Authorization: Basic <base64(user:pass)>``.
``INFOBLOX_HOST`` is the operator's Grid Master host (e.g.
``infoblox.mycorp.com``); ``https://`` is added automatically
when the operator pasted in a bare FQDN.  TLS verification is
left to ``requests`` defaults (operators with self-signed
appliance certs should set ``REQUESTS_CA_BUNDLE`` in the
dispatcher env to point at the appliance CA bundle).

Severity for host records / networks is always ``info``
(they're DDI inventory entries, not findings — the value is
the cross-reference signal, not a vulnerability score).
Tags: [infoblox_ddi, network, ddi, ipam, host-record|network].
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

TIMEOUT = 60
PER_PAGE = 100  # WAPI _max_results default; hard cap is 1000.
DEFAULT_PAGES = 5
MAX_PAGES = 50
WAPI_VERSION = "v2.12"

SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - InfobloxDDI: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on INFOBLOX_HOST.

    No default — the Infoblox Grid Master host is operator-
    specific so we ``sys.exit(1)`` upstream in ``main`` when the
    env var is missing.  Here we just whitespace-trim, strip
    trailing slashes and add ``https://`` when the operator
    pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_view(value):
    """Validate INFOBLOX_VIEW (the operator-supplied view filter).

    None / blank -> ``""`` (no narrowing; every host record /
    network the credentials can read is walked).  Whitespace
    is trimmed.  Forwarded into the ``?view=`` query parameter
    on the record:host surface (Infoblox DNS view) and the
    ``?network_view=`` query parameter on the network surface
    (Infoblox network view — the IPAM surface doesn't carry a
    DNS view field, the closest analogue is the network view).
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_network_filter(value):
    """Validate INFOBLOX_NETWORK_FILTER (operator-supplied CIDR filter).

    None / blank -> ``""`` (no narrowing; every network the
    credentials can read is walked).  Whitespace is trimmed.
    Forwarded into the ``?network=`` query parameter on the
    network surface only (exact CIDR match).  Not forwarded
    into the record:host surface (host records don't filter
    by network CIDR — they filter by name / IP / view).
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_pages(value):
    """Validate INFOBLOX_PAGES (per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-
    string; floats are floored.  Clamped to [1, MAX_PAGES] so
    a stray operator input can't fan out into 100k+ requests
    against the Infoblox WAPI.  Not exposed as a manifest
    argument (the playbook only lists INFOBLOX_VIEW +
    INFOBLOX_NETWORK_FILTER) but read from the env so a
    tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"INFOBLOX_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"INFOBLOX_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_host_records_url(host, view, page_id=None):
    """Build the record:host walk URL.

    First page sends ``_paging=1`` + ``_max_results`` +
    ``_return_as_object=1`` (and optionally ``view=<name>``).
    Subsequent pages send the same toggles plus
    ``_page_id=<cursor>``.
    """
    base = f"{normalize_base_url(host)}" f"/wapi/{WAPI_VERSION}/record:host"
    params = [
        "_paging=1",
        f"_max_results={PER_PAGE}",
        "_return_as_object=1",
    ]
    if page_id:
        params.append(f"_page_id={quote(str(page_id), safe='')}")
    elif view:
        params.append(f"view={quote(view, safe='')}")
    return f"{base}?{'&'.join(params)}"


def build_networks_url(host, view, network_filter, page_id=None):
    """Build the network walk URL.

    First page sends ``_paging=1`` + ``_max_results`` +
    ``_return_as_object=1`` (and optionally
    ``network_view=<name>`` and / or ``network=<CIDR>``).
    Subsequent pages send the same toggles plus
    ``_page_id=<cursor>``.
    """
    base = f"{normalize_base_url(host)}" f"/wapi/{WAPI_VERSION}/network"
    params = [
        "_paging=1",
        f"_max_results={PER_PAGE}",
        "_return_as_object=1",
    ]
    if page_id:
        params.append(f"_page_id={quote(str(page_id), safe='')}")
    else:
        if view:
            params.append(f"network_view={quote(view, safe='')}")
        if network_filter:
            params.append(f"network={quote(network_filter, safe='')}")
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


def _flatten_extattrs(extattrs):
    """Flatten Infoblox extattrs ``{key: {value: v}}`` into ``{key: v}``.

    Infoblox stores extensible attributes as a dict of
    ``{name: {value: ...}}`` objects so consumers can attach
    type metadata alongside the value.  For description /
    refs we just want the operator-facing ``key=value`` line.
    """
    if not isinstance(extattrs, dict):
        return {}
    out = {}
    for key, slot in extattrs.items():
        if isinstance(slot, dict) and "value" in slot:
            out[str(key)] = slot.get("value")
        else:
            out[str(key)] = slot
    return out


def _host_record_ip(record):
    """Pick a primary IP for an Infoblox host record.

    Infoblox surfaces both ``ipv4addrs`` and ``ipv6addrs`` as
    list-of-nested-dict projections; each nested entry has the
    canonical address under ``ipv4addr`` / ``ipv6addr``.  We
    prefer the first v4 entry (DNS host records are usually
    A-record-anchored) and fall back to v6.  Returns the bare
    address or the sentinel when no slot is set.
    """
    if not isinstance(record, dict):
        return SENTINEL_IP
    for slot_key, addr_key in (("ipv4addrs", "ipv4addr"), ("ipv6addrs", "ipv6addr")):
        slots = record.get(slot_key)
        if isinstance(slots, list):
            for entry in slots:
                if isinstance(entry, dict):
                    addr = _str(entry.get(addr_key))
                    if addr:
                        return addr
    return SENTINEL_IP


def host_record_hostnames(record):
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
        aliases = record.get("aliases")
        if isinstance(aliases, list):
            for a in aliases:
                add(a)
    return out


def host_record_mac(record):
    """Lift the first ``ipv4addrs[].mac`` value when present.

    DHCP-configured host records carry the assigned MAC under
    ``ipv4addrs[].mac``; pure DNS records leave the slot
    empty.  We surface the first non-empty value.
    """
    if not isinstance(record, dict):
        return ""
    slots = record.get("ipv4addrs")
    if isinstance(slots, list):
        for entry in slots:
            if isinstance(entry, dict):
                mac = _str(entry.get("mac"))
                if mac:
                    return mac
    return ""


def collect_host_record_refs(record):
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
    ref = _str(record.get("_ref"))
    if ref:
        add(f"Infoblox-Ref: {ref}")
    name = _str(record.get("name"))
    if name:
        add(f"Infoblox-Name: {name}")
    view = _str(record.get("view"))
    if view:
        add(f"Infoblox-View: {view}")
    nview = _str(record.get("network_view"))
    if nview:
        add(f"Infoblox-NetworkView: {nview}")
    zone = _str(record.get("zone"))
    if zone:
        add(f"Infoblox-Zone: {zone}")
    comment = _str(record.get("comment"))
    if comment:
        add(f"Infoblox-Comment: {comment}")

    slots = record.get("ipv4addrs")
    if isinstance(slots, list):
        for entry in slots:
            if isinstance(entry, dict):
                addr = _str(entry.get("ipv4addr"))
                if addr:
                    add(f"Infoblox-IPv4: {addr}")
                mac = _str(entry.get("mac"))
                if mac:
                    add(f"Infoblox-MAC: {mac}")
    slots6 = record.get("ipv6addrs")
    if isinstance(slots6, list):
        for entry in slots6:
            if isinstance(entry, dict):
                addr = _str(entry.get("ipv6addr"))
                if addr:
                    add(f"Infoblox-IPv6: {addr}")

    aliases = record.get("aliases")
    if isinstance(aliases, list):
        for a in aliases:
            sa = _str(a)
            if sa:
                add(f"Infoblox-Alias: {sa}")

    extattrs = _flatten_extattrs(record.get("extattrs"))
    for key, val in extattrs.items():
        sv = _str(val)
        if sv:
            add(f"Infoblox-EA-{key}: {sv}")
    return refs


def build_host_record_host(record, view_filter, network_filter):
    """Build a Faraday host dict for an Infoblox record:host."""
    if not isinstance(record, dict):
        return None
    hostnames = host_record_hostnames(record)
    primary = hostnames[0] if hostnames else (_str(record.get("_ref")) or "unknown host record")

    desc_parts = []
    for key in (
        "_ref",
        "name",
        "view",
        "network_view",
        "zone",
        "ipv4addrs",
        "ipv6addrs",
        "aliases",
        "comment",
        "extattrs",
    ):
        v = record.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if view_filter:
        desc_parts.append(f"infoblox_view: {view_filter}")
    if network_filter:
        desc_parts.append(f"infoblox_network_filter: {network_filter}")

    vuln = {
        "name": f"[NETWORK] Infoblox host record: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(record.get("_ref"))[:200] or f"infoblox-host-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Infoblox host records are DDI inventory entries, "
            "not vulnerabilities.  Cross-check the host against "
            "the other agents' findings — anything reported "
            "against this record's assigned IP indicates a real "
            "exposure on a managed DNS / DHCP endpoint the "
            "network team owns.  Decommission or re-classify "
            "the record in the Grid Manager (Data Management -> "
            "DNS -> Hosts) if it should no longer appear in "
            "the inventory."
        ),
        "data": "",
        "refs": collect_host_record_refs(record),
        "cve": [],
        "cvss3": {},
        "tags": ["infoblox_ddi", "network", "ddi", "ipam", "host-record"],
    }
    return {
        "ip": _host_record_ip(record),
        "os": "",
        "hostnames": hostnames,
        "mac": host_record_mac(record),
        "description": f"Infoblox host record {primary}",
        "vulnerabilities": [vuln],
    }


def network_hostnames(record):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(record, dict):
        add(record.get("network"))
    return out


def collect_network_refs(record):
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
    ref = _str(record.get("_ref"))
    if ref:
        add(f"Infoblox-Ref: {ref}")
    net = _str(record.get("network"))
    if net:
        add(f"Infoblox-Network: {net}")
    nview = _str(record.get("network_view"))
    if nview:
        add(f"Infoblox-NetworkView: {nview}")
    comment = _str(record.get("comment"))
    if comment:
        add(f"Infoblox-Comment: {comment}")
    util = record.get("utilization")
    if util not in (None, "", [], {}):
        add(f"Infoblox-Utilization: {_serialise(util)}")
    count = record.get("ipv4addr_count")
    if count not in (None, "", [], {}):
        add(f"Infoblox-Ipv4Count: {_serialise(count)}")
    members = record.get("members")
    if isinstance(members, list):
        for m in members:
            label = _serialise(m) if not isinstance(m, str) else m
            if label:
                add(f"Infoblox-Member: {label}")

    extattrs = _flatten_extattrs(record.get("extattrs"))
    for key, val in extattrs.items():
        sv = _str(val)
        if sv:
            add(f"Infoblox-EA-{key}: {sv}")
    return refs


def build_network_host(record, view_filter, network_filter):
    """Build a Faraday host dict for an Infoblox network record."""
    if not isinstance(record, dict):
        return None
    cidr = _str(record.get("network"))
    primary = cidr or _str(record.get("_ref")) or "unknown network"

    desc_parts = []
    for key in (
        "_ref",
        "network",
        "network_view",
        "comment",
        "extattrs",
        "members",
        "options",
        "ipv4addr_count",
        "utilization",
    ):
        v = record.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if view_filter:
        desc_parts.append(f"infoblox_view: {view_filter}")
    if network_filter:
        desc_parts.append(f"infoblox_network_filter: {network_filter}")

    vuln = {
        "name": f"[NETWORK] Infoblox network: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(record.get("_ref"))[:200] or f"infoblox-network-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Infoblox networks are IPAM container entries — "
            "subnet ranges, not single IP endpoints.  Cross-"
            "check the network against the other agents' "
            "findings — anything reported on an IP that falls "
            "inside this CIDR indicates a real exposure on a "
            "subnet the network team tracks (and therefore "
            "knows the network view, members and DHCP options "
            "for).  Reclaim or split the network in the Grid "
            "Manager (Data Management -> IPAM) if the "
            "assignment is stale or oversized."
        ),
        "data": "",
        "refs": collect_network_refs(record),
        "cve": [],
        "cvss3": {},
        "tags": ["infoblox_ddi", "network", "ddi", "ipam", "network"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": network_hostnames(record),
        "mac": "",
        "description": f"Infoblox network {primary}",
        "vulnerabilities": [vuln],
    }


def fetch_all(client, build_url, host, auth, max_pages, surface_name, **build_kwargs):
    """Walk an Infoblox WAPI paged ``{result, next_page_id}`` envelope.

    First request sends the surface URL with ``?_paging=1`` /
    ``?_max_results`` / ``?_return_as_object=1`` (plus
    operator filters).  Each subsequent request rebuilds the
    URL with ``?_page_id=<cursor>`` (and drops the
    operator-filter params — WAPI binds the filter to the
    cursor server-side, so re-sending them rejects with 400).
    Pages until ``next_page_id`` is absent or ``max_pages`` is
    reached.  401 short-circuits the whole executor because
    the operator credentials are wrong.  403 / 429 / 404 just
    stop pagination on the surface we're walking and return
    what we have.
    """
    out = []
    page_id = None
    pages = 0
    while pages < max_pages:
        url = build_url(host, page_id=page_id, **build_kwargs)
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
            log("Infoblox WAPI request rejected (401). " "Check INFOBLOX_USER / INFOBLOX_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"Infoblox {surface_name} request rejected (403). " f"Check the API admin group's object permissions.")
            return out
        if resp.status_code == 429:
            log(f"Infoblox rate-limited (429) on {surface_name}; " f"stopping pagination.")
            return out
        if resp.status_code == 404:
            log(f"Infoblox {surface_name} returned 404 — endpoint " f"missing on this NIOS version.")
            return out
        if resp.status_code >= 400:
            log(f"Infoblox {surface_name} failed " f"({resp.status_code}): " f"{getattr(resp, 'text', '')[:500]}")
            return out
        try:
            body = resp.json()
        except ValueError:
            log(f"Infoblox {surface_name} response was not JSON")
            return out
        results = []
        next_page_id = None
        if isinstance(body, dict):
            raw = body.get("result")
            if isinstance(raw, list):
                results = [r for r in raw if isinstance(r, dict)]
            next_page_id = body.get("next_page_id") or None
        elif isinstance(body, list):
            results = [r for r in body if isinstance(r, dict)]
        out.extend(results)
        if not next_page_id:
            return out
        page_id = next_page_id
        pages += 1
    if pages >= max_pages and page_id:
        log(f"hit INFOBLOX_PAGES={max_pages} on {surface_name}; " f"stopping pagination")
    return out


def main():
    started = time.time()

    view = validate_view(env("EXECUTOR_CONFIG_INFOBLOX_VIEW"))
    network_filter = validate_network_filter(env("EXECUTOR_CONFIG_INFOBLOX_NETWORK_FILTER"))
    pages = validate_pages(env("INFOBLOX_PAGES"))

    host = env("INFOBLOX_HOST", required=True)
    user = env("INFOBLOX_USER", required=True)
    password = env("INFOBLOX_PASSWORD", required=True)

    if not normalize_base_url(host):
        log("INFOBLOX_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    auth = (user, password)

    host_hits = fetch_all(
        requests,
        build_host_records_url,
        host,
        auth,
        pages,
        "/wapi/v2.12/record:host",
        view=view,
    )
    network_hits = fetch_all(
        requests,
        build_networks_url,
        host,
        auth,
        pages,
        "/wapi/v2.12/network",
        view=view,
        network_filter=network_filter,
    )

    log(
        f"Processing {len(host_hits)} Infoblox host records + "
        f"{len(network_hits)} networks "
        f"(view={view!r}, network_filter={network_filter!r}, "
        f"pages={pages})"
    )

    hosts_out = []
    for r in host_hits:
        built = build_host_record_host(r, view, network_filter)
        if built is not None:
            hosts_out.append(built)
    for n in network_hits:
        built = build_network_host(n, view, network_filter)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "infoblox_ddi",
            "command": "infoblox_ddi",
            "params": (f"view={view}," f"network_filter={network_filter}," f"pages={pages}"),
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
