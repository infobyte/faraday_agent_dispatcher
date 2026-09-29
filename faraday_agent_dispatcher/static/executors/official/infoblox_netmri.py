#!/usr/bin/env python
"""Infoblox NetMRI importer.

Pulls managed-device inventory and network-config / compliance
issues from an Infoblox NetMRI appliance via the NetMRI REST API
and emits Faraday bulk-create JSON to stdout.  NetMRI is the
legacy Infoblox network-change / configuration-management
appliance — distinct from the Infoblox NIOS DDI Grid Master
that the sibling :mod:`infoblox_ddi` executor talks to.  NIOS
owns the DNS / DHCP / IPAM source-of-truth (host records,
networks, IP-address objects); NetMRI owns the live network-
device fabric (the actual routers / switches / firewalls / load-
balancers it has discovered on the wire) plus the running
config-compliance and change-management issue feed that scores
those devices.  So this executor is the network-management
cross-reference feed Faraday operators correlate the
EDR / EASM / vuln-scanner agents' findings against to confirm
whether a vulnerable IP is a NetMRI-tracked managed network
device (and therefore an in-scope misconfiguration the network
team owns) or an unmanaged stray that wandered onto a tracked
subnet.

Each NetMRI device becomes one Faraday host — NetMRI device
records ARE network-keyed (every discovered device carries a
``DeviceIPDotted`` projection anchoring the record to the
management IP the appliance polled it on) so the executor lifts
``DeviceIPDotted`` onto ``host.ip`` when present (sentinel
``0.0.0.0`` falls through for the rare placeholder records that
slipped past discovery without a usable management address).
The ``DeviceName`` / ``DeviceSysName`` projection lands on
``host.hostnames``; the ``DeviceVendor`` / ``DeviceModel`` /
``DeviceVersion`` chain joins onto ``host.os``; ``DeviceMAC``
lands on ``host.mac``; ``DeviceID`` / ``DeviceType`` /
``DeviceSysLocation`` / ``DeviceAssurance`` / ``Network``
enrichment lands on ``host.description``; the device record
itself becomes one Faraday vulnerability with the ``[NETWORK]``
engine prefix so the finding lands in the workspace alongside
the other network-management feeds.  Severity for devices is
always ``info`` (managed-inventory entries, not findings).

Each NetMRI issue becomes one Faraday vulnerability on the
``0.0.0.0`` sentinel — issues are change-management /
config-compliance findings keyed to a device by ``DeviceID``
rather than to an IP coordinate (the appliance generates an
issue the moment a managed device drifts from policy, and the
issue itself lives in the NetMRI database not on the wire), so
landing them on the sentinel keeps them visible without
pretending they're network-routable events.  Severity is mapped
from NetMRI's ``Severity`` enum (``Error`` -> ``high``,
``Warning`` -> ``med``, ``Info`` / ``Informational`` ->
``info``); the ``IssueScore`` (NetMRI's 0-100 issue weight)
lands on ``host.description`` so the operator can re-sort if the
default severity mapping is too coarse.

Endpoints used:
  GET {NETMRI_HOST}/api/3/devices?limit=N&start=M[&DeviceGroupID=<id>]
      -> the canonical NetMRI managed-device inventory.
      Returns the NetMRI envelope
      ``{"devices": [...], "total": N, "start": S, "limit": L,
      "current": C}`` walked page-by-page via the ``start`` +
      ``limit`` offset cursor (next request increments ``start``
      by the page size) until the result list is shorter than
      the page size or the env-only ``NETMRI_PAGES`` cap is
      reached (default 5, clamped to [1, 50]).  Each record
      carries ``DeviceID``, ``DeviceName``, ``DeviceIPDotted``
      (the management IPv4 the appliance polls the device on),
      ``DeviceMAC``, ``DeviceVendor``, ``DeviceModel``,
      ``DeviceVersion``, ``DeviceType`` (``Router`` |
      ``Switch`` | ``Firewall`` | ``Load Balancer`` | ...),
      ``DeviceSysName`` / ``DeviceSysDescr`` /
      ``DeviceSysLocation`` (the SNMP sysName / sysDescr /
      sysLocation projection NetMRI pulled during discovery),
      ``DeviceAssurance`` (NetMRI's 0-100 confidence-in-
      discovery score), ``Network`` (the NetMRI "Network"
      logical-grouping label, distinct from a CIDR), and the
      ``DeviceStartTime`` / ``DeviceEndTime`` discovery
      lifetime.  When ``NETMRI_GROUP_ID`` is set the dispatcher
      forwards it as the ``?DeviceGroupID=<id>`` query
      parameter so the walk only returns devices that belong to
      that NetMRI device group (operators define device groups
      in the NetMRI UI under ``Network Explorer -> Inventory
      -> Device Groups`` — they're the canonical way to scope
      a NetMRI report to a single business unit / site / role
      slice without hand-rolling a filter expression).
  GET {NETMRI_HOST}/api/3/issues?limit=N&start=M[&DeviceGroupID=<id>]
      -> the canonical NetMRI issue / compliance-violation
      feed.  Same envelope; each record carries ``IssueID``,
      ``IssueTitle``, ``IssueDescription``, ``Severity``
      (``Error`` | ``Warning`` | ``Info`` / ``Informational``),
      ``IssueScore`` (0-100 weight), ``IssueType`` (the rule
      category — ``Config`` | ``Policy`` | ``Network`` |
      ``Performance`` | ``Security`` | ...), ``DeviceID``
      (foreign key into the device inventory above), the
      ``IssueTimestamp`` first-seen / last-seen window, the
      ``Component`` (interface / module / config-section the
      rule fired on), and any rule-specific ``Details``.  When
      ``NETMRI_GROUP_ID`` is set the dispatcher forwards it as
      ``?DeviceGroupID=<id>`` so the walk only returns issues
      whose owning device belongs to that group.

Pagination is offset-based via NetMRI's ``start`` + ``limit``
cursors.  The first request carries ``?limit=100&start=0``;
each subsequent request increments ``start`` by the page size
until the returned ``<resource>`` list is shorter than the page
size (NetMRI's documented "no more pages" signal — the
``total`` field is informational and not load-bearing here) or
the env-only ``NETMRI_PAGES`` cap is reached.  ``limit`` is
fixed at 100 (a conservative default; NetMRI accepts up to
10000 but smaller pages keep response sizes manageable for the
dispatcher event loop).

Auth: NetMRI's REST API supports HTTP Basic Auth.  Operators
provision a service account in the NetMRI admin UI under
``Settings -> User Admin -> Users`` with a read-only role
(``SysAdmin`` or a custom role with read-only access to the
device + issue surfaces is sufficient for the dispatcher).
The dispatcher carries credentials on every request as
``Authorization: Basic <base64(user:pass)>``.  ``NETMRI_HOST``
is the operator's NetMRI appliance host (e.g.
``netmri.mycorp.com``); ``https://`` is added automatically
when the operator pasted in a bare FQDN.  TLS verification is
left to ``requests`` defaults (operators with self-signed
appliance certs should set ``REQUESTS_CA_BUNDLE`` in the
dispatcher env to point at the appliance CA bundle).

Severity mapping for issues: NetMRI's ``Severity`` enum maps to
Faraday severities as ``Error`` -> ``high``, ``Warning`` ->
``med``, ``Info`` / ``Informational`` -> ``info``.  Devices are
always ``info`` (inventory entries, not findings).
Tags: [infoblox_netmri, network, ncm, device|issue].
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

TIMEOUT = 60
PER_PAGE = 100  # NetMRI default page size; hard cap is 10000.
DEFAULT_PAGES = 5
MAX_PAGES = 50
NETMRI_API_VERSION = "3"

SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - InfobloxNetMRI: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on NETMRI_HOST.

    No default — the NetMRI appliance host is operator-specific
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


def validate_group_id(value):
    """Validate NETMRI_GROUP_ID (operator-supplied device-group filter).

    None / blank -> ``""`` (no narrowing; every device / issue
    the credentials can read is walked).  Whitespace is
    trimmed.  Forwarded into the ``?DeviceGroupID=`` query
    parameter on both the devices and issues surfaces.  NetMRI
    device groups are integer-keyed in the API (operators see
    them by name in the UI under ``Network Explorer ->
    Inventory -> Device Groups`` but the API filter wants the
    numeric ID) so the executor passes the operator's value
    through verbatim and URL-encodes server-side — accidental
    non-numeric input will short-circuit cleanly with a 400 /
    empty result rather than corrupt the walk.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_pages(value):
    """Validate NETMRI_PAGES (per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-
    string; floats are floored.  Clamped to [1, MAX_PAGES] so
    a stray operator input can't fan out into 100k+ requests
    against the NetMRI API.  Not exposed as a manifest
    argument (the playbook only lists NETMRI_GROUP_ID) but
    read from the env so a tenant-side override can still tune
    the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"NETMRI_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"NETMRI_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_devices_url(host, group_id, start=0):
    """Build the /api/3/devices walk URL."""
    base = f"{normalize_base_url(host)}" f"/api/{NETMRI_API_VERSION}/devices"
    params = [f"limit={PER_PAGE}", f"start={int(start)}"]
    if group_id:
        params.append(f"DeviceGroupID={quote(str(group_id), safe='')}")
    return f"{base}?{'&'.join(params)}"


def build_issues_url(host, group_id, start=0):
    """Build the /api/3/issues walk URL."""
    base = f"{normalize_base_url(host)}" f"/api/{NETMRI_API_VERSION}/issues"
    params = [f"limit={PER_PAGE}", f"start={int(start)}"]
    if group_id:
        params.append(f"DeviceGroupID={quote(str(group_id), safe='')}")
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


SEVERITY_MAP = {
    "error": "high",
    "err": "high",
    "critical": "critical",
    "crit": "critical",
    "warning": "med",
    "warn": "med",
    "med": "med",
    "medium": "med",
    "info": "info",
    "informational": "info",
    "notice": "info",
    "low": "low",
}


def normalise_severity(value):
    """Map a NetMRI ``Severity`` string onto a Faraday severity.

    NetMRI canonically returns ``Error`` / ``Warning`` /
    ``Info`` (sometimes ``Informational``) but operators can
    customise the severity dictionary, so we tolerate a few
    aliases (``Critical``, ``Notice``, ``Low``, ``Medium``) and
    fall back to ``info`` for anything we don't recognise — the
    raw value is preserved on ``host.description`` so the
    operator can re-classify in the workspace.
    """
    if value is None:
        return "info"
    key = str(value).strip().lower()
    if not key:
        return "info"
    return SEVERITY_MAP.get(key, "info")


def _device_ip(device):
    """Pick a management IP for a NetMRI device record.

    NetMRI surfaces the management IPv4 as ``DeviceIPDotted``
    (the dotted-quad string the appliance polled the device
    on).  We fall back to the sentinel when the slot is empty.
    """
    if not isinstance(device, dict):
        return SENTINEL_IP
    addr = _str(device.get("DeviceIPDotted"))
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
        add(device.get("DeviceName"))
        add(device.get("DeviceSysName"))
    return out


def device_os(device):
    """Build the ``host.os`` string from the NetMRI vendor / model chain.

    NetMRI exposes ``DeviceVendor`` (e.g. ``Cisco``), ``DeviceModel``
    (e.g. ``ISR4451``) and ``DeviceVersion`` (the OS release).  We
    join them with a space when present so the Faraday host card
    reads like ``Cisco ISR4451 16.9.5``.
    """
    if not isinstance(device, dict):
        return ""
    bits = []
    vendor = _str(device.get("DeviceVendor"))
    if vendor:
        bits.append(vendor)
    model = _str(device.get("DeviceModel"))
    if model:
        bits.append(model)
    version = _str(device.get("DeviceVersion"))
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
    did = _str(device.get("DeviceID"))
    if did:
        add(f"NetMRI-DeviceId: {did}")
    name = _str(device.get("DeviceName"))
    if name:
        add(f"NetMRI-DeviceName: {name}")
    sysname = _str(device.get("DeviceSysName"))
    if sysname:
        add(f"NetMRI-SysName: {sysname}")
    sysdescr = _str(device.get("DeviceSysDescr"))
    if sysdescr:
        add(f"NetMRI-SysDescr: {sysdescr}")
    syslocation = _str(device.get("DeviceSysLocation"))
    if syslocation:
        add(f"NetMRI-SysLocation: {syslocation}")
    dtype = _str(device.get("DeviceType"))
    if dtype:
        add(f"NetMRI-DeviceType: {dtype}")
    vendor = _str(device.get("DeviceVendor"))
    if vendor:
        add(f"NetMRI-Vendor: {vendor}")
    model = _str(device.get("DeviceModel"))
    if model:
        add(f"NetMRI-Model: {model}")
    version = _str(device.get("DeviceVersion"))
    if version:
        add(f"NetMRI-Version: {version}")
    mac = _str(device.get("DeviceMAC"))
    if mac:
        add(f"NetMRI-MAC: {mac}")
    network = _str(device.get("Network"))
    if network:
        add(f"NetMRI-Network: {network}")
    assurance = device.get("DeviceAssurance")
    if assurance not in (None, "", [], {}):
        add(f"NetMRI-Assurance: {_serialise(assurance)}")
    start_t = _str(device.get("DeviceStartTime"))
    if start_t:
        add(f"NetMRI-StartTime: {start_t}")
    end_t = _str(device.get("DeviceEndTime"))
    if end_t:
        add(f"NetMRI-EndTime: {end_t}")
    return refs


def build_device_host(device, group_filter):
    """Build a Faraday host dict for a NetMRI device record."""
    if not isinstance(device, dict):
        return None
    hostnames = device_hostnames(device)
    primary = hostnames[0] if hostnames else (_str(device.get("DeviceID")) or "unknown device")

    desc_parts = []
    for key in (
        "DeviceID",
        "DeviceName",
        "DeviceIPDotted",
        "DeviceMAC",
        "DeviceVendor",
        "DeviceModel",
        "DeviceVersion",
        "DeviceType",
        "DeviceSysName",
        "DeviceSysDescr",
        "DeviceSysLocation",
        "DeviceAssurance",
        "Network",
        "DeviceStartTime",
        "DeviceEndTime",
    ):
        v = device.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if group_filter:
        desc_parts.append(f"netmri_group_id: {group_filter}")

    vuln = {
        "name": f"[NETWORK] NetMRI device: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": (_str(device.get("DeviceID"))[:200] or f"netmri-device-{primary}"[:200]),
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "NetMRI devices are network-management inventory "
            "entries, not vulnerabilities.  Cross-check the "
            "device against the other agents' findings — "
            "anything reported against this device's management "
            "IP indicates a real exposure on a managed network "
            "endpoint the network team owns.  Decommission or "
            "re-classify the device in the NetMRI UI "
            "(Network Explorer -> Inventory) if it should no "
            "longer appear in the discovery feed."
        ),
        "data": "",
        "refs": collect_device_refs(device),
        "cve": [],
        "cvss3": {},
        "tags": ["infoblox_netmri", "network", "ncm", "device"],
    }
    return {
        "ip": _device_ip(device),
        "os": device_os(device),
        "hostnames": hostnames,
        "mac": _str(device.get("DeviceMAC")),
        "description": f"NetMRI device {primary}",
        "vulnerabilities": [vuln],
    }


def issue_hostnames(record):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(record, dict):
        add(record.get("DeviceName"))
        add(record.get("DeviceSysName"))
    return out


def collect_issue_refs(record):
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
    iid = _str(record.get("IssueID"))
    if iid:
        add(f"NetMRI-IssueId: {iid}")
    title = _str(record.get("IssueTitle"))
    if title:
        add(f"NetMRI-IssueTitle: {title}")
    itype = _str(record.get("IssueType"))
    if itype:
        add(f"NetMRI-IssueType: {itype}")
    sev = _str(record.get("Severity"))
    if sev:
        add(f"NetMRI-Severity: {sev}")
    score = record.get("IssueScore")
    if score not in (None, "", [], {}):
        add(f"NetMRI-IssueScore: {_serialise(score)}")
    did = _str(record.get("DeviceID"))
    if did:
        add(f"NetMRI-DeviceId: {did}")
    dname = _str(record.get("DeviceName"))
    if dname:
        add(f"NetMRI-DeviceName: {dname}")
    component = _str(record.get("Component"))
    if component:
        add(f"NetMRI-Component: {component}")
    timestamp = _str(record.get("IssueTimestamp"))
    if timestamp:
        add(f"NetMRI-IssueTimestamp: {timestamp}")
    first = _str(record.get("FirstSeen"))
    if first:
        add(f"NetMRI-FirstSeen: {first}")
    last = _str(record.get("LastSeen"))
    if last:
        add(f"NetMRI-LastSeen: {last}")
    return refs


def build_issue_host(record, group_filter):
    """Build a Faraday host dict for a NetMRI issue record.

    Issues are change-management / config-compliance findings
    keyed to a device by ``DeviceID`` rather than to an IP
    coordinate, so we land them on the ``0.0.0.0`` sentinel.
    """
    if not isinstance(record, dict):
        return None
    title = (
        _str(record.get("IssueTitle"))
        or _str(record.get("IssueDescription"))
        or _str(record.get("IssueID"))
        or "unknown issue"
    )

    desc_parts = []
    for key in (
        "IssueID",
        "IssueTitle",
        "IssueDescription",
        "Severity",
        "IssueScore",
        "IssueType",
        "DeviceID",
        "DeviceName",
        "Component",
        "Details",
        "IssueTimestamp",
        "FirstSeen",
        "LastSeen",
    ):
        v = record.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if group_filter:
        desc_parts.append(f"netmri_group_id: {group_filter}")

    vuln = {
        "name": f"[NETWORK] NetMRI issue: {title}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": normalise_severity(record.get("Severity")),
        "external_id": (_str(record.get("IssueID"))[:200] or f"netmri-issue-{title}"[:200]),
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "NetMRI issues are change-management / "
            "config-compliance findings the appliance generated "
            "when a managed device drifted from policy.  Open "
            "the issue in the NetMRI UI (Network Explorer -> "
            "Issues) to see the rule definition, the offending "
            "configuration snippet and the recommended "
            "remediation.  Cross-reference against the "
            "vuln-scanner agents' findings for the same "
            "DeviceID — a high-severity NetMRI issue on a "
            "device that's also exposing a vulnerable service "
            "is usually the same root-cause misconfiguration "
            "viewed from two angles."
        ),
        "data": "",
        "refs": collect_issue_refs(record),
        "cve": [],
        "cvss3": {},
        "tags": ["infoblox_netmri", "network", "ncm", "issue"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": issue_hostnames(record),
        "mac": "",
        "description": f"NetMRI issue {title}",
        "vulnerabilities": [vuln],
    }


def fetch_all(client, build_url, host, auth, max_pages, surface_name, results_key, **build_kwargs):
    """Walk a NetMRI ``start`` + ``limit`` offset-paged envelope.

    First request sends the surface URL with ``?limit=100&start=0``
    (plus operator filters).  Each subsequent request rebuilds
    the URL with the next offset.  Stops when the returned
    ``<results_key>`` list is shorter than the page size
    (NetMRI's documented "no more pages" signal) or
    ``max_pages`` is reached.  401 short-circuits the whole
    executor because the operator credentials are wrong.  403 /
    429 / 404 just stop pagination on the surface we're walking
    and return what we have.
    """
    out = []
    start = 0
    pages = 0
    while pages < max_pages:
        url = build_url(host, start=start, **build_kwargs)
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
            log("NetMRI request rejected (401). " "Check NETMRI_USER / NETMRI_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"NetMRI {surface_name} request rejected (403). " f"Check the user role's object-level permissions.")
            return out
        if resp.status_code == 429:
            log(f"NetMRI rate-limited (429) on {surface_name}; " f"stopping pagination.")
            return out
        if resp.status_code == 404:
            log(f"NetMRI {surface_name} returned 404 — endpoint " f"missing on this NetMRI version.")
            return out
        if resp.status_code >= 400:
            log(f"NetMRI {surface_name} failed " f"({resp.status_code}): " f"{getattr(resp, 'text', '')[:500]}")
            return out
        try:
            body = resp.json()
        except ValueError:
            log(f"NetMRI {surface_name} response was not JSON")
            return out
        results = []
        if isinstance(body, dict):
            raw = body.get(results_key)
            if isinstance(raw, list):
                results = [r for r in raw if isinstance(r, dict)]
        elif isinstance(body, list):
            results = [r for r in body if isinstance(r, dict)]
        out.extend(results)
        if len(results) < PER_PAGE:
            return out
        start += PER_PAGE
        pages += 1
    if pages >= max_pages:
        log(f"hit NETMRI_PAGES={max_pages} on {surface_name}; " f"stopping pagination")
    return out


def main():
    started = time.time()

    group_id = validate_group_id(env("EXECUTOR_CONFIG_NETMRI_GROUP_ID"))
    pages = validate_pages(env("NETMRI_PAGES"))

    host = env("NETMRI_HOST", required=True)
    user = env("NETMRI_USER", required=True)
    password = env("NETMRI_PASSWORD", required=True)

    if not normalize_base_url(host):
        log("NETMRI_HOST is required")
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
        f"/api/{NETMRI_API_VERSION}/devices",
        "devices",
        group_id=group_id,
    )
    issue_hits = fetch_all(
        requests,
        build_issues_url,
        host,
        auth,
        pages,
        f"/api/{NETMRI_API_VERSION}/issues",
        "issues",
        group_id=group_id,
    )

    log(
        f"Processing {len(device_hits)} NetMRI devices + "
        f"{len(issue_hits)} issues "
        f"(group_id={group_id!r}, pages={pages})"
    )

    hosts_out = []
    for d in device_hits:
        built = build_device_host(d, group_id)
        if built is not None:
            hosts_out.append(built)
    for i in issue_hits:
        built = build_issue_host(i, group_id)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "infoblox_netmri",
            "command": "infoblox_netmri",
            "params": (f"group_id={group_id}," f"pages={pages}"),
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
