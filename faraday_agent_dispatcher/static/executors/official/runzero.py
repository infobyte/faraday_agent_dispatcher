#!/usr/bin/env python
"""runZero asset-inventory importer.

Pulls discovered assets and observed services from a runZero
(runzero.com, formerly Rumble Network Discovery) console via the
runZero v1.0 REST API and emits Faraday bulk-create JSON to stdout.
Each runZero asset becomes one Faraday host — the asset's first
non-loopback IP from ``addresses`` (with ``addresses_extra`` as a
fallback) maps onto ``host.ip`` (loopback / ``0.0.0.0`` / ``::1``
are explicitly skipped; we fall back to the ``0.0.0.0`` sentinel
when nothing usable is found), the ``names`` projection lands on
``host.hostnames``, the first ``macs`` entry lands on ``host.mac``,
the ``os`` / ``os_vendor`` / ``os_product`` / ``os_version`` /
``hw`` / ``hw_vendor`` chain joins onto ``host.os``, and the asset
itself becomes one Faraday vulnerability with the
``[ASSET-INVENTORY]`` engine prefix.  Each runZero service from
``/api/v1.0/org/services`` becomes one synthetic Faraday host keyed
on the service's ``address`` field so the workspace still surfaces
the per-port discovery alongside the asset inventory; the service
``port`` / ``protocol`` / ``service_product`` projection lands on
``host.hostnames`` and the per-service banner / summary fields are
embedded in the vulnerability description.

Endpoints used:
  GET {RUNZERO_HOST}/api/v1.0/org/assets?search=...&limit=N&offset=M
      -> the canonical runZero asset inventory.  Returns a bare JSON
      list of asset records (NOT wrapped in an envelope); each
      record carries ``id``, ``organization_id``, ``site_id``,
      ``site_name``, ``addresses`` (list of IPs),
      ``addresses_extra`` (list of additional / historical IPs),
      ``mac_vendors``, ``macs`` (list of MACs), ``names`` (list of
      hostnames), ``os``, ``os_vendor``, ``os_product``,
      ``os_version``, ``hw``, ``hw_vendor``, ``hw_product``,
      ``hw_version``, ``type`` (Desktop / Server / Phone / IoT /
      etc.), ``tags`` (list), ``last_seen``, ``first_seen``,
      ``service_count``, ``service_ports_products``,
      ``service_ports_protocols``, ``attributes`` (dict of
      operator-defined custom attributes).  ``RUNZERO_SEARCH`` is
      forwarded as a server-side ``search=<value>`` query-string
      filter using the runZero search query language (e.g.
      ``type:server os:linux`` or ``site:HQ``).
  GET {RUNZERO_HOST}/api/v1.0/org/services?search=...&limit=N
      &offset=M
      -> the runZero per-port service inventory.  Returns a bare
      JSON list of service records carrying ``id``, ``asset_id``,
      ``address`` (the service's IP), ``port``, ``protocol``
      (TCP / UDP / etc.), ``transport``, ``service_protocol``,
      ``service_summary``, ``service_vendor``, ``service_product``,
      ``service_version``, ``last_seen``, ``first_seen``,
      ``attributes`` (per-service banner / TLS / probe attributes).
      ``RUNZERO_SEARCH`` is forwarded verbatim on this surface too
      so a single AQL-ish query scopes both walks consistently
      (runZero shares the search syntax across the two endpoints).

Pagination is offset-based on both surfaces (``limit`` + ``offset``
in the query string).  We walk page-by-page (offset += limit per
request) until ``len(records) < limit`` or the env-only
``RUNZERO_PAGES`` cap is reached (default 5, clamped to [1, 50]).
``RUNZERO_LIMIT`` controls the per-page record cap (default 1000,
clamped to [1, 5000] — runZero's documented hard cap is 5000 per
page; values above 5000 are silently clamped server-side).

Auth: runZero uses long-lived organization API keys generated via
the runZero console under ``Account -> API Keys``; pick an
Organization-scoped key (NOT an Account-scoped one) since the
inventory walk is per-organization.  The dispatcher carries the
token on every request as the standard
``Authorization: Bearer <RUNZERO_TOKEN>`` header.  ``RUNZERO_HOST``
defaults to ``console.runzero.com`` (the SaaS console); on-prem /
self-hosted appliances are common so we also tolerate
``runzero.mycorp.local`` and add ``https://`` automatically when
the operator pasted in a bare FQDN.

Severity is always ``info`` because runZero hits are inventory
entries, not vulnerability findings — operators correlate against
the EDR / EASM / vuln-scanner agents' findings via the
``RunZero-Id`` / ``RunZero-Site`` / ``RunZero-Type`` /
``RunZero-LastSeen`` / ``RunZero-OSVersion`` / ``RunZero-Tags`` /
``RunZero-ServiceCount`` refs on asset hits, and the
``RunZero-ServiceId`` / ``RunZero-AssetId`` / ``RunZero-Port`` /
``RunZero-Protocol`` / ``RunZero-Product`` / ``RunZero-LastSeen``
refs on service hits.  Tags: [runzero, asset-inventory,
asset|service].
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
DEFAULT_LIMIT = 1000  # runZero's documented default page size.
MAX_LIMIT = 5000  # runZero's documented hard cap per page.
DEFAULT_PAGES = 5
MAX_PAGES = 50


def log(msg):
    print(f"{datetime.utcnow()} - runZero: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on RUNZERO_HOST.

    Defaults to ``console.runzero.com`` (the SaaS console) when no
    value is supplied so the SaaS-only operator can run the
    executor without setting RUNZERO_HOST explicitly.  Whitespace
    is trimmed, trailing slashes are stripped, and ``https://`` is
    added automatically when the operator pasted in a bare FQDN
    (self-hosted appliances commonly use raw hostnames).
    """
    if host is None or (isinstance(host, str) and not host.strip()):
        return "https://console.runzero.com"
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_search(value):
    """Validate RUNZERO_SEARCH (the operator-supplied query).

    None / blank -> ``""`` (no narrowing; the whole organization is
    walked).  Whitespace is trimmed.  runZero's query syntax is
    forwarded verbatim — the executor doesn't second-guess
    operator-supplied predicates like ``type:server os:linux`` or
    ``site:HQ alive:true``.
    """
    if value is None:
        return ""
    text = str(value).strip()
    return text


def validate_limit(value):
    """Validate RUNZERO_LIMIT (the per-page record cap).

    None / blank -> DEFAULT_LIMIT.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_LIMIT] so a stray
    operator input can't request more records per page than runZero
    actually serves (the API silently caps the value server-side
    anyway, but doing the clamp here keeps pagination honest).
    """
    if value is None or value == "":
        return DEFAULT_LIMIT
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"RUNZERO_LIMIT '{value}' not numeric; defaulting to {DEFAULT_LIMIT}")
        return DEFAULT_LIMIT
    if n < 1:
        return 1
    if n > MAX_LIMIT:
        log(f"RUNZERO_LIMIT {n} above MAX_LIMIT={MAX_LIMIT}; clamping")
        return MAX_LIMIT
    return n


def validate_pages(value):
    """Validate RUNZERO_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    runZero console.  Not exposed as a manifest argument (the
    playbook only lists RUNZERO_SEARCH + RUNZERO_LIMIT) but read
    from the env so a tenant-side override can still tune the
    walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"RUNZERO_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"RUNZERO_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_assets_url(host):
    return f"{normalize_base_url(host)}/api/v1.0/org/assets"


def build_services_url(host):
    return f"{normalize_base_url(host)}/api/v1.0/org/services"


def build_query(offset, limit=DEFAULT_LIMIT, extra=None):
    """Build the canonical runZero paging query string.

    runZero uses offset-based paging (``limit`` + ``offset``).
    ``extra`` is an optional dict of additional filter params (e.g.
    ``{"search": "type:server"}``).  Values are URL-encoded and
    blanks are dropped so the resulting query string never carries
    ``search=`` with an empty value (runZero would treat that as
    "match everything" anyway, but the explicit drop keeps the wire
    format predictable).
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


def bearer_auth_header(token):
    """Build the canonical ``Authorization: Bearer ...`` header value.

    runZero's REST API uses long-lived organization API keys
    generated via the runZero console under ``Account -> API
    Keys``.  We build the header inline (rather than relying on a
    third-party library) so test fixtures + unit checks can assert
    on the exact wire format and requests won't strip a
    manually-built Authorization header on cross-host redirects.
    """
    return f"Bearer {token or ''}"


def auth_headers(token):
    return {
        "Authorization": bearer_auth_header(token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_records(body):
    """Pull the record list from a runZero v1.0 response.

    runZero's ``/assets`` and ``/services`` return a bare JSON list
    of records (NOT wrapped in an envelope).  We also accept the
    common envelope shapes (``data`` / ``results`` / ``items`` /
    ``assets`` / ``services``) so federated / future stacks still
    round-trip through the same extractor.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("assets", "services", "data", "results", "items"):
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
    """Coerce a single runZero attribute value into a printable string."""
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
    """Coerce a runZero attribute value into a deduped string list."""
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


def asset_ips(asset):
    """Walk a runZero asset record for IP candidates.

    runZero projects IPs through ``addresses`` (list of strings) on
    the canonical ``/assets`` surface, with ``addresses_extra`` as
    a fallback list holding historical / secondary addresses.
    Loopback / zero are skipped.
    """
    if not isinstance(asset, dict):
        return []
    candidates = []
    for key in ("addresses", "addresses_extra"):
        v = asset.get(key)
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


def asset_ip(asset):
    """Pick the first non-loopback IP for a runZero asset."""
    ips = asset_ips(asset)
    return ips[0] if ips else "0.0.0.0"


def asset_hostnames(asset):
    """Walk a runZero asset record for hostname candidates."""
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

    if not isinstance(asset, dict):
        return out

    for n in _flatten_strings(asset.get("names")):
        add(n)
    for key in ("hostname", "fqdn", "name"):
        for n in _flatten_strings(asset.get(key)):
            add(n)
    return out


def asset_mac(asset):
    if not isinstance(asset, dict):
        return ""
    v = asset.get("macs")
    if v:
        s = _flatten_string(v)
        if s:
            return s
    for key in ("mac", "mac_address"):
        v = asset.get(key)
        if v:
            s = _flatten_string(v)
            if s:
                return s
    return ""


def asset_os(asset):
    """Build the ``host.os`` string from runZero's OS projection."""
    if not isinstance(asset, dict):
        return ""
    bits = []
    for key in ("os", "os_product", "os_vendor"):
        v = _flatten_string(asset.get(key))
        if v:
            bits.append(v)
            break
    for key in ("os_version",):
        v = _flatten_string(asset.get(key))
        if v:
            bits.append(v)
            break
    for key in ("hw", "hw_product"):
        v = _flatten_string(asset.get(key))
        if v:
            bits.append(v)
            break
    for key in ("hw_vendor",):
        v = _flatten_string(asset.get(key))
        if v:
            bits.append(v)
            break
    return " ".join(bits)


def asset_tags(asset):
    """Return a deduped list of runZero tag names for an asset."""
    out = []
    seen = set()
    if not isinstance(asset, dict):
        return out
    raw = asset.get("tags")
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("tag")
                if isinstance(name, str):
                    s = name.strip()
                    if s and s not in seen:
                        seen.add(s)
                        out.append(s)
            elif isinstance(entry, str):
                s = entry.strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
    elif isinstance(raw, dict):
        for k, v in raw.items():
            ks = str(k).strip()
            if ks and ks not in seen:
                seen.add(ks)
                out.append(ks)
            vs = str(v).strip() if v is not None else ""
            if vs and vs not in seen:
                seen.add(vs)
                out.append(vs)
    return out


def collect_cves(item):
    """Walk a runZero item for CVE-* ids.

    runZero doesn't surface CVE-keyed findings on the canonical
    ``/assets`` or ``/services`` endpoints, but operators sometimes
    paste CVEs into ``service_summary`` / banner attributes and tag
    names so we still scan those for completeness.
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

    for key in (
        "service_summary",
        "service_product",
        "service_version",
        "os",
        "os_version",
        "name",
        "comment",
    ):
        scan(item.get(key))

    attributes = item.get("attributes")
    if isinstance(attributes, dict):
        for v in attributes.values():
            if isinstance(v, str):
                scan(v)
            elif isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        scan(entry)

    tags = item.get("tags")
    if isinstance(tags, list):
        for entry in tags:
            if isinstance(entry, str):
                scan(entry)

    return found


def collect_refs(item, entity_type):
    """Walk a runZero record for advisory URLs / pivots."""
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

    if entity_type == "asset":
        aid = item.get("id") or item.get("asset_id")
        if aid is not None and str(aid).strip():
            add(f"RunZero-Id: {str(aid).strip()}")
        site_name = _flatten_string(item.get("site_name"))
        site_id = _flatten_string(item.get("site_id"))
        if site_name:
            add(f"RunZero-Site: {site_name}")
        elif site_id:
            add(f"RunZero-Site: {site_id}")
        asset_type = _flatten_string(item.get("type"))
        if asset_type:
            add(f"RunZero-Type: {asset_type}")
        for key in ("last_seen", "updated_at", "first_seen"):
            v = _flatten_string(item.get(key))
            if v:
                add(f"RunZero-LastSeen: {v}")
                break
        os_version = _flatten_string(item.get("os_version") or item.get("os"))
        if os_version:
            add(f"RunZero-OSVersion: {os_version}")
        tags = asset_tags(item)
        if tags:
            add(f"RunZero-Tags: {','.join(tags)}")
        svc_count = item.get("service_count")
        if isinstance(svc_count, (int, float)) and svc_count:
            add(f"RunZero-ServiceCount: {int(svc_count)}")
    else:
        sid = item.get("id") or item.get("service_id")
        if sid is not None and str(sid).strip():
            add(f"RunZero-ServiceId: {str(sid).strip()}")
        asset_id = _flatten_string(item.get("asset_id"))
        if asset_id:
            add(f"RunZero-AssetId: {asset_id}")
        port = item.get("port")
        if isinstance(port, (int, float)) and port:
            add(f"RunZero-Port: {int(port)}")
        elif isinstance(port, str) and port.strip():
            add(f"RunZero-Port: {port.strip()}")
        protocol = _flatten_string(item.get("protocol") or item.get("transport"))
        if protocol:
            add(f"RunZero-Protocol: {protocol}")
        product = _flatten_string(item.get("service_product") or item.get("service_summary"))
        if product:
            add(f"RunZero-Product: {product}")
        for key in ("last_seen", "updated_at", "first_seen"):
            v = _flatten_string(item.get(key))
            if v:
                add(f"RunZero-LastSeen: {v}")
                break

    return refs


def build_asset_vulnerability(item, entity_type, search, limit):
    """Build a Faraday vulnerability dict for one runZero record."""
    if entity_type == "asset":
        hostnames = asset_hostnames(item)
        primary = hostnames[0] if hostnames else (asset_ip(item) if asset_ip(item) != "0.0.0.0" else "unknown asset")
        label = f"[ASSET-INVENTORY] runZero asset: {primary}"
    else:
        if isinstance(item, dict):
            address = _flatten_string(item.get("address"))
            port = item.get("port")
            port_str = ""
            if isinstance(port, (int, float)) and port:
                port_str = str(int(port))
            elif isinstance(port, str) and port.strip():
                port_str = port.strip()
            if address and port_str:
                primary = f"{address}:{port_str}"
            else:
                primary = address or port_str or "unknown service"
        else:
            primary = "unknown service"
        label = f"[ASSET-INVENTORY] runZero service: {primary}"

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
    if search:
        desc_parts.append(f"runzero_search: {search}")
    if limit:
        desc_parts.append(f"runzero_limit: {limit}")

    cves = collect_cves(item) if isinstance(item, dict) else []
    refs = collect_refs(item, entity_type)

    external_id = ""
    if isinstance(item, dict):
        external_id = str(item.get("id") or item.get("asset_id") or item.get("service_id") or "")
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
            "runZero records are inventory entries, not "
            "vulnerabilities.  Cross-check the asset against the "
            "other agents' findings (EDR / EASM / vuln scanners) — "
            "anything reported against this runZero asset id "
            "indicates a real exposure on a known discovered "
            "endpoint.  Retire or merge the asset in runZero if it "
            "should no longer appear in the inventory.  For service "
            "hits, the surfaced record documents an open port — "
            "review the service banner against the operator's "
            "expected service catalogue."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["runzero", "asset-inventory", entity_type],
    }


def build_host_from_asset(asset_record, search, limit):
    """Build a Faraday host dict from a runZero asset record."""
    if asset_record is None or not isinstance(asset_record, dict):
        return None

    ip = asset_ip(asset_record)
    hostnames = asset_hostnames(asset_record)
    mac = asset_mac(asset_record)
    os_str = asset_os(asset_record)

    desc_parts = []
    for key in (
        "type",
        "site_name",
        "site_id",
        "os",
        "os_version",
        "hw",
        "hw_vendor",
        "service_count",
        "last_seen",
        "first_seen",
    ):
        v = asset_record.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    vuln = build_asset_vulnerability(asset_record, "asset", search, limit)
    return {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln] if vuln else [],
    }


def build_host_from_service(service_record, search, limit):
    """Build a Faraday host dict for a runZero service record.

    runZero services ARE IP-keyed (each carries an ``address``
    field), so we project the service's address onto host.ip rather
    than synthesising a sentinel.  Loopback / zero are skipped (we
    fall back to ``0.0.0.0`` if the address is missing or unusable).
    The ``port`` / ``service_product`` projection lands on
    hostnames so Faraday's hostname index still pivots on it.
    """
    if service_record is None or not isinstance(service_record, dict):
        return None

    raw_addr = _flatten_string(service_record.get("address"))
    if raw_addr in ("", "0.0.0.0", "127.0.0.1", "::1"):
        ip = "0.0.0.0"
    else:
        ip = raw_addr

    hostnames = []
    seen = set()

    def add(text):
        if not isinstance(text, str):
            return
        s = text.strip()
        if not s or s in seen:
            return
        seen.add(s)
        hostnames.append(s)

    port = service_record.get("port")
    port_str = ""
    if isinstance(port, (int, float)) and port:
        port_str = str(int(port))
    elif isinstance(port, str) and port.strip():
        port_str = port.strip()
    if port_str:
        add(f"port:{port_str}")
    add(_flatten_string(service_record.get("service_product")))
    add(_flatten_string(service_record.get("service_summary")))

    vuln = build_asset_vulnerability(service_record, "service", search, limit)
    return {
        "ip": ip,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "runZero discovered service",
        "vulnerabilities": [vuln] if vuln else [],
    }


def fetch_pages(requests_module, url, headers, limit, max_pages, extra_params=None):
    """Walk a runZero v1.0 ``/assets`` or ``/services`` envelope.

    Pagination is offset-based via ``limit`` + ``offset`` query
    parameters.  We page until either ``len(records) < limit`` or
    ``max_pages`` is reached.  401 short-circuits the whole
    executor (token is wrong); 403 / 429 / 5xx stop pagination on
    the surface and return what we have.
    """
    out = []
    offset = 0
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(offset, limit=limit, extra=extra_params)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("runZero request rejected (401). Check RUNZERO_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("runZero request rejected (403). Check the token's organization scope.")
            return out
        if resp.status_code == 429:
            log("runZero rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"runZero request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"runZero response was not JSON ({full_url})")
            return out
        records = extract_records(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < limit:
            break
        offset += limit
    if walked >= max_pages and len(records) >= limit:
        log(f"hit RUNZERO_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    search = validate_search(env("EXECUTOR_CONFIG_RUNZERO_SEARCH"))
    limit = validate_limit(env("EXECUTOR_CONFIG_RUNZERO_LIMIT"))
    pages = validate_pages(env("RUNZERO_PAGES"))

    host = env("RUNZERO_HOST")  # defaults to console.runzero.com via normalize_base_url
    token = env("RUNZERO_TOKEN", required=True)

    if not normalize_base_url(host):
        log("RUNZERO_HOST normalisation failed")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    assets_url = build_assets_url(host)
    services_url = build_services_url(host)

    extra = {"search": search} if search else None

    asset_records = fetch_pages(
        requests,
        assets_url,
        headers,
        limit,
        max_pages=pages,
        extra_params=extra,
    )
    service_records = fetch_pages(
        requests,
        services_url,
        headers,
        limit,
        max_pages=pages,
        extra_params=extra,
    )

    log(
        f"Processing {len(asset_records)} runZero assets + {len(service_records)} services "
        f"(search={search!r}, limit={limit}, pages={pages})"
    )

    hosts_out = []
    for record in asset_records:
        built = build_host_from_asset(record, search, limit)
        if built is not None:
            hosts_out.append(built)
    for record in service_records:
        built = build_host_from_service(record, search, limit)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "runzero",
            "command": "runzero",
            "params": (f"search={search}," f"limit={limit}," f"pages={pages}"),
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
