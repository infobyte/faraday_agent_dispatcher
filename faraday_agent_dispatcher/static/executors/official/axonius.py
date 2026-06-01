#!/usr/bin/env python
"""Axonius asset-inventory importer.

Pulls devices and users that match an Axonius Query Language (AQL)
expression from the Axonius v4 REST API and emits Faraday bulk-create
JSON to stdout.  Each Axonius asset becomes one Faraday host — the
device's first non-loopback IP maps onto ``host.ip`` (users get the
``0.0.0.0`` sentinel because Axonius user entities are
identity-keyed, not IP-keyed), the canonical ``hostname`` /
``adapter_count`` / ``last_seen`` enrichment lands on
``host.description``, and the asset itself becomes one Faraday
vulnerability with the ``[ASSET-INVENTORY]`` engine prefix so the
data lands in the Faraday workspace alongside the other CMDB-class
feeds (Device42, Fleet, runZero, Armis, Jamf Pro, Jira Insight).

Endpoints used:
  POST {AXONIUS_HOST}/api/V4.0/assets/devices
      -> paginated device inventory.  Request body is the canonical
      Axonius v4 search envelope:
      ``{"data": {"type": "entity_request_schema", "attributes":
      {"filter": "<AXONIUS_QUERY>", "fields": {"devices": [...]},
      "page": {"limit": 100, "offset": N}, "use_cursor": false}}}``.
      Response envelope is JSON-API:
      ``{"data": [{"type": "device", "id": "...", "attributes":
      {...}}], "meta": {"page": {"total": N, "size": M, "number":
      0}}}`` walked page-by-page until ``len(data) < limit`` or
      ``AXONIUS_PAGES`` is reached.
  POST {AXONIUS_HOST}/api/V4.0/assets/users
      -> paginated user inventory.  Same envelope shape as the
      devices surface but the ``fields`` block scopes to ``users``
      (Axonius v4 namespaces field lists per entity type).

Auth: Axonius v4 uses a pair of long-lived credentials (API Key +
API Secret) created in the Axonius console under
``Account -> API Key``.  The dispatcher carries them on every
request as the ``api-key`` and ``api-secret`` headers — Axonius
v4 explicitly does NOT use Authorization: Bearer / Basic.
``AXONIUS_HOST`` is the Axonius tenant host (e.g.
``axonius.mycorp.com``); on-prem deployments override it via the
agent env vars.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

TIMEOUT = 60
PER_PAGE = 100  # Axonius v4 caps page.limit at 2000 but 100 keeps the response sizes manageable.
DEFAULT_PAGES = 5
MAX_PAGES = 50

# Default device-side field set when AXONIUS_FIELDS is blank.  These
# are the canonical Axonius v4 paths every device adapter populates
# (specific_data.data.* projects across all installed adapters).
DEFAULT_DEVICE_FIELDS = (
    "specific_data.data.hostname",
    "specific_data.data.name",
    "specific_data.data.network_interfaces.ips",
    "specific_data.data.network_interfaces.mac",
    "specific_data.data.os.type",
    "specific_data.data.os.distribution",
    "specific_data.data.os.os_str",
    "specific_data.data.last_seen",
    "specific_data.data.first_seen",
    "adapter_list_length",
    "labels",
)
DEFAULT_USER_FIELDS = (
    "specific_data.data.username",
    "specific_data.data.mail",
    "specific_data.data.domain",
    "specific_data.data.last_seen",
    "specific_data.data.is_admin",
    "specific_data.data.is_disabled",
    "adapter_list_length",
    "labels",
)


def log(msg):
    print(f"{datetime.utcnow()} - Axonius: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on AXONIUS_HOST.

    No default — the Axonius tenant host is operator-specific so we
    sys.exit(1) upstream in ``main`` when the env var is missing.
    Here we just whitespace-trim, strip trailing slashes and add
    ``https://`` when the operator pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_query(value):
    """Validate AXONIUS_QUERY (the operator-supplied AQL string).

    None / blank -> ``""`` (Axonius v4 accepts an empty filter and
    interprets it as "all assets").  Whitespace is trimmed.  Anything
    else is forwarded verbatim — AQL is free-form (e.g.
    ``("specific_data.data.os.type" == "Windows") and
    ("specific_data.data.last_seen" > date("NOW - 30d"))``).
    """
    if value is None:
        return ""
    text = str(value).strip()
    return text


def parse_fields_csv(value, defaults):
    """Parse AXONIUS_FIELDS into a deduplicated field list.

    Empty / None -> ``list(defaults)``.  CSV input is split on commas,
    whitespace-trimmed, deduplicated (preserving first-seen order),
    and any blank entries are dropped.  Anything that doesn't look
    like an Axonius dotted path is forwarded verbatim — the operator
    may know about a tenant-specific adapter field.
    """
    if value is None:
        return list(defaults)
    text = str(value).strip()
    if not text:
        return list(defaults)
    out = []
    seen = set()
    for chunk in text.split(","):
        token = chunk.strip()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    if not out:
        return list(defaults)
    return out


def validate_pages(value):
    """Validate AXONIUS_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Axonius API.  Not exposed as a manifest argument (the playbook
    only lists AXONIUS_QUERY + AXONIUS_FIELDS) but read from the env
    so a tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"AXONIUS_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"AXONIUS_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_devices_url(host):
    return f"{normalize_base_url(host)}/api/V4.0/assets/devices"


def build_users_url(host):
    return f"{normalize_base_url(host)}/api/V4.0/assets/users"


def build_request_body(query, fields, offset, entity_field_key, limit=PER_PAGE):
    """Build the POST body for an Axonius v4 ``/assets/<entity>`` call.

    The Axonius v4 search envelope is JSON-API style:
    ``{"data": {"type": "entity_request_schema", "attributes": {...}}}``.
    The ``fields`` block is namespaced per entity type (``devices`` or
    ``users``) so the same envelope shape ships to both surfaces.
    Pagination is offset-based via ``page.limit`` + ``page.offset``.
    """
    return {
        "data": {
            "type": "entity_request_schema",
            "attributes": {
                "filter": str(query or ""),
                "fields": {entity_field_key: list(fields)},
                "page": {"limit": int(limit), "offset": int(offset) if offset is not None else 0},
                "use_cursor": False,
            },
        }
    }


def auth_headers(api_key, api_secret):
    """Return the Axonius v4 auth header set.

    Axonius v4 explicitly does NOT use ``Authorization: Bearer`` —
    the API key and secret travel as their own dedicated headers.
    """
    return {
        "api-key": str(api_key or ""),
        "api-secret": str(api_secret or ""),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_hits(body):
    """Pull the asset list from an Axonius v4 search envelope.

    Axonius v4 uses JSON-API: ``{"data": [{"type": ..., "id": ...,
    "attributes": {...}}], "meta": {...}}``.  Some federated /
    legacy stacks expose the hits at the envelope root or under
    ``assets`` / ``results`` — accept all four for resilience.
    """
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("data", "assets", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_attributes(hit):
    """Pull the ``attributes`` block from a JSON-API hit.

    Axonius v4 wraps every asset in ``{"type": ..., "id": ...,
    "attributes": {...}}``.  Legacy stacks emit the attributes flat
    at the root — return the hit itself in that case.
    """
    if not isinstance(hit, dict):
        return {}
    attrs = hit.get("attributes")
    if isinstance(attrs, dict):
        return attrs
    return hit


def extract_total(body):
    if not isinstance(body, dict):
        return None
    meta = body.get("meta")
    if isinstance(meta, dict):
        page = meta.get("page")
        if isinstance(page, dict):
            for key in ("total", "totalResults", "count"):
                v = page.get(key)
                if isinstance(v, int):
                    return v
        for key in ("total", "count"):
            v = meta.get(key)
            if isinstance(v, int):
                return v
    for key in ("total", "totalResults", "count"):
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
    """Coerce a single Axonius attribute value into a printable string.

    Axonius projects ``specific_data.data.<key>`` as either a scalar,
    a list (when multiple adapters report a value), or a list-of-lists
    (when each adapter reports its own list).  We flatten everything
    onto the first non-blank scalar so the executor can copy it into
    Faraday's ``host.os`` / ``host.ip`` slot.
    """
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
    return ""


def _flatten_strings(value):
    """Coerce an Axonius attribute value into a deduped string list."""
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

    add(value)
    return out


def device_ip(attrs):
    """Pick the first non-loopback IP for an Axonius device.

    Axonius projects IPs through ``specific_data.data.network_interfaces.ips``
    which is a list of strings (the projection auto-flattens the
    adapter-side list-of-lists).  Some tenants expose
    ``specific_data.data.last_used_ip`` directly.  Loopback / zero
    are explicitly skipped because Axonius would not return them in
    real data.
    """
    if not isinstance(attrs, dict):
        return "0.0.0.0"
    candidates = []
    for key in (
        "specific_data.data.network_interfaces.ips",
        "specific_data.data.last_used_ip",
        "specific_data.data.public_ips",
        "ips",
        "ip",
    ):
        v = attrs.get(key)
        candidates.extend(_flatten_strings(v))
    for ip in candidates:
        if ip and ip not in ("0.0.0.0", "127.0.0.1", "::1"):
            return ip
    return "0.0.0.0"


def device_hostnames(attrs):
    """Walk an Axonius device for hostname candidates."""
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

    if not isinstance(attrs, dict):
        return out

    for key in (
        "specific_data.data.hostname",
        "specific_data.data.name",
        "specific_data.data.fqdn",
        "specific_data.data.dns_name",
        "hostname",
        "name",
    ):
        for n in _flatten_strings(attrs.get(key)):
            add(n)
    return out


def device_mac(attrs):
    if not isinstance(attrs, dict):
        return ""
    for key in (
        "specific_data.data.network_interfaces.mac",
        "specific_data.data.mac_address",
        "mac",
    ):
        for m in _flatten_strings(attrs.get(key)):
            return m
    return ""


def device_os(attrs):
    """Build the ``host.os`` string from Axonius' OS projection."""
    if not isinstance(attrs, dict):
        return ""
    bits = []
    for key in (
        "specific_data.data.os.os_str",
        "specific_data.data.os.distribution",
        "specific_data.data.os.type",
        "specific_data.data.os.build",
        "specific_data.data.os.kernel_version",
    ):
        v = _flatten_string(attrs.get(key))
        if v:
            bits.append(v)
    if not bits:
        for legacy in ("os", "operating_system"):
            v = _flatten_string(attrs.get(legacy))
            if v:
                bits.append(v)
                break
    return " ".join(bits)


def user_principal(attrs):
    """Pick the canonical principal string for an Axonius user."""
    if not isinstance(attrs, dict):
        return ""
    for key in (
        "specific_data.data.username",
        "specific_data.data.mail",
        "specific_data.data.user_principal_name",
        "specific_data.data.upn",
        "username",
        "name",
    ):
        v = _flatten_string(attrs.get(key))
        if v:
            return v
    return ""


def collect_cves(item):
    """Walk an Axonius item for CVE-* ids."""
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

    for key in ("cve", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)

    for list_key in ("cves", "cve_ids", "vulnerabilities", "specific_data.data.vulnerabilities"):
        v = item.get(list_key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("cveId") or entry.get("id"))
                elif isinstance(entry, str):
                    add(entry)

    for key in ("name", "title", "description", "summary"):
        scan(item.get(key))
    return found


def collect_refs(hit, attrs, entity_type):
    """Walk an Axonius hit for advisory URLs / pivots."""
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

    if isinstance(hit, dict):
        aid = hit.get("id") or hit.get("internal_axon_id")
        if isinstance(aid, str) and aid.strip():
            add(f"Axonius-Id: {aid.strip()}")

    if isinstance(attrs, dict):
        internal = attrs.get("internal_axon_id")
        if isinstance(internal, str) and internal.strip():
            add(f"Axonius-InternalId: {internal.strip()}")
        adapter_count = attrs.get("adapter_list_length") or attrs.get("adapters")
        if isinstance(adapter_count, int):
            add(f"Axonius-Adapters: {adapter_count}")
        elif isinstance(adapter_count, list):
            add(f"Axonius-Adapters: {len(adapter_count)}")
        labels = attrs.get("labels")
        if isinstance(labels, list) and labels:
            joined = ",".join(str(label) for label in labels if label)
            if joined:
                add(f"Axonius-Labels: {joined}")
        for key in ("specific_data.data.last_seen", "last_seen"):
            v = _flatten_string(attrs.get(key))
            if v:
                add(f"Axonius-LastSeen: {v}")
                break

    if entity_type == "user":
        principal = user_principal(attrs) if isinstance(attrs, dict) else ""
        if principal:
            add(f"Axonius-User: {principal}")

    return refs


def build_asset_vulnerability(hit, attrs, entity_type, query):
    """Build a Faraday vulnerability dict for one Axonius asset."""
    if entity_type == "device":
        label_subject = device_hostnames(attrs)
        primary = (
            label_subject[0]
            if label_subject
            else (device_ip(attrs) if device_ip(attrs) != "0.0.0.0" else "unknown device")
        )
        label = f"[ASSET-INVENTORY] Axonius device: {primary}"
    else:
        principal = user_principal(attrs) or "unknown user"
        label = f"[ASSET-INVENTORY] Axonius user: {principal}"

    desc_parts = []
    if isinstance(attrs, dict):
        for key in sorted(attrs.keys()):
            v = attrs.get(key)
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"{key}: {_serialise(v)}")
            else:
                desc_parts.append(f"{key}: {v}")
    if query:
        desc_parts.append(f"axonius_query: {query}")

    cves = collect_cves(attrs) if isinstance(attrs, dict) else []
    refs = collect_refs(hit, attrs, entity_type)

    external_id = ""
    if isinstance(hit, dict):
        external_id = str(hit.get("id") or "")
    if not external_id and isinstance(attrs, dict):
        external_id = str(attrs.get("internal_axon_id") or "")
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
            "Axonius asset records are inventory entries, not vulnerabilities. "
            "Cross-check the asset against the other agents' findings (EDR / "
            "EASM / vuln scanners) — anything reported against this asset id "
            "indicates a real exposure on a known managed device.  Decommission "
            "or reclassify the asset in Axonius if it should no longer appear "
            "in the inventory."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["axonius", "asset-inventory", entity_type],
    }


def build_host_from_device(hit, query):
    """Build a Faraday host dict from an Axonius device hit."""
    if hit is None:
        return None
    attrs = extract_attributes(hit)
    if not isinstance(attrs, dict):
        return None

    ip = device_ip(attrs)
    hostnames = device_hostnames(attrs)
    mac = device_mac(attrs)
    os_str = device_os(attrs)

    desc_parts = []
    for key in (
        "adapter_list_length",
        "specific_data.data.first_seen",
        "specific_data.data.last_seen",
        "labels",
    ):
        v = attrs.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    vuln = build_asset_vulnerability(hit, attrs, "device", query)
    return {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln] if vuln else [],
    }


def build_host_from_user(hit, query):
    """Build a Faraday host dict for an Axonius user hit.

    Users aren't IP-keyed (Axonius identity entries can span many
    endpoints) — synthesise a 0.0.0.0 host so the workspace still
    surfaces the finding, and hang the principal on
    ``host.hostnames`` so Faraday's hostname index still pivots on
    it.
    """
    if hit is None:
        return None
    attrs = extract_attributes(hit)
    if not isinstance(attrs, dict):
        return None
    principal = user_principal(attrs)
    hostnames = [principal] if principal else []
    vuln = build_asset_vulnerability(hit, attrs, "user", query)
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Axonius user identity",
        "vulnerabilities": [vuln] if vuln else [],
    }


def fetch_pages(requests_module, url, headers, body_builder, max_pages):
    """Walk an Axonius v4 ``/assets/<entity>`` envelope.

    ``body_builder`` is a callable ``(offset) -> dict`` that builds
    each POST body.  We page until either ``len(hits) < PER_PAGE`` or
    ``max_pages`` is reached.  401 short-circuits the whole executor
    because the operator credentials are wrong (the matching
    surfaces also 401 on the same key set).  403 / 429 just stop
    pagination on the surface we're walking and return what we
    have.
    """
    out = []
    offset = 0
    walked = 0
    hits = []
    while walked < max_pages:
        body = body_builder(offset)
        try:
            resp = requests_module.post(url, headers=headers, json=body, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"POST {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Axonius request rejected (401). Check AXONIUS_API_KEY / AXONIUS_API_SECRET.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Axonius request rejected (403). Check the key's tenant scope.")
            return out
        if resp.status_code == 429:
            log("Axonius rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Axonius request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Axonius response was not JSON ({url})")
            return out
        hits = extract_hits(payload)
        for entry in hits:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(hits) < PER_PAGE:
            break
        offset += PER_PAGE
    if walked >= max_pages and len(hits) >= PER_PAGE:
        log(f"hit AXONIUS_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    query = validate_query(env("EXECUTOR_CONFIG_AXONIUS_QUERY"))
    raw_fields = env("EXECUTOR_CONFIG_AXONIUS_FIELDS")
    device_fields = parse_fields_csv(raw_fields, DEFAULT_DEVICE_FIELDS)
    user_fields = parse_fields_csv(raw_fields, DEFAULT_USER_FIELDS)
    pages = validate_pages(env("AXONIUS_PAGES"))

    host = env("AXONIUS_HOST", required=True)
    api_key = env("AXONIUS_API_KEY", required=True)
    api_secret = env("AXONIUS_API_SECRET", required=True)

    if not normalize_base_url(host):
        log("AXONIUS_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(api_key, api_secret)
    devices_url = build_devices_url(host)
    users_url = build_users_url(host)

    device_hits = fetch_pages(
        requests,
        devices_url,
        headers,
        lambda offset: build_request_body(query, device_fields, offset, "devices"),
        max_pages=pages,
    )
    user_hits = fetch_pages(
        requests,
        users_url,
        headers,
        lambda offset: build_request_body(query, user_fields, offset, "users"),
        max_pages=pages,
    )

    log(
        f"Processing {len(device_hits)} Axonius devices + {len(user_hits)} users "
        f"(query={query!r}, fields={len(device_fields)}+{len(user_fields)}, pages={pages})"
    )

    hosts_out = []
    for hit in device_hits:
        built = build_host_from_device(hit, query)
        if built is not None:
            hosts_out.append(built)
    for hit in user_hits:
        built = build_host_from_user(hit, query)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "axonius",
            "command": "axonius",
            "params": (
                f"query={query},"
                f"device_fields={len(device_fields)},"
                f"user_fields={len(user_fields)},"
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
