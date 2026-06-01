#!/usr/bin/env python
"""OpsLevel service-catalog asset-inventory importer.

Pulls Service records (the canonical OpsLevel surface) from an
OpsLevel tenant via the GraphQL API and emits Faraday bulk-create
JSON to stdout.  Each OpsLevel service becomes one Faraday host
(synthetic 0.0.0.0 — OpsLevel services are identity-keyed catalogue
entries in a developer portal / service catalog, not network
endpoints) and one Faraday vulnerability with the engine prefix
``[ASSET-INVENTORY]``; severity is always ``info`` since service-
catalog entries are inventory records not findings — operators
correlate against the other agents' findings (EDR / EASM / vuln
scanners) via the OpsLevel-Id / OpsLevel-Alias refs.

Endpoint used:
  POST <OPSLEVEL_HOST>/graphql
      -> single GraphQL `account.services` query carrying the
      ``tierAlias: [<tier>]`` and ``lifecycleAlias: [<lifecycle>]``
      filter args when set; paginated via the canonical Relay cursor
      shape ``{nodes, pageInfo: {hasNextPage, endCursor}, totalCount}``.

Auth: OpsLevel issues per-account API tokens via the OpsLevel console
under ``Account Settings -> API Tokens``.  The dispatcher carries
the token on every /graphql call as ``Authorization: Bearer
<OPSLEVEL_TOKEN>``.  ``OPSLEVEL_HOST`` defaults to the SaaS host
``https://app.opslevel.com``; EU-region / on-prem deployments
override the host.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# OpsLevel host validation — accept http(s)://host[:port], strip
# trailing slash.  Control chars (newline / tab / null / etc)
# rejected outright so a header-injection attempt can't sneak
# through.  Anchored with \A/\Z (not ^/$) so a trailing newline
# cannot sneak through — Python's default `$` matches just before
# a trailing `\n`.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")
# OpsLevel tier alias — canonical aliases are ``tier_1`` / ``tier_2``
# / ``tier_3`` / ``tier_4`` but operators sometimes pass the bare
# numeric (``1``) / display name (``Tier 1``).  We normalise to the
# canonical alias shape and reject anything outside the tier_N set.
TIER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\-]{0,63}\Z")
# OpsLevel lifecycle alias — canonical aliases are ``pre-alpha`` /
# ``alpha`` / ``beta`` / ``general_availability`` / ``end-of-life``
# / etc. (operator-configurable). Allow alphanumeric + `._-` up to
# 64 chars.
LIFECYCLE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\-]{0,63}\Z")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100
DEFAULT_HOST = "https://app.opslevel.com"

# OpsLevel service catalog records are inventory entries, not
# vulnerability findings, so severity is always `info` for parity
# with the other CMDB-class connectors in asset-inventory (Armis /
# Axonius / Device42 / Fleet / Jamf Pro / Jira Insight / LeanIX /
# runZero).
SEVERITY_INFO = "info"


# Map operator-supplied tier inputs onto the canonical OpsLevel
# ``tier_N`` alias shape used by the GraphQL filter arg.
_TIER_NORMALISE = {
    "1": "tier_1",
    "tier1": "tier_1",
    "tier_1": "tier_1",
    "t1": "tier_1",
    "2": "tier_2",
    "tier2": "tier_2",
    "tier_2": "tier_2",
    "t2": "tier_2",
    "3": "tier_3",
    "tier3": "tier_3",
    "tier_3": "tier_3",
    "t3": "tier_3",
    "4": "tier_4",
    "tier4": "tier_4",
    "tier_4": "tier_4",
    "t4": "tier_4",
}


def log(msg):
    print(f"{datetime.utcnow()} - OpsLevel: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def validate_host(value):
    """Validate OPSLEVEL_HOST.

    None / blank -> DEFAULT_HOST (``https://app.opslevel.com`` — the
    canonical SaaS host).  Must be ``http(s)://host[:port]``;
    trailing slash stripped client-side.  Control chars rejected so
    a header-injection attempt can't sneak through.
    """
    if value is None or value == "":
        return DEFAULT_HOST
    raw = str(value)
    # Reject any control char (incl. CR / LF / NUL) on the *raw* value
    # before .strip() runs — .strip() would otherwise eat trailing
    # newlines so a header-injection attempt could sneak through.
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("OPSLEVEL_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return DEFAULT_HOST
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"OPSLEVEL_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def validate_tier(value):
    """Validate OPSLEVEL_TIER.

    None / blank -> ``""`` (optional — when blank the executor fans
    out across all tiers).  Otherwise normalises to the canonical
    ``tier_N`` alias shape (accepts ``1`` / ``tier1`` / ``tier_1`` /
    ``Tier 1`` etc.).  Control chars rejected on the raw value
    before .strip() runs.
    """
    if value is None or value == "":
        return ""
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("OPSLEVEL_TIER contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return ""
    # Normalise common spellings: lower-case, collapse internal
    # whitespace, then look up in the canonical map.
    key = "".join(text.lower().split())
    canonical = _TIER_NORMALISE.get(key)
    if canonical:
        return canonical
    # Operator might have passed an already-canonical alias the map
    # doesn't cover; fall through to the generic alias shape check.
    if not TIER_RE.match(text):
        log(f"OPSLEVEL_TIER '{text}' is not a recognised tier alias " "(expected tier_1 / tier_2 / tier_3 / tier_4)")
        sys.exit(1)
    return text


def validate_lifecycle(value):
    """Validate OPSLEVEL_LIFECYCLE.

    None / blank -> ``""`` (optional — when blank the executor fans
    out across all lifecycles).  Otherwise must be alphanumeric +
    ``._-`` up to 64 chars (the OpsLevel lifecycle alias shape —
    e.g. ``alpha`` / ``beta`` / ``production`` /
    ``general_availability`` / ``end-of-life``).  Control chars
    rejected on the raw value before .strip() runs.
    """
    if value is None or value == "":
        return ""
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("OPSLEVEL_LIFECYCLE contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return ""
    if not LIFECYCLE_RE.match(text):
        log(f"OPSLEVEL_LIFECYCLE '{text}' is not a valid lifecycle alias " "(alphanumeric + ._- up to 64 chars)")
        sys.exit(1)
    return text


def build_graphql_url(host):
    return f"{host}/graphql"


# The canonical OpsLevel `account.services` GraphQL query.  Pagination
# uses Relay-style `first` / `after` cursors with the
# `pageInfo {hasNextPage endCursor}` envelope.  Filters are passed
# via the `tierAlias` and `lifecycleAlias` list-args on the
# `account.services` field.
SERVICES_QUERY = """
query ServicesPage($first: Int!, $after: String, $tier: [String!], $lifecycle: [String!]) {
  account {
    services(first: $first, after: $after, tierAlias: $tier, lifecycleAlias: $lifecycle) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes {
        id
        name
        description
        aliases
        product
        language
        framework
        type { alias name }
        tier { alias name index }
        lifecycle { alias name index }
        owner { alias name }
        tags { nodes { key value } }
        managedAliases
        timestamps { createdAt updatedAt }
        htmlUrl
      }
    }
  }
}
"""


def build_query_variables(tier, lifecycle, page_size, after_cursor):
    """Build the GraphQL variables dict for one ServicesPage call.

    ``tier`` / ``lifecycle`` are wrapped in a list when set (OpsLevel
    accepts a list of aliases for OR-style filtering); blank means
    `null` so the field isn't filtered.
    """
    variables = {"first": int(page_size)}
    variables["after"] = after_cursor if after_cursor else None
    variables["tier"] = [tier] if tier else None
    variables["lifecycle"] = [lifecycle] if lifecycle else None
    return variables


def graphql_headers(token):
    """Headers for the OpsLevel /graphql call (Bearer)."""
    return {
        "Authorization": f"Bearer {token or ''}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_services_envelope(body):
    """Pull the services connection from a GraphQL response.

    Returns the inner `account.services` dict or ``{}`` if the shape
    doesn't match (e.g. an `errors` envelope with no `data`).
    """
    if not isinstance(body, dict):
        return {}
    data = body.get("data")
    if not isinstance(data, dict):
        return {}
    account = data.get("account")
    if not isinstance(account, dict):
        return {}
    services = account.get("services")
    if not isinstance(services, dict):
        return {}
    return services


def extract_results(envelope):
    """Pull the service nodes list from a services connection envelope."""
    if not isinstance(envelope, dict):
        return []
    nodes = envelope.get("nodes")
    if isinstance(nodes, list):
        return [entry for entry in nodes if isinstance(entry, dict)]
    # GraphQL also supports edges -> [{node: {...}}] shape; fall back
    # for federated / proxied stacks that prefer it.
    edges = envelope.get("edges")
    if isinstance(edges, list):
        out = []
        for edge in edges:
            if isinstance(edge, dict) and isinstance(edge.get("node"), dict):
                out.append(edge["node"])
        return out
    return []


def extract_total(envelope):
    """Pull totalCount from a services connection envelope."""
    if not isinstance(envelope, dict):
        return None
    v = envelope.get("totalCount")
    if isinstance(v, int):
        return v
    return None


def extract_next_cursor(envelope):
    """Pull (hasNextPage, endCursor) from a services connection envelope.

    Returns ``""`` when pagination is exhausted (hasNextPage is False
    or endCursor is missing / blank).
    """
    if not isinstance(envelope, dict):
        return ""
    page_info = envelope.get("pageInfo")
    if not isinstance(page_info, dict):
        return ""
    has_next = page_info.get("hasNextPage")
    if has_next is False:
        return ""
    cursor = page_info.get("endCursor")
    if isinstance(cursor, str) and cursor.strip():
        return cursor.strip()
    return ""


def extract_graphql_errors(body):
    """Pull a (deduped) list of error messages from a GraphQL response."""
    if not isinstance(body, dict):
        return []
    errors = body.get("errors")
    if not isinstance(errors, list):
        return []
    out = []
    seen = set()
    for err in errors:
        if isinstance(err, dict):
            msg = err.get("message")
        else:
            msg = err
        if isinstance(msg, str) and msg.strip() and msg not in seen:
            seen.add(msg)
            out.append(msg.strip())
    return out


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


def collect_cves(item):
    """Walk an OpsLevel service payload for CVE-* ids.

    OpsLevel services don't carry CVEs natively (they're catalog
    entries, not vulnerability records) but service ``description``
    / ``product`` / ``framework`` text sometimes mention CVE refs
    in deprecation notes — defensive scan.
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

    for key in ("cve", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "cve_ids"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    for key in (
        "name",
        "description",
        "product",
        "framework",
        "language",
        "summary",
        "title",
    ):
        scan(item.get(key))

    return found


def _flatten_named(value):
    """Pull a display string from an OpsLevel nested {alias, name} dict."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("alias", "name", "key"):
            v = value.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def collect_refs(item, opslevel_host):
    """Walk an OpsLevel service payload for refs / pivots."""
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

    service_id = item.get("id") or item.get("serviceId") or item.get("service_id")
    if isinstance(service_id, str) and service_id.strip():
        sid = service_id.strip()
        add(f"OpsLevel-Id: {sid}")

    aliases = item.get("aliases") or item.get("managedAliases")
    if isinstance(aliases, list):
        joined = ",".join(str(a).strip() for a in aliases if isinstance(a, (str, int, float)) and str(a).strip())
        if joined:
            add(f"OpsLevel-Alias: {joined}")

    tier = _flatten_named(item.get("tier"))
    if tier:
        add(f"OpsLevel-Tier: {tier}")

    lifecycle = _flatten_named(item.get("lifecycle"))
    if lifecycle:
        add(f"OpsLevel-Lifecycle: {lifecycle}")

    type_label = _flatten_named(item.get("type"))
    if type_label:
        add(f"OpsLevel-Type: {type_label}")

    owner = _flatten_named(item.get("owner"))
    if owner:
        add(f"OpsLevel-Owner: {owner}")

    for key in ("product", "language", "framework"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            add(f"OpsLevel-{key[:1].upper()}{key[1:]}: {v.strip()}")

    # Tags can arrive as either {nodes: [{key, value}]} (the GraphQL
    # shape this executor requests) or a flat list of strings / dicts
    # for federated stacks.
    tags = item.get("tags")
    tag_strings = []
    if isinstance(tags, dict):
        nodes = tags.get("nodes")
        if isinstance(nodes, list):
            for n in nodes:
                if isinstance(n, dict):
                    k = n.get("key")
                    val = n.get("value")
                    if isinstance(k, str) and isinstance(val, str):
                        tag_strings.append(f"{k.strip()}:{val.strip()}")
                    elif isinstance(k, str) and k.strip():
                        tag_strings.append(k.strip())
    elif isinstance(tags, list):
        for t in tags:
            if isinstance(t, str) and t.strip():
                tag_strings.append(t.strip())
            elif isinstance(t, dict):
                k = t.get("key")
                val = t.get("value")
                if isinstance(k, str) and isinstance(val, str):
                    tag_strings.append(f"{k.strip()}:{val.strip()}")
    if tag_strings:
        add(f"OpsLevel-Tags: {','.join(tag_strings)}")

    # OpsLevel htmlUrl is the canonical service permalink — operators
    # can pivot from the Faraday vuln straight into the OpsLevel
    # console.
    html_url = item.get("htmlUrl") or item.get("html_url") or item.get("url")
    if isinstance(html_url, str) and html_url.strip():
        add(html_url.strip())
    elif isinstance(opslevel_host, str) and opslevel_host.strip() and aliases:
        # Build a fallback permalink from the first alias when the
        # tenant didn't vend htmlUrl.
        first_alias = next(
            (str(a).strip() for a in aliases if isinstance(a, (str, int, float)) and str(a).strip()),
            "",
        )
        if first_alias:
            add(f"{opslevel_host.rstrip('/')}/services/{first_alias}")

    return refs


def service_label(item):
    """Build the leading title fragment for an OpsLevel service."""
    if not isinstance(item, dict):
        return ""
    for key in ("name", "displayName", "title"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    aliases = item.get("aliases")
    if isinstance(aliases, list):
        for a in aliases:
            if isinstance(a, str) and a.strip():
                return a.strip()
    for key in ("id", "serviceId"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "OpsLevel service"


def service_hostnames(item):
    """Walk an OpsLevel service for hostname-like identifiers.

    OpsLevel services aren't IP-keyed (they're service-catalog
    entries) but they do carry useful name + alias pivots — name /
    aliases — that we hang on host.hostnames so Faraday's hostname
    index still surfaces the entry.
    """
    out = []
    seen = set()
    if not isinstance(item, dict):
        return out
    for key in ("name", "displayName"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            if s not in seen:
                seen.add(s)
                out.append(s)
    aliases = item.get("aliases") or item.get("managedAliases")
    if isinstance(aliases, list):
        for a in aliases:
            if isinstance(a, (str, int, float)):
                s = str(a).strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
    return out


def service_os(item):
    """Build the host.os string from an OpsLevel service record.

    OpsLevel services aren't OS-keyed (they're catalog entries) so
    host.os carries the OpsLevel type / tier / lifecycle pivot so
    the catalog entry is visible alongside the other CMDB feeds'
    host.os pivots.
    """
    if not isinstance(item, dict):
        return "OpsLevel service"
    type_label = _flatten_named(item.get("type"))
    tier = _flatten_named(item.get("tier"))
    lifecycle = _flatten_named(item.get("lifecycle"))
    bits = []
    bits.append(f"OpsLevel {type_label}" if type_label else "OpsLevel service")
    if tier:
        bits.append(f"tier={tier}")
    if lifecycle:
        bits.append(f"lifecycle={lifecycle}")
    return " ".join(bits)


def build_vulnerability(item, opslevel_host):
    """Build a Faraday vulnerability dict from an OpsLevel service."""
    if not isinstance(item, dict):
        return None

    type_label = _flatten_named(item.get("type")) or "service"
    label = service_label(item)
    name = f"[ASSET-INVENTORY] OpsLevel {type_label}: {label}"

    desc_parts = []
    description = item.get("description") or item.get("Description") or item.get("summary")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    flat_keys = (
        ("id", "id"),
        ("name", "name"),
        ("product", "product"),
        ("language", "language"),
        ("framework", "framework"),
        ("aliases", "aliases"),
        ("managedAliases", "managedAliases"),
        ("htmlUrl", "htmlUrl"),
    )
    for label_key, key in flat_keys:
        v = item.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    # Nested {alias, name} structures get a flattened label.
    for label_key, key in (
        ("type", "type"),
        ("tier", "tier"),
        ("lifecycle", "lifecycle"),
        ("owner", "owner"),
    ):
        flat = _flatten_named(item.get(key))
        if flat:
            desc_parts.append(f"{label_key}: {flat}")

    timestamps = item.get("timestamps")
    if isinstance(timestamps, dict):
        for k in ("createdAt", "updatedAt"):
            v = timestamps.get(k)
            if isinstance(v, str) and v.strip():
                desc_parts.append(f"{k}: {v.strip()}")

    cves = collect_cves(item)
    refs = collect_refs(item, opslevel_host)

    external_id = str(
        item.get("id") or item.get("serviceId") or item.get("service_id") or (cves[0] if cves else "") or label
    )

    tags = ["opslevel", "asset-inventory", "opslevel-service"]
    tier_alias = _flatten_named(item.get("tier"))
    if tier_alias:
        tags.append(str(tier_alias).lower())
    lifecycle_alias = _flatten_named(item.get("lifecycle"))
    if lifecycle_alias:
        tags.append(str(lifecycle_alias).lower())

    return {
        "name": str(name).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": SEVERITY_INFO,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "OpsLevel services are developer-portal catalog entries, "
            "not vulnerabilities. Cross-check the service against "
            "the other agents' findings (EDR / EASM / vuln scanners) "
            "— anything reported against this service id indicates a "
            "real exposure on a known managed service. Archive or "
            "reclassify the service in OpsLevel if it should no "
            "longer appear in the catalog."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": tags,
    }


def build_host_from_service(item, opslevel_host):
    """Build a Faraday host dict from an OpsLevel service record."""
    if not isinstance(item, dict):
        return None
    hostnames = service_hostnames(item)
    os_str = service_os(item)
    vuln = build_vulnerability(item, opslevel_host)

    desc_parts = []
    for label_key, key in (
        ("type", "type"),
        ("tier", "tier"),
        ("lifecycle", "lifecycle"),
        ("owner", "owner"),
    ):
        flat = _flatten_named(item.get(key))
        if flat:
            desc_parts.append(f"{label_key}={flat}")
    timestamps = item.get("timestamps")
    if isinstance(timestamps, dict):
        for k in ("createdAt", "updatedAt"):
            v = timestamps.get(k)
            if isinstance(v, str) and v.strip():
                desc_parts.append(f"{k}={v.strip()}")

    return {
        "ip": "0.0.0.0",
        "os": os_str,
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts) or "OpsLevel service",
        "vulnerabilities": [vuln] if vuln else [],
    }


def fetch_services(
    requests_module,
    host,
    token,
    tier,
    lifecycle,
    max_pages=MAX_PAGES,
    page_size=PAGE_SIZE,
):
    """Walk the OpsLevel /graphql account.services connection.

    Pagination is Relay-style ``first`` + ``after`` cursors with
    ``pageInfo.hasNextPage`` exhaustion detection.  We page until
    ``hasNextPage`` is False / missing or ``max_pages`` is reached.
    401 short-circuits the whole executor (the OpsLevel token is
    wrong).  403 / 429 just stop pagination and return what we have.
    """
    out = []
    url = build_graphql_url(host)
    headers = graphql_headers(token)
    after_cursor = ""
    pages_walked = 0
    while pages_walked < max_pages:
        variables = build_query_variables(tier, lifecycle, page_size, after_cursor)
        body = {"query": SERVICES_QUERY, "variables": variables}
        try:
            resp = requests_module.post(url, headers=headers, json=body, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"POST {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("OpsLevel request rejected (401). Check OPSLEVEL_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("OpsLevel request rejected (403). Check the token's role / scope.")
            return out
        if resp.status_code == 429:
            log("OpsLevel rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"OpsLevel request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"OpsLevel response was not JSON ({url})")
            return out
        errors = extract_graphql_errors(payload)
        if errors:
            log(f"OpsLevel GraphQL errors: {'; '.join(errors)[:500]}")
            # GraphQL can return partial data alongside errors — keep
            # whatever data is present, but stop pagination.
        envelope = extract_services_envelope(payload)
        results = extract_results(envelope)
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        pages_walked += 1
        if errors:
            break
        next_cursor = extract_next_cursor(envelope)
        if not next_cursor:
            break
        after_cursor = next_cursor
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    tier = validate_tier(env("EXECUTOR_CONFIG_OPSLEVEL_TIER"))
    lifecycle = validate_lifecycle(env("EXECUTOR_CONFIG_OPSLEVEL_LIFECYCLE"))
    host = validate_host(env("OPSLEVEL_HOST"))
    token = env("OPSLEVEL_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    services = fetch_services(requests, host, token, tier, lifecycle)

    log(f"Processing {len(services)} OpsLevel services " f"(tier={tier!r}, lifecycle={lifecycle!r})")

    hosts_out = []
    for entry in services:
        built = build_host_from_service(entry, host)
        if built is not None:
            hosts_out.append(built)

    if not hosts_out:
        # Synthetic placeholder host so the Faraday workspace still
        # records the OpsLevel query was processed, mirroring the
        # convention used by leanix_eam / securitybridge_sap /
        # redhat_satellite / ivanti_security_controls / wsus / sccm /
        # tripwire_enterprise.
        hosts_out.append(
            {
                "ip": "0.0.0.0",
                "os": "OpsLevel service",
                "hostnames": [],
                "mac": "",
                "description": (f"OpsLevel scan returned 0 services " f"(tier={tier!r}, lifecycle={lifecycle!r})"),
                "vulnerabilities": [],
            }
        )

    params_bits = [
        f"tier={tier}",
        f"lifecycle={lifecycle}",
    ]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "opslevel",
            "command": "opslevel",
            "params": ",".join(params_bits),
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
