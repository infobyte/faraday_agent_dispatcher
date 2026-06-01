#!/usr/bin/env python
"""Fleet (osquery) asset-inventory importer.

Pulls managed hosts and saved osquery queries from a Fleet
(fleetdm.com) appliance via the Fleet v1 REST API and emits Faraday
bulk-create JSON to stdout.  Each Fleet host becomes one Faraday host
— the host's ``primary_ip`` maps onto ``host.ip`` (loopback /
``0.0.0.0`` / ``::1`` are explicitly skipped; we fall back to a
walk of ``nics`` / ``network_interfaces`` then a ``0.0.0.0``
sentinel when nothing usable is found), the ``hostname`` /
``computer_name`` / ``display_name`` projection lands on
``host.hostnames``, ``primary_mac`` (with a fallback to ``nics``)
lands on ``host.mac``, the ``platform`` / ``os_version`` /
``hardware_model`` / ``hardware_vendor`` chain joins onto
``host.os``, and the asset itself becomes one Faraday vulnerability
with the ``[ASSET-INVENTORY]`` engine prefix.  Each saved query from
``/api/v1/fleet/queries`` becomes one synthetic Faraday host with
the ``0.0.0.0`` sentinel (queries aren't IP-keyed — they're
operator-defined osquery SQL packs) so the workspace still surfaces
the Fleet query inventory alongside the host inventory; the query
name lands on ``host.hostnames`` and the query SQL is embedded in
the description.

Endpoints used:
  GET {FLEET_HOST}/api/v1/fleet/hosts?per_page=100&page=N
      (&team_id=...)(&label_id=...)
      -> the canonical Fleet host inventory.  Returns
      ``{"hosts": [...]}`` with each host record carrying ``id``,
      ``hostname``, ``computer_name``, ``display_name``,
      ``primary_ip``, ``primary_mac``, ``platform``, ``os_version``,
      ``osquery_version``, ``hardware_vendor``, ``hardware_model``,
      ``hardware_serial``, ``team_id``, ``team_name``, ``last_seen``,
      ``seen_time``, ``status``, ``labels`` (list of
      ``{id, name, label_type}``), ``nics`` (list of
      ``{ip, mac, interface}`` per network interface), and
      ``software`` (when the operator opted into software inventory).
      ``FLEET_TEAM_ID`` and ``FLEET_LABEL_ID`` are forwarded as
      server-side ``team_id`` / ``label_id`` query-string filters so
      the dispatcher only walks one team / label's worth of inventory
      per agent run.  ``per_page`` defaults to 100; pagination is
      page-number based starting from 0.
  GET {FLEET_HOST}/api/v1/fleet/queries?per_page=100&page=N
      (&team_id=...)
      -> the saved osquery query inventory.  Returns
      ``{"queries": [...]}`` with each record carrying ``id``,
      ``name``, ``description``, ``query`` (the osquery SQL),
      ``platform``, ``interval``, ``team_id``, ``last_executed``,
      ``created_at``, ``updated_at``, ``observer_can_run``.  Walked
      with the same paging shape (page + per_page).  Fleet returns
      every saved query the API key can see; ``FLEET_TEAM_ID`` is
      forwarded as a filter so the operator can scope to a single
      team.  ``FLEET_LABEL_ID`` does NOT apply on the queries surface
      (Fleet doesn't label-key queries) so it is silently dropped
      there.

Pagination is page-number based on both surfaces (``page`` +
``per_page`` in the query string).  We walk page-by-page until
``len(records) < per_page`` or the env-only ``FLEET_PAGES`` cap is
reached (default 5, clamped to [1, 50]).  ``per_page`` is fixed at
100 (Fleet's documented default; the executor doesn't expose it as a
manifest argument since the playbook only lists
FLEET_TEAM_ID + FLEET_LABEL_ID).

Auth: Fleet uses long-lived bearer tokens generated either via the
Fleet UI (``Settings -> My Account -> Get API token``) or via
``fleetctl login --json`` for service accounts.  The dispatcher
carries the token on every request as the standard
``Authorization: Bearer <FLEET_TOKEN>`` header.  ``FLEET_HOST`` is
the Fleet appliance host (e.g. ``fleet.mycorp.com`` or
``https://fleet.mycorp.local:8080``); on-prem deployments are common
so we tolerate operator typos and add ``https://`` automatically
when the operator pasted in a bare FQDN.

Severity is always ``info`` because Fleet hits are inventory
entries, not vulnerability findings — operators correlate against
the EDR / EASM / vuln-scanner agents' findings via the
``Fleet-Id`` / ``Fleet-Team`` / ``Fleet-Platform`` /
``Fleet-Status`` / ``Fleet-LastSeen`` / ``Fleet-Labels`` /
``Fleet-OsqueryVersion`` / ``Fleet-Serial`` refs on host hits, and
the ``Fleet-QueryId`` / ``Fleet-QueryPlatform`` /
``Fleet-QueryInterval`` / ``Fleet-QueryTeam`` /
``Fleet-QueryLastExecuted`` refs on query hits.  Tags: [fleet,
asset-inventory, host|query].
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
PER_PAGE = 100  # Fleet's documented default page size.
DEFAULT_PAGES = 5
MAX_PAGES = 50


def log(msg):
    print(f"{datetime.utcnow()} - Fleet: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on FLEET_HOST.

    No default — the Fleet appliance host is operator-specific so we
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


def validate_team_id(value):
    """Validate FLEET_TEAM_ID (the operator-supplied team filter).

    None / blank -> ``""`` (no narrowing; every team in the appliance
    is walked).  Accepts int / numeric-string; non-numeric values are
    forwarded verbatim (Fleet 4.x accepts both ``team_id=0`` for
    "global" and the textual ``no-team`` slug on some surfaces).
    Whitespace is trimmed.
    """
    if value is None:
        return ""
    text = str(value).strip()
    return text


def validate_label_id(value):
    """Validate FLEET_LABEL_ID (the operator-supplied label filter).

    None / blank -> ``""``.  Forwarded as a server-side
    ``?label_id=<value>`` query-string filter on
    ``/api/v1/fleet/hosts`` only — Fleet doesn't label-key the
    ``/queries`` surface, so the executor silently drops this filter
    on the query walk.  Whitespace is trimmed.
    """
    if value is None:
        return ""
    text = str(value).strip()
    return text


def validate_pages(value):
    """Validate FLEET_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Fleet appliance.  Not exposed as a manifest argument (the
    playbook only lists FLEET_TEAM_ID + FLEET_LABEL_ID) but read from
    the env so a tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"FLEET_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"FLEET_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_hosts_url(host):
    return f"{normalize_base_url(host)}/api/v1/fleet/hosts"


def build_queries_url(host):
    return f"{normalize_base_url(host)}/api/v1/fleet/queries"


def build_query(page, per_page=PER_PAGE, extra=None):
    """Build the canonical Fleet paging query string.

    Fleet uses page-number paging (0-indexed) with ``per_page``,
    unlike Device42's offset-based paging.  ``extra`` is an optional
    dict of additional filter params (e.g.
    ``{"team_id": "3", "label_id": "7"}``).  Values are URL-encoded
    and blanks are dropped so the resulting query string never
    carries ``team_id=`` with an empty value (Fleet rejects that as
    a 400).
    """
    params = [("page", str(int(page))), ("per_page", str(int(per_page)))]
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

    Fleet's REST API uses bearer tokens generated either via the
    Fleet UI (``Settings -> My Account -> Get API token``) or via
    ``fleetctl login --json``.  We build the header inline (rather
    than relying on a third-party library) so test fixtures + unit
    checks can assert on the exact wire format and requests won't
    strip a manually-built Authorization header on cross-host
    redirects.
    """
    return f"Bearer {token or ''}"


def auth_headers(token):
    return {
        "Authorization": bearer_auth_header(token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_hosts(body):
    """Pull the host list from a Fleet v1 envelope.

    Fleet's ``/hosts`` returns ``{"hosts": [...]}`` with the canonical
    lowercased key.  Federated / future stacks may use
    ``data`` / ``results`` / ``items`` — accept all of them for
    resilience plus root-list passthrough.
    """
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("hosts", "Hosts", "data", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_queries(body):
    """Pull the saved-query list from a Fleet v1 envelope."""
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("queries", "Queries", "data", "results", "items"):
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
    """Coerce a single Fleet attribute value into a printable string."""
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
    """Coerce a Fleet attribute value into a deduped string list."""
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


def host_ips(host):
    """Walk a Fleet host record for IP candidates.

    Fleet projects IPs through ``primary_ip`` (string) on the
    canonical ``/hosts`` surface; some hosts surface only a flat
    list under ``nics`` (each ``{ip, mac, interface}``) or
    ``network_interfaces``.  Loopback / zero are skipped.
    """
    if not isinstance(host, dict):
        return []
    candidates = []
    for key in ("primary_ip", "public_ip"):
        v = host.get(key)
        if v:
            candidates.extend(_flatten_strings(v))
    for key in ("nics", "network_interfaces"):
        raw = host.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    ip = entry.get("ip") or entry.get("address") or entry.get("ip_address")
                    if ip:
                        candidates.extend(_flatten_strings(ip))
                elif isinstance(entry, str):
                    candidates.extend(_flatten_strings(entry))
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


def host_ip(host):
    """Pick the first non-loopback IP for a Fleet host."""
    ips = host_ips(host)
    return ips[0] if ips else "0.0.0.0"


def host_hostnames(host):
    """Walk a Fleet host record for hostname candidates."""
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

    if not isinstance(host, dict):
        return out

    for key in ("hostname", "computer_name", "display_name", "fqdn"):
        for n in _flatten_strings(host.get(key)):
            add(n)
    serial = _flatten_string(host.get("hardware_serial") or host.get("serial"))
    if serial:
        add(serial)
    return out


def host_mac(host):
    if not isinstance(host, dict):
        return ""
    v = host.get("primary_mac")
    if v:
        s = _flatten_string(v)
        if s:
            return s
    for key in ("nics", "network_interfaces"):
        raw = host.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    mac = entry.get("mac") or entry.get("mac_address") or entry.get("address")
                    if mac:
                        s = _flatten_string(mac)
                        if s:
                            return s
                elif isinstance(entry, str):
                    s = entry.strip()
                    if s:
                        return s
    for key in ("mac", "mac_address"):
        v = host.get(key)
        if v:
            s = _flatten_string(v)
            if s:
                return s
    return ""


def host_os(host):
    """Build the ``host.os`` string from Fleet's OS projection."""
    if not isinstance(host, dict):
        return ""
    bits = []
    for key in ("platform", "os_name", "operating_system"):
        v = _flatten_string(host.get(key))
        if v:
            bits.append(v)
            break
    for key in ("os_version", "os_release"):
        v = _flatten_string(host.get(key))
        if v:
            bits.append(v)
            break
    for key in ("hardware_model", "model"):
        v = _flatten_string(host.get(key))
        if v:
            bits.append(v)
            break
    for key in ("hardware_vendor", "vendor", "manufacturer"):
        v = _flatten_string(host.get(key))
        if v:
            bits.append(v)
            break
    return " ".join(bits)


def host_labels(host):
    """Return a deduped list of Fleet label names for a host."""
    out = []
    seen = set()
    if not isinstance(host, dict):
        return out
    raw = host.get("labels")
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("label_name")
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
    return out


def collect_cves(item):
    """Walk a Fleet item for CVE-* ids.

    Fleet doesn't surface CVE-keyed findings on the canonical
    ``/hosts`` or ``/queries`` endpoints, but operators sometimes
    paste CVEs into ``software`` advisory fields and saved-query
    descriptions so we still scan those for completeness.  Software
    inventory (when enabled) carries a ``vulnerabilities`` list per
    package with each entry holding a ``cve`` field — pull those
    too.
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

    for key in ("description", "name", "notes", "query"):
        scan(item.get(key))

    software = item.get("software")
    if isinstance(software, list):
        for pkg in software:
            if not isinstance(pkg, dict):
                continue
            vulns = pkg.get("vulnerabilities")
            if isinstance(vulns, list):
                for entry in vulns:
                    if isinstance(entry, dict):
                        add(entry.get("cve") or entry.get("cve_id") or entry.get("id"))
                    elif isinstance(entry, str):
                        add(entry)

    return found


def collect_refs(item, entity_type):
    """Walk a Fleet record for advisory URLs / pivots."""
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

    if entity_type == "host":
        hid = item.get("id") or item.get("host_id")
        if hid is not None and str(hid).strip():
            add(f"Fleet-Id: {str(hid).strip()}")
        team_name = _flatten_string(item.get("team_name"))
        team_id = _flatten_string(item.get("team_id"))
        if team_name:
            add(f"Fleet-Team: {team_name}")
        elif team_id:
            add(f"Fleet-Team: {team_id}")
        platform = _flatten_string(item.get("platform"))
        if platform:
            add(f"Fleet-Platform: {platform}")
        status = _flatten_string(item.get("status"))
        if status:
            add(f"Fleet-Status: {status}")
        for key in ("seen_time", "last_seen", "last_enrolled_at"):
            v = _flatten_string(item.get(key))
            if v:
                add(f"Fleet-LastSeen: {v}")
                break
        osq = _flatten_string(item.get("osquery_version"))
        if osq:
            add(f"Fleet-OsqueryVersion: {osq}")
        serial = _flatten_string(item.get("hardware_serial") or item.get("serial"))
        if serial:
            add(f"Fleet-Serial: {serial}")
        labels = host_labels(item)
        if labels:
            add(f"Fleet-Labels: {','.join(labels)}")
    else:
        qid = item.get("id") or item.get("query_id")
        if qid is not None and str(qid).strip():
            add(f"Fleet-QueryId: {str(qid).strip()}")
        platform = _flatten_string(item.get("platform"))
        if platform:
            add(f"Fleet-QueryPlatform: {platform}")
        interval = item.get("interval")
        if isinstance(interval, (int, float)) and interval:
            add(f"Fleet-QueryInterval: {int(interval)}")
        team_id = _flatten_string(item.get("team_id"))
        if team_id:
            add(f"Fleet-QueryTeam: {team_id}")
        for key in ("last_executed", "updated_at"):
            v = _flatten_string(item.get(key))
            if v:
                add(f"Fleet-QueryLastExecuted: {v}")
                break

    return refs


def build_asset_vulnerability(item, entity_type, team_id, label_id):
    """Build a Faraday vulnerability dict for one Fleet record."""
    if entity_type == "host":
        hostnames = host_hostnames(item)
        primary = hostnames[0] if hostnames else (host_ip(item) if host_ip(item) != "0.0.0.0" else "unknown host")
        label = f"[ASSET-INVENTORY] Fleet host: {primary}"
    else:
        name = _flatten_string(item.get("name")) if isinstance(item, dict) else ""
        label = f"[ASSET-INVENTORY] Fleet query: {name or 'unknown query'}"

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
    if team_id:
        desc_parts.append(f"fleet_team_id: {team_id}")
    if label_id and entity_type == "host":
        desc_parts.append(f"fleet_label_id: {label_id}")

    cves = collect_cves(item) if isinstance(item, dict) else []
    refs = collect_refs(item, entity_type)

    external_id = ""
    if isinstance(item, dict):
        external_id = str(item.get("id") or item.get("host_id") or item.get("query_id") or "")
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
            "Fleet records are inventory entries, not vulnerabilities. "
            "Cross-check the asset against the other agents' findings "
            "(EDR / EASM / vuln scanners) — anything reported against "
            "this Fleet host id indicates a real exposure on a known "
            "managed endpoint.  Decommission or reclassify the host "
            "in Fleet if it should no longer appear in the inventory. "
            "For saved-query hits, the surfaced record documents an "
            "operator-defined osquery SQL pack — review the query SQL "
            "to confirm it still matches the operator's compliance / "
            "investigation intent."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["fleet", "asset-inventory", entity_type],
    }


def build_host_from_host(host_record, team_id, label_id):
    """Build a Faraday host dict from a Fleet host record."""
    if host_record is None or not isinstance(host_record, dict):
        return None

    ip = host_ip(host_record)
    hostnames = host_hostnames(host_record)
    mac = host_mac(host_record)
    os_str = host_os(host_record)

    desc_parts = []
    for key in (
        "platform",
        "status",
        "team_name",
        "team_id",
        "osquery_version",
        "hardware_serial",
        "seen_time",
        "last_seen",
    ):
        v = host_record.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    vuln = build_asset_vulnerability(host_record, "host", team_id, label_id)
    return {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln] if vuln else [],
    }


def build_host_from_query(query_record, team_id):
    """Build a Faraday host dict for a Fleet saved-query record.

    Saved osquery queries aren't IP-keyed — they're operator-defined
    SQL packs that Fleet runs across the host fleet.  Synthesise a
    ``0.0.0.0`` host so the workspace still surfaces the finding,
    and hang the query name on ``host.hostnames`` so Faraday's
    hostname index still pivots on it.
    """
    if query_record is None or not isinstance(query_record, dict):
        return None
    name = _flatten_string(query_record.get("name"))
    hostnames = [name] if name else []
    vuln = build_asset_vulnerability(query_record, "query", team_id, "")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Fleet saved osquery query",
        "vulnerabilities": [vuln] if vuln else [],
    }


def fetch_pages(requests_module, url, headers, extractor, per_page, max_pages, extra_params=None):
    """Walk a Fleet v1 ``/hosts`` or ``/queries`` envelope.

    Pagination is page-number based via ``page`` + ``per_page`` query
    parameters (0-indexed).  We page until either
    ``len(records) < per_page`` or ``max_pages`` is reached.  401
    short-circuits the whole executor (token is wrong);
    403 / 429 / 5xx stop pagination on the surface and return what
    we have.
    """
    out = []
    page = 0
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(page, per_page=per_page, extra=extra_params)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Fleet request rejected (401). Check FLEET_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Fleet request rejected (403). Check the token's team/role scope.")
            return out
        if resp.status_code == 429:
            log("Fleet rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Fleet request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Fleet response was not JSON ({full_url})")
            return out
        records = extractor(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < per_page:
            break
        page += 1
    if walked >= max_pages and len(records) >= per_page:
        log(f"hit FLEET_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    team_id = validate_team_id(env("EXECUTOR_CONFIG_FLEET_TEAM_ID"))
    label_id = validate_label_id(env("EXECUTOR_CONFIG_FLEET_LABEL_ID"))
    pages = validate_pages(env("FLEET_PAGES"))

    host = env("FLEET_HOST", required=True)
    token = env("FLEET_TOKEN", required=True)

    if not normalize_base_url(host):
        log("FLEET_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    hosts_url = build_hosts_url(host)
    queries_url = build_queries_url(host)

    host_extra = {}
    if team_id:
        host_extra["team_id"] = team_id
    if label_id:
        host_extra["label_id"] = label_id
    host_extra = host_extra or None

    query_extra = {"team_id": team_id} if team_id else None

    host_records = fetch_pages(
        requests,
        hosts_url,
        headers,
        extract_hosts,
        PER_PAGE,
        max_pages=pages,
        extra_params=host_extra,
    )
    query_records = fetch_pages(
        requests,
        queries_url,
        headers,
        extract_queries,
        PER_PAGE,
        max_pages=pages,
        extra_params=query_extra,
    )

    log(
        f"Processing {len(host_records)} Fleet hosts + {len(query_records)} saved queries "
        f"(team_id={team_id!r}, label_id={label_id!r}, pages={pages})"
    )

    hosts_out = []
    for record in host_records:
        built = build_host_from_host(record, team_id, label_id)
        if built is not None:
            hosts_out.append(built)
    for record in query_records:
        built = build_host_from_query(record, team_id)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "fleet_osquery",
            "command": "fleet_osquery",
            "params": (f"team_id={team_id}," f"label_id={label_id}," f"pages={pages}"),
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
