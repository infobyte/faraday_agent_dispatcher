#!/usr/bin/env python
"""Armis asset-inventory importer.

Pulls discovered devices and security alerts from an Armis CPS
(Cyber-Physical Systems) console via the Armis v1 REST API and
emits Faraday bulk-create JSON to stdout.  Each Armis device
becomes one Faraday host — the device's ``ipAddress`` projects
onto ``host.ip`` (loopback / ``0.0.0.0`` / ``::1`` are explicitly
skipped; we fall back to the first usable entry in ``ipv6`` and
then to the ``0.0.0.0`` sentinel when nothing usable is found),
the ``name`` / ``hostName`` / ``fqdn`` projection lands on
``host.hostnames``, ``macAddress`` lands on ``host.mac``, the
``operatingSystem`` / ``operatingSystemVersion`` / ``manufacturer``
/ ``model`` chain joins onto ``host.os``, and the asset itself
becomes one Faraday vulnerability with the ``[ASSET-INVENTORY]``
engine prefix.  Each Armis alert becomes one Faraday host keyed on
the alert's ``ip`` field when device-keyed (alerts can travel with
the affected device's primary IP) or the ``0.0.0.0`` sentinel
otherwise; the alert ``title`` / ``policyTitle`` projection lands
on ``host.hostnames`` and the alert ``description`` / ``severity``
/ ``mitreAttackTechniques`` enrichment is embedded in the
vulnerability description.

Endpoints used:
  GET {ARMIS_HOST}/api/v1/devices/?aql=<asq>&from=N&length=M
      -> the canonical Armis device inventory.  Returns a JSON
      envelope ``{"data": {"results": [...], "count": N, "total":
      N, "next": K|null}, "success": true}``; each record carries
      ``id``, ``category``, ``type``, ``firstSeen``, ``lastSeen``,
      ``ipAddress``, ``ipv6`` (list), ``macAddress``, ``name``,
      ``hostName``, ``manufacturer``, ``model``,
      ``operatingSystem``, ``operatingSystemVersion``,
      ``riskLevel``, ``siteId``, ``siteName``, ``boundary``,
      ``purdueLevel``, ``tags`` (list), ``userIds`` (list of
      associated user identifiers).
  GET {ARMIS_HOST}/api/v1/alerts/?aql=<asq>&from=N&length=M
      -> the Armis security alert feed.  Returns the same envelope
      shape; each record carries ``alertId``, ``title``,
      ``description``, ``severity`` (Low / Medium / High),
      ``time``, ``status`` (Active / Closed), ``type``, ``ip``,
      ``policyId``, ``policyTitle``, ``siteId``, ``siteName``,
      ``mitreAttackTechniques`` (list), ``cveList`` (list, when
      Armis has CVE attribution), ``deviceIds`` (list of affected
      device ids), ``affectedDevicesCount``.

``ARMIS_SITE_ID`` and ``ARMIS_BOUNDARY`` are forwarded as ASQ
(Armis Search Query) predicates appended to the ``aql`` query
parameter on both surfaces.  When supplied together they compose
into ``aql=in:devices,siteId:<id>,boundary:"<value>"`` so the
dispatcher only walks one site / boundary's worth of inventory
per agent run; blank-strings are explicitly dropped so we never
emit a stray ``,siteId:`` predicate (Armis rejects that with a
400).  The ASQ ``in:`` prefix is set per-surface (``in:devices``
for the devices walk, ``in:alerts`` for the alerts walk).

Pagination is offset-based via ``from`` + ``length`` query
parameters on both surfaces.  We walk page-by-page (from += length
per request) until ``len(results) < length`` or the env-only
``ARMIS_PAGES`` cap is reached (default 5, clamped to [1, 50]).
``length`` is fixed at 100 (Armis' documented default page size;
the hard cap is 1000 but smaller pages keep response sizes
manageable for the dispatcher event loop).

Auth: Armis v1 uses a two-step auth flow.  The dispatcher carries
a long-lived ``ARMIS_SECRET_KEY`` (generated in the Armis console
under ``Settings -> Users & Roles -> Access Tokens``), and on
every executor run we exchange it for a short-lived access token
via POST ``{ARMIS_HOST}/api/v1/access_token/`` with
``secret_key=<key>`` form data.  The access token is returned in
the response envelope under ``data.access_token`` and travels on
every subsequent ``/api/v1/`` request as the ``Authorization:
<token>`` header — Armis does NOT use the ``Bearer`` prefix on
this header, the raw token IS the header value.  We build the
header inline (rather than relying on a third-party library) so
test fixtures + unit checks can assert on the exact wire format
and ``requests`` won't strip a manually-built Authorization header
on cross-host redirects.  ``ARMIS_HOST`` is the operator's
tenant host (e.g. ``mycorp.armis.com``); on-prem appliances are
tolerated and ``https://`` is added automatically when the
operator pasted in a bare FQDN.

Severity is always ``info`` because Armis device hits are
inventory entries and Armis alerts surface as inventory-side
observations that operators correlate against the EDR / EASM /
vuln-scanner agents' findings via the ``Armis-Id`` /
``Armis-Site`` / ``Armis-Boundary`` / ``Armis-Type`` /
``Armis-RiskLevel`` / ``Armis-LastSeen`` / ``Armis-Tags`` /
``Armis-PurdueLevel`` refs on device hits, and the
``Armis-AlertId`` / ``Armis-Policy`` / ``Armis-Status`` /
``Armis-Severity`` / ``Armis-Time`` / ``Armis-Type`` /
``Armis-MITRE`` / ``Armis-DeviceCount`` refs on alert hits.
Tags: [armis, asset-inventory, device|alert].
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
PER_PAGE = 100  # Armis' documented default page size.
DEFAULT_PAGES = 5
MAX_PAGES = 50


def log(msg):
    print(f"{datetime.utcnow()} - Armis: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on ARMIS_HOST.

    No default — the Armis tenant host is operator-specific so we
    ``sys.exit(1)`` upstream in ``main`` when the env var is
    missing.  Here we just whitespace-trim, strip trailing slashes
    and add ``https://`` when the operator pasted in a bare FQDN
    (on-prem appliances commonly use raw hostnames).
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_site_id(value):
    """Validate ARMIS_SITE_ID (the operator-supplied site predicate).

    None / blank -> ``""`` (no site narrowing; the whole tenant is
    walked).  Whitespace is trimmed.  Forwarded verbatim into the
    ASQ ``siteId:<value>`` predicate — the executor doesn't
    second-guess operator-supplied site ids (Armis accepts both
    numeric site ids and the literal site name in the ``siteId``
    slot depending on tenant configuration).
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_boundary(value):
    """Validate ARMIS_BOUNDARY (the operator-supplied boundary predicate).

    None / blank -> ``""`` (no boundary narrowing; the whole site
    is walked).  Whitespace is trimmed.  Forwarded verbatim into
    the ASQ ``boundary:"<value>"`` predicate — boundaries are
    free-form Armis network-segment names so we quote the value
    to allow spaces (e.g. ``boundary:"Corporate Network"``).
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_pages(value):
    """Validate ARMIS_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Armis console.  Not exposed as a manifest argument (the
    playbook only lists ARMIS_SITE_ID + ARMIS_BOUNDARY) but read
    from the env so a tenant-side override can still tune the
    walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"ARMIS_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"ARMIS_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_asq(entity, site_id, boundary):
    """Compose the ``aql`` query string for an Armis ``/api/v1/<entity>/``.

    The ASQ ``in:`` prefix scopes the predicate to one entity type
    (``in:devices`` for the devices walk, ``in:alerts`` for the
    alerts walk).  ``siteId`` and ``boundary`` are joined with
    commas (Armis treats comma-separated predicates as logical AND).
    Boundary values are double-quoted to tolerate spaces / special
    characters in the operator-supplied boundary name.  Blank
    inputs are silently dropped so the resulting predicate never
    contains an empty value (Armis rejects ``,siteId:`` as a 400).
    """
    parts = [f"in:{entity}"]
    if site_id:
        parts.append(f"siteId:{site_id}")
    if boundary:
        parts.append(f'boundary:"{boundary}"')
    return ",".join(parts)


def build_devices_url(host):
    return f"{normalize_base_url(host)}/api/v1/devices/"


def build_alerts_url(host):
    return f"{normalize_base_url(host)}/api/v1/alerts/"


def build_access_token_url(host):
    return f"{normalize_base_url(host)}/api/v1/access_token/"


def build_query(offset, length=PER_PAGE, extra=None):
    """Build the canonical Armis paging query string.

    Armis uses offset-based paging via ``from`` (the record offset)
    and ``length`` (the per-page record cap).  ``extra`` is an
    optional dict of additional filter params (e.g. ``{"aql":
    "in:devices,siteId:7"}``).  Values are URL-encoded and blanks
    are dropped so the resulting query string never carries
    ``aql=`` with an empty value (Armis would treat that as a 400
    anyway, but the explicit drop keeps the wire format
    predictable).
    """
    params = [("from", str(int(offset))), ("length", str(int(length)))]
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            s = str(v).strip()
            if not s:
                continue
            params.append((str(k), s))
    return urllib.parse.urlencode(params)


def armis_auth_header(token):
    """Build the canonical Armis ``Authorization`` header value.

    Armis v1 does NOT use the ``Bearer`` prefix on the
    Authorization header — the raw access token IS the header
    value.  We build the header inline (rather than relying on a
    third-party library) so test fixtures + unit checks can assert
    on the exact wire format and ``requests`` won't strip a
    manually-built Authorization header on cross-host redirects.
    """
    return str(token or "")


def auth_headers(token):
    return {
        "Authorization": armis_auth_header(token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_records(body):
    """Pull the record list from an Armis v1 response envelope.

    Armis wraps the record list under ``data.results`` (the
    documented v1 shape).  We also accept legacy / federated
    envelope shapes (bare list, top-level ``results`` / ``data`` /
    ``items`` / ``devices`` / ``alerts``) so future shapes round-
    trip through the same extractor.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    data = body.get("data")
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            return [entry for entry in results if isinstance(entry, dict)]
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]
    for key in ("results", "items", "devices", "alerts"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_total(body):
    if not isinstance(body, dict):
        return None
    data = body.get("data")
    if isinstance(data, dict):
        for key in ("total", "count", "totalCount"):
            v = data.get(key)
            if isinstance(v, int):
                return v
    for key in ("total", "count", "totalCount"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def extract_access_token(body):
    """Pull the short-lived access token from a v1 access_token reply.

    Armis returns ``{"data": {"access_token": "...",
    "expiration_utc": "..."}, "success": true}``.  Legacy /
    federated stacks may expose the token at the envelope root
    (``access_token``) — accept both for resilience.
    """
    if not isinstance(body, dict):
        return ""
    data = body.get("data")
    if isinstance(data, dict):
        for key in ("access_token", "token"):
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    for key in ("access_token", "token"):
        v = body.get(key)
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
    """Coerce a single Armis attribute value into a printable string."""
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
    """Coerce an Armis attribute value into a deduped string list."""
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


def device_ips(device):
    """Walk an Armis device record for IP candidates.

    Armis projects IPs through ``ipAddress`` (a scalar primary IP)
    and ``ipv6`` (list of additional addresses).  Loopback / zero
    are explicitly skipped.  Some federated tenants expose
    ``ipAddresses`` as a list rather than a scalar — accept both.
    """
    if not isinstance(device, dict):
        return []
    candidates = []
    for key in ("ipAddress", "ipAddresses", "ipv6", "ipv4"):
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
    """Pick the first non-loopback IP for an Armis device."""
    ips = device_ips(device)
    return ips[0] if ips else "0.0.0.0"


def device_hostnames(device):
    """Walk an Armis device record for hostname candidates."""
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

    for key in ("name", "hostName", "fqdn", "dnsName"):
        for n in _flatten_strings(device.get(key)):
            add(n)
    return out


def device_mac(device):
    if not isinstance(device, dict):
        return ""
    for key in ("macAddress", "mac", "macAddresses"):
        v = device.get(key)
        if v:
            s = _flatten_string(v)
            if s:
                return s
    return ""


def device_os(device):
    """Build the ``host.os`` string from Armis' OS projection."""
    if not isinstance(device, dict):
        return ""
    bits = []
    for key in ("operatingSystem", "os"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    for key in ("operatingSystemVersion", "osVersion"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    for key in ("manufacturer", "vendor"):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    for key in ("model",):
        v = _flatten_string(device.get(key))
        if v:
            bits.append(v)
            break
    return " ".join(bits)


def device_tags(device):
    """Return a deduped list of Armis tag names for a device."""
    out = []
    seen = set()
    if not isinstance(device, dict):
        return out
    raw = device.get("tags")
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
    elif isinstance(raw, str):
        s = raw.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def alert_ip(alert):
    """Pick the alert's IP key when device-keyed.

    Armis alerts carry a scalar ``ip`` field when the underlying
    event is sourced from one specific device's traffic.  We fall
    back to ``sourceIp`` / ``destIp`` / ``deviceIp`` for federated
    shapes and finally to the ``0.0.0.0`` sentinel when nothing
    usable is found (alerts can be policy-shaped and not keyed on
    any single device).
    """
    if not isinstance(alert, dict):
        return "0.0.0.0"
    for key in ("ip", "sourceIp", "destIp", "deviceIp"):
        v = _flatten_string(alert.get(key))
        if v and v not in ("0.0.0.0", "127.0.0.1", "::1"):
            return v
    return "0.0.0.0"


def collect_cves(item):
    """Walk an Armis item for CVE-* ids.

    Armis surfaces CVE attribution on alerts via the ``cveList``
    projection (list of CVE strings or dicts); we also scan
    ``description`` / ``title`` / ``policyTitle`` and the device
    ``operatingSystem`` / ``operatingSystemVersion`` / ``tags`` for
    operator-pasted CVE refs.
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

    raw = item.get("cveList")
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, str):
                add(entry)
            elif isinstance(entry, dict):
                add(entry.get("cve") or entry.get("cve_id") or entry.get("id"))

    for key in (
        "description",
        "title",
        "policyTitle",
        "operatingSystem",
        "operatingSystemVersion",
        "name",
        "summary",
    ):
        scan(item.get(key))

    tags = item.get("tags")
    if isinstance(tags, list):
        for entry in tags:
            if isinstance(entry, str):
                scan(entry)

    return found


def _severity_label(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return _flatten_string(value)


def collect_refs(item, entity_type):
    """Walk an Armis record for advisory URLs / pivots."""
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
        did = item.get("id") or item.get("deviceId")
        if did is not None and str(did).strip():
            add(f"Armis-Id: {str(did).strip()}")
        site_name = _flatten_string(item.get("siteName"))
        site_id = _flatten_string(item.get("siteId"))
        if site_name:
            add(f"Armis-Site: {site_name}")
        elif site_id:
            add(f"Armis-Site: {site_id}")
        boundary = _flatten_string(item.get("boundary"))
        if boundary:
            add(f"Armis-Boundary: {boundary}")
        dev_type = _flatten_string(item.get("type") or item.get("category"))
        if dev_type:
            add(f"Armis-Type: {dev_type}")
        risk = _severity_label(item.get("riskLevel") or item.get("risk"))
        if risk:
            add(f"Armis-RiskLevel: {risk}")
        for key in ("lastSeen", "last_seen", "firstSeen"):
            v = _flatten_string(item.get(key))
            if v:
                add(f"Armis-LastSeen: {v}")
                break
        tags = device_tags(item)
        if tags:
            add(f"Armis-Tags: {','.join(tags)}")
        purdue = _flatten_string(item.get("purdueLevel"))
        if purdue:
            add(f"Armis-PurdueLevel: {purdue}")
    else:
        aid = item.get("alertId") or item.get("id")
        if aid is not None and str(aid).strip():
            add(f"Armis-AlertId: {str(aid).strip()}")
        site_name = _flatten_string(item.get("siteName"))
        site_id = _flatten_string(item.get("siteId"))
        if site_name:
            add(f"Armis-Site: {site_name}")
        elif site_id:
            add(f"Armis-Site: {site_id}")
        policy = _flatten_string(item.get("policyTitle") or item.get("policyId"))
        if policy:
            add(f"Armis-Policy: {policy}")
        status = _flatten_string(item.get("status"))
        if status:
            add(f"Armis-Status: {status}")
        severity = _severity_label(item.get("severity"))
        if severity:
            add(f"Armis-Severity: {severity}")
        for key in ("time", "lastSeen", "firstSeen"):
            v = _flatten_string(item.get(key))
            if v:
                add(f"Armis-Time: {v}")
                break
        alert_type = _flatten_string(item.get("type"))
        if alert_type:
            add(f"Armis-Type: {alert_type}")
        mitre = item.get("mitreAttackTechniques")
        if isinstance(mitre, list) and mitre:
            joined = ",".join(str(m) for m in mitre if m)
            if joined:
                add(f"Armis-MITRE: {joined}")
        elif isinstance(mitre, str) and mitre.strip():
            add(f"Armis-MITRE: {mitre.strip()}")
        count = item.get("affectedDevicesCount")
        if isinstance(count, (int, float)) and count:
            add(f"Armis-DeviceCount: {int(count)}")
        elif isinstance(count, str) and count.strip():
            add(f"Armis-DeviceCount: {count.strip()}")

    return refs


def build_asset_vulnerability(item, entity_type, site_id, boundary):
    """Build a Faraday vulnerability dict for one Armis record."""
    if entity_type == "device":
        hostnames = device_hostnames(item)
        primary = (
            hostnames[0] if hostnames else (device_ip(item) if device_ip(item) != "0.0.0.0" else "unknown device")
        )
        label = f"[ASSET-INVENTORY] Armis device: {primary}"
    else:
        if isinstance(item, dict):
            title = _flatten_string(item.get("title") or item.get("policyTitle"))
            primary = title or _flatten_string(item.get("alertId") or item.get("id")) or "unknown alert"
        else:
            primary = "unknown alert"
        label = f"[ASSET-INVENTORY] Armis alert: {primary}"

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
    if site_id:
        desc_parts.append(f"armis_site_id: {site_id}")
    if boundary:
        desc_parts.append(f"armis_boundary: {boundary}")

    cves = collect_cves(item) if isinstance(item, dict) else []
    refs = collect_refs(item, entity_type)

    external_id = ""
    if isinstance(item, dict):
        if entity_type == "device":
            external_id = str(item.get("id") or item.get("deviceId") or "")
        else:
            external_id = str(item.get("alertId") or item.get("id") or "")
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
            "Armis records are inventory entries / CPS observations, not "
            "actionable vulnerabilities.  Cross-check the device against "
            "the other agents' findings (EDR / EASM / vuln scanners) — "
            "anything reported against this Armis device id indicates a "
            "real exposure on a known discovered endpoint.  For alert "
            "hits, the surfaced record documents a policy violation or "
            "anomaly — review the alert in the Armis console against the "
            "operator's expected policy catalogue.  Decommission or "
            "merge the device in Armis if it should no longer appear in "
            "the inventory."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["armis", "asset-inventory", entity_type],
    }


def build_host_from_device(device_record, site_id, boundary):
    """Build a Faraday host dict from an Armis device record."""
    if device_record is None or not isinstance(device_record, dict):
        return None

    ip = device_ip(device_record)
    hostnames = device_hostnames(device_record)
    mac = device_mac(device_record)
    os_str = device_os(device_record)

    desc_parts = []
    for key in (
        "category",
        "type",
        "siteName",
        "siteId",
        "boundary",
        "riskLevel",
        "purdueLevel",
        "manufacturer",
        "model",
        "firstSeen",
        "lastSeen",
    ):
        v = device_record.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    vuln = build_asset_vulnerability(device_record, "device", site_id, boundary)
    return {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln] if vuln else [],
    }


def build_host_from_alert(alert_record, site_id, boundary):
    """Build a Faraday host dict for an Armis alert record.

    Armis alerts CAN be device-keyed (the alert carries a scalar
    ``ip`` field when the underlying event came from one specific
    device's traffic), so we project the alert's IP onto host.ip
    when present.  Loopback / zero are skipped (we fall back to
    ``0.0.0.0`` when the alert is policy-shaped and not keyed on
    any single device).  The ``title`` / ``policyTitle``
    projection lands on hostnames so Faraday's hostname index
    still pivots on the alert subject.
    """
    if alert_record is None or not isinstance(alert_record, dict):
        return None

    ip = alert_ip(alert_record)

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

    add(_flatten_string(alert_record.get("title")))
    add(_flatten_string(alert_record.get("policyTitle")))
    add(_flatten_string(alert_record.get("type")))

    vuln = build_asset_vulnerability(alert_record, "alert", site_id, boundary)
    return {
        "ip": ip,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Armis security alert",
        "vulnerabilities": [vuln] if vuln else [],
    }


def exchange_secret_key(requests_module, host, secret_key):
    """Swap ARMIS_SECRET_KEY for a short-lived access token.

    Armis v1 uses a two-step auth flow.  POST
    ``/api/v1/access_token/`` with ``secret_key=<key>`` form data
    returns ``{"data": {"access_token": "...", "expiration_utc":
    "..."}, "success": true}``.  We forward the secret key as form
    data (Armis' documented contract — JSON bodies are rejected by
    the access_token endpoint) and pull the returned access token
    out of the envelope via ``extract_access_token`` so federated
    / future envelope shapes round-trip cleanly.  Returns the
    empty string on auth failure so the caller can ``sys.exit(1)``
    with a descriptive log message.
    """
    url = build_access_token_url(host)
    headers = {"Accept": "application/json"}
    try:
        resp = requests_module.post(
            url,
            data={"secret_key": secret_key},
            headers=headers,
            timeout=TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        return ""
    if resp.status_code == 401:
        log("Armis access_token request rejected (401). Check ARMIS_SECRET_KEY.")
        return ""
    if resp.status_code == 403:
        log("Armis access_token request rejected (403). Check the key's tenant scope.")
        return ""
    if resp.status_code >= 400:
        log(f"Armis access_token request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return ""
    try:
        payload = resp.json()
    except ValueError:
        log(f"Armis access_token response was not JSON ({url})")
        return ""
    token = extract_access_token(payload)
    if not token:
        log("Armis access_token response had no access_token field")
    return token


def fetch_pages(requests_module, url, headers, length, max_pages, extra_params=None):
    """Walk an Armis v1 ``/devices/`` or ``/alerts/`` envelope.

    Pagination is offset-based via ``from`` + ``length`` query
    parameters.  We page until either ``len(records) < length`` or
    ``max_pages`` is reached.  401 short-circuits the whole
    executor (token is wrong); 403 / 429 / 5xx stop pagination on
    the surface and return what we have.
    """
    out = []
    offset = 0
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(offset, length=length, extra=extra_params)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Armis request rejected (401). Access token expired or invalid.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Armis request rejected (403). Check the token's tenant scope.")
            return out
        if resp.status_code == 429:
            log("Armis rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Armis request failed ({resp.status_code}) for {full_url}: " f"{resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Armis response was not JSON ({full_url})")
            return out
        records = extract_records(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < length:
            break
        offset += length
    if walked >= max_pages and len(records) >= length:
        log(f"hit ARMIS_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    site_id = validate_site_id(env("EXECUTOR_CONFIG_ARMIS_SITE_ID"))
    boundary = validate_boundary(env("EXECUTOR_CONFIG_ARMIS_BOUNDARY"))
    pages = validate_pages(env("ARMIS_PAGES"))

    host = env("ARMIS_HOST", required=True)
    secret_key = env("ARMIS_SECRET_KEY", required=True)

    if not normalize_base_url(host):
        log("ARMIS_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    access_token = exchange_secret_key(requests, host, secret_key)
    if not access_token:
        log("Could not obtain Armis access token; aborting")
        sys.exit(1)

    headers = auth_headers(access_token)
    devices_url = build_devices_url(host)
    alerts_url = build_alerts_url(host)

    device_aql = build_asq("devices", site_id, boundary)
    alert_aql = build_asq("alerts", site_id, boundary)

    device_records = fetch_pages(
        requests,
        devices_url,
        headers,
        PER_PAGE,
        max_pages=pages,
        extra_params={"aql": device_aql},
    )
    alert_records = fetch_pages(
        requests,
        alerts_url,
        headers,
        PER_PAGE,
        max_pages=pages,
        extra_params={"aql": alert_aql},
    )

    log(
        f"Processing {len(device_records)} Armis devices + "
        f"{len(alert_records)} alerts "
        f"(site_id={site_id!r}, boundary={boundary!r}, pages={pages})"
    )

    hosts_out = []
    for record in device_records:
        built = build_host_from_device(record, site_id, boundary)
        if built is not None:
            hosts_out.append(built)
    for record in alert_records:
        built = build_host_from_alert(record, site_id, boundary)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "armis",
            "command": "armis",
            "params": (f"site_id={site_id}," f"boundary={boundary}," f"pages={pages}"),
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
