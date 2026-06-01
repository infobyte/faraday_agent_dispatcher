#!/usr/bin/env python
"""Nozomi Networks Vantage OT site + alert importer.

Pulls OT site inventory and security alerts from a Nozomi
Networks Vantage tenant via its v1 REST API and emits
Faraday bulk-create JSON to stdout.  Vantage is Nozomi's
SaaS-delivered OT / IoT / IT visibility platform — it
aggregates findings from federated Guardian appliances
(and lightweight Vantage IQ collectors) across an
operator's OT estate and surfaces both the resulting OT
site catalog and the rule-based / anomaly alert feed via
a hosted v1 REST surface.  This executor surfaces both
streams under the operator's existing Faraday workspace
so the connected-OT findings join the dispatcher's
IT-side scanner output.

Endpoints used:
  GET {VANTAGE_HOST}/v1/sites?page=N&page_size=M
      -> Paginated OT site inventory.  Each Vantage site
      models one OT facility / plant / process line in
      the operator's estate; the executor projects each
      site onto one Faraday host with an
      ``[ASSET-INVENTORY]`` vulnerability marker so OT
      facility records land alongside the other CMDB-
      class feeds.  The canonical envelope is
      ``{"results": [...], "count": N, "next": "...",
      "previous": "..."}`` (Vantage's Django-REST style);
      federated mirrors collapse this into bare lists or
      ``{"data": [...]}`` / ``{"items": [...]}`` /
      ``{"sites": [...]}`` — all shapes are accepted.
      Each record carries ``id``, ``name``, ``description``,
      ``location`` / ``address``, ``city``, ``country``,
      ``latitude`` / ``longitude``, ``time_zone``,
      ``created_at`` / ``updated_at``, the appliance
      roster (``appliances`` / ``guardian_count``),
      ``asset_count`` (rolled-up OT asset inventory size
      for the site), ``alert_count`` (open-alert
      backlog), and optional ``criticality`` /
      ``risk_score`` rollups (Critical / High / Medium /
      Low / Info label or 0..100 numeric on some
      tenants).

  GET {VANTAGE_HOST}/v1/alerts?site_id=<id>&page=N&page_size=M
      -> Paginated security alert feed.  Same envelope
      shape; each record carries ``id``, ``name`` /
      ``type_name``, ``description``, ``severity``
      (``Critical`` / ``High`` / ``Medium`` / ``Low`` /
      ``Info``, or 0..10 numeric on some firmwares),
      ``type_id`` (Vantage inherits Guardian's published
      alert taxonomy: ``SIGN:NETWORK:MALWARE`` /
      ``SIGN:PROTOCOL:ANOMALY`` /
      ``VI:UNAUTHORIZED-COMMAND`` / etc), ``status``
      (``open`` / ``acknowledged`` / ``closed`` /
      ``muted`` / ``resolved``), ``record_created_at``
      / ``record_updated_at`` (or ``created_at`` /
      ``updated_at`` on newer tenants), ``src_ip`` /
      ``dst_ip``, ``risk`` (0..10), ``site_id`` /
      ``site_name``, and ``zone_id`` / ``zone_name``.

Auth: Vantage uses the same stateless auth shape as
Guardian — there is no login round-trip; the operator-
issued ``VANTAGE_API_KEY`` is passed verbatim on every
``/v1/`` request, and Vantage rejects any request whose
key is missing or wrong with a 401.  The exact header
form is ``Authorization: Bearer <key>`` (the documented
Vantage API auth header; Vantage issues a single bearer-
shaped key per tenant in the Vantage console rather than
a username + password pair, so Guardian's Basic-Auth
encoding does not apply, but the no-login-round-trip
discipline matches).  The token never leaves the
dispatcher's process memory — it is only ever stitched
into the outgoing ``Authorization`` header.

Args:
  ``VANTAGE_SITE_ID`` (optional) — server-side site
  predicate forwarded as ``site_id=<value>`` on both
  ``/v1/sites`` and ``/v1/alerts``.  Empty / missing
  walks the entire tenant's OT estate (the operator's
  API-key scope still applies).  Whitespace is trimmed.
  Useful for sharding inventory pulls across multiple
  discovery profiles so each dispatcher agent only walks
  one OT site (one plant / one facility) per run.
  Vantage accepts both the numeric site id and the
  literal site name in this slot depending on tenant
  configuration.

Env vars:
  ``VANTAGE_HOST`` (mandatory) — the Vantage tenant base
  URL (e.g.  ``https://acme.vantage.nozominetworks.io``
  or the public hub ``https://api.vantage.nozominetworks.com``).
  Vantage is multi-tenant SaaS so there is no global
  default — the executor exits cleanly when
  ``VANTAGE_HOST`` is missing.  Whitespace is trimmed;
  ``https://`` is added when the operator pasted in a
  bare FQDN.

  ``VANTAGE_API_KEY`` (mandatory) — the tenant API key
  provisioned in the Vantage console.  Forwarded as
  ``Authorization: Bearer <key>`` on every request; the
  key never leaves the dispatcher's process memory.

Each Vantage record becomes one Faraday host.  Site
records project the first usable IP in ``ip`` /
``primary_ip`` / ``ip_address`` onto ``host.ip``
(loopback / 0.0.0.0 / ::1 are skipped, falling back to
the ``0.0.0.0`` sentinel when no IP is published —
Vantage sites are facility records and most do not carry
an IP), ``name`` / ``label`` / ``site_name`` onto
``host.hostnames``, and the location / city / country
chain joins onto ``host.os`` (a stand-in for the
facility's physical placement).  The site itself becomes
one Faraday vulnerability with the ``[ASSET-INVENTORY]``
engine prefix so OT facility records land alongside the
other CMDB-class feeds (Armis, Axonius, Device42, Fleet,
runZero, Jamf Pro, Guardian).  Alert records are keyed
on the first usable ``src_ip`` / ``source_ip`` /
``dst_ip`` / ``destination_ip`` / ``ip`` / ``node_ip``
field (then the ``0.0.0.0`` sentinel for policy-shaped
alerts not keyed on any single asset).

Severity bucketing:
  - Sites: the rolled-up ``criticality`` / ``risk_score``
    field is the canonical ``critical`` / ``high`` /
    ``medium`` / ``low`` / ``info`` label (or 0..4 /
    0..10 / 0..100 numeric ladder).  Missing /
    unparseable -> ``info``.
  - Alerts: ``severity`` is the canonical label or
    0..10 numeric; the alert ``risk`` is used as a
    fallback when only a numeric score is published.

Tags: ``[nozomi_vantage, ot-security, site|alert]``.
Status is always ``open`` (Vantage's terminal
``resolved`` / ``muted`` / ``closed`` / ``suppressed`` /
``dismissed`` / ``acknowledged`` / ``mitigated`` /
``accepted_risk`` states are preserved via the
info-severity floor + an explicit ``Vantage-Status``
pivot in the refs).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

TIMEOUT = 60

SITES_PATH = "/v1/sites"
ALERTS_PATH = "/v1/alerts"

DEFAULT_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 500
DEFAULT_PAGES = 10
MAX_PAGES = 100
INTER_REQUEST_SLEEP = 0.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(ALLOWED_SEVERITIES)}

# Vantage inherits Guardian's published label vocabulary
# (Critical / High / Medium / Low / Info / Informational)
# on the alert ``severity`` and site ``criticality``
# fields.  Operator-friendly aliases are normalised to
# Faraday's canonical lowercase ladder.
SEVERITY_ALIASES = {
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "high": "high",
    "elevated": "high",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
}

# Numeric 0..4 criticality ladder surfaced by some
# Vantage tenants (Critical=4 .. Info=0).
CRITICALITY_NUMERIC_ALIASES = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# Vantage alert terminal states — preserved via an
# explicit Vantage-Status pivot ref but floored to
# ``info`` severity (the record is no longer live).
CLOSED_ALERT_STATES = {
    "resolved",
    "closed",
    "muted",
    "suppressed",
    "dismissed",
    "false-positive",
    "false_positive",
    "falsepositive",
    "acknowledged",
    "ack",
    "mitigated",
    "accepted_risk",
    "accepted-risk",
    "acceptedrisk",
}


def log(msg):
    print(f"{datetime.utcnow()} - Vantage: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on VANTAGE_HOST.

    Vantage is multi-tenant SaaS (every operator gets a
    unique tenant subdomain — ``acme.vantage.nozominetworks.io``,
    ``acme.vantage.nozominetworks.com``, ``api.vantage.nozominetworks.com``)
    so there is no global default — empty / missing /
    non-string inputs return ``""`` (the caller hard-fails
    with a helpful error).  Whitespace is trimmed and
    ``https://`` is added when the operator pasted in a
    bare FQDN.
    """
    if not host or not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def normalize_site_id(value):
    """Trim VANTAGE_SITE_ID into a server-side predicate string.

    Empty / blank / non-string inputs return ``""`` so
    the caller skips the predicate entirely (walks the
    full tenant).  Vantage accepts both the numeric site
    id and the literal site name in this slot depending
    on tenant configuration; the executor forwards the
    operator's value verbatim and lets Vantage decide
    whether it matches.
    """
    if value is None or isinstance(value, bool):
        return ""
    if not isinstance(value, str):
        try:
            return str(value).strip()
        except Exception:  # noqa: BLE001 — defensive coerce
            return ""
    return value.strip()


def normalize_severity_label(value):
    """Coerce a Vantage severity / criticality label to Faraday's ladder.

    Returns ``None`` for missing / non-string / unknown
    inputs so the caller can fall back to numeric
    bucketing.
    """
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    return SEVERITY_ALIASES.get(text)


def severity_from_alert(value):
    """Bucket Faraday severity from a Vantage alert ``severity`` value.

    Accepts labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Info``) or 0..10 numeric
    score (Vantage's ``risk`` field).  Returns ``"info"``
    for missing / unparseable inputs.
    """
    label = normalize_severity_label(value) if isinstance(value, str) else None
    if label is not None:
        return label
    if isinstance(value, bool) or value is None:
        return "info"
    try:
        if isinstance(value, str):
            num = float(value.strip())
        else:
            num = float(value)
    except (TypeError, ValueError):
        return "info"
    if num != num:  # NaN
        return "info"
    if num < 0:
        return "info"
    if num >= 9.0:
        return "critical"
    if num >= 7.0:
        return "high"
    if num >= 4.0:
        return "medium"
    if num > 0.0:
        return "low"
    return "info"


def severity_from_criticality(value):
    """Bucket Faraday severity from a Vantage site ``criticality`` value.

    Accepts the labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Info``) and the numeric 0..4
    form (4=critical .. 0=info).  Falls back to the
    0..10 / 0..100 bucketing for tenants that surface
    criticality as a raw score.  Missing / unparseable
    inputs default to ``info``.
    """
    label = normalize_severity_label(value) if isinstance(value, str) else None
    if label is not None:
        return label
    if isinstance(value, bool) or value is None:
        return "info"
    try:
        if isinstance(value, str):
            num = float(value.strip())
        else:
            num = float(value)
    except (TypeError, ValueError):
        return "info"
    if num != num:  # NaN
        return "info"
    if num < 0:
        return "info"
    int_val = int(num) if num == int(num) else None
    if int_val is not None and int_val in CRITICALITY_NUMERIC_ALIASES:
        return CRITICALITY_NUMERIC_ALIASES[int_val]
    if num > 10.0:
        # 0..100 ladder (some tenants surface risk_score
        # as a percentage); scale to the 0..10 alert
        # bucketing path.
        return severity_from_alert(num / 10.0)
    return severity_from_alert(num)


def severity_meets_threshold(severity, min_severity):
    """True when ``severity`` >= ``min_severity`` in Faraday's ladder.

    ``min_severity is None`` keeps every record.  Unknown
    severity strings are dropped when a threshold is set
    (conservative — we cannot prove the record meets the
    bar).
    """
    if min_severity is None:
        return True
    if severity not in SEVERITY_ORDER or min_severity not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[min_severity]


def is_closed_alert(value):
    """True when a Vantage alert ``status`` is terminally closed."""
    if not isinstance(value, str):
        return False
    return value.strip().lower() in CLOSED_ALERT_STATES


def build_sites_url(host):
    return f"{normalize_base_url(host)}{SITES_PATH}"


def build_alerts_url(host):
    return f"{normalize_base_url(host)}{ALERTS_PATH}"


def build_query_string(site_id, page, page_size=DEFAULT_PAGE_SIZE):
    """Build the canonical Vantage page+predicate query string.

    Pagination is one-based (``page=1`` is the first
    page).  Bad inputs are coerced to safe defaults so a
    typo never crashes the dispatcher.  The site
    predicate is omitted when ``site_id`` is empty /
    missing (walks the full tenant).
    """
    try:
        p = int(page)
    except (TypeError, ValueError):
        p = 1
    if p < 1:
        p = 1
    try:
        s = int(page_size)
    except (TypeError, ValueError):
        s = DEFAULT_PAGE_SIZE
    if s < MIN_PAGE_SIZE:
        s = MIN_PAGE_SIZE
    if s > MAX_PAGE_SIZE:
        s = MAX_PAGE_SIZE
    params = []
    if isinstance(site_id, str) and site_id.strip():
        params.append(("site_id", site_id.strip()))
    params.append(("page", str(p)))
    params.append(("page_size", str(s)))
    return urlencode(params)


def bearer_auth_header(api_key):
    """Build the ``Authorization: Bearer <api_key>`` value.

    None / non-string / blank inputs still emit a
    well-formed (but empty) Bearer header so the server's
    401 surfaces as a clear error rather than a silently-
    skipped header.  The key is never logged or stored on
    the dispatcher.
    """
    k = api_key.strip() if isinstance(api_key, str) else ""
    return f"Bearer {k}"


def request_headers(api_key):
    """Build the request-header dict for a credentialed Vantage GET.

    Vantage's v1 surface documents
    ``Authorization: Bearer <key>`` on every request; the
    dispatcher uses the same shape across both
    ``/v1/sites`` and ``/v1/alerts``.  Missing / blank
    keys still produce a Bearer header so the server's
    401 is the visible failure mode rather than a
    silently-skipped header.
    """
    return {
        "Accept": "application/json",
        "Authorization": bearer_auth_header(api_key),
    }


def extract_records(body):
    """Pull the record list from a Vantage v1 response envelope.

    Canonical envelope wraps the record list under
    ``results`` (Vantage's Django-REST style — note the
    plural).  Federated / tenant mirrors also expose
    bare-list / ``result`` / ``data`` / ``items`` /
    ``sites`` / ``alerts`` — all shapes are tolerated.
    Non-dict entries are silently dropped.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in (
        "results",
        "result",
        "data",
        "items",
        "sites",
        "alerts",
    ):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def site_ip(site):
    """Pick the site's primary IP (skipping loopback / zero).

    Vantage sites are facility records and most do not
    carry an IP, but some tenants surface a primary
    appliance IP via ``ip`` / ``primary_ip`` /
    ``ip_address``.  Falls back to the ``0.0.0.0``
    sentinel when nothing usable is present.
    """
    if not isinstance(site, dict):
        return "0.0.0.0"
    candidates = []
    for key in ("ip", "ip_address", "primary_ip"):
        v = site.get(key)
        if isinstance(v, str) and v.strip():
            candidates.append(v.strip())
    for key in ("ips", "ip_addresses"):
        v = site.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    candidates.append(entry.strip())
                elif isinstance(entry, dict):
                    addr = entry.get("ip") or entry.get("address") or entry.get("value")
                    if isinstance(addr, str) and addr.strip():
                        candidates.append(addr.strip())
    for ip in candidates:
        if ip not in ("0.0.0.0", "127.0.0.1", "::1"):
            return ip
    return "0.0.0.0"


def site_hostnames(site):
    """Collect hostname candidates for a Vantage site."""
    if not isinstance(site, dict):
        return []
    out = []
    seen = set()
    for key in ("name", "label", "site_name", "hostname", "fqdn"):
        v = site.get(key)
        if isinstance(v, str):
            s = v.strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    return out


def site_location(site):
    """Build a human-readable location string for a Vantage site.

    Joins the ``location`` / ``address`` / ``city`` /
    ``region`` / ``country`` fields into a single
    ``city, country`` line projected onto ``host.os`` (a
    stand-in for the facility's physical placement —
    Vantage sites do not carry an OS of their own).
    """
    if not isinstance(site, dict):
        return ""
    bits = []
    seen = set()
    for key in ("location", "address", "city", "region", "country", "time_zone"):
        v = site.get(key)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            if s not in seen:
                seen.add(s)
                bits.append(s)
    return ", ".join(bits)


def alert_ip(alert):
    """Pick the alert's keyed IP (from src_ip / dst_ip / ip / related)."""
    if not isinstance(alert, dict):
        return "0.0.0.0"
    for key in ("src_ip", "source_ip", "dst_ip", "destination_ip", "ip", "node_ip"):
        v = alert.get(key)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            if s not in ("0.0.0.0", "127.0.0.1", "::1"):
                return s
    related = alert.get("related_assets") or alert.get("relatedAssets") or alert.get("related_devices")
    if isinstance(related, list):
        for entry in related:
            if isinstance(entry, str) and entry.strip():
                s = entry.strip()
                if s not in ("0.0.0.0", "127.0.0.1", "::1"):
                    return s
            elif isinstance(entry, dict):
                for key in ("ip", "ip_address", "primary_ip", "value"):
                    v = entry.get(key)
                    if isinstance(v, str) and v.strip():
                        s = v.strip()
                        if s not in ("0.0.0.0", "127.0.0.1", "::1"):
                            return s
    return "0.0.0.0"


def collect_cves(record):
    """Walk a Vantage record for CVE ids.

    Vantage surfaces CVE attribution on alerts via the
    description / title / type_name fields (and on some
    tenants via an explicit ``cve_list`` /
    ``vulnerabilities`` list).  All occurrences are
    deduplicated and uppercased to NVD's canonical form.
    """
    out = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if CVE_RE.fullmatch(s) and s not in seen:
            seen.add(s)
            out.append(s)

    def scan(text):
        if not isinstance(text, str):
            return
        for m in CVE_RE.findall(text):
            add(m)

    if not isinstance(record, dict):
        return out

    for key in ("cve_id", "cve"):
        v = record.get(key)
        if isinstance(v, str):
            add(v)

    for key in ("cve_list", "cves", "vulnerabilities", "vulnerability_list"):
        raw = record.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("id"))

    for key in ("name", "title", "description", "summary", "type_name"):
        scan(record.get(key))

    return out


def collect_refs(record, entity_type):
    """Build the refs list for a Vantage site / alert record."""
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

    if not isinstance(record, dict):
        return refs

    rec_id = record.get("id") or record.get("uuid")
    if rec_id is not None and str(rec_id).strip():
        if entity_type == "site":
            add(f"Vantage-SiteID: {str(rec_id).strip()}")
        else:
            add(f"Vantage-AlertID: {str(rec_id).strip()}")

    if entity_type == "site":
        for key, label in (
            ("name", "Vantage-SiteName"),
            ("location", "Vantage-Location"),
            ("address", "Vantage-Address"),
            ("city", "Vantage-City"),
            ("region", "Vantage-Region"),
            ("country", "Vantage-Country"),
            ("time_zone", "Vantage-TimeZone"),
            ("latitude", "Vantage-Latitude"),
            ("longitude", "Vantage-Longitude"),
            ("criticality", "Vantage-Criticality"),
            ("risk_score", "Vantage-RiskScore"),
            ("asset_count", "Vantage-AssetCount"),
            ("alert_count", "Vantage-AlertCount"),
            ("guardian_count", "Vantage-GuardianCount"),
            ("created_at", "Vantage-CreatedAt"),
            ("updated_at", "Vantage-UpdatedAt"),
        ):
            v = record.get(key)
            if v in (None, ""):
                continue
            add(f"{label}: {v}")
    else:
        site_name = record.get("site_name") or record.get("siteName")
        site_id = record.get("site_id") or record.get("siteId")
        if isinstance(site_name, str) and site_name.strip():
            add(f"Vantage-Site: {site_name.strip()}")
        elif site_id is not None and str(site_id).strip():
            add(f"Vantage-Site: {str(site_id).strip()}")

        zone_name = record.get("zone_name") or record.get("zoneName")
        zone_id = record.get("zone_id") or record.get("zoneId")
        if isinstance(zone_name, str) and zone_name.strip():
            add(f"Vantage-Zone: {zone_name.strip()}")
        elif zone_id is not None and str(zone_id).strip():
            add(f"Vantage-Zone: {str(zone_id).strip()}")

        for key, label in (
            ("severity", "Vantage-Severity"),
            ("type_id", "Vantage-TypeID"),
            ("type_name", "Vantage-TypeName"),
            ("category", "Vantage-Category"),
            ("status", "Vantage-Status"),
            ("risk", "Vantage-Risk"),
            ("risk_score", "Vantage-Risk"),
            ("src_ip", "Vantage-SrcIP"),
            ("dst_ip", "Vantage-DstIP"),
            ("record_created_at", "Vantage-CreatedAt"),
            ("record_updated_at", "Vantage-UpdatedAt"),
            ("created_at", "Vantage-CreatedAt"),
            ("updated_at", "Vantage-UpdatedAt"),
        ):
            v = record.get(key)
            if v in (None, ""):
                continue
            add(f"{label}: {v}")

    for cve in collect_cves(record):
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    return refs


def _serialise(value):
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def build_site_vulnerability(site, site_id_predicate, min_severity=None):
    """Build a Faraday vulnerability dict for one Vantage site.

    Returns ``None`` when the site's mapped severity is
    below ``min_severity``.  The site is surfaced as a
    Faraday vulnerability with the ``[ASSET-INVENTORY]``
    engine prefix so OT facility records land alongside
    the other CMDB-class feeds (Armis, Axonius, Device42,
    Fleet, runZero, Jamf Pro, Guardian).
    """
    if not isinstance(site, dict):
        return None
    severity_val = site.get("criticality")
    if severity_val is None:
        severity_val = site.get("risk_score")
    if severity_val is None:
        severity_val = site.get("risk")
    severity = severity_from_criticality(severity_val)
    if not severity_meets_threshold(severity, min_severity):
        return None

    hostnames = site_hostnames(site)
    primary = hostnames[0] if hostnames else (site_ip(site) if site_ip(site) != "0.0.0.0" else "unknown site")
    name = f"[ASSET-INVENTORY] Vantage site: {primary}"

    desc_parts = []
    for key in sorted(site.keys()):
        v = site.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if site_id_predicate:
        desc_parts.append(f"vantage_site_filter: {site_id_predicate}")

    site_id = str(site.get("id") or site.get("uuid") or name)

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"site::{site_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Nozomi Vantage site records are OT facility "
            "inventory entries — cross-check the site's "
            "asset / alert rollup against the operator's "
            "other agents (EDR / vuln scanners / EASM) for "
            "live exposures, verify the federated Guardian "
            "appliances reporting into the site are healthy "
            "in the Vantage console, and decommission or "
            "merge the site in Vantage if it should no "
            "longer appear in the inventory."
        ),
        "data": "",
        "refs": collect_refs(site, "site"),
        "cve": collect_cves(site),
        "cwe": [],
        "cvss3": {},
        "tags": ["nozomi_vantage", "ot-security", "site"],
    }


def build_alert_vulnerability(alert, site_id_predicate, min_severity=None):
    """Build a Faraday vulnerability dict for one Vantage alert.

    Returns ``None`` when the alert's mapped severity is
    below ``min_severity``.  Terminal Vantage states
    (``resolved`` / ``muted`` / ``closed`` /
    ``suppressed`` / ``dismissed`` / ``acknowledged`` /
    ``mitigated`` / ``accepted_risk``) floor the severity
    to ``info`` regardless of the published bucket.
    """
    if not isinstance(alert, dict):
        return None
    status = alert.get("status") if isinstance(alert.get("status"), str) else None
    severity_val = alert.get("severity")
    if severity_val is None:
        severity_val = alert.get("risk")
    if severity_val is None:
        severity_val = alert.get("risk_score")
    severity = severity_from_alert(severity_val)
    if is_closed_alert(status):
        severity = "info"
    if not severity_meets_threshold(severity, min_severity):
        return None

    title = alert.get("name") or alert.get("type_name") or alert.get("title") or alert.get("id") or "Vantage alert"
    name = f"[Vantage Alert] {str(title).strip()}"

    desc_parts = []
    description = alert.get("description") or alert.get("summary") or ""
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    for key in sorted(alert.keys()):
        if key in ("description", "summary"):
            continue
        v = alert.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if site_id_predicate:
        desc_parts.append(f"vantage_site_filter: {site_id_predicate}")

    alert_id = str(alert.get("id") or alert.get("uuid") or name)

    if is_closed_alert(status):
        resolution = (
            f"Vantage has marked this alert as {status}; "
            "verify the underlying condition is resolved on "
            "the affected OT asset before closing the "
            "Faraday finding."
        )
    else:
        resolution = (
            "Triage this Nozomi Vantage alert in the Vantage "
            "console, correlate against the src_ip / dst_ip "
            "and site_name / zone_name to identify the "
            "affected OT asset, and apply mitigations per "
            "the operator's incident-response runbook for "
            "the alert type_id (SIGN: signature-based, VI: "
            "variable-integrity, anomaly, protocol)."
        )

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"alert::{alert_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(alert, "alert"),
        "cve": collect_cves(alert),
        "cwe": [],
        "cvss3": {},
        "tags": ["nozomi_vantage", "ot-security", "alert"],
    }


def build_host_from_site(site, site_id_predicate, min_severity=None):
    """Build a Faraday host dict from a Vantage site record."""
    if not isinstance(site, dict):
        return None
    vuln = build_site_vulnerability(site, site_id_predicate, min_severity)
    if vuln is None:
        return None
    desc_parts = []
    for key in (
        "location",
        "city",
        "country",
        "time_zone",
        "asset_count",
        "alert_count",
        "guardian_count",
        "criticality",
        "risk_score",
        "created_at",
        "updated_at",
    ):
        v = site.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}={_serialise(v)}")
    return {
        "ip": site_ip(site),
        "os": site_location(site),
        "hostnames": site_hostnames(site),
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln],
    }


def build_host_from_alert(alert, site_id_predicate, min_severity=None):
    """Build a Faraday host dict from a Vantage alert record."""
    if not isinstance(alert, dict):
        return None
    vuln = build_alert_vulnerability(alert, site_id_predicate, min_severity)
    if vuln is None:
        return None
    hostnames = []
    title = alert.get("name") or alert.get("type_name") or alert.get("title")
    if isinstance(title, str) and title.strip():
        hostnames.append(title.strip())
    return {
        "ip": alert_ip(alert),
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Nozomi Vantage alert",
        "vulnerabilities": [vuln],
    }


def fetch_pages(requests_module, base_url, headers, site_id, surface_label, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk a Vantage v1 surface page-by-page.

    Pagination is one-based (``page=1`` is the first
    page).  Walks until either ``len(records) <
    page_size`` or ``max_pages`` is reached.  401
    short-circuits the whole executor (the API key is
    wrong); 403 / 429 / 5xx stop pagination on this
    surface and return what we have.
    """
    out = []
    page = 1
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query_string(site_id, page, page_size=page_size)
        full_url = f"{base_url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Vantage request rejected (401); check VANTAGE_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Vantage request rejected (403); check the API-key scope.")
            return out
        if resp.status_code == 429:
            log("Vantage rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Vantage request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Vantage response was not JSON ({full_url})")
            return out
        records = extract_records(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < page_size:
            break
        page += 1
    if walked >= max_pages and len(records) >= page_size:
        log(f"hit VANTAGE_PAGES={max_pages}; stopping pagination on {surface_label}")
    return out


def validate_pages(value):
    """Coerce VANTAGE_PAGES into a clamped integer.

    Env-only knob (not a manifest argument).  Defaults to
    ``DEFAULT_PAGES`` (10) when missing / blank /
    unparseable.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into thousands of
    requests against the tenant.
    """
    if value is None or value == "" or isinstance(value, bool):
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        return MAX_PAGES
    return n


def main():
    started = time.time()

    site_id = normalize_site_id(env("EXECUTOR_CONFIG_VANTAGE_SITE_ID"))
    pages = validate_pages(env("VANTAGE_PAGES"))

    host = env("VANTAGE_HOST", required=True)
    api_key = env("VANTAGE_API_KEY", required=True)

    if not normalize_base_url(host):
        log("VANTAGE_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = request_headers(api_key)
    sites_url = build_sites_url(host)
    alerts_url = build_alerts_url(host)

    sites = fetch_pages(requests, sites_url, headers, site_id, "sites", max_pages=pages)
    log(f"Vantage discovered {len(sites)} sites (site_id={site_id or '(all)'})")
    time.sleep(INTER_REQUEST_SLEEP)
    alerts = fetch_pages(requests, alerts_url, headers, site_id, "alerts", max_pages=pages)
    log(f"Vantage discovered {len(alerts)} alerts (site_id={site_id or '(all)'})")

    hosts_out = []
    for site in sites:
        built = build_host_from_site(site, site_id)
        if built is not None:
            hosts_out.append(built)
    for alert in alerts:
        built = build_host_from_alert(alert, site_id)
        if built is not None:
            hosts_out.append(built)

    log(
        f"Processed {len(hosts_out)} Vantage hosts "
        f"(sites={len(sites)}, alerts={len(alerts)}, "
        f"site_id={site_id or '(all)'})"
    )

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "nozomi_vantage",
            "command": "nozomi_vantage",
            "params": (f"site_id={site_id or ''} " f"sites={len(sites)} " f"alerts={len(alerts)} " f"pages={pages}"),
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
