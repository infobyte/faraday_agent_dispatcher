#!/usr/bin/env python
"""NetRise XIoT (firmware / IoT) REST importer.

Pulls managed devices and firmware vulnerabilities from a NetRise
tenant and emits Faraday bulk-create JSON to stdout.  Each NetRise
device becomes one Faraday host; firmware vulnerabilities attach as
Faraday vulnerabilities — one per finding id with engine prefix
``[EDR]``.  Because NetRise targets firmware / embedded / IoT assets
(network gear, OT controllers, BMC images, IoT cameras, satellite
ground stations, etc.) ``host.os`` is set to the firmware
``vendor / model`` (or ``vendor model version`` when a version is
available) rather than the operating system — firmware-targeted
vulnerabilities therefore land on a recognisable asset record even
when the underlying device has no traditional OS.

Endpoints used:
  GET {NETRISE_HOST}/api/v1/devices
      -> paginated device (firmware) inventory. Query params carry
      ``page`` / ``limit`` cursor pagination plus an optional
      ``group`` / ``device_group`` filter sourced from the
      NETRISE_DEVICE_GROUP arg. Response envelope is
      ``{"data": [...], "meta": {"total": N, "page": M, "pages": K}}``
      with ``items`` / ``devices`` / ``results`` accepted as alt-keys
      on federated / legacy stacks.
  GET {NETRISE_HOST}/api/v1/firmware-vulnerabilities
      -> paginated firmware vulnerability catalogue. Same query
      shape as the devices surface plus an optional ``device_id``
      filter walked per-device so re-emitted shapes still bucket
      every finding onto its source firmware image. Response envelope
      mirrors the device surface (``data`` / ``items`` / ``results``
      / ``vulnerabilities`` / ``findings`` accepted).

Auth: NetRise uses a static bearer-token header — the operator
creates an API token in the NetRise console (Settings -> API Tokens)
and the dispatcher carries it as ``Authorization: Bearer
<NETRISE_TOKEN>`` plus ``Accept: application/json`` on every
``/api/v1/`` call. ``NETRISE_HOST`` is the NetRise tenant base URL
(e.g. ``https://api.netrise.io`` or ``https://<tenant>.netrise.io``).
``NETRISE_DEVICE_GROUP`` is an optional client-side device-group
filter (the NetRise console lets operators bucket related firmware
into logical groups — e.g. ``edge_routers``, ``industrial_plc``);
when set, the filter is forwarded server-side via the devices.list
query param so NetRise does the bulk of the filtering server-side
and is also re-applied client-side after the device catalogue is
fetched so legacy stacks that ignore the query param still bucket
correctly.
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
MAX_PAGES = 200
PAGE_SIZE = 100  # NetRise paginates in 100-row windows on /api/v1/* surfaces.

# NetRise surfaces severity as a freeform string ("Critical" /
# "High" / "Medium" / "Low" / "Informational") plus a numeric
# ``cvss_score`` (or ``score``) when the underlying advisory carries
# a CVSS vector. The string enum buckets onto Faraday tiers; CVSS
# bucketing is used as a fallback when the string is missing /
# unrecognised.
NETRISE_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# NetRise finding status / state -> Faraday status. NetRise surfaces
# finding lifecycle through ``status`` / ``state`` / ``workflow`` —
# new / open / detected onto Faraday open; remediated / patched /
# fixed onto closed; suppressed / accepted / waived / wontfix onto
# risk-accepted (firmware patches are often impossible on legacy
# embedded gear so the platform actively encourages risk-accepted
# determinations as a first-class workflow state).
NETRISE_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "active": "open",
    "detected": "open",
    "in_progress": "open",
    "inprogress": "open",
    "investigating": "open",
    "triaging": "open",
    "closed": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "remediated": "closed",
    "patched": "closed",
    "mitigated": "closed",
    "suppressed": "risk-accepted",
    "dismissed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "wontfix": "risk-accepted",
    "won't_fix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "waived": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false_positive": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - NetRise: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "info"
    if score <= 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    if score > 10:
        return "info"
    return "critical"


def severity_from_netrise(value, cvss=None):
    """Map a NetRise severity to a Faraday bucket.

    Accepts the freeform string enum (Critical / High / Medium / Low
    / Informational), Faraday-side synonyms, numeric inputs (0-10
    CVSS-style), numeric strings, and falls back to CVSS bucketing
    on ``cvss`` when the primary value is missing or unrecognised.
    """
    if isinstance(value, bool):
        # Defensive: bool is a subclass of int — skip it entirely.
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower()
        if text in NETRISE_STRING_SEVERITY:
            return NETRISE_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_netrise(item):
    """Derive Faraday status from a NetRise finding payload.

    Walks ``status`` / ``state`` / ``workflow`` and falls back to
    ``determination`` for re-emitted shapes (TRUE_POSITIVE -> open,
    FALSE_POSITIVE -> risk-accepted).
    """
    if not isinstance(item, dict):
        return "open"
    for key in ("status", "state", "workflow", "workflow_state", "Status", "State"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in NETRISE_STATUS_BY_STATE:
                return NETRISE_STATUS_BY_STATE[compact]
            if squashed in NETRISE_STATUS_BY_STATE:
                return NETRISE_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in NETRISE_STATUS_BY_STATE:
                        return NETRISE_STATUS_BY_STATE[compact]
                    if squashed in NETRISE_STATUS_BY_STATE:
                        return NETRISE_STATUS_BY_STATE[squashed]
    determination = item.get("determination")
    if isinstance(determination, dict):
        value = determination.get("value") or determination.get("name")
        if isinstance(value, str) and value.strip():
            compact = value.strip().lower().replace(" ", "_").replace("-", "_")
            if compact == "false_positive":
                return "risk-accepted"
            if compact == "true_positive":
                return "open"
    elif isinstance(determination, str) and determination.strip():
        compact = determination.strip().lower().replace(" ", "_").replace("-", "_")
        if compact == "false_positive":
            return "risk-accepted"
        if compact == "true_positive":
            return "open"
    return "open"


def validate_min_severity(value):
    """Validate NETRISE_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus NetRise-side synonyms
    (informational, important / major, moderate, minor, none /
    unspecified / unknown) plus numeric-string input bucketed via
    severity_from_cvss.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = NETRISE_STRING_SEVERITY.get(text)
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"NETRISE_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_device_group(value):
    """Validate NETRISE_DEVICE_GROUP (the optional device-group filter).

    None / blank -> None (no filter). Whitespace is trimmed. NetRise
    device-group identifiers are free-form labels assigned in the
    console so we don't enforce a particular shape client-side beyond
    blank rejection.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    if not text:
        return None
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on the NetRise host."""
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def build_devices_url(host):
    base = normalize_base_url(host)
    return f"{base}/api/v1/devices"


def build_vulns_url(host):
    base = normalize_base_url(host)
    return f"{base}/api/v1/firmware-vulnerabilities"


def auth_headers(token):
    """NetRise expects ``Authorization: Bearer <NETRISE_TOKEN>``."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def build_devices_params(device_group, page, limit):
    """Build the query params for /api/v1/devices.

    Forwards the optional NETRISE_DEVICE_GROUP filter server-side via
    ``device_group`` (some federated stacks accept ``group`` as the
    legacy alias — we send both so the API picks whichever it knows).
    """
    params = {"page": int(page), "limit": int(limit)}
    if device_group:
        params["device_group"] = device_group
        params["group"] = device_group
    return params


def build_vulns_params(device_id, page, limit):
    """Build the query params for /api/v1/firmware-vulnerabilities."""
    params = {"page": int(page), "limit": int(limit)}
    if device_id:
        params["device_id"] = device_id
    return params


def extract_items(body, keys=("data", "items", "results", "devices", "vulnerabilities", "findings")):
    """Pull the result list out of a NetRise-style search envelope.

    NetRise uses ``{"data": [...], "meta": {...}}`` on most surfaces
    but ``items`` / ``results`` / ``devices`` / ``vulnerabilities`` /
    ``findings`` appear on legacy / federated stacks.
    """
    if not isinstance(body, dict):
        return []
    for key in keys:
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_meta_total(body):
    """Pull the total record count from a NetRise envelope's ``meta`` block."""
    if not isinstance(body, dict):
        return None
    meta = body.get("meta")
    if isinstance(meta, dict):
        for key in ("total", "totalCount", "total_count", "total_items"):
            v = meta.get(key)
            if isinstance(v, int):
                return v
    for key in ("total", "totalCount", "total_count", "total_items"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def cvss_score(item):
    """Pull a numeric CVSS score from a NetRise finding payload."""
    if not isinstance(item, dict):
        return None
    candidates = [item]
    vuln = item.get("vulnerability") or item.get("advisory") or item.get("cve")
    if isinstance(vuln, dict):
        candidates.insert(0, vuln)
    for src in candidates:
        if not isinstance(src, dict):
            continue
        for key in ("cvssScore", "cvss_score", "cvss", "score", "baseScore", "base_score"):
            v = src.get(key)
            if v is None or isinstance(v, (dict, list, bool)):
                continue
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
        for nested_key in ("cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2"):
            nested = src.get(nested_key)
            if isinstance(nested, dict):
                for inner_key in ("3.0", "3.1", "2.0"):
                    inner = nested.get(inner_key)
                    if isinstance(inner, dict):
                        for k in ("base", "Base", "score", "Score", "baseScore", "base_score"):
                            v = inner.get(k)
                            if v is None or isinstance(v, (dict, list, bool)):
                                continue
                            try:
                                return float(v)
                            except (TypeError, ValueError):
                                continue
                for k in ("score", "baseScore", "base_score", "base"):
                    v = nested.get(k)
                    if v is None or isinstance(v, (dict, list, bool)):
                        continue
                    try:
                        return float(v)
                    except (TypeError, ValueError):
                        continue
    return None


def cvss_vector(item):
    if not isinstance(item, dict):
        return ""
    candidates = [item]
    vuln = item.get("vulnerability") or item.get("advisory") or item.get("cve")
    if isinstance(vuln, dict):
        candidates.insert(0, vuln)
    for src in candidates:
        if not isinstance(src, dict):
            continue
        for k in ("cvssVector", "cvss_vector", "vector", "vectorString", "vector_string"):
            s = src.get(k)
            if isinstance(s, str) and s.strip():
                return s.strip()
        for nested_key in ("cvss3", "cvssV3", "cvss_v3"):
            nested = src.get(nested_key)
            if isinstance(nested, dict):
                for inner_key in ("3.0", "3.1", "2.0"):
                    inner = nested.get(inner_key)
                    if isinstance(inner, dict):
                        for k in ("vector", "Vector", "vectorString", "vector_string"):
                            s = inner.get(k)
                            if isinstance(s, str) and s.strip():
                                return s.strip()
                for k in ("vector", "vectorString", "vector_string"):
                    s = nested.get(k)
                    if isinstance(s, str) and s.strip():
                        return s.strip()
    return ""


def collect_cves(item):
    """Pull CVE-* ids out of a NetRise firmware-vulnerability payload."""
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

    vuln = item.get("vulnerability") or item.get("advisory") or {}
    if not isinstance(vuln, dict):
        vuln = {}

    for src in (item, vuln):
        if not isinstance(src, dict):
            continue
        for key in ("cve", "cveId", "cve_id", "Cve", "CveId"):
            v = src.get(key)
            if isinstance(v, str) and v.strip():
                add(v)
            elif isinstance(v, dict):
                add(v.get("id") or v.get("Id") or v.get("name") or v.get("value"))
        for key in ("cves", "cveIds", "cve_ids", "aliases", "Cves"):
            v = src.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add(entry)
                    elif isinstance(entry, dict):
                        add(
                            entry.get("id")
                            or entry.get("Id")
                            or entry.get("name")
                            or entry.get("cve")
                            or entry.get("cveId")
                        )

    for key in (
        "title",
        "Title",
        "name",
        "Name",
        "summary",
        "Summary",
        "description",
        "Description",
        "details",
        "Details",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)

    for key in ("title", "name", "summary", "description"):
        v = vuln.get(key) if isinstance(vuln, dict) else None
        if isinstance(v, str):
            scan(v)

    return found


def collect_refs(item):
    """Walk a NetRise finding for advisory URLs / pivots.

    Surfaces NetRise-side pivots (``NetRise-Finding: {id}``,
    ``NetRise-Component: {name}``, ``NetRise-Firmware: {hash}``,
    ``NetRise-Package: {name@version}``) plus any inline URLs from
    the advisory catalogue.
    """
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

    def add_cwe(value):
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, (int, float)):
            add(f"CWE-{int(value)}")
            return
        if isinstance(value, str) and value.strip():
            s = value.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
            return
        if isinstance(value, dict):
            cid = value.get("id") or value.get("Id") or value.get("value") or value.get("name")
            if cid is not None:
                add_cwe(cid)

    if not isinstance(item, dict):
        return refs

    vuln = item.get("vulnerability") or item.get("advisory") or {}
    if not isinstance(vuln, dict):
        vuln = {}

    for src in (item, vuln):
        if not isinstance(src, dict):
            continue
        for source_key in ("cweId", "cwe_id", "cwe", "CWE"):
            add_cwe(src.get(source_key))
        for source_key in ("cwes", "cweIds", "cwe_ids", "CWEs"):
            entries = src.get(source_key)
            if isinstance(entries, list):
                for it in entries:
                    add_cwe(it)

    finding_id = item.get("id") or item.get("finding_id") or item.get("findingId")
    if finding_id is not None:
        s = str(finding_id).strip()
        if s:
            add(f"NetRise-Finding: {s}")

    device_id = item.get("device_id") or item.get("deviceId")
    if device_id is not None:
        s = str(device_id).strip()
        if s:
            add(f"NetRise-Device: {s}")

    firmware_id = (
        item.get("firmware_id") or item.get("firmwareId") or item.get("firmware_hash") or item.get("firmwareHash")
    )
    if firmware_id is not None:
        s = str(firmware_id).strip()
        if s:
            add(f"NetRise-Firmware: {s}")

    component = (
        item.get("component")
        or item.get("componentName")
        or item.get("component_name")
        or item.get("package")
        or item.get("packageName")
        or item.get("package_name")
    )
    if isinstance(component, str) and component.strip():
        comp_version = (
            item.get("component_version")
            or item.get("componentVersion")
            or item.get("package_version")
            or item.get("packageVersion")
            or item.get("version")
        )
        if comp_version:
            add(f"NetRise-Package: {component.strip()}@{comp_version}")
        else:
            add(f"NetRise-Component: {component.strip()}")
    elif isinstance(component, dict):
        cname = component.get("name") or component.get("id")
        cver = component.get("version") or component.get("Version")
        if isinstance(cname, str) and cname.strip():
            if cver:
                add(f"NetRise-Package: {cname.strip()}@{cver}")
            else:
                add(f"NetRise-Component: {cname.strip()}")

    # references / links lists shared with other CSPM / EDR shapes.
    for key in ("references", "links", "References", "Links", "advisory_urls"):
        entry = item.get(key) if isinstance(item, dict) else None
        if entry is None and isinstance(vuln, dict):
            entry = vuln.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = (
                        it.get("href")
                        or it.get("Href")
                        or it.get("url")
                        or it.get("Url")
                        or it.get("name")
                        or it.get("value")
                    )
                    if href:
                        add(href)
                elif it:
                    add(str(it))
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def device_label(item):
    """Build a friendly label for a NetRise device record."""
    if not isinstance(item, dict):
        return ""
    for key in ("name", "device_name", "deviceName", "hostname", "Hostname", "label"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("model", "Model"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("id", "Id", "device_id", "deviceId"):
        v = item.get(key)
        if v is not None:
            s = str(v).strip()
            if s:
                return s
    return ""


def device_os(item):
    """Build the firmware vendor/model string used as ``host.os``.

    Per the NetRise integration spec ``host.os`` carries the firmware
    vendor + model (e.g. ``Cisco / ASR-9000``) rather than the OS,
    because NetRise targets firmware / embedded / IoT assets where
    the OS layer is often a stripped-down vendor blob.  Falls back to
    the OS field when neither vendor nor model is set.
    """
    if not isinstance(item, dict):
        return ""
    vendor = ""
    for key in ("vendor", "Vendor", "manufacturer", "Manufacturer", "make", "Make"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            vendor = v.strip()
            break
    model = ""
    for key in ("model", "Model", "device_model", "deviceModel", "product", "Product"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            model = v.strip()
            break
    firmware_version = ""
    for key in (
        "firmware_version",
        "firmwareVersion",
        "version",
        "Version",
        "fw_version",
        "fwVersion",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            firmware_version = v.strip()
            break
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            firmware_version = str(v)
            break

    if vendor and model:
        base = f"{vendor} / {model}"
    elif vendor:
        base = vendor
    elif model:
        base = model
    else:
        # Fall back to a traditional OS string if neither vendor nor
        # model is present — some legacy stacks ship those as ``os``.
        os_name = item.get("os") or item.get("operating_system") or ""
        os_version = item.get("os_version") or ""
        if os_name and os_version:
            return f"{os_name} {os_version}".strip()
        return str(os_name or os_version or "").strip()

    if firmware_version:
        return f"{base} {firmware_version}".strip()
    return base


def vuln_label(item):
    """Build the leading title fragment for a NetRise finding."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "title",
        "Title",
        "name",
        "Name",
        "summary",
        "Summary",
        "vulnerability_name",
        "vulnName",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    vuln = item.get("vulnerability") or item.get("advisory")
    if isinstance(vuln, dict):
        for key in ("title", "name", "summary"):
            v = vuln.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    cve = item.get("cve") or item.get("cveId") or item.get("cve_id")
    if isinstance(cve, str) and cve.strip():
        return cve.strip()
    return "NetRise firmware finding"


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


def build_vulnerability(item, device_lookup=None):
    """Build a Faraday vulnerability dict from a NetRise finding record."""
    if not isinstance(item, dict):
        return None

    score = cvss_score(item)
    severity_raw = item.get("severity") or item.get("Severity") or item.get("risk")
    if severity_raw is None:
        vuln = item.get("vulnerability") or item.get("advisory")
        if isinstance(vuln, dict):
            severity_raw = vuln.get("severity") or vuln.get("risk")
    severity = severity_from_netrise(severity_raw, score)
    status = status_from_netrise(item)

    label = vuln_label(item)
    name = f"[EDR] {label}" if label else "[EDR] NetRise firmware finding"

    desc_parts = []
    description = item.get("description") or item.get("Description") or item.get("details")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("finding_id", "id"),
        ("finding_uid", "uid"),
        ("title", "title"),
        ("summary", "summary"),
        ("severity_raw", "severity"),
        ("risk", "risk"),
        ("detected_at", "detected_at"),
        ("first_seen", "first_seen"),
        ("last_seen", "last_seen"),
        ("created_at", "created_at"),
        ("updated_at", "updated_at"),
        ("device_id", "device_id"),
        ("device_name", "device_name"),
        ("firmware_id", "firmware_id"),
        ("firmware_hash", "firmware_hash"),
        ("firmware_version", "firmware_version"),
        ("component", "component"),
        ("component_name", "component_name"),
        ("component_version", "component_version"),
        ("package", "package"),
        ("package_name", "package_name"),
        ("package_version", "package_version"),
        ("file_path", "file_path"),
        ("file", "file"),
        ("path", "path"),
        ("kernel_module", "kernel_module"),
        ("binary", "binary"),
        ("exploit_available", "exploit_available"),
        ("known_exploited", "known_exploited"),
        ("kev", "kev"),
        ("epss", "epss"),
        ("epss_score", "epss_score"),
        ("cwe", "cwe"),
        ("workflow_state", "workflow"),
        ("determination", "determination"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(item)
    if vector:
        desc_parts.append(f"vector: {vector}")

    if isinstance(device_lookup, dict):
        device_id = item.get("device_id") or item.get("deviceId")
        if device_id is not None:
            device = device_lookup.get(str(device_id))
            if isinstance(device, dict):
                for sub_key in (
                    "vendor",
                    "manufacturer",
                    "model",
                    "product",
                    "device_type",
                    "deviceType",
                    "device_group",
                    "group",
                    "firmware_version",
                    "fw_version",
                    "version",
                    "serial_number",
                    "serialNumber",
                    "asset_tag",
                    "platform",
                    "architecture",
                    "arch",
                    "site",
                    "location",
                    "last_seen",
                    "first_seen",
                    "ip",
                    "ip_address",
                    "mac",
                    "mac_address",
                ):
                    sv = device.get(sub_key)
                    if sv in (None, ""):
                        continue
                    if isinstance(sv, (dict, list)):
                        desc_parts.append(f"device_{sub_key}: {_serialise(sv)}")
                    else:
                        desc_parts.append(f"device_{sub_key}: {sv}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    rem = (
        item.get("remediation")
        or item.get("Remediation")
        or item.get("remediation_description")
        or item.get("remediationDescription")
        or item.get("fix")
        or item.get("Fix")
        or item.get("recommendation")
        or item.get("Recommendation")
    )
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution:
        fixed_version = item.get("fixed_version") or item.get("fixedVersion") or item.get("fix_version")
        if isinstance(fixed_version, str) and fixed_version.strip():
            resolution = (
                f"Upgrade the affected firmware component to "
                f"{fixed_version.strip()} or later, or apply the vendor's "
                "firmware advisory mitigation if no patched build is yet "
                "available."
            )
    if not resolution:
        resolution = (
            "Investigate the finding in the NetRise console "
            "(Findings -> select finding) and pivot to the firmware-image "
            "view; if no patched build is available from the vendor, "
            "accept the risk or apply a network-layer compensating "
            "control (segmentation / acl)."
        )

    external_id = str(
        item.get("id")
        or item.get("finding_id")
        or item.get("findingId")
        or item.get("uid")
        or (cves[0] if cves else "")
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"NetRise finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["netrise", "edr", "endpoint-edr"],
    }


def host_bucket_key(item):
    """Pick a stable bucket key for a NetRise device / finding record."""
    if not isinstance(item, dict):
        return "__unknown__"
    for key in ("device_id", "deviceId", "id", "Id"):
        v = item.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    for key in ("device_name", "deviceName", "name"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "__unknown__"


def host_ip(item):
    """Pick the host IP from a NetRise device / finding record.

    NetRise devices may carry no IP at all (a firmware image
    extracted off the bench has no online presence). We fall back to
    synthetic ``0.0.0.0`` so the host record still lands in Faraday.
    """
    if not isinstance(item, dict):
        return "0.0.0.0"
    for key in (
        "ip",
        "ipAddress",
        "ip_address",
        "management_ip",
        "mgmt_ip",
        "mgmtIp",
        "device_ip",
        "deviceIp",
        "external_ip",
        "externalIp",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1"):
            return v.strip()
    # Some firmware records expose an ip array (multi-NIC gear).
    for key in ("ips", "ip_addresses"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip() and entry.strip() not in ("0.0.0.0", "127.0.0.1"):
                    return entry.strip()
    return "0.0.0.0"


def host_mac(item):
    if not isinstance(item, dict):
        return ""
    for key in ("mac_address", "macAddress", "mac"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def build_host(bucket_key, sample_finding, sample_device, vulns):
    """Build a Faraday host record for the supplied device bucket."""
    sample = sample_device or sample_finding
    label = device_label(sample) if sample else ""
    hostname = ""
    if label:
        hostname = label
    elif bucket_key and bucket_key != "__unknown__":
        hostname = bucket_key

    ip = host_ip(sample_device) if sample_device else (host_ip(sample_finding) if sample_finding else "0.0.0.0")
    mac = host_mac(sample_device) if sample_device else (host_mac(sample_finding) if sample_finding else "")
    os_str = device_os(sample_device) if sample_device else (device_os(sample_finding) if sample_finding else "")

    desc_parts = []
    if bucket_key and bucket_key != "__unknown__":
        desc_parts.append(f"device_id={bucket_key}")

    if isinstance(sample_device, dict):
        for label_key, key in (
            ("device_name", "name"),
            ("vendor", "vendor"),
            ("manufacturer", "manufacturer"),
            ("model", "model"),
            ("product", "product"),
            ("device_type", "device_type"),
            ("device_group", "device_group"),
            ("group", "group"),
            ("firmware_version", "firmware_version"),
            ("fw_version", "fw_version"),
            ("serial_number", "serial_number"),
            ("asset_tag", "asset_tag"),
            ("platform", "platform"),
            ("architecture", "architecture"),
            ("site", "site"),
            ("location", "location"),
            ("last_seen", "last_seen"),
            ("first_seen", "first_seen"),
        ):
            v = sample_device.get(key)
            if v not in (None, ""):
                desc_parts.append(f"{label_key}={v}")
    elif isinstance(sample_finding, dict):
        for label_key, key in (
            ("device_name", "device_name"),
            ("vendor", "vendor"),
            ("model", "model"),
            ("firmware_version", "firmware_version"),
        ):
            v = sample_finding.get(key)
            if v not in (None, ""):
                desc_parts.append(f"{label_key}={v}")

    if vulns:
        desc_parts.append(f"findings={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_pages(requests_module, url, headers, params_builder, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk a NetRise-paged ``{"data": [...], "meta": {...}}`` envelope.

    ``params_builder`` is a callable ``(page, limit) -> dict`` that builds
    each GET query-param dict. We page until either a short page comes
    back or ``meta.total`` is exhausted.
    """
    out = []
    page = 1
    seen = 0
    pages_walked = 0
    while pages_walked < max_pages:
        params = params_builder(page, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("NetRise request rejected (401). Check NETRISE_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("NetRise request rejected (403). Check the token's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"NetRise request 404 for {url} — endpoint not found")
            return out
        if resp.status_code >= 400:
            log(f"NetRise request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"NetRise response was not JSON ({url})")
            return out
        results = extract_items(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        seen += len(results)
        if len(results) < page_size:
            break
        total = extract_meta_total(payload)
        if isinstance(total, int) and seen >= total:
            break
        page += 1
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    device_group = validate_device_group(env("EXECUTOR_CONFIG_NETRISE_DEVICE_GROUP"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_NETRISE_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = env("NETRISE_HOST", required=True)
    token = env("NETRISE_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    devices_url = build_devices_url(host)
    vulns_url = build_vulns_url(host)

    devices = fetch_pages(
        requests,
        devices_url,
        headers,
        lambda page, limit: build_devices_params(device_group, page, limit),
    )

    # Re-apply the device-group filter client-side so legacy stacks
    # that ignore the query param still bucket correctly.
    if device_group:
        kept = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            dg = device.get("device_group") or device.get("group") or device.get("deviceGroup")
            if isinstance(dg, str) and dg.strip().lower() == device_group.strip().lower():
                kept.append(device)
            elif isinstance(dg, dict):
                name = dg.get("name") or dg.get("id") or dg.get("value")
                if isinstance(name, str) and name.strip().lower() == device_group.strip().lower():
                    kept.append(device)
        # Only narrow the catalogue if the server-side filter actually
        # tagged the device records with a recognisable group field.
        # If no device exposes a device_group string we trust the
        # server-side filter and pass the full catalogue through.
        if kept:
            devices = kept

    device_lookup = {}
    for device in devices:
        if not isinstance(device, dict):
            continue
        did = device.get("id") or device.get("Id") or device.get("device_id")
        if did is not None:
            device_lookup[str(did)] = device

    # Walk firmware vulnerabilities per device so each finding is
    # cleanly anchored to its source firmware image. When no devices
    # came back from the catalogue (e.g. NETRISE_DEVICE_GROUP filtered
    # everything out) we fall back to a single global vulnerability
    # pull so the run still surfaces every finding the operator can
    # read.
    findings = []
    if device_lookup:
        for did in device_lookup:
            findings.extend(
                fetch_pages(
                    requests,
                    vulns_url,
                    headers,
                    lambda page, limit, _did=did: build_vulns_params(_did, page, limit),
                )
            )
    else:
        findings = fetch_pages(
            requests,
            vulns_url,
            headers,
            lambda page, limit: build_vulns_params(None, page, limit),
        )

    log(
        f"Processing {len(findings)} NetRise findings + {len(devices)} devices "
        f"(device_group={device_group or 'ALL'}, min_severity={min_severity})"
    )

    buckets = {}
    sample_findings = {}
    for finding in findings:
        key = host_bucket_key(finding)
        buckets.setdefault(key, []).append(finding)
        sample_findings.setdefault(key, finding)

    # Devices with no findings still surface as inventory hosts so
    # the Faraday workspace mirrors the full firmware inventory.
    for did in device_lookup:
        buckets.setdefault(did, [])
        sample_findings.setdefault(did, None)

    hosts = []
    for key, finding_items in buckets.items():
        vulns = []
        for finding in finding_items:
            built = build_vulnerability(finding, device_lookup=device_lookup)
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        sample_finding = sample_findings.get(key)
        sample_device = device_lookup.get(key) if key != "__unknown__" else None
        hosts.append(build_host(key, sample_finding, sample_device, vulns))

    params_bits = [f"min_severity={min_severity}"]
    if device_group:
        params_bits.append(f"device_group={device_group}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "netrise",
            "command": "netrise",
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
