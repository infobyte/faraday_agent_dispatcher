#!/usr/bin/env python
"""Ivanti Security Controls (iSec) patch-management REST importer.

Pulls the scan metadata record (machine group + scan template + start
time + machine count) and the missing-patch catalogue from an iSec
console and emits Faraday bulk-create JSON to stdout.  Each scanned
machine becomes one Faraday host (keyed by the iSec machine record —
hostname / IP / OS string carried verbatim from the iSec ``machines``
list when present); each missing patch on that machine attaches as a
Faraday vulnerability with the engine prefix ``[PATCH-MGMT]``.

Endpoints used:
  GET <ISEC_HOST>/api/scans
      -> paginated scan list (used when ``ISEC_SCAN_ID`` is not set —
      most recent scan in the optional ``ISEC_MACHINE_GROUP`` filter is
      picked).  Pagination is ``page`` + ``count`` cursor.
  GET <ISEC_HOST>/api/scans/{scan_id}
      -> scan metadata record (machine group + template + start time +
      machine count + status).  Used to build the per-machine host
      record's ``host.description`` enrichment.
  GET <ISEC_HOST>/api/scans/{scan_id}/missingPatches
      -> paginated missing-patch catalogue keyed by ``machineId`` /
      ``machineName`` / ``ip`` plus the patch metadata (``bulletinId``
      / ``kbId`` / ``cveIds`` / ``severity`` / ``releaseDate``).
      Pagination is ``page`` + ``count`` cursor with ``links.next``
      exhaustion detection.

Auth: iSec issues per-tenant API keys carried as ``Authorization:
AppKey <ISEC_API_KEY>`` on every ``/api/`` call.  ``ISEC_API_KEY`` is
the key created in the iSec console under ``Tools -> Options -> REST
API``.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# iSec KB ids on missing-patch entries — ``KB1234567`` (digits, 4-10).
KB_RE = re.compile(r"\bKB\s?\d{4,10}\b", re.IGNORECASE)
# iSec host validation — accept http(s)://host[:port], strip trailing
# slash.  Control chars (newline / tab / null / etc) rejected outright
# so a header-injection attempt can't sneak through.  Anchored with
# \A/\Z (not ^/$) so a trailing newline cannot sneak through —
# Python's default ``$`` matches just before a trailing ``\n``.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")
# iSec scan id validation — iSec exposes scans as positive integer ids
# (typical) or short alphanumeric uuids on some builds.  Accept either
# shape: alphanumeric + ``-_.`` up to 64 chars.  Anchored with \A/\Z.
SCAN_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\-]{0,63}\Z")
# iSec machine group ids/names are user-defined strings — typically
# friendly names like "Workstations" / "Servers" / "DC Tier-1".
# Accept alphanumeric + spaces + ``._-`` up to 128 chars.
MACHINE_GROUP_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\- ]{0,127}\Z")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# iSec surfaces ``severity`` on missing-patch records as a freeform
# string enum (critical / important / moderate / low / unspecified)
# plus a numeric ``cvssScore`` 0-10.  The string enum buckets onto
# Faraday tiers; numeric bucketing is used as a fallback when the
# string is missing or unrecognised.
ISEC_STRING_SEVERITY = {
    "critical": "critical",
    "severe": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "unspecified": "info",
    "none": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# iSec missing-patch lifecycle is exposed through ``status`` /
# ``state`` / ``patchStatus``.  iSec missingPatches endpoint, by
# definition, only returns patches that are missing (state = open) but
# the field is normalised here so re-emitted shapes from federated
# stacks don't surprise us.
ISEC_STATUS_BY_STATE = {
    "missing": "open",
    "open": "open",
    "pending": "open",
    "new": "open",
    "detected": "open",
    "applicable": "open",
    "scheduled": "open",
    "in_progress": "open",
    "inprogress": "open",
    "installing": "open",
    "downloading": "open",
    "reboot_pending": "open",
    "rebootpending": "open",
    "installed": "closed",
    "applied": "closed",
    "succeeded": "closed",
    "success": "closed",
    "fixed": "closed",
    "patched": "closed",
    "resolved": "closed",
    "mitigated": "closed",
    "closed": "closed",
    "completed": "closed",
    "superseded": "closed",
    "not_applicable": "closed",
    "notapplicable": "closed",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "deferred": "risk-accepted",
    "excluded": "risk-accepted",
    "waived": "risk-accepted",
    "accepted": "risk-accepted",
    "acknowledged": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "will_not_install": "risk-accepted",
    "willnotinstall": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "failed": "open",
}


def log(msg):
    print(f"{datetime.utcnow()} - iSec: {msg}", file=sys.stderr, flush=True)


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


def severity_from_cvss(score):
    """Bucket a numeric severity (0-10 CVSS-style) onto a Faraday tier."""
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


def severity_from_isec(value, numeric=None):
    """Map an iSec severity string onto a Faraday bucket.

    Accepts the freeform string enum (critical / important / moderate
    / low / unspecified), Faraday-side synonyms (severe / high /
    medium / minor / informational), numeric inputs (0-10 CVSS-style),
    numeric strings, and falls back to numeric bucketing on
    ``numeric`` when the primary value is missing or unrecognised.
    """
    if isinstance(value, bool):
        if numeric is not None:
            return severity_from_cvss(numeric)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        if text in ISEC_STRING_SEVERITY:
            return ISEC_STRING_SEVERITY[text]
        squashed = text.replace("_", "")
        if squashed in ISEC_STRING_SEVERITY:
            return ISEC_STRING_SEVERITY[squashed]
        try:
            return severity_from_cvss(float(value.strip()))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def status_from_isec(item):
    """Derive Faraday status from an iSec missing-patch payload."""
    if not isinstance(item, dict):
        return "open"
    for key in (
        "status",
        "state",
        "patchStatus",
        "patch_status",
        "deploymentStatus",
        "deployment_status",
        "installStatus",
        "install_status",
        "Status",
        "State",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in ISEC_STATUS_BY_STATE:
                return ISEC_STATUS_BY_STATE[compact]
            if squashed in ISEC_STATUS_BY_STATE:
                return ISEC_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in ISEC_STATUS_BY_STATE:
                        return ISEC_STATUS_BY_STATE[compact]
                    if squashed in ISEC_STATUS_BY_STATE:
                        return ISEC_STATUS_BY_STATE[squashed]
    return "open"


def validate_min_severity(value):
    """Validate ISEC_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus iSec-side synonyms
    (severe -> critical, important -> high, moderate / warning ->
    medium, minor -> low, informational / information / unspecified
    -> info) plus numeric-string input bucketed via severity_from_cvss.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "info"
    bucket = ISEC_STRING_SEVERITY.get(text)
    if bucket is None:
        bucket = ISEC_STRING_SEVERITY.get(text.replace("_", ""))
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(str(value).strip()))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"ISEC_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_scan_id(value):
    """Validate ISEC_SCAN_ID.

    None / blank -> None (optional — caller decides if at least one of
    SCAN_ID / MACHINE_GROUP is required).  iSec scan ids are typically
    positive integers but some builds expose short alphanumeric uuids
    — accept either shape up to 64 chars (alnum + ``._-``) so a typo
    or control char can't fan out into ``/api/scans/None`` calls.
    """
    if value is None or value == "":
        return None
    raw = str(value)
    # Reject any control char on the *raw* value before .strip() runs —
    # .strip() would otherwise eat trailing newlines so a typo ending
    # in \n / \r could sneak through SCAN_ID_RE.
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("ISEC_SCAN_ID contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return None
    if not SCAN_ID_RE.match(text):
        log(f"ISEC_SCAN_ID '{text}' is not a valid identifier " "(alphanumeric + ._- up to 64 chars)")
        sys.exit(1)
    return text


def validate_machine_group(value):
    """Validate ISEC_MACHINE_GROUP.

    None / blank -> None (optional — caller decides if at least one of
    SCAN_ID / MACHINE_GROUP is required).  Machine group names in iSec
    are user-defined strings — typically friendly names like
    ``Workstations`` / ``Servers`` / ``DC Tier-1``.  Accept alphanumeric
    + spaces + ``._-`` up to 128 chars.  Control chars rejected.
    """
    if value is None or value == "":
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("ISEC_MACHINE_GROUP contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return None
    if not MACHINE_GROUP_RE.match(text):
        log(f"ISEC_MACHINE_GROUP '{text}' is not a valid name " "(alphanumeric + spaces + ._- up to 128 chars)")
        sys.exit(1)
    return text


def validate_host(value):
    """Validate ISEC_HOST.

    None / blank -> sys.exit(1).  Must be ``http(s)://host[:port]``;
    trailing slash stripped client-side.  Control chars rejected so a
    header-injection attempt can't sneak through.
    """
    if value is None or value == "":
        log("ISEC_HOST is required")
        sys.exit(1)
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("ISEC_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("ISEC_HOST is required")
        sys.exit(1)
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"ISEC_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(api_key):
    """iSec expects ``Authorization: AppKey <ISEC_API_KEY>``."""
    return {
        "Authorization": f"AppKey {api_key or ''}",
        "Accept": "application/json",
    }


def build_scans_url(host):
    return f"{host}/api/scans"


def build_scan_url(host, scan_id):
    return f"{host}/api/scans/{scan_id}"


def build_missing_patches_url(host, scan_id):
    return f"{host}/api/scans/{scan_id}/missingPatches"


def build_scans_params(machine_group, page, count):
    """Build query params for the iSec scans list endpoint."""
    params = {"page": int(page), "count": int(count)}
    if machine_group:
        params["machineGroup"] = machine_group
    return params


def build_patches_params(page, count):
    """Build query params for the iSec missing-patches endpoint."""
    return {"page": int(page), "count": int(count)}


def extract_results(body):
    """Pull the result list out of an iSec pagination envelope.

    iSec uses ``{"value": [...], "total": N}`` on /api/ routes (OData
    style) — accept ``data`` / ``items`` / ``results`` / ``scans`` /
    ``missingPatches`` / ``patches`` as alt-keys for federated stacks.
    """
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for key in (
        "value",
        "results",
        "data",
        "items",
        "scans",
        "missingPatches",
        "missing_patches",
        "patches",
        "entries",
    ):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_count(body):
    """Pull the total record count from an iSec envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("total", "count", "total_count", "totalCount", "@odata.count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def extract_next_link(body):
    """Pull the ``links.next`` URL from an iSec envelope (None if exhausted)."""
    if not isinstance(body, dict):
        return None
    for key in ("nextLink", "next_link", "@odata.nextLink"):
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    links = body.get("links")
    if isinstance(links, dict):
        nxt = links.get("next")
        if isinstance(nxt, str) and nxt.strip():
            return nxt.strip()
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


def collect_cves(item):
    """Walk an iSec missing-patch payload for CVE-* ids."""
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
    for key in ("cves", "cveIds", "cve_ids"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    for key in (
        "description",
        "summary",
        "name",
        "title",
        "patchDescription",
        "patch_description",
        "bulletinSummary",
        "bulletin_summary",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
    return found


def collect_kb_ids(item):
    """Walk an iSec missing-patch payload for Microsoft KB ids.

    KB ids are iSec's primary advisory reference on Microsoft patches —
    typically 7-digit numeric ``KBnnnnnnn``.  Returned as the bare
    numeric id (without the ``KB`` prefix) so the caller can format
    them as ``KB1234567`` in the refs.
    """
    found = []
    seen = set()

    def add(num):
        if not num:
            return
        s = str(num).strip().upper()
        # Strip a leading "KB" prefix if present.
        if s.startswith("KB"):
            s = s[2:].lstrip()
        if not s.isdigit() or not (4 <= len(s) <= 10):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    def scan(text):
        if not isinstance(text, str):
            return
        for m in KB_RE.findall(text):
            add(m.replace(" ", ""))

    if not isinstance(item, dict):
        return found

    for key in ("kb", "kbId", "kb_id", "kbNumber", "kb_number"):
        v = item.get(key)
        if isinstance(v, (int, str)):
            add(v)
    for key in ("kbIds", "kb_ids", "kbs"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, (int, str)):
                    add(entry)

    for key in (
        "description",
        "summary",
        "name",
        "title",
        "bulletinId",
        "bulletin_id",
        "patchName",
        "patch_name",
    ):
        v = item.get(key)
        if isinstance(v, str):
            scan(v)
    return found


def collect_refs(item):
    """Walk an iSec missing-patch payload for advisory URLs and iSec pivots."""
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

    bulletin_id = (
        item.get("bulletinId") or item.get("bulletin_id") or item.get("bulletin") or item.get("vendorBulletinId")
    )
    if bulletin_id is not None:
        s = str(bulletin_id).strip()
        if s:
            add(f"iSec-Bulletin: {s}")

    patch_id = item.get("patchId") or item.get("patch_id") or item.get("id")
    if patch_id is not None:
        s = str(patch_id).strip()
        if s:
            add(f"iSec-Patch: {s}")

    vendor = item.get("vendor") or item.get("vendorName") or item.get("publisher")
    if isinstance(vendor, str) and vendor.strip():
        add(f"iSec-Vendor: {vendor.strip()}")

    product = item.get("product") or item.get("productName") or item.get("product_name") or item.get("application")
    if isinstance(product, str) and product.strip():
        add(f"iSec-Product: {product.strip()}")

    family = item.get("family") or item.get("productFamily") or item.get("product_family")
    if isinstance(family, str) and family.strip():
        add(f"iSec-Family: {family.strip()}")

    classification = item.get("classification") or item.get("patchType") or item.get("patch_type") or item.get("type")
    if isinstance(classification, str) and classification.strip():
        add(f"iSec-Classification: {classification.strip()}")

    machine = item.get("machineName") or item.get("machine_name") or item.get("hostname") or item.get("computerName")
    if isinstance(machine, str) and machine.strip():
        add(f"iSec-Machine: {machine.strip()}")
    elif isinstance(machine, dict):
        label = machine.get("name") or machine.get("hostname")
        if isinstance(label, str) and label.strip():
            add(f"iSec-Machine: {label.strip()}")

    for key in ("references", "links", "advisoryUrls", "advisory_urls", "kbUrls"):
        entry = item.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("link") or it.get("help_text") or it.get("name")
                    if href:
                        add(href)
                elif isinstance(it, str):
                    add(it)
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def patch_label(item):
    """Build the leading title fragment for an iSec missing-patch finding."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "title",
        "patchName",
        "patch_name",
        "name",
        "displayName",
        "display_name",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("bulletinId", "bulletin_id", "bulletin"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("kbId", "kb_id", "kbNumber"):
        v = item.get(key)
        if isinstance(v, (str, int)) and str(v).strip():
            s = str(v).strip()
            return s if s.upper().startswith("KB") else f"KB{s}"
    for key in ("summary", "description"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "Missing patch"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from an iSec missing-patch record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    for key in ("cvssScore", "cvss_score", "cvss", "score", "riskScore", "risk_score"):
        raw_numeric = item.get(key)
        if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
            severity_numeric = float(raw_numeric)
            break
        if isinstance(raw_numeric, str) and raw_numeric.strip():
            try:
                severity_numeric = float(raw_numeric.strip())
                break
            except ValueError:
                continue

    severity_string = (
        item.get("severity")
        or item.get("severityLabel")
        or item.get("severity_label")
        or item.get("severityName")
        or item.get("severity_name")
        or item.get("risk_level")
        or item.get("riskLevel")
    )
    severity = severity_from_isec(severity_string, severity_numeric)
    status = status_from_isec(item)

    label = patch_label(item)
    if label and label != "Missing patch":
        name = f"[PATCH-MGMT] Missing patch: {label}"
    else:
        name = "[PATCH-MGMT] Missing patch"

    desc_parts = []
    description = (
        item.get("description")
        or item.get("Description")
        or item.get("patchDescription")
        or item.get("patch_description")
        or item.get("bulletinSummary")
        or item.get("bulletin_summary")
    )
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("patch_id", "patchId"),
        ("bulletin_id", "bulletinId"),
        ("kb_id", "kbId"),
        ("vendor", "vendor"),
        ("product", "product"),
        ("family", "family"),
        ("classification", "classification"),
        ("severity", "severity"),
        ("cvss_score", "cvssScore"),
        ("release_date", "releaseDate"),
        ("first_detected", "firstDetected"),
        ("last_detected", "lastDetected"),
        ("status", "status"),
        ("machine_id", "machineId"),
        ("machine_name", "machineName"),
        ("machine_ip", "machineIp"),
        ("machine_group", "machineGroup"),
        ("scan_id", "scanId"),
        ("reboot_required", "rebootRequired"),
        ("supersededBy", "supersededBy"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if severity_numeric is not None:
        desc_parts.append(f"severity_score: {severity_numeric}")

    cves = collect_cves(item)
    kb_ids = collect_kb_ids(item)
    refs = collect_refs(item)
    for kb in kb_ids:
        ref_name = f"KB: KB{kb}"
        if ref_name not in {r.get("name") for r in refs}:
            refs.append({"name": ref_name, "type": "other"})
        url_name = f"https://support.microsoft.com/help/{kb}"
        if url_name not in {r.get("name") for r in refs}:
            refs.append({"name": url_name, "type": "other"})

    resolution = ""
    remediations = item.get("remediation") or item.get("resolution") or item.get("recommendation")
    if isinstance(remediations, list):
        bits = []
        for r in remediations:
            if isinstance(r, dict):
                txt = r.get("help_text") or r.get("description") or r.get("name") or r.get("solution")
                if isinstance(txt, str) and txt.strip():
                    bits.append(txt.strip())
            elif isinstance(r, str) and r.strip():
                bits.append(r.strip())
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(remediations, str) and remediations.strip():
        resolution = remediations.strip()
    if not resolution:
        kb_hint = ""
        if kb_ids:
            kb_hint = f" Apply KB{', KB'.join(kb_ids[:5])}."
        resolution = (
            "Deploy the missing patch through the Ivanti Security "
            "Controls console (Patch -> Missing -> select the patch "
            "-> Deploy) targeting the affected machine group; or "
            "accept the risk via the iSec ignore-list / exception "
            "workflow if the patch cannot be applied."
            f"{kb_hint}"
        )

    external_id = str(
        item.get("patchId")
        or item.get("patch_id")
        or item.get("id")
        or item.get("bulletinId")
        or item.get("bulletin_id")
        or (f"KB{kb_ids[0]}" if kb_ids else "")
        or (cves[0] if cves else "")
    )

    return {
        "name": str(name).strip()[:200] or f"Missing patch {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["ivanti", "patch-management", "ivanti-security-controls", "missing-patch"],
    }


def machine_hostname(machine, fallback):
    """Pick the canonical hostname for an iSec machine record."""
    if isinstance(machine, dict):
        for key in (
            "machineName",
            "machine_name",
            "hostname",
            "name",
            "computerName",
            "computer_name",
            "fqdn",
        ):
            v = machine.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return ""


def machine_ip(machine):
    """Pick an IP address for the iSec machine record."""
    if not isinstance(machine, dict):
        return "0.0.0.0"
    for key in (
        "ip",
        "ipAddress",
        "ip_address",
        "machineIp",
        "machine_ip",
        "primaryIp",
        "primary_ip",
    ):
        v = machine.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "0.0.0.0"


def machine_mac(machine):
    """Pick a MAC address for the iSec machine record."""
    if not isinstance(machine, dict):
        return ""
    for key in ("mac", "macAddress", "mac_address"):
        v = machine.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def machine_os(machine):
    """Build the host.os string from an iSec machine record."""
    if not isinstance(machine, dict):
        return "unknown"
    os_obj = machine.get("operatingSystem") or machine.get("operating_system")
    if isinstance(os_obj, dict):
        for key in ("name", "displayName", "version"):
            v = os_obj.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    for key in (
        "operatingSystem",
        "operating_system",
        "os",
        "osName",
        "os_name",
        "osVersion",
        "os_version",
        "platform",
    ):
        v = machine.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "unknown"


def build_host(machine_key, machine, vulns, scan_meta=None):
    """Build a Faraday host record for an iSec-scanned machine."""
    if not isinstance(machine, dict):
        machine = {}
    if not isinstance(scan_meta, dict):
        scan_meta = {}
    hostname = machine_hostname(machine, machine_key)
    os_str = machine_os(machine)
    ip = machine_ip(machine)
    mac = machine_mac(machine)

    desc_parts = []
    if machine_key:
        desc_parts.append(f"machine_key={machine_key}")
    for label_key, key in (
        ("machine_id", "machineId"),
        ("hostname", "machineName"),
        ("ip", "ip"),
        ("mac", "mac"),
        ("os", "operatingSystem"),
        ("domain", "domain"),
        ("machine_group", "machineGroup"),
        ("last_scan", "lastScan"),
        ("status", "status"),
    ):
        v = machine.get(key)
        if v in (None, "") or isinstance(v, (dict, list)):
            continue
        desc_parts.append(f"{label_key}={v}")

    for label_key, key in (
        ("scan_id", "id"),
        ("scan_id", "scanId"),
        ("scan_name", "name"),
        ("scan_template", "scanTemplate"),
        ("scan_status", "status"),
        ("scan_started", "startTime"),
        ("scan_finished", "endTime"),
    ):
        v = scan_meta.get(key)
        if v in (None, "") or isinstance(v, (dict, list)):
            continue
        token = f"{label_key}={v}"
        if token not in desc_parts:
            desc_parts.append(token)

    if vulns:
        desc_parts.append(f"missing_patches={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_scan(requests_module, host, scan_id, headers):
    """GET the iSec scan metadata record."""
    url = build_scan_url(host, scan_id)
    try:
        resp = requests_module.get(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return {}
    if resp.status_code == 401:
        log("iSec request rejected (401). Check ISEC_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log("iSec request rejected (403). Check the key's role / scope.")
        return {}
    if resp.status_code == 404:
        log(f"iSec scan {scan_id} not found (404).")
        return {}
    if resp.status_code >= 400:
        log(f"iSec request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return {}
    try:
        payload = resp.json()
    except ValueError:
        log(f"iSec response was not JSON ({url})")
        return {}
    if isinstance(payload, dict):
        inner = payload.get("value") if "value" in payload else payload.get("data")
        if isinstance(inner, dict):
            return inner
        return payload
    return {}


def fetch_scans(requests_module, host, machine_group, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk the iSec scans list via page / count pagination."""
    out = []
    url = build_scans_url(host)
    page = 1
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_scans_params(machine_group, page, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("iSec request rejected (401). Check ISEC_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("iSec request rejected (403). Check the key's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"iSec scans endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"iSec scans request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"iSec scans response was not JSON ({url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < page_size:
            break
        total = extract_count(payload)
        if isinstance(total, int) and len(out) >= total:
            break
        if not extract_next_link(payload):
            if total is None:
                break
        page += 1
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping scan-list pagination")
    return out


def fetch_missing_patches(requests_module, host, scan_id, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk the iSec missing-patches catalogue for ``scan_id`` via page/count."""
    out = []
    url = build_missing_patches_url(host, scan_id)
    page = 1
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_patches_params(page, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("iSec request rejected (401). Check ISEC_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log("iSec request rejected (403). Check the key's role / scope.")
            return out
        if resp.status_code == 404:
            log(f"iSec missing-patches endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"iSec missing-patches request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"iSec missing-patches response was not JSON ({url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < page_size:
            break
        total = extract_count(payload)
        if isinstance(total, int) and len(out) >= total:
            break
        if not extract_next_link(payload):
            if total is None:
                break
        page += 1
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def pick_scan_id(scans, machine_group):
    """Pick the most recent scan for the optional ``machine_group`` filter.

    iSec scans returned by /api/scans usually carry a ``startTime`` /
    ``startedAt`` timestamp — pick the most recent.  If the machine
    group is set, prefer scans whose ``machineGroup`` matches (case
    insensitive); fall back to the most recent overall scan if no
    machine-group match is found.
    """
    if not isinstance(scans, list) or not scans:
        return None, None

    def started(entry):
        for k in ("startTime", "start_time", "startedAt", "started_at", "createdAt", "created_at"):
            v = entry.get(k) if isinstance(entry, dict) else None
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    if machine_group:
        mg_norm = machine_group.strip().lower()
        scoped = [
            s
            for s in scans
            if isinstance(s, dict)
            and isinstance(s.get("machineGroup") or s.get("machine_group"), str)
            and (s.get("machineGroup") or s.get("machine_group")).strip().lower() == mg_norm
        ]
        if scoped:
            scoped.sort(key=started, reverse=True)
            picked = scoped[0]
            return str(picked.get("id") or picked.get("scanId") or "").strip() or None, picked

    scans_sorted = sorted([s for s in scans if isinstance(s, dict)], key=started, reverse=True)
    if not scans_sorted:
        return None, None
    picked = scans_sorted[0]
    return str(picked.get("id") or picked.get("scanId") or "").strip() or None, picked


def machine_key_for(patch):
    """Pick the machine grouping key for a missing-patch entry."""
    if not isinstance(patch, dict):
        return ""
    for key in ("machineId", "machine_id", "machineName", "machine_name", "hostname", "ip"):
        v = patch.get(key)
        if isinstance(v, (str, int)) and str(v).strip():
            return str(v).strip()
    machine = patch.get("machine")
    if isinstance(machine, dict):
        for key in ("id", "machineId", "name", "hostname", "ip"):
            v = machine.get(key)
            if isinstance(v, (str, int)) and str(v).strip():
                return str(v).strip()
    return ""


def extract_machine_record(patch):
    """Pull the embedded machine sub-record out of a missing-patch entry."""
    if not isinstance(patch, dict):
        return {}
    machine = patch.get("machine")
    if isinstance(machine, dict):
        return machine
    # Some iSec builds inline the machine fields directly on the patch.
    record = {}
    for k in (
        "machineId",
        "machineName",
        "machineIp",
        "machineGroup",
        "ip",
        "ipAddress",
        "hostname",
        "mac",
        "operatingSystem",
        "domain",
        "lastScan",
    ):
        v = patch.get(k)
        if v not in (None, ""):
            record[k] = v
    return record


def main():
    started = time.time()

    scan_id = validate_scan_id(env("EXECUTOR_CONFIG_ISEC_SCAN_ID"))
    machine_group = validate_machine_group(env("EXECUTOR_CONFIG_ISEC_MACHINE_GROUP"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_ISEC_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    if not scan_id and not machine_group:
        log("at least one of ISEC_SCAN_ID / ISEC_MACHINE_GROUP must be set")
        sys.exit(1)

    host = validate_host(env("ISEC_HOST", required=True))
    api_key = env("ISEC_API_KEY", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(api_key)

    scan_meta = {}
    if scan_id:
        scan_meta = fetch_scan(requests, host, scan_id, headers)
    else:
        scans = fetch_scans(requests, host, machine_group, headers)
        scan_id, scan_meta = pick_scan_id(scans, machine_group)
        if not scan_id:
            log(f"no scans found for machine group '{machine_group}' " "via /api/scans")
            scan_meta = scan_meta or {}

    patches = []
    if scan_id:
        patches = fetch_missing_patches(requests, host, scan_id, headers)

    log(
        f"Processing {len(patches)} iSec missing patches for scan "
        f"{scan_id or '<none>'} (machine_group={machine_group or '<all>'}, "
        f"min_severity={min_severity})"
    )

    # If a machine group is set but the picked scan's machineGroup
    # column doesn't match, the iSec server-side filter has already
    # done the work — we don't re-filter client-side because the
    # missingPatches endpoint is scan-scoped, not group-scoped.
    by_machine = {}
    for patch in patches:
        built = build_vulnerability(patch)
        if built is None:
            continue
        if allowed_severities and built["severity"] not in allowed_severities:
            continue
        key = machine_key_for(patch) or "unknown"
        entry = by_machine.setdefault(key, {"machine": extract_machine_record(patch), "vulns": []})
        entry["vulns"].append(built)

    hosts = []
    for key, entry in by_machine.items():
        hosts.append(build_host(key, entry["machine"], entry["vulns"], scan_meta))

    if not hosts:
        # Still emit a synthetic placeholder host so the Faraday
        # workspace records that the iSec scan was processed even
        # when zero matching missing patches came back.
        hosts.append(
            build_host(
                machine_group or scan_id or "isec",
                {"machineName": machine_group or "isec"},
                [],
                scan_meta,
            )
        )

    params_bits = []
    if scan_id:
        params_bits.append(f"scan_id={scan_id}")
    if machine_group:
        params_bits.append(f"machine_group={machine_group}")
    params_bits.append(f"min_severity={min_severity}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "ivanti_security_controls",
            "command": "ivanti_security_controls",
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
