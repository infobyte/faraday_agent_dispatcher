#!/usr/bin/env python
"""Red Hat Satellite patch-management REST importer.

Pulls the host catalogue (one Foreman/Satellite-managed asset per row)
and the per-host applicable errata (RHSA / RHBA / RHEA advisories) from
a Red Hat Satellite console and emits Faraday bulk-create JSON to
stdout.  Each Satellite-managed host becomes one Faraday host (keyed
by the Foreman host record -- hostname / IP / MAC / OS string /
organization / host-collection memberships); each applicable erratum
attaches as a Faraday vulnerability with the engine prefix
``[PATCH-MGMT]``.

Endpoints used:
  GET <SATELLITE_HOST>/api/hosts
      -> paginated Foreman host list (optionally scoped by
      ``organization_id`` and / or by a host-collection name passed
      through the Foreman search-query syntax
      ``host_collection = "<name>"``).  Pagination is ``page`` +
      ``per_page`` cursor (Foreman canonical).
  GET <SATELLITE_HOST>/api/hosts/{host_id}/errata
      -> paginated applicable-errata catalogue keyed by ``errata_id``
      (RHSA-2024:1234 / RHBA-... / RHEA-...) plus the advisory
      metadata (``type`` security/bugfix/enhancement, ``severity``
      Low / Moderate / Important / Critical, ``issued`` / ``updated``,
      ``cves``, ``packages``, ``description``, ``solution``).  Same
      ``page`` + ``per_page`` cursor.

Auth: Red Hat Satellite uses HTTP Basic with the SATELLITE_USER /
SATELLITE_PASSWORD credentials (typically a service account scoped to
``view_hosts`` + ``view_errata``).  Carried on every ``/api/`` call
together with ``Accept: application/json``.
"""

import base64
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Satellite host validation -- accept http(s)://host[:port], strip
# trailing slash.  Control chars (newline / tab / null / etc) rejected
# outright so a header-injection attempt can't sneak through.
# Anchored with \A/\Z (not ^/$) so a trailing newline cannot sneak
# through -- Python's default ``$`` matches just before a trailing
# ``\n``.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")
# Satellite organisation ids are typically positive integers (Foreman
# uses numeric ids primarily) but the REST API also accepts string
# labels on some endpoints.  Accept alphanumeric + ``._-`` up to 64
# chars (covers both integer ids and short label strings) with
# ``\A``/``\Z`` anchors.
ORG_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\-]{0,63}\Z")
# Satellite host-collection names are user-defined strings -- typically
# friendly names like ``Production Servers`` / ``Web Tier`` /
# ``DC-1``.  Accept alphanumeric + spaces + ``._-`` up to 128 chars.
HOST_COLLECTION_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\- ]{0,127}\Z")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# Satellite surfaces errata ``severity`` as a Red Hat freeform string
# enum: Critical / Important / Moderate / Low for security advisories
# and ``None`` (literal string) for bugfix / enhancement advisories.
# The string enum buckets onto Faraday tiers; numeric bucketing is
# used as a fallback when the string is missing or unrecognised.
SATELLITE_STRING_SEVERITY = {
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

# Erratum type defaults the severity bucket for non-security advisories
# (bugfix / enhancement carry severity="None" in Satellite, so the type
# is used to bucket them onto ``info`` / ``low`` rather than dropping
# them on the floor).
SATELLITE_TYPE_DEFAULT_SEVERITY = {
    "security": "medium",
    "bugfix": "info",
    "bug fix": "info",
    "enhancement": "info",
    "feature": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Satellite errata applicability lifecycle: the /api/hosts/{id}/errata
# endpoint returns applicable errata (i.e. open by definition).  Field
# is normalised here so re-emitted shapes don't surprise us.
SATELLITE_STATUS_BY_STATE = {
    "applicable": "open",
    "installable": "open",
    "needed": "open",
    "missing": "open",
    "open": "open",
    "pending": "open",
    "new": "open",
    "detected": "open",
    "applied": "closed",
    "installed": "closed",
    "succeeded": "closed",
    "success": "closed",
    "fixed": "closed",
    "patched": "closed",
    "resolved": "closed",
    "mitigated": "closed",
    "closed": "closed",
    "completed": "closed",
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
}


def log(msg):
    print(
        f"{datetime.utcnow()} - Satellite: {msg}",
        file=sys.stderr,
        flush=True,
    )


def env(name, required=False, default=None):
    value = os.getenv(name, default)
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


def _type_default_severity(errata_type):
    """Bucket an erratum type onto a default severity.

    Satellite security advisories that have no explicit severity
    string ("None" literal or absent) get bucketed to ``medium`` -- a
    sensible default given Red Hat publishes a security advisory only
    when the issue is real.  Bugfix / enhancement advisories default
    to ``info``.
    """
    if not isinstance(errata_type, str):
        return None
    t = errata_type.strip().lower().replace(" ", "_")
    if t in SATELLITE_TYPE_DEFAULT_SEVERITY:
        return SATELLITE_TYPE_DEFAULT_SEVERITY[t]
    squashed = t.replace("_", "")
    if squashed in SATELLITE_TYPE_DEFAULT_SEVERITY:
        return SATELLITE_TYPE_DEFAULT_SEVERITY[squashed]
    return None


def severity_from_satellite(value, numeric=None, errata_type=None):
    """Map a Satellite errata severity onto a Faraday bucket.

    Satellite errata carry ``severity`` as the Red Hat string enum
    (Critical / Important / Moderate / Low) for security advisories
    and ``None`` (literal string) for bugfix / enhancement.  Accepts
    Faraday-side synonyms (severe / high / medium / minor /
    informational), numeric inputs (0-10 CVSS-style), numeric strings,
    and falls back to numeric bucketing on ``numeric`` when the
    primary value is missing or unrecognised.

    ``errata_type`` is a secondary fallback for the ``None`` /
    ``none`` literal that Satellite emits on bugfix / enhancement
    advisories (and on security advisories that haven't been
    classified yet).  Security type defaults bucket to ``medium``;
    bugfix / enhancement bucket to ``info``.
    """
    if isinstance(value, bool):
        if numeric is not None:
            return severity_from_cvss(numeric)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        # Red Hat's "None" literal is a placeholder, not a real
        # severity bucket -- delegate to the erratum-type default so
        # security advisories carrying "None" still come through
        # as ``medium`` rather than being silently dropped to ``info``.
        if text in {"none", "unspecified", "unknown"}:
            t_default = _type_default_severity(errata_type)
            if t_default is not None:
                return t_default
            return "info"
        if text in SATELLITE_STRING_SEVERITY:
            return SATELLITE_STRING_SEVERITY[text]
        squashed = text.replace("_", "")
        if squashed in SATELLITE_STRING_SEVERITY:
            return SATELLITE_STRING_SEVERITY[squashed]
        try:
            return severity_from_cvss(float(value.strip()))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    # No explicit severity -- delegate to the erratum-type default
    # (security -> medium, bugfix / enhancement -> info).
    t_default = _type_default_severity(errata_type)
    if t_default is not None:
        return t_default
    return "info"


def status_from_satellite(item):
    """Derive Faraday status from a Satellite errata payload."""
    if not isinstance(item, dict):
        return "open"
    for key in (
        "status",
        "state",
        "errataStatus",
        "errata_status",
        "applicabilityStatus",
        "applicability_status",
        "installationStatus",
        "installation_status",
        "Status",
        "State",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in SATELLITE_STATUS_BY_STATE:
                return SATELLITE_STATUS_BY_STATE[compact]
            if squashed in SATELLITE_STATUS_BY_STATE:
                return SATELLITE_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in SATELLITE_STATUS_BY_STATE:
                        return SATELLITE_STATUS_BY_STATE[compact]
                    if squashed in SATELLITE_STATUS_BY_STATE:
                        return SATELLITE_STATUS_BY_STATE[squashed]
    # Foreman exposes ``installable`` as a bool -- True = applicable
    # (open).  Bool fallback only after the string keys.
    installable = item.get("installable")
    if isinstance(installable, bool):
        return "open" if installable else "closed"
    return "open"


def validate_min_severity(value):
    """Validate SATELLITE_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus Red Hat synonyms
    (severe -> critical, important -> high, moderate / warning ->
    medium, minor -> low, informational / information / unspecified
    / none -> info) plus numeric-string CVSS-style input bucketed via
    severity_from_cvss.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "info"
    bucket = SATELLITE_STRING_SEVERITY.get(text)
    if bucket is None:
        bucket = SATELLITE_STRING_SEVERITY.get(text.replace("_", ""))
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(str(value).strip()))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"SATELLITE_MIN_SEVERITY '{value}' not recognised; " "defaulting to 'info'")
        return "info"
    return bucket


def validate_org_id(value):
    """Validate SATELLITE_ORG_ID.

    None / blank -> None (optional -- caller can fan out across all
    orgs the credentials can see).  Foreman org ids are typically
    positive integers but the REST API also accepts string labels; we
    accept either shape up to 64 chars (alnum + ``._-``) so a typo or
    control char can't sneak into ``/api/organizations/None`` calls.
    """
    if value is None or value == "":
        return None
    raw = str(value)
    # Reject any control char on the *raw* value before .strip() runs
    # -- .strip() would otherwise eat trailing newlines so a typo
    # ending in \n / \r could sneak through ORG_ID_RE.
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("SATELLITE_ORG_ID contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return None
    if not ORG_ID_RE.match(text):
        log(f"SATELLITE_ORG_ID '{text}' is not a valid identifier " "(alphanumeric + ._- up to 64 chars)")
        sys.exit(1)
    return text


def validate_host_collection(value):
    """Validate SATELLITE_HOST_COLLECTION.

    None / blank -> None (optional -- caller decides whether to walk
    all hosts in the org).  Host collection names in Satellite are
    user-defined strings -- typically friendly names like
    ``Production Servers`` / ``Web Tier`` / ``DC-1``.  Accept
    alphanumeric + spaces + ``._-`` up to 128 chars.  Control chars
    rejected.
    """
    if value is None or value == "":
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("SATELLITE_HOST_COLLECTION contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return None
    if not HOST_COLLECTION_RE.match(text):
        log(f"SATELLITE_HOST_COLLECTION '{text}' is not a valid name " "(alphanumeric + spaces + ._- up to 128 chars)")
        sys.exit(1)
    return text


def validate_host(value):
    """Validate SATELLITE_HOST.

    None / blank -> sys.exit(1).  Must be ``http(s)://host[:port]``;
    trailing slash stripped client-side.  Control chars rejected so a
    header-injection attempt can't sneak through.
    """
    if value is None or value == "":
        log("SATELLITE_HOST is required")
        sys.exit(1)
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("SATELLITE_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("SATELLITE_HOST is required")
        sys.exit(1)
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"SATELLITE_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(user, password):
    """Satellite uses HTTP Basic auth -- header is built explicitly.

    Built explicitly (instead of relying on requests's ``auth=`` kwarg)
    so the function is testable without a live ``requests`` install
    and so the encoded credentials never leak into log output.
    """
    creds = f"{user or ''}:{password or ''}".encode("utf-8")
    token = base64.b64encode(creds).decode("ascii")
    return {
        "Authorization": f"Basic {token}",
        "Accept": "application/json",
    }


def build_hosts_url(host):
    return f"{host}/api/hosts"


def build_errata_url(host, host_id):
    return f"{host}/api/hosts/{host_id}/errata"


def build_hosts_params(org_id, host_collection, page, per_page):
    """Build query params for the Foreman /api/hosts list endpoint.

    Foreman's search syntax (``search``) takes a quoted scoper like
    ``host_collection = "Production Servers"`` for host-collection
    membership.  ``organization_id`` is a top-level numeric / label
    filter.
    """
    params = {"page": int(page), "per_page": int(per_page)}
    if org_id:
        params["organization_id"] = org_id
    if host_collection:
        # Escape any embedded double-quote so the search syntax stays
        # well-formed (Foreman uses ``"`` to delimit string literals).
        # Backslash-escape the embedded quote like Foreman does.
        escaped = host_collection.replace('"', r"\"")
        params["search"] = f'host_collection = "{escaped}"'
    return params


def build_errata_params(page, per_page):
    """Build query params for the Foreman /api/hosts/{id}/errata endpoint."""
    return {"page": int(page), "per_page": int(per_page)}


def extract_results(body):
    """Pull the result list out of a Foreman pagination envelope.

    Foreman / Katello uses ``{"results": [...], "total": N,
    "subtotal": N, "page": N, "per_page": N}`` on /api/ routes --
    accept ``data`` / ``items`` / ``hosts`` / ``errata`` as alt-keys
    for federated stacks.
    """
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for key in (
        "results",
        "data",
        "items",
        "hosts",
        "errata",
        "value",
        "entries",
    ):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_count(body):
    """Pull the total record count from a Foreman envelope.

    Foreman exposes ``total`` (org-wide) and ``subtotal`` (filtered)
    -- we prefer ``subtotal`` because pagination exhaustion should
    track the *filtered* count, not the unfiltered org total.
    """
    if not isinstance(body, dict):
        return None
    for key in ("subtotal", "total", "count", "total_count", "totalCount"):
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


def collect_cves(item):
    """Walk a Satellite errata payload for CVE-* ids.

    Foreman returns ``cves`` as a list of objects like
    ``[{"cve_id": "CVE-2024-12345", "href": "..."}, ...]``.  Some
    Satellite versions also surface ``cve_ids`` or inline ``CVE-...``
    refs in ``description`` / ``solution`` / ``title`` / ``summary``.
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

    cves = item.get("cves")
    if isinstance(cves, list):
        for entry in cves:
            if isinstance(entry, str):
                add(entry)
            elif isinstance(entry, dict):
                add(entry.get("cve_id") or entry.get("id") or entry.get("cve") or entry.get("name"))
    for key in ("cve", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cveIds", "cve_ids"):
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
        "solution",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
    return found


def collect_refs(item):
    """Walk a Satellite errata payload for advisory URLs and pivots."""
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

    errata_id = item.get("errata_id") or item.get("errataId") or item.get("advisory") or item.get("advisory_id")
    if errata_id is not None:
        s = str(errata_id).strip()
        if s:
            add(f"Satellite-Errata: {s}")
            # Red Hat canonical advisory URLs for the RHxA family.
            up = s.upper()
            if up.startswith("RHSA-") or up.startswith("RHBA-") or up.startswith("RHEA-"):
                add(f"https://access.redhat.com/errata/{s}")

    errata_type = item.get("type") or item.get("errata_type")
    if isinstance(errata_type, str) and errata_type.strip():
        add(f"Satellite-Type: {errata_type.strip()}")

    severity_raw = item.get("severity") or item.get("severityLabel") or item.get("severity_label")
    if isinstance(severity_raw, str) and severity_raw.strip() and severity_raw.strip().lower() != "none":
        add(f"Satellite-Severity: {severity_raw.strip()}")

    reboot_suggested = item.get("reboot_suggested") or item.get("rebootSuggested")
    if isinstance(reboot_suggested, bool) and reboot_suggested:
        add("Satellite-Reboot: true")

    issued = item.get("issued") or item.get("issued_at")
    if isinstance(issued, str) and issued.strip():
        add(f"Satellite-Issued: {issued.strip()}")

    updated = item.get("updated") or item.get("updated_at")
    if isinstance(updated, str) and updated.strip():
        add(f"Satellite-Updated: {updated.strip()}")

    # Foreman exposes ``packages`` on errata as a list of package
    # NEVRA strings or dicts -- pivot the first few so the Faraday
    # review can search the workspace for assets running the same
    # package.
    packages = item.get("packages")
    if isinstance(packages, list):
        for entry in packages[:10]:
            if isinstance(entry, str) and entry.strip():
                add(f"Satellite-Package: {entry.strip()}")
            elif isinstance(entry, dict):
                label = entry.get("nvrea") or entry.get("nvra") or entry.get("filename") or entry.get("name")
                if isinstance(label, str) and label.strip():
                    add(f"Satellite-Package: {label.strip()}")

    bugzilla = item.get("bugs") or item.get("bugzilla")
    if isinstance(bugzilla, list):
        for entry in bugzilla[:5]:
            if isinstance(entry, dict):
                bug_id = entry.get("bug_id") or entry.get("id")
                href = entry.get("href") or entry.get("url")
                if bug_id:
                    add(f"Satellite-Bug: {bug_id}")
                if isinstance(href, str) and href.strip():
                    add(href.strip())
            elif isinstance(entry, (str, int)):
                add(f"Satellite-Bug: {entry}")

    for key in ("references", "links", "advisoryUrls", "advisory_urls"):
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


def errata_label(item):
    """Build the leading title fragment for a Satellite errata finding."""
    if not isinstance(item, dict):
        return ""
    for key in ("title", "name", "summary", "displayName", "display_name"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("errata_id", "errataId", "advisory", "advisory_id"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("description",):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "Applicable erratum"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from a Satellite errata record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    for key in ("cvss_score", "cvssScore", "cvss", "score", "riskScore", "risk_score"):
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
    errata_type = item.get("type") or item.get("errata_type")
    severity = severity_from_satellite(severity_string, severity_numeric, errata_type)
    status = status_from_satellite(item)

    label = errata_label(item)
    advisory = str(item.get("errata_id") or item.get("errataId") or item.get("advisory") or "").strip()
    if advisory and advisory not in label:
        name = f"[PATCH-MGMT] {advisory}: {label}"
    elif label and label != "Applicable erratum":
        name = f"[PATCH-MGMT] Applicable erratum: {label}"
    else:
        name = "[PATCH-MGMT] Applicable erratum"

    desc_parts = []
    description = item.get("description") or item.get("Description") or item.get("summary")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("errata_id", "errata_id"),
        ("type", "type"),
        ("severity", "severity"),
        ("issued", "issued"),
        ("updated", "updated"),
        ("reboot_suggested", "reboot_suggested"),
        ("installable", "installable"),
        ("hosts_available_count", "hosts_available_count"),
        ("hosts_applicable_count", "hosts_applicable_count"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    packages = item.get("packages")
    if isinstance(packages, list) and packages:
        pkg_labels = []
        for entry in packages[:10]:
            if isinstance(entry, str) and entry.strip():
                pkg_labels.append(entry.strip())
            elif isinstance(entry, dict):
                pl = entry.get("nvrea") or entry.get("nvra") or entry.get("filename") or entry.get("name")
                if isinstance(pl, str) and pl.strip():
                    pkg_labels.append(pl.strip())
        if pkg_labels:
            desc_parts.append("packages: " + ", ".join(pkg_labels))

    if severity_numeric is not None:
        desc_parts.append(f"severity_score: {severity_numeric}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    sol = item.get("solution") or item.get("recommendation") or item.get("remediation")
    if isinstance(sol, str) and sol.strip():
        resolution = sol.strip()
    elif isinstance(sol, list):
        bits = []
        for r in sol:
            if isinstance(r, str) and r.strip():
                bits.append(r.strip())
            elif isinstance(r, dict):
                txt = r.get("help_text") or r.get("description") or r.get("name") or r.get("solution")
                if isinstance(txt, str) and txt.strip():
                    bits.append(txt.strip())
        if bits:
            resolution = "\n".join(bits)
    if not resolution:
        advisory_hint = ""
        if advisory:
            advisory_hint = f" Apply {advisory} (yum/dnf update or via the Satellite content host UI)."
        resolution = (
            "Apply the applicable erratum through the Red Hat "
            "Satellite content host (Hosts -> All Hosts -> select the "
            "host -> Errata -> select the advisory -> Apply); or "
            "schedule the patch through a Satellite remote-execution "
            "job; or accept the risk if the patch cannot be applied."
            f"{advisory_hint}"
        )

    external_id = str(
        item.get("errata_id")
        or item.get("errataId")
        or item.get("advisory")
        or item.get("id")
        or (cves[0] if cves else "")
    )

    return {
        "name": str(name).strip()[:200] or f"Applicable erratum {external_id}",
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
        "tags": ["redhat", "patch-management", "satellite", "errata"],
    }


def host_hostname(host_record):
    """Pick the canonical hostname for a Foreman host record."""
    if isinstance(host_record, dict):
        for key in (
            "name",
            "hostname",
            "certname",
            "fqdn",
            "display_name",
            "displayName",
        ):
            v = host_record.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def host_ip(host_record):
    """Pick an IP address for the Foreman host record."""
    if not isinstance(host_record, dict):
        return "0.0.0.0"
    for key in (
        "ip",
        "ipAddress",
        "ip_address",
        "primary_interface_ip",
        "ip6",
    ):
        v = host_record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "0.0.0.0"


def host_mac(host_record):
    """Pick a MAC address for the Foreman host record."""
    if not isinstance(host_record, dict):
        return ""
    for key in ("mac", "macAddress", "mac_address"):
        v = host_record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def host_os(host_record):
    """Build the host.os string from a Foreman host record."""
    if not isinstance(host_record, dict):
        return "unknown"
    os_obj = host_record.get("operatingsystem") or host_record.get("operating_system")
    if isinstance(os_obj, dict):
        for key in ("description", "name", "title", "fullname"):
            v = os_obj.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    for key in (
        "operatingsystem_name",
        "operating_system",
        "os",
        "osName",
        "os_name",
        "osVersion",
        "os_version",
        "platform",
    ):
        v = host_record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "unknown"


def build_host(host_key, host_record, vulns, scoping=None):
    """Build a Faraday host record for a Satellite-managed asset."""
    if not isinstance(host_record, dict):
        host_record = {}
    if not isinstance(scoping, dict):
        scoping = {}
    hostname = host_hostname(host_record) or str(host_key or "")
    os_str = host_os(host_record)
    ip = host_ip(host_record)
    mac = host_mac(host_record)

    desc_parts = []
    if host_key:
        desc_parts.append(f"host_key={host_key}")
    for label_key, key in (
        ("host_id", "id"),
        ("name", "name"),
        ("ip", "ip"),
        ("mac", "mac"),
        ("os", "operatingsystem_name"),
        ("domain", "domain_name"),
        ("organization", "organization_name"),
        ("location", "location_name"),
        ("host_collections", "host_collection_names"),
        ("errata_status", "errata_status_label"),
        ("last_checkin", "last_checkin"),
        ("subscription_status", "subscription_status_label"),
    ):
        v = host_record.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, list):
            joined = ",".join(str(x).strip() for x in v if isinstance(x, (str, int)) and str(x).strip())
            if joined:
                desc_parts.append(f"{label_key}={joined}")
            continue
        if isinstance(v, dict):
            continue
        desc_parts.append(f"{label_key}={v}")

    for label_key, key in (
        ("scope_org", "org_id"),
        ("scope_host_collection", "host_collection"),
    ):
        v = scoping.get(key)
        if v in (None, ""):
            continue
        token = f"{label_key}={v}"
        if token not in desc_parts:
            desc_parts.append(token)

    if vulns:
        desc_parts.append(f"applicable_errata={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_hosts(
    requests_module,
    host,
    org_id,
    host_collection,
    headers,
    max_pages=MAX_PAGES,
    per_page=PAGE_SIZE,
):
    """Walk the Foreman /api/hosts list via page / per_page pagination."""
    out = []
    url = build_hosts_url(host)
    page = 1
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_hosts_params(org_id, host_collection, page, per_page)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 -- surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Satellite request rejected (401). Check SATELLITE_USER / SATELLITE_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Satellite request rejected (403). Check the role's permissions.")
            return out
        if resp.status_code == 404:
            log(f"Satellite hosts endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"Satellite hosts request failed ({resp.status_code}) " f"for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Satellite hosts response was not JSON ({url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < per_page:
            break
        total = extract_count(payload)
        if isinstance(total, int) and len(out) >= total:
            break
        page += 1
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping hosts pagination")
    return out


def fetch_errata(
    requests_module,
    host,
    host_id,
    headers,
    max_pages=MAX_PAGES,
    per_page=PAGE_SIZE,
):
    """Walk the Foreman /api/hosts/{id}/errata catalogue."""
    out = []
    url = build_errata_url(host, host_id)
    page = 1
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_errata_params(page, per_page)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 -- surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Satellite request rejected (401). Check SATELLITE_USER / SATELLITE_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Satellite request rejected (403). Check the role's permissions.")
            return out
        if resp.status_code == 404:
            log(f"Satellite errata endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"Satellite errata request failed ({resp.status_code}) " f"for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Satellite errata response was not JSON ({url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < per_page:
            break
        total = extract_count(payload)
        if isinstance(total, int) and len(out) >= total:
            break
        page += 1
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping errata pagination")
    return out


def host_key_for(host_record):
    """Pick the host grouping key (the Foreman numeric host id)."""
    if not isinstance(host_record, dict):
        return ""
    for key in ("id", "host_id", "uuid", "name", "fqdn"):
        v = host_record.get(key)
        if isinstance(v, (str, int)) and str(v).strip():
            return str(v).strip()
    return ""


def main():
    started = time.time()

    org_id = validate_org_id(env("EXECUTOR_CONFIG_SATELLITE_ORG_ID"))
    host_collection = validate_host_collection(env("EXECUTOR_CONFIG_SATELLITE_HOST_COLLECTION"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_SATELLITE_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = validate_host(env("SATELLITE_HOST", required=True))
    user = env("SATELLITE_USER", required=True)
    password = env("SATELLITE_PASSWORD", required=True)

    try:
        import requests  # noqa: WPS433 -- lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(user, password)

    hosts_records = fetch_hosts(requests, host, org_id, host_collection, headers)

    log(
        f"Processing {len(hosts_records)} Satellite hosts "
        f"(org_id={org_id or '<all>'}, "
        f"host_collection={host_collection or '<all>'}, "
        f"min_severity={min_severity})"
    )

    scoping = {"org_id": org_id, "host_collection": host_collection}

    hosts = []
    for host_record in hosts_records:
        host_id = host_key_for(host_record)
        if not host_id:
            continue
        errata = fetch_errata(requests, host, host_id, headers)
        vulns = []
        for erratum in errata:
            built = build_vulnerability(erratum)
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        hosts.append(build_host(host_id, host_record, vulns, scoping))

    if not hosts:
        # Still emit a synthetic placeholder host so the Faraday
        # workspace records that the Satellite query was processed
        # even when zero hosts came back.
        hosts.append(
            build_host(
                host_collection or org_id or "satellite",
                {"name": host_collection or "satellite"},
                [],
                scoping,
            )
        )

    params_bits = []
    if org_id:
        params_bits.append(f"org_id={org_id}")
    if host_collection:
        params_bits.append(f"host_collection={host_collection}")
    params_bits.append(f"min_severity={min_severity}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "redhat_satellite",
            "command": "redhat_satellite",
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
