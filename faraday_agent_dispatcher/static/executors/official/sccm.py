#!/usr/bin/env python
"""Microsoft SCCM / MECM patch-management REST importer.

Pulls the SMS Provider's system catalogue (one Configuration Manager
managed asset per row), the missing-update compliance state, and the
software-update catalogue from an SCCM / MECM AdminService REST
endpoint and emits Faraday bulk-create JSON to stdout.  Each
SCCM-managed system becomes one Faraday host (keyed by the
``SMS_R_System`` record -- ``Name`` / ``NetbiosName`` /
``IPAddresses`` / ``MACAddresses`` / ``OperatingSystemNameandVersion``
/ ``ResourceDomainORWorkgroup`` / ``ClientVersion`` /
``SMSAssignedSites`` / ``LastLogonTimestamp``); each missing update
attaches as a Faraday vulnerability with the engine prefix
``[PATCH-MGMT]``.

Endpoints used:
  GET <SCCM_HOST>/AdminService/wmi/SMS_FullCollectionMembership
      -> paginated collection membership list (used only when
      ``SCCM_COLLECTION_ID`` is set, since the SMS_R_System WMI class
      does not expose a CollectionID column for direct filtering).
      Returns ``ResourceID`` entries scoped to the collection so the
      following SMS_R_System / SMS_UpdateComplianceStatus calls can be
      pinned to that membership.
  GET <SCCM_HOST>/AdminService/wmi/SMS_R_System
      -> paginated system catalogue.  Optionally narrowed by
      ``SCCM_SITE_CODE`` (filters via ``SMSAssignedSites/any(s: s eq
      '<site>')``) and / or by the collection membership join.  Each
      row carries the canonical SCCM device metadata.
  GET <SCCM_HOST>/AdminService/wmi/SMS_UpdateComplianceStatus
      -> paginated per-resource missing-update join (``Status eq 2``
      = required / missing).  Pulls the CI_ID of every update the
      device has not installed but is deployed for.  Used to drive
      the per-host missing-update list.
  GET <SCCM_HOST>/AdminService/wmi/SMS_SoftwareUpdate
      -> paginated software-update catalogue (CI_ID + ArticleID /
      BulletinID + LocalizedDisplayName + LocalizedDescription +
      Severity / SeverityName + DateRevised + UpdateClassification
      + Vendor + IsDeployed + IsExpired + IsSuperseded).  Used to
      resolve the CI_IDs collected from SMS_UpdateComplianceStatus
      into per-update metadata.

Auth: SCCM AdminService is typically published behind IIS with
Windows authentication (NTLM / Kerberos).  This executor carries
``Authorization: Basic <b64(SCCM_USER:SCCM_PASSWORD)>`` on every
``/AdminService/`` call when the IIS site is configured for Basic
auth (the documented config for non-domain-joined service accounts).
When the ``requests_ntlm`` library is available in the executor's
Python environment, NTLM is preferred (the user is treated as
``DOMAIN\\user`` or ``user@DOMAIN`` so the SMS Provider can resolve
the service account).  ``SCCM_HOST`` is the SMS Provider FQDN URL
(typically the primary site server) hard-validated client-side as
``http(s)://host[:port]``.
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
# SCCM ArticleID values are bare digits (no "KB" prefix) on the
# SMS_SoftwareUpdate record but appear as ``KB1234567`` in the
# LocalizedDisplayName / LocalizedDescription free text.  Accept both
# shapes with optional spacing.
KB_RE = re.compile(r"\bKB\s?\d{4,10}\b", re.IGNORECASE)
# SCCM host validation -- accept http(s)://host[:port], strip trailing
# slash.  Control chars (newline / tab / null / etc) rejected outright
# so a header-injection attempt can't sneak through.  Anchored with
# \A/\Z (not ^/$) so a trailing newline cannot sneak through --
# Python's default ``$`` matches just before a trailing ``\n``.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")
# SCCM site codes are canonical 3-character alphanumeric strings
# (e.g. "PRI", "CAS", "P01") -- the SMS Provider enforces this shape
# at install time.  Anchored with \A/\Z.
SITE_CODE_RE = re.compile(r"\A[A-Za-z0-9]{3}\Z")
# SCCM collection ids are canonical 8-character alphanumeric strings
# (e.g. "SMS00001" for the built-in "All Systems", or "PRI00014" for a
# user-defined collection).  The first 3 chars are the site code (or
# "SMS" for the built-in ones).  Accept 8 chars exactly; anchored.
COLLECTION_ID_RE = re.compile(r"\A[A-Za-z0-9]{8}\Z")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# SCCM exposes update severity via two fields: the freeform string
# ``SeverityName`` (Low / Moderate / Important / Critical) and the
# numeric ``Severity`` integer that uses a Microsoft-internal scale
# (0 = None, 2 = Low, 6 = Moderate, 8 = Important, 10 = Critical) --
# NOT a CVSS 0-10 scale.  The string enum buckets onto Faraday tiers;
# the SCCM numeric scale gets its own bucket function so it doesn't
# get mistakenly fed through the CVSS bucketing math.
SCCM_STRING_SEVERITY = {
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

# SCCM internal severity scale -- NOT CVSS 0-10.  The SMS Provider
# uses these exact integer codes on every SMS_SoftwareUpdate record.
SCCM_NUMERIC_SEVERITY = {
    0: "info",
    2: "low",
    6: "medium",
    8: "high",
    10: "critical",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# SCCM SMS_UpdateComplianceStatus.Status values:
#   0 = Unknown / not detected -> open (default)
#   1 = NotRequired / not applicable -> closed
#   2 = Required / missing -> open (this is the value we filter on)
#   3 = Installed / compliant -> closed
SCCM_COMPLIANCE_STATUS = {
    0: "open",
    1: "closed",
    2: "open",
    3: "closed",
}

# Status normalisation for SMS_SoftwareUpdate / SMS_UpdateComplianceStatus
# fields exposed as freeform strings on some federated stacks.
SCCM_STATUS_BY_STATE = {
    "missing": "open",
    "required": "open",
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
    "failed": "open",
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
    "not_required": "closed",
    "notrequired": "closed",
    "compliant": "closed",
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
    print(f"{datetime.utcnow()} - SCCM: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
    """Bucket a numeric severity (0-10 CVSS-style) onto a Faraday tier.

    Used only when an explicit CVSS score is provided via
    ``CVSS3Score`` / ``CVSS2Score`` / ``cvss`` fields -- NOT for the
    SCCM internal Severity scale (0/2/6/8/10) which goes through
    severity_from_sccm_numeric() instead.
    """
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


def severity_from_sccm_numeric(value):
    """Bucket the SCCM internal Severity scale (0/2/6/8/10).

    SCCM stores update severity as a numeric ``Severity`` integer that
    maps to the SeverityName enum: 0=None, 2=Low, 6=Moderate (medium),
    8=Important (high), 10=Critical.  Values outside the canonical set
    are bucketed by proximity (1-3 low, 4-7 medium, 8-9 high, >=10
    critical) so federated SMS Providers with non-canonical numeric
    severity columns still get a sensible bucket.
    """
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        try:
            n = int(float(value))
        except (TypeError, ValueError):
            return None
    if n in SCCM_NUMERIC_SEVERITY:
        return SCCM_NUMERIC_SEVERITY[n]
    if n <= 0:
        return "info"
    if n <= 3:
        return "low"
    if n <= 7:
        return "medium"
    if n <= 9:
        return "high"
    return "critical"


def severity_from_sccm(value, sccm_numeric=None, cvss_numeric=None):
    """Map an SCCM update severity onto a Faraday bucket.

    Accepts the freeform ``SeverityName`` string enum (Critical /
    Important / Moderate / Low) plus Faraday-side synonyms (severe /
    high / medium / minor / informational / informational / unknown /
    none), numeric SCCM Severity codes (0/2/6/8/10), and falls back
    to:
      1. ``sccm_numeric`` bucket via severity_from_sccm_numeric -- the
         SCCM internal 0/2/6/8/10 scale.
      2. ``cvss_numeric`` bucket via severity_from_cvss -- the
         standard 0-10 CVSS scale (used when an explicit CVSS3Score /
         CVSS2Score is on the record).

    Placeholder string values ("none" / "unspecified" / "unknown")
    delegate to the numeric fallback chain rather than bucketing
    straight to ``info`` -- some federated SMS Providers leave
    SeverityName="None" on records whose numeric Severity column
    still carries a meaningful 2/6/8/10 code.
    """
    placeholder = {"none", "unspecified", "unknown"}
    if isinstance(value, bool):
        if sccm_numeric is not None:
            bucket = severity_from_sccm_numeric(sccm_numeric)
            if bucket is not None:
                return bucket
        if cvss_numeric is not None:
            return severity_from_cvss(cvss_numeric)
        return "info"
    if isinstance(value, (int, float)):
        bucket = severity_from_sccm_numeric(value)
        if bucket is not None:
            return bucket
    if isinstance(value, str) and value.strip():
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        # Placeholder string -- delegate to numeric fallback chain so
        # SeverityName="None" doesn't silently drop a Severity=8
        # finding to info.
        if text not in placeholder and text.replace("_", "") not in placeholder:
            if text in SCCM_STRING_SEVERITY:
                return SCCM_STRING_SEVERITY[text]
            squashed = text.replace("_", "")
            if squashed in SCCM_STRING_SEVERITY:
                return SCCM_STRING_SEVERITY[squashed]
            try:
                n = int(value.strip())
                bucket = severity_from_sccm_numeric(n)
                if bucket is not None:
                    return bucket
            except ValueError:
                pass
            try:
                return severity_from_cvss(float(value.strip()))
            except ValueError:
                pass
    if sccm_numeric is not None:
        bucket = severity_from_sccm_numeric(sccm_numeric)
        if bucket is not None:
            return bucket
    if cvss_numeric is not None:
        return severity_from_cvss(cvss_numeric)
    return "info"


def status_from_sccm(item):
    """Derive Faraday status from an SCCM update / compliance payload."""
    if not isinstance(item, dict):
        return "open"
    # SMS_UpdateComplianceStatus.Status is a numeric column -- preferred.
    raw_numeric = item.get("Status")
    if isinstance(raw_numeric, bool):
        pass  # fall through to string handling
    elif isinstance(raw_numeric, int) and raw_numeric in SCCM_COMPLIANCE_STATUS:
        return SCCM_COMPLIANCE_STATUS[raw_numeric]
    elif isinstance(raw_numeric, str) and raw_numeric.strip().isdigit():
        try:
            n = int(raw_numeric.strip())
            if n in SCCM_COMPLIANCE_STATUS:
                return SCCM_COMPLIANCE_STATUS[n]
        except ValueError:
            pass

    for key in (
        "status",
        "Status",
        "state",
        "State",
        "complianceStatus",
        "compliance_status",
        "ComplianceState",
        "compliance_state",
        "updateStatus",
        "update_status",
        "deploymentStatus",
        "deployment_status",
        "installStatus",
        "install_status",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in SCCM_STATUS_BY_STATE:
                return SCCM_STATUS_BY_STATE[compact]
            if squashed in SCCM_STATUS_BY_STATE:
                return SCCM_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in SCCM_STATUS_BY_STATE:
                        return SCCM_STATUS_BY_STATE[compact]
                    if squashed in SCCM_STATUS_BY_STATE:
                        return SCCM_STATUS_BY_STATE[squashed]
    # SMS_SoftwareUpdate.IsExpired / IsSuperseded bool fallback.
    if item.get("IsExpired") is True or item.get("isExpired") is True:
        return "closed"
    if item.get("IsSuperseded") is True or item.get("isSuperseded") is True:
        return "closed"
    return "open"


def validate_min_severity(value):
    """Validate SCCM_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus Microsoft synonyms
    (severe -> critical, important -> high, moderate / warning ->
    medium, minor -> low, informational / information / unspecified /
    none / unknown -> info) plus numeric-string input bucketed via
    severity_from_sccm_numeric (SCCM 0/2/6/8/10 scale tried first),
    then severity_from_cvss as a secondary fallback.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "info"
    bucket = SCCM_STRING_SEVERITY.get(text)
    if bucket is None:
        bucket = SCCM_STRING_SEVERITY.get(text.replace("_", ""))
    if bucket is None:
        try:
            n = int(str(value).strip())
            bucket = severity_from_sccm_numeric(n)
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(str(value).strip()))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"SCCM_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_site_code(value):
    """Validate SCCM_SITE_CODE.

    None / blank -> None (optional -- caller can walk all sites the
    SCCM_USER service account can see).  SCCM site codes are canonical
    3-character alphanumeric strings (e.g. "PRI" / "CAS" / "P01").
    Control chars rejected on the *raw* value before ``.strip()`` runs
    so a typo ending in \\n / \\r can't sneak through SITE_CODE_RE.
    """
    if value is None or value == "":
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("SCCM_SITE_CODE contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return None
    if not SITE_CODE_RE.match(text):
        log(f"SCCM_SITE_CODE '{text}' is not a valid 3-character " "alphanumeric site code")
        sys.exit(1)
    # SCCM site codes are uppercase by canonical convention.
    return text.upper()


def validate_collection_id(value):
    """Validate SCCM_COLLECTION_ID.

    None / blank -> None (optional -- when unset the executor walks
    SMS_R_System scoped only by SCCM_SITE_CODE).  SCCM collection ids
    are canonical 8-character alphanumeric strings (first 3 chars are
    the site code, or "SMS" for the built-in ones like SMS00001 = All
    Systems).  Control chars rejected on the raw value before
    .strip().
    """
    if value is None or value == "":
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("SCCM_COLLECTION_ID contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return None
    if not COLLECTION_ID_RE.match(text):
        log(f"SCCM_COLLECTION_ID '{text}' is not a valid 8-character " "alphanumeric collection id")
        sys.exit(1)
    return text.upper()


def validate_host(value):
    """Validate SCCM_HOST.

    None / blank -> sys.exit(1).  Must be ``http(s)://host[:port]``;
    trailing slash stripped client-side.  Control chars rejected so a
    header-injection attempt can't sneak through.
    """
    if value is None or value == "":
        log("SCCM_HOST is required")
        sys.exit(1)
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("SCCM_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("SCCM_HOST is required")
        sys.exit(1)
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"SCCM_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(user, password):
    """SCCM AdminService uses HTTP Basic auth when IIS is configured for it.

    Built explicitly (instead of relying on requests's ``auth=`` kwarg)
    so the function stays testable without a live ``requests`` install
    and so the encoded credentials never leak into log output.  When
    the SMS Provider runs with NTLM-only auth, the optional NTLM path
    in main() takes precedence; this header is the fallback.
    """
    creds = f"{user or ''}:{password or ''}".encode("utf-8")
    token = base64.b64encode(creds).decode("ascii")
    return {
        "Authorization": f"Basic {token}",
        "Accept": "application/json",
    }


def build_collection_membership_url(host):
    return f"{host}/AdminService/wmi/SMS_FullCollectionMembership"


def build_systems_url(host):
    return f"{host}/AdminService/wmi/SMS_R_System"


def build_compliance_status_url(host):
    return f"{host}/AdminService/wmi/SMS_UpdateComplianceStatus"


def build_software_update_url(host):
    return f"{host}/AdminService/wmi/SMS_SoftwareUpdate"


def _odata_quote(value):
    """Escape a string literal for an OData v4 ``$filter`` query.

    OData v4 string literals use single quotes; embedded single quotes
    are doubled.  Used for CollectionID / site code / scalar-string
    filters.
    """
    return str(value).replace("'", "''")


def build_collection_membership_params(collection_id, top, skip):
    """Build OData query params for SMS_FullCollectionMembership."""
    params = {
        "$filter": f"CollectionID eq '{_odata_quote(collection_id)}'",
        "$select": "ResourceID,Name,SMSID,IsClient,IsAssigned",
        "$top": int(top),
        "$skip": int(skip),
    }
    return params


def build_systems_params(site_code, resource_ids, top, skip):
    """Build OData query params for SMS_R_System.

    Optional ``site_code`` filters via ``SMSAssignedSites/any(s: s eq
    '<code>')`` -- the SMS Provider exposes SMSAssignedSites as a
    multi-valued column.  Optional ``resource_ids`` (an iterable of
    int resource ids from the collection membership join) builds a
    chained ``ResourceID eq A or ResourceID eq B`` clause -- OData v4
    ``in`` is not consistently supported across SCCM versions, so the
    chained ``eq`` shape is the portable form.
    """
    parts = []
    if site_code:
        parts.append(f"SMSAssignedSites/any(s: s eq '{_odata_quote(site_code)}')")
    if resource_ids:
        clauses = []
        for rid in resource_ids:
            try:
                n = int(rid)
            except (TypeError, ValueError):
                continue
            clauses.append(f"ResourceID eq {n}")
        if clauses:
            parts.append("(" + " or ".join(clauses) + ")")
    params = {
        "$top": int(top),
        "$skip": int(skip),
    }
    if parts:
        params["$filter"] = " and ".join(parts)
    return params


def build_compliance_params(resource_id, top, skip):
    """Build OData query params for SMS_UpdateComplianceStatus.

    Filters to ``Status eq 2`` (required / missing).  Optional
    ``resource_id`` narrows to a single machine.
    """
    parts = ["Status eq 2"]
    if resource_id is not None:
        try:
            n = int(resource_id)
            parts.append(f"ResourceID eq {n}")
        except (TypeError, ValueError):
            pass
    params = {
        "$filter": " and ".join(parts),
        "$top": int(top),
        "$skip": int(skip),
    }
    return params


def build_software_update_params(ci_ids, top, skip):
    """Build OData query params for SMS_SoftwareUpdate.

    Filters to deployed + non-expired updates.  When ``ci_ids`` is
    provided, the filter is narrowed to that CI_ID set via chained
    ``CI_ID eq A or CI_ID eq B``.
    """
    parts = ["IsDeployed eq true", "IsExpired eq false"]
    if ci_ids:
        clauses = []
        for cid in ci_ids:
            try:
                n = int(cid)
            except (TypeError, ValueError):
                continue
            clauses.append(f"CI_ID eq {n}")
        if clauses:
            parts.append("(" + " or ".join(clauses) + ")")
    params = {
        "$filter": " and ".join(parts),
        "$top": int(top),
        "$skip": int(skip),
    }
    return params


def extract_results(body):
    """Pull the result list out of an AdminService OData envelope.

    SCCM AdminService uses ``{"value": [...], "@odata.count": N,
    "@odata.nextLink": "..."}`` -- accept ``data`` / ``results`` /
    ``items`` as alt-keys for federated stacks.
    """
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for key in ("value", "results", "data", "items", "entries"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_count(body):
    """Pull the total record count from an AdminService envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("@odata.count", "odata_count", "count", "total", "totalCount", "total_count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def extract_next_link(body):
    """Pull the ``@odata.nextLink`` URL from an AdminService envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("@odata.nextLink", "odata_nextLink", "nextLink", "next_link"):
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
    """Walk an SCCM SMS_SoftwareUpdate payload for CVE-* ids.

    SCCM updates don't carry CVE ids in dedicated columns (the SMS
    Provider doesn't expose a CVE field on the WMI class).  CVE ids
    typically appear inline in LocalizedDescription / KB advisory
    text -- regex-scanned from the title / summary / description
    fields.
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

    # Federated stacks sometimes vend a ``CVE`` / ``CVEs`` column even
    # though stock SCCM does not.  Honour it if present.
    for key in ("cve", "CVE", "cveId", "CVEId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "CVEs", "cveIds", "CVEIds", "cve_ids"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    for key in (
        "LocalizedDescription",
        "LocalizedDisplayName",
        "description",
        "Description",
        "summary",
        "Summary",
        "name",
        "Name",
        "title",
        "Title",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
    return found


def collect_kb_ids(item):
    """Walk an SCCM SMS_SoftwareUpdate payload for Microsoft KB ids.

    SCCM's canonical KB reference is ``ArticleID`` (bare digits, no
    "KB" prefix).  Also inline-scan LocalizedDisplayName /
    LocalizedDescription / BulletinID for ``KB<digits>`` references
    so federated SMS Providers with non-canonical ArticleID columns
    still surface their KB pivots.
    """
    found = []
    seen = set()

    def add(num):
        if not num:
            return
        s = str(num).strip().upper()
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

    for key in ("ArticleID", "articleId", "article_id", "kb", "kbId", "kb_id"):
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
        "LocalizedDisplayName",
        "LocalizedDescription",
        "description",
        "Description",
        "summary",
        "Summary",
        "name",
        "Name",
        "title",
        "Title",
        "BulletinID",
        "bulletinId",
        "bulletin_id",
    ):
        v = item.get(key)
        if isinstance(v, str):
            scan(v)
    return found


def collect_refs(item):
    """Walk an SCCM SMS_SoftwareUpdate payload for advisory pivots."""
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

    ci_id = item.get("CI_ID") or item.get("ci_id") or item.get("CIID")
    if ci_id is not None:
        s = str(ci_id).strip()
        if s:
            add(f"SCCM-CI: {s}")

    article_id = item.get("ArticleID") or item.get("articleId") or item.get("article_id")
    if article_id is not None:
        s = str(article_id).strip()
        if s:
            add(f"SCCM-Article: {s}")

    bulletin_id = item.get("BulletinID") or item.get("bulletinId") or item.get("bulletin_id") or item.get("Bulletin")
    if bulletin_id is not None:
        s = str(bulletin_id).strip()
        if s:
            add(f"SCCM-Bulletin: {s}")

    classification = (
        item.get("UpdateClassification")
        or item.get("update_classification")
        or item.get("Classification")
        or item.get("classification")
    )
    if isinstance(classification, str) and classification.strip():
        add(f"SCCM-Classification: {classification.strip()}")
    elif isinstance(classification, dict):
        label = classification.get("name") or classification.get("LocalizedDisplayName")
        if isinstance(label, str) and label.strip():
            add(f"SCCM-Classification: {label.strip()}")

    vendor = item.get("Vendor") or item.get("vendor") or item.get("Publisher")
    if isinstance(vendor, str) and vendor.strip():
        add(f"SCCM-Vendor: {vendor.strip()}")

    product = item.get("Product") or item.get("product") or item.get("ProductFamily")
    if isinstance(product, str) and product.strip():
        add(f"SCCM-Product: {product.strip()}")

    severity_raw = (
        item.get("SeverityName")
        or item.get("severityName")
        or item.get("severity_name")
        or item.get("severity")
        or item.get("Severity")
    )
    if isinstance(severity_raw, str) and severity_raw.strip() and severity_raw.strip().lower() != "none":
        add(f"SCCM-Severity: {severity_raw.strip()}")

    date_revised = (
        item.get("DateRevised") or item.get("dateRevised") or item.get("date_revised") or item.get("DatePosted")
    )
    if isinstance(date_revised, str) and date_revised.strip():
        add(f"SCCM-DateRevised: {date_revised.strip()}")

    if item.get("IsSuperseded") is True or item.get("isSuperseded") is True:
        add("SCCM-Superseded: true")

    machine = item.get("MachineName") or item.get("machineName") or item.get("Name") or item.get("NetbiosName")
    if isinstance(machine, str) and machine.strip():
        add(f"SCCM-Machine: {machine.strip()}")

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


def update_label(item):
    """Build the leading title fragment for an SCCM missing-update finding."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "LocalizedDisplayName",
        "localizedDisplayName",
        "localized_display_name",
        "title",
        "Title",
        "name",
        "Name",
        "displayName",
        "display_name",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("BulletinID", "bulletinId", "bulletin"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("ArticleID", "articleId", "article_id"):
        v = item.get(key)
        if isinstance(v, (str, int)) and str(v).strip():
            s = str(v).strip()
            return s if s.upper().startswith("KB") else f"KB{s}"
    for key in ("LocalizedDescription", "description", "summary"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "Missing update"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from an SCCM software-update record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    # SCCM internal Severity (0/2/6/8/10) -- preferred over CVSS.
    for key in ("Severity", "severity"):
        raw_numeric = item.get(key)
        if isinstance(raw_numeric, bool):
            continue
        if isinstance(raw_numeric, int):
            severity_numeric = raw_numeric
            break
        if isinstance(raw_numeric, str) and raw_numeric.strip():
            try:
                severity_numeric = int(raw_numeric.strip())
                break
            except ValueError:
                continue

    # Optional CVSS columns surfaced on federated stacks.
    cvss_numeric = None
    for key in (
        "CVSS3Score",
        "CVSS3_Score",
        "cvss3Score",
        "cvss3_score",
        "CVSS2Score",
        "CVSS2_Score",
        "cvss2Score",
        "cvss2_score",
        "cvssScore",
        "cvss_score",
        "cvss",
    ):
        raw_numeric = item.get(key)
        if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
            cvss_numeric = float(raw_numeric)
            break
        if isinstance(raw_numeric, str) and raw_numeric.strip():
            try:
                cvss_numeric = float(raw_numeric.strip())
                break
            except ValueError:
                continue

    severity_string = (
        item.get("SeverityName")
        or item.get("severityName")
        or item.get("severity_name")
        or item.get("severityLabel")
        or item.get("severity_label")
        or item.get("risk_level")
        or item.get("riskLevel")
    )
    severity = severity_from_sccm(severity_string, severity_numeric, cvss_numeric)
    status = status_from_sccm(item)

    label = update_label(item)
    if label and label != "Missing update":
        name = f"[PATCH-MGMT] Missing update: {label}"
    else:
        name = "[PATCH-MGMT] Missing update"

    desc_parts = []
    description = (
        item.get("LocalizedDescription")
        or item.get("localizedDescription")
        or item.get("description")
        or item.get("Description")
        or item.get("summary")
        or item.get("Summary")
    )
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("ci_id", "CI_ID"),
        ("article_id", "ArticleID"),
        ("bulletin_id", "BulletinID"),
        ("vendor", "Vendor"),
        ("product", "Product"),
        ("classification", "UpdateClassification"),
        ("severity_name", "SeverityName"),
        ("severity_numeric", "Severity"),
        ("date_revised", "DateRevised"),
        ("date_posted", "DatePosted"),
        ("is_deployed", "IsDeployed"),
        ("is_expired", "IsExpired"),
        ("is_superseded", "IsSuperseded"),
        ("superseded_by", "SupersededByCIID"),
        ("resource_id", "ResourceID"),
        ("machine_name", "MachineName"),
        ("machine_ip", "MachineIP"),
        ("collection_id", "CollectionID"),
        ("site_code", "SMSAssignedSite"),
        ("compliance_status", "ComplianceState"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if severity_numeric is not None:
        desc_parts.append(f"sccm_severity_code: {severity_numeric}")
    if cvss_numeric is not None:
        desc_parts.append(f"cvss_score: {cvss_numeric}")

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

    info_url = item.get("InfoURL") or item.get("infoUrl") or item.get("info_url")
    if isinstance(info_url, str) and info_url.strip():
        url_name = info_url.strip()
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
            "Deploy the missing update through the Configuration "
            "Manager console (Software Library -> Software Updates -> "
            "All Software Updates -> select the update -> Deploy) "
            "targeting the affected device collection; or trigger a "
            "client-side software update scan via "
            "''Configuration Manager Properties -> Actions -> "
            "Software Updates Scan Cycle''; or accept the risk via "
            "the SCCM exemption workflow if the update cannot be "
            "applied."
            f"{kb_hint}"
        )

    external_id = str(
        item.get("CI_ID")
        or item.get("ci_id")
        or item.get("ArticleID")
        or item.get("articleId")
        or item.get("BulletinID")
        or item.get("bulletinId")
        or (f"KB{kb_ids[0]}" if kb_ids else "")
        or (cves[0] if cves else "")
    )

    return {
        "name": str(name).strip()[:200] or f"Missing update {external_id}",
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
        "tags": ["microsoft", "patch-management", "sccm", "mecm", "missing-patch"],
    }


def system_hostname(system, fallback):
    """Pick the canonical hostname for an SMS_R_System record."""
    if isinstance(system, dict):
        for key in (
            "Name",
            "name",
            "NetbiosName",
            "netbios_name",
            "FullDomainName",
            "fqdn",
            "FQDN",
            "ComputerName",
            "computer_name",
            "hostname",
            "Hostname",
        ):
            v = system.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return ""


def system_ip(system):
    """Pick an IP address for the SMS_R_System record.

    SCCM stores IP addresses as a multi-valued ``IPAddresses`` column
    (an array of strings).  Some federated stacks also surface a
    scalar ``IPAddress`` / ``ip`` field.
    """
    if not isinstance(system, dict):
        return "0.0.0.0"
    for key in ("IPAddresses", "ipAddresses", "ip_addresses"):
        v = system.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    return entry.strip()
    for key in (
        "IPAddress",
        "ipAddress",
        "ip_address",
        "ip",
        "primaryIp",
        "primary_ip",
    ):
        v = system.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "0.0.0.0"


def system_mac(system):
    """Pick a MAC address for the SMS_R_System record."""
    if not isinstance(system, dict):
        return ""
    for key in ("MACAddresses", "macAddresses", "mac_addresses"):
        v = system.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    return entry.strip()
    for key in ("MACAddress", "macAddress", "mac_address", "mac", "Mac"):
        v = system.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def system_os(system):
    """Build the host.os string from an SMS_R_System record."""
    if not isinstance(system, dict):
        return "unknown"
    for key in (
        "OperatingSystemNameandVersion",
        "operating_system_name_and_version",
        "OperatingSystemNameAndVersion",
        "OperatingSystem",
        "operating_system",
        "operatingSystem",
        "os",
        "osName",
        "os_name",
        "osVersion",
        "os_version",
        "platform",
    ):
        v = system.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "unknown"


def build_host(resource_id, system, vulns, scoping=None):
    """Build a Faraday host record for an SCCM-managed system."""
    if not isinstance(system, dict):
        system = {}
    if not isinstance(scoping, dict):
        scoping = {}
    hostname = system_hostname(system, str(resource_id or ""))
    os_str = system_os(system)
    ip = system_ip(system)
    mac = system_mac(system)

    desc_parts = []
    if resource_id:
        desc_parts.append(f"resource_id={resource_id}")
    for label_key, key in (
        ("name", "Name"),
        ("netbios", "NetbiosName"),
        ("fqdn", "FullDomainName"),
        ("os", "OperatingSystemNameandVersion"),
        ("domain", "ResourceDomainORWorkgroup"),
        ("client_type", "ClientType"),
        ("client_version", "ClientVersion"),
        ("last_logon_user", "LastLogonUserName"),
        ("last_logon_domain", "LastLogonUserDomain"),
        ("last_logon", "LastLogonTimestamp"),
        ("is_client", "Client"),
        ("is_active", "IsActive"),
        ("is_obsolete", "Obsolete"),
        ("is_decommissioned", "Decommissioned"),
    ):
        v = system.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            if isinstance(v, list):
                joined = ",".join(str(x).strip() for x in v if isinstance(x, (str, int)) and str(x).strip())
                if joined:
                    desc_parts.append(f"{label_key}={joined}")
            continue
        desc_parts.append(f"{label_key}={v}")

    # SMSAssignedSites is multi-valued.
    sites = system.get("SMSAssignedSites") or system.get("sms_assigned_sites")
    if isinstance(sites, list):
        joined = ",".join(str(x).strip() for x in sites if str(x).strip())
        if joined:
            desc_parts.append(f"sites={joined}")
    elif isinstance(sites, str) and sites.strip():
        desc_parts.append(f"sites={sites.strip()}")

    for label_key, key in (
        ("scope_site_code", "site_code"),
        ("scope_collection_id", "collection_id"),
    ):
        v = scoping.get(key)
        if v in (None, ""):
            continue
        token = f"{label_key}={v}"
        if token not in desc_parts:
            desc_parts.append(token)

    if vulns:
        desc_parts.append(f"missing_updates={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def _paged_get(
    requests_module,
    url,
    headers,
    params_builder,
    auth=None,
    max_pages=MAX_PAGES,
    page_size=PAGE_SIZE,
    label="SCCM",
):
    """Generic paged GET against the AdminService OData endpoint.

    ``params_builder`` is a callable ``(top, skip) -> dict``.  Pages
    via $top + $skip until the response carries fewer than $top rows
    or until $@odata.count is reached.  Per-call NTLM auth is
    optional.
    """
    out = []
    skip = 0
    pages_walked = 0
    while pages_walked < max_pages:
        params = params_builder(page_size, skip)
        try:
            kwargs = {"headers": headers, "params": params, "timeout": TIMEOUT}
            if auth is not None:
                kwargs["auth"] = auth
            resp = requests_module.get(url, **kwargs)
        except Exception as exc:  # noqa: BLE001 -- surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log(f"{label} request rejected (401). Check SCCM_USER / " "SCCM_PASSWORD or NTLM-auth setup.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"{label} request rejected (403). Check the user's " "AdminService RBAC role.")
            return out
        if resp.status_code == 404:
            log(f"{label} endpoint 404 for {url}")
            return out
        if resp.status_code >= 400:
            log(f"{label} request failed ({resp.status_code}) " f"for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"{label} response was not JSON ({url})")
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
        if not extract_next_link(payload) and total is None:
            # No nextLink + no total -- assume one page only.
            break
        skip += page_size
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping {label} pagination")
    return out


def fetch_collection_members(requests_module, host, collection_id, headers, auth=None):
    """Walk SMS_FullCollectionMembership for a collection -> ResourceID list."""
    url = build_collection_membership_url(host)
    return _paged_get(
        requests_module,
        url,
        headers,
        lambda top, skip: build_collection_membership_params(collection_id, top, skip),
        auth=auth,
        label="SCCM collection-membership",
    )


def fetch_systems(
    requests_module,
    host,
    site_code,
    resource_ids,
    headers,
    auth=None,
):
    """Walk SMS_R_System optionally scoped by site code + resource id list."""
    url = build_systems_url(host)
    # Cap the resource_ids chunk size so the OData filter URL doesn't
    # blow past the AdminService's 16 KB query limit.  Roughly 50
    # ResourceID-eq clauses fit comfortably.
    chunk = 50
    out = []
    rid_list = list(resource_ids) if resource_ids else None
    if not rid_list:
        out.extend(
            _paged_get(
                requests_module,
                url,
                headers,
                lambda top, skip: build_systems_params(site_code, None, top, skip),
                auth=auth,
                label="SCCM systems",
            )
        )
        return out
    for i in range(0, len(rid_list), chunk):
        sub = rid_list[i : i + chunk]
        out.extend(
            _paged_get(
                requests_module,
                url,
                headers,
                lambda top, skip, _sub=sub: build_systems_params(site_code, _sub, top, skip),
                auth=auth,
                label="SCCM systems",
            )
        )
    return out


def fetch_compliance_status(requests_module, host, resource_id, headers, auth=None):
    """Walk SMS_UpdateComplianceStatus for a single ResourceID -> CI_ID list."""
    url = build_compliance_status_url(host)
    return _paged_get(
        requests_module,
        url,
        headers,
        lambda top, skip: build_compliance_params(resource_id, top, skip),
        auth=auth,
        label="SCCM compliance-status",
    )


def fetch_software_updates(requests_module, host, ci_ids, headers, auth=None):
    """Walk SMS_SoftwareUpdate optionally narrowed to a CI_ID set."""
    url = build_software_update_url(host)
    chunk = 50
    out = []
    ci_list = list(ci_ids) if ci_ids else None
    if not ci_list:
        out.extend(
            _paged_get(
                requests_module,
                url,
                headers,
                lambda top, skip: build_software_update_params(None, top, skip),
                auth=auth,
                label="SCCM software-update",
            )
        )
        return out
    for i in range(0, len(ci_list), chunk):
        sub = ci_list[i : i + chunk]
        out.extend(
            _paged_get(
                requests_module,
                url,
                headers,
                lambda top, skip, _sub=sub: build_software_update_params(_sub, top, skip),
                auth=auth,
                label="SCCM software-update",
            )
        )
    return out


def resource_id_for(record):
    """Pick a numeric ResourceID out of a system or membership record."""
    if not isinstance(record, dict):
        return None
    for key in ("ResourceID", "resourceId", "resource_id", "ResourceId"):
        v = record.get(key)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
        if isinstance(v, str) and v.strip():
            try:
                return int(v.strip())
            except ValueError:
                continue
    return None


def ci_id_for(record):
    """Pick a numeric CI_ID out of a compliance / update record."""
    if not isinstance(record, dict):
        return None
    for key in ("CI_ID", "ci_id", "CIID", "ciId"):
        v = record.get(key)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
        if isinstance(v, str) and v.strip():
            try:
                return int(v.strip())
            except ValueError:
                continue
    return None


def _maybe_ntlm_auth(user, password):
    """Build an NTLM auth handler when ``requests_ntlm`` is installed.

    Returns None when ``requests_ntlm`` is not available -- the caller
    falls back to the HTTP Basic header in that case.  SCCM_USER is
    expected as ``DOMAIN\\user`` or ``user@DOMAIN`` so the SMS Provider
    can resolve the service account; that shape passes through
    requests_ntlm unchanged.
    """
    try:
        from requests_ntlm import HttpNtlmAuth  # noqa: WPS433 -- optional
    except ImportError:
        return None
    return HttpNtlmAuth(user or "", password or "")


def main():
    started = time.time()

    site_code = validate_site_code(env("EXECUTOR_CONFIG_SCCM_SITE_CODE"))
    collection_id = validate_collection_id(env("EXECUTOR_CONFIG_SCCM_COLLECTION_ID"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_SCCM_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = validate_host(env("SCCM_HOST", required=True))
    user = env("SCCM_USER", required=True)
    password = env("SCCM_PASSWORD", required=True)

    try:
        import requests  # noqa: WPS433 -- lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(user, password)
    ntlm_auth = _maybe_ntlm_auth(user, password)
    if ntlm_auth is not None:
        log("requests_ntlm available; using NTLM auth alongside HTTP Basic header")

    member_ids = []
    if collection_id:
        members = fetch_collection_members(requests, host, collection_id, headers, auth=ntlm_auth)
        for entry in members:
            rid = resource_id_for(entry)
            if rid is not None:
                member_ids.append(rid)
        log(f"Resolved {len(member_ids)} resource ids from collection " f"{collection_id}")
        if not member_ids:
            log(f"collection {collection_id} has no resolvable members; " "no systems to enumerate")

    systems = fetch_systems(requests, host, site_code, member_ids or None, headers, auth=ntlm_auth)

    log(
        f"Processing {len(systems)} SCCM systems (site_code="
        f"{site_code or '<all>'}, collection_id="
        f"{collection_id or '<all>'}, min_severity={min_severity})"
    )

    scoping = {"site_code": site_code, "collection_id": collection_id}

    # Per-host compliance lookup -> map ResourceID -> set(CI_ID).
    compliance_by_resource = {}
    all_ci_ids = set()
    for system in systems:
        rid = resource_id_for(system)
        if rid is None:
            continue
        records = fetch_compliance_status(requests, host, rid, headers, auth=ntlm_auth)
        ci_ids = set()
        for rec in records:
            ci = ci_id_for(rec)
            if ci is not None:
                ci_ids.add(ci)
        compliance_by_resource[rid] = ci_ids
        all_ci_ids.update(ci_ids)

    # Resolve every distinct missing CI_ID to its SMS_SoftwareUpdate
    # metadata record in one batched walk.
    update_records = fetch_software_updates(requests, host, all_ci_ids or None, headers, auth=ntlm_auth)
    update_by_ci = {}
    for entry in update_records:
        ci = ci_id_for(entry)
        if ci is not None:
            update_by_ci[ci] = entry

    hosts = []
    for system in systems:
        rid = resource_id_for(system)
        if rid is None:
            continue
        ci_ids = compliance_by_resource.get(rid, set())
        vulns = []
        for ci in sorted(ci_ids):
            update_rec = update_by_ci.get(ci)
            if not isinstance(update_rec, dict):
                # The update exists in compliance status but the
                # catalogue lookup didn't resolve it (deployment was
                # revoked between calls, or the CI_ID is a
                # configuration item rather than a software update).
                # Skip it rather than emit an empty vulnerability.
                continue
            # Add the resource_id / machine context so build_vulnerability
            # surfaces it in the description / refs.
            enriched = dict(update_rec)
            enriched.setdefault("ResourceID", rid)
            machine_name = system.get("Name") or system.get("NetbiosName") or ""
            if machine_name:
                enriched.setdefault("MachineName", machine_name)
            sites = system.get("SMSAssignedSites")
            if isinstance(sites, list) and sites:
                enriched.setdefault("SMSAssignedSite", str(sites[0]).strip())
            elif site_code:
                enriched.setdefault("SMSAssignedSite", site_code)
            if collection_id:
                enriched.setdefault("CollectionID", collection_id)
            built = build_vulnerability(enriched)
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        hosts.append(build_host(rid, system, vulns, scoping))

    if not hosts:
        # Still emit a synthetic placeholder host so the Faraday
        # workspace records that the SCCM query was processed even
        # when zero matching systems came back.
        hosts.append(
            build_host(
                collection_id or site_code or "sccm",
                {"Name": collection_id or site_code or "sccm"},
                [],
                scoping,
            )
        )

    params_bits = []
    if site_code:
        params_bits.append(f"site_code={site_code}")
    if collection_id:
        params_bits.append(f"collection_id={collection_id}")
    params_bits.append(f"min_severity={min_severity}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "sccm",
            "command": "sccm",
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
