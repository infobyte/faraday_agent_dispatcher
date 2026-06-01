#!/usr/bin/env python
"""Microsoft Intune (Endpoint Manager) REST importer.

Pulls managed devices, device compliance policies, and device
configuration assignments from Microsoft Intune via the Microsoft
Graph v1.0 REST surface
(``GET /deviceManagement/managedDevices``,
``GET /deviceManagement/deviceCompliancePolicies``,
``GET /deviceManagement/deviceConfigurations/{id}/assignments``) and
emits Faraday bulk-create JSON to stdout. Each managed device becomes
one Faraday host (``ip`` = ``device.ipAddressV4`` when present,
falling back to synthetic ``0.0.0.0`` because Intune devices are often
NAT-ed and only carry private IPs); non-compliance findings attach as
Faraday vulnerabilities — one per (device, compliance reason) pair
with engine prefix ``[EDR]``.

Endpoints used:
  POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
      -> Azure AD OAuth2 client_credentials. Returns
      ``{"access_token": "...", "expires_in": N, "token_type": "Bearer"}``;
      subsequent calls send ``Authorization: Bearer <access_token>``.
      Scope is fixed to ``https://graph.microsoft.com/.default`` — the
      Microsoft Graph control plane that fronts Intune.
  GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices
      -> primary managed-device query. Returns the canonical Graph
      ``{"value": [...], "@odata.nextLink": "..."}`` envelope;
      ``fetch_pages`` walks the next-link until exhausted or
      ``MAX_PAGES`` is hit. When ``INTUNE_COMPLIANCE_STATE_FILTER`` is
      set the query adds ``$filter=complianceState eq '...'``; when
      ``INTUNE_PLATFORM`` is set the filter chains
      ``operatingSystem eq '...'`` (combined with ``and`` if both
      filters apply).
  GET https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies
      -> compliance policy catalogue; surfaced as references on
      vulnerabilities so operators can pivot from a non-compliant
      device to the controlling policy.
  GET https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/{id}/assignments
      -> per-configuration assignment list; surfaced so each
      configuration assignment that targets a device's group can be
      pivoted from the device record. Intune's Graph surface does not
      expose a single "all assignments" endpoint, so we walk the
      catalogue once and resolve assignments per configuration.

Auth: Intune lives behind Microsoft Graph and uses Azure AD
client_credentials. A service-principal app registration is created
in the Azure portal with the ``DeviceManagementManagedDevices.Read.All``
and ``DeviceManagementConfiguration.Read.All`` application (not
delegated) permissions granted at the tenant scope and admin consent
applied. Credentials are exposed to the dispatcher as
``AZURE_TENANT_ID`` (the directory id), ``AZURE_CLIENT_ID`` (the
service principal application id), and ``AZURE_CLIENT_SECRET`` (the
client secret). The token exchange is
``POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token``
with form body ``grant_type=client_credentials&client_id=...&client_secret=...&scope=https://graph.microsoft.com/.default``.  # noqa: E501
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

GRAPH_HOST = "https://graph.microsoft.com"
GRAPH_API_VERSION = "v1.0"
TOKEN_SCOPE = "https://graph.microsoft.com/.default"

TIMEOUT = 60
MAX_PAGES = 200

# Intune surfaces compliance/configuration "severity" via the
# compliance state plus, on subassessments, a numeric score. The string
# enum maps cleanly onto Faraday buckets; Faraday-side synonyms are
# accepted so re-emitted findings still bucket correctly.
INTUNE_STRING_SEVERITY = {
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

# Intune complianceState enum (per Graph docs):
#   unknown | compliant | noncompliant | conflict | error | inGracePeriod | configManager
# We bucket the non-success states into Faraday severity tiers. Devices
# that are compliant don't emit a vulnerability — they still show up as
# hosts so the inventory side stays complete.
COMPLIANCE_SEVERITY = {
    "compliant": None,
    "noncompliant": "high",
    "non_compliant": "high",
    "conflict": "medium",
    "error": "high",
    "ingraceperiod": "low",
    "in_grace_period": "low",
    "configmanager": "info",
    "config_manager": "info",
    "unknown": "info",
}

# Intune compliance state -> Faraday status. Non-compliant /
# conflict / error / in-grace-period collapse to open; compliant /
# configManager / unknown stay closed (the latter two because we
# don't emit a vulnerability for them — but keep the mapping
# defensive in case build_vulnerability is called with one anyway).
COMPLIANCE_STATUS = {
    "compliant": "closed",
    "noncompliant": "open",
    "non_compliant": "open",
    "conflict": "open",
    "error": "open",
    "ingraceperiod": "open",
    "in_grace_period": "open",
    "configmanager": "closed",
    "config_manager": "closed",
    "unknown": "closed",
}

# Filter args.
VALID_COMPLIANCE_STATE_FILTER = ("compliant", "noncompliant", "unknown")
COMPLIANCE_STATE_FILTER_ALIASES = {
    "compliant": "compliant",
    "noncompliant": "noncompliant",
    "non_compliant": "noncompliant",
    "non-compliant": "noncompliant",
    "unknown": "unknown",
}

# Microsoft Graph operatingSystem strings (per the managedDevice
# resource doc): "Windows", "macOS", "iOS", "Android", plus a handful
# of variants. We normalise to the canonical Graph token so the
# server-side $filter comparison matches.
VALID_PLATFORM = ("windows", "macos", "ios", "android")
PLATFORM_TO_GRAPH = {
    "windows": "Windows",
    "win": "Windows",
    "win32": "Windows",
    "win64": "Windows",
    "macos": "macOS",
    "mac": "macOS",
    "osx": "macOS",
    "darwin": "macOS",
    "ios": "iOS",
    "iphone": "iOS",
    "ipad": "iOS",
    "android": "Android",
}


def log(msg):
    print(f"{datetime.utcnow()} - MsIntune: {msg}", file=sys.stderr, flush=True)


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


def severity_from_intune(value, cvss=None):
    """Map an Intune severity / compliance state to a Faraday bucket.

    Accepts the canonical Intune compliance enum (compliant /
    noncompliant / conflict / error / inGracePeriod / unknown), the
    free-form string enum used by configuration profile state
    (High / Medium / Low / Informational) plus Faraday-side synonyms,
    and falls back to CVSS bucketing on ``cvss`` when the primary
    value is missing or unrecognised. Numeric inputs are interpreted as
    CVSS base scores so subassessments that surface a bare score still
    bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        text_compact = text.replace(" ", "").replace("-", "").replace("_", "")
        if text_compact in COMPLIANCE_SEVERITY:
            mapped = COMPLIANCE_SEVERITY[text_compact]
            # Uninformative states (compliant, configManager, unknown
            # -> 'info' / None) let CVSS override when present so
            # re-emitted vendor shapes that surface a numeric score
            # still bucket correctly. Informative states
            # (noncompliant -> high, conflict -> medium, error -> high,
            # inGracePeriod -> low) take precedence over CVSS.
            uninformative = text_compact in ("unknown", "configmanager", "compliant")
            if mapped is not None and not uninformative:
                return mapped
            if cvss is not None:
                return severity_from_cvss(cvss)
            if mapped is not None:
                return mapped
            return "info"
        if text in INTUNE_STRING_SEVERITY:
            return INTUNE_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_intune(item):
    """Derive Faraday status from a managed device payload.

    Devices carry ``complianceState`` (unknown / compliant /
    noncompliant / conflict / error / inGracePeriod / configManager).
    Non-compliant + conflict + error + in-grace-period -> open;
    compliant + configManager + unknown -> closed. Falls back to a
    generic ``status`` / ``state`` field for re-emitted shapes.
    """
    if not isinstance(item, dict):
        return "open"
    for key in ("complianceState", "compliance_state", "ComplianceState"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            keyed = raw.strip().lower().replace(" ", "_").replace("-", "_")
            compact = keyed.replace("_", "")
            if compact in COMPLIANCE_STATUS:
                return COMPLIANCE_STATUS[compact]
    for key in ("status", "state", "Status", "State"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            keyed = raw.strip().lower().replace(" ", "_").replace("-", "_")
            compact = keyed.replace("_", "")
            if compact in COMPLIANCE_STATUS:
                return COMPLIANCE_STATUS[compact]
            # Standard open / closed pass-through.
            if compact in ("open", "active", "new"):
                return "open"
            if compact in ("closed", "resolved", "fixed", "remediated"):
                return "closed"
            if compact in (
                "dismissed",
                "suppressed",
                "ignored",
                "wontfix",
                "riskaccepted",
                "accepted",
                "falsepositive",
            ):
                return "risk-accepted"
    return "open"


def validate_min_severity(value):
    """Validate INTUNE_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied
    beyond the default). Accepts the canonical Faraday buckets plus
    Intune-side synonyms.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    bucket = INTUNE_STRING_SEVERITY.get(text)
    if bucket is None:
        log(f"INTUNE_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_compliance_state_filter(value):
    """Validate INTUNE_COMPLIANCE_STATE_FILTER.

    Accepts ``compliant | nonCompliant | unknown`` plus a couple of
    common alias / casing variants. None / blank / garbage -> None
    (no filter; query every device the principal can read).
    Returns the canonical Graph token (``compliant`` /
    ``noncompliant`` / ``unknown``) suitable for the OData
    ``$filter=complianceState eq '...'`` comparison.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    if not text:
        return None
    keyed = text.lower().replace(" ", "_").replace("-", "_")
    if keyed in COMPLIANCE_STATE_FILTER_ALIASES:
        return COMPLIANCE_STATE_FILTER_ALIASES[keyed]
    log(f"INTUNE_COMPLIANCE_STATE_FILTER '{value}' not recognised; dropping filter")
    return None


def validate_platform(value):
    """Validate INTUNE_PLATFORM.

    Accepts ``windows | macos | ios | android`` plus aliases (win /
    osx / darwin / iphone / ipad). None / blank / garbage -> None
    (no filter). Returns the canonical Graph ``operatingSystem`` token
    (``Windows`` / ``macOS`` / ``iOS`` / ``Android``) suitable for the
    OData ``$filter=operatingSystem eq '...'`` comparison.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    if not text:
        return None
    keyed = text.lower().replace(" ", "").replace("-", "").replace("_", "")
    if keyed in PLATFORM_TO_GRAPH:
        return PLATFORM_TO_GRAPH[keyed]
    log(f"INTUNE_PLATFORM '{value}' not recognised; dropping filter")
    return None


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def build_odata_filter(compliance_state, platform):
    """Build the ``$filter=...`` clause for ``/managedDevices``.

    Returns a query-string filter value (without the leading
    ``$filter=``) or ``None`` when no filters apply. Both filters are
    joined with ``and`` per the OData v4 spec.
    """
    parts = []
    if compliance_state:
        parts.append(f"complianceState eq '{compliance_state}'")
    if platform:
        parts.append(f"operatingSystem eq '{platform}'")
    if not parts:
        return None
    return " and ".join(parts)


def build_graph_url(path_suffix, odata_filter=None):
    """Build a Microsoft Graph URL for an Intune endpoint."""
    base = f"{GRAPH_HOST}/{GRAPH_API_VERSION}/{path_suffix.lstrip('/')}"
    if odata_filter:
        # Graph requires the filter value to be URL-encoded; lazy
        # imports keep helpers reachable without requests installed.
        from urllib.parse import quote

        return f"{base}?$filter={quote(odata_filter)}"
    return base


def cvss_score(item):
    """Pull a numeric CVSS score from an Intune payload.

    Intune device records don't carry CVSS directly, but compliance
    policy state shapes occasionally surface vendor-supplied scores
    in ``additionalData.cvss`` or ``additionalData.score``. Walk those
    surfaces defensively so re-emitted findings still bucket correctly.
    """
    if not isinstance(item, dict):
        return None
    candidates = [item]
    additional = item.get("additionalData") or item.get("additional_data")
    if isinstance(additional, dict):
        candidates.insert(0, additional)
    for src in candidates:
        if not isinstance(src, dict):
            continue
        for key in ("cvssScore", "cvss_score", "score", "baseScore", "base_score"):
            v = src.get(key)
            if v is None or isinstance(v, (dict, list, bool)):
                continue
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
        for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2"):
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
            elif isinstance(nested, list):
                for entry in nested:
                    if not isinstance(entry, dict):
                        continue
                    for k in ("baseScore", "base_score", "score", "base"):
                        v = entry.get(k)
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
    additional = item.get("additionalData") or item.get("additional_data")
    if isinstance(additional, dict):
        candidates.insert(0, additional)
    for src in candidates:
        if not isinstance(src, dict):
            continue
        for k in ("cvssVector", "cvss_vector", "vector", "vectorString", "vector_string"):
            s = src.get(k)
            if isinstance(s, str) and s.strip():
                return s.strip()
        for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3"):
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
            elif isinstance(nested, list):
                for entry in nested:
                    if not isinstance(entry, dict):
                        continue
                    for k in ("vector", "vectorString", "vector_string"):
                        s = entry.get(k)
                        if isinstance(s, str) and s.strip():
                            return s.strip()
    return ""


def collect_cves(item):
    """Pull CVE-* ids out of an Intune payload.

    Walks ``additionalData.cve`` / ``cves`` / ``aliases`` surfaces and
    falls back to free-form description / displayName scans. Intune
    devices rarely carry CVEs directly, but compliance / config state
    re-shapes occasionally embed them, so the collector stays defensive.
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

    additional = item.get("additionalData") or item.get("additional_data") or {}
    if not isinstance(additional, dict):
        additional = {}

    for src in (item, additional):
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
        "displayName",
        "description",
        "title",
        "Title",
        "settingName",
        "settingDisplayName",
        "errorDescription",
        "remediation",
        "remediationDescription",
    ):
        v = item.get(key)
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)

    return found


def collect_refs(item, policies=None, assignments=None):
    """Walk an Intune device for advisory URLs / pivots.

    ``policies`` is the compliance-policy catalogue (a list of
    Graph policy objects) and is used to surface a
    ``IntunePolicy: {displayName}`` pivot for every policy that targets
    the device's platform. ``assignments`` is a list of
    ``IntuneAssignment: {configDisplayName}`` strings already resolved
    by the caller and surfaced as references verbatim.
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

    additional = item.get("additionalData") or item.get("additional_data") or {}
    if not isinstance(additional, dict):
        additional = {}

    for src in (item, additional):
        if not isinstance(src, dict):
            continue
        for source_key in ("cweId", "cwe_id", "cwe", "CWE"):
            add_cwe(src.get(source_key))
        for source_key in ("cwes", "cweIds", "cwe_ids", "CWEs"):
            items = src.get(source_key)
            if isinstance(items, list):
                for it in items:
                    add_cwe(it)

    # Intune-side pivots — device id, user principal, management agent.
    did = item.get("id") or item.get("Id") or item.get("deviceId") or item.get("DeviceId")
    if isinstance(did, str) and did.strip():
        add(f"IntuneDevice: {did.strip()}")

    upn = item.get("userPrincipalName") or item.get("UserPrincipalName") or item.get("userId")
    if isinstance(upn, str) and upn.strip():
        add(f"IntuneUser: {upn.strip()}")

    mgmt = item.get("managementAgent") or item.get("ManagementAgent")
    if isinstance(mgmt, str) and mgmt.strip():
        add(f"IntuneAgent: {mgmt.strip()}")

    enrolled = item.get("enrolledByUserId") or item.get("EnrolledByUserId")
    if isinstance(enrolled, str) and enrolled.strip():
        add(f"IntuneEnroller: {enrolled.strip()}")

    # Compliance policy pivots (collected by the caller against the
    # catalogue; we surface the policy displayName as a refs entry).
    if isinstance(policies, list):
        platform = (item.get("operatingSystem") or "").strip().lower()
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            name = policy.get("displayName") or policy.get("DisplayName") or policy.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            policy_type = policy.get("@odata.type") or policy.get("odata_type") or ""
            if isinstance(policy_type, str):
                ptype_lower = policy_type.lower()
                if platform and platform not in ptype_lower and ptype_lower:
                    # Skip policies that clearly target a different
                    # platform (Graph uses
                    # microsoft.graph.windows10CompliancePolicy and
                    # similar). Empty type -> include defensively.
                    keep = False
                    for token in (platform, platform[:3]):
                        if token and token in ptype_lower:
                            keep = True
                            break
                    if not keep:
                        continue
            add(f"IntunePolicy: {name.strip()}")

    # Configuration assignment pivots (resolved upstream into
    # "IntuneAssignment: {displayName}" strings).
    if isinstance(assignments, list):
        for entry in assignments:
            if isinstance(entry, str) and entry.strip():
                add(entry.strip())

    # additionalData.remediationUrl / supportUrl etc.
    for src in (item, additional):
        if not isinstance(src, dict):
            continue
        for key in (
            "remediationUrl",
            "remediation_url",
            "supportUrl",
            "support_url",
            "helpUrl",
            "help_url",
            "settingUrl",
            "setting_url",
        ):
            v = src.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    # references / links lists shared with other CSPM / EDR shapes.
    for key in ("references", "links", "References", "Links"):
        entry = item.get(key)
        if entry is None:
            entry = additional.get(key)
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
    """Build a friendly label for an Intune managed device."""
    if not isinstance(item, dict):
        return ""
    name = item.get("deviceName") or item.get("DeviceName") or item.get("managedDeviceName")
    if isinstance(name, str) and name.strip():
        return name.strip()
    upn = item.get("userPrincipalName") or item.get("UserPrincipalName") or item.get("emailAddress")
    if isinstance(upn, str) and upn.strip():
        return upn.strip()
    did = item.get("id") or item.get("Id") or item.get("deviceId")
    if isinstance(did, str) and did.strip():
        return did.strip()
    return ""


def vuln_label(item):
    """Build the leading title fragment for an Intune finding."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "displayName",
        "DisplayName",
        "settingDisplayName",
        "settingName",
        "title",
        "Title",
        "errorDescription",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    state = item.get("complianceState") or item.get("compliance_state")
    if isinstance(state, str) and state.strip():
        return f"Device {state.strip()}"
    name = device_label(item)
    if name:
        return f"Device {name}"
    return "Intune finding"


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


def build_vulnerability(item, policies=None, assignments=None):
    """Build a Faraday vulnerability dict from a managed-device record.

    ``policies`` is the device-compliance-policy catalogue (list of
    Graph policy objects) and ``assignments`` is the list of
    ``IntuneAssignment: {displayName}`` pivot strings already resolved
    by the caller.

    Devices with ``complianceState == compliant`` return ``None`` —
    the inventory side picks them up via ``build_host`` but they don't
    surface a vulnerability. Devices in any non-success state surface
    a single ``[EDR] Device <state>`` vulnerability whose severity is
    bucketed via ``COMPLIANCE_SEVERITY`` and whose description carries
    every device + compliance enrichment available.
    """
    if not isinstance(item, dict):
        return None

    state = item.get("complianceState") or item.get("compliance_state") or "unknown"
    if isinstance(state, str):
        state_compact = state.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
    else:
        state_compact = "unknown"

    if state_compact == "compliant":
        # Compliant devices have no finding; the host still appears.
        return None

    score = cvss_score(item)
    severity = severity_from_intune(state, score)
    status = status_from_intune(item)

    name_label = device_label(item)
    vlabel = vuln_label(item)
    raw_name = (
        f"{vlabel} on {name_label}" if name_label and name_label != vlabel and vlabel else (vlabel or name_label)
    )
    name = f"[EDR] {raw_name}" if raw_name else "[EDR] Intune finding"

    desc_parts = []
    description = item.get("description") or item.get("Description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label, key in (
        ("device_id", "id"),
        ("device_name", "deviceName"),
        ("user_principal", "userPrincipalName"),
        ("user_display", "userDisplayName"),
        ("email", "emailAddress"),
        ("compliance_state", "complianceState"),
        ("management_agent", "managementAgent"),
        ("management_state", "managementState"),
        ("operating_system", "operatingSystem"),
        ("os_version", "osVersion"),
        ("model", "model"),
        ("manufacturer", "manufacturer"),
        ("serial_number", "serialNumber"),
        ("imei", "imei"),
        ("meid", "meid"),
        ("phone_number", "phoneNumber"),
        ("ip_address", "ipAddressV4"),
        ("subnet_address", "subnetAddress"),
        ("wifi_mac_address", "wiFiMacAddress"),
        ("ethernet_mac_address", "ethernetMacAddress"),
        ("compliance_grace_period_expiration", "complianceGracePeriodExpirationDateTime"),
        ("enrolled_date", "enrolledDateTime"),
        ("last_sync", "lastSyncDateTime"),
        ("device_category", "deviceCategoryDisplayName"),
        ("encryption_state", "isEncrypted"),
        ("supervised", "isSupervised"),
        ("jail_broken", "jailBroken"),
        ("device_enrollment_type", "deviceEnrollmentType"),
        ("device_registration_state", "deviceRegistrationState"),
        ("activation_lock_bypass_code", "activationLockBypassCode"),
        ("azure_ad_device_id", "azureADDeviceId"),
        ("azure_ad_registered", "azureADRegistered"),
        ("aad_registered", "aadRegistered"),
        ("autopilot_enrolled", "autopilotEnrolled"),
        ("compliance_state_detail", "deviceHealthAttestationState"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label}: {v}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(item)
    if vector:
        desc_parts.append(f"vector: {vector}")

    additional = item.get("additionalData") or item.get("additional_data")
    if isinstance(additional, dict):
        for k, v in additional.items():
            if v is None or v == "":
                continue
            if k.lower() in (
                "cve",
                "cveid",
                "cves",
                "cwe",
                "cwes",
                "cvss",
                "cvss_score",
                "cvssscore",
                "score",
                "basescore",
                "vector",
                "cvssvector",
                "references",
                "remediation",
            ):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"{k}: {_serialise(v)}")
            else:
                desc_parts.append(f"{k}: {v}")

    cves = collect_cves(item)
    refs = collect_refs(item, policies=policies, assignments=assignments)

    resolution = ""
    rem = item.get("remediation") or item.get("remediationDescription") or item.get("remediation_description")
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution and isinstance(additional, dict):
        rem_extra = (
            additional.get("remediation")
            or additional.get("remediationSteps")
            or additional.get("remediationDescription")
        )
        if isinstance(rem_extra, list):
            bits = [str(r).strip() for r in rem_extra if str(r).strip()]
            if bits:
                resolution = "\n".join(bits)
        elif isinstance(rem_extra, str) and rem_extra.strip():
            resolution = rem_extra.strip()
    if not resolution:
        # Default operator guidance — Intune findings don't carry a
        # remediation string, the action is always "bring the device
        # into compliance with the assigned policy".
        if state_compact == "noncompliant":
            resolution = (
                "Review the Intune compliance policy assigned to this device and "
                "remediate the failing setting (Intune portal -> Devices -> All "
                "devices -> select device -> Device compliance)."
            )
        elif state_compact == "conflict":
            resolution = (
                "Resolve the policy conflict by ensuring only one Intune compliance "
                "policy targets the device's assigned group, or align the conflicting "
                "policies on shared settings."
            )
        elif state_compact == "error":
            resolution = (
                "Investigate the Intune error state — check the device's "
                "Management agent state and the per-setting status for failure "
                "details."
            )

    external_id = str(item.get("id") or item.get("Id") or item.get("deviceId") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Intune finding {external_id}",
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
        "tags": ["ms_intune", "edr", "endpoint-edr"],
    }


def host_bucket_key(item):
    """Pick a stable bucket key for a managed-device record.

    Intune devices have a stable ``id`` (the managed device GUID); we
    use that verbatim. Falls back to ``deviceName`` so re-emitted
    shapes still bucket sensibly. ``__unknown__`` for anything that
    can't be keyed.
    """
    if not isinstance(item, dict):
        return "__unknown__"
    for key in ("id", "Id", "deviceId", "DeviceId"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("deviceName", "DeviceName"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "__unknown__"


def device_ip(item):
    """Pick the host IP from a managed-device record.

    Intune surfaces the wired/wireless IPv4 in ``ipAddressV4``. Falls
    back to ``0.0.0.0`` when missing because Intune-managed mobile
    devices are commonly NAT-ed and only carry private addresses or no
    address at all.
    """
    if not isinstance(item, dict):
        return "0.0.0.0"
    for key in ("ipAddressV4", "ip_address_v4", "ipAddress", "ip_address"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "0.0.0.0"


def device_mac(item):
    if not isinstance(item, dict):
        return ""
    for key in ("wiFiMacAddress", "ethernetMacAddress", "wifiMacAddress", "macAddress"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def device_os(item):
    if not isinstance(item, dict):
        return ""
    os_name = item.get("operatingSystem") or item.get("OperatingSystem") or ""
    os_version = item.get("osVersion") or item.get("OsVersion") or ""
    if os_name and os_version:
        return f"{os_name} {os_version}".strip()
    return str(os_name or os_version or "").strip()


def build_host(bucket_key, sample_item, vulns):
    """Build a Faraday host record for the supplied managed-device bucket."""
    label = device_label(sample_item) if sample_item else ""
    hostname = ""
    if label and bucket_key and bucket_key != "__unknown__":
        hostname = label
    elif label:
        hostname = label
    elif bucket_key and bucket_key != "__unknown__":
        hostname = bucket_key

    ip = device_ip(sample_item) if sample_item else "0.0.0.0"
    mac = device_mac(sample_item) if sample_item else ""
    os_str = device_os(sample_item) if sample_item else ""

    desc_parts = []
    if bucket_key and bucket_key != "__unknown__":
        desc_parts.append(f"device_id={bucket_key}")

    if isinstance(sample_item, dict):
        for label_key, key in (
            ("device_name", "deviceName"),
            ("user_principal", "userPrincipalName"),
            ("user_display", "userDisplayName"),
            ("operating_system", "operatingSystem"),
            ("os_version", "osVersion"),
            ("model", "model"),
            ("manufacturer", "manufacturer"),
            ("serial_number", "serialNumber"),
            ("compliance_state", "complianceState"),
            ("management_agent", "managementAgent"),
            ("management_state", "managementState"),
            ("last_sync", "lastSyncDateTime"),
            ("enrolled_date", "enrolledDateTime"),
            ("device_category", "deviceCategoryDisplayName"),
        ):
            v = sample_item.get(key)
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


def fetch_access_token(requests_module, tenant_id, client_id, client_secret):
    """Exchange Azure AD service-principal credentials for a Graph bearer."""
    if not tenant_id or not client_id or not client_secret:
        return None
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": TOKEN_SCOPE,
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        resp = requests_module.post(url, data=payload, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any requests/network exc
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Azure AD token request rejected (401). Check AZURE_CLIENT_ID / AZURE_CLIENT_SECRET.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Azure AD token request failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log("Azure AD token response was not JSON")
        return None
    token = body.get("access_token") or body.get("accessToken") or body.get("token")
    if not token:
        log("Azure AD token response missing access_token")
        return None
    return token


def fetch_pages(requests_module, url, headers, max_pages=MAX_PAGES):
    """Walk a Graph-paged ``{"value": [...], "@odata.nextLink": "..."}`` envelope."""
    out = []
    next_url = url
    pages = 0
    while next_url and pages < max_pages:
        try:
            resp = requests_module.get(next_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            log(f"GET {next_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Graph request rejected (401). Bearer expired or invalid.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Graph request rejected (403). Check DeviceManagement* application permissions.")
            return out
        if resp.status_code == 404:
            log(f"Graph request 404 for {next_url} — endpoint not found")
            return out
        if resp.status_code >= 400:
            log(f"Graph request failed ({resp.status_code}) for {next_url}: {resp.text[:500]}")
            return out
        try:
            body = resp.json()
        except ValueError:
            log(f"Graph response was not JSON ({next_url})")
            return out
        if not isinstance(body, dict):
            return out
        value = body.get("value")
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict):
                    out.append(entry)
        next_url = body.get("@odata.nextLink") or body.get("nextLink") or None
        pages += 1
    if pages >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def fetch_assignment_labels(requests_module, configurations, headers):
    """Resolve ``IntuneAssignment: {displayName}`` pivot strings.

    Walks the device-configuration catalogue and fetches each
    configuration's assignments. Returns a list of pivot strings —
    one per (configuration, assignment) pair — so the caller can pass
    them into ``collect_refs`` for every device. Failures on a single
    assignment list are logged + skipped; the global list still
    surfaces every assignment that did come back.
    """
    labels = []
    seen = set()
    if not isinstance(configurations, list):
        return labels
    for cfg in configurations:
        if not isinstance(cfg, dict):
            continue
        cfg_id = cfg.get("id") or cfg.get("Id")
        cfg_name = cfg.get("displayName") or cfg.get("DisplayName") or cfg_id
        if not isinstance(cfg_id, str) or not cfg_id.strip():
            continue
        url = build_graph_url(f"deviceManagement/deviceConfigurations/{cfg_id}/assignments")
        page = fetch_pages(requests_module, url, headers, max_pages=10)
        for entry in page:
            if not isinstance(entry, dict):
                continue
            label = f"IntuneAssignment: {cfg_name}" if cfg_name else None
            if label and label not in seen:
                seen.add(label)
                labels.append(label)
    return labels


def main():
    started = time.time()

    state_filter = validate_compliance_state_filter(env("EXECUTOR_CONFIG_INTUNE_COMPLIANCE_STATE_FILTER"))
    platform = validate_platform(env("EXECUTOR_CONFIG_INTUNE_PLATFORM"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_INTUNE_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    tenant_id = env("AZURE_TENANT_ID")
    client_id = env("AZURE_CLIENT_ID")
    client_secret = env("AZURE_CLIENT_SECRET")
    if not tenant_id or not client_id or not client_secret:
        log("AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_access_token(requests, tenant_id, client_id, client_secret)
    if not token:
        log("Failed to acquire Azure AD access token; exiting")
        sys.exit(1)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    odata_filter = build_odata_filter(state_filter, platform)
    devices_url = build_graph_url("deviceManagement/managedDevices", odata_filter)
    policies_url = build_graph_url("deviceManagement/deviceCompliancePolicies")
    configurations_url = build_graph_url("deviceManagement/deviceConfigurations")

    devices = fetch_pages(requests, devices_url, headers)
    policies = fetch_pages(requests, policies_url, headers)
    configurations = fetch_pages(requests, configurations_url, headers)
    assignment_labels = fetch_assignment_labels(requests, configurations, headers)
    log(
        f"Processing {len(devices)} Intune managed devices "
        f"(compliance_filter={state_filter or 'ALL'}, platform={platform or 'ALL'}, "
        f"policies={len(policies)}, configurations={len(configurations)}, "
        f"assignments={len(assignment_labels)}, min_severity={min_severity})"
    )

    buckets = {}
    sample_resources = {}
    for device in devices:
        key = host_bucket_key(device)
        buckets.setdefault(key, []).append(device)
        if key not in sample_resources:
            sample_resources[key] = device

    hosts = []
    for key, items in buckets.items():
        vulns = []
        for device in items:
            built = build_vulnerability(device, policies=policies, assignments=assignment_labels)
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        sample = sample_resources.get(key)
        # We surface a host record per device — even compliant devices
        # so the inventory side stays complete; ``vulns`` may be empty.
        hosts.append(build_host(key, sample, vulns))

    params_bits = [f"min_severity={min_severity}"]
    if state_filter:
        params_bits.append(f"compliance_state={state_filter}")
    if platform:
        params_bits.append(f"platform={platform}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "ms_intune",
            "command": "ms_intune",
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
