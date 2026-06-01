#!/usr/bin/env python
"""Microsoft Defender for Cloud (Azure CSPM / CWP) REST importer.

Pulls security alerts and security assessments (recommendations) from
Microsoft Defender for Cloud via the canonical Azure REST surface
(``GET /subscriptions/{sub}/providers/Microsoft.Security/alerts`` and
``GET /subscriptions/{sub}/providers/Microsoft.Security/assessments``)
and emits Faraday bulk-create JSON to stdout. Each affected Azure
resource (resolved from ``alert.properties.resourceIdentifiers[].azureResourceId``
or ``assessment.properties.resourceDetails.id``) becomes one Faraday
host (``ip`` = synthetic ``0.0.0.0`` because Defender findings live on
ARM resources, not on IPs); per-resource alerts / assessments attach as
Faraday vulnerabilities — one per Defender object ``name`` with engine
prefix ``[CNAPP]``.

Endpoints used:
  POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
      -> Azure AD OAuth2 client_credentials. Returns
      ``{"access_token": "...", "expires_in": N, "token_type": "Bearer"}``;
      subsequent calls send ``Authorization: Bearer <access_token>``.
      Scope is fixed to ``https://management.azure.com/.default`` — the
      ARM control plane that fronts Defender for Cloud.
  GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Security/alerts?api-version=2022-01-01
      -> primary alert query. Returns a paged ``{"value": [...], "nextLink": "..."}``
      envelope; ``fetch_pages`` walks ``nextLink`` until exhausted or
      ``MAX_PAGES`` is hit. When ``DEFENDER_RESOURCE_GROUP`` is set the
      path narrows to
      ``/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Security/alerts``
      so the ARM authorization layer scopes the query at the RG instead
      of the whole subscription.
  GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Security/assessments?api-version=2020-01-01
      -> assessments (recommendations / posture findings) query. Same
      ``{"value": [...], "nextLink": "..."}`` paging shape. Same RG
      narrowing as above when ``DEFENDER_RESOURCE_GROUP`` is set.

Auth: Defender for Cloud lives behind the standard Azure Resource
Manager (ARM) control plane and uses Azure AD client_credentials. A
service-principal app registration is created in the Azure portal with
the ``Security Reader`` (or ``Security Admin``) role assigned at the
subscription scope. Credentials are exposed to the dispatcher as
``AZURE_TENANT_ID`` (the directory id), ``AZURE_CLIENT_ID`` (the
service principal application id), and ``AZURE_CLIENT_SECRET`` (the
client secret). The token exchange is
``POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token``
with form body ``grant_type=client_credentials&client_id=...&client_secret=...&scope=https://management.azure.com/.default``.  # noqa: E501
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

ARM_HOST = "https://management.azure.com"
ALERTS_API_VERSION = "2022-01-01"
ASSESSMENTS_API_VERSION = "2020-01-01"
TOKEN_SCOPE = "https://management.azure.com/.default"

TIMEOUT = 60
MAX_PAGES = 200

# Defender for Cloud uses High / Medium / Low / Informational across
# alerts and assessments; accept the usual Faraday-side synonyms.
DEFENDER_STRING_SEVERITY = {
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

# Alert status enum (Defender for Cloud): Active / Resolved / Dismissed
# / InProgress / Closed. Assessment status code: Healthy / Unhealthy /
# NotApplicable. We collapse both into Faraday's open / closed /
# risk-accepted scheme.
DEFENDER_STATUS_TO_FARADAY = {
    "active": "open",
    "open": "open",
    "new": "open",
    "reopened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "investigating": "open",
    "unhealthy": "open",
    "resolved": "closed",
    "closed": "closed",
    "fixed": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "healthy": "closed",
    "notapplicable": "closed",
    "not_applicable": "closed",
    "dismissed": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "expired": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - MsDefenderForCloud: {msg}", file=sys.stderr, flush=True)


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


def severity_from_defender(value, cvss=None):
    """Map a Defender severity to a Faraday bucket.

    Accepts Defender's string enum (High / Medium / Low / Informational
    plus the usual Faraday synonyms) and falls back to CVSS bucketing on
    ``cvss`` when the primary value is missing or unrecognised. Numeric
    inputs are interpreted as CVSS base scores so subassessments that
    surface a bare score still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in DEFENDER_STRING_SEVERITY:
            return DEFENDER_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def _normalise_status_token(text):
    if not isinstance(text, str):
        return None
    raw = text.strip().lower()
    if not raw:
        return None
    keyed = raw.replace(" ", "_").replace("-", "_")
    if keyed in DEFENDER_STATUS_TO_FARADAY:
        return DEFENDER_STATUS_TO_FARADAY[keyed]
    compact = raw.replace(" ", "").replace("-", "").replace("_", "")
    if compact in DEFENDER_STATUS_TO_FARADAY:
        return DEFENDER_STATUS_TO_FARADAY[compact]
    return None


def status_from_defender(item):
    """Derive Faraday status from a Defender alert or assessment payload.

    Alerts surface status as ``properties.status`` (Active / Resolved /
    Dismissed / InProgress). Assessments use
    ``properties.status.code`` (Healthy / Unhealthy / NotApplicable).
    Dict-shape and synonym variants tolerated so re-emitted findings
    still map cleanly.
    """
    if not isinstance(item, dict):
        return "open"
    props = item.get("properties") if isinstance(item.get("properties"), dict) else item
    if not isinstance(props, dict):
        props = {}
    status_blob = props.get("status") if "status" in props else item.get("status")
    if isinstance(status_blob, dict):
        for key in ("code", "Code", "name", "Name", "value", "Value", "state", "State"):
            raw = status_blob.get(key)
            mapped = _normalise_status_token(raw) if isinstance(raw, str) else None
            if mapped:
                return mapped
    elif isinstance(status_blob, str):
        mapped = _normalise_status_token(status_blob)
        if mapped:
            return mapped
    for alt_key in ("alertStatus", "alert_status", "state", "State"):
        raw = props.get(alt_key) or item.get(alt_key)
        if isinstance(raw, dict):
            for key in ("code", "Code", "name", "Name", "value", "Value"):
                inner = raw.get(key)
                mapped = _normalise_status_token(inner) if isinstance(inner, str) else None
                if mapped:
                    return mapped
        elif isinstance(raw, str):
            mapped = _normalise_status_token(raw)
            if mapped:
                return mapped
    return "open"


def validate_min_severity(value):
    """Validate DEFENDER_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied
    beyond the default). Accepts the canonical Faraday buckets plus the
    Defender-side synonyms (informational / unknown -> info, important
    / major -> high, moderate -> medium, minor -> low).
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    bucket = DEFENDER_STRING_SEVERITY.get(text)
    if bucket is None:
        log(f"DEFENDER_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_resource_group(value):
    """Validate DEFENDER_RESOURCE_GROUP — the ARM resource group name.

    None / blank -> None (query the whole subscription). The value is
    used verbatim in the ARM URL path
    ``/subscriptions/{sub}/resourceGroups/{rg}``; ARM rejects names with
    illegal chars so we trim whitespace but don't otherwise massage.
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


def validate_subscription_id(value):
    """Validate AZURE_SUBSCRIPTION_ID.

    Azure subscription ids are GUIDs, but we accept any non-blank string
    and let ARM reject malformed ones at request time. None / blank ->
    None so the caller can ``sys.exit`` with a clear message.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    return text or None


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``.

    Used for client-side filtering — Defender for Cloud's list APIs
    don't expose a server-side severity filter, so the floor is applied
    after build_vulnerability has bucketed each finding.
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def cvss_score(item):
    """Pull a numeric CVSS score out of a Defender alert / assessment payload.

    Defender for Cloud alerts don't usually carry CVSS, but assessments
    (and subassessments, when expanded) surface CVSS v3 base scores in
    ``additionalData.cvss`` or ``properties.cvss``. We walk those plus a
    couple of common synonyms so vendor-shaped reports that re-emit
    Defender findings still bucket correctly.
    """
    if not isinstance(item, dict):
        return None
    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    candidates = []
    for src in (item, props):
        if not isinstance(src, dict):
            continue
        additional = src.get("additionalData") or src.get("additional_data")
        if isinstance(additional, dict):
            candidates.append(additional)
        candidates.append(src)
    for src in candidates:
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
                # Defender shape: {"3.0": {"base": 9.8, "vector": "..."}}
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
    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    candidates = []
    for src in (item, props):
        if not isinstance(src, dict):
            continue
        additional = src.get("additionalData") or src.get("additional_data")
        if isinstance(additional, dict):
            candidates.append(additional)
        candidates.append(src)
    for src in candidates:
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
    """Pull CVE-* ids out of a Defender alert / assessment payload.

    Walks the canonical ``properties.additionalData.cve`` /
    ``properties.cve`` surfaces (subassessment vulnerability findings),
    then falls back to title / description / displayName / remediation
    token scans (defensive — Defender often surfaces a CVE only in the
    alert / assessment text for hand-curated findings).
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

    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    additional = {}
    if isinstance(props, dict):
        ad = props.get("additionalData") or props.get("additional_data")
        if isinstance(ad, dict):
            additional = ad

    for src in (item, props, additional):
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
        for key in ("references", "Reference", "vulnerabilities", "Vulnerabilities"):
            v = src.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, dict):
                        add(
                            entry.get("id")
                            or entry.get("Id")
                            or entry.get("cve")
                            or entry.get("cveId")
                            or entry.get("vulnerabilityId")
                        )
                    elif isinstance(entry, str):
                        scan(entry)

    for key in (
        "alertDisplayName",
        "displayName",
        "description",
        "title",
        "Title",
        "summary",
        "alertType",
        "remediation",
        "remediationSteps",
        "DisplayName",
    ):
        v = item.get(key) if key in item else props.get(key) if isinstance(props, dict) else None
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)

    return found


def collect_refs(item):
    """Walk a Defender alert / assessment for advisory URLs / pivots."""
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

    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    additional = {}
    if isinstance(props, dict):
        ad = props.get("additionalData") or props.get("additional_data")
        if isinstance(ad, dict):
            additional = ad

    for src in (item, props, additional):
        if not isinstance(src, dict):
            continue
        for source_key in ("cweId", "cwe_id", "cwe", "CWE"):
            add_cwe(src.get(source_key))
        for source_key in ("cwes", "cweIds", "cwe_ids", "CWEs"):
            items = src.get(source_key)
            if isinstance(items, list):
                for it in items:
                    add_cwe(it)

    # Alert / assessment portal links + alertUri.
    for key in ("alertUri", "alert_uri", "AlertUri"):
        v = item.get(key) if key in item else props.get(key)
        if isinstance(v, str) and v.strip():
            add(v.strip())

    # extendedLinks list on alerts: [{ "category": "external", "type": "webLink",
    #                                  "href": "https://...", "label": "..." }]
    for src_key in ("extendedLinks", "extended_links", "ExtendedLinks"):
        ext = props.get(src_key) if isinstance(props, dict) else None
        if ext is None:
            ext = item.get(src_key)
        if isinstance(ext, list):
            for entry in ext:
                if isinstance(entry, dict):
                    href = entry.get("href") or entry.get("Href") or entry.get("url") or entry.get("Url")
                    if href:
                        add(href)
                elif isinstance(entry, str) and entry.strip():
                    add(entry.strip())

    # Assessment links (`links.azurePortalUri`).
    links = props.get("links") if isinstance(props, dict) else None
    if isinstance(links, dict):
        for k in ("azurePortalUri", "azurePortal", "portalUri", "AzurePortalUri"):
            v = links.get(k)
            if isinstance(v, str) and v.strip():
                add(v.strip())

    # alertType / assessmentType -> pivot.
    alert_type = props.get("alertType") if isinstance(props, dict) else None
    if isinstance(alert_type, str) and alert_type.strip():
        add(f"DefenderAlertType: {alert_type.strip()}")

    intent = props.get("intent") if isinstance(props, dict) else None
    if isinstance(intent, str) and intent.strip():
        add(f"DefenderIntent: {intent.strip()}")
    elif isinstance(intent, list):
        for t in intent:
            if isinstance(t, str) and t.strip():
                add(f"DefenderIntent: {t.strip()}")

    # Assessment id pivot — Defender's stable assessment id.
    asmt_id = item.get("name") or item.get("Name")
    item_type = item.get("type") or item.get("Type")
    if isinstance(item_type, str) and "assessments" in item_type.lower():
        if isinstance(asmt_id, str) and asmt_id.strip():
            add(f"DefenderAssessment: {asmt_id.strip()}")
    elif isinstance(item_type, str) and "alerts" in item_type.lower():
        if isinstance(asmt_id, str) and asmt_id.strip():
            add(f"DefenderAlert: {asmt_id.strip()}")

    # MITRE ATT&CK tactics / techniques surfaced on some alerts.
    for k in ("tactics", "Tactics"):
        v = props.get(k) if isinstance(props, dict) else None
        if isinstance(v, list):
            for t in v:
                if isinstance(t, str) and t.strip():
                    add(f"MITRE-Tactic: {t.strip()}")
    for k in ("techniques", "Techniques"):
        v = props.get(k) if isinstance(props, dict) else None
        if isinstance(v, list):
            for t in v:
                if isinstance(t, str) and t.strip():
                    add(f"MITRE-Technique: {t.strip()}")

    # references / links lists shared with other CSPM shapes.
    for key in ("references", "links", "References", "Links"):
        entry = item.get(key)
        if entry is None and isinstance(props, dict):
            entry = props.get(key)
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


def _parse_arm_resource(rid):
    """Pull resource_group + provider + resource_type + name out of an ARM id.

    ARM resource ids follow
    ``/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}``
    (plus optional sub-resource segments). Returns a dict — empty when
    the id doesn't match the canonical shape.
    """
    out = {}
    if not isinstance(rid, str) or not rid.strip():
        return out
    parts = [p for p in rid.strip().split("/") if p]
    i = 0
    while i < len(parts) - 1:
        token = parts[i].lower()
        if token == "subscriptions":
            out["subscription_id"] = parts[i + 1]
            i += 2
            continue
        if token == "resourcegroups":
            out["resource_group"] = parts[i + 1]
            i += 2
            continue
        if token == "providers":
            provider = parts[i + 1] if i + 1 < len(parts) else ""
            if provider:
                out["provider"] = provider
            type_bits = []
            j = i + 2
            while j < len(parts):
                # ARM nests "type/name/subtype/subname/..." — capture the
                # outermost type/name pair plus any sub-type chain.
                type_bits.append(parts[j])
                j += 1
            if len(type_bits) >= 2:
                out["resource_type"] = f"{provider}/{type_bits[0]}"
                out["resource_name"] = type_bits[-1]
            elif len(type_bits) == 1:
                out["resource_type"] = f"{provider}/{type_bits[0]}"
            break
        i += 1
    return out


def _extract_resource_id(item):
    """Pick the canonical Azure resource id out of an alert or assessment.

    Alerts carry ``properties.resourceIdentifiers`` (a list of typed id
    blobs, the ``AzureResource`` flavour is the one we want, with
    ``azureResourceId``). Some alerts also carry ``properties.entities[]``
    with a ``resourceId`` field. Assessments carry
    ``properties.resourceDetails.id`` (or ``ResourceId``).
    """
    if not isinstance(item, dict):
        return ""
    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    if not isinstance(props, dict):
        props = {}

    # Assessment shape first.
    rd = props.get("resourceDetails") or props.get("resource_details")
    if isinstance(rd, dict):
        for key in ("id", "Id", "resourceId", "ResourceId", "azureResourceId", "AzureResourceId"):
            v = rd.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()

    # Alert shape: resourceIdentifiers list.
    rids = props.get("resourceIdentifiers") or props.get("resource_identifiers")
    if isinstance(rids, list):
        # Prefer AzureResource flavour.
        for entry in rids:
            if not isinstance(entry, dict):
                continue
            etype = entry.get("type") or entry.get("Type")
            if isinstance(etype, str) and etype.lower() in ("azureresource", "azure_resource", "azure resource"):
                for key in ("azureResourceId", "AzureResourceId", "id", "Id", "resourceId", "ResourceId"):
                    v = entry.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
        # Fallback to the first entry with any id-shaped field.
        for entry in rids:
            if not isinstance(entry, dict):
                continue
            for key in ("azureResourceId", "AzureResourceId", "id", "Id", "resourceId", "ResourceId"):
                v = entry.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()

    # entities[] fallback (some alerts carry the AzureResource entity).
    entities = props.get("entities")
    if isinstance(entities, list):
        for entry in entities:
            if not isinstance(entry, dict):
                continue
            for key in ("resourceId", "ResourceId", "azureResourceId", "AzureResourceId"):
                v = entry.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()

    # compromisedEntity (alert-only fallback, often just a hostname).
    ce = props.get("compromisedEntity")
    if isinstance(ce, str) and ce.strip():
        return ce.strip()

    return ""


def resource_label(item, resource_id=""):
    """Build a friendly label for a Defender finding's primary resource."""
    if not isinstance(item, dict):
        return ""
    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    if not isinstance(props, dict):
        props = {}
    rid = resource_id or _extract_resource_id(item)
    parsed = _parse_arm_resource(rid)
    rtype = parsed.get("resource_type", "")
    rname = parsed.get("resource_name", "")
    rg = parsed.get("resource_group", "")

    # Assessment-side fallback for type/source.
    rd = props.get("resourceDetails") or props.get("resource_details")
    if not rtype and isinstance(rd, dict):
        rtype = rd.get("resourceType") or rd.get("ResourceType") or rd.get("source") or rd.get("Source") or ""
    if not rname:
        rname = props.get("compromisedEntity") or props.get("CompromisedEntity") or ""

    if rname and rtype:
        label = f"{rtype} {rname}"
    elif rname:
        label = rname
    elif rtype and rid:
        label = f"{rtype} {rid}"
    elif rid:
        label = rid
    else:
        label = rtype or ""
    if rg:
        label = f"{label} [{rg}]" if label else f"[{rg}]"
    return str(label).strip()


def vuln_label(item):
    """Build the leading title fragment for a Defender finding."""
    if not isinstance(item, dict):
        return ""
    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    if isinstance(props, dict):
        for key in ("alertDisplayName", "displayName", "title", "AlertDisplayName", "DisplayName", "Title"):
            v = props.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        # alertType is a stable enum id; keep it last because operators
        # prefer the human display name when available.
        v = props.get("alertType") or props.get("AlertType")
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("name", "Name", "id", "Id"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "Defender finding"


def _serialise(obj):
    """Best-effort to-string for datetime / decimal values."""
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


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from one Defender alert or assessment."""
    if not isinstance(item, dict):
        return None

    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    if not isinstance(props, dict):
        props = {}
    item_type = item.get("type") or item.get("Type") or ""
    is_assessment = isinstance(item_type, str) and "assessments" in item_type.lower()

    score = cvss_score(item)
    sev_raw = props.get("severity") or props.get("Severity")
    severity = severity_from_defender(sev_raw, score)
    status = status_from_defender(item)

    rid = _extract_resource_id(item)
    rlabel = resource_label(item, rid)
    vlabel = vuln_label(item)
    raw_name = f"{vlabel} on {rlabel}" if rlabel else vlabel
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = props.get("description") or props.get("Description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    # Defender alert-only enrichments.
    if not is_assessment:
        for label, key in (
            ("alert_type", "alertType"),
            ("intent", "intent"),
            ("compromised_entity", "compromisedEntity"),
            ("vendor", "vendorName"),
            ("product", "productName"),
        ):
            v = props.get(key)
            if v:
                desc_parts.append(f"{label}: {_serialise(v)}")
        tactics = props.get("tactics") or props.get("Tactics")
        if isinstance(tactics, list) and tactics:
            desc_parts.append(f"tactics: {', '.join(str(t) for t in tactics if t)}")
        techniques = props.get("techniques") or props.get("Techniques")
        if isinstance(techniques, list) and techniques:
            desc_parts.append(f"techniques: {', '.join(str(t) for t in techniques if t)}")

    # Assessment-only enrichments.
    if is_assessment:
        for label, key in (
            ("display_name", "displayName"),
            ("category", "category"),
        ):
            v = props.get(key)
            if v:
                desc_parts.append(f"{label}: {_serialise(v)}")
        status_blob = props.get("status")
        if isinstance(status_blob, dict):
            for label, key in (
                ("status_code", "code"),
                ("status_cause", "cause"),
                ("status_description", "description"),
            ):
                v = status_blob.get(key)
                if v:
                    desc_parts.append(f"{label}: {_serialise(v)}")
        rd = props.get("resourceDetails") or props.get("resource_details")
        if isinstance(rd, dict):
            for label, key in (
                ("resource_source", "source"),
                ("resource_type", "resourceType"),
                ("connector_id", "connectorId"),
            ):
                v = rd.get(key)
                if v:
                    desc_parts.append(f"{label}: {_serialise(v)}")

    additional = props.get("additionalData") or props.get("additional_data")
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
                "vulnerabilities",
            ):
                # Surfaces are picked up by collect_cves / collect_refs /
                # cvss_score — skip here to keep the desc concise.
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"{k}: {_serialise(v)}")
            else:
                desc_parts.append(f"{k}: {v}")

    if rid:
        parsed = _parse_arm_resource(rid)
        if parsed.get("resource_group"):
            desc_parts.append(f"resource_group: {parsed['resource_group']}")
        if parsed.get("resource_type"):
            desc_parts.append(f"resource_type: {parsed['resource_type']}")
        if parsed.get("resource_name"):
            desc_parts.append(f"resource_name: {parsed['resource_name']}")
        if parsed.get("subscription_id"):
            desc_parts.append(f"subscription_id: {parsed['subscription_id']}")
        desc_parts.append(f"resource_id: {rid}")

    for label, key in (
        ("first_observed", "startTimeUtc"),
        ("last_observed", "endTimeUtc"),
        ("detected_at", "timeGeneratedUtc"),
        ("reported_at", "reportedTimeUtc"),
        ("processing_at", "processingEndTimeUtc"),
    ):
        v = props.get(key)
        if v:
            desc_parts.append(f"{label}: {_serialise(v)}")

    if sev_raw:
        desc_parts.append(f"defender_severity: {sev_raw}")
    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(item)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    rem = props.get("remediationSteps") or props.get("remediation_steps") or props.get("remediation")
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution and isinstance(additional, dict):
        rem_extra = additional.get("remediationSteps") or additional.get("remediation")
        if isinstance(rem_extra, list):
            bits = [str(r).strip() for r in rem_extra if str(r).strip()]
            if bits:
                resolution = "\n".join(bits)
        elif isinstance(rem_extra, str) and rem_extra.strip():
            resolution = rem_extra.strip()

    external_id = str(item.get("name") or item.get("id") or item.get("Id") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Defender finding {external_id}",
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
        "tags": ["ms_defender_for_cloud", "cnapp", "cloud-native-posture"],
    }


def host_bucket_key(item):
    """Pick a stable bucket key for a Defender finding's primary resource."""
    if not isinstance(item, dict):
        return "__unknown__"
    rid = _extract_resource_id(item)
    return rid or "__unknown__"


def build_host(bucket_key, sample_item, vulns):
    """Build a Faraday host record for the supplied Azure resource bucket."""
    parsed = _parse_arm_resource(bucket_key) if bucket_key and bucket_key != "__unknown__" else {}
    rtype = parsed.get("resource_type", "")
    rname = parsed.get("resource_name", "")
    rg = parsed.get("resource_group", "")
    sub = parsed.get("subscription_id", "")

    label = resource_label(sample_item, bucket_key) if sample_item else ""
    hostname = ""
    if label and bucket_key and bucket_key != "__unknown__":
        hostname = f"{label}@{bucket_key}"
    elif label:
        hostname = label
    elif bucket_key and bucket_key != "__unknown__":
        hostname = bucket_key

    desc_parts = []
    if bucket_key and bucket_key != "__unknown__":
        desc_parts.append(f"resource_id={bucket_key}")
    if rtype:
        desc_parts.append(f"resource_type={rtype}")
    if rname:
        desc_parts.append(f"resource_name={rname}")
    if rg:
        desc_parts.append(f"resource_group={rg}")
    if sub:
        desc_parts.append(f"subscription_id={sub}")

    if isinstance(sample_item, dict):
        props = sample_item.get("properties") if isinstance(sample_item.get("properties"), dict) else {}
        if isinstance(props, dict):
            rd = props.get("resourceDetails") or props.get("resource_details")
            if isinstance(rd, dict):
                source = rd.get("source") or rd.get("Source")
                if source:
                    desc_parts.append(f"source={source}")
            ce = props.get("compromisedEntity")
            if ce and not rname:
                desc_parts.append(f"compromised_entity={ce}")

    if vulns:
        desc_parts.append(f"findings={len(vulns)}")

    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def build_arm_url(subscription_id, resource_group, path_suffix, api_version):
    """Build the ARM URL for an alerts / assessments query."""
    if resource_group:
        base = (
            f"{ARM_HOST}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Security/{path_suffix}"
        )
    else:
        base = f"{ARM_HOST}/subscriptions/{subscription_id}/providers/Microsoft.Security/{path_suffix}"
    return f"{base}?api-version={api_version}"


def fetch_access_token(requests_module, tenant_id, client_id, client_secret):
    """Exchange Azure AD service-principal credentials for an ARM bearer.

    ``POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token``
    with ``grant_type=client_credentials&client_id=...&client_secret=...&scope=https://management.azure.com/.default``
    -> ``{"access_token": "...", "expires_in": N, "token_type": "Bearer"}``.
    """
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
    """Walk an ARM-paged ``{"value": [...], "nextLink": "..."}`` envelope."""
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
            log("ARM request rejected (401). Bearer expired or invalid.")
            sys.exit(1)
        if resp.status_code == 403:
            log("ARM request rejected (403). Check service-principal role assignment.")
            return out
        if resp.status_code == 404:
            log(f"ARM request 404 for {next_url} — subscription / resource group not found")
            return out
        if resp.status_code >= 400:
            log(f"ARM request failed ({resp.status_code}) for {next_url}: {resp.text[:500]}")
            return out
        try:
            body = resp.json()
        except ValueError:
            log(f"ARM response was not JSON ({next_url})")
            return out
        if not isinstance(body, dict):
            return out
        value = body.get("value")
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict):
                    out.append(entry)
        next_url = body.get("nextLink") or body.get("@odata.nextLink") or None
        pages += 1
    if pages >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()
    subscription_id = validate_subscription_id(env("EXECUTOR_CONFIG_AZURE_SUBSCRIPTION_ID"))
    if not subscription_id:
        log("AZURE_SUBSCRIPTION_ID is required")
        sys.exit(1)

    resource_group = validate_resource_group(env("EXECUTOR_CONFIG_DEFENDER_RESOURCE_GROUP"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_DEFENDER_MIN_SEVERITY"))
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

    alerts_url = build_arm_url(subscription_id, resource_group, "alerts", ALERTS_API_VERSION)
    assessments_url = build_arm_url(subscription_id, resource_group, "assessments", ASSESSMENTS_API_VERSION)

    alerts = fetch_pages(requests, alerts_url, headers)
    assessments = fetch_pages(requests, assessments_url, headers)
    findings = list(alerts) + list(assessments)
    log(
        f"Processing {len(findings)} Defender for Cloud findings "
        f"(alerts={len(alerts)}, assessments={len(assessments)}, "
        f"subscription={subscription_id}, resource_group={resource_group or 'ALL'}, "
        f"min_severity={min_severity})"
    )

    buckets = {}
    sample_resources = {}
    for finding in findings:
        key = host_bucket_key(finding)
        buckets.setdefault(key, []).append(finding)
        if key not in sample_resources:
            sample_resources[key] = finding

    hosts = []
    for key, items in buckets.items():
        vulns = []
        for finding in items:
            built = build_vulnerability(finding)
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        if not vulns:
            continue
        sample = sample_resources.get(key)
        hosts.append(build_host(key, sample, vulns))

    params_bits = [
        f"subscription={subscription_id}",
        f"min_severity={min_severity}",
    ]
    if resource_group:
        params_bits.append(f"resource_group={resource_group}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "ms_defender_for_cloud",
            "command": "ms_defender_for_cloud",
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
