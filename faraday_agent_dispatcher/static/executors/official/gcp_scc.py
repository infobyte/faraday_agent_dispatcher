#!/usr/bin/env python
"""Google Cloud Security Command Center v2 vendor-native CSPM importer.

Pulls security findings from GCP Security Command Center (SCC) v2 via
the canonical ``google-cloud-securitycenter`` SDK
(``SecurityCenterClient.list_findings``) and emits Faraday bulk-create
JSON to stdout. Each affected GCP asset (resolved from
``finding.resourceName`` — the canonical GCP asset name such as
``//compute.googleapis.com/projects/{proj}/zones/{zone}/instances/{name}``
or the per-result ``resource`` blob returned by SCC v2) becomes one
Faraday host (``ip`` = synthetic ``0.0.0.0`` because SCC findings live
on GCP assets, not on IPs); per-resource findings attach as Faraday
vulnerabilities — one per Finding ``name`` with engine prefix
``[CNAPP]``.

Endpoints used:
  ``securitycenter_v2.SecurityCenterClient().list_findings(parent=..., filter=...)``
      -> primary findings query. ``parent`` is
      ``organizations/{org}/sources/{source}/locations/{loc}`` (the v2
      surface is regional — we default to ``global`` so subscribers
      get the canonical aggregated view). ``filter`` carries the
      optional state floor (``state=\"ACTIVE\"`` / ``state=\"INACTIVE\"``)
      and severity floor (``severity=\"CRITICAL\" OR severity=\"HIGH\"``
      …). The SDK paginator handles ``nextPageToken`` walking
      internally; ``fetch_findings`` stops at ``MAX_PAGES=200`` worth of
      result-page iterations as a safety net.

Auth: GCP Security Command Center v2 uses the standard Google
Application Default Credentials chain. A service account with the
``roles/securitycenter.findingsViewer`` role (or equivalent custom
role granting ``securitycenter.findings.list``) is required, with
credentials exposed to the dispatcher as a service-account JSON key
file whose path is set in ``GOOGLE_APPLICATION_CREDENTIALS``. The SDK
picks the file up automatically via ADC; the executor validates that
the path exists and is readable before instantiating the client.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

DEFAULT_LOCATION = "global"
MAX_PAGES = 200

# SCC severity enum: CRITICAL / HIGH / MEDIUM / LOW / UNDEFINED /
# SEVERITY_UNSPECIFIED. Map to Faraday's five-bucket scheme; accept the
# usual Faraday-side synonyms so re-emitted findings still bucket.
SCC_STRING_SEVERITY = {
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
    "undefined": "info",
    "severity_unspecified": "info",
    "unspecified": "info",
    "none": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# SCC API severity tokens (UPPERCASE) — used to assemble the optional
# ``severity="..."`` filter clause forwarded to ``list_findings``.
SCC_API_SEVERITY = {
    "info": "LOW",  # SCC has no INFORMATIONAL bucket; LOW is the floor.
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}

VALID_STATES = ("ACTIVE", "INACTIVE")

# SCC v2 state enum -> Faraday status. ACTIVE -> open, INACTIVE -> closed.
# Synonyms tolerated for re-emitted findings.
SCC_STATUS_TO_FARADAY = {
    "active": "open",
    "open": "open",
    "new": "open",
    "reopened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "inactive": "closed",
    "closed": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "state_unspecified": "open",
    "unspecified": "open",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "dismissed": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - GcpScc: {msg}", file=sys.stderr, flush=True)


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


def severity_from_scc(value, cvss=None):
    """Map an SCC severity to a Faraday bucket.

    Accepts SCC's UPPERCASE enum (CRITICAL / HIGH / MEDIUM / LOW /
    UNDEFINED / SEVERITY_UNSPECIFIED) and falls back to CVSS bucketing
    on ``cvss`` when the primary value is missing or unrecognised.
    Numeric inputs are interpreted as CVSS base scores so vendor-shaped
    findings that surface a bare score still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in SCC_STRING_SEVERITY:
            return SCC_STRING_SEVERITY[text]
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
    if keyed in SCC_STATUS_TO_FARADAY:
        return SCC_STATUS_TO_FARADAY[keyed]
    compact = raw.replace(" ", "").replace("-", "").replace("_", "")
    if compact in SCC_STATUS_TO_FARADAY:
        return SCC_STATUS_TO_FARADAY[compact]
    return None


def status_from_scc(finding):
    """Derive Faraday status from an SCC v2 finding payload.

    SCC v2 surfaces lifecycle via ``state`` (ACTIVE / INACTIVE /
    STATE_UNSPECIFIED) and a separate ``mute`` enum
    (MUTED / UNMUTED / UNDEFINED). MUTED collapses to risk-accepted so
    operators who've explicitly muted noise don't see it re-open.
    """
    if not isinstance(finding, dict):
        return "open"
    mute = finding.get("mute") or finding.get("Mute")
    if isinstance(mute, dict):
        mute = mute.get("name") or mute.get("value")
    if isinstance(mute, str) and mute.strip().upper() == "MUTED":
        return "risk-accepted"
    for key in ("state", "State", "status", "Status", "findingStatus", "finding_status"):
        raw = finding.get(key)
        if isinstance(raw, dict):
            raw = (
                raw.get("name")
                or raw.get("Name")
                or raw.get("value")
                or raw.get("Value")
                or raw.get("code")
                or raw.get("Code")
            )
        if isinstance(raw, str):
            mapped = _normalise_status_token(raw)
            if mapped:
                return mapped
    return "open"


def validate_organization_id(value):
    """Validate GCP_ORGANIZATION_ID.

    Accepts a bare numeric id (canonical GCP organization id), the
    fully-qualified ``organizations/{id}`` form, and a couple of common
    typo-tolerant variants (organisation / org). None / blank -> None
    so the caller can ``sys.exit`` with a clear message.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # Strip a leading "organizations/" / "organisations/" / "org/" prefix.
    lowered = text.lower()
    for prefix in ("organizations/", "organisations/", "org/"):
        if lowered.startswith(prefix):
            text = text[len(prefix) :].strip()
            break
    return text or None


def validate_source(value):
    """Validate GCP_SOURCE — the SCC source id.

    Accepts a bare numeric source id and the fully-qualified
    ``sources/{id}`` form (also tolerates being passed a full parent
    string ``organizations/{org}/sources/{src}`` — only the source id
    portion is kept). None / blank -> None which means
    "list_findings across all sources" (the canonical aggregated query
    uses ``sources/-`` as a wildcard).
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # Strip a "sources/" segment wherever it appears.
    parts = [p for p in text.split("/") if p]
    if "sources" in parts:
        idx = parts.index("sources")
        if idx + 1 < len(parts):
            return parts[idx + 1].strip() or None
        return None
    return text


def validate_min_severity(value):
    """Validate SCC_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied
    beyond the default). Accepts the canonical Faraday buckets plus the
    SCC-side synonyms (informational / undefined / severity_unspecified
    -> info, important / major -> high, moderate -> medium, minor ->
    low, none / unspecified / unknown -> info).
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    bucket = SCC_STRING_SEVERITY.get(text)
    if bucket is None:
        log(f"SCC_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_state(value):
    """Validate SCC_STATE (ACTIVE | INACTIVE).

    Canonicalises to the UPPERCASE SCC token so it can be forwarded
    verbatim into the ``state=\"...\"`` filter clause. None / blank /
    garbage -> None (no state filter, list_findings returns every state
    the IAM principal can read).
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    upper = text.upper().replace(" ", "_").replace("-", "_")
    if upper in VALID_STATES:
        return upper
    # Common synonyms.
    aliases = {
        "OPEN": "ACTIVE",
        "ACTIVE_ONLY": "ACTIVE",
        "CLOSED": "INACTIVE",
        "RESOLVED": "INACTIVE",
    }
    if upper in aliases:
        return aliases[upper]
    log(f"SCC_STATE '{value}' not recognised; ignored (no state filter)")
    return None


def severities_at_or_above(min_severity):
    """Return the SCC API severity tokens at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = SCC_API_SEVERITY.get(bucket)
            if api and api not in out:
                out.append(api)
    return out


def faraday_buckets_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``.

    Used for client-side filtering — the SCC ``severity="..."`` filter
    only knows about the SCC enum (LOW / MEDIUM / HIGH / CRITICAL), so
    findings that bucket to ``info`` (when CVSS score is 0 or there's no
    severity at all) need a second client-side check.
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def build_parent(organization_id, source_id, location=DEFAULT_LOCATION):
    """Build the SCC v2 ``parent`` string for ``list_findings``.

    The v2 surface is regional — ``location`` defaults to ``global``
    so subscribers get the canonical aggregated view. ``source_id`` may
    be ``None``; in that case the wildcard ``sources/-`` is used (the
    canonical pattern for aggregated listing).
    """
    src = source_id or "-"
    loc = location or DEFAULT_LOCATION
    return f"organizations/{organization_id}/sources/{src}/locations/{loc}"


def build_filter(state, min_severity):
    """Assemble the SCC v2 ``filter`` clause.

    SCC's filter language uses CEL-style equality (``state="ACTIVE"``)
    and ``OR`` for disjunctions (``severity="CRITICAL" OR severity="HIGH"``).
    Returns ``""`` when neither a state nor a severity floor is in play
    (list_findings returns every finding the IAM principal can read).
    """
    clauses = []
    if state:
        clauses.append(f'state="{state}"')
    sevs = severities_at_or_above(min_severity) if min_severity else []
    # No point shipping the severity floor when it includes every SCC
    # bucket — the API doesn't have an INFORMATIONAL token, so any
    # min_severity of "info" or "low" admits the entire LOW-and-up set.
    if min_severity and min_severity not in ("info", "low") and sevs:
        sev_or = " OR ".join(f'severity="{s}"' for s in sevs)
        clauses.append(f"({sev_or})")
    return " AND ".join(clauses)


def cvss_score(finding):
    """Pull a numeric CVSS score out of an SCC v2 finding payload.

    Walks the canonical ``vulnerability.cve.cvssv3.baseScore`` first,
    then ``cves[].cvssv3.baseScore``, then a couple of common synonyms
    so vendor-shaped reports that re-emit SCC findings still bucket
    correctly.
    """
    if not isinstance(finding, dict):
        return None

    def from_cvss_blob(blob):
        if not isinstance(blob, dict):
            return None
        for k in ("baseScore", "base_score", "score", "base"):
            v = blob.get(k)
            if v is None or isinstance(v, (dict, list, bool)):
                continue
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
        return None

    vuln = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
    if isinstance(vuln, dict):
        cve = vuln.get("cve") if isinstance(vuln.get("cve"), dict) else {}
        for k in ("cvssv3", "cvssV3", "cvss_v3", "cvss3", "cvss"):
            score = from_cvss_blob(cve.get(k)) if isinstance(cve, dict) else None
            if score is not None:
                return score
        # Some SCC v2 findings carry the score at vulnerability.cvssv3 level.
        for k in ("cvssv3", "cvssV3", "cvss_v3", "cvss3", "cvss"):
            score = from_cvss_blob(vuln.get(k))
            if score is not None:
                return score

    cves = finding.get("cves") or finding.get("Cves")
    if isinstance(cves, list):
        for entry in cves:
            if not isinstance(entry, dict):
                continue
            for k in ("cvssv3", "cvssV3", "cvss_v3", "cvss3", "cvss"):
                score = from_cvss_blob(entry.get(k))
                if score is not None:
                    return score

    for key in ("cvssScore", "cvss_score", "score", "baseScore", "base_score"):
        v = finding.get(key)
        if v is None or isinstance(v, (dict, list, bool)):
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3"):
        nested = finding.get(nested_key)
        if isinstance(nested, dict):
            score = from_cvss_blob(nested)
            if score is not None:
                return score
    return None


def cvss_vector(finding):
    if not isinstance(finding, dict):
        return ""

    def from_blob(blob):
        if not isinstance(blob, dict):
            return ""
        for k in ("vector", "Vector", "vectorString", "vector_string"):
            s = blob.get(k)
            if isinstance(s, str) and s.strip():
                return s.strip()
        return ""

    vuln = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
    if isinstance(vuln, dict):
        cve = vuln.get("cve") if isinstance(vuln.get("cve"), dict) else {}
        for k in ("cvssv3", "cvssV3", "cvss_v3", "cvss3", "cvss"):
            v = from_blob(cve.get(k)) if isinstance(cve, dict) else ""
            if v:
                return v
        for k in ("cvssv3", "cvssV3", "cvss_v3", "cvss3", "cvss"):
            v = from_blob(vuln.get(k))
            if v:
                return v

    cves = finding.get("cves") or finding.get("Cves")
    if isinstance(cves, list):
        for entry in cves:
            if not isinstance(entry, dict):
                continue
            for k in ("cvssv3", "cvssV3", "cvss_v3", "cvss3", "cvss"):
                v = from_blob(entry.get(k))
                if v:
                    return v

    for k in ("cvssVector", "cvss_vector", "vector", "vectorString", "vector_string"):
        s = finding.get(k)
        if isinstance(s, str) and s.strip():
            return s.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3"):
        nested = finding.get(nested_key)
        v = from_blob(nested)
        if v:
            return v
    return ""


def collect_cves(finding):
    """Pull CVE-* ids out of an SCC v2 finding payload.

    Walks the canonical ``vulnerability.cve.id`` / ``cves[].id``
    surfaces, then falls back to category / description / sourceProperties
    token scans (defensive — partner findings sometimes surface a CVE
    only in the title or description).
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

    if not isinstance(finding, dict):
        return found

    vuln = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
    if isinstance(vuln, dict):
        cve = vuln.get("cve") if isinstance(vuln.get("cve"), dict) else {}
        if isinstance(cve, dict):
            add(cve.get("id") or cve.get("Id"))
            refs = cve.get("references")
            if isinstance(refs, list):
                for r in refs:
                    if isinstance(r, dict):
                        # SCC reference shape: {source, uri}
                        scan(r.get("uri") or "")
                        scan(r.get("source") or "")
                    elif isinstance(r, str):
                        scan(r)

    cves = finding.get("cves") or finding.get("Cves")
    if isinstance(cves, list):
        for entry in cves:
            if isinstance(entry, dict):
                add(entry.get("id") or entry.get("Id") or entry.get("cve") or entry.get("cveId"))
            elif isinstance(entry, str):
                add(entry)

    for key in ("cve", "cveId", "cve_id"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            add(v)
        elif isinstance(v, dict):
            add(v.get("id") or v.get("Id") or v.get("name"))

    for key in ("cveIds", "cve_ids", "aliases"):
        v = finding.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("Id") or entry.get("cve") or entry.get("cveId"))

    for key in ("category", "description", "title", "summary"):
        v = finding.get(key)
        if isinstance(v, str):
            scan(v)

    sp = finding.get("sourceProperties") or finding.get("source_properties")
    if isinstance(sp, dict):
        for v in sp.values():
            if isinstance(v, str):
                scan(v)
            elif isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        scan(entry)

    return found


def collect_refs(finding):
    """Walk an SCC v2 finding for CWE / advisory URL / pivot refs."""
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

    if not isinstance(finding, dict):
        return refs

    # CWE surfaces — vulnerability.cve.cwes (SCC v2 shape: list-of-dict
    # {"id": "CWE-79"}) plus the usual top-level / additional spots.
    vuln = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
    if isinstance(vuln, dict):
        cve = vuln.get("cve") if isinstance(vuln.get("cve"), dict) else {}
        if isinstance(cve, dict):
            cwes = cve.get("cwes") or cve.get("CWEs") or cve.get("cwe")
            if isinstance(cwes, list):
                for c in cwes:
                    add_cwe(c)
            elif cwes is not None:
                add_cwe(cwes)
            # CVE references (URL pivots).
            crefs = cve.get("references")
            if isinstance(crefs, list):
                for r in crefs:
                    if isinstance(r, dict):
                        uri = r.get("uri") or r.get("Uri") or r.get("url") or r.get("Url")
                        if uri:
                            add(uri)
                    elif isinstance(r, str) and r.strip():
                        add(r.strip())
            cid = cve.get("id") or cve.get("Id")
            if isinstance(cid, str) and cid.strip():
                add(f"SCC-Vuln: {cid.strip()}")
            # Exploit / fix surfaces.
            ea = cve.get("exploitationActivity") or cve.get("exploitation_activity")
            if (
                isinstance(ea, str)
                and ea.strip()
                and ea.strip().upper() not in ("EXPLOITATION_ACTIVITY_UNSPECIFIED", "UNDEFINED")
            ):
                add(f"SCC-Exploitation: {ea.strip()}")
            ufa = cve.get("upstreamFixAvailable") or cve.get("upstream_fix_available")
            if (
                isinstance(ufa, str)
                and ufa.strip()
                and ufa.strip().upper() not in ("UPSTREAM_FIX_AVAILABLE_UNSPECIFIED", "UNDEFINED")
            ):
                add(f"SCC-UpstreamFix: {ufa.strip()}")

    for source_key in ("cweId", "cwe_id", "cwe", "CWE"):
        add_cwe(finding.get(source_key))
    for source_key in ("cwes", "cweIds", "cwe_ids", "CWEs"):
        items = finding.get(source_key)
        if isinstance(items, list):
            for it in items:
                add_cwe(it)

    # externalUri (the SCC console deep-link).
    for key in ("externalUri", "external_uri", "ExternalUri"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            add(v.strip())

    # canonicalName pivot — stable across renames.
    cn = finding.get("canonicalName") or finding.get("canonical_name")
    if isinstance(cn, str) and cn.strip():
        add(f"SCC-Finding: {cn.strip()}")

    # category pivot (e.g., "MFA_NOT_ENFORCED").
    cat = finding.get("category") or finding.get("Category")
    if isinstance(cat, str) and cat.strip():
        add(f"SCC-Category: {cat.strip()}")

    # findingClass pivot (VULNERABILITY / MISCONFIGURATION / THREAT / ...).
    fc = finding.get("findingClass") or finding.get("finding_class")
    if isinstance(fc, str) and fc.strip() and fc.strip().upper() not in ("FINDING_CLASS_UNSPECIFIED", "UNSPECIFIED"):
        add(f"SCC-Class: {fc.strip()}")

    # parentDisplayName / parent — surfaces which SCC source emitted the finding.
    pdn = finding.get("parentDisplayName") or finding.get("parent_display_name")
    if isinstance(pdn, str) and pdn.strip():
        add(f"SCC-Source: {pdn.strip()}")

    # mitreAttack tactics / techniques.
    ma = finding.get("mitreAttack") or finding.get("mitre_attack")
    if isinstance(ma, dict):
        prim_tac = ma.get("primaryTactic") or ma.get("primary_tactic")
        if isinstance(prim_tac, str) and prim_tac.strip() and prim_tac.strip().upper() != "TACTIC_UNSPECIFIED":
            add(f"MITRE-Tactic: {prim_tac.strip()}")
        for k in ("additionalTactics", "additional_tactics"):
            extras = ma.get(k)
            if isinstance(extras, list):
                for t in extras:
                    if isinstance(t, str) and t.strip() and t.strip().upper() != "TACTIC_UNSPECIFIED":
                        add(f"MITRE-Tactic: {t.strip()}")
        for k in ("primaryTechniques", "primary_techniques", "additionalTechniques", "additional_techniques"):
            techs = ma.get(k)
            if isinstance(techs, list):
                for t in techs:
                    if isinstance(t, str) and t.strip() and t.strip().upper() != "TECHNIQUE_UNSPECIFIED":
                        add(f"MITRE-Technique: {t.strip()}")

    # compliance pivots (CIS_GCP_FOUNDATION 1.0 1.1 1.2 ...).
    comps = finding.get("compliances") or finding.get("Compliances")
    if isinstance(comps, list):
        for c in comps:
            if not isinstance(c, dict):
                continue
            std = c.get("standard") or c.get("Standard") or ""
            ver = c.get("version") or c.get("Version") or ""
            ids = c.get("ids") or c.get("Ids") or []
            if isinstance(ids, list):
                for cid in ids:
                    if isinstance(cid, str) and cid.strip():
                        bits = " ".join(str(x) for x in (std, ver) if x)
                        add(f"Compliance: {bits + ' ' if bits else ''}{cid.strip()}".strip())

    # references / links lists shared with other CSPM shapes.
    for key in ("references", "links", "References", "Links"):
        entry = finding.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = (
                        it.get("href")
                        or it.get("Href")
                        or it.get("url")
                        or it.get("Url")
                        or it.get("uri")
                        or it.get("Uri")
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


def _parse_resource_name(resource_name):
    """Pull provider / resource_type / project / region / name out of a GCP asset name.

    GCP asset names follow
    ``//{service}.googleapis.com/projects/{proj}/{scope}/{loc}/{type}/{name}``
    (e.g. ``//compute.googleapis.com/projects/p/zones/us-east1-b/instances/vm-1``)
    or the shorter
    ``//{service}.googleapis.com/projects/{proj}/{type}/{name}``
    (e.g. ``//storage.googleapis.com/projects/p/buckets/bk``). Returns a
    dict — empty when the name doesn't match the canonical shape.
    """
    out = {}
    if not isinstance(resource_name, str) or not resource_name.strip():
        return out
    text = resource_name.strip()
    if text.startswith("//"):
        text = text[2:]
    parts = [p for p in text.split("/") if p]
    if not parts:
        return out

    service = parts[0]
    if service.endswith(".googleapis.com"):
        out["service"] = service
        out["provider"] = service.split(".", 1)[0]
    elif "." in service:
        out["service"] = service
        out["provider"] = service.split(".", 1)[0]
    parts = parts[1:]

    i = 0
    while i < len(parts) - 1:
        token = parts[i].lower()
        if token == "projects":
            out["project"] = parts[i + 1]
            i += 2
            continue
        if token in ("zones", "regions", "locations"):
            out["location"] = parts[i + 1]
            i += 2
            continue
        if token in ("folders",):
            out["folder"] = parts[i + 1]
            i += 2
            continue
        if token in ("organizations", "orgs"):
            out["organization"] = parts[i + 1]
            i += 2
            continue
        # First unmapped token + its value is the resource type + name.
        if "resource_type" not in out:
            provider = out.get("provider", "")
            type_label = f"{provider}/{parts[i]}" if provider else parts[i]
            out["resource_type"] = type_label
            out["resource_name"] = parts[i + 1] if i + 1 < len(parts) else ""
            # Capture any sub-resource segments by preferring the deepest name.
            if i + 2 < len(parts):
                out["resource_name"] = parts[-1]
            break
        i += 1
    if "resource_type" not in out and parts:
        # Last-ditch: surface the trailing segment as the name.
        out["resource_name"] = parts[-1]
    return out


def _extract_resource_name(item):
    """Pick the canonical GCP resource name out of a list-findings result.

    SCC v2 list_findings returns ``ListFindingsResult`` objects with two
    shapes:
      - a ``finding`` blob (the Finding itself, with ``resourceName``)
      - a ``resource`` blob (an associated Resource with ``name``)
    We accept both top-level shapes plus a bare Finding so the helpers
    can be unit-tested without the SDK installed.
    """
    if not isinstance(item, dict):
        return ""
    # ListFindingsResult shape — pull from the embedded resource first
    # (it carries more accurate display info), then fall back to the
    # finding.resourceName.
    res = item.get("resource") or item.get("Resource")
    if isinstance(res, dict):
        for key in ("name", "Name"):
            v = res.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    finding = item.get("finding") if isinstance(item.get("finding"), dict) else item
    if isinstance(finding, dict):
        for key in ("resourceName", "resource_name", "ResourceName"):
            v = finding.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _extract_finding(item):
    """Pull the Finding payload out of a list_findings result.

    SCC v2 returns ``ListFindingsResult { finding, resource }``; the
    helpers downstream expect to operate on the Finding directly. We
    accept either the wrapped shape or a bare Finding so the helpers
    stay testable.
    """
    if not isinstance(item, dict):
        return {}
    if isinstance(item.get("finding"), dict):
        return item["finding"]
    return item


def resource_label(item, resource_name=""):
    """Build a friendly label for a SCC finding's primary resource."""
    if not isinstance(item, dict):
        return ""
    rname = resource_name or _extract_resource_name(item)
    parsed = _parse_resource_name(rname)
    rtype = parsed.get("resource_type", "")
    name = parsed.get("resource_name", "")
    project = parsed.get("project", "")
    location = parsed.get("location", "")

    # Resource-side display name wins (it's a curated, operator-friendly
    # name; the path-derived one is the bare ARM segment).
    res = item.get("resource") or item.get("Resource")
    if isinstance(res, dict):
        for key in ("displayName", "display_name", "DisplayName"):
            v = res.get(key)
            if isinstance(v, str) and v.strip():
                name = v.strip()
                break
        if not rtype:
            for key in ("type", "Type"):
                v = res.get(key)
                if isinstance(v, str) and v.strip():
                    rtype = v.strip()
                    break
        if not project:
            for key in ("projectDisplayName", "project_display_name", "projectName", "project_name"):
                v = res.get(key)
                if isinstance(v, str) and v.strip():
                    project = v.strip()
                    break

    if name and rtype:
        label = f"{rtype} {name}"
    elif name:
        label = name
    elif rtype and rname:
        label = f"{rtype} {rname}"
    elif rname:
        label = rname
    else:
        label = rtype or ""
    suffix = ""
    if location and project:
        suffix = f" [{project}/{location}]"
    elif project:
        suffix = f" [{project}]"
    elif location:
        suffix = f" [{location}]"
    if suffix:
        label = f"{label}{suffix}" if label else suffix.strip(" []")
    return str(label).strip()


def vuln_label(item):
    """Build the leading title fragment for a SCC finding."""
    if not isinstance(item, dict):
        return ""
    finding = _extract_finding(item)
    if not isinstance(finding, dict):
        finding = {}
    vuln = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
    if isinstance(vuln, dict):
        cve = vuln.get("cve") if isinstance(vuln.get("cve"), dict) else {}
        if isinstance(cve, dict):
            cid = cve.get("id") or cve.get("Id")
            if isinstance(cid, str) and cid.strip():
                return cid.strip()
    for key in ("category", "Category", "title", "Title", "displayName", "display_name"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("name", "Name"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            # finding.name is a long resource path — take the trailing segment.
            return v.strip().rsplit("/", 1)[-1]
    return "SCC finding"


def _serialise(obj):
    """Best-effort to-string for SDK datetime / proto values."""
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
    """Build a Faraday vulnerability dict from one SCC list-findings result."""
    if not isinstance(item, dict):
        return None

    finding = _extract_finding(item)
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding)
    sev_raw = finding.get("severity") or finding.get("Severity")
    severity = severity_from_scc(sev_raw, score)
    status = status_from_scc(finding)

    rname = _extract_resource_name(item)
    rlabel = resource_label(item, rname)
    vlabel = vuln_label(item)
    raw_name = f"{vlabel} on {rlabel}" if rlabel else vlabel
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = finding.get("description") or finding.get("Description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    vuln = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
    if isinstance(vuln, dict):
        cve = vuln.get("cve") if isinstance(vuln.get("cve"), dict) else {}
        if isinstance(cve, dict):
            cid = cve.get("id") or cve.get("Id")
            if cid:
                desc_parts.append(f"vulnerability_id: {cid}")
            ufa = cve.get("upstreamFixAvailable") or cve.get("upstream_fix_available")
            if ufa:
                desc_parts.append(f"upstream_fix_available: {ufa}")
            ea = cve.get("exploitationActivity") or cve.get("exploitation_activity")
            if ea:
                desc_parts.append(f"exploitation_activity: {ea}")
            obs = cve.get("observedInTheWild") or cve.get("observed_in_the_wild")
            if obs is not None:
                desc_parts.append(f"observed_in_the_wild: {obs}")
            zd = cve.get("zeroDay") or cve.get("zero_day")
            if zd is not None:
                desc_parts.append(f"zero_day: {zd}")
            impact = cve.get("impact") or cve.get("Impact")
            if impact:
                desc_parts.append(f"impact: {impact}")
        pkg = vuln.get("package") or vuln.get("Package")
        if isinstance(pkg, dict):
            pname = pkg.get("packageName") or pkg.get("package_name") or pkg.get("name")
            pver = pkg.get("packageVersion") or pkg.get("package_version") or pkg.get("version")
            pfix = pkg.get("fixedInVersion") or pkg.get("fixed_in_version") or pkg.get("cpeUri")
            ptype = pkg.get("packageType") or pkg.get("package_type")
            if pname:
                desc_parts.append(f"package: {pname}" + (f" {pver}" if pver else ""))
            if pfix:
                desc_parts.append(f"fixed_in: {pfix}")
            if ptype:
                desc_parts.append(f"package_type: {ptype}")
        oss = vuln.get("offendingPackage") or vuln.get("offending_package")
        if isinstance(oss, dict):
            pname = oss.get("packageName") or oss.get("name")
            pver = oss.get("packageVersion") or oss.get("version")
            if pname:
                desc_parts.append(f"offending_package: {pname}" + (f" {pver}" if pver else ""))

    findingClass = finding.get("findingClass") or finding.get("finding_class")
    if findingClass:
        desc_parts.append(f"finding_class: {findingClass}")
    category = finding.get("category") or finding.get("Category")
    if category:
        desc_parts.append(f"category: {category}")
    parent = finding.get("parent") or finding.get("Parent")
    if parent:
        desc_parts.append(f"parent: {parent}")
    parent_display = finding.get("parentDisplayName") or finding.get("parent_display_name")
    if parent_display:
        desc_parts.append(f"parent_display_name: {parent_display}")
    state = finding.get("state") or finding.get("State")
    if state:
        desc_parts.append(f"state: {state}")
    mute = finding.get("mute") or finding.get("Mute")
    if mute:
        desc_parts.append(f"mute: {mute}")
    mute_init = finding.get("muteInitiator") or finding.get("mute_initiator")
    if mute_init:
        desc_parts.append(f"mute_initiator: {mute_init}")

    # Access / connections enrichment (threat findings).
    access = finding.get("access") or finding.get("Access")
    if isinstance(access, dict):
        for label, key in (
            ("principal_email", "principalEmail"),
            ("caller_ip", "callerIp"),
            ("user_agent", "userAgent"),
            ("method_name", "methodName"),
            ("service_name", "serviceName"),
        ):
            v = access.get(key)
            if v:
                desc_parts.append(f"{label}: {_serialise(v)}")
    connections = finding.get("connections") or finding.get("Connections")
    if isinstance(connections, list):
        for c in connections:
            if not isinstance(c, dict):
                continue
            bits = []
            for label, key in (
                ("destination_ip", "destinationIp"),
                ("destination_port", "destinationPort"),
                ("source_ip", "sourceIp"),
                ("source_port", "sourcePort"),
                ("protocol", "protocol"),
            ):
                v = c.get(key)
                if v:
                    bits.append(f"{label}={v}")
            if bits:
                desc_parts.append("connection: " + ", ".join(bits))
                break  # one connection line is enough for the desc

    res = item.get("resource") or item.get("Resource")
    if isinstance(res, dict):
        for label, key in (
            ("resource_name", "name"),
            ("resource_display_name", "displayName"),
            ("resource_type", "type"),
            ("resource_project", "projectDisplayName"),
            ("resource_project_name", "projectName"),
            ("resource_parent", "parentDisplayName"),
        ):
            v = res.get(key) or res.get(_to_snake(key))
            if v:
                desc_parts.append(f"{label}: {_serialise(v)}")
        folders = res.get("folders")
        if isinstance(folders, list) and folders:
            joined = ", ".join(
                (f.get("resourceFolderDisplayName") or f.get("resourceFolder") or str(f)) for f in folders if f
            )
            if joined:
                desc_parts.append(f"resource_folders: {joined}")

    if rname:
        parsed = _parse_resource_name(rname)
        for label, key in (
            ("project", "project"),
            ("location", "location"),
            ("provider", "provider"),
            ("service", "service"),
        ):
            v = parsed.get(key)
            if v:
                desc_parts.append(f"{label}: {v}")
        desc_parts.append(f"resource_name_full: {rname}")

    for label, key in (
        ("event_time", "eventTime"),
        ("create_time", "createTime"),
    ):
        v = finding.get(key)
        if v:
            desc_parts.append(f"{label}: {_serialise(v)}")

    # sourceProperties passthrough (skip surfaces handled elsewhere).
    sp = finding.get("sourceProperties") or finding.get("source_properties")
    if isinstance(sp, dict):
        for k, v in sp.items():
            if v is None or v == "":
                continue
            lk = k.lower()
            if lk in (
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
                "explanation",
                "exploitability",
            ):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"{k}: {_serialise(v)}")
            else:
                desc_parts.append(f"{k}: {v}")

    if sev_raw:
        desc_parts.append(f"scc_severity: {sev_raw}")
    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(finding)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(finding)
    refs = collect_refs(finding)

    resolution = ""
    # SCC v2 'nextSteps' is the canonical operator-facing guidance.
    for key in ("nextSteps", "next_steps", "remediation", "Remediation"):
        v = finding.get(key)
        if isinstance(v, list):
            bits = [str(r).strip() for r in v if str(r).strip()]
            if bits:
                resolution = "\n".join(bits)
                break
        elif isinstance(v, str) and v.strip():
            resolution = v.strip()
            break
    if not resolution and isinstance(sp, dict):
        for key in ("Recommendation", "recommendation", "Explanation", "explanation"):
            v = sp.get(key)
            if isinstance(v, str) and v.strip():
                resolution = v.strip()
                break

    external_id = ""
    finding_name = finding.get("name") or finding.get("Name") or ""
    if isinstance(finding_name, str) and finding_name.strip():
        external_id = finding_name.strip().rsplit("/", 1)[-1]
    if not external_id:
        external_id = str(finding.get("canonicalName") or finding.get("canonical_name") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"SCC finding {external_id}",
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
        "tags": ["gcp_scc", "cnapp", "cloud-native-posture"],
    }


def _to_snake(key):
    """camelCase / PascalCase -> snake_case helper (best-effort)."""
    out = []
    for i, ch in enumerate(key):
        if ch.isupper() and i:
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def host_bucket_key(item):
    """Pick a stable bucket key for a SCC finding's primary resource."""
    if not isinstance(item, dict):
        return "__unknown__"
    rname = _extract_resource_name(item)
    return rname or "__unknown__"


def build_host(bucket_key, sample_item, vulns):
    """Build a Faraday host record for the supplied GCP resource bucket."""
    parsed = _parse_resource_name(bucket_key) if bucket_key and bucket_key != "__unknown__" else {}
    rtype = parsed.get("resource_type", "")
    rname = parsed.get("resource_name", "")
    project = parsed.get("project", "")
    location = parsed.get("location", "")
    provider = parsed.get("provider", "")

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
        desc_parts.append(f"resource_name={bucket_key}")
    if rtype:
        desc_parts.append(f"resource_type={rtype}")
    if rname:
        desc_parts.append(f"resource_display_name={rname}")
    if project:
        desc_parts.append(f"project={project}")
    if location:
        desc_parts.append(f"location={location}")
    if provider:
        desc_parts.append(f"provider={provider}")

    if isinstance(sample_item, dict):
        res = sample_item.get("resource") or sample_item.get("Resource")
        if isinstance(res, dict):
            for label_k, key in (
                ("resource_display_name", "displayName"),
                ("resource_project", "projectDisplayName"),
                ("resource_parent", "parentDisplayName"),
                ("resource_type", "type"),
            ):
                v = res.get(key)
                if v and f"{label_k}={v}" not in desc_parts:
                    desc_parts.append(f"{label_k}={v}")
            folders = res.get("folders")
            if isinstance(folders, list) and folders:
                joined = ", ".join(
                    (f.get("resourceFolderDisplayName") or f.get("resourceFolder") or str(f)) for f in folders if f
                )
                if joined:
                    desc_parts.append(f"resource_folders={joined}")

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


def _result_to_dict(result):
    """Coerce an SDK ``ListFindingsResult`` into a plain dict.

    The google-cloud-securitycenter SDK returns protobuf objects; the
    canonical way to flatten them is ``proto.Message.to_dict``. The
    helper is forgiving: dicts pass through, proto objects flatten,
    everything else is dropped.
    """
    if isinstance(result, dict):
        return result
    # proto-plus shape — has a static to_dict.
    to_dict = getattr(type(result), "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict(result)
        except Exception:  # noqa: BLE001
            pass
    # Fallback: try a generic vars()-style flatten.
    try:
        return json.loads(json.dumps(result, default=lambda o: getattr(o, "__dict__", str(o))))
    except Exception:  # noqa: BLE001
        return {}


def fetch_findings(client, parent, filter_clause, max_pages=MAX_PAGES):
    """Paginate ``SecurityCenterClient.list_findings`` with the supplied filter."""
    findings = []
    request = {"parent": parent}
    if filter_clause:
        request["filter"] = filter_clause
    try:
        pager = client.list_findings(request=request)
    except Exception as exc:  # noqa: BLE001
        log(f"SCC list_findings failed: {exc}")
        return findings
    pages = 0
    iterable = pager
    for result in iterable:
        as_dict = _result_to_dict(result)
        if isinstance(as_dict, dict) and as_dict:
            findings.append(as_dict)
        # The proto iterator emits one ListFindingsResult per finding;
        # the page bound below is a best-effort safety net rather than
        # a strict page count.
        if pages >= max_pages * 1000:
            log(f"hit MAX_PAGES safety net ({max_pages}); stopping")
            break
        pages += 1
    return findings


def main():
    started = time.time()
    organization_id = validate_organization_id(env("EXECUTOR_CONFIG_GCP_ORGANIZATION_ID"))
    if not organization_id:
        log("GCP_ORGANIZATION_ID is required")
        sys.exit(1)

    source_id = validate_source(env("EXECUTOR_CONFIG_GCP_SOURCE"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_SCC_MIN_SEVERITY"))
    state = validate_state(env("EXECUTOR_CONFIG_SCC_STATE"))
    allowed_buckets = set(faraday_buckets_at_or_above(min_severity))

    creds_path = env("GOOGLE_APPLICATION_CREDENTIALS")
    if not creds_path:
        log("GOOGLE_APPLICATION_CREDENTIALS is required (path to GCP service account JSON)")
        sys.exit(1)
    if not os.path.isfile(creds_path):
        log(f"GOOGLE_APPLICATION_CREDENTIALS path '{creds_path}' is not a readable file")
        sys.exit(1)

    try:
        from google.cloud import securitycenter_v2  # noqa: WPS433 — lazy
    except ImportError:
        log("google-cloud-securitycenter is not installed in the executor environment")
        sys.exit(1)

    client = securitycenter_v2.SecurityCenterClient()

    parent = build_parent(organization_id, source_id, DEFAULT_LOCATION)
    filter_clause = build_filter(state, min_severity)

    findings = fetch_findings(client, parent, filter_clause)
    log(
        f"Processing {len(findings)} SCC v2 findings "
        f"(organization={organization_id}, source={source_id or 'ALL'}, "
        f"state={state or 'ALL'}, min_severity={min_severity})"
    )

    buckets = {}
    sample_items = {}
    for item in findings:
        key = host_bucket_key(item)
        buckets.setdefault(key, []).append(item)
        if key not in sample_items:
            sample_items[key] = item

    hosts = []
    for key, items in buckets.items():
        vulns = []
        for item in items:
            built = build_vulnerability(item)
            if built is None:
                continue
            if allowed_buckets and built["severity"] not in allowed_buckets:
                continue
            vulns.append(built)
        if not vulns:
            continue
        sample = sample_items.get(key)
        hosts.append(build_host(key, sample, vulns))

    params_bits = [
        f"organization={organization_id}",
        f"min_severity={min_severity}",
    ]
    if source_id:
        params_bits.append(f"source={source_id}")
    if state:
        params_bits.append(f"state={state}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "gcp_scc",
            "command": "gcp_scc",
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
