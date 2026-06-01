#!/usr/bin/env python
"""Microsoft Security Response Center (MSRC) CVRF feed importer.

Pulls the monthly Microsoft Security Update Guide release as a
CVRF (Common Vulnerability Reporting Framework) document from
the public MSRC REST API
(``https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{YYYY-MMM}``)
and emits Faraday bulk-create JSON to stdout.  Microsoft
publishes one CVRF document per Patch Tuesday release; each
document carries every CVE Microsoft addressed that month with
per-product affected-version metadata, CVSS scoring, exploit
status, and the canonical KB / advisory remediation URLs.

Endpoint used:
  GET {MSRC_HOST}/cvrf/v3.0/cvrf/{YYYY-MMM}
      -> Returns the canonical MSRC CVRF envelope:
      ``{"DocumentTitle": {"Value": "..."},
         "DocumentTracking": {"Identification": {"ID": {"Value": "..."}},
                              "CurrentReleaseDate": "...",
                              "InitialReleaseDate": "..."},
         "DocumentPublisher": {...},
         "ProductTree": {"FullProductName": [...], "Branch": [...]},
         "Vulnerability": [ {"CVE": "CVE-...", "Title": {"Value": "..."},
                              "Notes": [...], "CVSSScoreSets": [...],
                              "ProductStatuses": [...], "Remediations": [...],
                              "Threats": [...], "RevisionHistory": [...]} ]}``
      The release ID is the slug ``YYYY-MMM`` where ``MMM`` is
      the three-letter or full month name (e.g. ``2026-May``,
      ``2026-Jan``).  MSRC also accepts the slug case-insensitively
      but the documented examples use title case so we normalise
      to title case in the URL.

``MSRC_YEAR_MONTH`` is a mandatory string in either ``YYYY-MMM``
form (``2026-May`` / ``2026-Jan``) or ``YYYY-MM`` numeric form
(``2026-05``).  The numeric form is translated to the title-case
month name MSRC expects before the request is issued.  Malformed
input aborts the run with an explicit error so the operator can
correct the manifest.

``MSRC_PRODUCT`` is an optional case-insensitive substring filter
applied to the affected-product set after the CVRF document is
fetched.  A CVE is kept when any of its affected ``ProductID`` ->
``FullProductName`` mappings contain the filter substring;
otherwise it is dropped.  Blank / missing input keeps every CVE
in the release (the typical operational mode where the operator
wants the whole Patch Tuesday rollup).

Each CVE becomes one Faraday vulnerability under a single
synthetic ``0.0.0.0`` host with hostname ``msrc``.  MSRC entries
are CVE-keyed not host-keyed — the operator's other agents emit
the host-side findings this feed is correlated against.  The
vulnerability carries ``tags: ['msrc']`` and surfaces the CVE
id, MSRC title, affected products, CVSS score / severity / vector,
exploit status, and KB / advisory remediation URLs in both the
description and the refs list so the operator can pivot from a
Faraday finding back to the canonical MSRC release.

Severity is derived from CVSS v3 — the explicit ``BaseSeverity``
text (``Critical`` / ``Important`` / ``Moderate`` / ``Low`` /
``None``) is mapped to Faraday's ladder (``Important`` -> ``high``
per MSRC's published severity rubric) when present, falling back
to a numeric ``BaseScore`` bucket otherwise:
  * BaseScore >= 9.0 -> critical
  * BaseScore >= 7.0 -> high
  * BaseScore >= 4.0 -> medium
  * BaseScore  > 0.0 -> low
  * BaseScore == 0.0 -> info

Unscored CVEs (typical for advisories that document a defence-in-
depth update rather than a scored vulnerability) default to
``info`` — we don't synthesise a ranking MSRC hasn't published.
CVEs whose ``Threats`` block flags a known exploit
(``ExploitStatus`` containing ``Exploited: Yes`` or ``Exploit
Code Maturity: Functional`` etc.) are bumped to ``critical``
regardless of the CVSS bucket — active exploitation overrides
the calendar floor.

Auth: ``MSRC_API_KEY`` is an optional ``api-key`` HTTP header on
every request.  The MSRC API requires a key for sustained use
(the developer portal at https://msrc.microsoft.com/developer
issues free keys after signup) but it tolerates unauthenticated
requests at a lower rate; the executor is fully functional
without one — supplying a key just raises the throughput
ceiling.  ``MSRC_HOST`` may optionally be overridden via env to
point at a federated mirror or an offline cache; defaults to
``https://api.msrc.microsoft.com``.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

TIMEOUT = 60
DEFAULT_HOST = "https://api.msrc.microsoft.com"
CVRF_PATH = "/cvrf/v3.0/cvrf"

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

MONTH_NAMES = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]
MONTH_TO_INDEX = {name.lower(): idx for idx, name in enumerate(MONTH_NAMES, start=1)}
MONTH_TO_INDEX.update({name.lower()[:3]: idx for idx, name in enumerate(MONTH_NAMES, start=1)})

# MSRC publishes BaseSeverity using its own marketing nomenclature
# (Critical / Important / Moderate / Low).  We map these onto
# Faraday's standard ladder per the Microsoft Security Update
# Guide rubric — Important is treated as `high` since MSRC
# documents it as "Exploitation could result in compromise of
# the confidentiality, integrity, or availability of user data".
MSRC_BASE_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "IMPORTANT": "high",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
}

YEAR_MONTH_RE = re.compile(r"^(\d{4})[-/](\w+)$")


def log(msg):
    print(f"{datetime.utcnow()} - Msrc: {msg}", file=sys.stderr, flush=True)


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


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on MSRC_HOST.

    Defaults to ``https://api.msrc.microsoft.com`` (the canonical
    MSRC REST host) when the env override is missing / blank.
    Whitespace is trimmed and ``https://`` is added automatically
    when the operator pasted in a bare FQDN (on-prem mirrors
    typically use raw hostnames).
    """
    if not host:
        return DEFAULT_HOST
    if not isinstance(host, str):
        return DEFAULT_HOST
    text = host.strip().rstrip("/")
    if not text:
        return DEFAULT_HOST
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def normalize_year_month(value):
    """Normalise MSRC_YEAR_MONTH into the canonical ``YYYY-MMM`` slug.

    Accepts ``YYYY-MMM`` (month name or 3-letter abbreviation,
    case-insensitive) and ``YYYY-MM`` (numeric, leading-zero
    optional).  Returns the canonical title-case slug MSRC's
    URL path expects (e.g. ``2026-May``) or ``None`` when the
    input cannot be parsed.  Trailing whitespace is tolerated.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    match = YEAR_MONTH_RE.match(text)
    if not match:
        return None
    year_str, month_str = match.group(1), match.group(2)
    try:
        year = int(year_str)
    except (TypeError, ValueError):
        return None
    if year < 1999 or year > 2999:
        return None
    month_str = month_str.strip()
    if not month_str:
        return None
    # Numeric month branch
    if month_str.isdigit():
        try:
            month_idx = int(month_str)
        except (TypeError, ValueError):
            return None
        if month_idx < 1 or month_idx > 12:
            return None
        return f"{year:04d}-{MONTH_NAMES[month_idx - 1]}"
    # Named month branch
    idx = MONTH_TO_INDEX.get(month_str.lower())
    if idx is None:
        return None
    return f"{year:04d}-{MONTH_NAMES[idx - 1]}"


def normalize_product_filter(value):
    """Coerce MSRC_PRODUCT into a lowercased substring filter.

    None / blank / non-string -> ``None`` (no filtering — every
    CVE in the release is kept).  Whitespace is trimmed and the
    value is lowercased so the per-CVE filter check can use a
    case-insensitive ``in`` against the product-name set.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    return text.lower()


def build_cvrf_url(host, year_month_slug):
    """Build the per-release CVRF URL for a YYYY-MMM slug.

    The path segment is URL-encoded defensively (the slug is
    expected to be ASCII but the API tolerates encoded forms)
    so any operator typo can't break out of the path.
    """
    base = normalize_base_url(host)
    slug = quote(str(year_month_slug or "").strip(), safe="")
    return f"{base}{CVRF_PATH}/{slug}"


def request_headers(api_key):
    """Build the headers dict for a single MSRC GET.

    ``Accept: application/json`` is always sent.  ``api-key`` is
    included only when the operator supplied a non-blank
    ``MSRC_API_KEY``; the MSRC API tolerates the header being
    absent (subject to the lower rate limit).
    """
    headers = {"Accept": "application/json"}
    if isinstance(api_key, str) and api_key.strip():
        headers["api-key"] = api_key.strip()
    return headers


def extract_document_meta(body):
    """Pull document-level metadata for provenance.

    Returns whatever MSRC-documented fields are present: title,
    tracking id, publisher contact, initial / current release
    dates.  Used to embed catalog-version style breadcrumbs on
    the synthetic host so operators can pivot from a Faraday
    finding back to the exact CVRF release that produced it.
    """
    out = {}
    if not isinstance(body, dict):
        return out
    title_block = body.get("DocumentTitle")
    if isinstance(title_block, dict):
        title = title_block.get("Value")
        if isinstance(title, str) and title.strip():
            out["title"] = title.strip()
    tracking = body.get("DocumentTracking")
    if isinstance(tracking, dict):
        ident = tracking.get("Identification")
        if isinstance(ident, dict):
            ident_id = ident.get("ID")
            if isinstance(ident_id, dict):
                v = ident_id.get("Value")
                if isinstance(v, str) and v.strip():
                    out["id"] = v.strip()
        for key, dest in (
            ("InitialReleaseDate", "initialReleaseDate"),
            ("CurrentReleaseDate", "currentReleaseDate"),
        ):
            v = tracking.get(key)
            if isinstance(v, str) and v.strip():
                out[dest] = v.strip()
    publisher = body.get("DocumentPublisher")
    if isinstance(publisher, dict):
        contact = publisher.get("ContactDetails")
        if isinstance(contact, str) and contact.strip():
            out["publisher"] = contact.strip()
    return out


def build_product_map(body):
    """Build the ProductID -> FullProductName lookup map.

    The CVRF ProductTree carries a flat ``FullProductName`` list
    plus a nested ``Branch`` tree.  Both are walked so callers
    can resolve a ProductID from either shape (Microsoft has
    historically used both interchangeably across release years).
    Returns a dict; missing / non-dict input yields ``{}``.
    """
    out = {}
    if not isinstance(body, dict):
        return out
    tree = body.get("ProductTree")
    if not isinstance(tree, dict):
        return out
    flat = tree.get("FullProductName")
    if isinstance(flat, list):
        for entry in flat:
            if not isinstance(entry, dict):
                continue
            pid = entry.get("ProductID")
            value = entry.get("Value")
            if isinstance(pid, str) and isinstance(value, str) and pid.strip() and value.strip():
                out[pid.strip()] = value.strip()

    def walk(branches):
        if not isinstance(branches, list):
            return
        for b in branches:
            if not isinstance(b, dict):
                continue
            child = b.get("FullProductName")
            if isinstance(child, dict):
                pid = child.get("ProductID")
                value = child.get("Value")
                if isinstance(pid, str) and isinstance(value, str) and pid.strip() and value.strip():
                    out.setdefault(pid.strip(), value.strip())
            walk(b.get("Branch"))

    walk(tree.get("Branch"))
    return out


def extract_vulnerabilities(body):
    """Pull the inner ``Vulnerability`` list from a CVRF envelope.

    The canonical MSRC envelope wraps every vuln under the
    top-level ``Vulnerability`` key.  Federated / mirror stacks
    that emit bare-list / ``data`` / ``results`` / ``items``
    envelopes are accepted for resilience.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("Vulnerability", "vulnerabilities", "data", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_cve_id(vuln):
    """Pull the canonical CVE id from a CVRF Vulnerability entry."""
    if not isinstance(vuln, dict):
        return ""
    raw = vuln.get("CVE")
    if isinstance(raw, str) and raw.strip():
        return raw.strip().upper()
    return ""


def extract_title(vuln):
    """Pull the human-readable vulnerability title."""
    if not isinstance(vuln, dict):
        return ""
    title = vuln.get("Title")
    if isinstance(title, dict):
        v = title.get("Value")
        if isinstance(v, str) and v.strip():
            return v.strip()
    if isinstance(title, str) and title.strip():
        return title.strip()
    return ""


def extract_description(vuln):
    """Pull the description text from the Notes block.

    CVRF Notes are typed (Description / FAQ / Tag / Legal / ...);
    we prefer ``Description`` then fall back to the first non-
    empty note so callers always get something to surface.
    """
    if not isinstance(vuln, dict):
        return ""
    notes = vuln.get("Notes")
    if not isinstance(notes, list):
        return ""
    fallback = ""
    for note in notes:
        if not isinstance(note, dict):
            continue
        value = note.get("Value")
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text:
            continue
        note_type = note.get("Type")
        if isinstance(note_type, str) and note_type.strip().lower() == "description":
            return text
        if not fallback:
            fallback = text
    return fallback


def extract_cvss(vuln):
    """Pick the best-available CVSS score block.

    Returns a normalised dict with ``baseScore``, ``baseSeverity``
    (upper-cased), ``vectorString`` and ``version``, or ``None``
    when no scored block is attached.  Multiple score sets are
    common (one per affected product); we pick the highest
    ``BaseScore`` so the surfaced severity reflects the worst-case
    impact.
    """
    if not isinstance(vuln, dict):
        return None
    score_sets = vuln.get("CVSSScoreSets")
    if not isinstance(score_sets, list):
        return None
    best = None
    for entry in score_sets:
        if not isinstance(entry, dict):
            continue
        score = entry.get("BaseScore")
        try:
            s = float(score)
        except (TypeError, ValueError):
            continue
        sev_raw = entry.get("BaseSeverity") or entry.get("baseSeverity")
        sev = sev_raw.strip().upper() if isinstance(sev_raw, str) else ""
        vector = entry.get("Vector") if isinstance(entry.get("Vector"), str) else ""
        version = entry.get("Version") if isinstance(entry.get("Version"), str) else ""
        candidate = {
            "baseScore": s,
            "baseSeverity": sev,
            "vectorString": vector.strip(),
            "version": version.strip() or "3.x",
        }
        if best is None or candidate["baseScore"] > best["baseScore"]:
            best = candidate
    return best


def severity_from_cvss(cvss):
    """Map an MSRC CVSS block to a Faraday severity bucket.

    Prefers the explicit ``BaseSeverity`` text (``Critical`` /
    ``Important`` / ``Moderate`` / ``Low`` / ``None``); falls
    back to numeric ``BaseScore`` bucketing otherwise.  Returns
    ``None`` when the block is missing entirely so the caller can
    choose its own default (we surface unscored CVEs as ``info``).
    """
    if not isinstance(cvss, dict):
        return None
    sev_text = cvss.get("baseSeverity")
    if isinstance(sev_text, str):
        mapped = MSRC_BASE_SEVERITY_MAP.get(sev_text.strip().upper())
        if mapped:
            return mapped
    score = cvss.get("baseScore")
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def is_exploited(vuln):
    """Return True when MSRC flags active in-the-wild exploitation.

    The CVRF Threats block carries per-product entries with a
    Type identifying the threat category and a Description with
    free-form details.  Microsoft surfaces "Publicly Disclosed:
    Yes" / "Exploited: Yes" / "Exploit Code Maturity: Functional"
    here — any of these signals an exploit override of the
    calendar severity floor.
    """
    if not isinstance(vuln, dict):
        return False
    threats = vuln.get("Threats")
    if not isinstance(threats, list):
        return False
    for entry in threats:
        if not isinstance(entry, dict):
            continue
        desc = entry.get("Description")
        if isinstance(desc, dict):
            desc = desc.get("Value")
        if not isinstance(desc, str):
            continue
        text = desc.strip().lower()
        if not text:
            continue
        if "exploited:yes" in text.replace(" ", ""):
            return True
        if "exploit code maturity" in text and "functional" in text:
            return True
        if "publicly disclosed:yes" in text.replace(" ", "") and "exploited" in text:
            return True
    return False


def extract_threat_summary(vuln):
    """Pull a compact threat-status summary string for the description."""
    if not isinstance(vuln, dict):
        return ""
    threats = vuln.get("Threats")
    if not isinstance(threats, list):
        return ""
    seen = []
    for entry in threats:
        if not isinstance(entry, dict):
            continue
        desc = entry.get("Description")
        if isinstance(desc, dict):
            desc = desc.get("Value")
        if not isinstance(desc, str):
            continue
        text = desc.strip()
        if not text or text in seen:
            continue
        seen.append(text)
    return "; ".join(seen)


def extract_affected_products(vuln, product_map):
    """Resolve a vuln's affected ProductID list into product names.

    The ProductStatuses block carries ``{"Type": "Known Affected",
    "ProductID": ["..."]}`` entries (the ID is sometimes a string
    and sometimes a list per Microsoft's evolving schema).  We
    resolve every ProductID via ``product_map`` and return a
    sorted, deduped list of product names.
    """
    out = []
    if not isinstance(vuln, dict):
        return out
    statuses = vuln.get("ProductStatuses")
    if not isinstance(statuses, list):
        return out
    seen = set()
    for status in statuses:
        if not isinstance(status, dict):
            continue
        pids = status.get("ProductID")
        if isinstance(pids, str):
            pids = [pids]
        if not isinstance(pids, list):
            continue
        for pid in pids:
            if not isinstance(pid, str):
                continue
            key = pid.strip()
            if not key:
                continue
            name = product_map.get(key) if isinstance(product_map, dict) else None
            display = name or key
            if display in seen:
                continue
            seen.add(display)
            out.append(display)
    out.sort()
    return out


def extract_remediations(vuln):
    """Pull the per-CVE remediation entries (KB articles / advisories).

    Each remediation carries a Type (Vendor Fix / Mitigation /
    Workaround / Known Issue), an URL pointing at the KB article
    or advisory, an optional Description, and an optional
    SubType.  Returns a list of normalised dicts for downstream
    refs + resolution composition.
    """
    out = []
    if not isinstance(vuln, dict):
        return out
    rems = vuln.get("Remediations")
    if not isinstance(rems, list):
        return out
    for entry in rems:
        if not isinstance(entry, dict):
            continue
        url = entry.get("URL")
        if not isinstance(url, str) or not url.strip():
            url = ""
        rtype = entry.get("Type")
        if not isinstance(rtype, str):
            rtype = ""
        subtype = entry.get("SubType")
        if not isinstance(subtype, str):
            subtype = ""
        desc = entry.get("Description")
        if isinstance(desc, dict):
            desc = desc.get("Value")
        if not isinstance(desc, str):
            desc = ""
        out.append(
            {
                "url": url.strip(),
                "type": rtype.strip(),
                "subtype": subtype.strip(),
                "description": desc.strip(),
            }
        )
    return out


def filter_by_product(vulns, product_filter, product_map):
    """Apply the MSRC_PRODUCT substring filter client-side.

    Keeps a vuln when any of its resolved affected-product names
    contain ``product_filter`` (lowercased substring match).
    When ``product_filter`` is ``None`` the whole list passes
    through unchanged.  Vulns with no resolvable products are
    DROPPED when a filter is set (we cannot prove they match the
    filter) but KEPT when no filter is supplied.
    """
    if product_filter is None:
        return list(vulns) if isinstance(vulns, list) else []
    out = []
    if not isinstance(vulns, list):
        return out
    needle = str(product_filter).strip().lower()
    if not needle:
        return list(vulns)
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        products = extract_affected_products(vuln, product_map)
        if not products:
            continue
        for name in products:
            if needle in name.lower():
                out.append(vuln)
                break
    return out


def collect_cves(vuln):
    """Pull the canonical CVE id from an MSRC Vulnerability entry."""
    out = []
    if not isinstance(vuln, dict):
        return out
    cve = extract_cve_id(vuln)
    if cve:
        out.append(cve)
    return out


def collect_refs(vuln, product_map, doc_meta):
    """Build the refs list for one MSRC Vulnerability entry.

    Includes the canonical NVD CVE permalink, the MSRC update
    guide vulnerability permalink, every Remediation URL, and
    explicit ``Msrc-*`` pivots (CVE id, release id / dates,
    CVSS score / severity / vector, exploit status, affected
    product count) so operators can pivot from a Faraday finding
    back to the exact CVRF release field set.
    """
    refs = []
    seen = set()

    def add(text, ref_type="other"):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": ref_type})

    if not isinstance(vuln, dict):
        return refs

    cve = extract_cve_id(vuln)
    if cve:
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")
        add(f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}")
        add(f"Msrc-CveID: {cve}")

    cvss = extract_cvss(vuln)
    if cvss is not None:
        add(f"Msrc-CvssVersion: {cvss['version']}")
        add(f"Msrc-CvssScore: {cvss['baseScore']}")
        if cvss.get("baseSeverity"):
            add(f"Msrc-CvssSeverity: {cvss['baseSeverity']}")
        if cvss.get("vectorString"):
            add(f"Msrc-CvssVector: {cvss['vectorString']}")

    if is_exploited(vuln):
        add("Msrc-Exploited: Yes")
    threat_text = extract_threat_summary(vuln)
    if threat_text:
        add(f"Msrc-Threats: {threat_text[:300]}")

    products = extract_affected_products(vuln, product_map)
    if products:
        add(f"Msrc-AffectedProductCount: {len(products)}")

    for rem in extract_remediations(vuln):
        url = rem.get("url") or ""
        if not url:
            continue
        tag_text = ""
        rtype = rem.get("type") or ""
        if rtype:
            tag_text = f" [{rtype}]"
        add(f"{url}{tag_text}")

    if isinstance(doc_meta, dict):
        rel_id = doc_meta.get("id")
        if rel_id not in (None, ""):
            add(f"Msrc-ReleaseID: {rel_id}")
        current = doc_meta.get("currentReleaseDate")
        if current not in (None, ""):
            add(f"Msrc-CurrentReleaseDate: {current}")
        initial = doc_meta.get("initialReleaseDate")
        if initial not in (None, ""):
            add(f"Msrc-InitialReleaseDate: {initial}")

    return refs


def build_vulnerability(vuln, product_map, doc_meta):
    """Build a Faraday vulnerability dict for one CVRF entry."""
    if not isinstance(vuln, dict):
        return None

    cve = extract_cve_id(vuln)
    title = extract_title(vuln)
    description = extract_description(vuln)
    cvss = extract_cvss(vuln)
    exploited = is_exploited(vuln)

    sev = severity_from_cvss(cvss)
    severity = sev if sev else "info"
    if exploited and SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER["critical"]:
        severity = "critical"

    name_parts = ["[MSRC]"]
    if cve:
        name_parts.append(cve)
    if title:
        name_parts.append(title[:150])
    elif not cve:
        name_parts.append("MSRC advisory")
    name = " ".join(name_parts).strip()

    products = extract_affected_products(vuln, product_map)
    remediations = extract_remediations(vuln)
    threat_text = extract_threat_summary(vuln)

    desc_parts = []
    if cve:
        desc_parts.append(f"cve: {cve}")
    if title:
        desc_parts.append(f"title: {title}")
    if isinstance(doc_meta, dict):
        rel_id = doc_meta.get("id")
        if rel_id not in (None, ""):
            desc_parts.append(f"releaseId: {rel_id}")
        current = doc_meta.get("currentReleaseDate")
        if current not in (None, ""):
            desc_parts.append(f"currentReleaseDate: {current}")
    if cvss is not None:
        desc_parts.append(
            f"cvss{cvss['version']}: baseScore={cvss['baseScore']} " f"severity={cvss['baseSeverity'] or 'n/a'}"
        )
        if cvss.get("vectorString"):
            desc_parts.append(f"cvssVector: {cvss['vectorString']}")
    if exploited:
        desc_parts.append("exploited: Yes (active in-the-wild exploitation reported)")
    if threat_text:
        desc_parts.append(f"threats: {threat_text}")
    if products:
        shown = ", ".join(products[:8])
        if len(products) > 8:
            shown += f" (+{len(products) - 8} more)"
        desc_parts.append(f"affectedProducts ({len(products)}): {shown}")
    if remediations:
        desc_parts.append(f"remediations: {len(remediations)}")
    if description:
        desc_parts.append(f"description: {description}")

    patch_urls = [r["url"] for r in remediations if r.get("type", "").lower() == "vendor fix" and r.get("url")]
    if patch_urls:
        resolution = (
            f"Apply Microsoft vendor fixes for {cve or 'this advisory'} per the "
            f"linked KB articles ({len(patch_urls)} URL(s) attached)."
        )
    elif remediations:
        resolution = (
            f"Apply mitigations / workarounds for {cve or 'this advisory'} per the "
            "MSRC remediation guidance attached."
        )
    else:
        resolution = (
            f"Track {cve or 'this advisory'} via the MSRC update guide and apply "
            "vendor fixes once Microsoft publishes them."
        )

    external_id = cve or name[:200]

    return {
        "name": str(name).strip()[:200] or "MSRC advisory",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(vuln, product_map, doc_meta),
        "cve": collect_cves(vuln),
        "cvss3": {},
        "tags": ["msrc"],
    }


def build_host(vulns, doc_meta, year_month_slug, vulns_total):
    """Build the single synthetic host that carries every MSRC vuln.

    MSRC entries are CVE-keyed not host-keyed (the operator's
    other agents emit the host-side findings this feed is
    correlated against) so we collapse the whole release under
    one synthetic ``0.0.0.0`` host with hostname ``msrc``.  The
    host description carries the document metadata + release id
    + pre/post-filter vuln counts so operators can pivot from
    the host page back to the exact CVRF release that produced
    the run.
    """
    desc_parts = ["source=msrc"]
    if year_month_slug:
        desc_parts.append(f"release={year_month_slug}")
    if isinstance(doc_meta, dict):
        for key in ("id", "title", "currentReleaseDate", "initialReleaseDate"):
            v = doc_meta.get(key)
            if v in (None, ""):
                continue
            desc_parts.append(f"{key}={v}")
    try:
        desc_parts.append(f"cvrf_total={int(vulns_total)}")
    except (TypeError, ValueError):
        desc_parts.append("cvrf_total=?")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["msrc"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url, api_key):
    """GET a single MSRC URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient MSRC outage doesn't crash the
    dispatcher.  Returns ``None`` on any failure; the caller is
    expected to treat that as "no records" and continue.
    """
    try:
        resp = requests_module.get(
            url,
            timeout=TIMEOUT,
            headers=request_headers(api_key),
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"MSRC release not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"MSRC request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"MSRC response was not JSON ({url})")
        return None


def main():
    started = time.time()

    raw_year_month = env("EXECUTOR_CONFIG_MSRC_YEAR_MONTH", required=True)
    year_month_slug = normalize_year_month(raw_year_month)
    if not year_month_slug:
        log(
            f"MSRC_YEAR_MONTH {raw_year_month!r} is not a valid YYYY-MMM / "
            "YYYY-MM slug (e.g. '2026-May' or '2026-05')"
        )
        sys.exit(1)
    product_filter = normalize_product_filter(env("EXECUTOR_CONFIG_MSRC_PRODUCT"))
    host = env("MSRC_HOST", default=DEFAULT_HOST)
    api_key = env("MSRC_API_KEY")

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    url = build_cvrf_url(host, year_month_slug)
    body = fetch_url(requests, url, api_key)
    if body is None:
        log(f"MSRC fetch returned no body for release {year_month_slug}; nothing to emit")
        body = {}

    doc_meta = extract_document_meta(body)
    product_map = build_product_map(body)
    all_vulns = extract_vulnerabilities(body)
    filtered = filter_by_product(all_vulns, product_filter, product_map)

    vulns = []
    for entry in filtered:
        vuln = build_vulnerability(entry, product_map, doc_meta)
        if vuln is not None:
            vulns.append(vuln)

    log(
        f"Processed {len(vulns)} MSRC records "
        f"(release={year_month_slug}, total={len(all_vulns)}, "
        f"product_filter={product_filter or 'none'}, "
        f"api_key={'set' if (isinstance(api_key, str) and api_key.strip()) else 'none'})"
    )

    hosts_out = [build_host(vulns, doc_meta, year_month_slug, len(all_vulns))]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "msrc",
            "command": "msrc",
            "params": (f"release={year_month_slug} " f"product={product_filter or ''}"),
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
