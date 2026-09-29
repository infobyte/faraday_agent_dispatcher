#!/usr/bin/env python
"""WhiteHat Sentinel REST API importer.

Pulls Dynamic Application Security Testing findings from a legacy
WhiteHat Sentinel tenant and emits Faraday bulk-create JSON to stdout.
Each WhiteHat site (the per-application scan target) becomes one
Faraday host (``ip`` = synthetic ``0.0.0.0`` because WhiteHat reports
target URLs, not IPs); per-site vulnerabilities are attached as Faraday
vulnerabilities — one per vuln id with engine prefix ``[DAST]``.

Endpoints used:
  GET /api/site
      -> list every site visible to the API key. Filtered client-side
      by ``WH_SITE_ID`` so an empty match returns a clear error rather
      than fanning out across the whole catalogue.
  GET /api/site/{site_id}
      -> per-site metadata (label / target URL / status / found
      counts). Used to populate the host hostname / description.
  GET /api/vuln
      -> per-site vulnerability list, paginated via ``page`` /
      ``page_size``. The query parameter ``query_site=<site_id>``
      scopes the response to a single site; ``display_attack_vectors``,
      ``display_solution`` and ``display_description`` ensure the rich
      fields ride along on the listing instead of requiring a per-id
      detail fetch.

Auth: WhiteHat Sentinel uses a single long-lived API key on every
call — accepted either as the ``key=<WH_API_KEY>`` query parameter
(canonical) or as an ``X-API-Key: <WH_API_KEY>`` header. The executor
sends both so tenants fronted by proxies that strip one form still
authenticate. A pre-built ``Bearer <token>`` value in WH_API_KEY
short-circuits the API-key scheme and is sent as the Authorization
header verbatim — useful for tenants fronted by an OAuth gateway after
the WhiteHat → Black Duck Continuous Dynamic acquisition.

WH_HOST is the WhiteHat Sentinel base URL (e.g.
``https://sentinel.whitehatsec.com``). When the bare hostname is given
the executor prefixes ``https://``. Hosts already pointing at
``.../api`` are accepted as-is.

Note: WhiteHat is now Black Duck Continuous Dynamic; this executor is
kept for orgs still on the legacy product where the v2 endpoint shapes
(``/api/site``, ``/api/vuln``) are unchanged from the WhiteHat era.
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# WhiteHat Sentinel surfaces severity as a 1-5 integer scale on the
# ``severity`` field. The legacy UI used five textual buckets which
# also appear on some endpoints (and on the ``risk`` field on newer
# Black Duck Continuous Dynamic responses). Map both shapes to Faraday
# buckets so either surface lands in the same place.
WH_NUMERIC_SEVERITY = {
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: "info",
    0: "info",
}

WH_STRING_SEVERITY = {
    "critical": "critical",
    "urgent": "critical",
    "high": "high",
    "major": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "note": "info",
    "none": "info",
    "unspecified": "info",
    "unknown": "info",
    "negligible": "info",
    "trivial": "info",
}

# WhiteHat Sentinel vulnerability lifecycle:
#   open / reopened -> open
#   closed / fixed / patched -> closed
#   mitigated / accepted / ignored -> risk-accepted (analyst declared
#   not-an-issue or compensating-control)
WH_STATUS_TO_FARADAY = {
    "open": "open",
    "new": "open",
    "in_progress": "open",
    "inprogress": "open",
    "reopened": "open",
    "active": "open",
    "closed": "closed",
    "fixed": "closed",
    "patched": "closed",
    "resolved": "closed",
    "remediated": "closed",
    "mitigated": "risk-accepted",
    "accepted": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "acceptedrisk": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "invalid": "risk-accepted",
    "not_applicable": "risk-accepted",
    "notapplicable": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - WhiteHatSentinel: {msg}", file=sys.stderr, flush=True)


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
    """Normalise WH_HOST into a base URL ready for ``/api/...``.

    Accepts bare hostnames (prefixes ``https://``), full ``http(s)://``
    URLs, and trailing slashes. Hosts already pointing at ``.../api``
    are stripped of the suffix so the canonical ``{base}/api/site`` and
    ``{base}/api/vuln`` URLs assemble cleanly.
    """
    if not host:
        return ""
    base = str(host).strip()
    if not base:
        return ""
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    base = base.rstrip("/")
    lowered = base.lower()
    if lowered.endswith("/api"):
        base = base[:-4].rstrip("/")
    return base


def build_auth(api_key):
    """Build (auth_params, auth_headers) for WhiteHat Sentinel calls.

    Canonical WhiteHat scheme is ``key=<API_KEY>`` query parameter; we
    additionally send ``X-API-Key: <API_KEY>`` so proxies that strip
    one form still authenticate. A pre-built ``Bearer <token>`` value
    is forwarded verbatim as the Authorization header — useful when the
    tenant is fronted by an OAuth gateway after the Black Duck
    Continuous Dynamic migration.
    """
    if not api_key:
        return {}, {}
    text = str(api_key).strip()
    if text.lower().startswith("bearer "):
        return {}, {"Authorization": text}
    return {"key": text}, {"X-API-Key": text}


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"WH_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


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


def severity_from_whitehat(value, cvss=None):
    """Map a WhiteHat severity (numeric 1-5 or string enum) to a Faraday bucket.

    Falls back to CVSS bucketing on the provided ``cvss`` argument when
    the primary value is missing or unrecognised. Numeric inputs in the
    1-5 range route through the numeric map; anything outside it is
    treated as a CVSS-style score.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            ival = int(value)
            if 0 <= ival <= 5 and ival == value:
                return WH_NUMERIC_SEVERITY.get(ival, "info")
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in WH_STRING_SEVERITY:
            return WH_STRING_SEVERITY[text]
        try:
            num = float(text)
        except ValueError:
            num = None
        if num is not None:
            ival = int(num)
            if 0 <= ival <= 5 and ival == num:
                return WH_NUMERIC_SEVERITY.get(ival, "info")
            return severity_from_cvss(num)
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_whitehat(vuln):
    """Derive Faraday status from a WhiteHat vulnerability payload.

    Per-vuln analyst flags win over lifecycle status — a vulnerability
    that's still ``open`` but marked ``false_positive`` (or whose
    ``mitigation_status`` is ``accepted``) surfaces as risk-accepted.
    """
    if not isinstance(vuln, dict):
        return "open"
    if vuln.get("ignored") is True or vuln.get("muted") is True:
        return "risk-accepted"
    if vuln.get("suppressed") is True:
        return "risk-accepted"
    if vuln.get("falsePositive") is True or vuln.get("false_positive") is True:
        return "risk-accepted"
    if vuln.get("accepted") is True or vuln.get("mitigated") is True:
        return "risk-accepted"
    if vuln.get("fixed") is True or vuln.get("resolved") is True:
        return "closed"
    for key in ("status", "state", "vuln_status", "vulnStatus", "mitigation_status", "mitigationStatus"):
        raw = vuln.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value")
        if isinstance(raw, str):
            text = raw.strip().lower()
            if not text:
                continue
            compact_underscore = text.replace(" ", "_").replace("-", "_")
            mapped = WH_STATUS_TO_FARADAY.get(text)
            if mapped:
                return mapped
            mapped = WH_STATUS_TO_FARADAY.get(compact_underscore)
            if mapped:
                return mapped
            compact = text.replace(" ", "").replace("-", "").replace("_", "")
            mapped = WH_STATUS_TO_FARADAY.get(compact)
            if mapped:
                return mapped
    return "open"


def request_json(method, url, headers, params=None, payload=None):
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=payload,
            timeout=TIMEOUT,
            verify=False,
        )
    except requests.RequestException as exc:
        log(f"{method} {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). Check WH_API_KEY.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {url}. Check API key scope / site permissions.")
        return None
    if resp.status_code == 404:
        log(f"{method} {url} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"{method} {url} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        log(f"{method} {url} returned non-JSON body")
        return None


def extract_list(body, *keys):
    """Pluck a list value from common WhiteHat REST shapes.

    WhiteHat wraps list responses in a ``collection`` key (legacy) and
    later builds also use ``items`` / ``data``. Both shapes are tried
    before falling back to the bare-list shape.
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for candidate in keys:
            value = body.get(candidate)
            if isinstance(value, list):
                return value
        for candidate in ("collection", "items", "results", "data", "values", "content"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def get_site(base_url, site_id, auth_params, headers):
    """Resolve site metadata via /api/site/{id} with a /api/site fallback.

    Some legacy WhiteHat tenants disable the per-id endpoint; in that
    case the list endpoint is walked and filtered client-side. Either
    way the returned dict (possibly empty) carries label / url / status.
    """
    direct = request_json(
        "GET",
        f"{base_url}/api/site/{site_id}",
        headers,
        params=auth_params,
    )
    if isinstance(direct, dict) and direct and (direct.get("id") or direct.get("label") or direct.get("url")):
        return direct
    listing = request_json(
        "GET",
        f"{base_url}/api/site",
        headers,
        params=auth_params,
    )
    target = str(site_id).strip()
    for entry in extract_list(listing, "sites"):
        if not isinstance(entry, dict):
            continue
        candidate = entry.get("id") or entry.get("site_id") or entry.get("siteId")
        if candidate is None:
            continue
        if str(candidate).strip() == target:
            return entry
    return {}


def get_vulnerabilities(base_url, site_id, auth_params, headers):
    """GET /api/vuln scoped to ``site_id`` → paginated vulnerability list.

    WhiteHat paginates via ``page`` (1-based) + ``page_size``. The
    ``query_site`` parameter is the canonical site scoping filter;
    ``display_attack_vectors`` / ``display_solution`` /
    ``display_description`` request the rich fields inline so a
    per-vuln detail fetch isn't required.
    """
    issues = []
    page = 1
    for _ in range(MAX_PAGES):
        params = dict(auth_params)
        params.update(
            {
                "query_site": site_id,
                "page": page,
                "page_size": PAGE_SIZE,
                "display_attack_vectors": 1,
                "display_solution": 1,
                "display_description": 1,
            }
        )
        body = request_json(
            "GET",
            f"{base_url}/api/vuln",
            headers,
            params=params,
        )
        if body is None:
            break
        chunk = extract_list(body, "vulns", "vulnerabilities", "vuln")
        if not chunk:
            break
        for entry in chunk:
            if isinstance(entry, dict):
                issues.append(entry)
        total = None
        if isinstance(body, dict):
            total = body.get("total") or body.get("totalItems") or body.get("total_items") or body.get("found")
        if isinstance(total, int) and len(issues) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return issues


def cvss_score(vuln):
    """Pull a numeric CVSS score out of a WhiteHat vulnerability payload.

    Returns the max score found across the WhiteHat v3 / v2 surfaces so
    the imported severity matches the higher of the two scoring systems.
    """
    if not isinstance(vuln, dict):
        return None
    best = None
    for key in (
        "cvss_v3_score",
        "cvssV3Score",
        "cvss_v3",
        "cvssV3",
        "cvss_v2_score",
        "cvssV2Score",
        "cvss_v2",
        "cvssV2",
        "cvss_score",
        "cvssScore",
        "baseScore",
        "base_score",
        "score",
    ):
        value = vuln.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        try:
            score = float(value)
        except (TypeError, ValueError):
            continue
        if best is None or score > best:
            best = score
    return best


def cvss_vector(vuln):
    """Pull a CVSS vector string out of a WhiteHat vulnerability payload."""
    if not isinstance(vuln, dict):
        return ""
    for key in (
        "cvss_v3_vector",
        "cvssV3Vector",
        "cvss_v2_vector",
        "cvssV2Vector",
        "vector",
        "vectorString",
    ):
        value = vuln.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def collect_cves(vuln):
    """Pull CVE-* ids out of a WhiteHat vulnerability payload."""
    if not isinstance(vuln, dict):
        return []
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if not s.startswith("CVE-"):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    for key in ("cve", "cveId", "cve_id"):
        v = vuln.get(key)
        if isinstance(v, str) and v.strip():
            add(v)
    for key in ("cves", "aliases", "references"):
        v = vuln.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    for k in ("cve", "cveId", "cve_id", "name", "id", "value"):
                        val = entry.get(k)
                        if isinstance(val, str):
                            add(val)
                            break
    # The legacy WhiteHat vuln summary occasionally only carries the CVE
    # in the title (e.g. "CVE-2021-44228 (Log4Shell)").
    for key in ("name", "title", "summary", "vulnerability_name", "vulnerabilityName"):
        v = vuln.get(key)
        if isinstance(v, str):
            for token in v.replace(",", " ").split():
                add(token.strip("()[].,;"))
    return found


def collect_refs(vuln):
    """Walk a WhiteHat vulnerability for CWE / WASC / advisory / URL refs."""
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

    def add_cwe(raw):
        if isinstance(raw, bool):
            return
        if isinstance(raw, (int, float)):
            add(f"CWE-{int(raw)}")
        elif isinstance(raw, str) and raw.strip():
            s = raw.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")

    cwe_raw = vuln.get("cwe") or vuln.get("cweId") or vuln.get("cwe_id")
    if isinstance(cwe_raw, list):
        for it in cwe_raw:
            if isinstance(it, dict):
                cid = it.get("id") or it.get("value") or it.get("name")
                if cid is not None:
                    add_cwe(cid)
            else:
                add_cwe(it)
    else:
        add_cwe(cwe_raw)
    for key in ("cwes", "cweIds", "cwe_ids"):
        items = vuln.get(key)
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    cid = it.get("id") or it.get("value") or it.get("name")
                    if cid is not None:
                        add_cwe(cid)
                else:
                    add_cwe(it)

    # WhiteHat also surfaces WASC ids (Web Application Security
    # Consortium taxonomy) on the legacy ``wasc`` field.
    def add_wasc(raw):
        if isinstance(raw, bool):
            return
        if isinstance(raw, (int, float)):
            add(f"WASC-{int(raw)}")
        elif isinstance(raw, str) and raw.strip():
            s = raw.strip()
            add(s if s.upper().startswith("WASC-") else f"WASC-{s}")

    wasc_raw = vuln.get("wasc") or vuln.get("wascId") or vuln.get("wasc_id")
    if isinstance(wasc_raw, list):
        for it in wasc_raw:
            add_wasc(it)
    else:
        add_wasc(wasc_raw)

    # External references — string + dict shapes.
    for key in ("references", "external_references", "links"):
        entry = vuln.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("url") or it.get("href") or it.get("name") or it.get("id")
                    if href:
                        add(href)
                elif it:
                    add(str(it))
    for key in ("reference", "url", "advisory_url", "advisoryUrl"):
        value = vuln.get(key)
        if isinstance(value, str) and value.strip():
            add(value.strip())

    return refs


def collect_attack_vectors(vuln):
    """Return a list of attack-vector URL strings for a WhiteHat vuln.

    WhiteHat reports the URL + parameter combinations that exercised a
    vulnerability under the ``attack_vectors`` field — each entry has
    ``request.url`` / ``request.param`` (varying casing per build).
    """
    out = []
    if not isinstance(vuln, dict):
        return out
    entries = vuln.get("attack_vectors") or vuln.get("attackVectors")
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if isinstance(entry, str) and entry.strip():
            out.append(entry.strip())
            continue
        if not isinstance(entry, dict):
            continue
        url = ""
        param = ""
        req = entry.get("request") or entry.get("Request")
        if isinstance(req, dict):
            url = req.get("url") or req.get("URL") or req.get("uri") or ""
            param = req.get("param") or req.get("parameter") or req.get("paramName") or ""
        if not url:
            url = entry.get("url") or entry.get("URL") or entry.get("uri") or ""
        if not param:
            param = entry.get("param") or entry.get("parameter") or ""
        if isinstance(url, str) and url.strip():
            label = url.strip()
            if isinstance(param, str) and param.strip():
                label = f"{label} (param: {param.strip()})"
            out.append(label)
    return out


def vuln_label(vuln):
    """Return the human-readable label for the title of a WhiteHat vuln."""
    if not isinstance(vuln, dict):
        return ""
    for key in (
        "class",
        "className",
        "class_name",
        "name",
        "title",
        "vulnerability_class",
        "vulnerabilityClass",
    ):
        v = vuln.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            inner = v.get("name") or v.get("label") or v.get("value")
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
    return ""


def site_label(site):
    """Return a hostname-friendly label for the WhiteHat site host entry."""
    if not isinstance(site, dict):
        return ""
    for key in ("label", "site_label", "siteLabel", "name", "site_name", "siteName"):
        v = site.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("url", "site_url", "siteUrl", "target", "target_url"):
        v = site.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def build_vulnerability(vuln, site_id=None, site_label_value=None):
    """Build a Faraday vulnerability dict from one WhiteHat vuln entry."""
    if not isinstance(vuln, dict):
        return None

    score = cvss_score(vuln)
    severity_value = vuln.get("severity")
    if severity_value is None:
        severity_value = vuln.get("risk") or vuln.get("severity_label") or vuln.get("severityLabel")
    severity = severity_from_whitehat(severity_value, score)
    status = status_from_whitehat(vuln)

    label = vuln_label(vuln)
    location = ""
    for key in ("location", "url", "target", "target_url", "endpoint"):
        v = vuln.get(key)
        if isinstance(v, str) and v.strip():
            location = v.strip()
            break
    raw_name = label or "WhiteHat finding"
    if location:
        raw_name = f"{raw_name} in {location}"
    name = f"[DAST] {raw_name}"

    desc_parts = []
    description = vuln.get("description") or vuln.get("summary")
    if description:
        if isinstance(description, dict):
            desc_parts.append(json.dumps(description, separators=(",", ":")))
        else:
            desc_parts.append(str(description))
    if label:
        desc_parts.append(f"class: {label}")
    raw_severity = vuln.get("severity")
    if raw_severity is not None:
        desc_parts.append(f"severity: {raw_severity}")
    raw_risk = vuln.get("risk")
    if raw_risk is not None and raw_risk != raw_severity:
        desc_parts.append(f"risk: {raw_risk}")
    if score is not None:
        desc_parts.append(f"cvssScore: {score}")
    vector = cvss_vector(vuln)
    if vector:
        desc_parts.append(f"vector: {vector}")
    raw_status = vuln.get("status") or vuln.get("state")
    if raw_status:
        desc_parts.append(f"status: {raw_status}")
    mitigation_status = vuln.get("mitigation_status") or vuln.get("mitigationStatus")
    if mitigation_status:
        desc_parts.append(f"mitigationStatus: {mitigation_status}")
    for key, label_key in (
        ("found", "found"),
        ("first_found", "firstFound"),
        ("firstFound", "firstFound"),
        ("first_seen", "firstSeen"),
        ("opened", "opened"),
        ("closed", "closed"),
        ("last_tested", "lastTested"),
        ("lastTested", "lastTested"),
    ):
        v = vuln.get(key)
        if isinstance(v, str) and v.strip():
            desc_parts.append(f"{label_key}: {v.strip()}")
    notes = vuln.get("notes")
    if isinstance(notes, str) and notes.strip():
        desc_parts.append(f"notes: {notes.strip()}")
    elif isinstance(notes, list) and notes:
        rendered = []
        for entry in notes[:10]:
            if isinstance(entry, str) and entry.strip():
                rendered.append(entry.strip())
            elif isinstance(entry, dict):
                inner = entry.get("text") or entry.get("note") or entry.get("value")
                if isinstance(inner, str) and inner.strip():
                    rendered.append(inner.strip())
        if rendered:
            desc_parts.append("notes: " + " | ".join(rendered))
    if site_id:
        desc_parts.append(f"site: {site_id}")
    if site_label_value:
        desc_parts.append(f"siteLabel: {site_label_value}")

    attack_vectors = collect_attack_vectors(vuln)
    if attack_vectors:
        desc_parts.append("attackVectors: " + " | ".join(attack_vectors[:10]))

    cves = collect_cves(vuln)
    refs = collect_refs(vuln)

    resolution_parts = []
    for key in (
        "solution",
        "remediation",
        "fix",
        "fix_recommendation",
        "fixRecommendation",
        "recommendation",
    ):
        v = vuln.get(key)
        if isinstance(v, str) and v.strip():
            resolution_parts.append(v.strip())
        elif isinstance(v, dict):
            inner = v.get("text") or v.get("value")
            if isinstance(inner, str) and inner.strip():
                resolution_parts.append(inner.strip())
    resolution = " | ".join(dict.fromkeys(resolution_parts))

    external_id = (
        vuln.get("id")
        or vuln.get("vuln_id")
        or vuln.get("vulnId")
        or vuln.get("external_id")
        or (cves[0] if cves else "")
    )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"WhiteHat finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id),
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["whitehat_sentinel", "sentinel", "dast"],
    }


def build_host(site_id, site, vulns):
    """Build the Faraday host wrapper for the imported issues."""
    label = site_label(site) if isinstance(site, dict) else ""
    if label and site_id:
        hostname = f"{label}@{site_id}"
    elif label:
        hostname = label
    elif site_id:
        hostname = str(site_id)
    else:
        hostname = ""

    desc_parts = []
    if site_id:
        desc_parts.append(f"siteId={site_id}")
    if isinstance(site, dict) and site:
        for key, dlabel in (
            ("label", "label"),
            ("site_label", "label"),
            ("siteLabel", "label"),
            ("url", "url"),
            ("site_url", "url"),
            ("siteUrl", "url"),
            ("target", "target"),
            ("target_url", "target"),
            ("status", "status"),
            ("site_status", "status"),
            ("found", "foundCount"),
            ("open_vulns", "openVulns"),
            ("openVulns", "openVulns"),
            ("closed_vulns", "closedVulns"),
            ("closedVulns", "closedVulns"),
        ):
            v = site.get(key)
            if v is None or v == "":
                continue
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                rendered = str(v).strip() if isinstance(v, str) else str(v)
                if rendered:
                    desc_parts.append(f"{dlabel}={rendered}")

    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(dict.fromkeys(desc_parts)),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("WH_HOST", required=True)
    api_key = env("WH_API_KEY", required=True)
    site_id = env("EXECUTOR_CONFIG_WH_SITE_ID", required=True)
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_WH_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    if not base_url:
        log("WH_HOST is required")
        sys.exit(1)

    auth_params, auth_headers = build_auth(api_key)
    headers = {"Accept": "application/json"}
    headers.update(auth_headers)

    site = get_site(base_url, site_id, auth_params, headers)
    label = site_label(site)
    vulns_raw = get_vulnerabilities(base_url, site_id, auth_params, headers)

    log(
        f"Processing {len(vulns_raw)} WhiteHat vuln(s) "
        f"(site={site_id}, label={label or '-'}, min_severity={min_severity})"
    )

    vulns = []
    for entry in vulns_raw:
        if not isinstance(entry, dict):
            continue
        built = build_vulnerability(entry, site_id=site_id, site_label_value=label)
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        vulns.append(built)

    hosts = [build_host(site_id, site, vulns)] if vulns or site else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "whitehat_sentinel",
            "command": "whitehat_sentinel",
            "params": f"site={site_id},min_severity={min_severity}",
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
