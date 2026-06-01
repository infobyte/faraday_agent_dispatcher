#!/usr/bin/env python
"""Pradeo Mobile Security REST API importer.

Pulls Mobile Application Security Testing (MAST) findings from a Pradeo
Security tenant and emits Faraday bulk-create JSON to stdout. Each Pradeo
mobile application becomes one Faraday host (``ip`` = synthetic ``0.0.0.0``
because Pradeo findings live in mobile binaries, not on IPs); per-application
threats are attached as Faraday vulnerabilities — one per Pradeo threat id
with engine prefix ``[MAST]``.

Endpoints used:
  GET /api/v1/applications                -> list applications (paginated
      via ``page`` / ``per_page``; supports a ``bundle_id`` filter).
  GET /api/v1/applications/{id}           -> single application detail.
  GET /api/v1/threats?application_id=<id> -> per-application threats /
      findings (paginated).

Auth: ``Authorization: Bearer <PRADEO_TOKEN>`` on every API call. Pradeo's
Security Center exposes a long-lived API token under Settings -> API; the
token carries the tenant scope so no additional tenant identifier is needed.

PRADEO_HOST is the Pradeo Security Center base URL (e.g.
``https://api.pradeo.net`` or the on-prem manager URL).
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

# Pradeo emits severity as a string enum. Tolerant of casing and a few
# synonyms surfaced by other MAST vendors (Important / Moderate / Minor).
PRADEO_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "negligible": "info",
}

# Pradeo lifecycle / triage statuses. Resolved / Fixed close; False Positive
# / Accepted Risk / Ignored / Mitigated by analyst move the threat to Faraday
# risk-accepted; everything else stays open.
PRADEO_STATUS_TO_FARADAY = {
    "open": "open",
    "new": "open",
    "active": "open",
    "detected": "open",
    "pending": "open",
    "confirmed": "open",
    "reopened": "open",
    "untracked": "open",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "false positive": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "accepted": "risk-accepted",
    "accepted risk": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "acceptedrisk": "risk-accepted",
    "risk accepted": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "whitelisted": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - PradeoMobile: {msg}", file=sys.stderr, flush=True)


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


def normalize_base_url(value):
    """Translate PRADEO_HOST into a Pradeo Security Center base URL."""
    text = str(value).strip().rstrip("/")
    if not text:
        return text
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    return text.rstrip("/")


def severity_from_pradeo(value):
    """Map Pradeo's severity field to a Faraday severity bucket.

    Accepts the string enum (Critical / High / Medium / Low / Info), the 0-4
    numeric ladder Pradeo surfaces on some endpoints (0=info, 1=low,
    2=medium, 3=high, 4=critical), and a CVSS-style 0-10 float (bucketed
    against the standard CVSS v3 ranges) when only a numeric score is given.
    """
    if value is None:
        return "info"
    if isinstance(value, bool):
        return "info"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        score = float(value)
        # 0-4 ladder takes precedence: Pradeo exposes severity as 0/1/2/3/4
        # on some threat shapes; map directly when the value fits.
        if score == 0:
            return "info"
        if score == 1:
            return "low"
        if score == 2:
            return "medium"
        if score == 3:
            return "high"
        if score == 4:
            return "critical"
        # Fall through to CVSS v3 bucketing for arbitrary floats.
        if score <= 0:
            return "info"
        if score < 4:
            return "low"
        if score < 7:
            return "medium"
        if score < 9:
            return "high"
        if score <= 10:
            return "critical"
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    if text in PRADEO_STRING_SEVERITY:
        return PRADEO_STRING_SEVERITY[text]
    # Numeric-as-string: "2" → medium, "8.5" → high (CVSS fallback).
    try:
        return severity_from_pradeo(float(text))
    except (TypeError, ValueError):
        return "info"


def status_from_pradeo(threat):
    """Map Pradeo's lifecycle status to a Faraday status.

    Analyst-triage signals (risk-accepted / closed) win over lifecycle
    status — a New threat marked False Positive should still land as
    Faraday risk-accepted. Boolean flags (``is_false_positive`` /
    ``ignored`` / ``accepted``) feed the same priority pass when the
    string status is missing.
    """
    if not isinstance(threat, dict):
        return "open"
    candidates = []
    for key in ("status", "state", "resolution", "triage_status", "triageStatus"):
        raw = threat.get(key)
        if not raw:
            continue
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status")
        if not raw:
            continue
        candidates.append(str(raw).strip().lower())

    # Pass 1: explicit triage flags (booleans) override lifecycle status.
    for key in ("false_positive", "isFalsePositive", "is_false_positive", "falsePositive"):
        if threat.get(key):
            return "risk-accepted"
    for key in ("accepted_risk", "isAcceptedRisk", "acceptedRisk", "ignored", "isIgnored", "suppressed"):
        if threat.get(key):
            return "risk-accepted"

    # Pass 2: prefer risk-accepted over closed over open so analyst
    # decisions win over lifecycle close.
    for text in candidates:
        compact = text.replace(" ", "").replace("_", "").replace("-", "")
        if compact in {"falsepositive", "acceptedrisk", "riskaccepted", "ignored", "suppressed", "whitelisted"}:
            return "risk-accepted"
        if text in PRADEO_STATUS_TO_FARADAY and PRADEO_STATUS_TO_FARADAY[text] == "risk-accepted":
            return "risk-accepted"

    # Pass 3: closed wins over open.
    for text in candidates:
        if text in PRADEO_STATUS_TO_FARADAY and PRADEO_STATUS_TO_FARADAY[text] == "closed":
            return "closed"

    # Pass 4: lifecycle open.
    for text in candidates:
        if text in PRADEO_STATUS_TO_FARADAY:
            return PRADEO_STATUS_TO_FARADAY[text]

    # Boolean fallback: explicit ``fixed`` / ``resolved`` flags.
    for key in ("fixed", "is_fixed", "isFixed", "resolved", "isResolved"):
        if threat.get(key):
            return "closed"
    return "open"


def request_json(method, base_url, path, headers, params=None, payload=None):
    url = f"{base_url}{path}"
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
        log(f"{method} {path} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). Check PRADEO_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the scope of PRADEO_TOKEN.")
        return None
    if resp.status_code == 404:
        log(f"{method} {path} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"{method} {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        log(f"{method} {path} returned non-JSON body")
        return None


def extract_list(body, *keys):
    """Pluck a list out of a Pradeo REST response."""
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys:
            value = body.get(key)
            if isinstance(value, list):
                return value
        for candidate in ("applications", "threats", "findings", "items", "data", "results", "content"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def paginate(base_url, path, headers, params=None, list_keys=()):
    """Walk Pradeo paginated endpoints via ``page`` / ``per_page``."""
    results = []
    base_params = dict(params or {})
    page = 1
    for _ in range(MAX_PAGES):
        query = dict(base_params)
        query.update({"page": page, "per_page": PAGE_SIZE})
        body = request_json("GET", base_url, path, headers, params=query)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("total") or body.get("totalCount") or body.get("total_count") or body.get("count")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def get_applications(base_url, headers, bundle_id):
    """List Pradeo applications, optionally narrowed to a bundle id.

    Pradeo's ``/api/v1/applications`` endpoint accepts a ``bundle_id`` /
    ``package_name`` filter to narrow the result set to a single app. When
    that filter returns nothing we fall back to a client-side filter so
    older deployments that don't honour the query param still work.
    """
    if bundle_id:
        filtered = paginate(
            base_url,
            "/api/v1/applications",
            headers,
            params={"bundle_id": bundle_id, "package_name": bundle_id},
            list_keys=("applications",),
        )
        if filtered:
            return filtered
        # Client-side fallback: pull everything and match against the
        # bundle id / package name on the application body.
        every = paginate(base_url, "/api/v1/applications", headers, list_keys=("applications",))
        target = str(bundle_id).strip().lower()
        return [
            app
            for app in every
            if isinstance(app, dict)
            and target
            in {
                str(app.get("bundle_id") or "").strip().lower(),
                str(app.get("bundleId") or "").strip().lower(),
                str(app.get("package_name") or "").strip().lower(),
                str(app.get("packageName") or "").strip().lower(),
                str(app.get("identifier") or "").strip().lower(),
            }
        ]
    return paginate(base_url, "/api/v1/applications", headers, list_keys=("applications",))


def get_threats(base_url, headers, app_id):
    """Pull every threat (finding) for a single Pradeo application."""
    return paginate(
        base_url,
        "/api/v1/threats",
        headers,
        params={"application_id": app_id, "app_id": app_id},
        list_keys=("threats", "findings"),
    )


def collect_refs(threat):
    refs = []
    seen = set()

    def add(name):
        if not name:
            return
        text = str(name).strip()
        if not text or text in seen:
            return
        seen.add(text)
        refs.append({"name": text, "type": "other"})

    # CWE: surfaced as bare int, "CWE-79" string, list of either or list of
    # dicts with ``id`` / ``name`` / ``value`` keys.
    cwe_values = []
    single_cwe = threat.get("cwe") or threat.get("cweId") or threat.get("cwe_id")
    if single_cwe:
        cwe_values.append(single_cwe)
    for key in ("cwes", "cweIds", "cwe_ids"):
        value = threat.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            cwe_values.extend(value)
        else:
            cwe_values.append(value)
    for entry in cwe_values:
        if isinstance(entry, dict):
            entry = entry.get("id") or entry.get("name") or entry.get("value")
        if entry in (None, ""):
            continue
        text = str(entry).strip()
        text = text[4:] if text.lower().startswith("cwe-") else text
        if text:
            add(f"CWE-{text}")

    # OWASP Mobile Top 10 — Pradeo tags threats with M1..M10 categories.
    for key in ("owasp", "owasp_mobile", "owaspMobile", "owaspCategory"):
        value = threat.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if entry:
                    add(f"OWASP: {entry}")
        else:
            add(f"OWASP: {value}")

    # MASVS / MASTG — Mobile Application Security Verification Standard refs.
    for key in ("masvs", "masvs_id", "masvsId"):
        value = threat.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if entry:
                    add(f"MASVS-{entry}")
        else:
            add(f"MASVS-{value}")

    # Pradeo rule / threat identifier — always present on a threat.
    rule_name = (
        threat.get("rule_name")
        or threat.get("ruleName")
        or threat.get("rule")
        or threat.get("threat_id")
        or threat.get("threatId")
    )
    if rule_name:
        add(f"PradeoRule-{rule_name}")

    # Category surfaces Pradeo's threat pack ("Behavior", "Vulnerability",
    # "Network", "Privacy", etc.).
    category = threat.get("category") or threat.get("threat_category") or threat.get("threatCategory")
    if category:
        add(f"PradeoCategory-{category}")

    # References / links may surface CVEs and external advisory URLs.
    for entry in threat.get("references") or threat.get("links") or []:
        if isinstance(entry, str):
            add(entry)
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("name") or entry.get("value")
            add(value)

    return refs


def collect_cves(threat):
    cves = []
    seen = set()
    candidates = []
    for key in ("cve", "cveId", "cveName", "cve_id"):
        value = threat.get(key)
        if value:
            if isinstance(value, (list, tuple)):
                candidates.extend(value)
            else:
                candidates.append(value)
    for key in ("cves", "CVEs"):
        value = threat.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if isinstance(entry, str):
                    candidates.append(entry)
                elif isinstance(entry, dict):
                    inner = entry.get("name") or entry.get("id") or entry.get("value")
                    if inner:
                        candidates.append(inner)
    for value in candidates:
        text = str(value).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)
    return cves


def cvss_score(threat):
    """Pull a CVSS v3 base score out of a Pradeo threat.

    Accepts a nested ``cvss``/``cvss3`` dict shape (`{baseScore: 8.8, ...}`)
    or a bare numeric ``cvss_score`` / ``score``.
    """
    for key in ("cvss3", "cvssV3", "cvss"):
        value = threat.get(key)
        if isinstance(value, dict):
            for inner_key in ("baseScore", "base_score", "score"):
                inner = value.get(inner_key)
                if isinstance(inner, (int, float)) and not isinstance(inner, bool):
                    return float(inner)
                if isinstance(inner, str):
                    try:
                        return float(inner)
                    except ValueError:
                        continue
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    for key in ("cvss_score", "cvssScore", "score"):
        value = threat.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return None


def build_vulnerability(threat):
    """Build the Faraday vulnerability dict for a Pradeo threat."""
    if not isinstance(threat, dict):
        return None

    # Severity: prefer the explicit severity field, fall back to CVSS.
    raw_severity = (
        threat.get("severity")
        or threat.get("severityLabel")
        or threat.get("severity_label")
        or threat.get("risk_level")
        or threat.get("riskLevel")
        or threat.get("level")
    )
    severity = severity_from_pradeo(raw_severity)
    score = cvss_score(threat)
    if (severity == "info") and score is not None:
        severity = severity_from_pradeo(score)

    status = status_from_pradeo(threat)

    rule_name = (
        threat.get("rule_name")
        or threat.get("ruleName")
        or threat.get("rule")
        or threat.get("threat_id")
        or threat.get("threatId")
        or ""
    )
    title = (
        threat.get("title")
        or threat.get("name")
        or threat.get("display_name")
        or threat.get("displayName")
        or threat.get("description_short")
        or rule_name
        or "Pradeo Mobile finding"
    )
    name = f"[MAST] {title}"

    desc_parts = []
    description = (
        threat.get("description")
        or threat.get("summary")
        or threat.get("details")
        or threat.get("long_description")
        or threat.get("longDescription")
    )
    if isinstance(description, dict):
        description = description.get("text") or description.get("html") or description.get("value")
    if description:
        desc_parts.append(str(description))

    category = threat.get("category") or threat.get("threat_category") or threat.get("threatCategory")
    if category:
        desc_parts.append(f"category: {category}")
    threat_class = threat.get("threat_class") or threat.get("threatClass") or threat.get("type")
    if threat_class:
        desc_parts.append(f"class: {threat_class}")
    platform = threat.get("platform") or threat.get("os") or threat.get("os_name")
    if platform:
        desc_parts.append(f"platform: {platform}")
    if rule_name:
        desc_parts.append(f"rule: {rule_name}")

    first_seen = (
        threat.get("first_detected")
        or threat.get("firstDetected")
        or threat.get("first_seen")
        or threat.get("firstSeen")
        or threat.get("created_at")
    )
    if first_seen:
        desc_parts.append(f"first_detected: {first_seen}")
    last_seen = (
        threat.get("last_detected")
        or threat.get("lastDetected")
        or threat.get("last_seen")
        or threat.get("lastSeen")
        or threat.get("updated_at")
    )
    if last_seen:
        desc_parts.append(f"last_detected: {last_seen}")

    status_raw = threat.get("status") or threat.get("state")
    if status_raw:
        desc_parts.append(f"status: {status_raw}")

    threat_id = (
        threat.get("id")
        or threat.get("threat_id")
        or threat.get("threatId")
        or threat.get("uuid")
        or threat.get("identifier")
        or ""
    )
    if threat_id:
        desc_parts.append(f"id: {threat_id}")

    if score is not None:
        desc_parts.append(f"cvss: {score}")

    resolution = (
        threat.get("remediation")
        or threat.get("recommendation")
        or threat.get("recommendations")
        or threat.get("mitigation")
        or threat.get("howToFix")
        or threat.get("how_to_fix")
        or ""
    )
    if isinstance(resolution, dict):
        resolution = resolution.get("text") or resolution.get("html") or resolution.get("value") or ""

    cvss3 = {"base_score": score} if score is not None else {}

    external_id = str(threat_id) if threat_id else ""

    return {
        "name": str(name).strip()[:200] or f"Pradeo Mobile finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": collect_refs(threat),
        "cve": collect_cves(threat),
        "cvss3": cvss3,
        "tags": ["pradeo_mobile", "mast"],
    }


def build_host(application, vulns):
    """One Faraday host per Pradeo application.

    Pradeo findings live in mobile binaries, not on IPs — the host is a
    synthetic ``0.0.0.0`` carrying the bundle id (or app name) as the
    hostname so the data lands somewhere recognisable in the workspace.
    """
    name = (
        application.get("name")
        or application.get("application_name")
        or application.get("applicationName")
        or application.get("display_name")
        or application.get("displayName")
        or application.get("title")
        or "unknown"
    )
    bundle_id = (
        application.get("bundle_id")
        or application.get("bundleId")
        or application.get("package_name")
        or application.get("packageName")
        or application.get("identifier")
    )
    hostname = str(bundle_id) if bundle_id else str(name)
    desc_parts = [f"Pradeo application name={name}"]
    if bundle_id and str(name) != str(bundle_id):
        desc_parts.append(f"bundle_id={bundle_id}")
    app_id = application.get("id") or application.get("application_id") or application.get("applicationId")
    if app_id:
        desc_parts.append(f"id={app_id}")
    platform = application.get("platform") or application.get("os") or application.get("os_name")
    if platform:
        desc_parts.append(f"platform={platform}")
    version = application.get("version") or application.get("version_name") or application.get("versionName")
    if version:
        desc_parts.append(f"version={version}")
    risk_score = application.get("risk_score") or application.get("riskScore")
    if risk_score is not None:
        desc_parts.append(f"risk_score={risk_score}")
    return {
        "ip": "0.0.0.0",
        "os": str(platform) if platform else "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"PRADEO_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def app_id_of(application):
    if not isinstance(application, dict):
        return None
    return (
        application.get("id")
        or application.get("application_id")
        or application.get("applicationId")
        or application.get("app_id")
        or application.get("appId")
    )


def main():
    started = time.time()
    host = env("PRADEO_HOST", required=True)
    token = env("PRADEO_TOKEN", required=True)
    bundle_id = env("EXECUTOR_CONFIG_PRADEO_APP_BUNDLE_ID")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_PRADEO_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    applications = get_applications(base_url, headers, bundle_id)
    log(f"Found {len(applications)} application(s) " f"(bundle_id={bundle_id or 'all'}, min_severity={min_severity})")

    hosts = []
    for application in applications:
        if not isinstance(application, dict):
            continue
        aid = app_id_of(application)
        if not aid:
            continue
        raw_threats = get_threats(base_url, headers, aid)
        vulns = []
        for raw in raw_threats:
            built = build_vulnerability(raw)
            if not built:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
        if not vulns:
            continue
        hosts.append(build_host(application, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "pradeo_mobile",
            "command": "pradeo_mobile",
            "params": f"bundle_id={bundle_id or 'all'} min_severity={min_severity}",
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
