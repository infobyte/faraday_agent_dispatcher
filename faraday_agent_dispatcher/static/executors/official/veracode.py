#!/usr/bin/env python
"""Veracode Application Security REST API importer.

Pulls SAST / DAST / SCA / Manual findings from a Veracode tenant and emits
Faraday bulk-create JSON to stdout. Each Veracode application becomes one
Faraday host (``ip`` = synthetic ``0.0.0.0`` because Veracode findings live
in applications, not on IPs); per-application findings are attached as
Faraday vulnerabilities — one per Veracode issue id with engine prefix
(``[SAST]`` / ``[DAST]`` / ``[SCA]`` / ``[MANUAL]``).

Endpoints used:
  GET /appsec/v2/applications                   -> list applications
      (paginated via ``page`` / ``size``).
  GET /appsec/v2/applications/{app_guid}        -> single application
      detail (used when VERACODE_APP_GUID is set).
  GET /appsec/v2/applications/{app_guid}/findings -> per-application
      findings (paginated). Optionally scoped to a sandbox via the
      ``context`` query parameter (sandbox guid).

Auth: HMAC-SHA-256 ("VERACODE-HMAC-SHA-256"). VERACODE_API_KEY_ID
identifies the consumer and VERACODE_API_KEY_SECRET signs each request.
The signing chain is the canonical Veracode derived-key scheme:

    k_nonce   = HMAC-SHA256(hex_to_bytes(secret),    hex_to_bytes(nonce))
    k_date    = HMAC-SHA256(k_nonce,                 timestamp_ms_ascii)
    k_sig     = HMAC-SHA256(k_date,                  b"vcode_request_version_1")
    signature = HMAC-SHA256(k_sig,                   "id=<id>&host=<h>&url=<p>&method=<M>")

and sent in:

    Authorization: VERACODE-HMAC-SHA-256
        id=<api_key_id>,ts=<ts>,nonce=<hex_nonce>,sig=<hex_signature>

VERACODE_HOST defaults to ``https://api.veracode.com`` (Veracode's
commercial US region); set it explicitly to point at the EU region
(``https://api.veracode.eu``) or the FedRAMP tenant.
"""

import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200
DEFAULT_HOST = "https://api.veracode.com"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Veracode exposes severity as a 0-5 numeric scale.
#   5 -> Very High  -> critical
#   4 -> High       -> high
#   3 -> Medium     -> medium
#   2 -> Low        -> low
#   1 -> Very Low   -> info
#   0 -> Informational -> info
VERACODE_NUMERIC_SEVERITY = {
    0: "info",
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

VERACODE_STRING_SEVERITY = {
    "very high": "critical",
    "very_high": "critical",
    "veryhigh": "critical",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "very low": "info",
    "very_low": "info",
    "verylow": "info",
    "info": "info",
    "information": "info",
    "informational": "info",
    "none": "info",
}

# Veracode scan_type values -> engine prefix shown on the Faraday vuln name.
VERACODE_ENGINE_PREFIX = {
    "STATIC": "SAST",
    "DYNAMIC": "DAST",
    "SCA": "SCA",
    "MANUAL": "MANUAL",
    "DYNAMICDS": "DAST",
}


def log(msg):
    print(f"{datetime.utcnow()} - Veracode: {msg}", file=sys.stderr, flush=True)


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


def severity_from_veracode(value):
    """Normalise a Veracode severity into a Faraday bucket.

    ``value`` may be a numeric 0-5 score, a numeric-as-string, or a string
    severity name. Unknown / out-of-range values fall through to ``info``.
    """
    if value is None or isinstance(value, bool):
        return "info"
    if isinstance(value, (int, float)):
        try:
            int_value = int(value)
        except (TypeError, ValueError):
            return "info"
        if int_value in VERACODE_NUMERIC_SEVERITY:
            return VERACODE_NUMERIC_SEVERITY[int_value]
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    if text in VERACODE_STRING_SEVERITY:
        return VERACODE_STRING_SEVERITY[text]
    try:
        int_value = int(float(text))
    except ValueError:
        int_value = None
    if int_value in VERACODE_NUMERIC_SEVERITY:
        return VERACODE_NUMERIC_SEVERITY[int_value]
    return "info"


def status_from_veracode(finding):
    """Derive Faraday status from a Veracode finding's ``finding_status``.

    Veracode tracks finding lifecycle in ``finding_status``:
      * ``status``           -> "OPEN" / "CLOSED"
      * ``resolution``       -> "UNRESOLVED" / "FALSE_POSITIVE" /
                                "BENIGN_FINDING" / "OS_ENVIRONMENT" /
                                "NETWORK_ENVIRONMENT" / "MITIGATED_BY_DESIGN" /
                                "MITIGATED_BY_OTHER_INVESTIGATION" /
                                "RISK_ACCEPTED" / "POTENTIAL_FALSE_POSITIVE" /
                                "REPORTED_TO_LIBRARY_MAINTAINER"
      * ``resolution_status``-> "NONE" / "PROPOSED" / "ACCEPTED" / "REJECTED"

    Rules:
      * resolution_status=REJECTED -> ignore the resolution, fall through.
      * status=CLOSED with no risk-accepted resolution -> closed.
      * resolution in (FALSE_POSITIVE / BENIGN_FINDING / RISK_ACCEPTED /
        MITIGATED_*) and resolution_status not REJECTED -> risk-accepted.
      * everything else -> open.
    """
    finding_status = finding.get("finding_status") or {}
    if not isinstance(finding_status, dict):
        finding_status = {}
    raw_status = str(finding_status.get("status") or "").strip().upper()
    resolution = str(finding_status.get("resolution") or "").strip().upper()
    resolution_status = str(finding_status.get("resolution_status") or "").strip().upper()

    risk_accepted_resolutions = {
        "FALSE_POSITIVE",
        "POTENTIAL_FALSE_POSITIVE",
        "BENIGN_FINDING",
        "RISK_ACCEPTED",
        "MITIGATED_BY_DESIGN",
        "MITIGATED_BY_OTHER_INVESTIGATION",
        "OS_ENVIRONMENT",
        "NETWORK_ENVIRONMENT",
    }
    if resolution in risk_accepted_resolutions and resolution_status != "REJECTED":
        return "risk-accepted"
    if raw_status == "CLOSED":
        return "closed"
    return "open"


def sign_request(method, host, path, api_id, api_secret):
    """Build the Veracode HMAC-SHA-256 Authorization header for one request.

    The signing scheme is Veracode's canonical derived-key chain:
        k_nonce  = HMAC-SHA256(hex_to_bytes(api_secret), hex_to_bytes(nonce))
        k_date   = HMAC-SHA256(k_nonce, str(timestamp_ms).encode("ascii"))
        k_sig    = HMAC-SHA256(k_date, b"vcode_request_version_1")
        signature= HMAC-SHA256(k_sig, ("id=<id>&host=<h>&url=<p>&method=<M>").encode("ascii"))
    """
    timestamp_ms = str(int(time.time() * 1000))
    nonce = secrets.token_hex(16)
    data = f"id={api_id}&host={host}&url={path}&method={method.upper()}"

    try:
        secret_bytes = bytes.fromhex(api_secret)
    except ValueError:
        log("VERACODE_API_KEY_SECRET must be a hex-encoded string")
        sys.exit(1)

    nonce_bytes = bytes.fromhex(nonce)

    k_nonce = hmac.new(secret_bytes, nonce_bytes, hashlib.sha256).digest()
    k_date = hmac.new(k_nonce, timestamp_ms.encode("ascii"), hashlib.sha256).digest()
    k_sig = hmac.new(k_date, b"vcode_request_version_1", hashlib.sha256).digest()
    signature = hmac.new(k_sig, data.encode("ascii"), hashlib.sha256).hexdigest()

    auth_header = f"VERACODE-HMAC-SHA-256 id={api_id},ts={timestamp_ms},nonce={nonce.upper()},sig={signature}"
    return {"Authorization": auth_header, "Accept": "application/json"}


def request_path_with_query(path, params):
    """Build the canonical request path (path + querystring) used by signing.

    Veracode's HMAC string-to-sign uses the full ``path?querystring`` of the
    request — querystring included, sorted in the same order as sent on the
    wire. ``requests`` will URL-encode params on send; we mirror that here.
    """
    if not params:
        return path
    return f"{path}?{urlencode(params, doseq=True)}"


def api_get(base_url, path, api_id, api_secret, params=None):
    """Issue an authenticated GET against the Veracode API.

    Returns the parsed JSON body on success, ``None`` on any error.
    """
    host = urlsplit(base_url).netloc
    full_path = request_path_with_query(path, params)
    headers = sign_request("GET", host, full_path, api_id, api_secret)
    url = f"{base_url}{path}"
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"GET {path} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). Check VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check API role / team membership.")
        return None
    if resp.status_code == 404:
        log(f"GET {path} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def extract_list(body, *keys):
    """Pluck a list out of a Veracode JSON response.

    Veracode wraps list responses in HAL+JSON:
        {"_embedded": {"<resource>": [...]}, "page": {...}}
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        embedded = body.get("_embedded")
        if isinstance(embedded, dict):
            for key in keys:
                value = embedded.get(key)
                if isinstance(value, list):
                    return value
            for value in embedded.values():
                if isinstance(value, list):
                    return value
        for key in keys:
            value = body.get(key)
            if isinstance(value, list):
                return value
        for candidate in ("items", "data", "results"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, api_id, api_secret, base_params, list_keys):
    """Paginate a Veracode list endpoint via ``page`` + ``size``."""
    results = []
    page = 0
    for _ in range(MAX_PAGES):
        params = dict(base_params or {})
        params["page"] = page
        params["size"] = PAGE_SIZE
        body = api_get(base_url, path, api_id, api_secret, params=params)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        total_pages = None
        if isinstance(body, dict):
            page_meta = body.get("page") or {}
            if isinstance(page_meta, dict):
                total_pages = page_meta.get("total_pages") or page_meta.get("totalPages")
        if isinstance(total_pages, int) and page + 1 >= total_pages:
            break
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def get_applications(base_url, api_id, api_secret):
    return collect(base_url, "/appsec/v2/applications", api_id, api_secret, {}, ("applications",))


def get_application(base_url, api_id, api_secret, app_guid):
    body = api_get(base_url, f"/appsec/v2/applications/{app_guid}", api_id, api_secret)
    if isinstance(body, dict):
        return body
    return {}


def get_findings(base_url, api_id, api_secret, app_guid, sandbox_guid, min_severity):
    params = {}
    if sandbox_guid:
        params["context"] = sandbox_guid
    # Veracode's findings endpoint accepts a numeric ``severity_gte`` filter.
    # Forward the min-severity floor (mapped to Veracode's 0-5 scale) when set
    # above info; we still enforce client-side after normalisation.
    if min_severity and min_severity != "info":
        reverse_numeric = {
            "low": 2,
            "medium": 3,
            "high": 4,
            "critical": 5,
        }
        floor = reverse_numeric.get(min_severity)
        if floor is not None:
            params["severity_gte"] = floor
    return collect(
        base_url,
        f"/appsec/v2/applications/{app_guid}/findings",
        api_id,
        api_secret,
        params,
        ("findings",),
    )


def finding_details(finding):
    details = finding.get("finding_details") or {}
    if not isinstance(details, dict):
        return {}
    return details


def collect_refs(finding):
    refs = []
    seen = set()

    def add(name, ref_type="other"):
        if not name:
            return
        text = str(name).strip()
        if not text or text in seen:
            return
        seen.add(text)
        refs.append({"name": text, "type": ref_type or "other"})

    details = finding_details(finding)
    cwe = details.get("cwe")
    if isinstance(cwe, dict):
        cwe_id = cwe.get("id") or cwe.get("cwe_id")
        if cwe_id:
            add(f"CWE-{str(cwe_id).lstrip('CWE-').lstrip('cwe-')}")
        cwe_name = cwe.get("name")
        if cwe_name:
            add(str(cwe_name))
    elif cwe:
        add(f"CWE-{str(cwe).lstrip('CWE-').lstrip('cwe-')}")

    cwe_id = details.get("cwe_id")
    if cwe_id:
        add(f"CWE-{str(cwe_id).lstrip('CWE-').lstrip('cwe-')}")

    finding_category = details.get("finding_category")
    if isinstance(finding_category, dict):
        cat_name = finding_category.get("name")
        if cat_name:
            add(f"Category: {cat_name}")

    rule_id = details.get("rule_id") or details.get("rule")
    if rule_id:
        add(f"VeracodeRule-{rule_id}")

    plugin = details.get("plugin")
    if plugin:
        add(f"VeracodePlugin-{plugin}")

    cve_obj = details.get("cve")
    if isinstance(cve_obj, dict):
        cwe_from_cve = cve_obj.get("cwe_id")
        if cwe_from_cve:
            add(f"CWE-{str(cwe_from_cve).lstrip('CWE-').lstrip('cwe-')}")

    return refs


def collect_cves(finding):
    cves = []
    seen = set()
    details = finding_details(finding)
    candidates = []
    cve_obj = details.get("cve")
    if isinstance(cve_obj, dict):
        for key in ("name", "id", "cve_id", "cveName"):
            value = cve_obj.get(key)
            if value:
                candidates.append(value)
    elif isinstance(cve_obj, str):
        candidates.append(cve_obj)
    for key in ("cve", "cveId", "cve_id"):
        value = details.get(key)
        if value:
            candidates.append(value)
    cves_list = details.get("cves") or finding.get("cves") or []
    if isinstance(cves_list, list):
        for entry in cves_list:
            if isinstance(entry, str):
                candidates.append(entry)
            elif isinstance(entry, dict):
                value = entry.get("name") or entry.get("id") or entry.get("value")
                if value:
                    candidates.append(value)
    for value in candidates:
        text = str(value).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)
    return cves


def build_vulnerability(finding):
    details = finding_details(finding)
    scan_type = str(finding.get("scan_type") or details.get("scan_type") or "STATIC").upper()
    engine = VERACODE_ENGINE_PREFIX.get(scan_type, scan_type or "SAST")

    raw_name = None
    cat = details.get("finding_category")
    if isinstance(cat, dict):
        raw_name = cat.get("name")
    raw_name = raw_name or details.get("issue_type") or details.get("category_name")
    if not raw_name:
        cwe_obj = details.get("cwe")
        if isinstance(cwe_obj, dict):
            raw_name = cwe_obj.get("name")
    if not raw_name:
        cve_obj_local = details.get("cve")
        if isinstance(cve_obj_local, dict):
            raw_name = cve_obj_local.get("name")
    raw_name = raw_name or finding.get("description") or details.get("description") or f"Veracode {engine} finding"
    if isinstance(raw_name, str) and len(raw_name) > 180:
        raw_name = raw_name[:180].rstrip()
    name = f"[{engine}] {raw_name}"

    severity = severity_from_veracode(details.get("severity"))
    if severity == "info":
        severity = severity_from_veracode(finding.get("severity")) or severity
    status = status_from_veracode(finding)

    desc_parts = []
    description = finding.get("description") or details.get("description")
    if description:
        desc_parts.append(str(description))

    file_name = details.get("file_path") or details.get("file_name") or details.get("path")
    line_number = details.get("file_line_number") or details.get("line_number")
    if file_name and line_number:
        desc_parts.append(f"location: {file_name}:{line_number}")
    elif file_name:
        desc_parts.append(f"location: {file_name}")

    function_name = details.get("function_name") or details.get("procedure")
    if function_name:
        desc_parts.append(f"function: {function_name}")

    module = details.get("module") or details.get("relative_location")
    if module:
        desc_parts.append(f"module: {module}")

    url = details.get("url")
    if url:
        desc_parts.append(f"url: {url}")
    attack_vector = details.get("attack_vector")
    if attack_vector:
        desc_parts.append(f"attack_vector: {attack_vector}")
    plugin = details.get("plugin")
    if plugin:
        desc_parts.append(f"plugin: {plugin}")

    cve_obj = details.get("cve")
    if isinstance(cve_obj, dict):
        component = details.get("component_filename") or details.get("component_path")
        version = details.get("version")
        if component and version:
            desc_parts.append(f"package: {component}@{version}")
        elif component:
            desc_parts.append(f"package: {component}")
        fixed = details.get("first_fix_version") or details.get("fix_version") or details.get("fixed_version")
        if fixed:
            desc_parts.append(f"fixed_in: {fixed}")
        cvss3 = cve_obj.get("cvss3")
        if isinstance(cvss3, dict):
            score = cvss3.get("score") or cvss3.get("base_score")
            if score is not None:
                desc_parts.append(f"cvss3: {score}")

    issue_id = finding.get("issue_id") or finding.get("id")
    if issue_id is not None:
        desc_parts.append(f"issue_id: {issue_id}")

    finding_status = finding.get("finding_status") or {}
    if isinstance(finding_status, dict):
        resolution = finding_status.get("resolution")
        resolution_status = finding_status.get("resolution_status")
        if resolution:
            desc_parts.append(f"resolution: {resolution}")
        if resolution_status:
            desc_parts.append(f"resolution_status: {resolution_status}")
        first_found = finding_status.get("first_found_date")
        if first_found:
            desc_parts.append(f"first_found: {first_found}")

    cvss_score_obj = None
    if isinstance(cve_obj, dict):
        cvss3 = cve_obj.get("cvss3")
        if isinstance(cvss3, dict):
            cvss_score_obj = cvss3.get("score") or cvss3.get("base_score")

    return {
        "name": str(name).strip()[:200] or f"Veracode {engine} finding",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(issue_id or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": "",
        "data": "",
        "refs": collect_refs(finding),
        "cve": collect_cves(finding),
        "cvss3": {"base_score": str(cvss_score_obj)} if cvss_score_obj not in (None, "") else {},
        "tags": ["veracode", str(engine).lower()],
    }


def build_host(application, sandbox_guid, vulns):
    profile = application.get("profile") or {}
    if not isinstance(profile, dict):
        profile = {}
    app_name = profile.get("name") or application.get("name") or application.get("guid") or "unknown"
    label = app_name
    if sandbox_guid:
        label = f"{app_name}/sandbox:{sandbox_guid}"
    desc_parts = [f"Veracode application name={app_name}"]
    guid = application.get("guid") or application.get("app_guid")
    if guid:
        desc_parts.append(f"guid={guid}")
    if sandbox_guid:
        desc_parts.append(f"sandbox={sandbox_guid}")
    business_unit = profile.get("business_unit")
    if isinstance(business_unit, dict):
        bu_name = business_unit.get("name")
        if bu_name:
            desc_parts.append(f"business_unit={bu_name}")
    elif business_unit:
        desc_parts.append(f"business_unit={business_unit}")
    business_owners = profile.get("business_owners")
    if isinstance(business_owners, list) and business_owners:
        names = []
        for owner in business_owners:
            if isinstance(owner, dict):
                owner_name = owner.get("name") or owner.get("email")
                if owner_name:
                    names.append(str(owner_name))
        if names:
            desc_parts.append(f"business_owners={', '.join(names)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [label] if label else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    api_id = env("VERACODE_API_KEY_ID", required=True)
    api_secret = env("VERACODE_API_KEY_SECRET", required=True)
    host = env("VERACODE_HOST", default=DEFAULT_HOST).rstrip("/")
    app_guid = env("EXECUTOR_CONFIG_VERACODE_APP_GUID")
    sandbox_guid = env("EXECUTOR_CONFIG_VERACODE_SANDBOX_GUID")
    min_severity = (env("EXECUTOR_CONFIG_VERACODE_MIN_SEVERITY") or "info").lower()
    if min_severity not in VALID_MIN_SEVERITY:
        log(f"VERACODE_MIN_SEVERITY must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}")
        sys.exit(1)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"

    if app_guid:
        application = get_application(base_url, api_id, api_secret, app_guid)
        if not application:
            log(f"Application {app_guid} not found")
            applications = []
        else:
            application.setdefault("guid", app_guid)
            applications = [application]
    else:
        applications = get_applications(base_url, api_id, api_secret)
        log(f"Found {len(applications)} application(s)")

    min_threshold = SEVERITY_ORDER[min_severity]
    hosts = []
    for application in applications:
        guid = application.get("guid") or application.get("app_guid")
        if not guid:
            continue
        raw_findings = get_findings(base_url, api_id, api_secret, guid, sandbox_guid, min_severity)
        vulns = []
        for finding in raw_findings:
            if not isinstance(finding, dict):
                continue
            v = build_vulnerability(finding)
            if SEVERITY_ORDER.get(v["severity"], 0) >= min_threshold:
                vulns.append(v)
        if not vulns:
            continue
        hosts.append(build_host(application, sandbox_guid, vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "veracode",
            "command": "veracode",
            "params": (
                f"app_guid={app_guid or 'all'} sandbox_guid={sandbox_guid or 'none'} " f"min_severity={min_severity}"
            ),
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
