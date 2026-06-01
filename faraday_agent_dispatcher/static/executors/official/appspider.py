#!/usr/bin/env python
"""Rapid7 AppSpider Enterprise REST API importer.

Pulls dynamic application security testing (DAST) findings from a Rapid7
AppSpider Enterprise (formerly NTOSpider / NTObjectives) server and emits
Faraday bulk-create JSON to stdout. Each scan's findings are grouped by the
offending request URL hostname into Faraday hosts (one host per affected
web origin); findings without a resolvable URL fall back to the scan's
target URL or a synthetic ``0.0.0.0`` host so the data is still imported.

Endpoints used:
  GET /api/v1/Scans                          -> list scans (paginated via
      ``offset`` / ``limit``); a single scan via /api/v1/Scans/{id} when
      APPSPIDER_SCAN_ID is set.
  GET /api/v1/Vulnerabilities                -> per-scan vulnerabilities
      (filtered via ``scanId=<id>`` query parameter, paginated). Each
      entry carries severity (string + numeric), state (Active /
      FalsePositive / Fixed / ...), name, URL + HTTP method + vulnerable
      parameter, attack value, evidence, CWE / WASC / OWASP / CAPEC refs
      and a CVSS score.

Auth: ``Authorization: Bearer <APPSPIDER_TOKEN>`` carrying the AppSpider
Enterprise API token (obtained from POST /api/v1/Authentication/Login or
the AppSpider Enterprise console). Pre-built ``Bearer`` / ``Token`` /
``ApiToken`` prefixes in the supplied value are forwarded unchanged so
SSO-backed deployments work too. APPSPIDER_HOST is the AppSpider
Enterprise base URL (e.g. https://appspider.corp.example.com or the
on-prem manager URL).
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 200
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# AppSpider exposes severity as a string enum plus a numeric 0-4 ladder
# on newer builds. Critical is included to be forward-compatible.
APPSPIDER_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "informational": "info",
    "information": "info",
    "info": "info",
    "safe": "info",
    "none": "info",
    "best practice": "info",
    "best_practice": "info",
    "bestpractice": "info",
}

APPSPIDER_NUMERIC_SEVERITY = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# AppSpider finding states. FalsePositive / AcceptedRisk / Ignored map
# to Faraday risk-accepted. Fixed / Resolved / Closed close the
# finding. Active / Open / Pending / NewlyDiscovered stay open.
STATE_TO_STATUS = {
    "active": "open",
    "open": "open",
    "newlydiscovered": "open",
    "newly_discovered": "open",
    "newly discovered": "open",
    "pending": "open",
    "confirmed": "open",
    "verified": "open",
    "reopened": "open",
    "untracked": "open",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "patched": "closed",
    "mitigated": "closed",
    "remediated": "closed",
    "falsepositive": "risk-accepted",
    "false_positive": "risk-accepted",
    "false positive": "risk-accepted",
    "acceptedrisk": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "accepted risk": "risk-accepted",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "notapplicable": "risk-accepted",
    "not_applicable": "risk-accepted",
    "not applicable": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "risk-accepted": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - AppSpider: {msg}", file=sys.stderr, flush=True)


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
    return "critical"


def severity_from_appspider(value, cvss=None):
    """Map AppSpider's severity field to a Faraday severity bucket.

    Accepts AppSpider's string enum (Critical / High / Medium / Low /
    Informational) or its 0-4 numeric ladder. Falls back to CVSS
    bucketing on the provided ``cvss`` argument when the primary value
    is missing or unrecognised.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, int):
            mapped = APPSPIDER_NUMERIC_SEVERITY.get(value)
            if mapped:
                return mapped
        elif isinstance(value, float):
            mapped = APPSPIDER_NUMERIC_SEVERITY.get(int(value))
            if mapped:
                return mapped
        else:
            text = str(value).strip().lower()
            if text in APPSPIDER_STRING_SEVERITY:
                return APPSPIDER_STRING_SEVERITY[text]
            try:
                number = int(float(text))
                mapped = APPSPIDER_NUMERIC_SEVERITY.get(number)
                if mapped:
                    return mapped
            except ValueError:
                pass
            try:
                return severity_from_cvss(float(text))
            except ValueError:
                pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_appspider(vuln):
    """Derive Faraday status from AppSpider's status / triage flags.

    AppSpider tracks finding lifecycle via ``Status`` / ``State`` and
    analyst triage via ``IsFalsePositive`` / ``Ignored`` boolean flags
    (and some builds surface ``Disposition`` instead). Analyst triage
    wins over the lifecycle status, so a Fixed finding flagged as
    FalsePositive lands as Faraday risk-accepted.
    """
    if vuln.get("IsFalsePositive") or vuln.get("isFalsePositive") or vuln.get("false_positive"):
        return "risk-accepted"
    if vuln.get("Ignored") or vuln.get("ignored") or vuln.get("Suppressed") or vuln.get("suppressed"):
        return "risk-accepted"
    if vuln.get("AcceptedRisk") or vuln.get("acceptedRisk") or vuln.get("accepted_risk"):
        return "risk-accepted"
    for key in (
        "Status",
        "status",
        "State",
        "state",
        "Disposition",
        "disposition",
        "VulnerabilityStatus",
        "vulnerabilityStatus",
        "vulnerability_status",
    ):
        raw = vuln.get(key)
        if not raw:
            continue
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("Name") or raw.get("value") or raw.get("Value")
        if not raw:
            continue
        text = str(raw).strip().lower()
        if text in STATE_TO_STATUS:
            return STATE_TO_STATUS[text]
    if vuln.get("IsFixed") or vuln.get("isFixed") or vuln.get("Fixed") or vuln.get("fixed"):
        return "closed"
    return "open"


def build_auth_header(token):
    """Format the AppSpider token as an Authorization header value.

    AppSpider Enterprise's /api/v1 endpoints expect a Bearer token from
    POST /api/v1/Authentication/Login. Pre-built ``Bearer`` /
    ``Token`` / ``ApiToken`` prefixes are preserved so SSO-backed
    deployments can forward an unusual scheme verbatim.
    """
    if not token:
        return ""
    text = str(token).strip()
    lower = text.lower()
    if lower.startswith(("bearer ", "token ", "apitoken ", "appspider ")):
        return text
    return f"Bearer {text}"


def normalize_base_url(host):
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


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
        log("Authentication rejected (401). APPSPIDER_TOKEN expired or invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the token's role.")
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
    """Pluck a list out of an AppSpider REST response.

    AppSpider mixes PascalCase and camelCase across builds. Newer
    Enterprise releases wrap list responses in ``{"Scans": [...]}`` or
    ``{"Vulnerabilities": [...]}`` but older builds fall back to
    ``data`` / ``items`` / a bare list.
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys:
            value = body.get(key)
            if isinstance(value, list):
                return value
        for candidate in ("Scans", "scans", "Vulnerabilities", "vulnerabilities", "data", "items", "results", "List"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, base_params, *list_keys):
    """Paginate AppSpider list endpoints via ``offset`` + ``limit``."""
    results = []
    offset = 0
    for _ in range(MAX_PAGES):
        params = dict(base_params or {})
        params["offset"] = offset
        params["limit"] = PAGE_SIZE
        body = request_json("GET", base_url, path, headers, params=params)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = body.get("TotalCount") or body.get("totalCount") or body.get("total") or body.get("count")
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return results


def get_scans(base_url, headers, scan_id):
    if scan_id:
        body = request_json("GET", base_url, f"/api/v1/Scans/{scan_id}", headers)
        if isinstance(body, dict):
            data = body.get("Scan") or body.get("scan") or body.get("data")
            if isinstance(data, dict):
                return [data]
            if body.get("Id") is not None or body.get("id") is not None or body.get("scanId") is not None:
                return [body]
        return []
    return collect(base_url, "/api/v1/Scans", headers, {}, "Scans", "scans")


def get_vulnerabilities(base_url, headers, scan_id):
    return collect(
        base_url,
        "/api/v1/Vulnerabilities",
        headers,
        {"scanId": scan_id},
        "Vulnerabilities",
        "vulnerabilities",
    )


def cvss_score(vuln):
    """Pull a numeric CVSS score out of an AppSpider finding.

    AppSpider exposes ``CvssScore`` (PascalCase) on newer builds and
    ``cvssScore`` / ``cvss.baseScore`` / ``cvss3.baseScore`` on others.
    """
    for key in ("CvssScore", "cvssScore", "cvss_score", "Score", "score"):
        value = vuln.get(key)
        if value is None or isinstance(value, dict):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for key in ("Cvss", "cvss", "Cvss3", "cvss3", "CvssV3", "cvssV3"):
        value = vuln.get(key)
        if isinstance(value, dict):
            score = (
                value.get("BaseScore")
                or value.get("baseScore")
                or value.get("base_score")
                or value.get("Score")
                or value.get("score")
            )
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
        elif isinstance(value, (int, float)):
            return float(value)
    return None


def collect_refs(vuln):
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

    cwe_sources = (
        vuln.get("Cwe"),
        vuln.get("cwe"),
        vuln.get("CweId"),
        vuln.get("cweId"),
        vuln.get("cwe_id"),
        vuln.get("CweIds"),
        vuln.get("cweIds"),
        vuln.get("Cwes"),
        vuln.get("cwes"),
    )
    for cwe_val in cwe_sources:
        if not cwe_val:
            continue
        if isinstance(cwe_val, (list, tuple)):
            for entry in cwe_val:
                if isinstance(entry, dict):
                    val = (
                        entry.get("id")
                        or entry.get("Id")
                        or entry.get("name")
                        or entry.get("Name")
                        or entry.get("value")
                    )
                    if val:
                        text = str(val).strip()
                        text = text[4:] if text.lower().startswith("cwe-") else text
                        add(f"CWE-{text}")
                elif entry:
                    text = str(entry).strip()
                    text = text[4:] if text.lower().startswith("cwe-") else text
                    add(f"CWE-{text}")
        else:
            text = str(cwe_val).strip()
            text = text[4:] if text.lower().startswith("cwe-") else text
            add(f"CWE-{text}")

    for wasc_field in ("Wasc", "wasc", "WascId", "wascId", "WascIds", "wascIds"):
        value = vuln.get(wasc_field)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if entry:
                    add(f"WASC-{entry}")
        else:
            add(f"WASC-{value}")

    for owasp_field in (
        "Owasp",
        "owasp",
        "OwaspCategory",
        "owaspCategory",
        "Owasp2017",
        "owasp2017",
        "Owasp2021",
        "owasp2021",
    ):
        value = vuln.get(owasp_field)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if entry:
                    add(f"OWASP: {entry}")
        else:
            add(f"OWASP: {value}")

    for capec_field in ("Capec", "capec", "CapecId", "capecId"):
        value = vuln.get(capec_field)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if entry:
                    add(f"CAPEC-{entry}")
        else:
            add(f"CAPEC-{value}")

    check_id = (
        vuln.get("CheckTypeId")
        or vuln.get("checkTypeId")
        or vuln.get("CheckId")
        or vuln.get("checkId")
        or vuln.get("AttackId")
        or vuln.get("attackId")
    )
    if check_id:
        add(f"AppSpiderCheck-{check_id}")

    module_name = vuln.get("AttackType") or vuln.get("attackType") or vuln.get("Module") or vuln.get("module")
    if module_name:
        add(f"AppSpiderAttack-{module_name}")

    for entry in vuln.get("References") or vuln.get("references") or vuln.get("Links") or vuln.get("links") or []:
        if isinstance(entry, str):
            add(entry)
        elif isinstance(entry, dict):
            value = (
                entry.get("url")
                or entry.get("Url")
                or entry.get("href")
                or entry.get("Href")
                or entry.get("name")
                or entry.get("Name")
                or entry.get("value")
            )
            add(value)
    return refs


def collect_cves(vuln):
    cves = []
    seen = set()
    candidates = []
    for key in ("Cve", "cve", "CveId", "cveId", "CveName", "cveName", "cve_id"):
        value = vuln.get(key)
        if value:
            if isinstance(value, (list, tuple)):
                candidates.extend(value)
            else:
                candidates.append(value)
    for key in ("Cves", "cves", "CVEs"):
        value = vuln.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if isinstance(entry, str):
                    candidates.append(entry)
                elif isinstance(entry, dict):
                    inner = (
                        entry.get("name")
                        or entry.get("Name")
                        or entry.get("id")
                        or entry.get("Id")
                        or entry.get("value")
                    )
                    if inner:
                        candidates.append(inner)
    for value in candidates:
        text = str(value).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)
    return cves


def vuln_url(vuln):
    return (
        vuln.get("Url")
        or vuln.get("url")
        or vuln.get("RequestUrl")
        or vuln.get("requestUrl")
        or vuln.get("TargetUrl")
        or vuln.get("targetUrl")
        or vuln.get("Location")
        or vuln.get("location")
    )


def vuln_method(vuln):
    return (
        vuln.get("Method")
        or vuln.get("method")
        or vuln.get("HttpMethod")
        or vuln.get("httpMethod")
        or vuln.get("RequestMethod")
        or vuln.get("requestMethod")
    )


def build_vulnerability(vuln):
    score = cvss_score(vuln)
    severity = severity_from_appspider(
        vuln.get("Severity") or vuln.get("severity") or vuln.get("SeverityLevel") or vuln.get("severityLevel"),
        score,
    )
    status = status_from_appspider(vuln)
    check_name = (
        vuln.get("Name")
        or vuln.get("name")
        or vuln.get("VulnerabilityName")
        or vuln.get("vulnerabilityName")
        or vuln.get("Title")
        or vuln.get("title")
        or vuln.get("AttackType")
        or vuln.get("attackType")
        or f"AppSpider finding {vuln.get('Id') or vuln.get('id') or ''}"
    )
    name = f"[DAST] {check_name}"

    desc_parts = []
    description = (
        vuln.get("Description")
        or vuln.get("description")
        or vuln.get("Summary")
        or vuln.get("summary")
        or vuln.get("Synopsis")
        or vuln.get("synopsis")
    )
    if description:
        desc_parts.append(str(description))
    implication = vuln.get("Implication") or vuln.get("implication") or vuln.get("Impact") or vuln.get("impact")
    if implication:
        desc_parts.append(f"implication: {implication}")

    method = vuln_method(vuln)
    url = vuln_url(vuln)
    if url:
        if method:
            desc_parts.append(f"request: {method} {url}")
        else:
            desc_parts.append(f"url: {url}")
    elif method:
        desc_parts.append(f"method: {method}")

    parameter = (
        vuln.get("Parameter")
        or vuln.get("parameter")
        or vuln.get("VulnerableParameter")
        or vuln.get("vulnerableParameter")
        or vuln.get("ParameterName")
        or vuln.get("parameterName")
    )
    if parameter:
        param_type = (
            vuln.get("ParameterType") or vuln.get("parameterType") or vuln.get("ParamType") or vuln.get("paramType")
        )
        if param_type:
            desc_parts.append(f"parameter: {parameter} ({param_type})")
        else:
            desc_parts.append(f"parameter: {parameter}")

    attack = (
        vuln.get("AttackValue")
        or vuln.get("attackValue")
        or vuln.get("AttackString")
        or vuln.get("attackString")
        or vuln.get("Attack")
        or vuln.get("attack")
        or vuln.get("Payload")
        or vuln.get("payload")
    )
    if attack:
        desc_parts.append(f"attack: {attack}")

    certainty = vuln.get("Certainty") or vuln.get("certainty") or vuln.get("Confidence") or vuln.get("confidence")
    if certainty is not None and certainty != "":
        desc_parts.append(f"certainty: {certainty}")

    if score is not None:
        desc_parts.append(f"cvss: {score}")

    instance_id = (
        vuln.get("InstanceId")
        or vuln.get("instanceId")
        or vuln.get("UniqueId")
        or vuln.get("uniqueId")
        or vuln.get("LookupId")
        or vuln.get("lookupId")
    )
    if instance_id:
        desc_parts.append(f"instanceId: {instance_id}")

    status_raw = (
        vuln.get("Status")
        or vuln.get("status")
        or vuln.get("State")
        or vuln.get("state")
        or vuln.get("Disposition")
        or vuln.get("disposition")
    )
    if status_raw:
        desc_parts.append(f"state: {status_raw}")

    first_seen = (
        vuln.get("FirstDiscovered")
        or vuln.get("firstDiscovered")
        or vuln.get("FirstSeen")
        or vuln.get("firstSeen")
        or vuln.get("DiscoveredOn")
        or vuln.get("discoveredOn")
    )
    if first_seen:
        desc_parts.append(f"first_seen: {first_seen}")
    last_seen = (
        vuln.get("LastDiscovered")
        or vuln.get("lastDiscovered")
        or vuln.get("LastSeen")
        or vuln.get("lastSeen")
        or vuln.get("LastFound")
        or vuln.get("lastFound")
    )
    if last_seen:
        desc_parts.append(f"last_seen: {last_seen}")

    evidence = (
        vuln.get("Evidence")
        or vuln.get("evidence")
        or vuln.get("Proof")
        or vuln.get("proof")
        or vuln.get("ResponseContent")
        or vuln.get("responseContent")
        or vuln.get("AttackResponse")
        or vuln.get("attackResponse")
    )
    if evidence and not isinstance(evidence, (dict, list)):
        text = str(evidence)
        desc_parts.append(f"evidence: {text[:500]}{'...' if len(text) > 500 else ''}")

    resolution = (
        vuln.get("Recommendation")
        or vuln.get("recommendation")
        or vuln.get("Remediation")
        or vuln.get("remediation")
        or vuln.get("Fix")
        or vuln.get("fix")
        or vuln.get("Solution")
        or vuln.get("solution")
        or ""
    )

    request_data = (
        vuln.get("RawRequest")
        or vuln.get("rawRequest")
        or vuln.get("Request")
        or vuln.get("request")
        or vuln.get("RequestRaw")
        or vuln.get("requestRaw")
    )
    if isinstance(request_data, dict):
        request_data = (
            request_data.get("data")
            or request_data.get("Data")
            or request_data.get("content")
            or request_data.get("Content")
            or request_data.get("raw")
            or request_data.get("Raw")
            or ""
        )

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score

    external_id = (
        vuln.get("Id")
        or vuln.get("id")
        or vuln.get("VulnerabilityId")
        or vuln.get("vulnerabilityId")
        or instance_id
        or ""
    )

    return {
        "name": str(name).strip()[:200] or f"AppSpider finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id),
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": str(request_data) if request_data else "",
        "refs": collect_refs(vuln),
        "cve": collect_cves(vuln),
        "cvss3": cvss3,
        "tags": ["appspider", "dast"],
    }


def target_key(vuln, fallback_url):
    """Stable per-target key used to group vulnerabilities into hosts."""
    url = vuln_url(vuln) or fallback_url
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname
    if host:
        return ("host", host.lower())
    return ("host", str(url).strip().lower())


def build_host(key, sample_url, vulns, scan_meta):
    _, hostname = key
    desc_parts = []
    scan_id = scan_meta.get("scan_id") if scan_meta else None
    if scan_id is not None:
        desc_parts.append(f"scan_id={scan_id}")
    scan_name = scan_meta.get("scan_name") if scan_meta else None
    if scan_name:
        desc_parts.append(f"scan={scan_name}")
    policy = scan_meta.get("policy") if scan_meta else None
    if policy:
        desc_parts.append(f"policy={policy}")
    if sample_url:
        desc_parts.append(f"target_url={sample_url}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def synthetic_host(vulns, scan_meta):
    desc_parts = ["AppSpider findings without a resolvable URL"]
    scan_id = scan_meta.get("scan_id") if scan_meta else None
    if scan_id is not None:
        desc_parts.append(f"scan_id={scan_id}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def scan_meta_from(scan):
    if not isinstance(scan, dict):
        return {}
    return {
        "scan_id": (
            scan.get("Id")
            or scan.get("id")
            or scan.get("ScanId")
            or scan.get("scanId")
            or scan.get("Uuid")
            or scan.get("uuid")
        ),
        "scan_name": (
            scan.get("Name")
            or scan.get("name")
            or scan.get("ScanName")
            or scan.get("scanName")
            or scan.get("Title")
            or scan.get("title")
        ),
        "target_url": (
            scan.get("TargetUrl")
            or scan.get("targetUrl")
            or scan.get("StartUrl")
            or scan.get("startUrl")
            or scan.get("Url")
            or scan.get("url")
        ),
        "policy": (scan.get("PolicyName") or scan.get("policyName") or scan.get("Policy") or scan.get("policy")),
    }


def main():
    started = time.time()
    host = env("APPSPIDER_HOST", required=True).rstrip("/")
    token = env("APPSPIDER_TOKEN", required=True)
    scan_id_arg = env("EXECUTOR_CONFIG_APPSPIDER_SCAN_ID")

    base_url = normalize_base_url(host)
    headers = {
        "Authorization": build_auth_header(token),
        "Accept": "application/json",
    }

    scans = get_scans(base_url, headers, scan_id_arg)
    if not scans and scan_id_arg:
        log(f"Scan {scan_id_arg} not found or not accessible")
        scans = [{"Id": scan_id_arg}]
    log(f"Processing {len(scans)} scan(s) (scan_id={scan_id_arg or 'all'})")

    hosts = []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        meta = scan_meta_from(scan)
        sid = meta.get("scan_id")
        if sid is None:
            continue
        raw_vulns = get_vulnerabilities(base_url, headers, sid)
        by_target = {}
        orphan = []
        for raw in raw_vulns:
            if not isinstance(raw, dict):
                continue
            built = build_vulnerability(raw)
            key = target_key(raw, meta.get("target_url"))
            if key is None:
                orphan.append(built)
                continue
            bucket = by_target.setdefault(key, {"sample_url": None, "vulns": []})
            if bucket["sample_url"] is None:
                bucket["sample_url"] = vuln_url(raw) or meta.get("target_url")
            bucket["vulns"].append(built)
        for key, bucket in by_target.items():
            hosts.append(build_host(key, bucket["sample_url"], bucket["vulns"], meta))
        if orphan:
            hosts.append(synthetic_host(orphan, meta))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "appspider",
            "command": "appspider",
            "params": f"scan_id={scan_id_arg or 'all'}",
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
