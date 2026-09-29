#!/usr/bin/env python
"""Invicti (formerly Acunetix 360 / Netsparker) REST API importer.

Pulls dynamic application security testing (DAST) findings from an Invicti
cloud or on-prem server and emits Faraday bulk-create JSON to stdout. Each
scan's findings are grouped by target URL hostname into Faraday hosts (one
host per affected web origin); findings without a resolvable URL fall back
to the scan's target URL or a synthetic ``0.0.0.0`` host so the data is
still imported.

Endpoints used:
  GET /api/1.0/scans                          -> list scans (paginated via
      ``page`` / ``pageSize``); a single scan via /api/1.0/scans/{id} when
      INVICTI_SCAN_ID is set.
  GET /api/1.0/scans/{id}/vulnerabilities     -> per-scan vulnerabilities
      (paginated). Each entry carries severity, state (Confirmed /
      FalsePositive / Fixed / Pending / ...), name, URL + HTTP method +
      vulnerable parameter, attack vector / payload, evidence, CWE /
      WASC / OWASP / CAPEC refs and a CVSS score.

Auth: HTTP Basic with INVICTI_USER_ID as the username and INVICTI_API_TOKEN
as the password (this is the documented Invicti / Acunetix 360 REST API auth
scheme — see https://www.invicti.com/support/api/). INVICTI_HOST is the
Invicti server base URL (e.g. https://www.invicti.com,
https://online.acunetix360.com, or the on-prem manager URL).
"""

import json
import os
import socket
import sys
import time
from base64 import b64encode
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

# Invicti reports severity as a string enum. Critical was added on later
# Invicti Enterprise builds; older Netsparker / Acunetix 360 deployments
# top out at High. BestPractice / Information map to info.
INVICTI_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "best practice": "info",
    "best_practice": "info",
    "bestpractice": "info",
    "information": "info",
    "informational": "info",
    "info": "info",
    "none": "info",
}

# Invicti also exposes a 0-4 numeric severity ladder on some endpoints
# (mirroring its string severities). 0 = Information, 1 = Low,
# 2 = Medium, 3 = High, 4 = Critical.
INVICTI_NUMERIC_SEVERITY = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# Invicti finding states. AcceptedRisk / IgnoredFromScan / Suppressed
# / FalsePositive map to Faraday risk-accepted (analyst declared the
# finding non-exploitable or accepted). Fixed / Resolved close the
# finding. Confirmed / Pending / NotFixed stay open.
STATE_TO_STATUS = {
    "confirmed": "open",
    "pending": "open",
    "notfixed": "open",
    "not_fixed": "open",
    "not fixed": "open",
    "open": "open",
    "active": "open",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "patched": "closed",
    "mitigated": "closed",
    "fixedunconfirmed": "closed",
    "fixed_unconfirmed": "closed",
    "scancancelled": "closed",
    "falsepositive": "risk-accepted",
    "false_positive": "risk-accepted",
    "false positive": "risk-accepted",
    "acceptedrisk": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "accepted risk": "risk-accepted",
    "ignoredfromscan": "risk-accepted",
    "ignored_from_scan": "risk-accepted",
    "ignored from scan": "risk-accepted",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "notapplicable": "risk-accepted",
    "not_applicable": "risk-accepted",
    "not applicable": "risk-accepted",
    "announcementrevoked": "closed",
    "announcement_revoked": "closed",
    "revoked": "closed",
}


def log(msg):
    print(f"{datetime.utcnow()} - Invicti: {msg}", file=sys.stderr, flush=True)


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


def severity_from_invicti(value, cvss=None):
    """Map Invicti's severity field to a Faraday severity bucket.

    Accepts the string form (Critical/High/Medium/Low/BestPractice/
    Information) or the 0-4 numeric ladder. Falls back to CVSS bucketing
    when only a numeric CVSS score is available.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, int):
            if value in INVICTI_NUMERIC_SEVERITY:
                return INVICTI_NUMERIC_SEVERITY[value]
        elif isinstance(value, float):
            int_val = int(value)
            if int_val in INVICTI_NUMERIC_SEVERITY and float(int_val) == value:
                return INVICTI_NUMERIC_SEVERITY[int_val]
            # Treat unexpected floats as CVSS scores.
            return severity_from_cvss(value)
        else:
            text = str(value).strip().lower()
            if text in INVICTI_STRING_SEVERITY:
                return INVICTI_STRING_SEVERITY[text]
            try:
                num = int(text)
                if num in INVICTI_NUMERIC_SEVERITY:
                    return INVICTI_NUMERIC_SEVERITY[num]
            except ValueError:
                pass
            try:
                return severity_from_cvss(float(text))
            except ValueError:
                pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_invicti(vuln):
    """Derive Faraday status from Invicti lifecycle / audit flags.

    Invicti findings carry a ``State`` (and a few legacy aliases). When the
    state is missing, fall back to boolean flags ``isFalsePositive`` /
    ``falsePositive`` and ``isFixed`` / ``fixed``.
    """
    for key in ("state", "status", "vulnerabilityState"):
        raw = vuln.get(key)
        if not raw:
            continue
        text = str(raw).strip().lower()
        if text in STATE_TO_STATUS:
            return STATE_TO_STATUS[text]
        if text in ("falsepositive", "false_positive", "false positive"):
            return "risk-accepted"
    if vuln.get("isFalsePositive") or vuln.get("falsePositive"):
        return "risk-accepted"
    if vuln.get("isIgnored") or vuln.get("ignored") or vuln.get("suppressed"):
        return "risk-accepted"
    if vuln.get("isAcceptedRisk") or vuln.get("acceptedRisk"):
        return "risk-accepted"
    if vuln.get("isFixed") or vuln.get("fixed"):
        return "closed"
    return "open"


def normalize_base_url(host):
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def build_auth_header(user_id, token):
    """Build the HTTP Basic ``Authorization`` header value.

    Invicti's REST API uses HTTP Basic with the user id as the username
    and the API token as the password. See
    https://www.invicti.com/support/api/.
    """
    raw = f"{user_id}:{token}".encode("utf-8")
    return f"Basic {b64encode(raw).decode('ascii')}"


def get_page(base_url, path, headers, params):
    url = f"{base_url}{path}"
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        log(f"GET {path} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Authentication rejected (401). INVICTI_USER_ID / INVICTI_API_TOKEN invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the token's role.")
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
    """Pluck a list out of an Invicti REST response.

    Invicti wraps list responses in ``{"List": [...], "TotalItemCount": N,
    "PageCount": ...}`` (PascalCase on most builds, camelCase on newer
    ones). Some endpoints expose ``Vulnerabilities`` / ``Scans`` instead.
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
        for candidate in ("List", "list", "Items", "items", "Data", "data", "Results", "results"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def collect(base_url, path, headers, base_params, *list_keys):
    """Paginate Invicti list endpoints via ``page`` + ``pageSize``."""
    results = []
    page = 1
    for _ in range(MAX_PAGES):
        params = dict(base_params or {})
        params["page"] = page
        params["pageSize"] = PAGE_SIZE
        body = get_page(base_url, path, headers, params)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        total = None
        if isinstance(body, dict):
            total = (
                body.get("TotalItemCount")
                or body.get("totalItemCount")
                or body.get("Total")
                or body.get("total")
                or body.get("totalCount")
            )
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        page += 1
    return results


def get_scans(base_url, headers, scan_id):
    if scan_id:
        body = get_page(base_url, f"/api/1.0/scans/{scan_id}", headers, {})
        if isinstance(body, dict):
            data = body.get("data") or body.get("Data")
            if isinstance(data, dict):
                return [data]
            return [body]
        return []
    return collect(base_url, "/api/1.0/scans", headers, {}, "Scans", "scans")


def get_vulnerabilities(base_url, headers, scan_id):
    return collect(
        base_url,
        f"/api/1.0/scans/{scan_id}/vulnerabilities",
        headers,
        {},
        "Vulnerabilities",
        "vulnerabilities",
    )


def cvss_score(vuln):
    """Pull a numeric CVSS v3 base score out of an Invicti finding.

    Invicti exposes CVSS under a few shapes — ``cvss`` may be a dict with
    ``vector`` + ``baseScore``, ``cvssScore`` may be a bare float, and the
    nested ``cvss3.baseScore`` shape exists on older builds.
    """
    for key in ("cvss", "Cvss", "cvss3", "Cvss3", "cvssV3", "CvssV3"):
        value = vuln.get(key)
        if isinstance(value, dict):
            score = value.get("baseScore") or value.get("BaseScore") or value.get("score") or value.get("Score")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
        elif isinstance(value, (int, float)):
            return float(value)
    for key in ("cvssScore", "CvssScore", "cvss_score", "Score", "score"):
        value = vuln.get(key)
        if value is not None and not isinstance(value, dict):
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
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

    classification = (
        vuln.get("classification")
        or vuln.get("Classification")
        or vuln.get("classifications")
        or vuln.get("Classifications")
        or {}
    )
    if isinstance(classification, list):
        # Some Invicti versions emit list-of-{type, value} entries.
        merged = {}
        for entry in classification:
            if isinstance(entry, dict):
                key = entry.get("type") or entry.get("Type") or entry.get("name") or entry.get("Name")
                val = entry.get("value") or entry.get("Value") or entry.get("id") or entry.get("Id")
                if key and val is not None:
                    merged[str(key).lower()] = val
        classification = merged
    if not isinstance(classification, dict):
        classification = {}

    cwe_sources = (
        vuln.get("cwe"),
        vuln.get("CWE"),
        vuln.get("Cwe"),
        vuln.get("cweId"),
        vuln.get("CweId"),
        vuln.get("cweIds"),
        vuln.get("cwes"),
        classification.get("cwe"),
        classification.get("CWE"),
        classification.get("cwes"),
    )
    for cwe_val in cwe_sources:
        if not cwe_val:
            continue
        if isinstance(cwe_val, (list, tuple)):
            for entry in cwe_val:
                if isinstance(entry, dict):
                    val = entry.get("id") or entry.get("Id") or entry.get("name") or entry.get("value")
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

    for wasc_val in (vuln.get("wasc"), vuln.get("Wasc"), classification.get("wasc")):
        if not wasc_val:
            continue
        if isinstance(wasc_val, (list, tuple)):
            for entry in wasc_val:
                if entry:
                    add(f"WASC-{entry}")
        else:
            add(f"WASC-{wasc_val}")

    for owasp_val in (
        vuln.get("owasp"),
        vuln.get("Owasp"),
        vuln.get("owaspCategory"),
        classification.get("owasp"),
        classification.get("owasp2017"),
        classification.get("owasp2021"),
    ):
        if not owasp_val:
            continue
        if isinstance(owasp_val, (list, tuple)):
            for entry in owasp_val:
                if entry:
                    add(f"OWASP: {entry}")
        else:
            add(f"OWASP: {owasp_val}")

    for capec_val in (vuln.get("capec"), classification.get("capec")):
        if not capec_val:
            continue
        if isinstance(capec_val, (list, tuple)):
            for entry in capec_val:
                if entry:
                    add(f"CAPEC-{entry}")
        else:
            add(f"CAPEC-{capec_val}")

    for hipaa_val in (vuln.get("hipaa"), classification.get("hipaa")):
        if hipaa_val:
            add(f"HIPAA: {hipaa_val}")
    for pci_val in (vuln.get("pci"), vuln.get("pci32"), classification.get("pci")):
        if pci_val:
            add(f"PCI: {pci_val}")

    vuln_type = vuln.get("type") or vuln.get("Type") or vuln.get("vulnerabilityType")
    if vuln_type:
        add(f"InvictiCheck-{vuln_type}")

    for entry in vuln.get("references") or vuln.get("References") or vuln.get("externalReferences") or []:
        if isinstance(entry, str):
            add(entry)
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("Url") or entry.get("href") or entry.get("name")
            add(value)
    return refs


def collect_cves(vuln):
    cves = []
    seen = set()
    candidates = []
    for key in ("cve", "CVE", "Cve", "cveId", "CveId", "cveName", "cve_id"):
        value = vuln.get(key)
        if value:
            if isinstance(value, (list, tuple)):
                candidates.extend(value)
            else:
                candidates.append(value)
    for key in ("cves", "Cves", "CVEs"):
        value = vuln.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            for entry in value:
                if isinstance(entry, str):
                    candidates.append(entry)
                elif isinstance(entry, dict):
                    inner = entry.get("name") or entry.get("id") or entry.get("value") or entry.get("cve")
                    if inner:
                        candidates.append(inner)
    for value in candidates:
        text = str(value).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)
    return cves


def build_vulnerability(vuln):
    score = cvss_score(vuln)
    severity = severity_from_invicti(vuln.get("severity") or vuln.get("Severity") or vuln.get("severityCode"), score)
    status = status_from_invicti(vuln)
    check_name = (
        vuln.get("name")
        or vuln.get("Name")
        or vuln.get("title")
        or vuln.get("Title")
        or vuln.get("vulnerabilityName")
        or f"Invicti finding {vuln.get('id') or vuln.get('Id') or ''}"
    )
    name = f"[DAST] {check_name}"

    desc_parts = []
    description = (
        vuln.get("description")
        or vuln.get("Description")
        or vuln.get("summary")
        or vuln.get("Summary")
        or vuln.get("issueDescription")
    )
    if description:
        desc_parts.append(str(description))
    impact = vuln.get("impact") or vuln.get("Impact")
    if impact:
        desc_parts.append(f"impact: {impact}")

    method = vuln.get("httpMethod") or vuln.get("HttpMethod") or vuln.get("method") or vuln.get("Method")
    url = (
        vuln.get("url")
        or vuln.get("Url")
        or vuln.get("URL")
        or vuln.get("targetUrl")
        or vuln.get("TargetUrl")
        or vuln.get("location")
    )
    if url:
        if method:
            desc_parts.append(f"request: {method} {url}")
        else:
            desc_parts.append(f"url: {url}")
    elif method:
        desc_parts.append(f"method: {method}")

    parameter = (
        vuln.get("vulnerableParameter")
        or vuln.get("VulnerableParameter")
        or vuln.get("parameter")
        or vuln.get("Parameter")
        or vuln.get("parameterName")
    )
    if parameter:
        param_type = (
            vuln.get("vulnerableParameterType")
            or vuln.get("VulnerableParameterType")
            or vuln.get("parameterType")
            or vuln.get("ParameterType")
        )
        if param_type:
            desc_parts.append(f"parameter: {parameter} ({param_type})")
        else:
            desc_parts.append(f"parameter: {parameter}")

    attack = (
        vuln.get("vulnerableParameterValue")
        or vuln.get("VulnerableParameterValue")
        or vuln.get("attackPattern")
        or vuln.get("AttackPattern")
        or vuln.get("attack")
        or vuln.get("payload")
    )
    if attack:
        desc_parts.append(f"attack: {attack}")

    extracted_command = vuln.get("extractedCommand") or vuln.get("ExtractedCommand")
    if extracted_command:
        desc_parts.append(f"extractedCommand: {extracted_command}")

    cert = vuln.get("certainty") or vuln.get("Certainty") or vuln.get("confidence")
    if cert:
        desc_parts.append(f"certainty: {cert}")

    proof_url = vuln.get("proofOfConcept") or vuln.get("ProofOfConcept")
    if proof_url:
        desc_parts.append(f"poc: {proof_url}")

    if score is not None:
        desc_parts.append(f"cvss: {score}")

    state = vuln.get("state") or vuln.get("State") or vuln.get("status") or vuln.get("Status")
    if state:
        desc_parts.append(f"state: {state}")

    look_id = (
        vuln.get("lookupId")
        or vuln.get("LookupId")
        or vuln.get("uniqueId")
        or vuln.get("UniqueId")
        or vuln.get("vulnerabilityId")
        or vuln.get("VulnerabilityId")
    )
    if look_id:
        desc_parts.append(f"lookupId: {look_id}")

    evidence = (
        vuln.get("extractedResults")
        or vuln.get("ExtractedResults")
        or vuln.get("evidence")
        or vuln.get("Evidence")
        or vuln.get("proof")
        or vuln.get("response")
        or vuln.get("responseContent")
    )
    if evidence and not isinstance(evidence, (dict, list)):
        text = str(evidence)
        desc_parts.append(f"evidence: {text[:500]}{'...' if len(text) > 500 else ''}")

    resolution = (
        vuln.get("remedy")
        or vuln.get("Remedy")
        or vuln.get("remediation")
        or vuln.get("Remediation")
        or vuln.get("recommendation")
        or vuln.get("Recommendation")
        or vuln.get("solution")
        or vuln.get("fix")
        or ""
    )

    request_data = vuln.get("rawRequest") or vuln.get("RawRequest") or vuln.get("request") or vuln.get("Request")
    if isinstance(request_data, dict):
        request_data = request_data.get("data") or request_data.get("content") or ""

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score

    external_id = (
        vuln.get("id")
        or vuln.get("Id")
        or vuln.get("vulnerabilityId")
        or vuln.get("VulnerabilityId")
        or vuln.get("lookupId")
        or vuln.get("LookupId")
        or look_id
        or ""
    )

    return {
        "name": str(name).strip()[:200] or f"Invicti finding {external_id}",
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
        "tags": ["invicti", "dast"],
    }


def target_key(vuln, fallback_url):
    """Stable per-target key used to group vulnerabilities into hosts.

    Each Invicti finding carries the offending request URL; collapse on
    hostname so all findings against the same origin land on the same
    Faraday host. Findings without a URL fall back to the scan's target
    URL.
    """
    url = (
        vuln.get("url")
        or vuln.get("Url")
        or vuln.get("URL")
        or vuln.get("targetUrl")
        or vuln.get("TargetUrl")
        or vuln.get("location")
    )
    if not url:
        url = fallback_url
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
    desc_parts = ["Invicti findings without a resolvable URL"]
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
            scan.get("id")
            or scan.get("Id")
            or scan.get("scanId")
            or scan.get("ScanId")
            or scan.get("uuid")
            or scan.get("Uuid")
        ),
        "scan_name": (
            scan.get("name")
            or scan.get("Name")
            or scan.get("scanName")
            or scan.get("ScanName")
            or scan.get("websiteName")
            or scan.get("WebsiteName")
        ),
        "start_url": (
            scan.get("targetUrl")
            or scan.get("TargetUrl")
            or scan.get("startUrl")
            or scan.get("StartUrl")
            or scan.get("websiteUrl")
            or scan.get("WebsiteUrl")
        ),
        "policy": (
            scan.get("policyName")
            or scan.get("PolicyName")
            or scan.get("scanPolicy")
            or scan.get("ScanPolicy")
            or scan.get("policy")
            or scan.get("Policy")
        ),
    }


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"INVICTI_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def main():
    started = time.time()
    host = env("INVICTI_HOST", required=True).rstrip("/")
    user_id = env("INVICTI_USER_ID", required=True)
    token = env("INVICTI_API_TOKEN", required=True)
    scan_id_arg = env("EXECUTOR_CONFIG_INVICTI_SCAN_ID")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_INVICTI_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    headers = {
        "Authorization": build_auth_header(user_id, token),
        "Accept": "application/json",
    }

    scans = get_scans(base_url, headers, scan_id_arg)
    if not scans and scan_id_arg:
        log(f"Scan {scan_id_arg} not found or not accessible")
        scans = [{"id": scan_id_arg}]
    log(f"Processing {len(scans)} scan(s) (scan_id={scan_id_arg or 'all'}, min_severity={min_severity})")

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
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            key = target_key(raw, meta.get("start_url"))
            if key is None:
                orphan.append(built)
                continue
            bucket = by_target.setdefault(key, {"sample_url": None, "vulns": []})
            if bucket["sample_url"] is None:
                bucket["sample_url"] = raw.get("url") or raw.get("Url") or raw.get("URL") or meta.get("start_url")
            bucket["vulns"].append(built)
        for key, bucket in by_target.items():
            hosts.append(build_host(key, bucket["sample_url"], bucket["vulns"], meta))
        if orphan:
            hosts.append(synthetic_host(orphan, meta))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "invicti",
            "command": "invicti",
            "params": f"scan_id={scan_id_arg or 'all'},min_severity={min_severity}",
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
