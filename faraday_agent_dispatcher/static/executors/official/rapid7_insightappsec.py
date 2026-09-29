#!/usr/bin/env python
"""Rapid7 InsightAppSec REST API importer.

Pulls dynamic application security testing (DAST) findings from Rapid7's
Insight Platform (InsightAppSec product) and emits Faraday bulk-create JSON
to stdout. Each scan's findings are grouped by the offending request URL
hostname into Faraday hosts (one host per affected web origin); findings
without a resolvable URL fall back to the scan's app / target URL or a
synthetic ``0.0.0.0`` host so the data is still imported.

Endpoints used:
  POST /ias/v1/scans/search           -> filter scans by scan_config id /
      status (preferred when INSIGHTAPPSEC_SCAN_CONFIG_ID is set).
  GET  /ias/v1/scans                  -> list every scan visible to the API
      key (paginated via ``index`` / ``size``) when no scan_config filter
      is supplied.
  POST /ias/v1/vulnerabilities/search -> per-scan vulnerabilities (search
      query ``vulnerability.scan.id='<scan_id>'``, paginated). Each entry
      carries severity, status (UNREVIEWED / VERIFIED / FALSE_POSITIVE /
      REMEDIATED / IGNORED), the offending URL + HTTP method + parameter,
      attack vectors, the original / attack exchanges and a vulnerability
      score.

Auth: ``X-Api-Key: <INSIGHTAPPSEC_API_KEY>`` (Rapid7 platform API key —
generated under User Preferences → API Keys → Organization or User key).

The platform is region-partitioned. INSIGHTAPPSEC_REGION picks the regional
base URL:
  us  -> https://us.api.insight.rapid7.com   (default)
  us2 -> https://us2.api.insight.rapid7.com
  us3 -> https://us3.api.insight.rapid7.com
  eu  -> https://eu.api.insight.rapid7.com
  ca  -> https://ca.api.insight.rapid7.com
  au  -> https://au.api.insight.rapid7.com
  ap  -> https://ap.api.insight.rapid7.com
  jp  -> https://jp.api.insight.rapid7.com
A full base URL (e.g. ``https://us.api.insight.rapid7.com``) is also
accepted verbatim and used unchanged when provided.
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
PAGE_SIZE = 50
MAX_PAGES = 200

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

REGION_HOSTS = {
    "us": "https://us.api.insight.rapid7.com",
    "us2": "https://us2.api.insight.rapid7.com",
    "us3": "https://us3.api.insight.rapid7.com",
    "eu": "https://eu.api.insight.rapid7.com",
    "ca": "https://ca.api.insight.rapid7.com",
    "au": "https://au.api.insight.rapid7.com",
    "ap": "https://ap.api.insight.rapid7.com",
    "jp": "https://jp.api.insight.rapid7.com",
}
DEFAULT_REGION = "us"

# InsightAppSec exposes findings with a fixed severity enum. Critical is
# included to be forward-compatible with future builds and tolerant of
# string variations surfaced by integrations.
IAS_STRING_SEVERITY = {
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
}

# InsightAppSec lifecycle states. FALSE_POSITIVE / IGNORED map to Faraday
# risk-accepted (analyst declared the finding non-exploitable or accepted
# the risk). REMEDIATED / FIXED close the finding. UNREVIEWED / VERIFIED /
# VULNERABLE stay open.
STATUS_TO_FARADAY = {
    "unreviewed": "open",
    "verified": "open",
    "vulnerable": "open",
    "open": "open",
    "active": "open",
    "false_positive": "risk-accepted",
    "false positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "ignored": "risk-accepted",
    "accepted_risk": "risk-accepted",
    "accepted risk": "risk-accepted",
    "acceptedrisk": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "remediated": "closed",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
}


def log(msg):
    print(f"{datetime.utcnow()} - InsightAppSec: {msg}", file=sys.stderr, flush=True)


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


def severity_from_ias(value, cvss=None):
    """Map InsightAppSec's severity field to a Faraday severity bucket.

    Accepts the string enum (HIGH / MEDIUM / LOW / INFORMATIONAL / SAFE)
    or a numeric vulnerability_score (used as a CVSS-like 0-10 score).
    Falls back to CVSS bucketing on the provided ``cvss`` argument when
    the primary value is missing.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in IAS_STRING_SEVERITY:
            return IAS_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_ias(vuln):
    """Derive Faraday status from InsightAppSec's status / disposition.

    InsightAppSec stores the analyst disposition in ``status``; some
    endpoints also expose ``vulnerability.status``. Tolerant of legacy
    boolean flags ``isFalsePositive`` / ``isFixed`` from older builds.
    """
    for key in ("status", "vulnerabilityStatus", "vulnerability_status", "state"):
        raw = vuln.get(key)
        if not raw:
            continue
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value") or raw.get("status")
        if not raw:
            continue
        text = str(raw).strip().lower()
        if text in STATUS_TO_FARADAY:
            return STATUS_TO_FARADAY[text]
    if vuln.get("isFalsePositive") or vuln.get("false_positive") or vuln.get("falsePositive"):
        return "risk-accepted"
    if vuln.get("isIgnored") or vuln.get("ignored"):
        return "risk-accepted"
    if vuln.get("isFixed") or vuln.get("fixed") or vuln.get("remediated"):
        return "closed"
    return "open"


def normalize_base_url(value):
    """Translate INSIGHTAPPSEC_REGION into the regional API base URL.

    Accepts a short region code (us / us2 / us3 / eu / ca / au / ap / jp)
    or a fully-qualified base URL (``https://us.api.insight.rapid7.com``,
    ``https://eu.api.insight.rapid7.com``). Defaults to the US region.
    """
    if value is None or str(value).strip() == "":
        return REGION_HOSTS[DEFAULT_REGION]
    text = str(value).strip()
    if text.startswith(("http://", "https://")):
        return text.rstrip("/")
    key = text.lower()
    if key in REGION_HOSTS:
        return REGION_HOSTS[key]
    log(f"INSIGHTAPPSEC_REGION '{value}' not recognised; defaulting to '{DEFAULT_REGION}'")
    return REGION_HOSTS[DEFAULT_REGION]


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
        log("Authentication rejected (401). INSIGHTAPPSEC_API_KEY invalid.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"Authorization rejected (403) on {path}. Check the API key's organization scope.")
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
    """Pluck a list out of a Rapid7 Insight REST response.

    Insight platform responses wrap list data in ``{"data": [...],
    "metadata": {...}, "links": [...]}``. Some endpoints surface
    ``items`` or ``results`` instead; fall back to a bare list.
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
        for candidate in ("data", "items", "results", "elements"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def metadata_total(body):
    if not isinstance(body, dict):
        return None
    metadata = body.get("metadata")
    if not isinstance(metadata, dict):
        return None
    return (
        metadata.get("total_data")
        or metadata.get("totalData")
        or metadata.get("total")
        or metadata.get("total_count")
        or metadata.get("totalCount")
    )


def paginate(method, base_url, path, headers, payload=None, list_keys=()):
    """Walk Insight platform paginated list endpoints via ``index`` + ``size``."""
    results = []
    index = 0
    for _ in range(MAX_PAGES):
        params = {"index": index, "size": PAGE_SIZE}
        body = request_json(method, base_url, path, headers, params=params, payload=payload)
        chunk = extract_list(body, *list_keys)
        if not chunk:
            break
        results.extend(chunk)
        total = metadata_total(body)
        if isinstance(total, int) and len(results) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
        index += 1
    return results


def get_scans(base_url, headers, scan_config_id):
    """Resolve the list of scans to import.

    When ``scan_config_id`` is set, scope to scans for that scan config
    via ``POST /ias/v1/scans/search``; otherwise enumerate every scan
    visible to the API key via ``GET /ias/v1/scans``.
    """
    if scan_config_id:
        payload = {
            "type": "SCAN",
            "query": f"scan.scan_config.id='{scan_config_id}' && scan.status='COMPLETE'",
        }
        scans = paginate("POST", base_url, "/ias/v1/scans/search", headers, payload=payload)
        if scans:
            return scans
        # Fallback: drop the COMPLETE filter (older deployments use different
        # status casing or surface in-progress scans only).
        payload = {"type": "SCAN", "query": f"scan.scan_config.id='{scan_config_id}'"}
        return paginate("POST", base_url, "/ias/v1/scans/search", headers, payload=payload)
    return paginate("GET", base_url, "/ias/v1/scans", headers)


def get_vulnerabilities(base_url, headers, scan_id):
    payload = {
        "type": "VULNERABILITY",
        "query": f"vulnerability.scan.id='{scan_id}'",
    }
    return paginate(
        "POST",
        base_url,
        "/ias/v1/vulnerabilities/search",
        headers,
        payload=payload,
    )


def cvss_score(vuln):
    """Pull a numeric vulnerability score out of an InsightAppSec finding.

    InsightAppSec exposes a 0-10 ``vulnerability_score`` as the closest
    analogue to a CVSS base score. Also accepts ``score`` / ``cvss`` /
    ``cvss3`` shapes for compatibility with adjacent Rapid7 importers.
    """
    for key in (
        "vulnerability_score",
        "vulnerabilityScore",
        "score",
        "cvss_score",
        "cvssScore",
    ):
        value = vuln.get(key)
        if value is None or isinstance(value, dict):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    for key in ("cvss", "cvss3", "cvssV3"):
        value = vuln.get(key)
        if isinstance(value, dict):
            score = value.get("baseScore") or value.get("base_score") or value.get("score")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
        elif isinstance(value, (int, float)):
            return float(value)
    return None


def root_cause(vuln):
    """Return ``vuln.root_cause`` as a dict (older builds use ``rootCause``)."""
    for key in ("root_cause", "rootCause"):
        value = vuln.get(key)
        if isinstance(value, dict):
            return value
    return {}


def first_variance(vuln):
    """Return the first variance entry (carries module name + attack)."""
    variances = vuln.get("variances")
    if isinstance(variances, list) and variances:
        first = variances[0]
        if isinstance(first, dict):
            return first
    return {}


def collect_refs(vuln, variance):
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

    module = variance.get("module") if isinstance(variance, dict) else None
    if isinstance(module, dict):
        module_id = module.get("id") or module.get("module_id") or module.get("moduleId")
        if module_id:
            add(f"InsightAppSecModule-{module_id}")
        module_name = module.get("name") or module.get("display_name") or module.get("displayName")
        if module_name:
            add(f"InsightAppSecCheck-{module_name}")
    elif isinstance(module, str):
        add(f"InsightAppSecCheck-{module}")

    attack = variance.get("attack") if isinstance(variance, dict) else None
    if isinstance(attack, dict):
        attack_id = attack.get("id") or attack.get("type")
        if attack_id:
            add(f"InsightAppSecAttack-{attack_id}")

    cwe_sources = (
        vuln.get("cwe"),
        vuln.get("cweId"),
        vuln.get("cwe_id"),
        vuln.get("cweIds"),
        vuln.get("cwes"),
    )
    for cwe_val in cwe_sources:
        if not cwe_val:
            continue
        if isinstance(cwe_val, (list, tuple)):
            for entry in cwe_val:
                if isinstance(entry, dict):
                    val = entry.get("id") or entry.get("name") or entry.get("value")
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

    for owasp_val in (vuln.get("owasp"), vuln.get("owaspCategory")):
        if not owasp_val:
            continue
        if isinstance(owasp_val, (list, tuple)):
            for entry in owasp_val:
                if entry:
                    add(f"OWASP: {entry}")
        else:
            add(f"OWASP: {owasp_val}")

    for entry in vuln.get("references") or vuln.get("links") or []:
        if isinstance(entry, str):
            add(entry)
        elif isinstance(entry, dict):
            value = entry.get("url") or entry.get("href") or entry.get("rel") or entry.get("name")
            add(value)
    return refs


def collect_cves(vuln):
    cves = []
    seen = set()
    candidates = []
    for key in ("cve", "cveId", "cveName", "cve_id"):
        value = vuln.get(key)
        if value:
            if isinstance(value, (list, tuple)):
                candidates.extend(value)
            else:
                candidates.append(value)
    for key in ("cves", "CVEs"):
        value = vuln.get(key)
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


def build_vulnerability(vuln):
    score = cvss_score(vuln)
    severity = severity_from_ias(vuln.get("severity"), score)
    status = status_from_ias(vuln)
    rc = root_cause(vuln)
    variance = first_variance(vuln)
    module = variance.get("module") if isinstance(variance, dict) else None
    if isinstance(module, dict):
        check_name = module.get("name") or module.get("display_name") or module.get("displayName")
    elif isinstance(module, str):
        check_name = module
    else:
        check_name = None
    if not check_name:
        check_name = (
            vuln.get("name")
            or vuln.get("title")
            or vuln.get("vulnerabilityName")
            or f"InsightAppSec finding {vuln.get('id') or ''}"
        )
    name = f"[DAST] {check_name}"

    desc_parts = []
    description = (
        vuln.get("description")
        or vuln.get("summary")
        or (variance.get("message") if isinstance(variance, dict) else None)
        or (variance.get("description") if isinstance(variance, dict) else None)
    )
    if description:
        desc_parts.append(str(description))

    url = rc.get("url") or vuln.get("url") or vuln.get("targetUrl")
    method = rc.get("method") or vuln.get("method") or vuln.get("httpMethod")
    if url:
        if method:
            desc_parts.append(f"request: {method} {url}")
        else:
            desc_parts.append(f"url: {url}")
    elif method:
        desc_parts.append(f"method: {method}")

    parameter = rc.get("parameter") or vuln.get("parameter") or vuln.get("parameterName")
    if parameter:
        param_type = rc.get("parameter_type") or rc.get("parameterType") or vuln.get("parameterType")
        if param_type:
            desc_parts.append(f"parameter: {parameter} ({param_type})")
        else:
            desc_parts.append(f"parameter: {parameter}")

    attack_value = None
    if isinstance(variance, dict):
        attack_value = variance.get("attack_value") or variance.get("attackValue")
        if not attack_value:
            attack = variance.get("attack")
            if isinstance(attack, dict):
                attack_value = (
                    attack.get("value")
                    or attack.get("payload")
                    or attack.get("attack_string")
                    or attack.get("attackString")
                )
            elif isinstance(attack, str):
                attack_value = attack
    if not attack_value:
        attack_value = vuln.get("attack") or vuln.get("payload")
    if attack_value:
        desc_parts.append(f"attack: {attack_value}")

    original_value = variance.get("original_value") if isinstance(variance, dict) else None
    if original_value:
        desc_parts.append(f"original_value: {original_value}")

    if score is not None:
        desc_parts.append(f"vulnerability_score: {score}")

    status_raw = vuln.get("status") or vuln.get("vulnerabilityStatus") or vuln.get("vulnerability_status")
    if status_raw:
        desc_parts.append(f"status: {status_raw}")

    first_seen = vuln.get("first_discovered") or vuln.get("firstDiscovered")
    if first_seen:
        desc_parts.append(f"first_discovered: {first_seen}")
    last_seen = vuln.get("last_discovered") or vuln.get("lastDiscovered")
    if last_seen:
        desc_parts.append(f"last_discovered: {last_seen}")

    insight_id = vuln.get("insight_id") or vuln.get("insightId") or vuln.get("vulnerability_uid")
    if insight_id:
        desc_parts.append(f"insight_id: {insight_id}")

    # Pull request / response evidence from the variance's exchanges.
    request_data = ""
    evidence_text = ""
    if isinstance(variance, dict):
        exchanges = variance.get("original_exchange") or variance.get("originalExchange")
        if isinstance(exchanges, list) and exchanges:
            exchange = exchanges[0]
        else:
            exchange = exchanges if isinstance(exchanges, dict) else None
        if isinstance(exchange, dict):
            request_data = exchange.get("request") or ""
            evidence_text = exchange.get("response") or exchange.get("response_chunk") or ""
        attack_exchanges = variance.get("attack_exchanges") or variance.get("attackExchanges")
        if not evidence_text and isinstance(attack_exchanges, list) and attack_exchanges:
            ax = attack_exchanges[0]
            if isinstance(ax, dict):
                if not request_data:
                    request_data = ax.get("request") or ""
                evidence_text = ax.get("response") or ax.get("response_chunk") or ""
    if evidence_text and not isinstance(evidence_text, (dict, list)):
        text = str(evidence_text)
        desc_parts.append(f"evidence: {text[:500]}{'...' if len(text) > 500 else ''}")

    resolution = vuln.get("remediation") or vuln.get("recommendation") or vuln.get("solution") or vuln.get("fix") or ""

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score

    external_id = vuln.get("id") or vuln.get("vulnerability_id") or vuln.get("vulnerabilityId") or ""

    return {
        "name": str(name).strip()[:200] or f"InsightAppSec finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id),
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": str(request_data) if request_data else "",
        "refs": collect_refs(vuln, variance),
        "cve": collect_cves(vuln),
        "cvss3": cvss3,
        "tags": ["rapid7_insightappsec", "dast"],
    }


def target_key(vuln, fallback_url):
    """Stable per-target key used to group vulnerabilities into hosts.

    Each InsightAppSec finding carries the offending request URL in
    ``root_cause.url``; collapse on hostname so all findings against the
    same origin land on the same Faraday host. Findings without a URL
    fall back to the scan's app / target URL.
    """
    rc = root_cause(vuln)
    url = rc.get("url") or vuln.get("url") or vuln.get("targetUrl")
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
    scan_config_id = scan_meta.get("scan_config_id") if scan_meta else None
    if scan_config_id:
        desc_parts.append(f"scan_config_id={scan_config_id}")
    scan_config_name = scan_meta.get("scan_config_name") if scan_meta else None
    if scan_config_name:
        desc_parts.append(f"scan_config={scan_config_name}")
    app_name = scan_meta.get("app_name") if scan_meta else None
    if app_name:
        desc_parts.append(f"app={app_name}")
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
    desc_parts = ["InsightAppSec findings without a resolvable URL"]
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
    scan_config = scan.get("scan_config") or scan.get("scanConfig") or {}
    if not isinstance(scan_config, dict):
        scan_config = {}
    app = scan.get("app") or {}
    if not isinstance(app, dict):
        app = {}
    return {
        "scan_id": scan.get("id") or scan.get("scan_id") or scan.get("scanId"),
        "scan_config_id": scan_config.get("id") or scan.get("scan_config_id"),
        "scan_config_name": scan_config.get("name"),
        "app_id": app.get("id"),
        "app_name": app.get("name"),
        "start_url": (
            scan.get("target_url")
            or scan.get("targetUrl")
            or scan_config.get("url")
            or scan_config.get("target_url")
            or scan_config.get("targetUrl")
        ),
    }


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"INSIGHTAPPSEC_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def main():
    started = time.time()
    api_key = env("INSIGHTAPPSEC_API_KEY", required=True)
    region_arg = env("EXECUTOR_CONFIG_INSIGHTAPPSEC_REGION")
    scan_config_id = env("EXECUTOR_CONFIG_INSIGHTAPPSEC_SCAN_CONFIG_ID")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_INSIGHTAPPSEC_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(region_arg)
    headers = {
        "X-Api-Key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    scans = get_scans(base_url, headers, scan_config_id)
    log(
        f"Processing {len(scans)} scan(s) "
        f"(scan_config_id={scan_config_id or 'all'}, region={region_arg or DEFAULT_REGION}, "
        f"min_severity={min_severity})"
    )

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
                rc = root_cause(raw)
                bucket["sample_url"] = rc.get("url") or raw.get("url") or raw.get("targetUrl") or meta.get("start_url")
            bucket["vulns"].append(built)
        for key, bucket in by_target.items():
            hosts.append(build_host(key, bucket["sample_url"], bucket["vulns"], meta))
        if orphan:
            hosts.append(synthetic_host(orphan, meta))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "rapid7_insightappsec",
            "command": "rapid7_insightappsec",
            "params": (
                f"scan_config_id={scan_config_id or 'all'},"
                f"region={region_arg or DEFAULT_REGION},"
                f"min_severity={min_severity}"
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
