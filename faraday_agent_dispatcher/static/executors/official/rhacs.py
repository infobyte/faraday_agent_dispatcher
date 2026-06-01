#!/usr/bin/env python
"""Red Hat Advanced Cluster Security (RHACS / StackRox) REST importer.

Pulls Kubernetes-workload policy violations and container-image
vulnerability findings from a Red Hat Advanced Cluster Security
(formerly StackRox) Central console via the canonical
``GET /v1/alerts`` (policy violations) and ``GET /v1/images``
(per-image scan results) endpoints and emits Faraday bulk-create JSON
to stdout. Each RHACS deployment bucket (alerts grouped by
``deployment.clusterName/namespace/name``) becomes one Faraday host
(synthetic ``0.0.0.0`` ip — Kubernetes workloads do not surface a
single stable ip on the alert payload, the pivot lives in the
cluster/namespace/deployment tuple); each RHACS image bucket
(``image.id`` / ``image.name.fullName``) becomes one Faraday host
(synthetic ``0.0.0.0`` ip because image scans live on container layers
rather than IPs). Per-bucket findings are attached as Faraday
vulnerabilities — one per RHACS alert (`alert.id`) or one per
image-scan CVE+component (`{cve}@{component}@{image.fullName}`) — with
engine prefix ``[CNAPP]``.

Endpoints used:
  GET {RHACS_HOST}/v1/alerts
      -> primary policy-violation listing. Paginated via
      ``pagination.limit`` + ``pagination.offset`` cursor. Filters via
      the RHACS search query syntax (``query=Cluster:<name>+Namespace:
      <ns>+Severity:HIGH_SEVERITY,CRITICAL_SEVERITY``). Returns
      ``{"alerts": [...]}`` (each entry is a ListAlert summary).
  GET {RHACS_HOST}/v1/alerts/{id}
      -> per-alert detail. The list endpoint returns summary objects
      without violation messages or full policy descriptions; the
      detail endpoint surfaces the full Alert envelope (policy,
      deployment, violations, processViolation, lifecycleStage, time).
      Tolerant to 404 / missing.
  GET {RHACS_HOST}/v1/images
      -> image listing. Same pagination + query syntax as /v1/alerts.
      Returns ``{"images": [...]}`` (each entry is a ListImage summary
      without the full scan payload).
  GET {RHACS_HOST}/v1/images/{id}
      -> per-image detail with the full ``scan.components[].vulns[]``
      tree (per-package CVE list, fixedBy, cvss / cvss_v3 surfaces,
      vulnerability state).

Auth: RHACS Central issues long-lived API tokens via the
``Integrations -> Authentication Tokens`` page (or
``POST /v1/apitokens/generate``). The token is sent as
``Authorization: Bearer <RHACS_TOKEN>`` on every call — there is no
separate login exchange. ``RHACS_HOST`` is the Central console URL
(``https://central.<cluster>.example.com`` for the canonical OpenShift
route, or the ``central-<namespace>.apps.<cluster>`` Route created by
the Operator).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200

VALID_MIN_SEVERITY = (
    "LOW_SEVERITY",
    "MEDIUM_SEVERITY",
    "HIGH_SEVERITY",
    "CRITICAL_SEVERITY",
)
# RHACS-native enum order. UNSET_SEVERITY is treated as "info" in
# Faraday but the user-facing floor only exposes LOW/MEDIUM/HIGH/CRITICAL
# (the RHACS UI does the same).
RHACS_SEVERITY_ORDER = {
    "UNSET_SEVERITY": 0,
    "LOW_SEVERITY": 1,
    "MEDIUM_SEVERITY": 2,
    "HIGH_SEVERITY": 3,
    "CRITICAL_SEVERITY": 4,
}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# RHACS / StackRox severity enum: UNSET_SEVERITY / LOW_SEVERITY /
# MEDIUM_SEVERITY / HIGH_SEVERITY / CRITICAL_SEVERITY. Image-scan
# vulnerabilities pulled from upstream feeds (NVD / Red Hat advisories
# / OSV) may surface the more familiar "critical" / "high" / "medium"
# / "low" / "important" / "moderate" / "negligible" tokens; tolerate
# them too.
RHACS_STRING_SEVERITY = {
    "critical_severity": "critical",
    "high_severity": "high",
    "medium_severity": "medium",
    "low_severity": "low",
    "unset_severity": "info",
    "critical": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "negligible": "info",
    "unimportant": "info",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "unknown": "info",
}

# RHACS Alert.state: ACTIVE / SNOOZED / RESOLVED / ATTEMPTED.
# RHACS image vulnerability state: OBSERVED / DEFERRED /
# FALSE_POSITIVE (and "RESOLVED" when fixedBy has been applied and the
# scanner re-runs).
RHACS_STATUS_TO_FARADAY = {
    "active": "open",
    "attempted": "open",
    "observed": "open",
    "open": "open",
    "new": "open",
    "resolved": "closed",
    "closed": "closed",
    "fixed": "closed",
    "mitigated": "closed",
    "remediated": "closed",
    "snoozed": "risk-accepted",
    "deferred": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "false-positive": "risk-accepted",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "dismissed": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "acknowledged": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - RHACS: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Prefix a bare hostname with https:// and strip trailing slashes."""
    if not host:
        return ""
    text = str(host).strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    return text.rstrip("/")


def validate_min_severity(value):
    """Coerce RHACS_MIN_SEVERITY to a canonical RHACS enum token.

    Tolerates the bare ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``
    shorthand by suffixing ``_SEVERITY`` and case-folding to the
    canonical enum. Defaults to ``LOW_SEVERITY`` (i.e. no floor —
    UNSET findings are still surfaced separately).
    """
    if value is None or value == "":
        return "LOW_SEVERITY"
    text = str(value).strip().upper()
    if text in VALID_MIN_SEVERITY:
        return text
    if f"{text}_SEVERITY" in VALID_MIN_SEVERITY:
        return f"{text}_SEVERITY"
    log(f"RHACS_MIN_SEVERITY '{value}' not recognised; defaulting to LOW_SEVERITY")
    return "LOW_SEVERITY"


def severities_at_or_above(min_severity):
    """Return the RHACS severity tokens at or above ``min_severity``.

    Used to build the ``Severity:`` search-query filter sent to
    ``/v1/alerts``. RHACS expects a comma-separated list of enum
    values (``HIGH_SEVERITY,CRITICAL_SEVERITY``).
    """
    floor = RHACS_SEVERITY_ORDER.get(min_severity, 1)
    out = []
    for sev, order in RHACS_SEVERITY_ORDER.items():
        if sev == "UNSET_SEVERITY":
            continue
        if order >= floor:
            out.append(sev)
    return out


def build_search_query(cluster, namespace, severities):
    """Build a RHACS search-query string from filter fragments.

    RHACS uses a ``Field:value`` syntax with ``+`` separating ANDed
    terms. Multi-valued fields take a CSV. Empty filters are dropped
    so the resulting query stays short.
    """
    parts = []
    if cluster:
        parts.append(f"Cluster:{cluster}")
    if namespace:
        parts.append(f"Namespace:{namespace}")
    if severities:
        parts.append(f"Severity:{','.join(severities)}")
    return "+".join(parts)


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


def severity_from_rhacs(value, cvss=None):
    """Map a RHACS severity to a Faraday bucket.

    Accepts RHACS's enum (``CRITICAL_SEVERITY`` ... ``UNSET_SEVERITY``)
    and the more familiar critical/high/medium/low/negligible tokens
    image-scan vulnerabilities arrive with. Falls back to CVSS
    bucketing on ``cvss`` when the primary value is missing or
    unrecognised. Numeric inputs are interpreted as CVSS base scores.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in RHACS_STRING_SEVERITY:
            return RHACS_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_rhacs(payload):
    """Derive Faraday status from a RHACS alert / image-vuln payload.

    Alerts surface a ``state`` field (ACTIVE / SNOOZED / RESOLVED /
    ATTEMPTED); image-scan vulnerabilities surface a ``state`` of
    OBSERVED / DEFERRED / FALSE_POSITIVE plus an optional ``fixedBy``
    string when upstream has cut a fix (the scanner sets the vuln as
    open until the deployment re-pulls the patched image).
    """
    if not isinstance(payload, dict):
        return "open"
    raw = payload.get("state") or payload.get("status")
    if isinstance(raw, dict):
        raw = raw.get("name") or raw.get("value") or raw.get("status") or raw.get("state")
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in RHACS_STATUS_TO_FARADAY:
            return RHACS_STATUS_TO_FARADAY[text]
        compact = text.replace(" ", "").replace("-", "").replace("_", "")
        if compact in RHACS_STATUS_TO_FARADAY:
            return RHACS_STATUS_TO_FARADAY[compact]
    return "open"


def request(method, url, headers, params=None, json_body=None):
    """Wrap requests with shared error handling."""
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=TIMEOUT,
            verify=False,
        )
    except requests.RequestException as exc:
        log(f"{method} {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log(f"{method} {url} rejected (401). Check RHACS_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"{method} {url} rejected (403). Token lacks required scopes.")
        return None
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        log(f"{method} {url} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"{method} {url} response was not JSON")
        return None


def extract_items(payload, key):
    """Pull the alert / image list out of a RHACS envelope.

    RHACS returns ``{"alerts": [...]}`` for /v1/alerts and
    ``{"images": [...]}`` for /v1/images. Some stacks (especially when
    behind a reverse proxy that re-wraps) return a bare list or wrap
    everything under ``data``; tolerate both shapes.
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    primary = payload.get(key)
    if isinstance(primary, list):
        return [x for x in primary if isinstance(x, dict)]
    for fallback in ("data", "results", "items"):
        items = payload.get(fallback)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def fetch_page(base_url, headers, endpoint, query, offset, page_size):
    """Pull one page from a RHACS listing endpoint."""
    params = {
        "pagination.limit": page_size,
        "pagination.offset": offset,
    }
    if query:
        params["query"] = query
    return request("GET", f"{base_url}{endpoint}", headers, params=params)


def fetch_all(base_url, headers, endpoint, envelope_key, query):
    """Paginate through a RHACS listing endpoint."""
    results = []
    seen_ids = set()
    offset = 0
    for _ in range(MAX_PAGES):
        payload = fetch_page(base_url, headers, endpoint, query, offset, PAGE_SIZE)
        if payload is None:
            break
        chunk = extract_items(payload, envelope_key)
        if not chunk:
            break
        added = 0
        for item in chunk:
            iid = item.get("id") or item.get("_id")
            key = str(iid).strip() if iid else None
            if key and key in seen_ids:
                continue
            if key:
                seen_ids.add(key)
            results.append(item)
            added += 1
        if added == 0:
            break
        offset += len(chunk)
        if len(chunk) < PAGE_SIZE:
            break
    return results


def fetch_alert_detail(base_url, headers, alert_id):
    """Pull a full Alert envelope for one alert id.

    The /v1/alerts listing returns ListAlert summaries (id, time,
    policy.name, deployment.{clusterName, namespace, name}, state,
    enforcementCount). The detail endpoint adds the policy
    description / remediation / categories and the violations[]
    array. Falls back to the summary on 404 / network failure.
    """
    if not alert_id:
        return None
    payload = request("GET", f"{base_url}/v1/alerts/{alert_id}", headers)
    if isinstance(payload, dict) and isinstance(payload.get("alert"), dict):
        return payload["alert"]
    return payload if isinstance(payload, dict) else None


def fetch_image_detail(base_url, headers, image_id):
    """Pull a full Image envelope for one image id.

    The /v1/images listing returns ListImage summaries; the detail
    endpoint adds the ``scan.components[].vulns[]`` tree which
    carries the per-package CVE list with cvss / cvss_v3 / fixedBy /
    state. Falls back to None on 404 / network failure.
    """
    if not image_id:
        return None
    payload = request("GET", f"{base_url}/v1/images/{image_id}", headers)
    if isinstance(payload, dict) and isinstance(payload.get("image"), dict):
        return payload["image"]
    return payload if isinstance(payload, dict) else None


def cvss_score(finding, meta=None):
    """Pull a numeric CVSS / score out of a RHACS payload."""
    candidates = []
    if isinstance(finding, dict):
        candidates.append(finding)
    if isinstance(meta, dict):
        candidates.append(meta)
    for source in candidates:
        for key in ("cvss", "cvssScore", "cvss_score", "score", "baseScore", "base_score"):
            value = source.get(key)
            if value is None or isinstance(value, (dict, list, bool)):
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        for nested_key in ("cvssV3", "cvss_v3", "cvss3", "cvssV2", "cvss_v2"):
            nested = source.get(nested_key)
            if isinstance(nested, dict):
                for k in ("score", "baseScore", "base_score", "overallScore", "overall_score"):
                    score = nested.get(k)
                    if score is None or isinstance(score, (dict, list, bool)):
                        continue
                    try:
                        return float(score)
                    except (TypeError, ValueError):
                        continue
    return None


def cvss_vector(finding, meta=None):
    candidates = []
    if isinstance(finding, dict):
        candidates.append(finding)
    if isinstance(meta, dict):
        candidates.append(meta)
    for source in candidates:
        for key in ("vectorString", "vector_string", "cvssVector", "cvss_vector", "vector"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for nested_key in ("cvssV3", "cvss_v3", "cvss3", "cvssV2", "cvss_v2"):
            nested = source.get(nested_key)
            if isinstance(nested, dict):
                for k in ("vector", "vectorString", "vector_string"):
                    v = nested.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    return ""


def collect_cves(finding, meta=None):
    """Pull CVE-* ids out of a RHACS vuln payload (and optional meta)."""
    found = []
    seen = set()

    def add_token(text):
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
        for match in CVE_RE.findall(text):
            add_token(match)

    def add(text):
        if not isinstance(text, str):
            if text:
                add_token(text)
            return
        if CVE_RE.fullmatch(text.strip().upper()):
            add_token(text)
        else:
            scan(text)

    sources = []
    if isinstance(finding, dict):
        sources.append(finding)
    if isinstance(meta, dict):
        sources.append(meta)

    for source in sources:
        for key in ("cve", "cveId", "cve_id", "CVE"):
            v = source.get(key)
            if isinstance(v, str) and v.strip():
                add_token(v)
        for key in ("cves", "cveIds", "cve_ids", "aliases"):
            v = source.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        add_token(entry)
                    elif isinstance(entry, dict):
                        add_token(entry.get("name") or entry.get("id") or entry.get("cve") or entry.get("cveId"))
        for key in ("summary", "description", "title", "name", "link"):
            v = source.get(key)
            if isinstance(v, str):
                add(v)
    return found


def collect_refs(finding, image=None, meta=None):
    """Walk a RHACS vuln + image + meta payload for CWE / advisory / URL refs."""
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

    sources = []
    if isinstance(finding, dict):
        sources.append(finding)
    if isinstance(meta, dict):
        sources.append(meta)
    if isinstance(image, dict):
        sources.append(image)

    for source in sources:
        cwe_raw = source.get("cwe_id") or source.get("cweId") or source.get("cwe")
        if isinstance(cwe_raw, (int, float)) and not isinstance(cwe_raw, bool):
            add(f"CWE-{int(cwe_raw)}")
        elif isinstance(cwe_raw, str) and cwe_raw.strip():
            s = cwe_raw.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("cwes", "cweIds", "cwe_ids"):
            items = source.get(key)
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, dict):
                        cid = it.get("id") or it.get("value") or it.get("name")
                        if cid is None:
                            continue
                        text = str(cid).strip()
                        add(text if text.upper().startswith("CWE-") else f"CWE-{text}")
                    elif isinstance(it, (int, float)) and not isinstance(it, bool):
                        add(f"CWE-{int(it)}")
                    elif isinstance(it, str) and it.strip():
                        s = it.strip()
                        add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("link", "url", "advisoryUrl", "advisory_url", "vendor_url", "vendorUrl"):
            v = source.get(key)
            if isinstance(v, str) and v.strip():
                add(v.strip())
        for key in ("references", "links", "external_references", "externalReferences"):
            entry = source.get(key)
            if isinstance(entry, list):
                for it in entry:
                    if isinstance(it, dict):
                        href = it.get("href") or it.get("url") or it.get("name") or it.get("value")
                        if href:
                            add(href)
                    elif it:
                        add(str(it))
            elif isinstance(entry, str) and entry.strip():
                add(entry.strip())

    return refs


def image_label(image):
    """Build registry / repo / tag / id / os from a RHACS Image payload."""
    if not isinstance(image, dict):
        return "", "", "", "", ""
    name = image.get("name")
    registry = ""
    repo = ""
    tag = ""
    if isinstance(name, dict):
        registry = name.get("registry") or ""
        repo = name.get("remote") or name.get("repository") or name.get("repo") or ""
        tag = name.get("tag") or ""
        full = name.get("fullName")
        if not (registry or repo or tag) and isinstance(full, str) and full.strip():
            text = full.strip()
            if ":" in text:
                head, tag = text.rsplit(":", 1)
            else:
                head, tag = text, ""
            if "/" in head:
                registry, repo = head.split("/", 1)
            else:
                repo = head
    elif isinstance(name, str) and name.strip():
        text = name.strip()
        if ":" in text:
            head, tag = text.rsplit(":", 1)
        else:
            head, tag = text, ""
        if "/" in head:
            registry, repo = head.split("/", 1)
        else:
            repo = head
    image_id = image.get("id") or image.get("digest") or ""
    metadata = image.get("metadata")
    os_name = ""
    if isinstance(metadata, dict):
        layer = metadata.get("v1")
        if isinstance(layer, dict):
            os_name = layer.get("os") or ""
    scan = image.get("scan")
    if not os_name and isinstance(scan, dict):
        os_name = scan.get("operatingSystem") or scan.get("os") or ""
    return str(registry), str(repo), str(tag), str(image_id), str(os_name)


def deployment_label(payload):
    """Build cluster / namespace / deployment / type fields from an Alert."""
    if not isinstance(payload, dict):
        return "", "", "", ""
    deployment = payload.get("deployment")
    if not isinstance(deployment, dict):
        deployment = {}
    cluster = deployment.get("clusterName") or payload.get("clusterName") or ""
    namespace = deployment.get("namespace") or payload.get("namespace") or ""
    name = deployment.get("name") or deployment.get("deploymentName") or payload.get("name") or ""
    kind = deployment.get("type") or deployment.get("kind") or ""
    return str(cluster), str(namespace), str(name), str(kind)


def deployment_bucket_key(alert):
    """Build a stable bucket key for grouping alerts by deployment."""
    cluster, namespace, name, _ = deployment_label(alert)
    parts = [p for p in (cluster, namespace, name) if p]
    if parts:
        return "/".join(parts)
    deployment = alert.get("deployment") if isinstance(alert, dict) else None
    if isinstance(deployment, dict):
        did = deployment.get("id")
        if isinstance(did, str) and did.strip():
            return did.strip()
    resource = alert.get("resource") if isinstance(alert, dict) else None
    if isinstance(resource, dict):
        rname = resource.get("name")
        if isinstance(rname, str) and rname.strip():
            return rname.strip()
    return "__unknown__"


def image_bucket_key(image):
    """Build a stable bucket key for grouping an image."""
    if not isinstance(image, dict):
        return "__unknown__"
    iid = image.get("id") or image.get("digest")
    if isinstance(iid, str) and iid.strip():
        return iid.strip()
    registry, repo, tag, _, _ = image_label(image)
    if registry and repo and tag:
        return f"{registry}/{repo}:{tag}"
    if registry and repo:
        return f"{registry}/{repo}"
    if repo:
        return str(repo)
    return "__unknown__"


def policy_label(alert):
    """Build a friendly label for the RHACS policy."""
    if not isinstance(alert, dict):
        return ""
    policy = alert.get("policy")
    if isinstance(policy, dict):
        return str(policy.get("name") or policy.get("id") or "").strip()
    return ""


def build_alert_vulnerability(alert):
    """Build a Faraday vulnerability dict from one RHACS Alert.

    Each alert is one policy violation against a deployment / image /
    resource. The Faraday vuln title is ``[CNAPP] {policy} on
    {cluster/namespace/deployment}``; the description carries the
    policy description, the violation messages, the policy categories,
    the lifecycle stage and the alert id; the severity comes from the
    policy.severity enum; the status from alert.state.
    """
    if not isinstance(alert, dict):
        return None

    cluster, namespace, deployment, kind = deployment_label(alert)
    bucket = deployment_bucket_key(alert)
    policy_name = policy_label(alert)
    policy = alert.get("policy") if isinstance(alert.get("policy"), dict) else {}

    severity_raw = policy.get("severity") or alert.get("severity")
    score = cvss_score(alert) or cvss_score(policy)
    severity = severity_from_rhacs(severity_raw, score)
    status = status_from_rhacs(alert)

    parent_label = bucket if bucket != "__unknown__" else ""
    if policy_name and parent_label:
        base_title = f"{policy_name} on {parent_label}"
    elif policy_name:
        base_title = policy_name
    elif parent_label:
        base_title = parent_label
    else:
        base_title = str(alert.get("id") or "RHACS alert")
    name = f"[CNAPP] {base_title}"

    desc_parts = []
    description = policy.get("description") or alert.get("description")
    if isinstance(description, dict):
        desc_parts.append(json.dumps(description, separators=(",", ":")))
    elif description:
        desc_parts.append(str(description))

    if policy_name:
        desc_parts.append(f"policy: {policy_name}")
    policy_id = policy.get("id") or policy.get("policyId")
    if policy_id:
        desc_parts.append(f"policy_id: {policy_id}")
    categories = policy.get("categories")
    if isinstance(categories, list) and categories:
        desc_parts.append("categories: " + ", ".join(str(c) for c in categories if c))
    lifecycle = alert.get("lifecycleStage") or alert.get("lifecycle_stage")
    if lifecycle:
        desc_parts.append(f"lifecycle: {lifecycle}")
    if cluster:
        desc_parts.append(f"cluster: {cluster}")
    if namespace:
        desc_parts.append(f"namespace: {namespace}")
    if deployment:
        desc_parts.append(f"deployment: {deployment}")
    if kind:
        desc_parts.append(f"kind: {kind}")
    state = alert.get("state")
    if state:
        desc_parts.append(f"state: {state}")
    alert_time = alert.get("time") or alert.get("firstOccurred") or alert.get("first_occurred")
    if alert_time:
        desc_parts.append(f"time: {alert_time}")
    enforcement = alert.get("enforcement")
    if isinstance(enforcement, dict):
        action = enforcement.get("action")
        if action:
            desc_parts.append(f"enforcement: {action}")

    violations = alert.get("violations")
    if isinstance(violations, list):
        messages = []
        for v in violations:
            if isinstance(v, dict):
                msg = v.get("message") or v.get("description")
                if isinstance(msg, str) and msg.strip():
                    messages.append(msg.strip())
        if messages:
            desc_parts.append("violations:\n  - " + "\n  - ".join(messages))

    if score is not None:
        desc_parts.append(f"score: {score}")

    resolution = policy.get("remediation") or policy.get("rationale") or alert.get("remediation") or ""
    if isinstance(resolution, dict):
        resolution = (
            resolution.get("text")
            or resolution.get("description")
            or resolution.get("value")
            or json.dumps(resolution, separators=(",", ":"))
        )

    refs = collect_refs(alert, None, policy)
    cves = collect_cves(alert, policy)

    external_id_raw = alert.get("id") or policy.get("id")
    external_id = str(external_id_raw) if external_id_raw else ""

    return {
        "name": str(name).strip()[:200] or f"RHACS alert {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {"base_score": score} if score is not None else {},
        "tags": ["rhacs", "stackrox", "kubernetes", "container-security"],
    }


def build_image_vulnerability(finding, component, image, parent_label):
    """Build a Faraday vuln from one RHACS image-scan vulnerability."""
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding)
    severity_raw = finding.get("severity")
    severity = severity_from_rhacs(severity_raw, score)
    status = status_from_rhacs(finding)

    cve = finding.get("cve") or finding.get("CVE") or ""
    component_name = ""
    component_version = ""
    if isinstance(component, dict):
        component_name = str(component.get("name") or "")
        component_version = str(component.get("version") or "")

    if component_name and component_version:
        package = f"{component_name}@{component_version}"
    else:
        package = component_name or ""

    if cve and package:
        base_title = f"{cve} in {package}"
    elif cve:
        base_title = str(cve)
    elif package:
        base_title = package
    else:
        base_title = str(finding.get("summary") or finding.get("description") or "RHACS image finding")

    if parent_label:
        raw_name = f"{base_title} on {parent_label}"
    else:
        raw_name = base_title
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = finding.get("summary") or finding.get("description")
    if isinstance(description, dict):
        desc_parts.append(json.dumps(description, separators=(",", ":")))
    elif description:
        desc_parts.append(str(description))

    if cve:
        desc_parts.append(f"vuln_id: {cve}")
    if package:
        desc_parts.append(f"package: {package}")
    if parent_label:
        desc_parts.append(f"image: {parent_label}")

    for label, keys in (
        ("severity", ("severity",)),
        ("state", ("state",)),
        ("fixed_by", ("fixedBy", "fixed_by")),
        ("published", ("publishedOn", "published_on", "publishedDate", "publishedTime")),
        ("last_modified", ("lastModified", "last_modified")),
        ("scanner_version", ("scoreVersion", "score_version")),
    ):
        for k in keys:
            v = finding.get(k)
            if v not in (None, ""):
                desc_parts.append(f"{label}: {v}")
                break

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(finding)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(finding)
    refs = collect_refs(finding, image)

    resolution = (
        finding.get("fixedBy")
        or finding.get("fixed_by")
        or finding.get("remediation")
        or finding.get("solution")
        or ""
    )
    if resolution and component_name and not str(resolution).lower().startswith("upgrade"):
        resolution = f"Upgrade {component_name} to {resolution}."

    external_id_raw = finding.get("cve") or finding.get("CVE")
    if external_id_raw and component_name and parent_label:
        external_id = f"{external_id_raw}@{component_name}@{parent_label}"
    elif external_id_raw and component_name:
        external_id = f"{external_id_raw}@{component_name}"
    elif external_id_raw:
        external_id = str(external_id_raw)
    else:
        external_id = str(cves[0] if cves else "")

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"RHACS image finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": str(resolution) if resolution else "",
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["rhacs", "stackrox", "kubernetes", "container-security"],
    }


def build_deployment_host(bucket_key, alert, vulns):
    """Build a Faraday host shell from a RHACS deployment bucket."""
    cluster, namespace, deployment, kind = deployment_label(alert)
    desc_parts = ["scope=deployment"]
    if cluster:
        desc_parts.append(f"cluster={cluster}")
    if namespace:
        desc_parts.append(f"namespace={namespace}")
    if deployment:
        desc_parts.append(f"deployment={deployment}")
    if kind:
        desc_parts.append(f"kind={kind}")
    if vulns:
        desc_parts.append(f"alerts={len(vulns)}")
    hostname = bucket_key if bucket_key and bucket_key != "__unknown__" else ""
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def build_image_host(bucket_key, image, vulns):
    """Build a Faraday host shell from a RHACS image bucket."""
    registry, repo, tag, image_id, os_name = image_label(image)
    label = ""
    if registry and repo:
        label = f"{registry}/{repo}"
    elif repo:
        label = str(repo)
    elif registry:
        label = str(registry)
    if tag and label:
        label = f"{label}:{tag}"
    if label and image_id and image_id != bucket_key:
        hostname = f"{label}@{image_id}"
    elif label and bucket_key and bucket_key != label:
        hostname = f"{label}@{bucket_key}"
    elif label:
        hostname = label
    else:
        hostname = image_id or bucket_key or ""
    desc_parts = ["scope=image"]
    if image_id:
        desc_parts.append(f"image_id={image_id}")
    if registry:
        desc_parts.append(f"registry={registry}")
    if repo:
        desc_parts.append(f"repository={repo}")
    if tag:
        desc_parts.append(f"tag={tag}")
    if os_name:
        desc_parts.append(f"os={os_name}")
    if vulns:
        desc_parts.append(f"findings={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": str(os_name) if os_name else "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def emit_alert_buckets(alerts, floor):
    """Group RHACS alerts by deployment bucket and emit Faraday hosts."""
    buckets = {}
    order = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        built = build_alert_vulnerability(alert)
        if built is None:
            continue
        if SEVERITY_ORDER[built["severity"]] < floor:
            continue
        key = deployment_bucket_key(alert)
        if key not in buckets:
            buckets[key] = {"alert": alert, "vulns": []}
            order.append(key)
        buckets[key]["vulns"].append(built)

    hosts_out = []
    for key in order:
        entry = buckets[key]
        if not entry["vulns"]:
            continue
        hosts_out.append(build_deployment_host(key, entry["alert"], entry["vulns"]))
    return hosts_out


def emit_image_bucket(image, floor):
    """Build a Faraday host (+ vulns) from one RHACS Image record."""
    scan = image.get("scan") if isinstance(image, dict) else None
    if not isinstance(scan, dict):
        return None
    components = scan.get("components")
    if not isinstance(components, list):
        return None

    registry, repo, tag, image_id, _ = image_label(image)
    if registry and repo:
        parent_label = f"{registry}/{repo}"
    elif repo:
        parent_label = repo
    elif image_id:
        parent_label = image_id
    else:
        parent_label = ""
    if tag and parent_label:
        parent_label = f"{parent_label}:{tag}"

    vulns = []
    for component in components:
        if not isinstance(component, dict):
            continue
        comp_vulns = component.get("vulns") or component.get("vulnerabilities")
        if not isinstance(comp_vulns, list):
            continue
        for finding in comp_vulns:
            if not isinstance(finding, dict):
                continue
            built = build_image_vulnerability(finding, component, image, parent_label)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
    if not vulns:
        return None
    return build_image_host(image_bucket_key(image), image, vulns)


def main():
    started = time.time()
    rhacs_host = env("RHACS_HOST", required=True)
    token = env("RHACS_TOKEN", required=True)
    cluster = env("EXECUTOR_CONFIG_RHACS_CLUSTER")
    namespace = env("EXECUTOR_CONFIG_RHACS_NAMESPACE")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_RHACS_MIN_SEVERITY"))
    faraday_floor = {
        "LOW_SEVERITY": SEVERITY_ORDER["low"],
        "MEDIUM_SEVERITY": SEVERITY_ORDER["medium"],
        "HIGH_SEVERITY": SEVERITY_ORDER["high"],
        "CRITICAL_SEVERITY": SEVERITY_ORDER["critical"],
    }.get(min_severity, SEVERITY_ORDER["low"])

    base_url = normalize_base_url(rhacs_host)
    if not base_url:
        log("RHACS_HOST is required")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    severities = severities_at_or_above(min_severity)
    query = build_search_query(cluster, namespace, severities)

    hosts_out = []

    alerts = fetch_all(base_url, headers, "/v1/alerts", "alerts", query)
    log(
        f"Processing {len(alerts)} RHACS alerts (cluster={cluster or '*'}, "
        f"namespace={namespace or '*'}, min_severity={min_severity})"
    )
    full_alerts = []
    for alert in alerts:
        alert_id = alert.get("id") or alert.get("_id")
        detail = fetch_alert_detail(base_url, headers, alert_id) if alert_id else None
        full_alerts.append(detail or alert)
    hosts_out.extend(emit_alert_buckets(full_alerts, faraday_floor))

    # The image-scan vulnerability listing does not accept Severity:
    # filter (severity lives on each per-CVE entry, not on the image),
    # so we drop it from the search and floor client-side.
    image_query = build_search_query(cluster, namespace, [])
    images = fetch_all(base_url, headers, "/v1/images", "images", image_query)
    log(
        f"Processing {len(images)} RHACS images (cluster={cluster or '*'}, "
        f"namespace={namespace or '*'}, min_severity={min_severity})"
    )
    for image_summary in images:
        image_id = image_summary.get("id") or image_summary.get("_id")
        full_image = fetch_image_detail(base_url, headers, image_id) if image_id else None
        host_obj = emit_image_bucket(full_image or image_summary, faraday_floor)
        if host_obj is not None:
            hosts_out.append(host_obj)

    params = f"cluster={cluster or ''},namespace={namespace or ''},min_severity={min_severity}"

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "rhacs",
            "command": "rhacs",
            "params": params,
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
