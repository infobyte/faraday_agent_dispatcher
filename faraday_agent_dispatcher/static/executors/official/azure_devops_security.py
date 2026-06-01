#!/usr/bin/env python
"""Azure DevOps Advanced Security REST API importer (fan-out).

Pulls Advanced Security alerts from one or more of ADO's three alert
families (code-scanning / secret / dependency) against a single
repository and emits Faraday bulk-create JSON to stdout. Set
``ADO_ALERT_TYPE`` (CSV of ``code|secret|dependency``) to pick a
subset; omit it to fan out to all three under a single PAT.

Each ADO repository becomes one Faraday host (``ip`` = synthetic
``0.0.0.0`` because Advanced Security findings live in source repos,
build pipelines and pull-request diffs — not on IPs) with hostnames =
``{project}/{repo}``; each alert becomes one Faraday vulnerability
with an engine prefix matching the alert source (``[CODE]`` /
``[SECRETS]`` / ``[SCA]``).

Endpoints used:
  GET {base}/{org}/{project}/_apis/Alert/repositories/{repo}/Alerts
      ?api-version=7.2-preview.1
      &criteria.alertType={code|secret|dependency}
      &criteria.states=active
      &$top=100
      -> Advanced Security alerts for the repository, scoped by
      ``alertType``. ``criteria.states`` defaults to ``active`` so we
      pull open work — operators who want a full historical snapshot
      can set ``ADO_INCLUDE_CLOSED`` to also walk fixed / dismissed /
      autoDismissed states.

The Advanced Security surface is served from the ``advsec.dev.azure.com``
subdomain (the canonical Microsoft REST host for ADO Advanced Security
since the 7.2-preview API ships); the legacy ``dev.azure.com`` host is
NOT served. ``ADO_HOST`` defaults to ``https://advsec.dev.azure.com``
and can be overridden for a self-hosted Azure DevOps Server install or
for organisations whose advsec endpoint lives on a different host.

Auth: HTTP Basic with an empty username + ``ADO_PAT`` as the password
— ``Authorization: Basic base64(":<PAT>")``. This is the canonical
Azure DevOps REST auth pattern (PATs are sent as the password with an
empty username; Microsoft Entra OAuth tokens are sent as
``Authorization: Bearer <token>`` and a pre-built ``Bearer ...`` value
in ``ADO_PAT`` is forwarded verbatim). The PAT needs ``Advanced
Security: Read`` (vso.advsec) scope and ``Code: Read`` (vso.code) for
the repository metadata pull.

Pagination follows ADO REST's canonical ``x-ms-continuationtoken``
header — when present the executor follows the token via a
``continuationToken`` query-string param; otherwise it stops when a
short page is returned. Bounded at ``MAX_PAGES`` pages of
``PAGE_SIZE`` rows each (= 20k rows / alert type / repo).
"""

import base64
import json
import os
import re
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
DEFAULT_HOST = "https://advsec.dev.azure.com"
DEFAULT_API_VERSION = "7.2-preview.1"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

VALID_ALERT_TYPES = ("code", "secret", "dependency")

# ADO Advanced Security severity enum (per the canonical REST docs):
#   critical / high / medium / low / note
# Some federated tooling also surfaces error / warning / info / none /
# moderate / informational — we accept those so older / vendor-shaped
# report producers still import.
ADO_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "note": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unknown": "info",
    "error": "high",
    "warning": "medium",
}

# ADO Advanced Security alert state enum:
#   active        -> open work
#   dismissed     -> analyst-triaged + accepted
#   fixed         -> remediated
#   autoDismissed -> auto-closed (stale / superseded / repo deletion)
STATE_TO_STATUS = {
    "active": "open",
    "new": "open",
    "open": "open",
    "fixed": "closed",
    "resolved": "closed",
    "closed": "closed",
    "autodismissed": "closed",
    "auto_dismissed": "closed",
    "dismissed": "risk-accepted",
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)

# Hard-validation regexes — anchored with \A / \Z so $-matches-before-newline
# can't slip past either. ADO org / project / repo names follow the same
# alphabet (alphanumeric + spaces + `._-`) per the ADO docs.
ORG_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
PROJECT_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}\Z")
REPO_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}\Z")
HOST_URL_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")


def log(msg):
    print(f"{datetime.utcnow()} - AzureDevOpsSecurity: {msg}", file=sys.stderr, flush=True)


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


def severity_from_ado(value, cvss=None):
    """Map an ADO Advanced Security severity field to a Faraday bucket.

    Accepts the canonical ADO string enum (critical / high / medium /
    low / note) plus a couple of nearby aliases. Falls back to CVSS
    bucketing on the provided ``cvss`` argument when the primary value
    is missing or unrecognised. Numeric inputs are interpreted as CVSS
    v3 scores.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in ADO_TO_FARADAY:
            return ADO_TO_FARADAY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_state(state):
    """Map an ADO alert ``state`` to a Faraday status."""
    if not state:
        return "open"
    text = str(state).strip().lower().replace("-", "").replace(" ", "")
    if text in STATE_TO_STATUS:
        return STATE_TO_STATUS[text]
    # Tolerate camelCase ``autoDismissed`` via the dash/space-stripped form.
    norm = text.replace("_", "")
    return STATE_TO_STATUS.get(norm, "open")


def build_auth_header(pat):
    """Build the Azure DevOps REST auth header.

    A pre-built ``Bearer ...`` / ``Basic ...`` prefix in ``ADO_PAT``
    is forwarded verbatim (operators wiring up Microsoft Entra OAuth or
    a pre-encoded Basic header can paste it whole). A bare PAT is sent
    as HTTP Basic with an empty username — ``Authorization: Basic
    base64(":<PAT>")`` — the canonical ADO REST auth pattern.
    """
    if not pat:
        return {}
    text = str(pat).strip()
    lower = text.lower()
    if lower.startswith("bearer ") or lower.startswith("basic ") or lower.startswith("token "):
        return {"Authorization": text}
    encoded = base64.b64encode(f":{text}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def normalize_base_url(host):
    if not host:
        return DEFAULT_HOST
    base = str(host).strip()
    if not base:
        return DEFAULT_HOST
    # Reject control chars on the raw value before lowercasing / stripping.
    for ch in str(host):
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            log(f"ADO_HOST contained a control char; defaulting to {DEFAULT_HOST}")
            return DEFAULT_HOST
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    base = base.rstrip("/")
    if not HOST_URL_RE.match(base):
        log(f"ADO_HOST '{host}' is not a valid http(s) URL; defaulting to {DEFAULT_HOST}")
        return DEFAULT_HOST
    return base


def validate_org(value):
    """Validate the ADO org name (alphanumeric + ._- up to 64 chars)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or not ORG_NAME_RE.match(text):
        log(f"ADO_ORG '{value}' is not a valid Azure DevOps organisation name")
        sys.exit(1)
    return text


def validate_project(value):
    """Validate the ADO project name (alphanumeric + spaces + ._- up to 64 chars)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or not PROJECT_NAME_RE.match(text):
        log(f"ADO_PROJECT '{value}' is not a valid Azure DevOps project name")
        sys.exit(1)
    return text


def validate_repo(value):
    """Validate the ADO repo name (alphanumeric + spaces + ._- up to 64 chars)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or not REPO_NAME_RE.match(text):
        log(f"ADO_REPO '{value}' is not a valid Azure DevOps repository name")
        sys.exit(1)
    return text


def parse_alert_types(value):
    """Parse ``ADO_ALERT_TYPE`` into a normalised tuple.

    Empty / missing input fans out to all three families (code /
    secret / dependency) so the executor has a sensible no-config
    default. Unknown tokens are logged + skipped — the user gets a
    warning but the executor still runs the valid subset.
    """
    if value is None or str(value).strip() == "":
        return VALID_ALERT_TYPES
    seen = []
    for chunk in str(value).split(","):
        text = chunk.strip().lower()
        if not text:
            continue
        # ``secrets`` -> ``secret`` so operators can use either spelling.
        if text == "secrets":
            text = "secret"
        if text == "dependencies":
            text = "dependency"
        if text in VALID_ALERT_TYPES:
            if text not in seen:
                seen.append(text)
        else:
            log(f"ADO_ALERT_TYPE token '{chunk.strip()}' is not in " f"{', '.join(VALID_ALERT_TYPES)}; ignoring")
    return tuple(seen) if seen else VALID_ALERT_TYPES


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"ADO_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def parse_bool(value):
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "y", "t", "on")


def request_paginated(url, headers, params=None):
    """Walk an ADO REST list endpoint honouring ``x-ms-continuationtoken``.

    ADO paginates list-shaped responses via the
    ``x-ms-continuationtoken`` response header — when present, the next
    page is fetched by passing the token back as the
    ``continuationToken`` query-string param. We honour that when the
    server vends it and fall back to short-page termination otherwise.
    Bounded at ``MAX_PAGES`` pages of ``PAGE_SIZE`` rows.
    """
    results = []
    query = dict(params or {})
    query.setdefault("$top", PAGE_SIZE)
    next_url = url
    next_query = query
    for _ in range(MAX_PAGES):
        try:
            resp = requests.get(
                next_url,
                headers=headers,
                params=next_query,
                timeout=TIMEOUT,
                verify=False,
            )
        except requests.RequestException as exc:
            log(f"GET {next_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Authentication rejected (401). Check ADO_PAT (PAT must include 'Advanced Security: Read').")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"Authorization rejected (403) on {next_url}. Check the PAT scope.")
            break
        if resp.status_code == 404:
            log(f"GET {next_url} returned 404 (Advanced Security may not be enabled, or repo not accessible)")
            break
        if resp.status_code >= 400:
            log(f"GET {next_url} failed ({resp.status_code}): {resp.text[:500]}")
            break
        try:
            body = resp.json()
        except ValueError:
            log(f"GET {next_url} returned non-JSON body")
            break
        chunk = extract_list(body)
        if chunk:
            results.extend(chunk)
        token = None
        if hasattr(resp, "headers"):
            token = resp.headers.get("x-ms-continuationtoken") or resp.headers.get("X-MS-ContinuationToken")
        if token:
            next_query = dict(query)
            next_query["continuationToken"] = token
            continue
        if not chunk or len(chunk) < PAGE_SIZE:
            break
        # No continuation token but a full page — bump $skip as a fallback
        # for older ADO Server installs that don't vend the token.
        next_query = dict(query)
        next_query["$skip"] = next_query.get("$skip", 0) + len(chunk)
    return results


def extract_list(body):
    """Pluck a list of values out of an ADO REST response.

    ADO's REST endpoints uniformly wrap pages in
    ``{"value": [...], "count": N}``. A handful of internal endpoints
    surface a bare list / ``items`` / ``alerts`` shape, so we tolerate
    each of those (and an empty / None response from a 204).
    """
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for candidate in ("value", "values", "alerts", "items", "data", "results"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def fetch_alerts(base_url, org, project, repo, alert_type, headers, include_closed):
    """Fetch the Advanced Security alerts of one alert family.

    ``alert_type`` is the canonical ADO ``code|secret|dependency``;
    ``include_closed`` flips the ``criteria.states`` filter from
    ``active`` (the default) to no filter so fixed / dismissed /
    autoDismissed records also flow through.
    """
    url = f"{base_url}/{org}/{project}/_apis/Alert/repositories/{repo}/Alerts"
    params = {
        "api-version": DEFAULT_API_VERSION,
        "criteria.alertType": alert_type,
    }
    if not include_closed:
        params["criteria.states"] = "active"
    return request_paginated(url, headers, params=params)


def get_repo_meta(base_url, org, project, repo, headers):
    """Best-effort fetch of repo metadata for the host description.

    ADO repos are served from the regular ``dev.azure.com`` host (not
    the ``advsec.dev.azure.com`` subdomain), so we swap the host when
    constructing the URL. Failures are non-fatal — the host record
    still gets a sensible description from the project / repo names.
    """
    if not base_url:
        return {}
    # If the user pointed us at advsec.dev.azure.com (the default),
    # swap to dev.azure.com for the repo-metadata pull. If they
    # overrode ADO_HOST, leave the override in place — they probably
    # know their topology better than we do.
    meta_host = base_url
    if base_url == DEFAULT_HOST:
        meta_host = "https://dev.azure.com"
    url = f"{meta_host}/{org}/{project}/_apis/git/repositories/{repo}"
    try:
        resp = requests.get(
            url,
            headers=headers,
            params={"api-version": DEFAULT_API_VERSION},
            timeout=TIMEOUT,
            verify=False,
        )
    except requests.RequestException as exc:
        log(f"repo-meta GET {url} failed (non-fatal): {exc}")
        return {}
    if resp.status_code == 401:
        log("Repo-meta auth rejected (401). Check ADO_PAT scope (vso.code required).")
        return {}
    if resp.status_code >= 400:
        log(f"repo-meta GET {url} returned {resp.status_code} (non-fatal)")
        return {}
    try:
        body = resp.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def collect_cwes(node):
    """Pluck CWE-* identifiers out of a rule / tool / alert payload."""
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        match = CWE_PATTERN.search(str(text))
        if not match:
            return
        norm = match.group(0).upper()
        if norm in seen:
            return
        seen.add(norm)
        found.append(norm)

    if isinstance(node, dict):
        # ADO's rule payload carries a ``tags`` array (e.g. ``["CWE-79"]``)
        # and sometimes a ``properties.cwe`` / ``cwe`` field for
        # third-party SARIF-imported alerts.
        for tag in node.get("tags") or []:
            if isinstance(tag, str):
                add(tag)
        for key in ("cwe", "cweId", "cwe_id"):
            v = node.get(key)
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                s = str(v).strip()
                if s:
                    add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("cwes", "cweIds", "cwe_ids"):
            items = node.get(key)
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, dict):
                        cid = it.get("id") or it.get("value") or it.get("name")
                        if cid is None:
                            continue
                        s = str(cid).strip()
                        add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
                    elif isinstance(it, (int, float)) and not isinstance(it, bool):
                        add(f"CWE-{int(it)}")
                    elif isinstance(it, str) and it.strip():
                        s = it.strip()
                        add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
        for key in ("description", "summary", "helpText", "help"):
            text = node.get(key)
            if isinstance(text, str):
                for m in CWE_PATTERN.findall(text):
                    add(m)
    return found


def collect_cves(node):
    """Pluck CVE-* identifiers out of an ADO alert / advisory payload."""
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        match = CVE_PATTERN.search(str(text))
        if not match:
            return
        norm = match.group(0).upper()
        if norm in seen:
            return
        seen.add(norm)
        found.append(norm)

    if isinstance(node, dict):
        for key in ("cve", "cveId", "cve_id"):
            v = node.get(key)
            if isinstance(v, str) and v.strip():
                add(v)
        for key in ("cves", "cveIds", "cve_ids"):
            items = node.get(key)
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, str):
                        add(it)
                    elif isinstance(it, dict):
                        add(it.get("name") or it.get("id") or it.get("value"))
        # Dependency alerts often nest the CVE list under ``relations`` ->
        # ``advisory`` -> ``identifiers``.
        for key in ("description", "summary", "title", "shortDescription", "longDescription", "details"):
            text = node.get(key)
            if isinstance(text, str):
                for m in CVE_PATTERN.findall(text):
                    add(m)
    return found


def physical_location(alert):
    """Format the file:line location surfaced by a code-scanning alert."""
    if not isinstance(alert, dict):
        return None, ""
    # ADO Advanced Security exposes locations under several keys
    # depending on the alert family and ingestion source:
    #   * code-scanning native: ``physicalLocations`` list of dicts
    #     with ``filePath`` + ``region.line``.
    #   * SARIF-imported: ``locations`` list of dicts with
    #     ``physicalLocation.artifactLocation.uri`` + ``region.startLine``.
    #   * secret-scanning: ``truncatedPath`` plus ``physicalLocations``.
    candidates = []
    for key in ("physicalLocations", "locations"):
        items = alert.get(key)
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    candidates.append(it)
    for loc in candidates:
        path = loc.get("filePath") or loc.get("path") or (loc.get("artifactLocation") or {}).get("uri")
        region = loc.get("region") or loc.get("regionInfo") or {}
        start = None
        end = None
        if isinstance(region, dict):
            start = region.get("lineStart") or region.get("startLine") or region.get("line")
            end = region.get("lineEnd") or region.get("endLine")
        if path and start and end and str(start) != str(end):
            return f"location: {path}:{start}-{end}", path
        if path and start:
            return f"location: {path}:{start}", path
        if path:
            return f"location: {path}", path
    truncated = alert.get("truncatedPath")
    if isinstance(truncated, str) and truncated.strip():
        return f"location: {truncated.strip()}", truncated.strip()
    return None, ""


def collect_refs(alert, rule, html_url):
    """Walk an alert for CWE / advisory / tool refs + URLs."""
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

    for cwe in collect_cwes(rule) + collect_cwes(alert):
        add(cwe)

    if isinstance(rule, dict):
        help_uri = rule.get("helpUri") or rule.get("help_uri") or rule.get("helpUrl")
        if isinstance(help_uri, str) and help_uri.strip():
            add(help_uri.strip())
        elif isinstance(help_uri, dict):
            href = help_uri.get("href") or help_uri.get("url") or help_uri.get("name")
            if href:
                add(href)
        rule_id = rule.get("id") or rule.get("ruleId") or rule.get("name")
        if rule_id:
            add(f"ADO-Rule: {rule_id}")
        opaque_id = rule.get("opaqueId") or rule.get("opaque_id")
        if opaque_id:
            add(f"ADO-OpaqueRule: {opaque_id}")

    # ADO dependency alerts can carry GHSA identifiers in the relation /
    # advisory section — surface them as refs too.
    for ghsa in GHSA_PATTERN.findall(json.dumps(alert, default=str)):
        add(ghsa.upper())

    tools = alert.get("tools") or alert.get("tool")
    if isinstance(tools, dict):
        tools = [tools]
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict):
                name = tool.get("name") or tool.get("toolName")
                if name:
                    add(f"ADO-Tool: {name}")

    if isinstance(html_url, str) and html_url.strip():
        add(html_url.strip())

    return refs


def alert_html_url(base_url, org, project, repo, alert_id):
    """Construct the canonical ADO Advanced Security alert permalink."""
    if not (org and project and repo and alert_id):
        return ""
    # The web UI permalink uses ``dev.azure.com`` regardless of which
    # host the REST API is served from.
    return f"https://dev.azure.com/{org}/{project}/_git/{repo}/alerts/{alert_id}"


def alert_external_id(alert):
    for key in ("alertId", "id", "number"):
        v = alert.get(key) if isinstance(alert, dict) else None
        if v is not None:
            return str(v)
    return ""


def alert_severity(alert, rule):
    """Pick the severity off an alert, walking the common shapes."""
    if isinstance(rule, dict):
        for key in ("severity", "securitySeverityLevel", "security_severity_level", "level"):
            v = rule.get(key)
            if v not in (None, ""):
                return v
    if isinstance(alert, dict):
        for key in ("severity", "level", "priority"):
            v = alert.get(key)
            if v not in (None, ""):
                return v
    return None


def alert_state(alert):
    if not isinstance(alert, dict):
        return None
    return alert.get("state") or alert.get("status")


def dependency_meta(alert):
    """Pull package + version + ecosystem out of a dependency alert."""
    if not isinstance(alert, dict):
        return {}
    out = {}
    rel = alert.get("relations") or alert.get("relation")
    if isinstance(rel, dict):
        rel = [rel]
    if isinstance(rel, list):
        for entry in rel:
            if not isinstance(entry, dict):
                continue
            for key in ("packageName", "package", "componentName", "component", "name"):
                v = entry.get(key)
                if v and "package" not in out:
                    out["package"] = v if isinstance(v, str) else (v.get("name") if isinstance(v, dict) else None)
            for key in ("version", "versionRange", "vulnerableVersionRange"):
                v = entry.get(key)
                if v and "version" not in out:
                    out["version"] = v
            for key in ("ecosystem", "packageEcosystem", "type"):
                v = entry.get(key)
                if v and "ecosystem" not in out:
                    out["ecosystem"] = v
            for key in ("fixedIn", "firstPatchedVersion", "patchedVersion"):
                v = entry.get(key)
                if v and "fixed_in" not in out:
                    out["fixed_in"] = (
                        v if isinstance(v, str) else (v.get("identifier") if isinstance(v, dict) else None)
                    )
    for key, target in (
        ("packageName", "package"),
        ("componentName", "package"),
        ("componentVersion", "version"),
        ("ecosystem", "ecosystem"),
    ):
        v = alert.get(key) if isinstance(alert, dict) else None
        if v and target not in out:
            out[target] = v
    return out


def build_vulnerability(alert, alert_type, base_url, org, project, repo):
    rule = alert.get("rule") if isinstance(alert, dict) else None
    if not isinstance(rule, dict):
        rule = {}

    sev_raw = alert_severity(alert, rule)
    cvss = None
    if isinstance(alert, dict):
        for key in ("cvssScore", "cvss_score", "cvss"):
            v = alert.get(key)
            if v is None or isinstance(v, (dict, list, bool)):
                continue
            try:
                cvss = float(v)
                break
            except (TypeError, ValueError):
                continue
    severity = severity_from_ado(sev_raw, cvss)

    if alert_type == "secret":
        # ADO Advanced Security does not assign a severity to secret
        # alerts (Microsoft's docs match GitHub's stance here — exposed
        # credentials are treated as high-priority by default).
        if severity == "info":
            severity = "high"

    status = status_from_state(alert_state(alert))

    rule_name = (
        (rule.get("friendlyName") if isinstance(rule, dict) else None)
        or (rule.get("description") if isinstance(rule, dict) else None)
        or (rule.get("name") if isinstance(rule, dict) else None)
        or (rule.get("id") if isinstance(rule, dict) else None)
    )
    title_text = (
        rule_name
        or (alert.get("title") if isinstance(alert, dict) else None)
        or (alert.get("name") if isinstance(alert, dict) else None)
        or f"Advanced Security alert {alert_external_id(alert) or ''}"
    )
    prefix = {"code": "[CODE]", "secret": "[SECRETS]", "dependency": "[SCA]"}.get(alert_type, "[CODE]")
    name = f"{prefix} {title_text}".strip()

    desc_parts = []
    desc_source = None
    if isinstance(rule, dict):
        desc_source = rule.get("description") or rule.get("helpText") or rule.get("help")
    if not desc_source and isinstance(alert, dict):
        desc_source = (
            alert.get("description")
            or alert.get("longDescription")
            or alert.get("shortDescription")
            or (alert.get("rule") or {}).get("description")
        )
    if desc_source:
        desc_parts.append(str(desc_source))

    loc_text, path = physical_location(alert)
    if loc_text:
        desc_parts.append(loc_text)

    if alert_type == "dependency":
        dmeta = dependency_meta(alert)
        if dmeta.get("package"):
            desc_parts.append(
                f"package: {dmeta['package']}" + (f" ({dmeta['ecosystem']})" if dmeta.get("ecosystem") else "")
            )
        if dmeta.get("version"):
            desc_parts.append(f"affected_versions: {dmeta['version']}")
        if dmeta.get("fixed_in"):
            desc_parts.append(f"first_patched_version: {dmeta['fixed_in']}")

    introduced = alert.get("introducedDate") or alert.get("firstSeenDate")
    if introduced:
        desc_parts.append(f"first_seen: {introduced}")
    last_seen = alert.get("lastSeenDate") or alert.get("lastSeen")
    if last_seen:
        desc_parts.append(f"last_seen: {last_seen}")
    fixed_date = alert.get("fixedDate") or alert.get("fixedOn")
    if fixed_date:
        desc_parts.append(f"fixed: {fixed_date}")

    confidence = alert.get("confidence")
    if confidence:
        desc_parts.append(f"confidence: {confidence}")

    state_raw = alert_state(alert)
    if state_raw:
        desc_parts.append(f"state: {state_raw}")

    dismissal = alert.get("dismissal") if isinstance(alert, dict) else None
    if isinstance(dismissal, dict):
        dt = dismissal.get("dismissalType") or dismissal.get("type")
        if dt:
            desc_parts.append(f"dismissal_type: {dt}")
        dmsg = dismissal.get("message")
        if dmsg:
            desc_parts.append(f"dismissal_reason: {dmsg}")

    if cvss is not None:
        desc_parts.append(f"cvss: {cvss}")

    external_id = alert_external_id(alert)
    html_url = alert_html_url(base_url, org, project, repo, external_id)
    if html_url:
        desc_parts.append(f"[View it on Azure DevOps]({html_url})")

    cves = collect_cves(alert)
    if isinstance(rule, dict):
        for cve in collect_cves(rule):
            if cve not in cves:
                cves.append(cve)
    cwes = collect_cwes(rule) + [c for c in collect_cwes(alert) if c not in collect_cwes(rule)]
    refs = collect_refs(alert, rule, html_url)

    resolution = ""
    if isinstance(rule, dict):
        for key in ("helpText", "help", "remediation", "resolution", "fix", "recommendation"):
            v = rule.get(key)
            if isinstance(v, str) and v.strip():
                resolution = v.strip()
                break
    if not resolution and isinstance(alert, dict):
        for key in ("remediation", "resolution", "fix", "recommendation"):
            v = alert.get(key)
            if isinstance(v, str) and v.strip():
                resolution = v.strip()
                break

    cvss3 = {}
    if cvss is not None:
        cvss3["base_score"] = cvss

    tags = ["azure_devops_security", "advanced_security"]
    if alert_type == "code":
        tags.append("code_scanning")
    elif alert_type == "secret":
        tags.append("secret_detection")
    elif alert_type == "dependency":
        tags.append("dependency_scanning")

    return {
        "name": str(name).strip()[:200] or f"ADO Advanced Security alert {external_id}",
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
        "cwe": cwes,
        "tags": tags,
        "_path": path,
    }


def build_host(org, project, repo, repo_meta, vulns):
    hostname = f"{project}/{repo}" if project and repo else (project or repo or "")
    hostnames = [hostname] if hostname else []
    desc_parts = []
    if org and project and repo:
        desc_parts.append(f"repo=https://dev.azure.com/{org}/{project}/_git/{repo}")
    if isinstance(repo_meta, dict):
        for key, label in (
            ("name", "name"),
            ("id", "id"),
            ("defaultBranch", "default_branch"),
            ("size", "size"),
            ("webUrl", "url"),
            ("remoteUrl", "remote_url"),
        ):
            value = repo_meta.get(key)
            if value:
                desc_parts.append(f"{label}={value}")
    for v in vulns:
        v.pop("_path", None)
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("ADO_HOST", default=DEFAULT_HOST)
    pat = env("ADO_PAT", required=True)
    org = validate_org(env("ADO_ORG", required=True))
    project = validate_project(env("EXECUTOR_CONFIG_ADO_PROJECT", required=True))
    repo = validate_repo(env("EXECUTOR_CONFIG_ADO_REPO", required=True))
    alert_types = parse_alert_types(env("EXECUTOR_CONFIG_ADO_ALERT_TYPE"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_ADO_MIN_SEVERITY"))
    include_closed = parse_bool(env("EXECUTOR_CONFIG_ADO_INCLUDE_CLOSED"))
    floor = SEVERITY_ORDER[min_severity]

    base_url = normalize_base_url(host)
    headers = build_auth_header(pat)
    headers["Accept"] = "application/json"

    repo_meta = get_repo_meta(base_url, org, project, repo, headers)

    log(
        f"Processing {project}/{repo} "
        f"(alert_types={','.join(alert_types)}, min_severity={min_severity}, "
        f"include_closed={include_closed})"
    )

    vulns = []
    for alert_type in alert_types:
        page = fetch_alerts(base_url, org, project, repo, alert_type, headers, include_closed)
        for alert in page:
            if not isinstance(alert, dict):
                continue
            built = build_vulnerability(alert, alert_type, base_url, org, project, repo)
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)

    hosts = [build_host(org, project, repo, repo_meta, vulns)] if vulns else []

    output = {
        "hosts": hosts,
        "command": {
            "tool": "azure_devops_security",
            "command": "azure_devops_security",
            "params": (
                f"org={org},project={project},repo={repo},"
                f"alert_types={','.join(alert_types)},"
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
