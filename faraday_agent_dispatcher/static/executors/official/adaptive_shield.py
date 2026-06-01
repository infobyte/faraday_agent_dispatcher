#!/usr/bin/env python
"""Adaptive Shield SSPM importer.

Pulls SaaS-application inventory and security-posture findings
from an Adaptive Shield SSPM (SaaS Security Posture Management)
tenant via the Adaptive Shield REST API and emits Faraday
bulk-create JSON to stdout.  Adaptive Shield monitors the
operator's SaaS estate (M365, Salesforce, Google Workspace, Slack,
GitHub, Okta, Zoom, ServiceNow, etc.) for misconfigurations,
identity-hygiene gaps and integration risks — so this executor is
the SaaS-posture feed Faraday operators correlate the IAM /
identity / EDR / EASM agents' findings against to confirm whether
an identity exposure also lands on a misconfigured app integration.

Each Adaptive Shield application becomes one Faraday host —
SSPM applications aren't IP-keyed (the integration is logical,
not network-anchored) so they synthesise onto the ``0.0.0.0``
sentinel; the ``name`` / ``vendor`` / ``instance_name`` projection
lands on ``host.hostnames``; ``app_id`` / ``status`` /
``integration_status`` / ``connected_at`` enrichment lands on
``host.description``; the application record itself becomes one
Faraday vulnerability with the ``[IDENTITY]`` engine prefix so the
finding lands in the workspace alongside the other identity-
attack-surface feeds.  Each Adaptive Shield finding becomes one
Faraday host on the ``0.0.0.0`` sentinel — SSPM findings are
configuration-posture observations rather than network-keyed
events — and one Faraday vulnerability with severity mapped from
the finding's ``severity`` field (``info`` -> ``info``,
``low`` -> ``low``, ``medium``/``med`` -> ``med``,
``high`` -> ``high``, ``critical`` -> ``critical``).  The
``app_name`` / ``check_name`` / ``category`` projection lands on
``host.hostnames`` so the workspace's hostname index pivots on the
SaaS app + control name.

Endpoints used:
  GET {AS_HOST}/api/v1/applications?app_id=<AS_APP_ID>&page=N&page_size=M
      -> the canonical Adaptive Shield connected-application
      inventory.  Returns a JSON envelope ``{"results": [...],
      "next": <url|null>, "count": N}``; each record carries
      ``id``, ``app_id``, ``name``, ``vendor``, ``instance_name``,
      ``status``, ``integration_status``, ``connected_at``,
      ``last_scan_at``, ``tenant_id``.  When ``AS_APP_ID`` is set,
      the dispatcher forwards it as the ``?app_id=`` query
      parameter so the walk only returns that one SaaS app's
      integration record.
  GET {AS_HOST}/api/v1/findings?app_id=<AS_APP_ID>
      &min_severity=<AS_MIN_SEVERITY>&page=N&page_size=M
      -> the Adaptive Shield posture-finding feed.  Returns the
      same envelope shape; each record carries ``id``,
      ``check_id``, ``check_name``, ``description``, ``severity``,
      ``category``, ``app_id``, ``app_name``, ``status``,
      ``created_at``, ``updated_at``, ``remediation``,
      ``compliance`` (list of frameworks).  ``AS_MIN_SEVERITY``
      maps to Adaptive Shield's documented threshold filter on the
      same surface (info | low | medium | high | critical).

Pagination is page-number based via ``page`` + ``page_size`` query
parameters on both surfaces.  We walk page-by-page until either
``results`` is empty / ``next`` is null or the env-only
``AS_PAGES`` cap is reached (default 5, clamped to [1, 50]).
``page_size`` is fixed at 100 (Adaptive Shield's documented default
page size; the hard cap is 500 but smaller pages keep response
sizes manageable for the dispatcher event loop).

Auth: Adaptive Shield uses long-lived API keys.  Operators create
one in the Adaptive Shield admin console under ``Settings ->
Integrations -> REST API -> Generate Key``.  The dispatcher
carries it on every request as the standard
``Authorization: Bearer <AS_API_KEY>`` header.  ``AS_HOST`` is the
operator's Adaptive Shield tenant host (e.g.
``mycorp.adaptive-shield.com`` or
``mycorp.us.adaptive-shield.com``); ``https://`` is added
automatically when the operator pasted in a bare FQDN.

Severity for applications is always ``info`` (they're inventory
entries, not findings).  Severity for findings is mapped from the
``severity`` field via SEVERITY_MAP — anything not in the map
falls back to ``info``.  ``AS_MIN_SEVERITY`` is server-side
threshold filtering, NOT a client-side filter — Adaptive Shield's
own surface drops below-threshold findings before the response
ships, so the executor walks whatever comes back.  Tags:
[adaptive_shield, identity, sspm, application|finding].
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

TIMEOUT = 60
PER_PAGE = 100  # Adaptive Shield's documented default page size.
DEFAULT_PAGES = 5
MAX_PAGES = 50

# Adaptive Shield severity values -> Faraday severity slots.
SEVERITY_MAP = {
    "INFO": "info",
    "INFORMATIONAL": "info",
    "LOW": "low",
    "MEDIUM": "med",
    "MED": "med",
    "HIGH": "high",
    "CRITICAL": "critical",
}

ALLOWED_MIN_SEVERITIES = ("info", "low", "medium", "high", "critical")

# Sentinel IP used for non-IP-keyed records.
SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - AdaptiveShield: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on AS_HOST.

    No default — the Adaptive Shield tenant host is operator-
    specific so we ``sys.exit(1)`` upstream in ``main`` when the
    env var is missing.  Here we just whitespace-trim, strip
    trailing slashes and add ``https://`` when the operator pasted
    in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_app_id(value):
    """Validate AS_APP_ID (the operator-supplied app filter).

    None / blank -> ``""`` (no narrowing; every connected app is
    walked).  Whitespace is trimmed.  Forwarded verbatim into the
    ``?app_id=<value>`` query parameter — Adaptive Shield accepts
    both numeric ids and slugs (e.g. ``salesforce``, ``m365``) in
    the same slot.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_min_severity(value):
    """Validate AS_MIN_SEVERITY (the operator-supplied threshold).

    None / blank -> ``""`` (no threshold; every severity is
    walked).  Case-insensitive.  Accepted tokens: ``info``,
    ``low``, ``medium``, ``high``, ``critical``.  Anything else
    falls back to ``""`` so a stray operator input doesn't reject
    the whole walk — Adaptive Shield would 400 on an unknown
    threshold and we'd lose the findings call entirely.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    if text == "med":
        text = "medium"
    if text not in ALLOWED_MIN_SEVERITIES:
        log(f"AS_MIN_SEVERITY '{value}' not in " f"{ALLOWED_MIN_SEVERITIES}; ignoring")
        return ""
    return text


def validate_pages(value):
    """Validate AS_PAGES (per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Adaptive Shield API.  Not exposed as a manifest argument (the
    playbook only lists AS_APP_ID + AS_MIN_SEVERITY) but read from
    the env so a tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"AS_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"AS_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def auth_headers(token):
    """Return the Adaptive Shield auth header set.

    Adaptive Shield uses the standard ``Authorization: Bearer
    <token>`` scheme.  We also force ``Accept: application/json``
    because Adaptive Shield's content negotiation will default to
    JSON anyway but being explicit avoids edge cases on federated
    / proxy stacks that strip the default.
    """
    return {
        "Authorization": f"Bearer {token or ''}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def build_applications_url(host, app_id, page):
    base = f"{normalize_base_url(host)}/api/v1/applications"
    params = [f"page={int(page)}", f"page_size={PER_PAGE}"]
    if app_id:
        params.append(f"app_id={quote(app_id, safe='')}")
    return f"{base}?{'&'.join(params)}"


def build_findings_url(host, app_id, min_severity, page):
    base = f"{normalize_base_url(host)}/api/v1/findings"
    params = [f"page={int(page)}", f"page_size={PER_PAGE}"]
    if app_id:
        params.append(f"app_id={quote(app_id, safe='')}")
    if min_severity:
        params.append(f"min_severity={quote(min_severity, safe='')}")
    return f"{base}?{'&'.join(params)}"


def _str(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value)


def _serialise(obj):
    if obj is None:
        return ""
    if isinstance(obj, (str, int, float)):
        return str(obj)
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(obj)


def map_finding_severity(value):
    """Map an Adaptive Shield finding severity onto a Faraday slot."""
    if not value:
        return "info"
    return SEVERITY_MAP.get(str(value).strip().upper(), "info")


def fetch_all(requests_module, build_url, host, headers, max_pages, surface_name, **build_kwargs):
    """Walk an Adaptive Shield endpoint via page-number pagination.

    Pages until either the response stops carrying ``results`` /
    the page returns fewer than ``PER_PAGE`` entries or
    ``max_pages`` is reached.  401 short-circuits the whole
    executor because the operator credentials are wrong.  403 /
    429 just stop pagination on the surface we're walking and
    return what we have.
    """
    out = []
    page = 1
    while page <= max_pages:
        url = build_url(host, page=page, **build_kwargs)
        try:
            resp = requests_module.get(url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Adaptive Shield request rejected (401). Check AS_API_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"Adaptive Shield {surface_name} request rejected (403). " f"Check the API key's scope.")
            return out
        if resp.status_code == 429:
            log(f"Adaptive Shield rate-limited (429) on {surface_name}; " f"stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Adaptive Shield {surface_name} failed " f"({resp.status_code}): {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Adaptive Shield {surface_name} response was not JSON")
            return out
        results = []
        if isinstance(payload, dict):
            raw = payload.get("results")
            if isinstance(raw, list):
                results = [r for r in raw if isinstance(r, dict)]
        elif isinstance(payload, list):
            results = [r for r in payload if isinstance(r, dict)]
        out.extend(results)
        if len(results) < PER_PAGE:
            return out
        next_url = None
        if isinstance(payload, dict):
            next_url = payload.get("next")
        if not next_url:
            return out
        page += 1
    log(f"hit AS_PAGES={max_pages} on {surface_name}; stopping pagination")
    return out


def application_hostnames(app):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(app, dict):
        add(app.get("name"))
        add(app.get("vendor"))
        add(app.get("instance_name"))
        add(app.get("app_id"))
    return out


def collect_application_refs(app):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(app, dict):
        return refs
    aid = _str(app.get("id"))
    if aid:
        add(f"AdaptiveShield-Id: {aid}")
    app_id = _str(app.get("app_id"))
    if app_id:
        add(f"AdaptiveShield-AppId: {app_id}")
    vendor = _str(app.get("vendor"))
    if vendor:
        add(f"AdaptiveShield-Vendor: {vendor}")
    instance = _str(app.get("instance_name"))
    if instance:
        add(f"AdaptiveShield-Instance: {instance}")
    status = _str(app.get("status"))
    if status:
        add(f"AdaptiveShield-Status: {status}")
    integration = _str(app.get("integration_status"))
    if integration:
        add(f"AdaptiveShield-IntegrationStatus: {integration}")
    connected = _str(app.get("connected_at"))
    if connected:
        add(f"AdaptiveShield-ConnectedAt: {connected}")
    last_scan = _str(app.get("last_scan_at"))
    if last_scan:
        add(f"AdaptiveShield-LastScan: {last_scan}")
    tenant = _str(app.get("tenant_id"))
    if tenant:
        add(f"AdaptiveShield-Tenant: {tenant}")
    return refs


def build_application_host(app, app_id_filter):
    """Build a Faraday host dict for an Adaptive Shield app record."""
    if not isinstance(app, dict):
        return None
    hostnames = application_hostnames(app)
    primary = hostnames[0] if hostnames else _str(app.get("id")) or "unknown app"

    desc_parts = []
    for key in (
        "id",
        "app_id",
        "name",
        "vendor",
        "instance_name",
        "status",
        "integration_status",
        "connected_at",
        "last_scan_at",
        "tenant_id",
    ):
        v = app.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if app_id_filter:
        desc_parts.append(f"as_app_id: {app_id_filter}")

    vuln = {
        "name": f"[IDENTITY] Adaptive Shield app: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(app.get("id"))[:200] or f"adaptive-shield-app-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Adaptive Shield application records are SSPM "
            "inventory entries, not vulnerabilities.  Cross-check "
            "the connected app against the other agents' findings "
            "— anything reported against this app's identities or "
            "endpoints indicates a real exposure on a known SaaS "
            "integration.  Disconnect or rotate the integration in "
            "the Adaptive Shield console if the app should no "
            "longer be in scope."
        ),
        "data": "",
        "refs": collect_application_refs(app),
        "cve": [],
        "cvss3": {},
        "tags": ["adaptive_shield", "identity", "sspm", "application"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"Adaptive Shield app {primary}",
        "vulnerabilities": [vuln],
    }


def finding_hostnames(finding):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(finding, dict):
        add(finding.get("app_name"))
        add(finding.get("check_name"))
        add(finding.get("category"))
    return out


def collect_finding_refs(finding):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(finding, dict):
        return refs
    fid = _str(finding.get("id"))
    if fid:
        add(f"AdaptiveShield-FindingId: {fid}")
    check_id = _str(finding.get("check_id"))
    if check_id:
        add(f"AdaptiveShield-CheckId: {check_id}")
    check_name = _str(finding.get("check_name"))
    if check_name:
        add(f"AdaptiveShield-CheckName: {check_name}")
    severity = _str(finding.get("severity"))
    if severity:
        add(f"AdaptiveShield-Severity: {severity}")
    category = _str(finding.get("category"))
    if category:
        add(f"AdaptiveShield-Category: {category}")
    app_id = _str(finding.get("app_id"))
    if app_id:
        add(f"AdaptiveShield-AppId: {app_id}")
    app_name = _str(finding.get("app_name"))
    if app_name:
        add(f"AdaptiveShield-AppName: {app_name}")
    status = _str(finding.get("status"))
    if status:
        add(f"AdaptiveShield-Status: {status}")
    created = _str(finding.get("created_at"))
    if created:
        add(f"AdaptiveShield-Created: {created}")
    updated = _str(finding.get("updated_at"))
    if updated:
        add(f"AdaptiveShield-Updated: {updated}")
    compliance = finding.get("compliance")
    if isinstance(compliance, list) and compliance:
        joined = ",".join(_str(c) for c in compliance if c)
        if joined:
            add(f"AdaptiveShield-Compliance: {joined}")
    return refs


def build_finding_host(finding, app_id_filter, min_severity):
    """Build a Faraday host dict for an Adaptive Shield finding."""
    if not isinstance(finding, dict):
        return None
    hostnames = finding_hostnames(finding)
    check_name = _str(finding.get("check_name")) or "unknown finding"
    app_name = _str(finding.get("app_name"))
    label = f"[IDENTITY] Adaptive Shield finding: {check_name}"
    if app_name:
        label = f"{label} ({app_name})"

    desc_parts = []
    for key in (
        "id",
        "check_id",
        "check_name",
        "description",
        "severity",
        "category",
        "app_id",
        "app_name",
        "status",
        "created_at",
        "updated_at",
        "remediation",
    ):
        v = finding.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    compliance = finding.get("compliance")
    if compliance:
        desc_parts.append(f"compliance: {_serialise(compliance)}")
    if app_id_filter:
        desc_parts.append(f"as_app_id: {app_id_filter}")
    if min_severity:
        desc_parts.append(f"as_min_severity: {min_severity}")

    remediation = _str(finding.get("remediation"))
    resolution = remediation or (
        "Adaptive Shield findings are SaaS-posture observations — "
        "review the check description and remediation in the "
        "Adaptive Shield console and apply the recommended "
        "configuration change on the connected app."
    )

    vuln = {
        "name": label[:200],
        "desc": "\n".join(desc_parts),
        "severity": map_finding_severity(finding.get("severity")),
        "external_id": _str(finding.get("id"))[:200] or f"adaptive-shield-finding-{check_name}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_finding_refs(finding),
        "cve": [],
        "cvss3": {},
        "tags": ["adaptive_shield", "identity", "sspm", "finding"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"Adaptive Shield finding {check_name}",
        "vulnerabilities": [vuln],
    }


def main():
    started = time.time()

    app_id = validate_app_id(env("EXECUTOR_CONFIG_AS_APP_ID"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_AS_MIN_SEVERITY"))
    pages = validate_pages(env("AS_PAGES"))

    host = env("AS_HOST", required=True)
    token = env("AS_API_KEY", required=True)

    if not normalize_base_url(host):
        log("AS_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)

    app_hits = fetch_all(
        requests,
        build_applications_url,
        host,
        headers,
        pages,
        "/api/v1/applications",
        app_id=app_id,
    )
    finding_hits = fetch_all(
        requests,
        build_findings_url,
        host,
        headers,
        pages,
        "/api/v1/findings",
        app_id=app_id,
        min_severity=min_severity,
    )

    log(
        f"Processing {len(app_hits)} Adaptive Shield applications + "
        f"{len(finding_hits)} findings (app_id={app_id!r}, "
        f"min_severity={min_severity!r}, pages={pages})"
    )

    hosts_out = []
    for a in app_hits:
        built = build_application_host(a, app_id)
        if built is not None:
            hosts_out.append(built)
    for f in finding_hits:
        built = build_finding_host(f, app_id, min_severity)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "adaptive_shield",
            "command": "adaptive_shield",
            "params": (f"app_id={app_id}," f"min_severity={min_severity}," f"pages={pages}"),
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
