#!/usr/bin/env python
"""Microsoft Entra Permissions Management (CloudKnox) importer.

Pulls cloud authorization systems (AWS accounts, Azure
subscriptions, GCP projects) and permissions-risk findings from a
Microsoft Entra Permissions Management tenant (formerly CloudKnox
Security) via Microsoft Graph's ``/permissionManagement`` surface
plus the legacy CloudKnox REST API for the per-system risk feed,
and emits Faraday bulk-create JSON to stdout.  CloudKnox /
Permissions Management is the Microsoft-owned CIEM (Cloud
Infrastructure Entitlement Management) product that continuously
evaluates the permissions granted to identities across AWS / Azure
/ GCP and scores each identity by its Permission Creep Index (the
PCI score, 0-100, derived from the ratio of granted-but-unused
permissions to granted ones) — so this executor is the
cross-cloud-entitlement feed Faraday operators correlate the IAM /
EDR / vuln-scanner agents' findings against to confirm whether an
identity exposure intersects an over-privileged principal that has
permissions it has never used in production.

Each CloudKnox authorization system becomes one Faraday host —
authorization systems aren't IP-keyed (an AWS account / Azure
subscription / GCP project is a logical multi-cloud boundary, not
a network endpoint) so they synthesise onto the ``0.0.0.0``
sentinel; the ``displayName`` / ``authorizationSystemName`` /
``authorizationSystemType`` projection lands on
``host.hostnames``; ``id`` / ``status`` / ``dataCollectionInfo``
enrichment lands on ``host.description``; the authorization-system
record itself becomes one Faraday vulnerability with the
``[IDENTITY]`` engine prefix so the finding lands in the workspace
alongside the other identity-attack-surface feeds.  Each CloudKnox
risk finding becomes one Faraday host on the ``0.0.0.0`` sentinel
— CloudKnox findings are identity-entitlement observations, not
network-keyed events — and one Faraday vulnerability with severity
mapped from CloudKnox's ``riskLevel`` field
(``low`` -> ``low``, ``medium``/``med`` -> ``med``,
``high`` -> ``high``, ``critical`` -> ``critical``).

Endpoints used:
  POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
      -> Azure AD OAuth2 client_credentials.  Returns
      ``{"access_token": "...", "expires_in": N, "token_type": "Bearer"}``;
      subsequent calls send ``Authorization: Bearer <access_token>``.
      Scope is fixed to ``https://graph.microsoft.com/.default`` —
      the Microsoft Graph control plane that fronts CloudKnox /
      Permissions Management.
  GET https://graph.microsoft.com/beta/permissionManagement/authorizationSystems
      -> the canonical CloudKnox authorization-system inventory.
      Returns the Graph ``{"value": [...], "@odata.nextLink": ...}``
      envelope; each record carries ``id``,
      ``authorizationSystemId``, ``authorizationSystemName``,
      ``authorizationSystemType`` (AWS | Azure | GCP),
      ``displayName``, ``status``, ``dataCollectionInfo``.  When
      ``CK_AUTHSYSTEM_ID`` is set the dispatcher narrows the walk
      to that one auth-system via the Graph ``$filter=`` OData
      predicate.
  GET https://graph.microsoft.com/beta/permissionManagement/authorizationSystems/{id}/findings
      -> the legacy CloudKnox per-auth-system finding feed
      surfaced through the modern Graph proxy.  Returns the same
      Graph envelope; each record carries ``id``, ``findingType``,
      ``riskLevel`` (low | medium | high | critical),
      ``principal`` (the over-privileged identity),
      ``authorizationSystemId``, ``recommendation``, ``status``,
      ``createdDateTime``, ``lastModifiedDateTime``.
      ``CK_RISK_LEVEL`` is forwarded as
      ``?$filter=riskLevel eq '<value>'`` so the surface only
      returns findings at the operator-supplied risk floor.

Pagination is Graph-native ``@odata.nextLink`` based.  We walk
page-by-page until the next-link is absent or the env-only
``CK_PAGES`` cap is reached (default 5, clamped to [1, 50]).

Auth: CloudKnox / Permissions Management lives behind Microsoft
Graph and uses Azure AD client_credentials.  A service-principal
app registration is created in the Azure portal with the
``Permissions Management - PermissionsManagement.Read.All``
application (not delegated) permission granted at the tenant scope
and admin consent applied.  Credentials are exposed to the
dispatcher as ``AZURE_TENANT_ID`` (the directory id),
``AZURE_CLIENT_ID`` (the service principal application id), and
``AZURE_CLIENT_SECRET`` (the client secret).  The token exchange
is ``POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token``
with form body ``grant_type=client_credentials&client_id=...&client_secret=...&scope=https://graph.microsoft.com/.default``.  # noqa: E501

Severity for authorization systems is always ``info`` (they're
inventory entries, not findings).  Severity for findings is mapped
from CloudKnox's ``riskLevel`` field via SEVERITY_MAP — anything
not in the map falls back to ``info``.  Tags: [cloudknox,
identity, ciem, authorization-system|finding].
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

GRAPH_HOST = "https://graph.microsoft.com"
GRAPH_API_VERSION = "beta"
TOKEN_SCOPE = "https://graph.microsoft.com/.default"

TIMEOUT = 60
DEFAULT_PAGES = 5
MAX_PAGES = 50

# CloudKnox riskLevel values -> Faraday severity slots.
SEVERITY_MAP = {
    "INFO": "info",
    "INFORMATIONAL": "info",
    "LOW": "low",
    "MEDIUM": "med",
    "MED": "med",
    "MODERATE": "med",
    "HIGH": "high",
    "CRITICAL": "critical",
}

ALLOWED_RISK_LEVELS = ("low", "medium", "high", "critical")

# Sentinel IP used for non-IP-keyed identity records.
SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - CloudKnox: {msg}", file=sys.stderr, flush=True)


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


def validate_authsystem_id(value):
    """Validate CK_AUTHSYSTEM_ID (the operator-supplied auth-system filter).

    None / blank -> ``""`` (no narrowing; every authorization
    system known to the tenant is walked).  Whitespace is trimmed.
    Forwarded into the Graph ``$filter=authorizationSystemId eq
    '<value>'`` predicate on the inventory surface and used as the
    path segment on the per-system findings surface — CloudKnox
    accepts both numeric ids and AWS account ids / Azure
    subscription guids / GCP project ids in the same slot.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_risk_level(value):
    """Validate CK_RISK_LEVEL (the operator-supplied risk threshold).

    None / blank -> ``""`` (no narrowing; every risk level is
    walked).  Case-insensitive.  Accepted tokens: ``low``,
    ``medium``, ``high``, ``critical``.  ``med`` is normalised to
    ``medium``.  Anything else falls back to ``""`` so a stray
    operator input doesn't reject the whole walk — CloudKnox would
    400 on an unknown risk level and we'd lose the findings call
    entirely.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    if text == "med":
        text = "medium"
    if text not in ALLOWED_RISK_LEVELS:
        log(f"CK_RISK_LEVEL '{value}' not in " f"{ALLOWED_RISK_LEVELS}; ignoring")
        return ""
    return text


def validate_pages(value):
    """Validate CK_PAGES (per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    CloudKnox API.  Not exposed as a manifest argument (the
    playbook only lists CK_AUTHSYSTEM_ID + CK_RISK_LEVEL) but read
    from the env so a tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"CK_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"CK_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def auth_headers(token):
    """Return the CloudKnox / Graph auth header set.

    CloudKnox / Permissions Management lives behind Microsoft Graph
    and uses the standard ``Authorization: Bearer <token>`` scheme.
    We also force ``Accept: application/json`` because Graph's
    content negotiation will default to JSON anyway but being
    explicit avoids edge cases on federated / proxy stacks that
    strip the default.
    """
    return {
        "Authorization": f"Bearer {token or ''}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def build_authsystems_url(authsystem_id):
    """Build the Graph URL for the authorization-system inventory."""
    base = f"{GRAPH_HOST}/{GRAPH_API_VERSION}/permissionManagement/" f"authorizationSystems"
    if authsystem_id:
        # OData $filter uses single-quoted strings; CloudKnox auth-system
        # ids are GUIDs / account ids and never contain quotes.
        predicate = f"authorizationSystemId eq '{authsystem_id}'"
        return f"{base}?$filter={quote(predicate, safe='')}"
    return base


def build_findings_url(authsystem_id, risk_level):
    """Build the Graph URL for the per-auth-system findings feed.

    CloudKnox findings hang under the authorization system path —
    ``{base}/authorizationSystems/{id}/findings`` — when a specific
    auth-system is targeted.  Without a target the surface
    flattens to ``{base}/findings`` and Graph returns findings
    across every auth-system the principal can read.
    """
    base = f"{GRAPH_HOST}/{GRAPH_API_VERSION}/permissionManagement"
    if authsystem_id:
        url = f"{base}/authorizationSystems/" f"{quote(authsystem_id, safe='')}/findings"
    else:
        url = f"{base}/findings"
    if risk_level:
        predicate = f"riskLevel eq '{risk_level}'"
        return f"{url}?$filter={quote(predicate, safe='')}"
    return url


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


def map_risk_level(value):
    """Map a CloudKnox riskLevel value onto a Faraday severity slot."""
    if not value:
        return "info"
    return SEVERITY_MAP.get(str(value).strip().upper(), "info")


def fetch_access_token(requests_module, tenant_id, client_id, client_secret):
    """Exchange Azure AD service-principal credentials for a Graph bearer."""
    if not tenant_id or not client_id or not client_secret:
        return None
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": TOKEN_SCOPE,
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        resp = requests_module.post(url, data=payload, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        log("Azure AD token request rejected (401). " "Check AZURE_CLIENT_ID / AZURE_CLIENT_SECRET.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Azure AD token request failed ({resp.status_code}): " f"{resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log("Azure AD token response was not JSON")
        return None
    token = body.get("access_token") or body.get("accessToken") or body.get("token")
    if not token:
        log("Azure AD token response missing access_token")
        return None
    return token


def fetch_all(requests_module, url, headers, max_pages, surface_name):
    """Walk a Graph-paged ``{"value": [...], "@odata.nextLink": "..."}`` envelope.

    Pages until the next-link is absent / the response stops carrying
    ``value`` / ``max_pages`` is reached.  401 short-circuits the
    whole executor because the operator credentials are wrong.  403
    / 429 just stop pagination on the surface we're walking and
    return what we have.
    """
    out = []
    next_url = url
    pages = 0
    while next_url and pages < max_pages:
        try:
            resp = requests_module.get(next_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {next_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("CloudKnox / Graph request rejected (401). " "Bearer expired or invalid.")
            sys.exit(1)
        if resp.status_code == 403:
            log(
                f"CloudKnox {surface_name} request rejected (403). "
                f"Check PermissionsManagement.Read.All app permission."
            )
            return out
        if resp.status_code == 429:
            log(f"CloudKnox rate-limited (429) on {surface_name}; " f"stopping pagination.")
            return out
        if resp.status_code == 404:
            log(f"CloudKnox {surface_name} returned 404 — endpoint " f"missing or auth-system id unknown.")
            return out
        if resp.status_code >= 400:
            log(f"CloudKnox {surface_name} failed " f"({resp.status_code}): {resp.text[:500]}")
            return out
        try:
            body = resp.json()
        except ValueError:
            log(f"CloudKnox {surface_name} response was not JSON")
            return out
        if isinstance(body, list):
            out.extend(r for r in body if isinstance(r, dict))
            return out
        if not isinstance(body, dict):
            return out
        value = body.get("value")
        if isinstance(value, list):
            out.extend(r for r in value if isinstance(r, dict))
        next_url = body.get("@odata.nextLink") or body.get("nextLink") or None
        pages += 1
    if pages >= max_pages and next_url:
        log(f"hit CK_PAGES={max_pages} on {surface_name}; stopping pagination")
    return out


def authsystem_hostnames(system):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(system, dict):
        add(system.get("displayName"))
        add(system.get("authorizationSystemName"))
        add(system.get("authorizationSystemId"))
        add(system.get("authorizationSystemType"))
    return out


def collect_authsystem_refs(system):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(system, dict):
        return refs
    sid = _str(system.get("id"))
    if sid:
        add(f"CloudKnox-Id: {sid}")
    asid = _str(system.get("authorizationSystemId"))
    if asid:
        add(f"CloudKnox-AuthSystemId: {asid}")
    asname = _str(system.get("authorizationSystemName"))
    if asname:
        add(f"CloudKnox-AuthSystemName: {asname}")
    astype = _str(system.get("authorizationSystemType"))
    if astype:
        add(f"CloudKnox-AuthSystemType: {astype}")
    display = _str(system.get("displayName"))
    if display:
        add(f"CloudKnox-DisplayName: {display}")
    status = _str(system.get("status"))
    if status:
        add(f"CloudKnox-Status: {status}")
    return refs


def build_authsystem_host(system, authsystem_id_filter):
    """Build a Faraday host dict for a CloudKnox authorization-system record."""
    if not isinstance(system, dict):
        return None
    hostnames = authsystem_hostnames(system)
    primary = hostnames[0] if hostnames else _str(system.get("id")) or "unknown auth system"

    desc_parts = []
    for key in (
        "id",
        "authorizationSystemId",
        "authorizationSystemName",
        "authorizationSystemType",
        "displayName",
        "status",
        "dataCollectionInfo",
    ):
        v = system.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if authsystem_id_filter:
        desc_parts.append(f"ck_authsystem_id: {authsystem_id_filter}")

    vuln = {
        "name": f"[IDENTITY] CloudKnox auth system: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(system.get("id"))[:200]
        or _str(system.get("authorizationSystemId"))[:200]
        or f"cloudknox-authsystem-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "CloudKnox authorization systems are CIEM inventory "
            "entries, not vulnerabilities.  Cross-check the "
            "auth-system (AWS account / Azure subscription / GCP "
            "project) against the other agents' findings — "
            "anything reported against the identities or "
            "principals inside this auth-system indicates a real "
            "exposure on a known cloud boundary.  Disconnect or "
            "re-onboard the auth-system in the Entra Permissions "
            "Management console if it should no longer be in scope."
        ),
        "data": "",
        "refs": collect_authsystem_refs(system),
        "cve": [],
        "cvss3": {},
        "tags": ["cloudknox", "identity", "ciem", "authorization-system"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"CloudKnox auth system {primary}",
        "vulnerabilities": [vuln],
    }


def _principal_label(principal):
    """Best-effort label for a CloudKnox principal payload."""
    if isinstance(principal, dict):
        for key in ("displayName", "principalName", "userPrincipalName", "name", "id"):
            v = principal.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""
    if isinstance(principal, str):
        return principal.strip()
    return ""


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
        add(_principal_label(finding.get("principal")))
        add(finding.get("findingType"))
        add(finding.get("authorizationSystemId"))
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
        add(f"CloudKnox-FindingId: {fid}")
    ftype = _str(finding.get("findingType"))
    if ftype:
        add(f"CloudKnox-FindingType: {ftype}")
    risk = _str(finding.get("riskLevel"))
    if risk:
        add(f"CloudKnox-RiskLevel: {risk}")
    principal_label = _principal_label(finding.get("principal"))
    if principal_label:
        add(f"CloudKnox-Principal: {principal_label}")
    asid = _str(finding.get("authorizationSystemId"))
    if asid:
        add(f"CloudKnox-AuthSystemId: {asid}")
    status = _str(finding.get("status"))
    if status:
        add(f"CloudKnox-Status: {status}")
    created = _str(finding.get("createdDateTime"))
    if created:
        add(f"CloudKnox-Created: {created}")
    modified = _str(finding.get("lastModifiedDateTime"))
    if modified:
        add(f"CloudKnox-Modified: {modified}")
    return refs


def build_finding_host(finding, authsystem_id_filter, risk_level_filter):
    """Build a Faraday host dict for a CloudKnox finding record."""
    if not isinstance(finding, dict):
        return None
    hostnames = finding_hostnames(finding)
    ftype = _str(finding.get("findingType")) or "unknown finding"
    principal_label = _principal_label(finding.get("principal"))
    label = f"[IDENTITY] CloudKnox finding: {ftype}"
    if principal_label:
        label = f"{label} ({principal_label})"

    desc_parts = []
    for key in (
        "id",
        "findingType",
        "riskLevel",
        "principal",
        "authorizationSystemId",
        "recommendation",
        "status",
        "createdDateTime",
        "lastModifiedDateTime",
    ):
        v = finding.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if authsystem_id_filter:
        desc_parts.append(f"ck_authsystem_id: {authsystem_id_filter}")
    if risk_level_filter:
        desc_parts.append(f"ck_risk_level: {risk_level_filter}")

    recommendation = _str(finding.get("recommendation"))
    resolution = recommendation or (
        "CloudKnox findings are CIEM observations — over-privileged "
        "identities, dormant permissions or risky entitlement "
        "patterns surfaced by Entra Permissions Management.  Review "
        "the principal in the Permissions Management console, apply "
        "the recommended permission right-sizing, and re-run the "
        "evaluation to confirm the Permission Creep Index drops "
        "after remediation."
    )

    vuln = {
        "name": label[:200],
        "desc": "\n".join(desc_parts),
        "severity": map_risk_level(finding.get("riskLevel")),
        "external_id": _str(finding.get("id"))[:200] or f"cloudknox-finding-{ftype}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_finding_refs(finding),
        "cve": [],
        "cvss3": {},
        "tags": ["cloudknox", "identity", "ciem", "finding"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"CloudKnox finding {ftype}",
        "vulnerabilities": [vuln],
    }


def main():
    started = time.time()

    authsystem_id = validate_authsystem_id(env("EXECUTOR_CONFIG_CK_AUTHSYSTEM_ID"))
    risk_level = validate_risk_level(env("EXECUTOR_CONFIG_CK_RISK_LEVEL"))
    pages = validate_pages(env("CK_PAGES"))

    tenant_id = env("AZURE_TENANT_ID")
    client_id = env("AZURE_CLIENT_ID")
    client_secret = env("AZURE_CLIENT_SECRET")
    if not tenant_id or not client_id or not client_secret:
        log("AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_access_token(requests, tenant_id, client_id, client_secret)
    if not token:
        log("Failed to acquire Azure AD access token; exiting")
        sys.exit(1)
    headers = auth_headers(token)

    authsystems_url = build_authsystems_url(authsystem_id)
    findings_url = build_findings_url(authsystem_id, risk_level)

    authsystem_hits = fetch_all(
        requests,
        authsystems_url,
        headers,
        pages,
        "/permissionManagement/authorizationSystems",
    )
    finding_hits = fetch_all(
        requests,
        findings_url,
        headers,
        pages,
        "/permissionManagement/findings",
    )

    log(
        f"Processing {len(authsystem_hits)} CloudKnox authorization "
        f"systems + {len(finding_hits)} findings "
        f"(authsystem_id={authsystem_id!r}, "
        f"risk_level={risk_level!r}, pages={pages})"
    )

    hosts_out = []
    for s in authsystem_hits:
        built = build_authsystem_host(s, authsystem_id)
        if built is not None:
            hosts_out.append(built)
    for f in finding_hits:
        built = build_finding_host(f, authsystem_id, risk_level)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "cloudknox",
            "command": "cloudknox",
            "params": (f"authsystem_id={authsystem_id}," f"risk_level={risk_level}," f"pages={pages}"),
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
