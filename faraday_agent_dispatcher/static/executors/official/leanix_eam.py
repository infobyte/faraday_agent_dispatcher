#!/usr/bin/env python
"""LeanIX EAM (Enterprise Architecture Management) asset-inventory importer.

Pulls factSheet records (Application / BusinessCapability / ITComponent
/ Project / DataObject / Interface / TechnicalStack / etc.) from a
LeanIX (now SAP LeanIX) EAM tenant and emits Faraday bulk-create JSON
to stdout.  Each LeanIX factSheet becomes one Faraday host (synthetic
0.0.0.0 — factSheets are identity-keyed entries in an EAM CMDB, not
network endpoints) and one Faraday vulnerability with the engine
prefix ``[ASSET-INVENTORY]``; severity is always ``info`` since
factSheets are inventory records not findings — operators correlate
against the other agents' findings (EDR / EASM / vuln scanners) via
the LeanIX-Id / LeanIX-FactSheet refs.

Endpoints used:
  POST <LEANIX_HOST>/services/mtm/v1/oauth2/token
      -> exchange the LEANIX_API_TOKEN for a short-lived OAuth2
      bearer.  LeanIX uses OAuth2 client_credentials with
      ``apitoken`` as the username and the LEANIX_API_TOKEN as the
      password (HTTP Basic) plus ``grant_type=client_credentials``
      on the form-encoded body.  The returned ``access_token`` is
      then carried on every /services/pathfinder/ call as
      ``Authorization: Bearer <access_token>``.
  GET <LEANIX_HOST>/services/pathfinder/v1/factSheets
      -> paginated factSheet inventory.  Pagination is LeanIX's
      cursor-based ``pageSize`` + ``pageToken`` (PAGE_SIZE=100 per
      page capped at MAX_PAGES=200 = 20k records per scan).
      Optional ``factSheetType=<type>`` query param scopes which
      factSheet family is pulled (Application / BusinessCapability
      / ITComponent / Project / DataObject / Interface / etc.).
      Optional ``workspaceId=<uuid>`` query param scopes to a
      specific LeanIX workspace (defence-in-depth — the API token's
      scope already determines which workspace it sees).
      Response envelope: ``{"type": "Pagination", "total": N,
      "data": [{"id": "...", "type": "...", "name": "...",
      "displayName": "...", ...}], "pageToken": "..."}``.

Auth: LeanIX EAM issues per-workspace API tokens via the LeanIX
console under ``Administration -> Technical Users``.  The dispatcher
exchanges the API token for a short-lived OAuth2 bearer
(client_credentials) at POST /services/mtm/v1/oauth2/token, then
carries the bearer on every subsequent /services/pathfinder/ call as
``Authorization: Bearer <access_token>``.  ``LEANIX_HOST`` is the
LeanIX tenant host (e.g. ``https://app.leanix.net`` for SaaS — the
canonical SaaS host — or ``https://<tenant>.leanix.net`` for
tenant-specific subdomains; on-prem / EU / US-region deployments
override the host).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# LeanIX host validation — accept http(s)://host[:port], strip
# trailing slash.  Control chars (newline / tab / null / etc)
# rejected outright so a header-injection attempt can't sneak
# through.  Anchored with \A/\Z (not ^/$) so a trailing newline
# cannot sneak through — Python's default `$` matches just before
# a trailing `\n`.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")
# LeanIX workspace id — typically a uuid4 but LeanIX also accepts
# tenant-scoped slug names.  Allow either shape: alphanumeric + `_-.`
# up to 64 chars (gives room for tenant slugs like "acme-prod" plus
# 36-char uuids).
WORKSPACE_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._\-]{0,63}\Z")
# LeanIX factSheet type — PascalCase enum, alphanumeric only.
# Examples: Application / BusinessCapability / ITComponent / Project
# / DataObject / Interface / TechnicalStack / Provider / UserGroup.
FACTSHEET_TYPE_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9]{0,63}\Z")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100
DEFAULT_HOST = "https://app.leanix.net"

# LeanIX factSheet records are inventory entries, not findings, so
# severity is always `info` for parity with the other CMDB-class
# connectors in asset-inventory (Axonius / Device42 / Fleet / Armis
# / Jamf Pro / Jira Insight / runZero).
SEVERITY_INFO = "info"


def log(msg):
    print(f"{datetime.utcnow()} - LeanIX: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def validate_host(value):
    """Validate LEANIX_HOST.

    None / blank -> DEFAULT_HOST (``https://app.leanix.net`` — the
    canonical SaaS host).  Must be ``http(s)://host[:port]``;
    trailing slash stripped client-side.  Control chars rejected so
    a header-injection attempt can't sneak through.
    """
    if value is None or value == "":
        return DEFAULT_HOST
    raw = str(value)
    # Reject any control char (incl. CR / LF / NUL) on the *raw* value
    # before .strip() runs — .strip() would otherwise eat trailing
    # newlines so a header-injection attempt could sneak through.
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("LEANIX_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return DEFAULT_HOST
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"LEANIX_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def validate_workspace_id(value):
    """Validate LEANIX_WORKSPACE_ID.

    None / blank -> ``""`` (optional — when blank the API token's
    scope determines which workspace is pulled).  Otherwise must be
    alphanumeric + ``._-`` up to 64 chars (covers uuid4s + tenant
    slugs).  Control chars rejected on the raw value before .strip()
    runs.
    """
    if value is None or value == "":
        return ""
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("LEANIX_WORKSPACE_ID contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return ""
    if not WORKSPACE_ID_RE.match(text):
        log(f"LEANIX_WORKSPACE_ID '{text}' is not a valid identifier " "(alphanumeric + ._- up to 64 chars)")
        sys.exit(1)
    return text


def validate_factsheet_type(value):
    """Validate LEANIX_FACTSHEET_TYPE.

    None / blank -> ``""`` (optional — when blank the executor fans
    out across all factSheet types in the workspace).  Otherwise
    must be PascalCase alphanumeric only (Application /
    BusinessCapability / ITComponent / Project / DataObject /
    Interface / TechnicalStack / Provider / UserGroup / etc.).
    Control chars rejected on the raw value before .strip() runs.
    """
    if value is None or value == "":
        return ""
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("LEANIX_FACTSHEET_TYPE contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        return ""
    if not FACTSHEET_TYPE_RE.match(text):
        log(
            f"LEANIX_FACTSHEET_TYPE '{text}' is not a valid factSheet type " "(PascalCase alphanumeric up to 64 chars)"
        )
        sys.exit(1)
    return text


def build_token_url(host):
    return f"{host}/services/mtm/v1/oauth2/token"


def build_factsheets_url(host):
    return f"{host}/services/pathfinder/v1/factSheets"


def build_factsheets_params(workspace_id, factsheet_type, page_size, page_token):
    """Build the query-param dict for a LeanIX /factSheets call.

    ``workspaceId`` and ``factSheetType`` are optional — both are
    only included when the operator supplied a non-empty value.
    Pagination is LeanIX's cursor-based ``pageSize`` + ``pageToken``
    (no offset).
    """
    params = {"pageSize": int(page_size)}
    if workspace_id:
        params["workspaceId"] = workspace_id
    if factsheet_type:
        params["factSheetType"] = factsheet_type
    if page_token:
        params["pageToken"] = page_token
    return params


def token_request_basic(api_token):
    """Build the HTTP Basic auth header for the OAuth2 token exchange.

    LeanIX uses ``apitoken`` as the canonical username when exchanging
    an API token for a short-lived bearer (the actual API token goes in
    the password slot).  Built explicitly via base64 so the function
    stays testable without a live ``requests`` install.
    """
    import base64

    raw = f"apitoken:{api_token or ''}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def token_request_body():
    """OAuth2 client_credentials grant — no extra params required."""
    return {"grant_type": "client_credentials"}


def token_request_headers(api_token):
    """Headers for the OAuth2 token exchange call."""
    return {
        "Authorization": token_request_basic(api_token),
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }


def factsheets_headers(access_token):
    """Headers for /services/pathfinder/v1/factSheets calls (Bearer)."""
    return {
        "Authorization": f"Bearer {access_token or ''}",
        "Accept": "application/json",
    }


def extract_access_token(body):
    """Pull the access_token from a LeanIX OAuth2 token response.

    LeanIX uses the standard OAuth2 token-response envelope:
    ``{"access_token": "...", "scope": "...", "token_type":
    "bearer", "expires_in": 3600}``.
    """
    if not isinstance(body, dict):
        return ""
    for key in ("access_token", "accessToken"):
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_results(body):
    """Pull the factSheet list from a LeanIX pagination envelope.

    LeanIX uses ``{"type": "Pagination", "total": N, "data": [...],
    "pageToken": "..."}`` — accept ``items`` / ``results`` /
    ``factSheets`` as alt-keys for federated stacks.
    """
    if not isinstance(body, dict):
        if isinstance(body, list):
            return [entry for entry in body if isinstance(entry, dict)]
        return []
    for key in ("data", "items", "results", "factSheets"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_total(body):
    """Pull the total record count from a LeanIX pagination envelope."""
    if not isinstance(body, dict):
        return None
    for key in ("total", "totalCount", "total_count", "count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def extract_next_page_token(body):
    """Pull the next-page cursor from a LeanIX pagination envelope.

    LeanIX cursor field is ``pageToken`` (string).  Empty / missing
    means the walk is exhausted.
    """
    if not isinstance(body, dict):
        return ""
    for key in ("pageToken", "page_token", "nextPageToken", "next_page_token"):
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _serialise(obj):
    if obj is None:
        return ""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (str, int, float)):
        return str(obj)
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(obj)


def collect_cves(item):
    """Walk a LeanIX factSheet payload for CVE-* ids.

    LeanIX factSheets don't carry CVEs natively (they're EAM
    inventory records, not vulnerability records) but technical-stack
    / interface / IT-component factSheets sometimes carry CVE refs
    in the freeform ``description`` / ``technicalDescription`` text
    so we still scan for them defensively.
    """
    found = []
    seen = set()

    def add(text):
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
        for m in CVE_RE.findall(text):
            add(m)

    if not isinstance(item, dict):
        return found

    for key in ("cve", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "cve_ids"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    for key in (
        "name",
        "displayName",
        "description",
        "technicalDescription",
        "summary",
        "title",
    ):
        scan(item.get(key))

    return found


def collect_refs(item, leanix_host):
    """Walk a LeanIX factSheet payload for advisory URLs / pivots."""
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

    if not isinstance(item, dict):
        return refs

    factsheet_id = item.get("id") or item.get("factSheetId") or item.get("factsheet_id")
    if isinstance(factsheet_id, str) and factsheet_id.strip():
        fid = factsheet_id.strip()
        add(f"LeanIX-Id: {fid}")
        # Canonical LeanIX factSheet permalink — operators can pivot
        # straight from the Faraday vuln into the LeanIX console.
        if isinstance(leanix_host, str) and leanix_host.strip():
            workspace = item.get("workspaceId") or item.get("workspace_id") or ""
            if isinstance(workspace, str) and workspace.strip():
                add(f"{leanix_host.rstrip('/')}/{workspace.strip()}/factsheet/" f"{fid}")

    factsheet_type = item.get("type") or item.get("factSheetType") or item.get("factsheet_type")
    if isinstance(factsheet_type, str) and factsheet_type.strip():
        add(f"LeanIX-FactSheet: {factsheet_type.strip()}")

    workspace_id = item.get("workspaceId") or item.get("workspace_id")
    if isinstance(workspace_id, str) and workspace_id.strip():
        add(f"LeanIX-Workspace: {workspace_id.strip()}")

    status = item.get("status") or item.get("lifecycleStatus") or item.get("factSheetStatus")
    if isinstance(status, str) and status.strip():
        add(f"LeanIX-Status: {status.strip()}")

    completion = item.get("completion") or item.get("qualityScore") or item.get("completionRatio")
    if isinstance(completion, (int, float)):
        add(f"LeanIX-Completion: {completion}")

    for key in ("level", "category", "subType"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            add(f"LeanIX-{key[:1].upper()}{key[1:]}: {v.strip()}")

    for key in ("tags", "labels"):
        v = item.get(key)
        if isinstance(v, list):
            tags = [str(t).strip() for t in v if isinstance(t, (str, int, float)) and str(t).strip()]
            if tags:
                add(f"LeanIX-Tags: {','.join(tags)}")

    for key in ("technicalSuitability", "businessCriticality", "functionalFit"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            add(f"LeanIX-{key[:1].upper()}{key[1:]}: {v.strip()}")
        elif isinstance(v, (int, float)):
            add(f"LeanIX-{key[:1].upper()}{key[1:]}: {v}")

    return refs


def factsheet_label(item):
    """Build the leading title fragment for a LeanIX factSheet."""
    if not isinstance(item, dict):
        return ""
    for key in ("displayName", "name", "fullName", "title"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("id", "factSheetId"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "LeanIX factSheet"


def build_vulnerability(item, leanix_host):
    """Build a Faraday vulnerability dict from a LeanIX factSheet record."""
    if not isinstance(item, dict):
        return None

    factsheet_type = item.get("type") or item.get("factSheetType") or "factSheet"
    label = factsheet_label(item)
    name = f"[ASSET-INVENTORY] LeanIX {factsheet_type}: {label}"

    desc_parts = []
    description = (
        item.get("description") or item.get("Description") or item.get("technicalDescription") or item.get("summary")
    )
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    for label_key, key in (
        ("id", "id"),
        ("type", "type"),
        ("name", "name"),
        ("displayName", "displayName"),
        ("fullName", "fullName"),
        ("status", "status"),
        ("lifecycleStatus", "lifecycleStatus"),
        ("level", "level"),
        ("category", "category"),
        ("subType", "subType"),
        ("completion", "completion"),
        ("qualityScore", "qualityScore"),
        ("technicalSuitability", "technicalSuitability"),
        ("businessCriticality", "businessCriticality"),
        ("functionalFit", "functionalFit"),
        ("createdAt", "createdAt"),
        ("updatedAt", "updatedAt"),
        ("createdBy", "createdBy"),
        ("updatedBy", "updatedBy"),
        ("workspaceId", "workspaceId"),
        ("tags", "tags"),
        ("labels", "labels"),
    ):
        v = item.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    cves = collect_cves(item)
    refs = collect_refs(item, leanix_host)

    external_id = str(
        item.get("id") or item.get("factSheetId") or item.get("factsheet_id") or (cves[0] if cves else "") or label
    )

    return {
        "name": str(name).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": SEVERITY_INFO,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "LeanIX factSheets are EAM inventory entries, not "
            "vulnerabilities. Cross-check the factSheet against the "
            "other agents' findings (EDR / EASM / vuln scanners) — "
            "anything reported against this factSheet id indicates a "
            "real exposure on a known managed asset. Archive or "
            "reclassify the factSheet in LeanIX if it should no "
            "longer appear in the inventory."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["leanix", "asset-inventory", "leanix-eam", str(factsheet_type).lower()],
    }


def factsheet_hostnames(item):
    """Walk a LeanIX factSheet for hostname-like identifiers.

    LeanIX factSheets aren't IP-keyed (they're EAM identity records)
    but they do carry useful name pivots — displayName / fullName /
    name — that we hang on host.hostnames so Faraday's hostname
    index still surfaces the factSheet.
    """
    out = []
    seen = set()
    if not isinstance(item, dict):
        return out
    for key in ("displayName", "fullName", "name", "shortName"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out


def factsheet_os(item):
    """Build the host.os string from a LeanIX factSheet record.

    LeanIX factSheets aren't OS-keyed (they're EAM identity records)
    so host.os carries the factSheet type label (e.g. ``LeanIX
    Application``) so the EAM-class entry is visible alongside the
    other CMDB feeds' host.os pivots.
    """
    if not isinstance(item, dict):
        return "LeanIX factSheet"
    factsheet_type = item.get("type") or item.get("factSheetType")
    if isinstance(factsheet_type, str) and factsheet_type.strip():
        return f"LeanIX {factsheet_type.strip()}"
    return "LeanIX factSheet"


def build_host_from_factsheet(item, leanix_host):
    """Build a Faraday host dict from a LeanIX factSheet record."""
    if not isinstance(item, dict):
        return None
    hostnames = factsheet_hostnames(item)
    os_str = factsheet_os(item)
    vuln = build_vulnerability(item, leanix_host)

    desc_parts = []
    for key in ("type", "status", "lifecycleStatus", "completion", "createdAt", "updatedAt"):
        v = item.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    return {
        "ip": "0.0.0.0",
        "os": os_str,
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts) or "LeanIX factSheet",
        "vulnerabilities": [vuln] if vuln else [],
    }


def fetch_access_token(requests_module, host, api_token):
    """Exchange the LEANIX_API_TOKEN for a short-lived OAuth2 bearer.

    LeanIX uses OAuth2 client_credentials with ``apitoken`` as the
    canonical username + the API token in the password slot (HTTP
    Basic auth on the token endpoint).  The returned ``access_token``
    is then carried on every /services/pathfinder/ call as
    ``Authorization: Bearer <access_token>``.
    """
    url = build_token_url(host)
    headers = token_request_headers(api_token)
    body = token_request_body()
    try:
        resp = requests_module.post(url, headers=headers, data=body, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        sys.exit(1)
    if resp.status_code == 401:
        log("LeanIX token exchange rejected (401). Check LEANIX_API_TOKEN.")
        sys.exit(1)
    if resp.status_code == 403:
        log("LeanIX token exchange rejected (403). Check the token's role / scope.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"LeanIX token exchange failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        sys.exit(1)
    try:
        payload = resp.json()
    except ValueError:
        log(f"LeanIX token response was not JSON ({url})")
        sys.exit(1)
    token = extract_access_token(payload)
    if not token:
        log("LeanIX token response did not include access_token")
        sys.exit(1)
    return token


def fetch_factsheets(
    requests_module,
    host,
    access_token,
    workspace_id,
    factsheet_type,
    max_pages=MAX_PAGES,
    page_size=PAGE_SIZE,
):
    """Walk the LeanIX /services/pathfinder/v1/factSheets catalogue.

    Pagination is LeanIX's cursor-based ``pageSize`` + ``pageToken``
    (no offset).  We page until ``pageToken`` is missing / empty or
    ``max_pages`` is reached.  401 short-circuits the whole executor
    because the operator credentials are wrong.  403 / 429 just stop
    pagination and return what we have.
    """
    out = []
    url = build_factsheets_url(host)
    headers = factsheets_headers(access_token)
    page_token = ""
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_factsheets_params(workspace_id, factsheet_type, page_size, page_token)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("LeanIX request rejected (401). Check LEANIX_API_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("LeanIX request rejected (403). Check the token's role / scope.")
            return out
        if resp.status_code == 429:
            log("LeanIX rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"LeanIX request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"LeanIX response was not JSON ({url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        pages_walked += 1
        next_token = extract_next_page_token(payload)
        if not next_token:
            break
        page_token = next_token
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    workspace_id = validate_workspace_id(env("EXECUTOR_CONFIG_LEANIX_WORKSPACE_ID"))
    factsheet_type = validate_factsheet_type(env("EXECUTOR_CONFIG_LEANIX_FACTSHEET_TYPE"))
    host = validate_host(env("LEANIX_HOST"))
    api_token = env("LEANIX_API_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    access_token = fetch_access_token(requests, host, api_token)
    factsheets = fetch_factsheets(requests, host, access_token, workspace_id, factsheet_type)

    log(f"Processing {len(factsheets)} LeanIX factSheets " f"(workspace={workspace_id!r}, type={factsheet_type!r})")

    hosts_out = []
    for entry in factsheets:
        built = build_host_from_factsheet(entry, host)
        if built is not None:
            hosts_out.append(built)

    if not hosts_out:
        # Synthetic placeholder host so the Faraday workspace still
        # records the LeanIX query was processed, mirroring the
        # convention used by securitybridge_sap / redhat_satellite /
        # ivanti_security_controls / wsus / sccm / tripwire_enterprise.
        hosts_out.append(
            {
                "ip": "0.0.0.0",
                "os": "LeanIX factSheet",
                "hostnames": [],
                "mac": "",
                "description": (
                    f"LeanIX EAM scan returned 0 factSheets " f"(workspace={workspace_id!r}, type={factsheet_type!r})"
                ),
                "vulnerabilities": [],
            }
        )

    params_bits = [
        f"workspace_id={workspace_id}",
        f"factsheet_type={factsheet_type}",
    ]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "leanix_eam",
            "command": "leanix_eam",
            "params": ",".join(params_bits),
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
