#!/usr/bin/env python
"""BeyondTrust Password Safe importer.

Pulls vaulted asset inventory, managed-account records and
privileged-session reports from a BeyondTrust Password Safe (BT
PAM) deployment via the BeyondTrust REST API and emits Faraday
bulk-create JSON to stdout.  BeyondTrust Password Safe is the BT
PAM (Privileged Access Management) platform that vaults privileged
credentials, rotates passwords and SSH keys, brokers privileged
sessions and records every keystroke / RDP frame on managed
endpoints — so this executor is the privileged-credential and
session-replay feed Faraday operators correlate the IAM / EDR /
identity / vuln-scanner agents' findings against to confirm
whether a vulnerable host also has vaulted accounts an attacker
could escalate through, and whether the privileged-session feed
shows recent activity on the same machine.

Each BeyondTrust asset becomes one Faraday host — vaulted assets
ARE network-keyed (the BT asset record is anchored to a managed
endpoint with an IP) so the executor lifts the asset's
``IPAddress`` / ``IPv4Address`` field onto ``host.ip`` when
present and falls back to the ``0.0.0.0`` sentinel otherwise; the
``AssetName`` / ``DnsName`` / ``WorkgroupName`` projection lands
on ``host.hostnames``; ``OperatingSystem`` lands on ``host.os``;
``MacAddress`` lands on ``host.mac``; ``AssetID`` / ``DomainName``
/ ``Description`` enrichment lands on ``host.description``; the
asset record itself becomes one Faraday vulnerability with the
``[SECRETS]`` engine prefix so the finding lands in the workspace
alongside the other secrets-management feeds.  Each BeyondTrust
managed-account record becomes one Faraday host on the
``0.0.0.0`` sentinel — managed accounts are vault-credential
records, not network endpoints — and one Faraday vulnerability
that surfaces credential-hygiene state (last-change timestamp,
auto-management status, password rule, account category).  Each
BeyondTrust session report becomes one Faraday host on the
``0.0.0.0`` sentinel and one Faraday vulnerability that records
who connected to what, when, and via which protocol — the
forensic trail Faraday operators pivot through when correlating
an alert against privileged-session activity.

Endpoints used:
  POST {BT_HOST}/BeyondTrust/api/public/v3/Auth/SignAppin
      -> establishes the BeyondTrust API session.  BT uses a
      stateful auth model: the PS-Auth header authenticates the
      SignAppin call which seeds the response with session
      cookies; subsequent GETs ride the cookie jar.  We log the
      response and continue on failure — many BT installs accept
      stateless calls using only the PS-Auth header, so the
      executor gracefully degrades when SignAppin is unavailable.
  GET {BT_HOST}/BeyondTrust/api/public/v3/Assets?limit=N&offset=M&nameFilter=<BT_FILTER>
      -> the canonical Password Safe asset inventory.  Returns a
      bare JSON array ``[{...asset...}]`` (the BT REST API uses
      array-at-root envelopes on list endpoints — there is no
      ``{value: ...}`` / ``{results: ...}`` wrapper).  Each
      record carries ``AssetID``, ``AssetName``, ``DnsName``,
      ``IPAddress`` / ``IPv4Address``, ``WorkgroupID``,
      ``WorkgroupName``, ``OperatingSystem``, ``DomainName``,
      ``MacAddress``, ``Description``, ``LastUpdated``.  When
      ``BT_FILTER`` is set the dispatcher forwards it as the
      ``?nameFilter=`` query parameter so the walk only returns
      assets whose name matches.
  GET {BT_HOST}/BeyondTrust/api/public/v3/ManagedAccounts?limit=N&offset=M&accountName=<BT_FILTER>
      -> the vaulted-account inventory.  Same bare-array
      envelope; each record carries ``ManagedAccountID``,
      ``ManagedSystemID``, ``DomainName``, ``AccountName``,
      ``DistinguishedName``, ``UserPrincipalName``,
      ``LastChangeDate``, ``NextChangeDate``,
      ``IsChangeOnRelease``, ``ChangeFrequencyType``,
      ``AccountType``, ``ApplicationDisplayName``, ``Description``.
      ``BT_FILTER`` is forwarded as ``?accountName=`` so the walk
      narrows to a specific vaulted account name.
  GET {BT_HOST}/BeyondTrust/api/public/v3/Sessions/Reports?limit=N&offset=M&userID=<BT_FILTER>
      -> the privileged-session report feed.  Each record carries
      ``SessionID``, ``UserID``, ``LoginAccount``, ``NodeID``,
      ``Protocol``, ``StartTime``, ``EndTime``, ``Duration``,
      ``AssetName``, ``ManagedSystemID``, ``Status``, ``Reason``,
      ``ClientIPAddress``.  ``BT_FILTER`` is forwarded as
      ``?userID=`` so the walk narrows to a single requesting
      user when BT_FILTER is a numeric BT user id.

Pagination is offset-based via ``limit`` + ``offset`` query
parameters on all three surfaces.  We walk page-by-page until
either the response returns fewer than ``PER_PAGE`` records or
the env-only ``BT_PAGES`` cap is reached (default 5, clamped to
[1, 50]).  ``limit`` is fixed at 100 (BeyondTrust's default for
list endpoints; the hard cap is 1000 but smaller pages keep
response sizes manageable for the dispatcher event loop).

Auth: BeyondTrust uses the ``PS-Auth`` header scheme.  Operators
create an API registration in the Password Safe admin console
under ``Configuration -> General -> API Registrations`` (api
authentication policy: ``Key``) which mints a long-lived API key.
The dispatcher carries it on every request as
``Authorization: PS-Auth key=<BT_API_KEY>; runas=<BT_RUN_AS>;``.
``BT_RUN_AS`` is the BT user account the API key impersonates —
required by Password Safe for almost every read endpoint.
``BT_HOST`` is the operator's BeyondTrust appliance host (e.g.
``btvault.mycorp.com``); ``https://`` is added automatically when
the operator pasted in a bare FQDN.

Severity for assets / managed accounts / session reports is
always ``info`` (they're PAM-inventory entries, not findings —
the value is the cross-reference signal, not a vulnerability
score).  Tags: [beyondtrust_passwordsafe, secrets, pam,
asset|managed-account|session].
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

TIMEOUT = 60
PER_PAGE = 100  # BeyondTrust's documented default page size.
DEFAULT_PAGES = 5
MAX_PAGES = 50

# Sentinel IP used for non-IP-keyed records (managed accounts,
# session reports, and assets that arrive without an IPAddress
# field — some BT deployments redact the IP for non-network
# managed systems like databases).
SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - BeyondTrustPasswordSafe: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on BT_HOST.

    No default — the BeyondTrust appliance host is operator-
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


def validate_filter(value):
    """Validate BT_FILTER (the operator-supplied name/account filter).

    None / blank -> ``""`` (no narrowing; every asset / managed
    account / session report is walked).  Whitespace is trimmed.
    Forwarded into the per-surface filter query parameter:
    ``?nameFilter=`` on Assets, ``?accountName=`` on
    ManagedAccounts, ``?userID=`` on Sessions/Reports.
    BeyondTrust accepts both literal names and numeric ids in
    those slots — the executor URL-encodes whatever the operator
    pasted in.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_pages(value):
    """Validate BT_PAGES (per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    BeyondTrust API.  Not exposed as a manifest argument (the
    playbook only lists BT_FILTER) but read from the env so a
    tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"BT_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"BT_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def auth_headers(api_key, run_as):
    """Return the BeyondTrust PS-Auth header set.

    BeyondTrust's REST API uses a non-standard
    ``Authorization: PS-Auth key=<key>; runas=<user>;`` scheme.
    Both the key and the runas user are required for almost every
    read endpoint.  We assemble the value defensively (skipping
    missing fragments) so an empty BT_API_KEY produces a header
    that surfaces a clean 401 rather than a malformed value the
    appliance silently drops.
    """
    parts = []
    if api_key:
        parts.append(f"key={api_key}")
    if run_as:
        parts.append(f"runas={run_as}")
    ps_auth = "; ".join(parts)
    if ps_auth:
        ps_auth = f"{ps_auth};"
    return {
        "Authorization": f"PS-Auth {ps_auth}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def build_assets_url(host, filter_value, offset):
    base = f"{normalize_base_url(host)}/BeyondTrust/api/public/v3/Assets"
    params = [f"limit={PER_PAGE}", f"offset={int(offset)}"]
    if filter_value:
        params.append(f"nameFilter={quote(filter_value, safe='')}")
    return f"{base}?{'&'.join(params)}"


def build_managed_accounts_url(host, filter_value, offset):
    base = f"{normalize_base_url(host)}" f"/BeyondTrust/api/public/v3/ManagedAccounts"
    params = [f"limit={PER_PAGE}", f"offset={int(offset)}"]
    if filter_value:
        params.append(f"accountName={quote(filter_value, safe='')}")
    return f"{base}?{'&'.join(params)}"


def build_session_reports_url(host, filter_value, offset):
    base = f"{normalize_base_url(host)}" f"/BeyondTrust/api/public/v3/Sessions/Reports"
    params = [f"limit={PER_PAGE}", f"offset={int(offset)}"]
    if filter_value:
        params.append(f"userID={quote(filter_value, safe='')}")
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


def sign_in(client, host, api_key, run_as):
    """POST /Auth/SignAppin to establish a BeyondTrust API session.

    BeyondTrust's stateful auth model expects a SignAppin call
    before list endpoints will return data on certain hardened
    installs; on the more permissive default install the PS-Auth
    header alone is enough.  We attempt SignAppin and log the
    outcome — failure does not abort the executor (we fall
    through to the stateless code path on 404 / 405 / 200 with no
    cookies).  401 short-circuits because the operator
    credentials are wrong and walking further is wasted work.
    """
    base = normalize_base_url(host)
    if not base:
        return False
    url = f"{base}/BeyondTrust/api/public/v3/Auth/SignAppin"
    headers = auth_headers(api_key, run_as)
    try:
        resp = client.post(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        return False
    if resp.status_code == 401:
        log("BeyondTrust SignAppin rejected (401). " "Check BT_API_KEY / BT_RUN_AS.")
        sys.exit(1)
    if resp.status_code in (404, 405):
        log(f"BeyondTrust SignAppin returned {resp.status_code}; " f"falling through to stateless PS-Auth calls.")
        return False
    if resp.status_code >= 400:
        log(f"BeyondTrust SignAppin failed ({resp.status_code}): " f"{getattr(resp, 'text', '')[:500]}")
        return False
    return True


def sign_out(client, host, api_key, run_as):
    """POST /Auth/Signout — best-effort session cleanup."""
    base = normalize_base_url(host)
    if not base:
        return
    url = f"{base}/BeyondTrust/api/public/v3/Auth/Signout"
    headers = auth_headers(api_key, run_as)
    try:
        client.post(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — best-effort cleanup
        log(f"POST {url} failed: {exc}")


def fetch_all(client, build_url, host, headers, max_pages, surface_name, **build_kwargs):
    """Walk a BeyondTrust list endpoint via offset pagination.

    Pages until either the response returns fewer than
    ``PER_PAGE`` records or ``max_pages`` is reached.  401
    short-circuits the whole executor because the operator
    credentials are wrong.  403 / 429 just stop pagination on the
    surface we're walking and return what we have.  The
    BeyondTrust REST API uses bare-array envelopes
    (``[{...}, {...}]``) on list endpoints, so we accept both a
    list-at-root and a defensive ``{value|results: [...]}``
    wrapper without forcing the shape.
    """
    out = []
    offset = 0
    pages = 0
    while pages < max_pages:
        url = build_url(host, offset=offset, **build_kwargs)
        try:
            resp = client.get(url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("BeyondTrust request rejected (401). " "Bearer / cookies expired or invalid.")
            sys.exit(1)
        if resp.status_code == 403:
            log(
                f"BeyondTrust {surface_name} request rejected (403). "
                f"Check the API registration's scope / role mapping."
            )
            return out
        if resp.status_code == 429:
            log(f"BeyondTrust rate-limited (429) on {surface_name}; " f"stopping pagination.")
            return out
        if resp.status_code == 404:
            log(f"BeyondTrust {surface_name} returned 404 — " f"endpoint missing on this appliance version.")
            return out
        if resp.status_code >= 400:
            log(f"BeyondTrust {surface_name} failed " f"({resp.status_code}): " f"{getattr(resp, 'text', '')[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"BeyondTrust {surface_name} response was not JSON")
            return out
        results = []
        if isinstance(payload, list):
            results = [r for r in payload if isinstance(r, dict)]
        elif isinstance(payload, dict):
            for key in ("value", "results", "Data", "Items"):
                raw = payload.get(key)
                if isinstance(raw, list):
                    results = [r for r in raw if isinstance(r, dict)]
                    break
        out.extend(results)
        if len(results) < PER_PAGE:
            return out
        offset += PER_PAGE
        pages += 1
    log(f"hit BT_PAGES={max_pages} on {surface_name}; stopping pagination")
    return out


def asset_hostnames(asset):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(asset, dict):
        add(asset.get("AssetName"))
        add(asset.get("DnsName"))
        add(asset.get("WorkgroupName"))
        add(asset.get("DomainName"))
    return out


def _asset_ip(asset):
    """Lift the asset's IP onto host.ip when present, sentinel otherwise.

    BeyondTrust exposes both ``IPAddress`` (string) and
    ``IPv4Address`` (string) on its asset records depending on
    appliance version; we prefer the v3-canonical ``IPAddress``
    field but fall back to ``IPv4Address`` for older builds.
    """
    if not isinstance(asset, dict):
        return SENTINEL_IP
    for key in ("IPAddress", "IPv4Address"):
        v = _str(asset.get(key))
        if v:
            return v
    return SENTINEL_IP


def collect_asset_refs(asset):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(asset, dict):
        return refs
    aid = _str(asset.get("AssetID"))
    if aid:
        add(f"BeyondTrust-AssetID: {aid}")
    aname = _str(asset.get("AssetName"))
    if aname:
        add(f"BeyondTrust-AssetName: {aname}")
    dns = _str(asset.get("DnsName"))
    if dns:
        add(f"BeyondTrust-DnsName: {dns}")
    workgroup = _str(asset.get("WorkgroupName"))
    if workgroup:
        add(f"BeyondTrust-Workgroup: {workgroup}")
    domain = _str(asset.get("DomainName"))
    if domain:
        add(f"BeyondTrust-Domain: {domain}")
    op_sys = _str(asset.get("OperatingSystem"))
    if op_sys:
        add(f"BeyondTrust-OS: {op_sys}")
    mac = _str(asset.get("MacAddress"))
    if mac:
        add(f"BeyondTrust-MAC: {mac}")
    updated = _str(asset.get("LastUpdated"))
    if updated:
        add(f"BeyondTrust-LastUpdated: {updated}")
    return refs


def build_asset_host(asset, filter_value):
    """Build a Faraday host dict for a BeyondTrust asset record."""
    if not isinstance(asset, dict):
        return None
    hostnames = asset_hostnames(asset)
    primary = hostnames[0] if hostnames else (_str(asset.get("AssetID")) or "unknown asset")

    desc_parts = []
    for key in (
        "AssetID",
        "AssetName",
        "DnsName",
        "IPAddress",
        "IPv4Address",
        "WorkgroupID",
        "WorkgroupName",
        "OperatingSystem",
        "DomainName",
        "MacAddress",
        "Description",
        "LastUpdated",
    ):
        v = asset.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if filter_value:
        desc_parts.append(f"bt_filter: {filter_value}")

    vuln = {
        "name": f"[SECRETS] BeyondTrust asset: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(asset.get("AssetID"))[:200] or f"beyondtrust-asset-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "BeyondTrust assets are Password Safe inventory entries "
            "— vaulted endpoints whose privileged credentials sit in "
            "the BT secrets store.  Cross-check the asset against "
            "the other agents' findings — anything reported against "
            "this machine indicates a real exposure on a host whose "
            "privileged credentials are vault-managed and may be "
            "in scope for credential-rotation or break-glass "
            "audit.  Confirm in the Password Safe console that the "
            "asset is still actively managed and that recent "
            "password-change events have completed successfully."
        ),
        "data": "",
        "refs": collect_asset_refs(asset),
        "cve": [],
        "cvss3": {},
        "tags": ["beyondtrust_passwordsafe", "secrets", "pam", "asset"],
    }
    return {
        "ip": _asset_ip(asset),
        "os": _str(asset.get("OperatingSystem")),
        "hostnames": hostnames,
        "mac": _str(asset.get("MacAddress")),
        "description": f"BeyondTrust asset {primary}",
        "vulnerabilities": [vuln],
    }


def managed_account_hostnames(account):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(account, dict):
        add(account.get("AccountName"))
        add(account.get("UserPrincipalName"))
        add(account.get("DomainName"))
        add(account.get("ApplicationDisplayName"))
    return out


def collect_managed_account_refs(account):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(account, dict):
        return refs
    mid = _str(account.get("ManagedAccountID"))
    if mid:
        add(f"BeyondTrust-ManagedAccountID: {mid}")
    msid = _str(account.get("ManagedSystemID"))
    if msid:
        add(f"BeyondTrust-ManagedSystemID: {msid}")
    aname = _str(account.get("AccountName"))
    if aname:
        add(f"BeyondTrust-AccountName: {aname}")
    domain = _str(account.get("DomainName"))
    if domain:
        add(f"BeyondTrust-Domain: {domain}")
    upn = _str(account.get("UserPrincipalName"))
    if upn:
        add(f"BeyondTrust-UPN: {upn}")
    dn = _str(account.get("DistinguishedName"))
    if dn:
        add(f"BeyondTrust-DN: {dn}")
    last_change = _str(account.get("LastChangeDate"))
    if last_change:
        add(f"BeyondTrust-LastChange: {last_change}")
    next_change = _str(account.get("NextChangeDate"))
    if next_change:
        add(f"BeyondTrust-NextChange: {next_change}")
    change_freq = _str(account.get("ChangeFrequencyType"))
    if change_freq:
        add(f"BeyondTrust-ChangeFreq: {change_freq}")
    atype = _str(account.get("AccountType"))
    if atype:
        add(f"BeyondTrust-AccountType: {atype}")
    app = _str(account.get("ApplicationDisplayName"))
    if app:
        add(f"BeyondTrust-Application: {app}")
    return refs


def build_managed_account_host(account, filter_value):
    """Build a Faraday host dict for a BeyondTrust managed-account record."""
    if not isinstance(account, dict):
        return None
    hostnames = managed_account_hostnames(account)
    aname = _str(account.get("AccountName")) or "unknown account"

    desc_parts = []
    for key in (
        "ManagedAccountID",
        "ManagedSystemID",
        "AccountName",
        "DomainName",
        "UserPrincipalName",
        "DistinguishedName",
        "LastChangeDate",
        "NextChangeDate",
        "IsChangeOnRelease",
        "ChangeFrequencyType",
        "AccountType",
        "ApplicationDisplayName",
        "Description",
    ):
        v = account.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if filter_value:
        desc_parts.append(f"bt_filter: {filter_value}")

    vuln = {
        "name": f"[SECRETS] BeyondTrust managed account: {aname}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(account.get("ManagedAccountID"))[:200] or f"beyondtrust-account-{aname}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "BeyondTrust managed accounts are vaulted privileged "
            "credentials.  Cross-check the account against the "
            "other agents' findings — anything reported against "
            "the underlying host or identity indicates a real "
            "exposure on a credential that lives in the BT secrets "
            "store.  Confirm in the Password Safe console that the "
            "credential is on a current rotation schedule and "
            "review the LastChangeDate / NextChangeDate fields for "
            "stale auto-management state."
        ),
        "data": "",
        "refs": collect_managed_account_refs(account),
        "cve": [],
        "cvss3": {},
        "tags": ["beyondtrust_passwordsafe", "secrets", "pam", "managed-account"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"BeyondTrust managed account {aname}",
        "vulnerabilities": [vuln],
    }


def session_hostnames(report):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(report, dict):
        add(report.get("AssetName"))
        add(report.get("LoginAccount"))
        add(report.get("ClientIPAddress"))
    return out


def collect_session_refs(report):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(report, dict):
        return refs
    sid = _str(report.get("SessionID"))
    if sid:
        add(f"BeyondTrust-SessionID: {sid}")
    uid = _str(report.get("UserID"))
    if uid:
        add(f"BeyondTrust-UserID: {uid}")
    login = _str(report.get("LoginAccount"))
    if login:
        add(f"BeyondTrust-LoginAccount: {login}")
    node = _str(report.get("NodeID"))
    if node:
        add(f"BeyondTrust-NodeID: {node}")
    proto = _str(report.get("Protocol"))
    if proto:
        add(f"BeyondTrust-Protocol: {proto}")
    start = _str(report.get("StartTime"))
    if start:
        add(f"BeyondTrust-StartTime: {start}")
    end = _str(report.get("EndTime"))
    if end:
        add(f"BeyondTrust-EndTime: {end}")
    duration = _str(report.get("Duration"))
    if duration:
        add(f"BeyondTrust-Duration: {duration}")
    asset = _str(report.get("AssetName"))
    if asset:
        add(f"BeyondTrust-Asset: {asset}")
    msid = _str(report.get("ManagedSystemID"))
    if msid:
        add(f"BeyondTrust-ManagedSystemID: {msid}")
    status = _str(report.get("Status"))
    if status:
        add(f"BeyondTrust-Status: {status}")
    reason = _str(report.get("Reason"))
    if reason:
        add(f"BeyondTrust-Reason: {reason}")
    client_ip = _str(report.get("ClientIPAddress"))
    if client_ip:
        add(f"BeyondTrust-ClientIP: {client_ip}")
    return refs


def build_session_host(report, filter_value):
    """Build a Faraday host dict for a BeyondTrust session-report record."""
    if not isinstance(report, dict):
        return None
    hostnames = session_hostnames(report)
    sid = _str(report.get("SessionID")) or "unknown session"
    asset = _str(report.get("AssetName"))
    login = _str(report.get("LoginAccount"))
    label = f"[SECRETS] BeyondTrust session: {sid}"
    if asset and login:
        label = f"{label} ({login}@{asset})"
    elif asset:
        label = f"{label} (@{asset})"
    elif login:
        label = f"{label} ({login})"

    desc_parts = []
    for key in (
        "SessionID",
        "UserID",
        "LoginAccount",
        "NodeID",
        "Protocol",
        "StartTime",
        "EndTime",
        "Duration",
        "AssetName",
        "ManagedSystemID",
        "Status",
        "Reason",
        "ClientIPAddress",
    ):
        v = report.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if filter_value:
        desc_parts.append(f"bt_filter: {filter_value}")

    vuln = {
        "name": label[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(report.get("SessionID"))[:200] or f"beyondtrust-session-{sid}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "BeyondTrust session reports are privileged-session "
            "forensic records — who connected to what, when, and "
            "via which protocol.  Cross-check the session against "
            "the other agents' findings — a session that overlaps "
            "with an alert on the same asset or identity is the "
            "pivot point for a privileged-access investigation.  "
            "Review the full session recording in the Password "
            "Safe console (Sessions -> Reports -> View Recording) "
            "to confirm intent."
        ),
        "data": "",
        "refs": collect_session_refs(report),
        "cve": [],
        "cvss3": {},
        "tags": ["beyondtrust_passwordsafe", "secrets", "pam", "session"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"BeyondTrust session {sid}",
        "vulnerabilities": [vuln],
    }


def main():
    started = time.time()

    bt_filter = validate_filter(env("EXECUTOR_CONFIG_BT_FILTER"))
    pages = validate_pages(env("BT_PAGES"))

    host = env("BT_HOST", required=True)
    api_key = env("BT_API_KEY", required=True)
    run_as = env("BT_RUN_AS", required=True)

    if not normalize_base_url(host):
        log("BT_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    session = requests.Session()
    sign_in(session, host, api_key, run_as)
    headers = auth_headers(api_key, run_as)

    asset_hits = fetch_all(
        session,
        build_assets_url,
        host,
        headers,
        pages,
        "/Assets",
        filter_value=bt_filter,
    )
    account_hits = fetch_all(
        session,
        build_managed_accounts_url,
        host,
        headers,
        pages,
        "/ManagedAccounts",
        filter_value=bt_filter,
    )
    session_hits = fetch_all(
        session,
        build_session_reports_url,
        host,
        headers,
        pages,
        "/Sessions/Reports",
        filter_value=bt_filter,
    )

    log(
        f"Processing {len(asset_hits)} BeyondTrust assets + "
        f"{len(account_hits)} managed accounts + "
        f"{len(session_hits)} session reports "
        f"(filter={bt_filter!r}, pages={pages})"
    )

    hosts_out = []
    for a in asset_hits:
        built = build_asset_host(a, bt_filter)
        if built is not None:
            hosts_out.append(built)
    for m in account_hits:
        built = build_managed_account_host(m, bt_filter)
        if built is not None:
            hosts_out.append(built)
    for s in session_hits:
        built = build_session_host(s, bt_filter)
        if built is not None:
            hosts_out.append(built)

    sign_out(session, host, api_key, run_as)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "beyondtrust_passwordsafe",
            "command": "beyondtrust_passwordsafe",
            "params": (f"filter={bt_filter}," f"pages={pages}"),
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
