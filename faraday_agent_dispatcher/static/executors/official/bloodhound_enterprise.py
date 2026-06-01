#!/usr/bin/env python
"""BloodHound Enterprise (BHE) attack-path importer.

Pulls asset-group inventory and attack-path findings from a
BloodHound Enterprise tenant via the BHE REST API and emits
Faraday bulk-create JSON to stdout.  BHE is the SpecterOps-built
attack-path-management product that continuously evaluates
Active Directory / Azure AD identity-graph data and surfaces
the privilege-escalation paths real adversaries would follow —
so this executor is the identity-graph feed Faraday operators
correlate the EDR / EASM / vuln-scanner agents' findings against
to confirm whether an exposure intersects a known Tier Zero
attack path (i.e. a misconfigured workstation that's also two
hops from Domain Admin).

Each BHE asset group becomes one Faraday host — asset groups
aren't IP-keyed (they're logical collections of high-value
principals like Tier Zero / Owned) so they synthesise onto the
``0.0.0.0`` sentinel; the ``name`` / ``tag`` projection lands on
``host.hostnames``; ``id`` / ``member_count`` / ``system_group``
enrichment lands on ``host.description``; the asset group
record itself becomes one Faraday vulnerability with the
``[IDENTITY]`` engine prefix so the finding lands in the
workspace alongside the other identity-attack-surface feeds.
Each BHE attack-path finding becomes one Faraday host on the
``0.0.0.0`` sentinel — attack paths are graph relationships
between principals, not network-keyed events — and one Faraday
vulnerability with severity mapped from BHE's ``severity`` field
(``low`` -> ``low``, ``moderate``/``medium``/``med`` -> ``med``,
``high`` -> ``high``, ``critical`` -> ``critical``).

Endpoints used:
  GET {BHE_HOST}/api/v2/asset-groups?skip=N&limit=M
      -> the canonical BHE asset-group inventory.  Returns a JSON
      envelope ``{"data": {"asset_groups": [...]}}``; each record
      carries ``id``, ``name``, ``tag``, ``system_group``,
      ``member_count``, ``created_at``, ``updated_at``.
  GET {BHE_HOST}/api/v2/attack-paths/findings?domain=<BHE_DOMAIN_FQDN>
      &finding=<BHE_ATTACK_PATH_TYPE>&skip=N&limit=M
      -> the BHE attack-path finding feed.  Returns a JSON
      envelope ``{"data": [...]}``; each record carries ``id``,
      ``finding`` (the attack-path type slug, e.g.
      ``T0AddAllowedToAct``), ``severity``, ``domain_sid``,
      ``domain_name``, ``principal_kind``, ``from_principal``,
      ``to_principal``, ``created_at``, ``deleted_at``.
      ``BHE_DOMAIN_FQDN`` narrows the walk to a single AD /
      Azure tenant; ``BHE_ATTACK_PATH_TYPE`` narrows to one
      attack-path slug.

Pagination is offset/limit based via ``skip`` + ``limit`` query
parameters on both surfaces.  We walk page-by-page until either
the response stops carrying records / the page returns fewer
than ``limit`` entries or the env-only ``BHE_PAGES`` cap is
reached (default 5, clamped to [1, 50]).  ``limit`` is fixed at
100 (BHE's documented default page size; the hard cap is 1000
but smaller pages keep response sizes manageable for the
dispatcher event loop).

Auth: BHE uses HMAC-signed requests.  Operators create a token
pair (``token_id`` + ``token_key``) in the BHE admin console
under ``Administration -> API Tokens -> Create Token``.  The
dispatcher signs every request via the SpecterOps-documented
HMAC-SHA256 chain:

  operation_key = HMAC-SHA256(token_key, METHOD + URI_PATH)
  date_key      = HMAC-SHA256(operation_key, RFC3339_DATE[:13])
  signature     = HMAC-SHA256(date_key, request_body_bytes)

The base64-encoded signature ships on the ``Signature`` header,
the RFC3339 timestamp ships on the ``RequestDate`` header, and
the token id ships on ``Authorization: bhesignature <token_id>``.
The hour-truncated RFC3339 prefix means a signature is valid for
the wall-clock hour it was minted in — operators do not need to
synchronise dispatcher clocks tighter than that.

Severity for asset groups is always ``info`` (they're inventory
entries, not findings).  Severity for findings is mapped from
BHE's ``severity`` field via SEVERITY_MAP — anything not in the
map falls back to ``info``.  Tags: [bloodhound_enterprise,
identity, attack-path, asset-group|finding].
"""

import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

TIMEOUT = 60
PER_PAGE = 100  # BHE's documented default page size.
DEFAULT_PAGES = 5
MAX_PAGES = 50

# BHE severity values -> Faraday severity slots.
SEVERITY_MAP = {
    "INFO": "info",
    "INFORMATIONAL": "info",
    "LOW": "low",
    "MODERATE": "med",
    "MEDIUM": "med",
    "MED": "med",
    "HIGH": "high",
    "CRITICAL": "critical",
}

# Sentinel IP used for non-IP-keyed records.
SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - BloodHoundEnterprise: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on BHE_HOST.

    No default — the BHE tenant host is operator-specific so we
    ``sys.exit(1)`` upstream in ``main`` when the env var is
    missing.  Here we just whitespace-trim, strip trailing
    slashes and add ``https://`` when the operator pasted in a
    bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_domain_fqdn(value):
    """Validate BHE_DOMAIN_FQDN (the operator-supplied AD domain filter).

    None / blank -> ``""`` (no narrowing; every domain's
    findings are walked).  Whitespace is trimmed.  Forwarded
    verbatim into the ``?domain=<value>`` query parameter — BHE
    accepts both FQDNs (``corp.mycorp.com``) and the equivalent
    Azure tenant id (``00000000-0000-0000-0000-000000000000``)
    in the same slot.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_attack_path_type(value):
    """Validate BHE_ATTACK_PATH_TYPE (the operator-supplied finding slug).

    None / blank -> ``""`` (no narrowing; every attack-path
    type is walked).  Whitespace is trimmed.  Forwarded verbatim
    into the ``?finding=<value>`` query parameter — BHE attack
    path slugs are short tokens (e.g. ``T0AddAllowedToAct``,
    ``T0ESC1``, ``LargeDefaultGroups``).
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_pages(value):
    """Validate BHE_PAGES (per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against
    the BHE API.  Not exposed as a manifest argument (the
    playbook only lists BHE_DOMAIN_FQDN + BHE_ATTACK_PATH_TYPE)
    but read from the env so a tenant-side override can still
    tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"BHE_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"BHE_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def sign_request(token_key, method, uri_path, request_date, body_bytes=b""):
    """Compute the BHE HMAC signature for a request.

    The SpecterOps-documented signing scheme threads three
    HMAC-SHA256 rounds:

      1. operation_key = HMAC(token_key, METHOD + URI_PATH)
      2. date_key      = HMAC(operation_key, RFC3339_DATE[:13])
      3. signature     = HMAC(date_key, request_body_bytes)

    The hour-truncated RFC3339 prefix (``YYYY-MM-DDTHH``) means a
    signature is valid for the wall-clock hour it was minted in;
    operators don't need to synchronise dispatcher clocks
    tighter than that.  Body is included as bytes (empty bytes
    for GET).  Returns the base64-encoded digest as a str.
    """
    key = (token_key or "").encode("utf-8")
    digester = hmac.new(key, None, hashlib.sha256)
    digester.update(f"{method}{uri_path}".encode("utf-8"))
    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    digester.update((request_date or "")[:13].encode("utf-8"))
    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    if body_bytes:
        digester.update(body_bytes)
    return base64.b64encode(digester.digest()).decode("ascii")


def rfc3339_now():
    """Return the current time in RFC3339 (BHE's RequestDate format).

    BHE accepts ISO-8601 / RFC3339 with timezone offset.  We
    pin UTC explicitly so the signature is reproducible across
    dispatcher hosts in different timezones.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def auth_headers(token_id, token_key, method, url, body_bytes=b""):
    """Build the BHE auth headers for one request.

    BHE signs each request individually — the signature is bound
    to METHOD + URI_PATH + hour-truncated RequestDate + body, so
    we can't pre-compute and share a header dict across pages.
    The token id is the public half of the BHE token pair and
    ships verbatim on Authorization; the secret half (token_key)
    is mixed into the HMAC chain only.
    """
    parsed = urlparse(url)
    uri_path = parsed.path or "/"
    if parsed.query:
        uri_path = f"{uri_path}?{parsed.query}"
    request_date = rfc3339_now()
    signature = sign_request(token_key, method, uri_path, request_date, body_bytes)
    return {
        "Authorization": f"bhesignature {token_id or ''}",
        "RequestDate": request_date,
        "Signature": signature,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "faraday-bhe/1.0",
    }


def build_asset_groups_url(host, skip):
    base = f"{normalize_base_url(host)}/api/v2/asset-groups"
    params = [f"skip={int(skip)}", f"limit={PER_PAGE}"]
    return f"{base}?{'&'.join(params)}"


def build_findings_url(host, domain_fqdn, attack_path_type, skip):
    base = f"{normalize_base_url(host)}/api/v2/attack-paths/findings"
    params = [f"skip={int(skip)}", f"limit={PER_PAGE}"]
    if domain_fqdn:
        params.append(f"domain={quote(domain_fqdn, safe='')}")
    if attack_path_type:
        params.append(f"finding={quote(attack_path_type, safe='')}")
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
    """Map a BHE finding severity onto a Faraday slot."""
    if not value:
        return "info"
    return SEVERITY_MAP.get(str(value).strip().upper(), "info")


def extract_records(payload, surface_name):
    """Pull the per-page record list out of a BHE response envelope.

    BHE's v2 endpoints wrap the records under a ``data`` key,
    sometimes nested by surface (e.g.
    ``{"data": {"asset_groups": [...]}}`` for /asset-groups vs
    ``{"data": [...]}`` for /attack-paths/findings).  We tolerate
    both shapes and also accept a bare list at the envelope root
    for forward-compat with any v3 surfaces that flatten the
    response.
    """
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        # /asset-groups nests under data.asset_groups; tolerate a
        # few documented synonyms (findings / results / items)
        # so the executor survives BHE-side response renames.
        for key in ("asset_groups", "findings", "results", "items", surface_name.rsplit("/", 1)[-1].replace("-", "_")):
            if key and isinstance(data.get(key), list):
                return [r for r in data[key] if isinstance(r, dict)]
    return []


def fetch_all(requests_module, build_url, host, token_id, token_key, max_pages, surface_name, **build_kwargs):
    """Walk a BHE endpoint via skip/limit pagination.

    Pages until either the response stops carrying records / the
    page returns fewer than ``PER_PAGE`` entries or ``max_pages``
    is reached.  401 short-circuits the whole executor because
    the operator credentials are wrong.  403 / 429 just stop
    pagination on the surface we're walking and return what we
    have.
    """
    out = []
    page = 0
    while page < max_pages:
        skip = page * PER_PAGE
        url = build_url(host, skip=skip, **build_kwargs)
        headers = auth_headers(token_id, token_key, "GET", url)
        try:
            resp = requests_module.get(url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("BHE request rejected (401). Check BHE_TOKEN_ID / BHE_TOKEN_KEY.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"BHE {surface_name} request rejected (403). " f"Check the token's scope.")
            return out
        if resp.status_code == 429:
            log(f"BHE rate-limited (429) on {surface_name}; " f"stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"BHE {surface_name} failed " f"({resp.status_code}): {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"BHE {surface_name} response was not JSON")
            return out
        results = extract_records(payload, surface_name)
        out.extend(results)
        if len(results) < PER_PAGE:
            return out
        page += 1
    log(f"hit BHE_PAGES={max_pages} on {surface_name}; stopping pagination")
    return out


def asset_group_hostnames(group):
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(group, dict):
        add(group.get("name"))
        add(group.get("tag"))
    return out


def collect_asset_group_refs(group):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(group, dict):
        return refs
    gid = _str(group.get("id"))
    if gid:
        add(f"BHE-AssetGroupId: {gid}")
    name = _str(group.get("name"))
    if name:
        add(f"BHE-AssetGroupName: {name}")
    tag = _str(group.get("tag"))
    if tag:
        add(f"BHE-AssetGroupTag: {tag}")
    system = group.get("system_group")
    if system is not None:
        add(f"BHE-SystemGroup: {system}")
    member_count = group.get("member_count")
    if member_count is not None:
        add(f"BHE-MemberCount: {member_count}")
    created = _str(group.get("created_at"))
    if created:
        add(f"BHE-Created: {created}")
    updated = _str(group.get("updated_at"))
    if updated:
        add(f"BHE-Updated: {updated}")
    return refs


def build_asset_group_host(group, domain_fqdn):
    """Build a Faraday host dict for a BHE asset-group record."""
    if not isinstance(group, dict):
        return None
    hostnames = asset_group_hostnames(group)
    primary = hostnames[0] if hostnames else _str(group.get("id")) or "unknown group"

    desc_parts = []
    for key in ("id", "name", "tag", "system_group", "member_count", "created_at", "updated_at"):
        v = group.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if domain_fqdn:
        desc_parts.append(f"bhe_domain_fqdn: {domain_fqdn}")

    vuln = {
        "name": f"[IDENTITY] BHE asset group: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(group.get("id"))[:200] or f"bhe-asset-group-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "BHE asset groups are identity-graph inventory "
            "entries, not vulnerabilities.  Tier Zero / Owned / "
            "operator-defined groups define the blast-radius "
            "scope BHE evaluates attack paths against.  Review "
            "membership in the BHE console and re-tier any "
            "principal whose classification is wrong."
        ),
        "data": "",
        "refs": collect_asset_group_refs(group),
        "cve": [],
        "cvss3": {},
        "tags": ["bloodhound_enterprise", "identity", "attack-path", "asset-group"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"BHE asset group {primary}",
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
        add(finding.get("domain_name"))
        add(finding.get("from_principal"))
        add(finding.get("to_principal"))
        add(finding.get("finding"))
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
        add(f"BHE-FindingId: {fid}")
    finding_type = _str(finding.get("finding"))
    if finding_type:
        add(f"BHE-Finding: {finding_type}")
    severity = _str(finding.get("severity"))
    if severity:
        add(f"BHE-Severity: {severity}")
    domain_sid = _str(finding.get("domain_sid"))
    if domain_sid:
        add(f"BHE-DomainSID: {domain_sid}")
    domain_name = _str(finding.get("domain_name"))
    if domain_name:
        add(f"BHE-DomainName: {domain_name}")
    principal_kind = _str(finding.get("principal_kind"))
    if principal_kind:
        add(f"BHE-PrincipalKind: {principal_kind}")
    from_principal = _str(finding.get("from_principal"))
    if from_principal:
        add(f"BHE-FromPrincipal: {from_principal}")
    to_principal = _str(finding.get("to_principal"))
    if to_principal:
        add(f"BHE-ToPrincipal: {to_principal}")
    created = _str(finding.get("created_at"))
    if created:
        add(f"BHE-Created: {created}")
    deleted = _str(finding.get("deleted_at"))
    if deleted:
        add(f"BHE-Deleted: {deleted}")
    return refs


def build_finding_host(finding, domain_fqdn, attack_path_type):
    """Build a Faraday host dict for a BHE attack-path finding."""
    if not isinstance(finding, dict):
        return None
    hostnames = finding_hostnames(finding)
    finding_type = _str(finding.get("finding")) or "unknown finding"
    domain_name = _str(finding.get("domain_name"))
    label = f"[IDENTITY] BHE attack path: {finding_type}"
    if domain_name:
        label = f"{label} ({domain_name})"

    desc_parts = []
    for key in (
        "id",
        "finding",
        "severity",
        "domain_sid",
        "domain_name",
        "principal_kind",
        "from_principal",
        "to_principal",
        "created_at",
        "deleted_at",
    ):
        v = finding.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if domain_fqdn:
        desc_parts.append(f"bhe_domain_fqdn: {domain_fqdn}")
    if attack_path_type:
        desc_parts.append(f"bhe_attack_path_type: {attack_path_type}")

    vuln = {
        "name": label[:200],
        "desc": "\n".join(desc_parts),
        "severity": map_finding_severity(finding.get("severity")),
        "external_id": _str(finding.get("id"))[:200] or f"bhe-finding-{finding_type}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "BHE attack-path findings are identity-graph "
            "relationships an adversary could traverse to reach "
            "Tier Zero.  Review the from_principal -> "
            "to_principal edge in the BHE console, follow the "
            "remediation guidance for the specific finding type "
            "(typically: revoke the inherited permission, remove "
            "the principal from the privileged group, or tier-0 "
            "the destination), and re-run BHE post-fix to "
            "confirm the path is closed."
        ),
        "data": "",
        "refs": collect_finding_refs(finding),
        "cve": [],
        "cvss3": {},
        "tags": ["bloodhound_enterprise", "identity", "attack-path", "finding"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"BHE attack-path finding {finding_type}",
        "vulnerabilities": [vuln],
    }


def main():
    started = time.time()

    domain_fqdn = validate_domain_fqdn(env("EXECUTOR_CONFIG_BHE_DOMAIN_FQDN"))
    attack_path_type = validate_attack_path_type(env("EXECUTOR_CONFIG_BHE_ATTACK_PATH_TYPE"))
    pages = validate_pages(env("BHE_PAGES"))

    host = env("BHE_HOST", required=True)
    token_id = env("BHE_TOKEN_ID", required=True)
    token_key = env("BHE_TOKEN_KEY", required=True)

    if not normalize_base_url(host):
        log("BHE_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    asset_group_hits = fetch_all(
        requests,
        build_asset_groups_url,
        host,
        token_id,
        token_key,
        pages,
        "/api/v2/asset-groups",
    )
    finding_hits = fetch_all(
        requests,
        build_findings_url,
        host,
        token_id,
        token_key,
        pages,
        "/api/v2/attack-paths/findings",
        domain_fqdn=domain_fqdn,
        attack_path_type=attack_path_type,
    )

    log(
        f"Processing {len(asset_group_hits)} BHE asset groups + "
        f"{len(finding_hits)} attack-path findings "
        f"(domain_fqdn={domain_fqdn!r}, "
        f"attack_path_type={attack_path_type!r}, pages={pages})"
    )

    hosts_out = []
    for g in asset_group_hits:
        built = build_asset_group_host(g, domain_fqdn)
        if built is not None:
            hosts_out.append(built)
    for f in finding_hits:
        built = build_finding_host(f, domain_fqdn, attack_path_type)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "bloodhound_enterprise",
            "command": "bloodhound_enterprise",
            "params": (f"domain_fqdn={domain_fqdn}," f"attack_path_type={attack_path_type}," f"pages={pages}"),
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
