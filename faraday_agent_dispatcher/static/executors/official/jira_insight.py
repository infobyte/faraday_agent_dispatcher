#!/usr/bin/env python
"""Atlassian Insight (Assets) asset-inventory importer.

Pulls Insight / Jira Service Management Assets objects from an
Atlassian tenant via the Insight v1 REST API and emits Faraday
bulk-create JSON to stdout.  Atlassian Insight (now branded
"Jira Service Management Assets") is the CMDB Atlassian customers
use to track servers, network gear, applications, contracts, and
just about any other typed asset they can model into an object
schema, so this executor is the CMDB-class feed Faraday operators
correlate the EDR / EASM / vuln-scanner agents' findings against
to confirm an exposed host is, in fact, a known managed Insight
object.

Each Insight object becomes one Faraday host — the first IP-shaped
attribute value (matched by ``IP_RE`` against the flat list of
``attributes[*].objectAttributeValues[*].value`` /
``displayValue`` projections) maps onto ``host.ip`` (loopback /
``0.0.0.0`` / ``::1`` are explicitly skipped; we fall back to the
``0.0.0.0`` sentinel when nothing usable is found), the
``label`` / ``objectKey`` / ``name`` projection lands on
``host.hostnames`` (with any FQDN-shaped attribute values appended
as additional pivots), the first MAC-shaped attribute value lands
on ``host.mac``, the first OS-keyword-shaped attribute values (any
attribute whose value contains ``Linux`` / ``Windows`` / ``macOS``
/ ``Ubuntu`` / etc.) join onto ``host.os``, and the asset itself
becomes one Faraday vulnerability with the ``[ASSET-INVENTORY]``
engine prefix.

Endpoint used:
  GET {JIRA_HOST}/rest/insight/1.0/iql/objects?iql=<IQL>&page=N&resultPerPage=50(&objectSchemaId=...)
      -> the canonical Insight v1 IQL object walk.  Returns the
      JSON envelope ``{"objectEntries": [...], "objectTypeAttributes":
      [...], "totalFilterCount": N, "startIndex": K, "toIndex": K+M,
      "pageObject": P, "pageSize": M, "iql": "..."}``.  Each
      ``objectEntries`` record carries ``id``, ``label``,
      ``objectKey``, ``name``, ``avatar``, ``objectType`` (``{id,
      name, type}``), ``created``, ``updated``, plus ``attributes``
      — a list of ``{id, objectTypeAttributeId,
      objectAttributeValues: [{value, displayValue, searchValue,
      referencedType, referencedObject}]}`` records that hold the
      operator-modelled attribute payload (IPs, hostnames, MACs,
      OS, owner, location, contract, etc.).

``INSIGHT_WORKSPACE_ID`` is forwarded as a server-side
``?objectSchemaId=<value>`` query-string filter so the dispatcher
only walks one Insight object schema (workspace) per agent run;
blank-strings are explicitly dropped so we never emit
``objectSchemaId=`` (Insight rejects that as a 400).
``INSIGHT_OBJECT_TYPE`` is composed into the IQL as an
``objectType = "<value>"`` predicate so the walk only surfaces
records of one type (e.g. ``Server`` / ``Network Device`` /
``Application``); when ``INSIGHT_IQL`` is also supplied the two
predicates compose into ``objectType = "<type>" AND (<user
IQL>)`` so the user-supplied IQL never silently overrides the
type filter.  ``INSIGHT_IQL`` is the operator-supplied IQL
predicate forwarded verbatim into ``?iql=<value>`` (free-form
Insight Query Language — e.g. ``"Owner" = "ops" AND created >
"2026-01-01"``); when blank we fall back to ``objectSchema =
<workspace>`` (when ``INSIGHT_WORKSPACE_ID`` is set) or the
empty string (which Insight treats as "every object the token
can see").

Pagination is page-based via ``page`` (1-indexed) +
``resultPerPage``; walked page-by-page (``page += 1`` per request)
until ``len(objectEntries) < resultPerPage`` or the env-only
``INSIGHT_PAGES`` cap is reached (default 5, clamped to [1, 50]).
``resultPerPage`` is fixed at 50 (Insight's documented default
page size; the hard cap is 500 but smaller pages keep response
sizes manageable on tenants with millions of objects).

Auth: Atlassian's REST API uses HTTP Basic Authentication with
the user's email as the username and an Atlassian-issued API
token as the password (Cloud tenants — generate at
``https://id.atlassian.com/manage/api-tokens``; on-prem Server /
DC tenants accept the user's actual password or a PAT issued from
the user profile).  The dispatcher carries the credentials in the
standard ``Authorization: Basic <base64(JIRA_USER:JIRA_API_TOKEN)>``
header on every ``/rest/insight/1.0/`` call, built inline via
``basic_auth_header()`` rather than via
``requests.auth.HTTPBasicAuth`` so the wire format is unit-
testable and ``requests`` will not strip the header on cross-host
redirects.  ``JIRA_HOST`` is the operator's Jira / JSM tenant
host (e.g. ``mycorp.atlassian.net``); on-prem deployments are
tolerated and ``https://`` is added automatically when the
operator pasted in a bare FQDN.

Severity is always ``info`` because Insight hits are CMDB
inventory entries, not vulnerability findings — operators
correlate against the other agents' findings via the
``Insight-Id`` / ``Insight-Key`` / ``Insight-Workspace`` /
``Insight-ObjectType`` / ``Insight-ObjectTypeId`` / ``Insight-Created``
/ ``Insight-Updated`` refs.  Tags:
[jira_insight, asset-inventory, object].
"""

import base64
import json
import os
import re
import socket
import sys
import time
import urllib.parse
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
IP_RE = re.compile(r"^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)" r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$")
IPV6_RE = re.compile(r"^[0-9A-Fa-f:]{2,}$")
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$")
FQDN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+" r"[A-Za-z]{2,63}$")
OS_KEYWORDS = (
    "linux",
    "ubuntu",
    "debian",
    "centos",
    "rhel",
    "redhat",
    "red hat",
    "fedora",
    "suse",
    "windows",
    "macos",
    "mac os",
    "osx",
    "freebsd",
    "openbsd",
    "solaris",
    "aix",
)

TIMEOUT = 60
PER_PAGE = 50  # Insight's documented default resultPerPage.
MAX_PER_PAGE = 500
DEFAULT_PAGES = 5
MAX_PAGES = 50


def log(msg):
    print(f"{datetime.utcnow()} - JiraInsight: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on JIRA_HOST.

    No default — the Jira / JSM tenant host is operator-specific so
    we ``sys.exit(1)`` upstream in ``main`` when the env var is
    missing.  Here we just whitespace-trim, strip trailing slashes
    and add ``https://`` when the operator pasted in a bare FQDN
    (on-prem Jira deployments commonly use raw hostnames).
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_workspace_id(value):
    """Validate INSIGHT_WORKSPACE_ID (the Insight schema / workspace id).

    None / blank -> ``""`` (no schema narrowing; every object the
    token can see is walked).  Whitespace is trimmed.  Forwarded
    verbatim into a ``?objectSchemaId=<value>`` query-string filter
    on ``/rest/insight/1.0/iql/objects`` — Insight accepts both
    numeric schema ids (e.g. ``objectSchemaId=42``) and the literal
    schema key (e.g. ``objectSchemaId=ITSM``) depending on tenant
    configuration so we don't second-guess the operator.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_iql(value):
    """Validate INSIGHT_IQL (the operator-supplied IQL predicate).

    None / blank -> ``""`` (the executor builds a default IQL from
    INSIGHT_OBJECT_TYPE / INSIGHT_WORKSPACE_ID in
    ``compose_iql()``; if none of the three are set Insight
    interprets the empty IQL as "every object the token can see").
    Whitespace is trimmed.  Forwarded verbatim — Insight Query
    Language is free-form so the executor doesn't second-guess
    operator-supplied predicates.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_object_type(value):
    """Validate INSIGHT_OBJECT_TYPE (the per-type narrowing knob).

    None / blank -> ``""`` (no type narrowing; every object type
    in the schema is walked).  Whitespace is trimmed.  When
    supplied it's composed into the IQL as an ``objectType =
    "<value>"`` predicate via ``compose_iql()`` so the user's IQL
    never silently overrides the type filter.
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_pages(value):
    """Validate INSIGHT_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Insight tenant.  Not exposed as a manifest argument (the
    playbook only lists INSIGHT_WORKSPACE_ID + INSIGHT_IQL +
    INSIGHT_OBJECT_TYPE) but read from the env so a tenant-side
    override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"INSIGHT_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"INSIGHT_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_objects_url(host):
    return f"{normalize_base_url(host)}/rest/insight/1.0/iql/objects"


def compose_iql(user_iql, object_type, workspace_id):
    """Compose the final IQL predicate from operator inputs.

    The composition order is:
      objectType = "<type>" AND (<user IQL>)
    so the user-supplied IQL never silently overrides the type
    filter.  When ``object_type`` is blank we just forward the
    user IQL verbatim.  When both are blank we fall back to
    ``objectSchema = <workspace>`` (when ``workspace_id`` is set)
    or the empty string (which Insight treats as "every object the
    token can see").  Predicate parentheses are added around the
    user IQL to preserve the operator's intent under composition.
    """
    type_val = str(object_type or "").strip()
    iql_val = str(user_iql or "").strip()
    ws_val = str(workspace_id or "").strip()
    if type_val and iql_val:
        return f'objectType = "{type_val}" AND ({iql_val})'
    if type_val:
        return f'objectType = "{type_val}"'
    if iql_val:
        return iql_val
    if ws_val:
        return f"objectSchema = {ws_val}"
    return ""


def build_query(page, per_page=PER_PAGE, iql="", extra=None):
    """Build the canonical Insight v1 paging query string.

    Insight uses page-based pagination via ``page`` (1-indexed) +
    ``resultPerPage``.  ``iql`` is appended as ``?iql=<value>``
    when non-blank (Insight tolerates an empty ``iql`` param value
    but treating the empty string as a sentinel keeps the query
    string predictable).  ``extra`` is an optional dict of
    additional filter params (e.g. ``{"objectSchemaId": "42"}``);
    values are URL-encoded and blanks are dropped so the resulting
    query string never carries a value-less key.
    """
    params = [
        ("page", str(int(page))),
        ("resultPerPage", str(int(per_page))),
    ]
    iql_val = str(iql or "").strip()
    if iql_val:
        params.append(("iql", iql_val))
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            s = str(v).strip()
            if not s:
                continue
            params.append((str(k), s))
    return urllib.parse.urlencode(params)


def basic_auth_header(user, password):
    """Build the canonical Authorization: Basic header string.

    Atlassian's REST API uses HTTP Basic Auth — we build the
    header inline rather than relying on ``requests.auth.HTTPBasicAuth``
    so test fixtures + unit checks can assert on the exact wire
    format (requests will strip a manually-built Authorization
    header on cross-host redirects, which we don't want for
    on-prem tenants behind reverse proxies).
    """
    raw = f"{user or ''}:{password or ''}".encode("utf-8")
    return f"Basic {base64.b64encode(raw).decode('ascii')}"


def auth_headers(user, password):
    return {
        "Authorization": basic_auth_header(user, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_objects(body):
    """Pull the object list from an Insight v1 IQL response envelope.

    Insight wraps the records under ``objectEntries`` (the
    documented v1 shape).  Federated / future stacks may use
    bare-list / top-level ``objects`` / ``data`` / ``results`` /
    ``items`` — accept all for resilience.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("objectEntries", "objects", "data", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_total(body):
    if not isinstance(body, dict):
        return None
    for key in ("totalFilterCount", "totalCount", "total", "count"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


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


def _flatten_string(value):
    """Coerce a single Insight attribute value into a printable string."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        for entry in value:
            scalar = _flatten_string(entry)
            if scalar:
                return scalar
        return ""
    if isinstance(value, dict):
        for key in ("value", "displayValue", "name", "key", "label", "id"):
            v = value.get(key)
            if v:
                return _flatten_string(v)
    return ""


def attribute_values(obj):
    """Walk an Insight object's ``attributes`` for raw scalar values.

    Each Insight attribute carries an ``objectAttributeValues`` list
    of ``{value, displayValue, searchValue, referencedType,
    referencedObject}`` records.  We project each entry through
    ``value`` (the canonical persisted form) with ``displayValue``
    as a fallback (used for referenced objects / user pickers)
    plus ``referencedObject.label`` for nested-object refs.
    Returns a deduped list of trimmed strings ordered by attribute
    appearance.
    """
    out = []
    seen = set()
    if not isinstance(obj, dict):
        return out

    def add(text):
        if not isinstance(text, str):
            return
        s = text.strip()
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    attrs = obj.get("attributes")
    if not isinstance(attrs, list):
        return out
    for attr in attrs:
        if not isinstance(attr, dict):
            continue
        values = attr.get("objectAttributeValues")
        if not isinstance(values, list):
            continue
        for v in values:
            if not isinstance(v, dict):
                if isinstance(v, str):
                    add(v)
                continue
            for key in ("value", "displayValue", "searchValue"):
                scalar = _flatten_string(v.get(key))
                if scalar:
                    add(scalar)
            ref = v.get("referencedObject")
            if isinstance(ref, dict):
                for key in ("label", "name", "objectKey"):
                    scalar = _flatten_string(ref.get(key))
                    if scalar:
                        add(scalar)
    return out


def object_ips(obj):
    """Walk an Insight object for IP candidates.

    Pulls every IPv4-shaped scalar value out of the attributes
    list (matched against ``IP_RE``).  Loopback / zero are
    explicitly skipped.  Insight has no canonical "ip" attribute
    name (operators model the schema however they like — common
    names include ``IP Address`` / ``Management IP`` / ``Primary
    IP`` / ``Public IP``) so we walk every attribute value and
    match by shape.
    """
    out = []
    seen = set()
    for val in attribute_values(obj):
        s = val.strip()
        if not s or s in seen:
            continue
        if not IP_RE.match(s):
            continue
        if s in ("0.0.0.0", "127.0.0.1", "::1"):
            continue
        seen.add(s)
        out.append(s)
    return out


def object_ip(obj):
    """Pick the first non-loopback IP for an Insight object."""
    ips = object_ips(obj)
    return ips[0] if ips else "0.0.0.0"


def object_hostnames(obj):
    """Walk an Insight object for hostname candidates.

    Primary projection is the object's ``label`` / ``objectKey`` /
    ``name`` — these are the Insight-canonical identifiers that
    operators search on in the JSM UI.  We also pull any FQDN-
    shaped attribute values (matched against ``FQDN_RE``) so the
    Faraday hostname index pivots on the asset's network identity.
    """
    out = []
    seen = set()

    def add(text):
        if not isinstance(text, str):
            return
        s = text.strip()
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if not isinstance(obj, dict):
        return out

    for key in ("label", "objectKey", "name"):
        add(_flatten_string(obj.get(key)))

    for val in attribute_values(obj):
        if FQDN_RE.match(val):
            add(val)
    return out


def object_mac(obj):
    """Pick the first MAC-shaped attribute value for an Insight object."""
    for val in attribute_values(obj):
        if MAC_RE.match(val):
            return val
    return ""


def object_os(obj):
    """Build the ``host.os`` string from Insight attribute values.

    Insight has no canonical OS attribute (operators model the
    schema however they like — common names include ``Operating
    System`` / ``OS`` / ``Platform``).  We walk every attribute
    value and pick the first one that contains a known OS keyword
    (``Linux`` / ``Windows`` / ``macOS`` / etc.).  Returns the
    raw matched string so the OS version travels with the keyword.
    """
    for val in attribute_values(obj):
        low = val.lower()
        for kw in OS_KEYWORDS:
            if kw in low:
                return val
    return ""


def object_type(obj):
    """Pull the Insight object type name (``objectType.name``)."""
    if not isinstance(obj, dict):
        return ""
    ot = obj.get("objectType")
    if isinstance(ot, dict):
        for key in ("name", "key", "label"):
            v = _flatten_string(ot.get(key))
            if v:
                return v
    if isinstance(ot, str):
        return ot.strip()
    return ""


def object_type_id(obj):
    """Pull the Insight object type id (``objectType.id``)."""
    if not isinstance(obj, dict):
        return ""
    ot = obj.get("objectType")
    if isinstance(ot, dict):
        v = ot.get("id")
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def collect_cves(item):
    """Walk an Insight object for CVE-* ids.

    Insight doesn't surface CVE-keyed findings on the canonical
    iql/objects endpoint, but operators sometimes paste CVEs into
    attribute values (e.g. an ``Open CVEs`` attribute on Application
    or Server objects) so we still scan every attribute value plus
    the object's ``label`` / ``name`` for completeness.
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

    for key in ("label", "name", "objectKey"):
        scan(item.get(key))

    for val in attribute_values(item):
        scan(val)

    return found


def collect_refs(item, workspace_id):
    """Walk an Insight object for advisory URLs / pivots."""
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

    iid = item.get("id")
    if iid is not None and str(iid).strip():
        add(f"Insight-Id: {str(iid).strip()}")
    key = _flatten_string(item.get("objectKey"))
    if key:
        add(f"Insight-Key: {key}")
    ot_name = object_type(item)
    if ot_name:
        add(f"Insight-ObjectType: {ot_name}")
    ot_id = object_type_id(item)
    if ot_id:
        add(f"Insight-ObjectTypeId: {ot_id}")
    if workspace_id:
        add(f"Insight-Workspace: {workspace_id}")
    created = _flatten_string(item.get("created"))
    if created:
        add(f"Insight-Created: {created}")
    updated = _flatten_string(item.get("updated"))
    if updated:
        add(f"Insight-Updated: {updated}")

    return refs


def build_asset_vulnerability(item, workspace_id, iql):
    """Build a Faraday vulnerability dict for one Insight object."""
    hostnames = object_hostnames(item)
    primary = hostnames[0] if hostnames else (object_ip(item) if object_ip(item) != "0.0.0.0" else "unknown object")
    label = f"[ASSET-INVENTORY] Insight object: {primary}"

    desc_parts = []
    if isinstance(item, dict):
        for key in sorted(item.keys()):
            v = item.get(key)
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (dict, list)):
                desc_parts.append(f"{key}: {_serialise(v)}")
            else:
                desc_parts.append(f"{key}: {v}")
    if workspace_id:
        desc_parts.append(f"insight_workspace_id: {workspace_id}")
    if iql:
        desc_parts.append(f"insight_iql: {iql}")

    cves = collect_cves(item) if isinstance(item, dict) else []
    refs = collect_refs(item, workspace_id)

    external_id = ""
    if isinstance(item, dict):
        key = _flatten_string(item.get("objectKey"))
        if key:
            external_id = key
        elif item.get("id") is not None:
            external_id = str(item.get("id"))
    if not external_id:
        external_id = label

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Insight records are CMDB inventory entries, not "
            "vulnerabilities.  Cross-check the object against the "
            "other agents' findings (EDR / EASM / vuln scanners) — "
            "anything reported against this Insight object id "
            "indicates a real exposure on a known managed asset.  "
            "Decommission, reclassify, or merge the object in "
            "Insight if it should no longer appear in the inventory."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["jira_insight", "asset-inventory", "object"],
    }


def build_host_from_object(obj, workspace_id, iql):
    """Build a Faraday host dict from an Insight object record."""
    if obj is None or not isinstance(obj, dict):
        return None

    ip = object_ip(obj)
    hostnames = object_hostnames(obj)
    mac = object_mac(obj)
    os_str = object_os(obj)

    desc_parts = []
    ot_name = object_type(obj)
    if ot_name:
        desc_parts.append(f"objectType={ot_name}")
    for key in ("objectKey", "created", "updated"):
        v = obj.get(key)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    vuln = build_asset_vulnerability(obj, workspace_id, iql)
    return {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [vuln] if vuln else [],
    }


def fetch_pages(requests_module, url, headers, iql, per_page, max_pages, extra_params=None):
    """Walk an Insight v1 ``/rest/insight/1.0/iql/objects`` envelope.

    Pagination is page-based via ``page`` (1-indexed) +
    ``resultPerPage`` query parameters.  We page until either
    ``len(objectEntries) < per_page`` or ``max_pages`` is reached.
    401 short-circuits the whole executor (credentials are wrong);
    403 / 429 / 5xx stop pagination on the surface and return what
    we have.
    """
    out = []
    page = 1
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(page, per_page=per_page, iql=iql, extra=extra_params)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Insight request rejected (401). " "Check JIRA_USER / JIRA_API_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Insight request rejected (403). Check the user's project / schema scope.")
            return out
        if resp.status_code == 429:
            log("Insight rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Insight request failed ({resp.status_code}) for {full_url}: " f"{resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Insight response was not JSON ({full_url})")
            return out
        records = extract_objects(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < per_page:
            break
        page += 1
    if walked >= max_pages and len(records) >= per_page:
        log(f"hit INSIGHT_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    workspace_id = validate_workspace_id(env("EXECUTOR_CONFIG_INSIGHT_WORKSPACE_ID"))
    iql_arg = validate_iql(env("EXECUTOR_CONFIG_INSIGHT_IQL"))
    object_type_arg = validate_object_type(env("EXECUTOR_CONFIG_INSIGHT_OBJECT_TYPE"))
    pages = validate_pages(env("INSIGHT_PAGES"))

    host = env("JIRA_HOST", required=True)
    user = env("JIRA_USER", required=True)
    token = env("JIRA_API_TOKEN", required=True)

    if not normalize_base_url(host):
        log("JIRA_HOST is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(user, token)
    url = build_objects_url(host)
    iql = compose_iql(iql_arg, object_type_arg, workspace_id)
    extra = {"objectSchemaId": workspace_id} if workspace_id else None

    records = fetch_pages(
        requests,
        url,
        headers,
        iql,
        PER_PAGE,
        max_pages=pages,
        extra_params=extra,
    )

    log(
        f"Processing {len(records)} Insight objects "
        f"(workspace_id={workspace_id!r}, object_type={object_type_arg!r}, "
        f"iql={iql!r}, pages={pages})"
    )

    hosts_out = []
    for obj in records:
        built = build_host_from_object(obj, workspace_id, iql)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "jira_insight",
            "command": "jira_insight",
            "params": (
                f"workspace_id={workspace_id}," f"object_type={object_type_arg}," f"iql={iql_arg}," f"pages={pages}"
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
