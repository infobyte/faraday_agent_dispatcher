#!/usr/bin/env python
"""Secureworks Taegis XDR Threat Intelligence importer.

Pulls investigations + XDR alerts from the Secureworks Taegis
XDR GraphQL API and emits Faraday bulk-create JSON to stdout.
Taegis XDR is Secureworks' managed-detection-and-response SaaS
— sensors + analytics emit XDR alerts, the Counter Threat Unit
analysts triage them into investigations, and the operator's
SOC works each investigation through Open -> Awaiting Action
-> Closed.  This executor surfaces both the alert stream and
the investigation pipeline as Faraday vulnerabilities so the
Taegis output joins the operator's existing host-side scanner
output under a single workspace.

Endpoints used:
  POST {TAEGIS_HOST}/auth/api/v2/auth/token
      -> OAuth2 ``client_credentials`` token exchange.  The
      executor sends ``Authorization: Basic
      <b64(client_id:client_secret)>`` + a form-encoded
      ``grant_type=client_credentials`` body per RFC 6749 and
      Secureworks' documented Taegis token surface.  The
      response payload is the canonical OAuth2 envelope
      ``{"access_token": "...", "token_type": "Bearer",
      "expires_in": 3600}``; the dispatcher forwards the
      ``access_token`` as the ``Authorization: Bearer ...``
      header on every subsequent GraphQL request.

  POST {TAEGIS_HOST}/graphql
      -> The canonical Taegis XDR GraphQL surface.  The
      executor issues two queries in a single run:

      (1) ``investigations`` — pulls the operator's
      tenant-scoped investigations (Taegis' case object).
      Each node carries ``id``, ``title``, ``description``,
      ``priority`` (``Critical`` / ``High`` / ``Medium`` /
      ``Low`` / ``Informational`` — sometimes also surfaced
      as the numeric 1..5 ladder), ``status`` (``Open`` /
      ``Awaiting Action`` / ``Active`` / ``Suspended`` /
      ``Closed`` and Secureworks' published variants),
      ``type``, ``keyFindings``, ``createdAt``, ``updatedAt``,
      optional ``assignee`` + ``tags`` + ``alertCount``.

      (2) ``alertsServiceSearch`` — pulls XDR alerts via the
      Taegis CQL surface.  Each alert carries ``id`` plus a
      ``metadata`` block with ``title``, ``description``,
      ``severity`` (0..1 float on the XDR surface; some
      vendor adapters also emit 0..10 / labelled forms),
      ``confidence``, ``createdAt``; plus ``eventCount`` /
      ``status`` / ``tenantId`` on the alert envelope.

Auth: Taegis uses OAuth2 ``client_credentials``.  Both
``TAEGIS_CLIENT_ID`` and ``TAEGIS_CLIENT_SECRET`` are mandatory
env vars; the dispatcher exchanges them for a short-lived
Bearer token at ``POST {TAEGIS_HOST}/auth/api/v2/auth/token``
(HTTP Basic + ``grant_type=client_credentials``) and forwards
the ``access_token`` as ``Authorization: Bearer ...`` on every
subsequent GraphQL request alongside the tenant scope header
``x-tenant-context: <TAEGIS_TENANT_ID>``.

Args:
  ``TAEGIS_TENANT_ID`` (mandatory) — the Taegis tenant id
  scoped on every GraphQL request and surfaced in both the
  description and the refs list so the operator can pivot
  from a Faraday finding back to the exact Taegis tenant.

  ``TAEGIS_MIN_SEVERITY`` (optional) — case-insensitive
  Faraday severity floor (``info`` / ``low`` / ``medium`` /
  ``high`` / ``critical``); records whose mapped severity is
  strictly below the floor are dropped client-side after the
  fetch.  Blank / missing / unparseable values keep every
  record (the typical operational mode).

Env vars:
  ``TAEGIS_CLIENT_ID`` + ``TAEGIS_CLIENT_SECRET`` (mandatory)
  — the OAuth2 client_credentials pair issued by the Taegis
  console.  The executor exits cleanly when either is missing.

  ``TAEGIS_HOST`` (optional, default
  ``https://api.ctpx.secureworks.com``) — the Taegis API base
  URL.  US-East tenants typically use
  ``https://api.ctpx.secureworks.com``; the executor tolerates
  region-specific mirrors (``https://api.us.secureworks.com``,
  ``https://api.eu.secureworks.com``) and adds ``https://``
  automatically when the operator pasted in a bare FQDN.

Each Taegis record (one per alert + one per investigation)
becomes one Faraday vulnerability under a single synthetic
``0.0.0.0`` host with hostname ``secureworks-taegis``.  Taegis
records are tenant-keyed not host-keyed — the operator's other
agents emit the host-side findings this feed is correlated
against.  Every Faraday vuln carries ``tags:
['secureworks-taegis']`` with the canonical Taegis title in the
name (alerts prefixed ``[Taegis Alert]``, investigations
prefixed ``[Taegis Investigation]`` so operators can filter the
two streams independently), the canonical record id in
``external_id``, and the canonical metadata fields surfaced in
both the description and the refs list so the operator can
pivot from a Faraday finding back to the exact Taegis record.

Severity is bucketed from Taegis' published rating:
  - Alerts: ``metadata.severity`` is a 0..1 float on XDR; we
    map ``>= 0.8 -> critical``, ``>= 0.6 -> high``, ``>= 0.4
    -> medium``, ``>= 0.2 -> low``, ``< 0.2 -> info``.  Vendor
    adapters that surface 0..10 numeric scores are bucketed
    via the ``>=9/>=7/>=4/>0`` ladder; labelled severities
    (``Critical`` / ``High`` / ``Medium`` / ``Low`` /
    ``Informational``) are passed through verbatim.
  - Investigations: ``priority`` is the canonical
    ``Critical`` / ``High`` / ``Medium`` / ``Low`` /
    ``Informational`` label (or the 1..5 numeric form);
    the alias table maps each value to Faraday's ladder.
  - Closed / Resolved investigations are floored to ``info``
    (the case is no longer live; the closed state is preserved
    via an explicit ``Taegis-Status`` pivot).
  - Unparseable / missing severity defaults to ``info`` — we
    don't synthesise a ranking Taegis hasn't published.

Status is always ``open`` (a Taegis record can transition to
``Closed`` in the console but the underlying alert / case lives
on; Faraday surfaces the finding as open so the operator's
remediation workflow takes over — the Closed state is preserved
via the info-severity floor + an explicit ``Taegis-Status``
pivot).
"""

import json
import os
import re
import socket
import sys
import time
from base64 import b64encode
from datetime import datetime, timezone
from urllib.parse import urlencode

TIMEOUT = 60
TOKEN_PATH = "/auth/api/v2/auth/token"
GRAPHQL_PATH = "/graphql"

DEFAULT_HOST = "https://api.ctpx.secureworks.com"
DEFAULT_ALERT_LIMIT = 500
DEFAULT_INVESTIGATION_LIMIT = 500
INTER_REQUEST_SLEEP = 0.3

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(VALID_SEVERITY)}

# Secureworks Taegis severity / priority vocabulary.  Both
# alerts (metadata.severity) and investigations (priority) use
# the same Critical / High / Medium / Low / Informational
# ladder, with the numeric 1..5 form occasionally surfaced on
# the investigation priority field.
SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    "none": "info",
    "nothing": "info",
}

PRIORITY_NUMERIC_ALIASES = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
    "5": "info",
}

# Taegis investigation closed-state vocabulary — terminal
# states floored to ``info`` regardless of the priority ladder.
CLOSED_INV_STATES = {
    "closed",
    "resolved",
    "suspended",
    "not-applicable",
    "notapplicable",
    "not applicable",
    "false positive",
    "false-positive",
    "falsepositive",
}

INVESTIGATIONS_QUERY = (
    "query Investigations($tenantId: String!, $first: Int!) {\n"
    "  investigations(in: {tenantId: $tenantId, first: $first}) {\n"
    "    edges {\n"
    "      node {\n"
    "        id\n"
    "        title\n"
    "        description\n"
    "        priority\n"
    "        status\n"
    "        type\n"
    "        keyFindings\n"
    "        createdAt\n"
    "        updatedAt\n"
    "        assignee { email }\n"
    "        tags\n"
    "        alertCount\n"
    "      }\n"
    "    }\n"
    "  }\n"
    "}"
)

ALERTS_QUERY = (
    "query Alerts($cql: String!, $limit: Int!) {\n"
    "  alertsServiceSearch(in: {CQL: $cql, limit: $limit, offset: 0}) {\n"
    "    alerts {\n"
    "      list {\n"
    "        id\n"
    "        metadata {\n"
    "          title\n"
    "          description\n"
    "          severity\n"
    "          confidence\n"
    "          createdAt\n"
    "        }\n"
    "        eventCount\n"
    "        status\n"
    "        tenantId\n"
    "      }\n"
    "    }\n"
    "  }\n"
    "}"
)

DEFAULT_ALERT_CQL = "FROM alert SEVERITY >= 0.2 EARLIEST = -30days"


def log(msg):
    print(f"{datetime.utcnow()} - SecureworksTaegis: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + apply DEFAULT_HOST + tolerate operator typos.

    Taegis is a regionally-deployed SaaS so we default to the
    US-East canonical endpoint (``https://api.ctpx.secureworks.com``)
    when the operator does not override.  Whitespace is trimmed
    and ``https://`` is added when the operator pasted in a
    bare FQDN (regional mirrors such as
    ``api.us.secureworks.com`` / ``api.eu.secureworks.com``
    are tolerated).
    """
    if host in (None, False, True):
        return DEFAULT_HOST
    if not isinstance(host, str):
        return DEFAULT_HOST
    text = host.strip().rstrip("/")
    if not text:
        return DEFAULT_HOST
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def build_token_url(host):
    return f"{normalize_base_url(host)}{TOKEN_PATH}"


def build_graphql_url(host):
    return f"{normalize_base_url(host)}{GRAPHQL_PATH}"


def basic_auth_header(client_id, client_secret):
    """Build the HTTP Basic auth header for OAuth2 token exchange.

    Returns ``Basic <b64(client_id:client_secret)>`` per RFC
    6749 + RFC 7617.  Used inside ``fetch_token`` only;
    subsequent GraphQL requests use the Bearer token returned
    by the token endpoint.
    """
    creds = f"{str(client_id or '').strip()}:{str(client_secret or '').strip()}"
    encoded = b64encode(creds.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def request_headers(token, tenant_id):
    """Build the headers dict for a single Taegis GraphQL POST.

    ``Authorization: Bearer ...`` carries the OAuth2 access
    token; ``x-tenant-context`` is the Taegis-documented
    per-request tenant scope header.  ``Accept`` +
    ``Content-Type`` are set to ``application/json`` per the
    GraphQL convention.  Missing / blank inputs are coerced
    to safe defaults so the request still goes through and the
    server can return a useful 401 / 403.
    """
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if isinstance(token, str) and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    if isinstance(tenant_id, str) and tenant_id.strip():
        headers["x-tenant-context"] = tenant_id.strip()
    return headers


def normalize_tenant_id(value):
    """Coerce TAEGIS_TENANT_ID into a non-empty stripped string."""
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:  # noqa: BLE001
            return None
    text = value.strip()
    return text or None


def normalize_severity_label(value):
    """Coerce a Taegis severity / priority label to Faraday's ladder."""
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    return SEVERITY_ALIASES.get(text)


def parse_min_severity(value):
    """Parse TAEGIS_MIN_SEVERITY into a canonical Faraday severity.

    Accepts the canonical labels (``info`` / ``low`` /
    ``medium`` / ``high`` / ``critical``) plus operator-friendly
    aliases (``informational`` -> ``info``, ``moderate`` ->
    ``medium``, ``crit`` -> ``critical``).  Returns ``None`` for
    missing / unparseable inputs so the caller treats the run
    as 'keep every record'.
    """
    return normalize_severity_label(value)


def severity_from_taegis(severity_value):
    """Bucket Faraday severity from a Taegis severity value.

    Accepts labelled form (``Critical`` / ``High`` / ``Medium``
    / ``Low`` / ``Informational``), 0..1 float (XDR alert
    severity), or 0..10 numeric (vendor-adapter scores).
    Returns ``"info"`` for missing / unparseable inputs.
    """
    if isinstance(severity_value, str):
        label = normalize_severity_label(severity_value)
        if label is not None:
            return label
        try:
            num = float(severity_value.strip())
        except (TypeError, ValueError, AttributeError):
            return "info"
    elif isinstance(severity_value, bool):
        return "info"
    elif severity_value is None:
        return "info"
    else:
        try:
            num = float(severity_value)
        except (TypeError, ValueError):
            return "info"
    if num != num:  # NaN check
        return "info"
    if num < 0:
        return "info"
    if num > 1.0:
        if num >= 9.0:
            return "critical"
        if num >= 7.0:
            return "high"
        if num >= 4.0:
            return "medium"
        if num > 0.0:
            return "low"
        return "info"
    if num >= 0.8:
        return "critical"
    if num >= 0.6:
        return "high"
    if num >= 0.4:
        return "medium"
    if num >= 0.2:
        return "low"
    return "info"


def severity_from_priority(value):
    """Bucket Faraday severity from a Taegis investigation priority.

    Accepts both the labelled form (``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``Informational``) and the numeric
    1..5 form (1=critical .. 5=info).  Returns ``None`` for
    missing / unparseable inputs so the caller falls back to
    ``severity_from_taegis`` for fully numeric ratings.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        text = str(value).strip()
    elif isinstance(value, str):
        text = value.strip()
    else:
        return None
    if not text:
        return None
    label = SEVERITY_ALIASES.get(text.lower())
    if label is not None:
        return label
    return PRIORITY_NUMERIC_ALIASES.get(text)


def is_closed_state(value):
    """True when a Taegis investigation status is terminally closed."""
    if value is None or isinstance(value, bool):
        return False
    if not isinstance(value, str):
        return False
    return value.strip().lower() in CLOSED_INV_STATES


def severity_meets_threshold(severity, min_severity):
    """True when ``severity`` is >= ``min_severity`` in Faraday's ladder.

    ``min_severity is None`` keeps every record.  Unknown
    severity strings are dropped when a threshold is set
    (conservative — we cannot prove the record meets the bar).
    """
    if min_severity is None:
        return True
    if severity not in SEVERITY_ORDER:
        return False
    if min_severity not in SEVERITY_ORDER:
        return True
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[min_severity]


def parse_iso_datetime(value):
    """Parse an ISO-8601 timestamp into a UTC-aware datetime."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_graphql_errors(body):
    """Pull the GraphQL ``errors`` array as a list of message strings.

    Returns ``[]`` for missing / non-list inputs so the caller
    can treat the response as error-free.  Each entry may be
    a dict with a ``message`` field or a bare string; both are
    accepted for federated / mirror stacks.
    """
    if not isinstance(body, dict):
        return []
    errs = body.get("errors")
    if not isinstance(errs, list):
        return []
    out = []
    for err in errs:
        if isinstance(err, dict):
            msg = err.get("message")
            if msg:
                out.append(str(msg))
        elif isinstance(err, str) and err.strip():
            out.append(err.strip())
    return out


def extract_investigations(body):
    """Pull the investigation list from a Taegis GraphQL response.

    Canonical envelope is ``{"data": {"investigations":
    {"edges": [{"node": {...}}]}}}``.  Falls back to bare-list
    / ``investigations`` / ``list`` / ``data`` / ``items`` /
    ``results`` for federated / mirror stacks.
    """
    if not isinstance(body, dict):
        return []
    data = body.get("data")
    if isinstance(data, dict):
        inv = data.get("investigations")
    else:
        inv = body.get("investigations")
    if isinstance(inv, dict):
        edges = inv.get("edges")
        if isinstance(edges, list):
            out = []
            for edge in edges:
                if isinstance(edge, dict):
                    node = edge.get("node")
                    if isinstance(node, dict):
                        out.append(node)
            return out
        for key in ("list", "investigations", "data", "items", "results"):
            v = inv.get(key)
            if isinstance(v, list):
                return [e for e in v if isinstance(e, dict)]
    if isinstance(inv, list):
        return [e for e in inv if isinstance(e, dict)]
    return []


def extract_alerts(body):
    """Pull the alert list from a Taegis GraphQL response.

    Canonical envelope is ``{"data": {"alertsServiceSearch":
    {"alerts": {"list": [...]}}}}``.  Falls back to
    ``alerts.list`` / ``alerts`` bare-list / top-level
    ``alerts.list`` for federated / mirror stacks.
    """
    if not isinstance(body, dict):
        return []
    data = body.get("data")
    container = data if isinstance(data, dict) else body
    service = container.get("alertsServiceSearch") if isinstance(container, dict) else None
    if isinstance(service, dict):
        alerts = service.get("alerts")
        if isinstance(alerts, dict):
            lst = alerts.get("list")
            if isinstance(lst, list):
                return [e for e in lst if isinstance(e, dict)]
        if isinstance(alerts, list):
            return [e for e in alerts if isinstance(e, dict)]
    alerts = container.get("alerts") if isinstance(container, dict) else None
    if isinstance(alerts, dict):
        lst = alerts.get("list")
        if isinstance(lst, list):
            return [e for e in lst if isinstance(e, dict)]
    if isinstance(alerts, list):
        return [e for e in alerts if isinstance(e, dict)]
    return []


def collect_cves(record):
    """Pull CVE ids surfaced in the title / description / keyFindings."""
    if not isinstance(record, dict):
        return []
    haystacks = [
        record.get("title"),
        record.get("description"),
        record.get("keyFindings"),
        record.get("notes"),
    ]
    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        haystacks.extend([metadata.get("title"), metadata.get("description")])
    out = []
    seen = set()
    for blob in haystacks:
        if not blob:
            continue
        text = blob if isinstance(blob, str) else str(blob)
        for match in CVE_RE.finditer(text):
            upper = match.group(0).upper()
            if upper in seen:
                continue
            seen.add(upper)
            out.append(upper)
    return out


def alert_console_url(host, alert_id, tenant_id):
    """Build a best-effort Taegis XDR console deep-link for an alert."""
    base = normalize_base_url(host)
    if not base or not alert_id:
        return ""
    aid = str(alert_id).strip()
    tid = str(tenant_id or "").strip()
    if tid:
        return f"https://ctpx.secureworks.com/alerts/{aid}?tenant={tid}"
    return f"https://ctpx.secureworks.com/alerts/{aid}"


def investigation_console_url(host, inv_id, tenant_id):
    """Build a best-effort Taegis XDR console deep-link for an investigation."""
    base = normalize_base_url(host)
    if not base or not inv_id:
        return ""
    iid = str(inv_id).strip()
    tid = str(tenant_id or "").strip()
    if tid:
        return f"https://ctpx.secureworks.com/investigations/{iid}?tenant={tid}"
    return f"https://ctpx.secureworks.com/investigations/{iid}"


def collect_alert_refs(alert, tenant_id, host):
    """Build the refs list for one Taegis alert."""
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

    if not isinstance(alert, dict):
        return refs

    alert_id = str(alert.get("id") or "").strip()
    if alert_id:
        deep = alert_console_url(host, alert_id, tenant_id)
        if deep:
            add(deep)
        add(f"Taegis-AlertID: {alert_id}")
    if tenant_id:
        add(f"Taegis-TenantID: {tenant_id}")

    metadata = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    title = metadata.get("title") or alert.get("title")
    if title:
        add(f"Taegis-Title: {str(title).strip()}")
    severity = metadata.get("severity")
    if severity is None:
        severity = alert.get("severity")
    if severity is not None:
        add(f"Taegis-Severity: {severity}")
    confidence = metadata.get("confidence")
    if confidence is not None:
        add(f"Taegis-Confidence: {confidence}")
    event_count = alert.get("eventCount")
    if event_count is not None:
        add(f"Taegis-EventCount: {event_count}")
    status = alert.get("status")
    if isinstance(status, str) and status.strip():
        add(f"Taegis-Status: {status.strip()}")
    created = metadata.get("createdAt") or alert.get("createdAt")
    if created:
        add(f"Taegis-CreatedAt: {created}")

    for cve in collect_cves(alert):
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    return refs


def collect_investigation_refs(inv, tenant_id, host):
    """Build the refs list for one Taegis investigation."""
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

    if not isinstance(inv, dict):
        return refs

    inv_id = str(inv.get("id") or "").strip()
    if inv_id:
        deep = investigation_console_url(host, inv_id, tenant_id)
        if deep:
            add(deep)
        add(f"Taegis-InvestigationID: {inv_id}")
    if tenant_id:
        add(f"Taegis-TenantID: {tenant_id}")

    title = inv.get("title")
    if title:
        add(f"Taegis-Title: {str(title).strip()}")
    priority = inv.get("priority")
    if priority is not None:
        add(f"Taegis-Priority: {priority}")
    status = inv.get("status")
    if isinstance(status, str) and status.strip():
        add(f"Taegis-Status: {status.strip()}")
    inv_type = inv.get("type")
    if inv_type:
        add(f"Taegis-Type: {str(inv_type).strip()}")
    alert_count = inv.get("alertCount")
    if alert_count is not None:
        add(f"Taegis-AlertCount: {alert_count}")
    assignee = inv.get("assignee")
    if isinstance(assignee, dict):
        email = assignee.get("email")
        if email:
            add(f"Taegis-Assignee: {str(email).strip()}")
    elif isinstance(assignee, str) and assignee.strip():
        add(f"Taegis-Assignee: {assignee.strip()}")
    created = inv.get("createdAt")
    if created:
        add(f"Taegis-CreatedAt: {created}")
    updated = inv.get("updatedAt")
    if updated:
        add(f"Taegis-UpdatedAt: {updated}")
    tags = inv.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if tag:
                add(f"Taegis-Tag: {str(tag).strip()}")

    for cve in collect_cves(inv):
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    return refs


def build_alert_vulnerability(alert, tenant_id, host, min_severity=None):
    """Build a Faraday vulnerability dict for one Taegis XDR alert."""
    if not isinstance(alert, dict):
        return None
    metadata = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    raw_title = str(metadata.get("title") or alert.get("title") or alert.get("id") or "").strip()
    description = str(metadata.get("description") or alert.get("description") or "").strip()
    severity_val = metadata.get("severity")
    if severity_val is None:
        severity_val = alert.get("severity")
    severity = severity_from_taegis(severity_val)
    if not severity_meets_threshold(severity, min_severity):
        return None

    alert_id = str(alert.get("id") or "").strip()
    desc_parts = []
    if description:
        desc_parts.append(description)
    if alert_id:
        desc_parts.append(f"alertId: {alert_id}")
    if tenant_id:
        desc_parts.append(f"tenantId: {tenant_id}")
    if severity_val is not None:
        desc_parts.append(f"severity: {severity_val}")
    confidence = metadata.get("confidence")
    if confidence is not None:
        desc_parts.append(f"confidence: {confidence}")
    event_count = alert.get("eventCount")
    if event_count is not None:
        desc_parts.append(f"eventCount: {event_count}")
    status = alert.get("status")
    if status:
        desc_parts.append(f"status: {status}")
    created = metadata.get("createdAt") or alert.get("createdAt")
    if created:
        desc_parts.append(f"createdAt: {created}")

    name = f"[Taegis Alert] {raw_title or 'Taegis alert'}"

    return {
        "name": name.strip()[:200] or "Taegis alert",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": (f"alert::{alert_id}" if alert_id else "taegis-alert")[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Triage this Secureworks Taegis XDR alert in the Taegis "
            "console (ctpx.secureworks.com) and apply mitigations per "
            "the runbook attached to the alert; correlate with the "
            "operator's other agents to surface affected hosts."
        ),
        "data": "",
        "refs": collect_alert_refs(alert, tenant_id, host),
        "cve": collect_cves(alert),
        "cwe": [],
        "cvss3": {},
        "tags": ["secureworks-taegis"],
    }


def build_investigation_vulnerability(inv, tenant_id, host, min_severity=None):
    """Build a Faraday vulnerability dict for one Taegis investigation."""
    if not isinstance(inv, dict):
        return None
    raw_title = str(inv.get("title") or inv.get("description") or inv.get("id") or "").strip()
    priority = inv.get("priority")
    status = inv.get("status") if isinstance(inv.get("status"), str) else None

    severity = severity_from_priority(priority)
    if severity is None:
        severity = severity_from_taegis(priority)
    if is_closed_state(status):
        severity = "info"
    if not severity_meets_threshold(severity, min_severity):
        return None

    inv_id = str(inv.get("id") or "").strip()
    desc_parts = []
    description = str(inv.get("description") or "").strip()
    if description:
        desc_parts.append(description)
    if inv_id:
        desc_parts.append(f"investigationId: {inv_id}")
    if tenant_id:
        desc_parts.append(f"tenantId: {tenant_id}")
    if priority is not None:
        desc_parts.append(f"priority: {priority}")
    if status:
        desc_parts.append(f"status: {status}")
    inv_type = inv.get("type")
    if inv_type:
        desc_parts.append(f"type: {inv_type}")
    key_findings = inv.get("keyFindings")
    if key_findings:
        desc_parts.append(f"keyFindings: {key_findings}")
    alert_count = inv.get("alertCount")
    if alert_count is not None:
        desc_parts.append(f"alertCount: {alert_count}")
    assignee = inv.get("assignee")
    if isinstance(assignee, dict):
        email = assignee.get("email")
        if email:
            desc_parts.append(f"assignee: {email}")
    created = inv.get("createdAt")
    if created:
        desc_parts.append(f"createdAt: {created}")
    updated = inv.get("updatedAt")
    if updated:
        desc_parts.append(f"updatedAt: {updated}")

    if is_closed_state(status):
        resolution = (
            f"Taegis has marked this investigation as {status}. No "
            "further triage is required in the Taegis console; verify "
            "the mitigation is reflected on the affected hosts before "
            "closing the Faraday finding."
        )
    else:
        resolution = (
            "Work this Taegis investigation in the console "
            "(ctpx.secureworks.com), apply mitigations per the "
            "analyst's recommendations, and transition the status "
            "from Open -> Awaiting Action -> Closed once verified."
        )

    name = f"[Taegis Investigation] {raw_title or 'Taegis investigation'}"

    return {
        "name": name.strip()[:200] or "Taegis investigation",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": (f"inv::{inv_id}" if inv_id else "taegis-investigation")[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_investigation_refs(inv, tenant_id, host),
        "cve": collect_cves(inv),
        "cwe": [],
        "cvss3": {},
        "tags": ["secureworks-taegis"],
    }


def build_host(vulns, host, tenant_id, alert_count, inv_count):
    """Build the single synthetic host that carries every Taegis vuln."""
    desc_parts = ["source=secureworks-taegis"]
    base = normalize_base_url(host)
    if base:
        desc_parts.append(f"host={base}")
    if tenant_id:
        desc_parts.append(f"tenant_id={tenant_id}")
    try:
        desc_parts.append(f"alerts={int(alert_count)}")
    except (TypeError, ValueError):
        desc_parts.append("alerts=?")
    try:
        desc_parts.append(f"investigations={int(inv_count)}")
    except (TypeError, ValueError):
        desc_parts.append("investigations=?")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["secureworks-taegis"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_token(requests_module, host, client_id, client_secret):
    """Exchange Taegis client credentials for an OAuth2 Bearer token."""
    url = build_token_url(host)
    headers = {
        "Accept": "application/json",
        "Authorization": basic_auth_header(client_id, client_secret),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = urlencode({"grant_type": "client_credentials"})
    try:
        resp = requests_module.post(url, data=body, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"OAuth2 token exchange failed: {exc}")
        return None
    if resp.status_code >= 400:
        log(f"OAuth2 token exchange failed ({resp.status_code}): " f"{resp.text[:500]}")
        return None
    try:
        payload = resp.json()
    except ValueError:
        log("OAuth2 token response was not JSON")
        return None
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token.strip():
        log("OAuth2 token response missing access_token")
        return None
    return token.strip()


def post_graphql(requests_module, host, headers, query, variables):
    """POST a single GraphQL query to Taegis and return the parsed body."""
    url = build_graphql_url(host)
    payload = json.dumps({"query": query, "variables": variables or {}})
    try:
        resp = requests_module.post(url, data=payload, headers=headers, timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"Taegis GraphQL endpoint not found at {url} (404)")
        return None
    if resp.status_code in (401, 403):
        log(f"Taegis auth failed ({resp.status_code}) for {url}: " "check TAEGIS_CLIENT_ID / TAEGIS_CLIENT_SECRET")
        return None
    if resp.status_code >= 400:
        log(f"Taegis request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log(f"Taegis response was not JSON ({url})")
        return None
    errors = extract_graphql_errors(body)
    if errors:
        log(f"Taegis GraphQL errors: {'; '.join(errors)[:500]}")
    return body


def fetch_investigations(requests_module, host, headers, tenant_id, first=DEFAULT_INVESTIGATION_LIMIT):
    """POST the investigations GraphQL query and return the unwrapped list."""
    body = post_graphql(
        requests_module,
        host,
        headers,
        INVESTIGATIONS_QUERY,
        {"tenantId": tenant_id, "first": int(first)},
    )
    if body is None:
        return []
    return extract_investigations(body)


def fetch_alerts(requests_module, host, headers, cql=DEFAULT_ALERT_CQL, limit=DEFAULT_ALERT_LIMIT):
    """POST the alerts GraphQL query and return the unwrapped list."""
    body = post_graphql(
        requests_module,
        host,
        headers,
        ALERTS_QUERY,
        {"cql": cql, "limit": int(limit)},
    )
    if body is None:
        return []
    return extract_alerts(body)


def main():
    started = time.time()

    tenant_id = normalize_tenant_id(env("EXECUTOR_CONFIG_TAEGIS_TENANT_ID"))
    if not tenant_id:
        log("TAEGIS_TENANT_ID is required")
        sys.exit(1)
    min_severity = parse_min_severity(env("EXECUTOR_CONFIG_TAEGIS_MIN_SEVERITY"))
    client_id = env("TAEGIS_CLIENT_ID", required=True)
    client_secret = env("TAEGIS_CLIENT_SECRET", required=True)
    host = env("TAEGIS_HOST", default=DEFAULT_HOST)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_token(requests, host, client_id, client_secret)
    if not token:
        log("Could not obtain a Taegis OAuth2 token; aborting")
        sys.exit(1)
    headers = request_headers(token, tenant_id)

    investigations = fetch_investigations(requests, host, headers, tenant_id)
    log(f"Taegis discovered {len(investigations)} investigations")
    time.sleep(INTER_REQUEST_SLEEP)
    alerts = fetch_alerts(requests, host, headers)
    log(f"Taegis discovered {len(alerts)} alerts")

    vulns = []
    for inv in investigations:
        vuln = build_investigation_vulnerability(inv, tenant_id, host, min_severity)
        if vuln is not None:
            vulns.append(vuln)
    for alert in alerts:
        vuln = build_alert_vulnerability(alert, tenant_id, host, min_severity)
        if vuln is not None:
            vulns.append(vuln)

    log(
        f"Processed {len(vulns)} Taegis records "
        f"(alerts={len(alerts)}, investigations={len(investigations)}, "
        f"min_severity={min_severity or '(none)'})"
    )

    hosts_out = [build_host(vulns, host, tenant_id, len(alerts), len(investigations))]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "secureworks_taegis",
            "command": "secureworks_taegis",
            "params": (
                f"tenant_id={tenant_id} "
                f"min_severity={min_severity or ''} "
                f"alerts={len(alerts)} "
                f"investigations={len(investigations)}"
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
