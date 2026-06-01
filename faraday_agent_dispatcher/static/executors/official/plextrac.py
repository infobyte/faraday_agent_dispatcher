#!/usr/bin/env python
"""PlexTrac pentest finding importer.

Pulls validated findings from the PlexTrac REST API and
emits Faraday bulk-create JSON to stdout.  PlexTrac is a
pentest reporting and collaboration platform — internal
red teams and external consultants author findings
during scoped engagements and the platform tracks the
resulting findings through an Open / In Process /
Closed lifecycle.  This executor surfaces validated
findings under the operator's existing Faraday
workspace so the external pentest pipeline joins the
dispatcher's internal scanner output.

Endpoints used:
  POST {PLEXTRAC_HOST}/api/v1/authenticate
      -> Login endpoint.  Body
      ``{"username": "...", "password": "..."}``;
      response envelope
      ``{"token": "<JWT>", "tenant_id": "...",
      "tenantId": "..."}`` (older PlexTrac releases
      return ``token``; newer multi-tenant tenants
      include ``tenant_id`` / ``tenantId``).  The
      returned JWT is forwarded verbatim on every
      subsequent ``/api/v1/`` request as the
      ``Authorization: Bearer <token>`` header value.

  GET {PLEXTRAC_HOST}/api/v1/findings?client_id=<id>&report_id=<id>&limit=N&offset=M
      -> Paginated finding feed.  Canonical envelope is
      ``{"data": [{...}], "total": N}`` (newer releases
      wrap under ``data``; older releases return a bare
      list).  Each record carries ``flaw_id`` / ``id``,
      ``title``, ``severity`` (``Critical`` / ``High``
      / ``Medium`` / ``Low`` / ``Informational`` —
      PlexTrac's published label ladder), ``status``
      (``Open`` / ``In Process`` / ``Closed`` /
      ``Mitigated`` / ``Accepted Risk`` / ``Resolved``
      — PlexTrac's published state machine),
      ``description`` (finding write-up),
      ``recommendations`` (remediation guidance),
      ``references`` (free-text refs body),
      ``affected_assets`` (dict of scoped asset id ->
      ``{"asset": "<url>", "status": "..."}`` for the
      assets the finding hits), ``cvss`` / ``cvss_vector``,
      ``cve`` / ``cwe`` (attributed CVE / CWE strings),
      ``client_id`` / ``report_id``, ``assignedTo`` /
      ``createdBy`` (PlexTrac user identifiers),
      ``created_at`` / ``updated_at`` / ``closed_at`` /
      ``last_update`` (epoch seconds or ISO 8601),
      ``tags`` (operator-set free-text tags).

  GET {PLEXTRAC_HOST}/api/v1/clients/<id>/reports
      -> Paginated reports-per-client feed.  Documented
      here so the operator understands which uuids
      belong to which reports; the dispatcher never
      fetches this endpoint directly (the operator
      pastes the relevant ``PLEXTRAC_REPORT_ID`` into
      the manifest argument).

Auth: PlexTrac's REST surface uses a short-lived JWT
minted from the operator's long-lived
``PLEXTRAC_USER`` + ``PLEXTRAC_PASSWORD`` pair.  The
``/api/v1/authenticate`` POST consumes the
username / password body and returns the JWT, which
the dispatcher then forwards verbatim as the
``Authorization: Bearer <token>`` header value on
every subsequent ``/api/v1/`` request.  The
``Accept: application/json`` header is forced so
PlexTrac never tries to negotiate an HTML envelope.

Args:
  ``PLEXTRAC_CLIENT_ID`` (optional) — server-side
  PlexTrac client-scope predicate forwarded as the
  ``client_id=<id>`` query parameter on
  ``/api/v1/findings``.  Empty / blank walks the
  entire identity's client scope (the typical
  operational mode for a first-time import).
  Comma-separated client ids are split + trimmed +
  deduplicated; PlexTrac accepts either the numeric id
  or the uuid — the dispatcher forwards whatever the
  operator pasted in verbatim.

  ``PLEXTRAC_REPORT_ID`` (optional) — server-side
  PlexTrac report-scope predicate forwarded as the
  ``report_id=<id>`` query parameter on
  ``/api/v1/findings``.  Empty / blank walks the
  entire client's report scope.  Comma-separated
  report ids are split + trimmed + deduplicated so a
  single agent can pull findings from several reports
  in one run (e.g. ``acme-q1-pentest,acme-mobile-q1``).

Env vars:
  ``PLEXTRAC_USER`` (mandatory) — login username or
  email (provisioned per identity in PlexTrac's user
  settings).  Posted in the ``/api/v1/authenticate``
  body — never logged or stored on the dispatcher.

  ``PLEXTRAC_PASSWORD`` (mandatory) — login password.
  Posted in the ``/api/v1/authenticate`` body — never
  logged or stored on the dispatcher.

  ``PLEXTRAC_HOST`` (optional, env-only) — base URL
  override (defaults to ``https://api.plextrac.com``,
  the public PlexTrac SaaS endpoint).  Almost every
  PlexTrac tenant runs on its own ``<tenant>.plextrac.com``
  subdomain, so this env var typically needs to be
  set to the operator's tenant URL.  Whitespace is
  trimmed; ``https://`` is added when the operator
  pasted in a bare FQDN.

Each PlexTrac finding becomes one Faraday host.  The
host ``ip`` falls back to the ``0.0.0.0`` sentinel
because pentest findings are keyed on a URL / asset
path rather than an IP address; the affected-asset
URL is surfaced as the ``hostname`` and embedded in
the vulnerability description.  The finding itself
becomes one Faraday vulnerability with the
``[PENTEST]`` engine prefix so external pentester
findings land alongside the other crowd-sourced
feeds.

Severity bucketing:
  - PlexTrac's published label vocabulary is
    ``Critical`` / ``High`` / ``Medium`` / ``Low`` /
    ``Informational``.  ``Informational`` / ``None``
    map to Faraday's ``info`` bucket so the finding
    is still visible in the workspace; the rest pass
    through verbatim.
  - Terminal PlexTrac statuses (``Closed`` /
    ``Resolved`` / ``Mitigated`` / ``Accepted Risk``)
    floor the severity to ``info`` regardless of the
    published rating; the closed status is preserved
    via an explicit ``PlexTrac-Status`` pivot in the
    refs.

Tags: ``[plextrac, pentest-platforms, finding]``.
Status is always ``open`` (PlexTrac's terminal
statuses are preserved via the info-severity floor +
an explicit ``PlexTrac-Status`` pivot in the refs).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

TIMEOUT = 60

AUTH_PATH = "/api/v1/authenticate"
FINDINGS_PATH = "/api/v1/findings"
REPORTS_PATH = "/api/v1/clients/{client_id}/reports"
DEFAULT_HOST = "https://api.plextrac.com"
ACCEPT_HEADER = "application/json"

DEFAULT_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100  # PlexTrac caps limit at 100
DEFAULT_PAGES = 10
MAX_PAGES = 100
INTER_REQUEST_SLEEP = 0.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(ALLOWED_SEVERITIES)}

# PlexTrac's published label vocabulary is
# Critical / High / Medium / Low / Informational.
# Operator-friendly aliases are normalised to Faraday's
# canonical lowercase ladder; ``informational`` /
# ``none`` are mapped to ``info`` so the finding is
# still visible in the workspace.
SEVERITY_ALIASES = {
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "high": "high",
    "elevated": "high",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
}

# PlexTrac's published finding-status machine.
# Operator-friendly aliases are normalised to the
# canonical lowercase form for closed-state detection.
STATUS_ALIASES = {
    "open": "open",
    "new": "open",
    "in process": "in process",
    "in_process": "in process",
    "in-process": "in process",
    "inprocess": "in process",
    "in progress": "in process",
    "in_progress": "in process",
    "in-progress": "in process",
    "closed": "closed",
    "fixed": "closed",
    "resolved": "resolved",
    "mitigated": "mitigated",
    "accepted risk": "accepted risk",
    "accepted_risk": "accepted risk",
    "accepted-risk": "accepted risk",
    "acceptedrisk": "accepted risk",
    "accepted": "accepted risk",
    "risk_accepted": "accepted risk",
    "risk-accepted": "accepted risk",
}

# PlexTrac terminal finding statuses — preserved via an
# explicit PlexTrac-Status pivot ref but floored to
# ``info`` severity (the finding is no longer
# actionable).
CLOSED_STATUSES = {
    "closed",
    "resolved",
    "mitigated",
    "accepted risk",
}


def log(msg):
    print(f"{datetime.utcnow()} - PlexTrac: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on PLEXTRAC_HOST.

    Almost every PlexTrac tenant runs on its own
    ``<tenant>.plextrac.com`` subdomain, so the env-only
    ``PLEXTRAC_HOST`` knob typically needs to be set;
    the ``DEFAULT_HOST`` placeholder
    (``https://api.plextrac.com``) is preserved as a
    fallback so the canonical SaaS multi-tenant entry
    point works out of the box.  Empty / missing /
    non-string inputs return the ``DEFAULT_HOST``.
    Whitespace is trimmed and ``https://`` is added
    when the operator pasted in a bare FQDN.
    """
    if not host or not isinstance(host, str):
        return DEFAULT_HOST
    text = host.strip().rstrip("/")
    if not text:
        return DEFAULT_HOST
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def parse_csv_ids(value):
    """Parse a comma-separated id list into a deduped, trimmed list.

    None / blank / bool -> ``[]`` (no narrowing; walk
    the entire identity's scope).  Comma-separated ids
    / uuids are split, trimmed and deduplicated.
    PlexTrac accepts either numeric ids or uuids — the
    dispatcher forwards whatever the operator pasted
    in verbatim.
    """
    if value is None or isinstance(value, bool):
        return []
    if not isinstance(value, str):
        return []
    out = []
    seen = set()
    for entry in value.split(","):
        s = entry.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def normalize_severity_label(value):
    """Coerce a PlexTrac severity label to Faraday's ladder.

    Returns ``None`` for missing / non-string / unknown
    inputs so the caller can fall back to ``info``
    bucketing.
    """
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    return SEVERITY_ALIASES.get(text)


def parse_min_severity(value):
    """Parse PLEXTRAC_MIN_SEVERITY into a canonical Faraday label.

    Reserved for future use — the manifest does not
    expose a min-severity argument for parity with
    PlexTrac's primary use case (operators typically
    want every finding the platform surfaces).
    Documented here so the helper round-trips via
    ``normalize_severity_label``.
    """
    return normalize_severity_label(value)


def severity_from_finding(value):
    """Bucket Faraday severity from a PlexTrac severity field.

    Accepts the scalar label form (``Critical`` /
    ``High`` / ``Medium`` / ``Low`` / ``Informational``)
    and the nested ``{"rating": "...", "score": 0..10}``
    shape used by federated mirrors.  Returns
    ``"info"`` for missing / unparseable inputs so the
    finding is still visible in the workspace.
    """
    if isinstance(value, dict):
        nested = value.get("rating") or value.get("value") or value.get("label")
        label = normalize_severity_label(nested) if isinstance(nested, str) else None
        if label is not None:
            return label
        score = value.get("score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            return severity_from_score(score)
        return "info"
    label = normalize_severity_label(value) if isinstance(value, str) else None
    if label is not None:
        return label
    return "info"


def severity_from_score(score):
    """Bucket Faraday severity from a CVSS 0..10 score.

    Uses CVSS v3's published ranges: 0.0 -> info,
    0.1..3.9 -> low, 4.0..6.9 -> medium, 7.0..8.9 ->
    high, 9.0..10.0 -> critical.  Returns ``"info"``
    for out-of-range inputs.
    """
    try:
        n = float(score)
    except (TypeError, ValueError):
        return "info"
    if n <= 0:
        return "info"
    if n < 4.0:
        return "low"
    if n < 7.0:
        return "medium"
    if n < 9.0:
        return "high"
    if n <= 10.0:
        return "critical"
    return "info"


def severity_meets_threshold(severity, min_severity):
    """True when ``severity`` is at or above ``min_severity`` on Faraday's ladder.

    ``min_severity is None`` keeps every record.
    Unknown severities fall back to ``info`` (already
    floored) — they only pass when the floor is also
    ``info``.
    """
    if min_severity is None:
        return True
    if severity not in SEVERITY_ORDER:
        severity = "info"
    if min_severity not in SEVERITY_ORDER:
        return True
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[min_severity]


def is_closed_status(value):
    """True when a PlexTrac finding ``status`` is terminally closed."""
    if not isinstance(value, str):
        return False
    canonical = STATUS_ALIASES.get(value.strip().lower())
    return canonical in CLOSED_STATUSES


def build_auth_url(host):
    return f"{normalize_base_url(host)}{AUTH_PATH}"


def build_findings_url(host):
    return f"{normalize_base_url(host)}{FINDINGS_PATH}"


def build_reports_url(host, client_id):
    cid = str(client_id).strip() if client_id is not None else ""
    return f"{normalize_base_url(host)}{REPORTS_PATH.format(client_id=cid)}"


def build_query(page, page_size=DEFAULT_PAGE_SIZE, client_ids=None, report_ids=None):
    """Build the canonical PlexTrac paging + filter query string.

    PlexTrac's REST surface uses ``limit=N`` +
    ``offset=M`` pagination (offset is the zero-based
    record count, not the page number).  Client /
    report ids are forwarded as repeated
    ``client_id=<id>`` / ``report_id=<id>`` entries so
    a single run can pull findings from several
    clients / reports.  Bad page / page_size inputs are
    coerced to safe defaults so a typo never crashes
    the dispatcher.
    """
    try:
        p = int(page)
    except (TypeError, ValueError):
        p = 1
    if p < 1:
        p = 1
    try:
        s = int(page_size)
    except (TypeError, ValueError):
        s = DEFAULT_PAGE_SIZE
    if s < MIN_PAGE_SIZE:
        s = MIN_PAGE_SIZE
    if s > MAX_PAGE_SIZE:
        s = MAX_PAGE_SIZE
    offset = (p - 1) * s
    params = [("limit", s), ("offset", offset)]
    if client_ids:
        for cid in client_ids:
            text = str(cid).strip()
            if text:
                params.append(("client_id", text))
    if report_ids:
        for rid in report_ids:
            text = str(rid).strip()
            if text:
                params.append(("report_id", text))
    return urlencode(params)


def bearer_auth_header(token):
    """Build the ``Authorization: Bearer <token>`` value.

    None / non-string / blank inputs are coerced to an
    empty string so the server can return a useful 401.
    The token is never logged or stored on the
    dispatcher.
    """
    if isinstance(token, str):
        t = token.strip()
    elif token is None or isinstance(token, bool):
        t = ""
    else:
        t = str(token).strip()
    return f"Bearer {t}"


def request_headers(token):
    """Build the request-header dict for a credentialed REST GET.

    PlexTrac's REST surface documents single-header
    auth: the JWT minted by ``/api/v1/authenticate``
    is forwarded as ``Authorization: Bearer <token>``.
    The forced ``Accept: application/json`` keeps
    PlexTrac from trying to negotiate an HTML envelope.
    Missing / blank tokens still produce
    (well-formed but unauthorised) headers so the
    server's 401 surfaces as a clear error rather than
    a silently-skipped header.
    """
    return {
        "Accept": ACCEPT_HEADER,
        "Content-Type": ACCEPT_HEADER,
        "Authorization": bearer_auth_header(token),
    }


def extract_token(body):
    """Pull the JWT from a PlexTrac /api/v1/authenticate response.

    Canonical envelope wraps the token directly under
    ``token`` (older PlexTrac releases); newer
    multi-tenant releases expose it under
    ``access_token`` / ``jwt`` / ``data.token``.  All
    shapes are tolerated.  Returns ``""`` when nothing
    usable is present so the caller can short-circuit
    with a clear 401-equivalent error.
    """
    if isinstance(body, str):
        text = body.strip()
        return text if text else ""
    if not isinstance(body, dict):
        return ""
    for key in ("token", "access_token", "jwt", "id_token"):
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    data = body.get("data")
    if isinstance(data, dict):
        for key in ("token", "access_token", "jwt", "id_token"):
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def extract_records(body):
    """Pull the finding list from a PlexTrac REST response envelope.

    Canonical envelope wraps the record list under
    ``data`` (newer PlexTrac releases); older releases
    return a bare list directly; federated mirrors
    also expose ``results`` / ``items`` / ``findings``
    / ``records`` / ``flaws``.  All shapes are
    tolerated.  Non-dict entries are silently dropped.
    A single-record fetch envelope (``{"id": "..."}``)
    is collapsed into a one-element list so downstream
    pagination still works.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    data = body.get("data")
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]
    if isinstance(data, dict):
        return [data]
    for key in ("results", "items", "findings", "records", "flaws"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
        if isinstance(v, dict):
            return [v]
    if body.get("id") or body.get("flaw_id"):
        return [body]
    return []


def record_id(record):
    """Pick the finding's canonical PlexTrac id."""
    if not isinstance(record, dict):
        return ""
    for key in ("flaw_id", "id", "flawId", "finding_id", "findingId"):
        v = record.get(key)
        if v in (None, ""):
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def record_client_id(record):
    """Pick the finding's parent PlexTrac client id."""
    if not isinstance(record, dict):
        return ""
    for key in ("client_id", "clientId", "client"):
        v = record.get(key)
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            s = str(v).strip()
            if s:
                return s
        if isinstance(v, dict):
            for ik in ("id", "uuid", "value"):
                iv = v.get(ik)
                if isinstance(iv, (str, int, float)) and not isinstance(iv, bool):
                    s = str(iv).strip()
                    if s:
                        return s
    return ""


def record_report_id(record):
    """Pick the finding's parent PlexTrac report id."""
    if not isinstance(record, dict):
        return ""
    for key in ("report_id", "reportId", "report"):
        v = record.get(key)
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            s = str(v).strip()
            if s:
                return s
        if isinstance(v, dict):
            for ik in ("id", "uuid", "value"):
                iv = v.get(ik)
                if isinstance(iv, (str, int, float)) and not isinstance(iv, bool):
                    s = str(iv).strip()
                    if s:
                        return s
    return ""


def record_assignee(record):
    """Pick the finding's PlexTrac assignee / reporter username."""
    if not isinstance(record, dict):
        return ""
    for key in ("assignedTo", "assigned_to", "createdBy", "created_by", "reporter", "researcher"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            for ik in ("username", "email", "name", "handle"):
                iv = v.get(ik)
                if isinstance(iv, str) and iv.strip():
                    return iv.strip()
    return ""


def record_status(record):
    """Pick the finding's canonical PlexTrac status."""
    if not isinstance(record, dict):
        return ""
    for key in ("status", "state"):
        v = record.get(key)
        if isinstance(v, dict):
            for ik in ("value", "label", "name"):
                iv = v.get(ik)
                if isinstance(iv, str) and iv.strip():
                    return iv.strip()
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_severity_label(record):
    """Pick the finding's PlexTrac severity label (raw, not bucketed)."""
    if not isinstance(record, dict):
        return ""
    sev = record.get("severity")
    if isinstance(sev, dict):
        for key in ("rating", "value", "label"):
            v = sev.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(sev, str) and sev.strip():
        return sev.strip()
    return ""


def record_url(record):
    """Pick the vulnerable URL / asset the finding targets.

    PlexTrac stores affected assets under
    ``affected_assets`` as a dict of asset-id ->
    ``{"asset": "<url>", "status": "..."}``.  Federated
    mirrors also expose ``vulnerable_url`` /
    ``affected_url`` / ``url`` / a list under
    ``assets``.  Returns ``""`` when nothing usable is
    present.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("vulnerable_url", "affected_url", "url", "endpoint"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    affected = record.get("affected_assets")
    if isinstance(affected, dict):
        for entry in affected.values():
            if isinstance(entry, str) and entry.strip():
                return entry.strip()
            if isinstance(entry, dict):
                for ik in ("asset", "url", "name", "value", "endpoint"):
                    iv = entry.get(ik)
                    if isinstance(iv, str) and iv.strip():
                        return iv.strip()
    if isinstance(affected, list):
        for entry in affected:
            if isinstance(entry, str) and entry.strip():
                return entry.strip()
            if isinstance(entry, dict):
                for ik in ("asset", "url", "name", "value", "endpoint"):
                    iv = entry.get(ik)
                    if isinstance(iv, str) and iv.strip():
                        return iv.strip()
    assets = record.get("assets")
    if isinstance(assets, list):
        for entry in assets:
            if isinstance(entry, str) and entry.strip():
                return entry.strip()
            if isinstance(entry, dict):
                for ik in ("asset", "url", "name", "value"):
                    iv = entry.get(ik)
                    if isinstance(iv, str) and iv.strip():
                        return iv.strip()
    return ""


def collect_cves(record):
    """Walk a PlexTrac finding for CVE ids.

    PlexTrac surfaces CVE attribution under ``cve`` /
    ``cves`` / ``cve_ids`` (string or list of CVE
    strings) and embeds CVE refs in the title /
    description / recommendations / references body.
    All occurrences are deduplicated and uppercased to
    NVD's canonical form.
    """
    out = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if CVE_RE.fullmatch(s) and s not in seen:
            seen.add(s)
            out.append(s)

    def scan(text):
        if not isinstance(text, str):
            return
        for m in CVE_RE.findall(text):
            add(m)

    if not isinstance(record, dict):
        return out

    for key in ("cve", "cves", "cve_ids", "cveIds", "cve_list"):
        raw = record.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("id") or entry.get("value"))
        elif isinstance(raw, str):
            scan(raw)

    for key in ("title", "description", "recommendations", "references", "summary"):
        scan(record.get(key))

    return out


def collect_cwes(record):
    """Walk a PlexTrac finding for CWE ids.

    PlexTrac surfaces CWE attribution under ``cwe`` /
    ``cwes`` (string, dict or list).  Pentesters
    frequently embed CWE refs in the title /
    description / recommendations / references body.
    All occurrences are deduplicated and uppercased to
    MITRE's canonical form.
    """
    out = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        m = CWE_RE.fullmatch(s)
        if m and s not in seen:
            seen.add(s)
            out.append(s)

    def scan(text):
        if not isinstance(text, str):
            return
        for m in CWE_RE.findall(text):
            add(f"CWE-{m}")

    if not isinstance(record, dict):
        return out

    for key in ("cwe", "cwes", "cwe_id", "cweId"):
        raw = record.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    scan(entry)
                elif isinstance(entry, dict):
                    scan(entry.get("value") or entry.get("cwe") or entry.get("id") or entry.get("name"))
        elif isinstance(raw, dict):
            for key2 in ("value", "id", "name"):
                scan(raw.get(key2))
        elif isinstance(raw, str):
            scan(raw)

    for key in ("title", "description", "recommendations", "references", "summary"):
        scan(record.get(key))

    return out


def collect_refs(record):
    """Build the refs list for a PlexTrac finding record."""
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

    if not isinstance(record, dict):
        return refs

    rec_id = record_id(record)
    if rec_id:
        add(f"PlexTrac-FindingID: {rec_id}")

    client_id = record_client_id(record)
    if client_id:
        add(f"PlexTrac-Client: {client_id}")

    report_id = record_report_id(record)
    if report_id:
        add(f"PlexTrac-Report: {report_id}")

    assignee = record_assignee(record)
    if assignee:
        add(f"PlexTrac-Assignee: {assignee}")

    status = record_status(record)
    if status:
        add(f"PlexTrac-Status: {status}")

    severity_label = record_severity_label(record)
    if severity_label:
        add(f"PlexTrac-Severity: {severity_label}")

    for key, label in (
        ("substatus", "PlexTrac-Substatus"),
        ("created_at", "PlexTrac-CreatedAt"),
        ("createdAt", "PlexTrac-CreatedAt"),
        ("updated_at", "PlexTrac-UpdatedAt"),
        ("updatedAt", "PlexTrac-UpdatedAt"),
        ("last_update", "PlexTrac-LastUpdate"),
        ("lastUpdate", "PlexTrac-LastUpdate"),
        ("closed_at", "PlexTrac-ClosedAt"),
        ("closedAt", "PlexTrac-ClosedAt"),
        ("source", "PlexTrac-Source"),
        ("vulnerable_url", "PlexTrac-VulnerableURL"),
        ("cvss_vector", "PlexTrac-CVSSVector"),
        ("cvssVector", "PlexTrac-CVSSVector"),
        ("cvss", "PlexTrac-CVSSScore"),
        ("cvss_score", "PlexTrac-CVSSScore"),
        ("cvssScore", "PlexTrac-CVSSScore"),
        ("impact", "PlexTrac-Impact"),
        ("likelihood", "PlexTrac-Likelihood"),
    ):
        v = record.get(key)
        if v in (None, "", [], {}):
            continue
        add(f"{label}: {v}")

    url = record_url(record)
    if url:
        add(f"PlexTrac-Asset: {url}")

    tags = record.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.strip():
                add(f"PlexTrac-Tag: {tag.strip()}")

    if client_id and report_id and rec_id:
        add(f"https://app.plextrac.com/client/{client_id}" f"/report/{report_id}/finding/{rec_id}")
    if client_id and report_id:
        add(f"https://app.plextrac.com/client/{client_id}/report/{report_id}")
    if client_id:
        add(f"https://app.plextrac.com/client/{client_id}")

    for cve in collect_cves(record):
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    for cwe in collect_cwes(record):
        m = CWE_RE.fullmatch(cwe)
        if m:
            add(f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html")

    return refs


def _serialise(value):
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def build_finding_vulnerability(record, min_severity=None):
    """Build a Faraday vulnerability dict for one PlexTrac finding.

    Returns ``None`` when the finding's mapped severity
    is strictly below ``min_severity``.  Terminal
    PlexTrac statuses (``Closed`` / ``Resolved`` /
    ``Mitigated`` / ``Accepted Risk``) floor the
    severity to ``info`` regardless of the published
    rating.  The finding is surfaced as a Faraday
    vulnerability with the ``[PENTEST]`` engine prefix
    so external pentester findings land alongside the
    other crowd-sourced feeds.
    """
    if not isinstance(record, dict):
        return None
    status = record_status(record)
    sev_value = record.get("severity")
    severity = severity_from_finding(sev_value)
    if is_closed_status(status):
        severity = "info"
    if not severity_meets_threshold(severity, min_severity):
        return None

    title = record.get("title") or record.get("name") or record_id(record) or "PlexTrac finding"
    name = f"[PENTEST] PlexTrac finding: {str(title).strip()}"

    desc_parts = []
    vinfo = record.get("description") or record.get("recommendations") or record.get("summary") or ""
    if isinstance(vinfo, str) and vinfo.strip():
        desc_parts.append(vinfo.strip())
    for key in sorted(record.keys()):
        if key in ("description", "recommendations", "summary", "title"):
            continue
        v = record.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")

    rec_id = record_id(record) or name

    if is_closed_status(status):
        resolution = (
            f"PlexTrac has marked this finding as {status}; "
            "verify the underlying vulnerability is patched "
            "(for Closed / Resolved / Mitigated findings) or "
            "that the platform's triage decision matches the "
            "operator's risk appetite (for Accepted Risk) "
            "before closing the Faraday finding."
        )
    else:
        resolution = (
            "Triage this PlexTrac finding in the pentest "
            "workspace, correlate the affected_assets URL "
            "against the operator's asset inventory, and "
            "coordinate with the assignee via the finding "
            "thread for any reproduction steps or "
            "proof-of-concept artefacts.  Validate the "
            "finding against the engagement's scope and "
            "remediate per the platform's recommendations "
            "guidance."
        )

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"plextrac-finding::{rec_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record),
        "cve": collect_cves(record),
        "cwe": collect_cwes(record),
        "cvss3": {},
        "tags": ["plextrac", "pentest-platforms", "finding"],
    }


def build_host_from_finding(record, min_severity=None):
    """Build a Faraday host dict from a PlexTrac finding record."""
    if not isinstance(record, dict):
        return None
    vuln = build_finding_vulnerability(record, min_severity)
    if vuln is None:
        return None
    hostnames = []
    title = record.get("title") or record.get("name")
    if isinstance(title, str) and title.strip():
        hostnames.append(title.strip())
    url = record_url(record)
    if url and url not in hostnames:
        hostnames.append(url)
    client_id = record_client_id(record)
    report_id = record_report_id(record)
    desc_parts = []
    if client_id:
        desc_parts.append(f"client={client_id}")
    if report_id:
        desc_parts.append(f"report={report_id}")
    status = record_status(record)
    if status:
        desc_parts.append(f"status={status}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts) or "PlexTrac pentest finding",
        "vulnerabilities": [vuln],
    }


def authenticate(requests_module, host, user, password):
    """Mint a PlexTrac JWT from username + password.

    Posts to ``/api/v1/authenticate`` and returns the
    JWT string.  Network failures / 4xx / 5xx responses
    sys.exit(1) so the executor never falls through to
    an unauthenticated GET loop.  The JWT is never
    logged.
    """
    url = build_auth_url(host)
    body = {"username": user or "", "password": password or ""}
    try:
        resp = requests_module.post(
            url,
            json=body,
            headers={"Accept": ACCEPT_HEADER, "Content-Type": ACCEPT_HEADER},
            timeout=TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        sys.exit(1)
    if resp.status_code == 401:
        log("PlexTrac /authenticate rejected (401); check PLEXTRAC_USER / PLEXTRAC_PASSWORD.")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"PlexTrac /authenticate failed ({resp.status_code}): {resp.text[:500]}")
        sys.exit(1)
    try:
        payload = resp.json()
    except ValueError:
        log("PlexTrac /authenticate response was not JSON")
        sys.exit(1)
    token = extract_token(payload)
    if not token:
        log("PlexTrac /authenticate response missing token")
        sys.exit(1)
    return token


def fetch_pages(requests_module, url, headers, client_ids, report_ids, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk the PlexTrac /api/v1/findings surface page-by-page.

    Pagination is offset-based via ``limit=N`` +
    ``offset=M``.  Walks until either
    ``len(records) < page_size`` or ``max_pages`` is
    reached.  401 short-circuits the whole executor
    (credentials are wrong); 403 / 429 / 5xx stop
    pagination and return what we have.
    """
    out = []
    page = 1
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(page, page_size=page_size, client_ids=client_ids, report_ids=report_ids)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("PlexTrac request rejected (401); the JWT may have expired.")
            sys.exit(1)
        if resp.status_code == 403:
            log("PlexTrac request rejected (403); check the identity's client / report scope.")
            return out
        if resp.status_code == 429:
            log("PlexTrac rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"PlexTrac request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"PlexTrac response was not JSON ({full_url})")
            return out
        records = extract_records(payload)
        for entry in records:
            if isinstance(entry, dict):
                out.append(entry)
        walked += 1
        if len(records) < page_size:
            break
        page += 1
    if walked >= max_pages and len(records) >= page_size:
        log(f"hit PLEXTRAC_PAGES={max_pages}; stopping pagination")
    return out


def validate_pages(value):
    """Coerce PLEXTRAC_PAGES into a clamped integer.

    Env-only knob (not a manifest argument).  Defaults
    to ``DEFAULT_PAGES`` (10) when missing / blank /
    unparseable.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into thousands of
    requests against the platform.
    """
    if value is None or value == "" or isinstance(value, bool):
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        return MAX_PAGES
    return n


def main():
    started = time.time()

    client_ids = parse_csv_ids(env("EXECUTOR_CONFIG_PLEXTRAC_CLIENT_ID"))
    report_ids = parse_csv_ids(env("EXECUTOR_CONFIG_PLEXTRAC_REPORT_ID"))
    pages = validate_pages(env("PLEXTRAC_PAGES"))

    host = env("PLEXTRAC_HOST", default=DEFAULT_HOST)
    user = env("PLEXTRAC_USER", required=True)
    password = env("PLEXTRAC_PASSWORD", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = authenticate(requests, host, user, password)
    headers = request_headers(token)
    findings_url = build_findings_url(host)

    findings = fetch_pages(
        requests,
        findings_url,
        headers,
        client_ids,
        report_ids,
        max_pages=pages,
    )
    log(
        f"PlexTrac discovered {len(findings)} findings "
        f"(clients={','.join(client_ids) or '(all)'}, "
        f"reports={','.join(report_ids) or '(all)'})"
    )

    hosts_out = []
    for record in findings:
        built = build_host_from_finding(record)
        if built is not None:
            hosts_out.append(built)

    log(f"Processed {len(hosts_out)} PlexTrac hosts " f"(findings={len(findings)})")

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "plextrac",
            "command": "plextrac",
            "params": (
                f"clients={','.join(client_ids)} "
                f"reports={','.join(report_ids)} "
                f"findings={len(findings)} "
                f"pages={pages}"
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
