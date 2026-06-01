#!/usr/bin/env python
"""HackerOne crowd-sourced bug-bounty report importer.

Pulls validated bug-bounty reports from the HackerOne v1
REST API and emits Faraday bulk-create JSON to stdout.
HackerOne is a crowd-sourced security platform — external
researchers submit vulnerability reports against a
program's scope and the program triages, validates,
prioritises, and pays out on the resulting findings.  This
executor surfaces validated reports under the operator's
existing Faraday workspace so the external bug-bounty
pipeline joins the dispatcher's internal scanner output.

Endpoints used:
  GET {H1_HOST}/v1/reports?filter[program][]=<handle>&filter[state][]=<state>&page[number]=N&page[size]=M
      -> Paginated bug-bounty report feed.  HackerOne speaks
      JSON:API so the canonical envelope is
      ``{"data": [{"id": "...", "type": "report",
      "attributes": {...}, "relationships": {...}}],
      "links": {"next": "...", "prev": "..."}}``.  Each
      record's ``attributes`` carries ``title``,
      ``vulnerability_information``, ``state`` (``new`` /
      ``triaged`` / ``needs-more-info`` /
      ``pending-program-review`` / ``informative`` /
      ``resolved`` / ``not-applicable`` / ``duplicate`` /
      ``spam`` / ``retesting`` — HackerOne's published
      state machine), ``severity`` (``critical`` /
      ``high`` / ``medium`` / ``low`` / ``none``, or a
      nested ``{"rating": "...", "score": 0..10}`` shape
      on newer programs), ``created_at`` / ``updated_at``
      / ``triaged_at`` / ``closed_at`` / ``disclosed_at``,
      ``bounty_awarded_amount`` / ``bounty_currency``,
      ``cve_ids`` (list of attributed CVE strings),
      ``weakness`` (CWE attribution), and ``vulnerable_endpoint``
      (URL / asset the researcher targeted).
      ``relationships`` carries pointers to ``program``
      (handle + name), ``reporter`` (researcher username),
      ``swag_awarded`` and ``bounties`` (payout breakdown).

  GET {H1_HOST}/v1/reports/<id>
      -> Individual report fetch (used only when the
      operator pastes a single report id into
      ``H1_PROGRAM_HANDLE`` — not wired in the canonical
      flow but tolerated by ``extract_records`` so a
      misconfigured handle that happens to be a numeric
      report id still surfaces a record rather than a
      silent zero-result run).

Auth: HackerOne's v1 surface uses HTTP Basic Auth — the
dispatcher sends ``Authorization: Basic <base64(H1_USER:H1_API_TOKEN)>``
on every ``/v1/`` request, with no separate login round-trip
(HackerOne provisions a long-lived API token per identity
in the platform's API settings; the username is the
identity's API handle, not the human-readable display
name).  HackerOne also exposes a GraphQL surface under
``/graphql`` but the dispatcher unconditionally uses the
REST path so the same code shape covers both the
researcher-facing and the program-facing token scopes.

Args:
  ``H1_PROGRAM_HANDLE`` (optional) — server-side program
  scope forwarded as the ``filter[program][]=<handle>``
  query parameter on ``/v1/reports``.  Empty / blank walks
  the entire token's program scope (the typical
  operational mode for a single-program identity).
  Comma-separated handles are split + forwarded as
  multiple ``filter[program][]=`` entries so a single
  agent can pull from several programs in one run.
  Whitespace is trimmed around each entry.

  ``H1_STATE`` (optional) — server-side report state
  filter (CSV: ``new`` / ``triaged`` / ``needs-more-info``
  / ``pending-program-review`` / ``informative`` /
  ``resolved`` / ``not-applicable`` / ``duplicate`` /
  ``spam`` / ``retesting``).  Forwarded verbatim as
  ``filter[state][]=<state1>,<state2>,...`` per
  HackerOne's documented filter shape (HackerOne accepts
  the comma-joined form as a single query parameter
  rather than one entry per state, so the dispatcher emits
  a single ``filter[state][]`` param to avoid the URL
  ballooning when the operator supplies all ten states).
  Operator-friendly aliases (``needs-info`` ->
  ``needs-more-info``, ``not-applicable`` /
  ``notapplicable`` / ``na`` -> ``not-applicable``,
  ``dup`` -> ``duplicate``) are normalised.  Blank /
  missing walks every state (the typical operational
  mode for first-time imports; HackerOne's filter is
  inclusive so omitting the filter returns every
  state's reports up to the token's scope).

  ``H1_MIN_SEVERITY`` (optional) — Faraday severity floor
  (case-insensitive ``info`` / ``low`` / ``medium`` /
  ``high`` / ``critical``).  Reports whose mapped
  severity is strictly below the floor are dropped
  client-side after the fetch (HackerOne's severity
  field is the program-set CVSS rating, not the
  researcher's self-assessed one).  Operator-friendly
  aliases (``informational`` -> ``info``, ``moderate``
  -> ``medium``, ``crit`` -> ``critical``, ``none`` ->
  ``info``) are normalised.  Blank / missing input
  keeps every record.

Env vars:
  ``H1_USER`` (mandatory) — the identity's API username
  (provisioned in HackerOne's API settings; this is the
  literal handle the platform issues, not the
  researcher's display name).  Forwarded verbatim as the
  Basic Auth username.

  ``H1_API_TOKEN`` (mandatory) — the long-lived API
  token (also provisioned in HackerOne's API settings).
  Forwarded verbatim as the Basic Auth password — never
  logged or stored on the dispatcher.  The token's scope
  determines which programs the run can read; the
  ``H1_PROGRAM_HANDLE`` filter narrows the scope further
  but cannot widen it.

  ``H1_HOST`` (optional, env-only) — base URL override
  (defaults to ``https://api.hackerone.com``).  Useful
  for the rare on-prem / enterprise mirror and for
  staging tests against ``api.staging.hackerone.com``.
  Whitespace is trimmed; ``https://`` is added when the
  operator pasted in a bare FQDN.

Each HackerOne report becomes one Faraday host.  The host
``ip`` falls back to the ``0.0.0.0`` sentinel because
bug-bounty reports are keyed on a URL / asset path rather
than an IP address; the URL is surfaced as the
``hostname`` and embedded in the vulnerability description.
The report itself becomes one Faraday vulnerability with
the ``[BUG-BOUNTY]`` engine prefix so external researcher
reports land alongside other crowd-sourced feeds.

Severity bucketing:
  - HackerOne's published label vocabulary is
    ``critical`` / ``high`` / ``medium`` / ``low`` /
    ``none`` (CVSS-aligned).  ``none`` is mapped to
    Faraday's ``info`` bucket so the report is still
    visible in the workspace; the rest pass through
    verbatim.
  - The nested ``severity.rating`` / ``severity.score``
    shape (used on newer programs) is tolerated — the
    rating is preferred and the 0..10 score is used as a
    fallback.

Tags: ``[hackerone, pentest-platforms, report]``.  Status
is always ``open`` (HackerOne's terminal ``resolved`` /
``informative`` / ``not-applicable`` / ``duplicate`` /
``spam`` states are preserved via the info-severity
floor + an explicit ``H1-State`` pivot in the refs).
"""

import base64
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

TIMEOUT = 60

REPORTS_PATH = "/v1/reports"
DEFAULT_HOST = "https://api.hackerone.com"

DEFAULT_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100  # HackerOne caps page[size] at 100
DEFAULT_PAGES = 10
MAX_PAGES = 100
INTER_REQUEST_SLEEP = 0.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(ALLOWED_SEVERITIES)}

# HackerOne's published label vocabulary is CVSS-aligned:
# critical / high / medium / low / none.  Operator-friendly
# aliases are normalised to Faraday's canonical lowercase
# ladder; ``none`` is mapped to ``info`` so the report is
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

# HackerOne's published report-state machine.  Operator-
# friendly aliases are normalised to the canonical hyphen
# form HackerOne expects.
STATE_ALIASES = {
    "new": "new",
    "triaged": "triaged",
    "needs-more-info": "needs-more-info",
    "needs_more_info": "needs-more-info",
    "needsmoreinfo": "needs-more-info",
    "needs-info": "needs-more-info",
    "needs_info": "needs-more-info",
    "pending-program-review": "pending-program-review",
    "pending_program_review": "pending-program-review",
    "pendingprogramreview": "pending-program-review",
    "pending": "pending-program-review",
    "informative": "informative",
    "info": "informative",
    "resolved": "resolved",
    "closed": "resolved",
    "fixed": "resolved",
    "not-applicable": "not-applicable",
    "not_applicable": "not-applicable",
    "notapplicable": "not-applicable",
    "na": "not-applicable",
    "duplicate": "duplicate",
    "dup": "duplicate",
    "spam": "spam",
    "retesting": "retesting",
    "retest": "retesting",
}

# HackerOne terminal report states — preserved via an
# explicit H1-State pivot ref but floored to ``info``
# severity (the report is no longer actionable).
CLOSED_STATES = {
    "resolved",
    "informative",
    "not-applicable",
    "duplicate",
    "spam",
}


def log(msg):
    print(f"{datetime.utcnow()} - HackerOne: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on H1_HOST.

    HackerOne's public API is at ``api.hackerone.com``;
    the env-only ``H1_HOST`` knob exists for the rare
    on-prem mirror and the staging endpoint.  Empty /
    missing / non-string inputs return the
    ``DEFAULT_HOST`` so the canonical SaaS flow works
    out of the box.  Whitespace is trimmed and
    ``https://`` is added when the operator pasted in a
    bare FQDN.
    """
    if not host or not isinstance(host, str):
        return DEFAULT_HOST
    text = host.strip().rstrip("/")
    if not text:
        return DEFAULT_HOST
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def parse_program_handles(value):
    """Parse H1_PROGRAM_HANDLE into a list of program handles.

    None / blank / bool -> ``[]`` (no program narrowing;
    walk every program in the token's scope).
    Comma-separated handles are split and trimmed.
    Forwarded as multiple ``filter[program][]=<handle>``
    query entries so a single agent can pull from
    several programs in one run.
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


def parse_states(value):
    """Parse H1_STATE into a CSV of canonical HackerOne report states.

    None / blank / bool -> ``""`` (no state narrowing;
    walk every state).  Comma-separated states are
    split, trimmed, normalised via STATE_ALIASES, and
    deduplicated.  Unknown entries are dropped silently
    (a typo never crashes the dispatcher).  Returns the
    canonical CSV string ready to forward as a single
    ``filter[state][]=<csv>`` query parameter.
    """
    if value is None or isinstance(value, bool):
        return ""
    if not isinstance(value, str):
        return ""
    out = []
    seen = set()
    for entry in value.split(","):
        s = entry.strip().lower()
        if not s:
            continue
        canonical = STATE_ALIASES.get(s)
        if canonical is None:
            continue
        if canonical not in seen:
            seen.add(canonical)
            out.append(canonical)
    return ",".join(out)


def normalize_severity_label(value):
    """Coerce a HackerOne severity label to Faraday's ladder.

    Returns ``None`` for missing / non-string / unknown
    inputs so the caller can fall back to numeric
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
    """Parse H1_MIN_SEVERITY into a canonical Faraday severity.

    Accepts the canonical labels + the operator-friendly
    aliases (``informational`` / ``moderate`` / ``crit``
    / ``elevated`` / ``severe`` / ``none``).  Returns
    ``None`` for missing / blank / unparseable inputs so
    the caller treats the run as 'keep every record'.
    """
    return normalize_severity_label(value)


def severity_from_report(value):
    """Bucket Faraday severity from a HackerOne report severity field.

    Accepts the scalar label form (``critical`` /
    ``high`` / ``medium`` / ``low`` / ``none``), the
    nested ``{"rating": "...", "score": 0..10}`` shape
    (used on newer programs), or a raw 0..10 numeric
    score (falls back to the standard 0..10 ladder).
    Returns ``"info"`` for missing / unparseable inputs.
    """
    if isinstance(value, dict):
        rating = value.get("rating")
        label = normalize_severity_label(rating) if isinstance(rating, str) else None
        if label is not None:
            return label
        score = value.get("score")
        if score is not None:
            return severity_from_report(score)
        return "info"
    label = normalize_severity_label(value) if isinstance(value, str) else None
    if label is not None:
        return label
    if isinstance(value, bool) or value is None:
        return "info"
    try:
        if isinstance(value, str):
            num = float(value.strip())
        else:
            num = float(value)
    except (TypeError, ValueError):
        return "info"
    if num != num:  # NaN
        return "info"
    if num < 0:
        return "info"
    if num >= 9.0:
        return "critical"
    if num >= 7.0:
        return "high"
    if num >= 4.0:
        return "medium"
    if num > 0.0:
        return "low"
    return "info"


def severity_meets_threshold(severity, min_severity):
    """True when ``severity`` >= ``min_severity`` in Faraday's ladder.

    ``min_severity is None`` keeps every record.  Unknown
    severity strings are dropped when a threshold is set
    (conservative — we cannot prove the record meets the
    bar).
    """
    if min_severity is None:
        return True
    if severity not in SEVERITY_ORDER or min_severity not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[min_severity]


def is_closed_state(value):
    """True when a HackerOne report ``state`` is terminally closed."""
    if not isinstance(value, str):
        return False
    canonical = STATE_ALIASES.get(value.strip().lower())
    return canonical in CLOSED_STATES


def build_reports_url(host):
    return f"{normalize_base_url(host)}{REPORTS_PATH}"


def build_query(page, page_size=DEFAULT_PAGE_SIZE, program_handles=None, states=""):
    """Build the canonical HackerOne paging + filter query string.

    HackerOne's v1 surface uses JSON:API style
    ``page[number]=N`` + ``page[size]=M`` pagination.
    Program handles are forwarded as repeated
    ``filter[program][]=<handle>`` entries (the JSON:API
    array-filter convention HackerOne documents) so a
    single run can pull from several programs.  States
    are forwarded as a single comma-joined
    ``filter[state][]=<csv>`` parameter (HackerOne
    accepts both forms but the joined form avoids the
    URL ballooning when the operator supplies all ten
    states).  Bad page / page_size inputs are coerced to
    safe defaults so a typo never crashes the dispatcher.
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
    params = [("page[number]", p), ("page[size]", s)]
    if program_handles:
        for handle in program_handles:
            text = str(handle).strip()
            if text:
                params.append(("filter[program][]", text))
    if states:
        text = str(states).strip()
        if text:
            params.append(("filter[state][]", text))
    return urlencode(params)


def basic_auth_header(username, password):
    """Build the ``Authorization: Basic <base64(user:token)>`` value.

    None / non-string inputs are coerced to empty strings
    so the server can return a useful 401.  The
    credentials are never logged or stored on the
    dispatcher.
    """
    u = username.strip() if isinstance(username, str) else ""
    p = password.strip() if isinstance(password, str) else (str(password) if password is not None else "")
    token = base64.b64encode(f"{u}:{p}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def request_headers(username, password):
    """Build the request-header dict for a credentialed v1 GET.

    HackerOne's v1 surface documents HTTP Basic Auth on
    every ``/v1/`` request.  Missing / blank credentials
    still produce a (well-formed but unauthorised) Basic
    header so the server's 401 surfaces as a clear error
    rather than a silently-skipped header.
    """
    return {
        "Accept": "application/json",
        "Authorization": basic_auth_header(username, password),
    }


def extract_records(body):
    """Pull the report list from a HackerOne v1 response envelope.

    Canonical envelope wraps the record list under
    ``data`` (HackerOne's JSON:API shape).  Federated
    mirrors / staging stacks also expose bare-list /
    ``results`` / ``items`` / ``reports`` — all shapes
    are tolerated.  Non-dict entries are silently
    dropped.  A single-record fetch (e.g.  ``GET
    /v1/reports/<id>``) returns the record directly
    under ``data``; that case is collapsed into a
    one-element list so downstream pagination still
    works.
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
    for key in ("results", "items", "reports"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def report_attributes(report):
    """Pull the JSON:API ``attributes`` sub-dict from a report.

    Returns the ``attributes`` sub-dict if present;
    falls back to the record itself for federated
    mirrors that flatten the JSON:API envelope.  Always
    returns a dict so callers can ``.get(...)`` safely.
    """
    if not isinstance(report, dict):
        return {}
    attrs = report.get("attributes")
    if isinstance(attrs, dict):
        return attrs
    return report


def report_relationships(report):
    """Pull the JSON:API ``relationships`` sub-dict from a report.

    Returns the ``relationships`` sub-dict if present;
    falls back to ``{}`` for federated mirrors that
    flatten the envelope.  Always returns a dict so
    callers can ``.get(...)`` safely.
    """
    if not isinstance(report, dict):
        return {}
    rels = report.get("relationships")
    if isinstance(rels, dict):
        return rels
    return {}


def report_program_handle(report):
    """Pick the report's program handle from the relationships sub-dict.

    HackerOne carries the program handle under
    ``relationships.program.data.attributes.handle`` (the
    JSON:API nested-attribute convention).  Federated /
    staging mirrors also expose it directly under
    ``attributes.program_handle`` / ``program_handle``.
    Returns ``""`` when nothing usable is present.
    """
    if not isinstance(report, dict):
        return ""
    rels = report_relationships(report)
    program = rels.get("program")
    if isinstance(program, dict):
        data = program.get("data")
        if isinstance(data, dict):
            attrs = data.get("attributes")
            if isinstance(attrs, dict):
                for key in ("handle", "name"):
                    v = attrs.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            handle = data.get("handle") or data.get("id")
            if isinstance(handle, str) and handle.strip():
                return handle.strip()
    attrs = report_attributes(report)
    for key in ("program_handle", "program"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def report_reporter(report):
    """Pick the report's reporter username from the relationships sub-dict."""
    if not isinstance(report, dict):
        return ""
    rels = report_relationships(report)
    reporter = rels.get("reporter")
    if isinstance(reporter, dict):
        data = reporter.get("data")
        if isinstance(data, dict):
            attrs = data.get("attributes")
            if isinstance(attrs, dict):
                for key in ("username", "name"):
                    v = attrs.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    attrs = report_attributes(report)
    for key in ("reporter_username", "reporter"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def report_url(report):
    """Pick the vulnerable URL / endpoint the report targets.

    HackerOne carries the vulnerable URL under
    ``attributes.vulnerable_endpoint`` (the report
    submission form's URL field); federated mirrors
    also expose ``vulnerable_url`` / ``url`` / a list
    under ``structured_scope`` for programs that
    require scoped URLs.  Returns ``""`` when nothing
    usable is present.
    """
    attrs = report_attributes(report)
    for key in ("vulnerable_endpoint", "vulnerable_url", "url"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    scope = attrs.get("structured_scope")
    if isinstance(scope, dict):
        v = scope.get("asset_identifier")
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def report_severity(report):
    """Pick the report's severity (label or nested rating/score)."""
    attrs = report_attributes(report)
    sev = attrs.get("severity")
    if sev is None:
        rels = report_relationships(report)
        nested = rels.get("severity")
        if isinstance(nested, dict):
            data = nested.get("data")
            if isinstance(data, dict):
                inner = data.get("attributes")
                if isinstance(inner, dict):
                    return inner
    return sev


def collect_cves(record):
    """Walk a HackerOne report for CVE ids.

    HackerOne surfaces CVE attribution on reports via
    ``attributes.cve_ids`` (list of CVE strings) and
    embeds CVE refs in the title / vulnerability
    information body.  All occurrences are deduplicated
    and uppercased to NVD's canonical form.
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

    attrs = report_attributes(record)
    for key in ("cve_ids", "cves", "cve_list"):
        raw = attrs.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("id"))
        elif isinstance(raw, str):
            scan(raw)

    for key in ("title", "vulnerability_information", "description", "summary"):
        scan(attrs.get(key))

    return out


def collect_cwes(record):
    """Walk a HackerOne report for CWE ids.

    HackerOne surfaces CWE attribution on reports via
    the nested ``relationships.weakness.data.attributes.external_id``
    (the canonical CWE-NNN string); federated mirrors
    also expose ``attributes.weakness`` / ``cwe`` and
    embed CWE refs in the title / vulnerability
    information body.  All occurrences are deduplicated
    and uppercased.
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

    rels = report_relationships(record)
    weakness = rels.get("weakness")
    if isinstance(weakness, dict):
        data = weakness.get("data")
        if isinstance(data, dict):
            attrs = data.get("attributes")
            if isinstance(attrs, dict):
                for key in ("external_id", "name"):
                    scan(attrs.get(key))

    attrs = report_attributes(record)
    weakness = attrs.get("weakness")
    if isinstance(weakness, dict):
        for key in ("external_id", "name", "id"):
            scan(weakness.get(key))
    elif isinstance(weakness, str):
        scan(weakness)

    for key in ("title", "vulnerability_information", "description", "summary", "cwe"):
        scan(attrs.get(key))

    return out


def collect_refs(record):
    """Build the refs list for a HackerOne report record."""
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

    rec_id = record.get("id") or record.get("uuid")
    if rec_id is not None and str(rec_id).strip():
        add(f"H1-ReportID: {str(rec_id).strip()}")

    program_handle = report_program_handle(record)
    if program_handle:
        add(f"H1-Program: {program_handle}")
        add(f"https://hackerone.com/{program_handle}")

    reporter = report_reporter(record)
    if reporter:
        add(f"H1-Reporter: {reporter}")
        add(f"https://hackerone.com/{reporter}")

    attrs = report_attributes(record)
    for key, label in (
        ("state", "H1-State"),
        ("substate", "H1-Substate"),
        ("created_at", "H1-CreatedAt"),
        ("updated_at", "H1-UpdatedAt"),
        ("triaged_at", "H1-TriagedAt"),
        ("closed_at", "H1-ClosedAt"),
        ("disclosed_at", "H1-DisclosedAt"),
        ("bounty_awarded_amount", "H1-Bounty"),
        ("bounty_currency", "H1-Currency"),
        ("source", "H1-Source"),
        ("vulnerable_endpoint", "H1-VulnerableEndpoint"),
    ):
        v = attrs.get(key)
        if v in (None, ""):
            continue
        add(f"{label}: {v}")

    sev = report_severity(record)
    if isinstance(sev, str) and sev.strip():
        add(f"H1-Severity: {sev.strip()}")
    elif isinstance(sev, dict):
        rating = sev.get("rating")
        if isinstance(rating, str) and rating.strip():
            add(f"H1-Severity: {rating.strip()}")
        score = sev.get("score")
        if score not in (None, ""):
            add(f"H1-CVSS: {score}")

    rec_id_str = str(rec_id).strip() if rec_id is not None else ""
    if rec_id_str:
        add(f"https://hackerone.com/reports/{rec_id_str}")

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


def build_report_vulnerability(report, min_severity=None):
    """Build a Faraday vulnerability dict for one HackerOne report.

    Returns ``None`` when the report's mapped severity
    is below ``min_severity``.  Terminal HackerOne
    states (``resolved`` / ``informative`` /
    ``not-applicable`` / ``duplicate`` / ``spam``)
    floor the severity to ``info`` regardless of the
    published rating.  The report is surfaced as a
    Faraday vulnerability with the ``[BUG-BOUNTY]``
    engine prefix so external researcher reports land
    alongside the other crowd-sourced feeds.
    """
    if not isinstance(report, dict):
        return None
    attrs = report_attributes(report)
    state = attrs.get("state") if isinstance(attrs.get("state"), str) else None
    sev_value = report_severity(report)
    severity = severity_from_report(sev_value)
    if is_closed_state(state):
        severity = "info"
    if not severity_meets_threshold(severity, min_severity):
        return None

    title = attrs.get("title") or report.get("id") or "HackerOne report"
    name = f"[BUG-BOUNTY] HackerOne report: {str(title).strip()}"

    desc_parts = []
    vinfo = attrs.get("vulnerability_information") or attrs.get("description") or attrs.get("summary") or ""
    if isinstance(vinfo, str) and vinfo.strip():
        desc_parts.append(vinfo.strip())
    for key in sorted(attrs.keys()):
        if key in ("vulnerability_information", "description", "summary", "title"):
            continue
        v = attrs.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    program_handle = report_program_handle(report)
    if program_handle:
        desc_parts.append(f"program: {program_handle}")
    reporter = report_reporter(report)
    if reporter:
        desc_parts.append(f"reporter: {reporter}")

    report_id = str(report.get("id") or report.get("uuid") or name)

    if is_closed_state(state):
        resolution = (
            f"HackerOne has marked this report as {state}; "
            "verify the underlying vulnerability is patched "
            "(for resolved reports) or that the platform's "
            "triage decision matches the operator's risk "
            "appetite (for informative / not-applicable / "
            "duplicate / spam) before closing the Faraday "
            "finding."
        )
    else:
        resolution = (
            "Triage this HackerOne report in the program's "
            "inbox, correlate the vulnerable_endpoint URL "
            "against the operator's asset inventory, and "
            "coordinate with the researcher via the report "
            "thread for any reproduction steps or proof-of-"
            "concept artefacts.  Award the bounty once the "
            "finding is validated per the program's payout "
            "policy."
        )

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"h1-report::{report_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(report),
        "cve": collect_cves(report),
        "cwe": collect_cwes(report),
        "cvss3": {},
        "tags": ["hackerone", "pentest-platforms", "report"],
    }


def build_host_from_report(report, min_severity=None):
    """Build a Faraday host dict from a HackerOne report record."""
    if not isinstance(report, dict):
        return None
    vuln = build_report_vulnerability(report, min_severity)
    if vuln is None:
        return None
    attrs = report_attributes(report)
    hostnames = []
    title = attrs.get("title")
    if isinstance(title, str) and title.strip():
        hostnames.append(title.strip())
    url = report_url(report)
    if url and url not in hostnames:
        hostnames.append(url)
    program_handle = report_program_handle(report)
    desc_parts = []
    if program_handle:
        desc_parts.append(f"program={program_handle}")
    state = attrs.get("state")
    if isinstance(state, str) and state.strip():
        desc_parts.append(f"state={state.strip()}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts) or "HackerOne bug-bounty report",
        "vulnerabilities": [vuln],
    }


def fetch_pages(requests_module, url, headers, program_handles, states, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk the HackerOne /v1/reports surface page-by-page.

    Pagination is one-based via JSON:API's ``page[number]=N``
    + ``page[size]=M``.  Walks until either
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
        qs = build_query(page, page_size=page_size, program_handles=program_handles, states=states)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("HackerOne request rejected (401); check H1_USER / H1_API_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("HackerOne request rejected (403); check the token's program scope.")
            return out
        if resp.status_code == 429:
            log("HackerOne rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"HackerOne request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"HackerOne response was not JSON ({full_url})")
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
        log(f"hit H1_PAGES={max_pages}; stopping pagination")
    return out


def validate_pages(value):
    """Coerce H1_PAGES into a clamped integer.

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

    program_handles = parse_program_handles(env("EXECUTOR_CONFIG_H1_PROGRAM_HANDLE"))
    states = parse_states(env("EXECUTOR_CONFIG_H1_STATE"))
    min_severity = parse_min_severity(env("EXECUTOR_CONFIG_H1_MIN_SEVERITY"))
    pages = validate_pages(env("H1_PAGES"))

    host = env("H1_HOST", default=DEFAULT_HOST)
    username = env("H1_USER", required=True)
    api_token = env("H1_API_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = request_headers(username, api_token)
    reports_url = build_reports_url(host)

    reports = fetch_pages(
        requests,
        reports_url,
        headers,
        program_handles,
        states,
        max_pages=pages,
    )
    log(
        f"HackerOne discovered {len(reports)} reports "
        f"(programs={','.join(program_handles) or '(all)'}, "
        f"states={states or '(all)'})"
    )

    hosts_out = []
    for record in reports:
        built = build_host_from_report(record, min_severity)
        if built is not None:
            hosts_out.append(built)

    log(
        f"Processed {len(hosts_out)} HackerOne hosts "
        f"(reports={len(reports)}, "
        f"min_severity={min_severity or '(none)'})"
    )

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "hackerone",
            "command": "hackerone",
            "params": (
                f"programs={','.join(program_handles)} "
                f"states={states} "
                f"min_severity={min_severity or ''} "
                f"reports={len(reports)} "
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
