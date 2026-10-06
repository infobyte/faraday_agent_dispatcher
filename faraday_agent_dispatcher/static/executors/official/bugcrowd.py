#!/usr/bin/env python
"""Bugcrowd crowd-sourced bug-bounty submission importer.

Pulls validated submissions from the Bugcrowd REST API
and emits Faraday bulk-create JSON to stdout.  Bugcrowd
is a crowd-sourced security platform — external
researchers submit vulnerability reports against a
program's scope and the program triages, validates,
prioritises, and pays out on the resulting findings.
This executor surfaces validated submissions under the
operator's existing Faraday workspace so the external
bug-bounty pipeline joins the dispatcher's internal
scanner output.

Endpoints used:
  GET {BC_HOST}/submissions?filter[program][]=<uuid>&filter[state][]=<state>&page[offset]=N&page[limit]=M
      -> Paginated bug-bounty submission feed.  Bugcrowd
      speaks JSON:API so the canonical envelope is
      ``{"data": [{"id": "...", "type": "submission",
      "attributes": {...}, "relationships": {...}}],
      "meta": {"total_hits": N}, "links": {"next": "...",
      "prev": "..."}}``.  Each record's ``attributes``
      carries ``title``, ``description`` /
      ``vulnerability_information``, ``state`` (``new`` /
      ``triaged`` / ``unresolved`` / ``resolved`` /
      ``duplicate`` / ``not-reproducible`` /
      ``not-applicable`` / ``out-of-scope`` /
      ``informational`` / ``needs-reproduction`` /
      ``spam`` — Bugcrowd's published state machine),
      ``substate`` (additional triage detail),
      ``priority`` (integer 1..5 — Bugcrowd's P1..P5
      ladder where P1 is most critical and P5 is least),
      ``cvss_vector`` / ``cvss_score``, ``vrt_id`` (the
      Vulnerability Rating Taxonomy id — Bugcrowd's
      canonical issue-type ontology), ``vrt_version``,
      ``bug_url`` / ``vulnerability_url`` (URL / asset
      the researcher targeted), ``cve`` (attributed CVE
      strings), ``created_at`` / ``submitted_at`` /
      ``triaged_at`` / ``resolved_at`` / ``disclosed_at``
      / ``last_updated_at``, ``monetary_reward`` /
      ``reward_currency`` (payout breakdown).
      ``relationships`` carries pointers to ``program``
      (uuid + name), ``researcher`` (username),
      ``target`` (scoped asset), and ``rewards``
      (payout breakdown).

  GET {BC_HOST}/submissions/<uuid>
      -> Individual submission fetch (used only when the
      operator pastes a single submission uuid into
      ``BC_PROGRAM_UUID`` — not wired in the canonical
      flow but tolerated by ``extract_records`` so a
      misconfigured uuid that happens to be a submission
      uuid still surfaces a record rather than a silent
      zero-result run).

Auth: Bugcrowd's REST surface uses a single long-lived
API token in the ``Authorization: Token <token>``
header (no username — the token alone is the identity).
The token is provisioned per identity in Bugcrowd's API
settings and scopes the run to the programs the
identity has access to; ``BC_PROGRAM_UUID`` narrows the
scope further but cannot widen it.  The dispatcher
locks the API version with the
``Accept: application/vnd.bugcrowd.v4+json`` header so
later API breaking changes do not silently warp the
ingest shape.

Args:
  ``BC_PROGRAM_UUID`` (optional) — server-side program
  scope forwarded as the ``filter[program][]=<uuid>``
  query parameter on ``/submissions``.  Empty / blank
  walks the entire token's program scope (the typical
  operational mode for a single-program identity).
  Comma-separated uuids are split + forwarded as
  multiple ``filter[program][]=`` entries so a single
  agent can pull from several programs in one run
  (e.g. ``11111111-2222-...,22222222-3333-...``).
  Bugcrowd accepts either the program's uuid or its
  slug (``handle``) — the dispatcher forwards
  whatever the operator pasted in verbatim.  Whitespace
  is trimmed around each entry.

  ``BC_STATE`` (optional) — server-side submission
  state filter (CSV: ``new`` / ``triaged`` /
  ``unresolved`` / ``resolved`` / ``duplicate`` /
  ``not-reproducible`` / ``not-applicable`` /
  ``out-of-scope`` / ``informational`` /
  ``needs-reproduction`` / ``spam``).  Forwarded as a
  single comma-joined ``filter[state][]=<csv>`` query
  parameter (Bugcrowd accepts both the comma-joined
  form and one entry per state but the joined form
  avoids URL ballooning when the operator supplies
  many states).  Operator-friendly aliases
  (``open`` -> ``unresolved``, ``nr`` ->
  ``not-reproducible``, ``na`` -> ``not-applicable``,
  ``oos`` -> ``out-of-scope``, ``dup`` ->
  ``duplicate``, ``info`` -> ``informational``,
  ``closed`` / ``fixed`` -> ``resolved``) are
  normalised.  Blank / missing walks every state (the
  typical operational mode for first-time imports).

  ``BC_MIN_PRIORITY`` (optional) — Bugcrowd priority
  floor (integer 1..5, where 1 is most critical and
  5 is least).  Submissions whose priority is
  numerically greater than the floor (less severe)
  are dropped client-side after the fetch.  Bugcrowd's
  priority ladder maps to Faraday severities as
  P1 -> critical, P2 -> high, P3 -> medium,
  P4 -> low, P5 -> info.  Blank / missing input
  keeps every record.

Env vars:
  ``BC_API_TOKEN`` (mandatory) — the long-lived API
  token (provisioned in Bugcrowd's API settings).
  Forwarded verbatim as the
  ``Authorization: Token <token>`` header value —
  never logged or stored on the dispatcher.  The
  token's scope determines which programs the run can
  read; the ``BC_PROGRAM_UUID`` filter narrows the
  scope further but cannot widen it.

  ``BC_HOST`` (optional, env-only) — base URL override
  (defaults to ``https://api.bugcrowd.com``).  Useful
  for the rare enterprise mirror and for staging
  tests against a Bugcrowd-provided sandbox endpoint.
  Whitespace is trimmed; ``https://`` is added when
  the operator pasted in a bare FQDN.

Each Bugcrowd submission becomes one Faraday host.  The
host ``ip`` falls back to the ``0.0.0.0`` sentinel
because bug-bounty submissions are keyed on a URL /
asset path rather than an IP address; the URL is
surfaced as the ``hostname`` and embedded in the
vulnerability description.  The submission itself
becomes one Faraday vulnerability with the
``[BUG-BOUNTY]`` engine prefix so external researcher
reports land alongside the other crowd-sourced feeds.

Severity bucketing:
  - Bugcrowd's published priority ladder is
    P1 (critical) / P2 (high) / P3 (medium) /
    P4 (low) / P5 (info).  Integer or ``P<N>``
    scalar inputs are accepted; missing / unparseable
    inputs default to ``info``.
  - Terminal Bugcrowd states (``resolved`` /
    ``duplicate`` / ``not-reproducible`` /
    ``not-applicable`` / ``out-of-scope`` /
    ``informational`` / ``spam``) floor the severity
    to ``info`` regardless of the published priority.

Tags: ``[bugcrowd, pentest-platforms, submission]``.
Status is always ``open`` (Bugcrowd's terminal states
are preserved via the info-severity floor + an
explicit ``BC-State`` pivot in the refs).
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

SUBMISSIONS_PATH = "/submissions"
DEFAULT_HOST = "https://api.bugcrowd.com"
ACCEPT_HEADER = "application/vnd.bugcrowd.v4+json"

DEFAULT_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100  # Bugcrowd caps page[limit] at 100
DEFAULT_PAGES = 10
MAX_PAGES = 100
INTER_REQUEST_SLEEP = 0.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(ALLOWED_SEVERITIES)}

# Bugcrowd's published priority ladder maps to Faraday's
# severity ladder.  P1 is most critical, P5 is least.
PRIORITY_TO_SEVERITY = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
    5: "info",
}
MIN_PRIORITY = 1
MAX_PRIORITY = 5

# Bugcrowd's published submission-state machine.  Operator-
# friendly aliases are normalised to the canonical hyphen
# form Bugcrowd expects.
STATE_ALIASES = {
    "new": "new",
    "triaged": "triaged",
    "unresolved": "unresolved",
    "open": "unresolved",
    "resolved": "resolved",
    "closed": "resolved",
    "fixed": "resolved",
    "duplicate": "duplicate",
    "dup": "duplicate",
    "not-reproducible": "not-reproducible",
    "not_reproducible": "not-reproducible",
    "notreproducible": "not-reproducible",
    "nr": "not-reproducible",
    "not-applicable": "not-applicable",
    "not_applicable": "not-applicable",
    "notapplicable": "not-applicable",
    "na": "not-applicable",
    "out-of-scope": "out-of-scope",
    "out_of_scope": "out-of-scope",
    "outofscope": "out-of-scope",
    "oos": "out-of-scope",
    "informational": "informational",
    "info": "informational",
    "needs-reproduction": "needs-reproduction",
    "needs_reproduction": "needs-reproduction",
    "needsreproduction": "needs-reproduction",
    "needs-info": "needs-reproduction",
    "needs_info": "needs-reproduction",
    "spam": "spam",
}

# Bugcrowd terminal submission states — preserved via an
# explicit BC-State pivot ref but floored to ``info``
# severity (the submission is no longer actionable).
CLOSED_STATES = {
    "resolved",
    "duplicate",
    "not-reproducible",
    "not-applicable",
    "out-of-scope",
    "informational",
    "spam",
}


def log(msg):
    print(f"{datetime.utcnow()} - Bugcrowd: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on BC_HOST.

    Bugcrowd's public API is at ``api.bugcrowd.com``;
    the env-only ``BC_HOST`` knob exists for the rare
    enterprise mirror and the staging endpoint.  Empty
    / missing / non-string inputs return the
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


def parse_program_uuids(value):
    """Parse BC_PROGRAM_UUID into a list of program uuids / slugs.

    None / blank / bool -> ``[]`` (no program narrowing;
    walk every program in the token's scope).
    Comma-separated uuids / slugs are split and
    trimmed.  Forwarded as multiple
    ``filter[program][]=<uuid>`` query entries so a
    single agent can pull from several programs in one
    run.
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
    """Parse BC_STATE into a CSV of canonical Bugcrowd submission states.

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


def parse_min_priority(value):
    """Parse BC_MIN_PRIORITY into a clamped Bugcrowd priority integer.

    Accepts integer / float / ``P<N>`` scalar inputs.
    Returns ``None`` for missing / blank / unparseable
    inputs so the caller treats the run as 'keep every
    record'.  Clamped to [MIN_PRIORITY, MAX_PRIORITY]
    so a stray operator input can't disable the floor.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return None
        if text.startswith("p"):
            text = text[1:]
        try:
            n = int(float(text))
        except (TypeError, ValueError):
            return None
    else:
        try:
            n = int(float(value))
        except (TypeError, ValueError):
            return None
    if n < MIN_PRIORITY:
        return MIN_PRIORITY
    if n > MAX_PRIORITY:
        return MAX_PRIORITY
    return n


def normalize_priority(value):
    """Coerce a Bugcrowd priority field to a 1..5 integer.

    Accepts integer / float / ``P<N>`` scalar inputs.
    Returns ``None`` for missing / unparseable inputs so
    the caller can fall back to ``info`` bucketing.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return None
        if text.startswith("p"):
            text = text[1:]
        try:
            n = int(float(text))
        except (TypeError, ValueError):
            return None
    else:
        try:
            n = int(float(value))
        except (TypeError, ValueError):
            return None
    if n < MIN_PRIORITY or n > MAX_PRIORITY:
        return None
    return n


def severity_from_priority(value):
    """Bucket Faraday severity from a Bugcrowd priority field.

    Returns ``"info"`` for missing / unparseable inputs
    so the submission is still visible in the workspace.
    """
    n = normalize_priority(value)
    if n is None:
        return "info"
    return PRIORITY_TO_SEVERITY[n]


def priority_meets_threshold(priority, min_priority):
    """True when ``priority`` <= ``min_priority`` in Bugcrowd's ladder.

    Bugcrowd's priority is inverted (P1 most critical,
    P5 least) so a 'min priority' floor of N means
    'keep priorities <= N' — P1 and P2 pass a min of 2,
    P3 / P4 / P5 are dropped.  ``min_priority is None``
    keeps every record.  Unparseable priorities are
    dropped when a floor is set (conservative — we
    cannot prove the record meets the bar).
    """
    if min_priority is None:
        return True
    n = normalize_priority(priority)
    if n is None:
        return False
    return n <= min_priority


def is_closed_state(value):
    """True when a Bugcrowd submission ``state`` is terminally closed."""
    if not isinstance(value, str):
        return False
    canonical = STATE_ALIASES.get(value.strip().lower())
    return canonical in CLOSED_STATES


def build_submissions_url(host):
    return f"{normalize_base_url(host)}{SUBMISSIONS_PATH}"


def build_query(page, page_size=DEFAULT_PAGE_SIZE, program_uuids=None, states=""):
    """Build the canonical Bugcrowd paging + filter query string.

    Bugcrowd's REST surface uses JSON:API style
    ``page[offset]=N`` + ``page[limit]=M`` pagination
    (offset is the zero-based record count, not the
    page number).  Program uuids are forwarded as
    repeated ``filter[program][]=<uuid>`` entries (the
    JSON:API array-filter convention Bugcrowd
    documents) so a single run can pull from several
    programs.  States are forwarded as a single
    comma-joined ``filter[state][]=<csv>`` parameter
    (Bugcrowd accepts both forms but the joined form
    avoids the URL ballooning when the operator
    supplies many states).  Bad page / page_size
    inputs are coerced to safe defaults so a typo
    never crashes the dispatcher.
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
    params = [("page[offset]", offset), ("page[limit]", s)]
    if program_uuids:
        for uuid in program_uuids:
            text = str(uuid).strip()
            if text:
                params.append(("filter[program][]", text))
    if states:
        text = str(states).strip()
        if text:
            params.append(("filter[state][]", text))
    return urlencode(params)


def token_auth_header(token):
    """Build the ``Authorization: Token <token>`` value.

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
    return f"Token {t}"


def request_headers(token):
    """Build the request-header dict for a credentialed REST GET.

    Bugcrowd's REST surface documents single-token auth
    on every request.  The version-locked
    ``Accept: application/vnd.bugcrowd.v4+json`` header
    keeps the ingest shape stable across later
    Bugcrowd API releases.  Missing / blank tokens
    still produce a (well-formed but unauthorised)
    Token header so the server's 401 surfaces as a
    clear error rather than a silently-skipped header.
    """
    return {
        "Accept": ACCEPT_HEADER,
        "Authorization": token_auth_header(token),
    }


def extract_records(body):
    """Pull the submission list from a Bugcrowd REST response envelope.

    Canonical envelope wraps the record list under
    ``data`` (Bugcrowd's JSON:API shape).  Federated
    mirrors / staging stacks also expose bare-list /
    ``results`` / ``items`` / ``submissions`` — all
    shapes are tolerated.  Non-dict entries are silently
    dropped.  A single-record fetch (e.g.  ``GET
    /submissions/<uuid>``) returns the record directly
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
    for key in ("results", "items", "submissions"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def record_attributes(record):
    """Pull the JSON:API ``attributes`` sub-dict from a submission.

    Returns the ``attributes`` sub-dict if present;
    falls back to the record itself for federated
    mirrors that flatten the JSON:API envelope.  Always
    returns a dict so callers can ``.get(...)`` safely.
    """
    if not isinstance(record, dict):
        return {}
    attrs = record.get("attributes")
    if isinstance(attrs, dict):
        return attrs
    return record


def record_relationships(record):
    """Pull the JSON:API ``relationships`` sub-dict from a submission.

    Returns the ``relationships`` sub-dict if present;
    falls back to ``{}`` for federated mirrors that
    flatten the envelope.  Always returns a dict so
    callers can ``.get(...)`` safely.
    """
    if not isinstance(record, dict):
        return {}
    rels = record.get("relationships")
    if isinstance(rels, dict):
        return rels
    return {}


def record_program(record):
    """Pick the submission's program uuid / handle from the relationships sub-dict.

    Bugcrowd carries the program identifier under
    ``relationships.program.data.id`` (the JSON:API
    nested-relationship convention) with the program
    handle exposed under
    ``relationships.program.data.attributes.handle``.
    Federated / staging mirrors also expose it directly
    under ``attributes.program`` /
    ``attributes.program_handle``.  Returns ``""``
    when nothing usable is present.
    """
    if not isinstance(record, dict):
        return ""
    rels = record_relationships(record)
    program = rels.get("program")
    if isinstance(program, dict):
        data = program.get("data")
        if isinstance(data, dict):
            attrs = data.get("attributes")
            if isinstance(attrs, dict):
                for key in ("handle", "name", "slug"):
                    v = attrs.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            for key in ("handle", "slug", "id"):
                v = data.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    attrs = record_attributes(record)
    for key in ("program_handle", "program", "program_slug", "program_uuid"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_researcher(record):
    """Pick the submission's researcher username from the relationships sub-dict."""
    if not isinstance(record, dict):
        return ""
    rels = record_relationships(record)
    researcher = rels.get("researcher") or rels.get("reporter")
    if isinstance(researcher, dict):
        data = researcher.get("data")
        if isinstance(data, dict):
            attrs = data.get("attributes")
            if isinstance(attrs, dict):
                for key in ("username", "name", "handle"):
                    v = attrs.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            for key in ("username", "handle"):
                v = data.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    attrs = record_attributes(record)
    for key in ("researcher_username", "researcher", "reporter_username", "reporter"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_url(record):
    """Pick the vulnerable URL / endpoint the submission targets.

    Bugcrowd carries the vulnerable URL under
    ``attributes.bug_url`` (the submission form's URL
    field); federated mirrors also expose
    ``vulnerable_url`` / ``url`` / a nested
    ``relationships.target.data.attributes.name`` for
    programs that require scoped URLs.  Returns
    ``""`` when nothing usable is present.
    """
    attrs = record_attributes(record)
    for key in ("bug_url", "vulnerable_url", "vulnerability_url", "url"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    rels = record_relationships(record)
    target = rels.get("target")
    if isinstance(target, dict):
        data = target.get("data")
        if isinstance(data, dict):
            inner = data.get("attributes")
            if isinstance(inner, dict):
                for key in ("name", "uri", "url"):
                    v = inner.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    return ""


def record_priority(record):
    """Pick the submission's priority (1..5 integer) from the attributes sub-dict."""
    attrs = record_attributes(record)
    for key in ("priority", "severity", "p_rating"):
        v = attrs.get(key)
        n = normalize_priority(v)
        if n is not None:
            return n
    return None


def record_vrt(record):
    """Pick the submission's VRT id (Bugcrowd's canonical issue-type ontology)."""
    attrs = record_attributes(record)
    for key in ("vrt_id", "vrt"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    rels = record_relationships(record)
    vrt = rels.get("vrt")
    if isinstance(vrt, dict):
        data = vrt.get("data")
        if isinstance(data, dict):
            inner = data.get("attributes")
            if isinstance(inner, dict):
                for key in ("vrt_id", "id", "name"):
                    v = inner.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            for key in ("id", "vrt_id"):
                v = data.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def collect_cves(record):
    """Walk a Bugcrowd submission for CVE ids.

    Bugcrowd surfaces CVE attribution under
    ``attributes.cve`` / ``attributes.cves`` (string or
    list of CVE strings) and embeds CVE refs in the
    title / description / vulnerability_information
    body.  All occurrences are deduplicated and
    uppercased to NVD's canonical form.
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

    attrs = record_attributes(record)
    for key in ("cve", "cves", "cve_ids", "cve_list"):
        raw = attrs.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("id"))
        elif isinstance(raw, str):
            scan(raw)

    for key in ("title", "description", "vulnerability_information", "summary"):
        scan(attrs.get(key))

    return out


def collect_cwes(record):
    """Walk a Bugcrowd submission for CWE ids.

    Bugcrowd's primary issue-type ontology is VRT
    (Vulnerability Rating Taxonomy) rather than CWE,
    but the VRT entries carry a CWE mapping which
    federated mirrors surface under
    ``attributes.cwe`` / ``relationships.vrt.data.attributes.cwe``,
    and researchers frequently embed CWE refs in the
    title / description body.  All occurrences are
    deduplicated and uppercased.
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

    rels = record_relationships(record)
    vrt = rels.get("vrt")
    if isinstance(vrt, dict):
        data = vrt.get("data")
        if isinstance(data, dict):
            inner = data.get("attributes")
            if isinstance(inner, dict):
                for key in ("cwe", "external_id", "name"):
                    raw = inner.get(key)
                    if isinstance(raw, list):
                        for entry in raw:
                            scan(entry if isinstance(entry, str) else str(entry))
                    else:
                        scan(raw)

    attrs = record_attributes(record)
    for key in ("cwe", "cwes", "cwe_id"):
        raw = attrs.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    scan(entry)
                elif isinstance(entry, dict):
                    scan(entry.get("cwe") or entry.get("id") or entry.get("name"))
        elif isinstance(raw, str):
            scan(raw)

    for key in ("title", "description", "vulnerability_information", "summary"):
        scan(attrs.get(key))

    return out


def collect_refs(record):
    """Build the refs list for a Bugcrowd submission record."""
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
        add(f"BC-SubmissionID: {str(rec_id).strip()}")

    program = record_program(record)
    if program:
        add(f"BC-Program: {program}")
        add(f"https://bugcrowd.com/{program}")

    researcher = record_researcher(record)
    if researcher:
        add(f"BC-Researcher: {researcher}")
        add(f"https://bugcrowd.com/{researcher}")

    attrs = record_attributes(record)
    for key, label in (
        ("state", "BC-State"),
        ("substate", "BC-Substate"),
        ("priority", "BC-Priority"),
        ("created_at", "BC-CreatedAt"),
        ("submitted_at", "BC-SubmittedAt"),
        ("triaged_at", "BC-TriagedAt"),
        ("resolved_at", "BC-ResolvedAt"),
        ("disclosed_at", "BC-DisclosedAt"),
        ("last_updated_at", "BC-UpdatedAt"),
        ("monetary_reward", "BC-Reward"),
        ("reward_currency", "BC-Currency"),
        ("source", "BC-Source"),
        ("bug_url", "BC-BugURL"),
        ("cvss_vector", "BC-CVSSVector"),
        ("cvss_score", "BC-CVSSScore"),
    ):
        v = attrs.get(key)
        if v in (None, ""):
            continue
        add(f"{label}: {v}")

    vrt = record_vrt(record)
    if vrt:
        add(f"BC-VRT: {vrt}")
        add("https://bugcrowd.com/vulnerability-rating-taxonomy")

    rec_id_str = str(rec_id).strip() if rec_id is not None else ""
    if rec_id_str:
        add(f"https://tracker.bugcrowd.com/submissions/{rec_id_str}")

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


def build_submission_vulnerability(record, min_priority=None):
    """Build a Faraday vulnerability dict for one Bugcrowd submission.

    Returns ``None`` when the submission's priority is
    numerically greater (less severe) than
    ``min_priority``.  Terminal Bugcrowd states
    (``resolved`` / ``duplicate`` / ``not-reproducible``
    / ``not-applicable`` / ``out-of-scope`` /
    ``informational`` / ``spam``) floor the severity to
    ``info`` regardless of the published priority.  The
    submission is surfaced as a Faraday vulnerability
    with the ``[BUG-BOUNTY]`` engine prefix so external
    researcher reports land alongside the other
    crowd-sourced feeds.
    """
    if not isinstance(record, dict):
        return None
    attrs = record_attributes(record)
    state = attrs.get("state") if isinstance(attrs.get("state"), str) else None
    priority = record_priority(record)
    if not priority_meets_threshold(priority, min_priority):
        return None
    severity = severity_from_priority(priority)
    if is_closed_state(state):
        severity = "info"

    title = attrs.get("title") or record.get("id") or "Bugcrowd submission"
    name = f"[BUG-BOUNTY] Bugcrowd submission: {str(title).strip()}"

    desc_parts = []
    vinfo = attrs.get("description") or attrs.get("vulnerability_information") or attrs.get("summary") or ""
    if isinstance(vinfo, str) and vinfo.strip():
        desc_parts.append(vinfo.strip())
    for key in sorted(attrs.keys()):
        if key in ("description", "vulnerability_information", "summary", "title"):
            continue
        v = attrs.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    program = record_program(record)
    if program:
        desc_parts.append(f"program: {program}")
    researcher = record_researcher(record)
    if researcher:
        desc_parts.append(f"researcher: {researcher}")

    record_id = str(record.get("id") or record.get("uuid") or name)

    if is_closed_state(state):
        resolution = (
            f"Bugcrowd has marked this submission as {state}; "
            "verify the underlying vulnerability is patched "
            "(for resolved submissions) or that the platform's "
            "triage decision matches the operator's risk "
            "appetite (for duplicate / not-reproducible / "
            "not-applicable / out-of-scope / informational / "
            "spam) before closing the Faraday finding."
        )
    else:
        resolution = (
            "Triage this Bugcrowd submission in the program's "
            "inbox, correlate the bug_url against the "
            "operator's asset inventory, and coordinate with "
            "the researcher via the submission thread for any "
            "reproduction steps or proof-of-concept artefacts. "
            "Award the bounty once the finding is validated "
            "per the program's payout policy."
        )

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"bc-submission::{record_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record),
        "cve": collect_cves(record),
        "cwe": collect_cwes(record),
        "cvss3": {},
        "tags": ["bugcrowd", "pentest-platforms", "submission"],
    }


def build_host_from_submission(record, min_priority=None):
    """Build a Faraday host dict from a Bugcrowd submission record."""
    if not isinstance(record, dict):
        return None
    vuln = build_submission_vulnerability(record, min_priority)
    if vuln is None:
        return None
    attrs = record_attributes(record)
    hostnames = []
    title = attrs.get("title")
    if isinstance(title, str) and title.strip():
        hostnames.append(title.strip())
    url = record_url(record)
    if url and url not in hostnames:
        hostnames.append(url)
    program = record_program(record)
    desc_parts = []
    if program:
        desc_parts.append(f"program={program}")
    state = attrs.get("state")
    if isinstance(state, str) and state.strip():
        desc_parts.append(f"state={state.strip()}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts) or "Bugcrowd bug-bounty submission",
        "vulnerabilities": [vuln],
    }


def fetch_pages(requests_module, url, headers, program_uuids, states, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk the Bugcrowd /submissions surface page-by-page.

    Pagination is offset-based via JSON:API's
    ``page[offset]=N`` + ``page[limit]=M``.  Walks
    until either ``len(records) < page_size`` or
    ``max_pages`` is reached.  401 short-circuits the
    whole executor (credentials are wrong); 403 / 429 /
    5xx stop pagination and return what we have.
    """
    out = []
    page = 1
    walked = 0
    records = []
    while walked < max_pages:
        qs = build_query(page, page_size=page_size, program_uuids=program_uuids, states=states)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Bugcrowd request rejected (401); check BC_API_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Bugcrowd request rejected (403); check the token's program scope.")
            return out
        if resp.status_code == 429:
            log("Bugcrowd rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Bugcrowd request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Bugcrowd response was not JSON ({full_url})")
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
        log(f"hit BC_PAGES={max_pages}; stopping pagination")
    return out


def validate_pages(value):
    """Coerce BC_PAGES into a clamped integer.

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

    program_uuids = parse_program_uuids(env("EXECUTOR_CONFIG_BC_PROGRAM_UUID"))
    states = parse_states(env("EXECUTOR_CONFIG_BC_STATE"))
    min_priority = parse_min_priority(env("EXECUTOR_CONFIG_BC_MIN_PRIORITY"))
    pages = validate_pages(env("BC_PAGES"))

    host = env("BC_HOST", default=DEFAULT_HOST)
    api_token = env("BC_API_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = request_headers(api_token)
    submissions_url = build_submissions_url(host)

    submissions = fetch_pages(
        requests,
        submissions_url,
        headers,
        program_uuids,
        states,
        max_pages=pages,
    )
    log(
        f"Bugcrowd discovered {len(submissions)} submissions "
        f"(programs={','.join(program_uuids) or '(all)'}, "
        f"states={states or '(all)'})"
    )

    hosts_out = []
    for record in submissions:
        built = build_host_from_submission(record, min_priority)
        if built is not None:
            hosts_out.append(built)

    log(
        f"Processed {len(hosts_out)} Bugcrowd hosts "
        f"(submissions={len(submissions)}, "
        f"min_priority={min_priority if min_priority is not None else '(none)'})"
    )

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "bugcrowd",
            "command": "bugcrowd",
            "params": (
                f"programs={','.join(program_uuids)} "
                f"states={states} "
                f"min_priority={min_priority if min_priority is not None else ''} "
                f"submissions={len(submissions)} "
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
