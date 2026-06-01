#!/usr/bin/env python
"""Cobalt.io pentest-as-a-service finding importer.

Pulls validated findings from the Cobalt.io v2 REST API
and emits Faraday bulk-create JSON to stdout.  Cobalt.io
is a pentest-as-a-service platform — vetted pentesters
deliver scoped engagements against the operator's assets
and the platform tracks the resulting findings through a
triage / acceptance / remediation lifecycle.  This
executor surfaces validated findings under the operator's
existing Faraday workspace so the external pentest
pipeline joins the dispatcher's internal scanner output.

Endpoints used:
  GET {COBALT_HOST}/v2/findings?filter[pentest_id]=<id>&limit=N&offset=M
      -> Paginated pentest finding feed.  Cobalt.io speaks
      JSON:API so the canonical envelope is
      ``{"data": [{"id": "...", "resource": "Finding",
      "attributes": {...}, "relationships": {...}}],
      "links": {"next": "...", "prev": "..."},
      "meta": {"total": N}}``.  Each record's
      ``attributes`` carries ``title``, ``description``,
      ``log`` (researcher proof / reproduction notes),
      ``type_category`` (Cobalt's published issue-type
      ontology — e.g. ``Server Security Misconfiguration``,
      ``Application-Logic & Server-Side``, ``Sensitive
      Data Exposure``), ``severity`` (``informational`` /
      ``low`` / ``medium`` / ``high`` / ``critical`` —
      Cobalt's CVSS-aligned ladder), ``state`` (``new`` /
      ``triaging`` / ``valid_triaged`` / ``invalid`` /
      ``out_of_scope`` / ``accepted_risk`` / ``wont_fix`` /
      ``need_more_info`` / ``not_applicable`` /
      ``duplicate`` / ``resolved`` / ``check_fix`` /
      ``fix_in_progress`` — Cobalt's published state
      machine), ``affected_targets`` (list of scoped
      assets the pentester targeted), ``vulnerable_url``
      (URL the pentester targeted), ``proof_of_concept``
      / ``suggested_fix`` (remediation guidance),
      ``cvss_score`` / ``cvss_vector``, ``impact`` /
      ``likelihood`` (Cobalt's published 1..5 ladders for
      the program-set severity rating), ``created_at`` /
      ``updated_at`` / ``submitted_at`` / ``triaged_at`` /
      ``resolved_at``.  ``relationships`` carries pointers
      to ``pentest`` (engagement uuid + handle),
      ``pentester`` (researcher username), and ``asset``
      (scoped target).

  GET {COBALT_HOST}/v2/pentests
      -> Paginated pentest-engagement feed.  Documented
      here so the operator understands which uuids belong
      to which engagements; the dispatcher never fetches
      this endpoint directly (the operator pastes the
      relevant ``COBALT_PENTEST_ID`` into the manifest
      argument).

  GET {COBALT_HOST}/v2/findings/<id>
      -> Individual finding fetch (used only when the
      operator pastes a single finding id into
      ``COBALT_PENTEST_ID`` — not wired in the canonical
      flow but tolerated by ``extract_records`` so a
      misconfigured id that happens to be a finding id
      still surfaces a record rather than a silent
      zero-result run).

Auth: Cobalt.io's REST surface uses a long-lived API
token in the ``Authorization: Bearer <token>`` header
plus the organisation-scoped ``X-Org-Token: <org_token>``
header (Cobalt's documented v2 auth shape — the API
token identifies the user identity, the org token narrows
the call to a specific organisation under that identity's
access).  Both are provisioned per identity in Cobalt's
API settings; ``COBALT_PENTEST_ID`` narrows the scope
further but cannot widen it.  The dispatcher locks the
API version with the ``Accept: application/vnd.cobalt.v2+json``
header so later API breaking changes do not silently warp
the ingest shape.

Args:
  ``COBALT_PENTEST_ID`` (optional) — server-side pentest
  scope forwarded as the ``filter[pentest_id]=<uuid>``
  query parameter on ``/v2/findings``.  Empty / blank
  walks the entire org's pentest scope (the typical
  operational mode for a first-time import).
  Comma-separated uuids are split + forwarded as
  multiple ``filter[pentest_id]=`` entries so a single
  agent can pull findings from several engagements in
  one run (e.g.
  ``11111111-2222-3333-4444-555555555555,acme-mobile-q1``).
  Cobalt accepts either the pentest uuid or its handle
  (``slug``) — the dispatcher forwards whatever the
  operator pasted in verbatim.  Whitespace is trimmed
  around each entry.

  ``COBALT_MIN_SEVERITY`` (optional) — Faraday severity
  floor (case-insensitive ``info`` / ``low`` / ``medium``
  / ``high`` / ``critical``).  Findings whose mapped
  severity is strictly below the floor are dropped
  client-side after the fetch (Cobalt's severity field
  is the program-set CVSS rating).  Operator-friendly
  aliases (``informational`` -> ``info``, ``moderate``
  -> ``medium``, ``crit`` -> ``critical``, ``none`` ->
  ``info``) are normalised.  Blank / missing input
  keeps every record (the typical operational mode for
  first-time imports).

Env vars:
  ``COBALT_TOKEN`` (mandatory) — the long-lived API token
  (provisioned in Cobalt's API settings).  Forwarded
  verbatim as the ``Authorization: Bearer <token>``
  header value — never logged or stored on the
  dispatcher.

  ``COBALT_ORG_TOKEN`` (mandatory) — the organisation
  scope token (provisioned in Cobalt's API settings
  alongside the API token).  Forwarded verbatim as the
  ``X-Org-Token: <token>`` header value — never logged
  or stored on the dispatcher.  The org token's scope
  determines which pentests the run can read; the
  ``COBALT_PENTEST_ID`` filter narrows the scope further
  but cannot widen it.

  ``COBALT_HOST`` (optional, env-only) — base URL override
  (defaults to ``https://api.cobalt.io``).  Useful for
  the rare enterprise mirror and for staging tests
  against a Cobalt-provided sandbox endpoint.
  Whitespace is trimmed; ``https://`` is added when the
  operator pasted in a bare FQDN.

Each Cobalt finding becomes one Faraday host.  The host
``ip`` falls back to the ``0.0.0.0`` sentinel because
pentest findings are keyed on a URL / asset path rather
than an IP address; the URL is surfaced as the
``hostname`` and embedded in the vulnerability description.
The finding itself becomes one Faraday vulnerability with
the ``[PENTEST]`` engine prefix so external pentester
findings land alongside the other crowd-sourced feeds.

Severity bucketing:
  - Cobalt's published label vocabulary is
    ``informational`` / ``low`` / ``medium`` / ``high``
    / ``critical`` (CVSS-aligned).  ``informational`` /
    ``none`` are mapped to Faraday's ``info`` bucket so
    the finding is still visible in the workspace; the
    rest pass through verbatim.
  - Terminal Cobalt states (``invalid`` /
    ``out_of_scope`` / ``not_applicable`` / ``duplicate``
    / ``accepted_risk`` / ``wont_fix`` / ``resolved``)
    floor the severity to ``info`` regardless of the
    published rating; the closed state is preserved via
    an explicit ``Cobalt-State`` pivot in the refs.

Tags: ``[cobalt, pentest-platforms, finding]``.  Status is
always ``open`` (Cobalt's terminal states are preserved
via the info-severity floor + an explicit
``Cobalt-State`` pivot in the refs).
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

FINDINGS_PATH = "/v2/findings"
PENTESTS_PATH = "/v2/pentests"
DEFAULT_HOST = "https://api.cobalt.io"
ACCEPT_HEADER = "application/vnd.cobalt.v2+json"

DEFAULT_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100  # Cobalt caps limit at 100
DEFAULT_PAGES = 10
MAX_PAGES = 100
INTER_REQUEST_SLEEP = 0.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(ALLOWED_SEVERITIES)}

# Cobalt's published label vocabulary is CVSS-aligned:
# informational / low / medium / high / critical.
# Operator-friendly aliases are normalised to Faraday's
# canonical lowercase ladder; ``informational`` / ``none``
# are mapped to ``info`` so the finding is still visible
# in the workspace.
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

# Cobalt's published finding-state machine.  Operator-
# friendly aliases are normalised to the canonical
# snake_case form Cobalt documents.
STATE_ALIASES = {
    "new": "new",
    "triaging": "triaging",
    "triage": "triaging",
    "valid": "valid_triaged",
    "valid_triaged": "valid_triaged",
    "valid-triaged": "valid_triaged",
    "triaged": "valid_triaged",
    "invalid": "invalid",
    "out_of_scope": "out_of_scope",
    "out-of-scope": "out_of_scope",
    "outofscope": "out_of_scope",
    "oos": "out_of_scope",
    "accepted_risk": "accepted_risk",
    "accepted-risk": "accepted_risk",
    "acceptedrisk": "accepted_risk",
    "accepted": "accepted_risk",
    "wont_fix": "wont_fix",
    "wont-fix": "wont_fix",
    "wontfix": "wont_fix",
    "won't-fix": "wont_fix",
    "need_more_info": "need_more_info",
    "need-more-info": "need_more_info",
    "needmoreinfo": "need_more_info",
    "needs-more-info": "need_more_info",
    "needs_more_info": "need_more_info",
    "needs-info": "need_more_info",
    "needs_info": "need_more_info",
    "not_applicable": "not_applicable",
    "not-applicable": "not_applicable",
    "notapplicable": "not_applicable",
    "na": "not_applicable",
    "duplicate": "duplicate",
    "dup": "duplicate",
    "resolved": "resolved",
    "closed": "resolved",
    "fixed": "resolved",
    "check_fix": "check_fix",
    "check-fix": "check_fix",
    "checkfix": "check_fix",
    "fix_in_progress": "fix_in_progress",
    "fix-in-progress": "fix_in_progress",
    "fixinprogress": "fix_in_progress",
    "in_progress": "fix_in_progress",
    "in-progress": "fix_in_progress",
    "inprogress": "fix_in_progress",
}

# Cobalt terminal finding states — preserved via an
# explicit Cobalt-State pivot ref but floored to ``info``
# severity (the finding is no longer actionable).
CLOSED_STATES = {
    "invalid",
    "out_of_scope",
    "not_applicable",
    "duplicate",
    "accepted_risk",
    "wont_fix",
    "resolved",
}


def log(msg):
    print(f"{datetime.utcnow()} - Cobalt: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on COBALT_HOST.

    Cobalt's public API is at ``api.cobalt.io``; the
    env-only ``COBALT_HOST`` knob exists for the rare
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


def parse_pentest_ids(value):
    """Parse COBALT_PENTEST_ID into a list of pentest uuids / slugs.

    None / blank / bool -> ``[]`` (no pentest narrowing;
    walk every engagement in the token's scope).
    Comma-separated uuids / slugs are split and trimmed.
    Forwarded as multiple ``filter[pentest_id]=<uuid>``
    query entries so a single agent can pull from
    several engagements in one run.
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
    """Coerce a Cobalt severity label to Faraday's ladder.

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
    """Parse COBALT_MIN_SEVERITY into a canonical Faraday label.

    Returns ``None`` for missing / blank / unparseable
    inputs so the caller treats the run as 'keep every
    record'.  Operator-friendly aliases
    (``informational`` -> ``info``, ``moderate`` ->
    ``medium``, ``crit`` -> ``critical``, ``none`` ->
    ``info``) are normalised.
    """
    return normalize_severity_label(value)


def severity_from_finding(value):
    """Bucket Faraday severity from a Cobalt severity field.

    Accepts the scalar label form (``informational`` /
    ``low`` / ``medium`` / ``high`` / ``critical``) and
    the nested ``{"rating": "...", "score": 0..10}`` shape
    used by some federated mirrors.  Returns ``"info"``
    for missing / unparseable inputs so the finding is
    still visible in the workspace.
    """
    if isinstance(value, dict):
        nested = value.get("rating") or value.get("value")
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
    high, 9.0..10.0 -> critical.  Returns ``"info"`` for
    out-of-range inputs.
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


def is_closed_state(value):
    """True when a Cobalt finding ``state`` is terminally closed."""
    if not isinstance(value, str):
        return False
    canonical = STATE_ALIASES.get(value.strip().lower())
    return canonical in CLOSED_STATES


def build_findings_url(host):
    return f"{normalize_base_url(host)}{FINDINGS_PATH}"


def build_pentests_url(host):
    return f"{normalize_base_url(host)}{PENTESTS_PATH}"


def build_query(page, page_size=DEFAULT_PAGE_SIZE, pentest_ids=None):
    """Build the canonical Cobalt paging + filter query string.

    Cobalt's REST surface uses ``limit=N`` + ``offset=M``
    pagination (offset is the zero-based record count,
    not the page number).  Pentest ids are forwarded as
    repeated ``filter[pentest_id]=<uuid>`` entries so a
    single run can pull from several engagements.  Bad
    page / page_size inputs are coerced to safe defaults
    so a typo never crashes the dispatcher.
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
    if pentest_ids:
        for pid in pentest_ids:
            text = str(pid).strip()
            if text:
                params.append(("filter[pentest_id]", text))
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


def org_token_header(token):
    """Build the ``X-Org-Token: <token>`` value.

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
    return t


def request_headers(token, org_token):
    """Build the request-header dict for a credentialed REST GET.

    Cobalt's REST surface documents two-header auth: the
    user-identity API token in ``Authorization: Bearer``
    plus the organisation scope token in ``X-Org-Token``.
    The version-locked
    ``Accept: application/vnd.cobalt.v2+json`` header
    keeps the ingest shape stable across later Cobalt
    API releases.  Missing / blank tokens still produce
    (well-formed but unauthorised) headers so the
    server's 401 surfaces as a clear error rather than a
    silently-skipped header.
    """
    return {
        "Accept": ACCEPT_HEADER,
        "Authorization": bearer_auth_header(token),
        "X-Org-Token": org_token_header(org_token),
    }


def extract_records(body):
    """Pull the finding list from a Cobalt REST response envelope.

    Canonical envelope wraps the record list under
    ``data`` (Cobalt's JSON:API shape).  Federated
    mirrors / staging stacks also expose bare-list /
    ``results`` / ``items`` / ``findings`` /
    ``records`` — all shapes are tolerated.  Non-dict
    entries are silently dropped.  A single-record
    fetch (e.g. ``GET /v2/findings/<id>``) returns the
    record directly under ``data``; that case is
    collapsed into a one-element list so downstream
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
    for key in ("results", "items", "findings", "records"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
        if isinstance(v, dict):
            return [v]
    if body.get("id") or body.get("tag"):
        return [body]
    return []


def record_attributes(record):
    """Pull the JSON:API ``attributes`` sub-dict from a finding.

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
    """Pull the JSON:API ``relationships`` sub-dict from a finding.

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


def record_pentest(record):
    """Pick the finding's pentest uuid / handle.

    Cobalt carries the pentest identifier under
    ``relationships.pentest.data.id`` (the JSON:API
    nested-relationship convention) with the pentest
    handle exposed under
    ``relationships.pentest.data.attributes.handle`` /
    ``attributes.title``.  Federated / staging mirrors
    also expose it directly under
    ``attributes.pentest_id`` / ``attributes.pentest``.
    Returns ``""`` when nothing usable is present.
    """
    if not isinstance(record, dict):
        return ""
    rels = record_relationships(record)
    pentest = rels.get("pentest")
    if isinstance(pentest, dict):
        data = pentest.get("data")
        if isinstance(data, dict):
            attrs = data.get("attributes")
            if isinstance(attrs, dict):
                for key in ("handle", "title", "name", "slug"):
                    v = attrs.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            for key in ("handle", "slug", "id"):
                v = data.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    attrs = record_attributes(record)
    for key in ("pentest_id", "pentestId", "pentest", "pentest_handle"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_pentester(record):
    """Pick the finding's pentester username."""
    if not isinstance(record, dict):
        return ""
    rels = record_relationships(record)
    pentester = rels.get("pentester") or rels.get("researcher") or rels.get("reporter")
    if isinstance(pentester, dict):
        data = pentester.get("data")
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
    for key in ("pentester_username", "pentester", "researcher", "reporter"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_url(record):
    """Pick the vulnerable URL / endpoint the finding targets.

    Cobalt carries the vulnerable URL under
    ``attributes.vulnerable_url`` (the finding form's URL
    field); federated mirrors also expose ``url`` /
    ``affected_url`` / a nested
    ``relationships.asset.data.attributes.name`` /
    ``attributes.affected_targets[0]`` for programs
    that require scoped URLs.  Returns ``""`` when
    nothing usable is present.
    """
    attrs = record_attributes(record)
    for key in ("vulnerable_url", "affected_url", "url"):
        v = attrs.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    targets = attrs.get("affected_targets")
    if isinstance(targets, list):
        for entry in targets:
            if isinstance(entry, str) and entry.strip():
                return entry.strip()
            if isinstance(entry, dict):
                for key in ("url", "name", "value", "endpoint"):
                    v = entry.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    rels = record_relationships(record)
    asset = rels.get("asset") or rels.get("target")
    if isinstance(asset, dict):
        data = asset.get("data")
        if isinstance(data, dict):
            inner = data.get("attributes")
            if isinstance(inner, dict):
                for key in ("name", "uri", "url"):
                    v = inner.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    return ""


def record_state(record):
    """Pick the finding's canonical Cobalt state."""
    attrs = record_attributes(record)
    for key in ("state", "status"):
        v = attrs.get(key)
        if isinstance(v, dict):
            inner = v.get("value")
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_type_category(record):
    """Pick the finding's Cobalt type-category (issue-type ontology) label."""
    attrs = record_attributes(record)
    for key in ("type_category", "category", "issue_type"):
        v = attrs.get(key)
        if isinstance(v, dict):
            for inner_key in ("value", "name", "id"):
                inner = v.get(inner_key)
                if isinstance(inner, str) and inner.strip():
                    return inner.strip()
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_severity_label(record):
    """Pick the finding's Cobalt severity label (raw, not bucketed)."""
    attrs = record_attributes(record)
    sev = attrs.get("severity")
    if isinstance(sev, dict):
        for key in ("rating", "value"):
            v = sev.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(sev, str) and sev.strip():
        return sev.strip()
    return ""


def collect_cves(record):
    """Walk a Cobalt finding for CVE ids.

    Cobalt surfaces CVE attribution under
    ``attributes.cve`` / ``attributes.cves`` (string or
    list of CVE strings) and embeds CVE refs in the
    title / description / log body.  All occurrences
    are deduplicated and uppercased to NVD's canonical
    form.
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
    for key in ("cve", "cves", "cve_ids", "cveIds", "cve_list"):
        raw = attrs.get(key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("id") or entry.get("value"))
        elif isinstance(raw, str):
            scan(raw)

    for key in ("title", "description", "log", "proof_of_concept", "suggested_fix", "summary"):
        scan(attrs.get(key))

    return out


def collect_cwes(record):
    """Walk a Cobalt finding for CWE ids.

    Cobalt's primary issue-type ontology is
    ``type_category`` rather than CWE, but the category
    entries carry a CWE mapping which federated mirrors
    surface under ``attributes.cwe`` /
    ``attributes.type_category.cwe``, and pentesters
    frequently embed CWE refs in the title / description
    / log body.  All occurrences are deduplicated and
    uppercased.
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

    attrs = record_attributes(record)
    for key in ("cwe", "cwes", "cwe_id", "cweId"):
        raw = attrs.get(key)
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

    category = attrs.get("type_category")
    if isinstance(category, dict):
        for key in ("cwe", "value", "name"):
            raw = category.get(key)
            if isinstance(raw, list):
                for entry in raw:
                    scan(entry if isinstance(entry, str) else str(entry))
            else:
                scan(raw)

    for key in ("title", "description", "log", "proof_of_concept", "suggested_fix", "summary"):
        scan(attrs.get(key))

    return out


def collect_refs(record):
    """Build the refs list for a Cobalt finding record."""
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

    rec_id = record.get("id") or record.get("uuid") or record.get("tag")
    if rec_id is not None and str(rec_id).strip():
        add(f"Cobalt-FindingID: {str(rec_id).strip()}")

    attrs = record_attributes(record)
    tag = attrs.get("tag") or record.get("tag")
    if isinstance(tag, str) and tag.strip() and (not rec_id or str(rec_id).strip() != tag.strip()):
        add(f"Cobalt-Tag: {tag.strip()}")

    pentest = record_pentest(record)
    if pentest:
        add(f"Cobalt-Pentest: {pentest}")
        add(f"https://app.cobalt.io/pentests/{pentest}")

    pentester = record_pentester(record)
    if pentester:
        add(f"Cobalt-Pentester: {pentester}")
        add(f"https://app.cobalt.io/users/{pentester}")

    state = record_state(record)
    if state:
        add(f"Cobalt-State: {state}")

    type_category = record_type_category(record)
    if type_category:
        add(f"Cobalt-Type: {type_category}")

    severity_label = record_severity_label(record)
    if severity_label:
        add(f"Cobalt-Severity: {severity_label}")

    for key, label in (
        ("substate", "Cobalt-Substate"),
        ("created_at", "Cobalt-CreatedAt"),
        ("submitted_at", "Cobalt-SubmittedAt"),
        ("triaged_at", "Cobalt-TriagedAt"),
        ("resolved_at", "Cobalt-ResolvedAt"),
        ("updated_at", "Cobalt-UpdatedAt"),
        ("disclosed_at", "Cobalt-DisclosedAt"),
        ("source", "Cobalt-Source"),
        ("vulnerable_url", "Cobalt-VulnerableURL"),
        ("cvss_vector", "Cobalt-CVSSVector"),
        ("cvss_score", "Cobalt-CVSSScore"),
        ("impact", "Cobalt-Impact"),
        ("likelihood", "Cobalt-Likelihood"),
    ):
        v = attrs.get(key)
        if v in (None, "", [], {}):
            continue
        add(f"{label}: {v}")

    rec_id_str = str(rec_id).strip() if rec_id is not None else ""
    if rec_id_str:
        add(f"https://app.cobalt.io/findings/{rec_id_str}")

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
    """Build a Faraday vulnerability dict for one Cobalt finding.

    Returns ``None`` when the finding's mapped severity
    is strictly below ``min_severity``.  Terminal Cobalt
    states (``invalid`` / ``out_of_scope`` /
    ``not_applicable`` / ``duplicate`` /
    ``accepted_risk`` / ``wont_fix`` / ``resolved``)
    floor the severity to ``info`` regardless of the
    published rating.  The finding is surfaced as a
    Faraday vulnerability with the ``[PENTEST]`` engine
    prefix so external pentester findings land alongside
    the other crowd-sourced feeds.
    """
    if not isinstance(record, dict):
        return None
    attrs = record_attributes(record)
    state = record_state(record)
    sev_value = attrs.get("severity")
    severity = severity_from_finding(sev_value)
    if is_closed_state(state):
        severity = "info"
    if not severity_meets_threshold(severity, min_severity):
        return None

    title = attrs.get("title") or attrs.get("tag") or record.get("tag") or record.get("id") or "Cobalt finding"
    name = f"[PENTEST] Cobalt finding: {str(title).strip()}"

    desc_parts = []
    vinfo = attrs.get("description") or attrs.get("log") or attrs.get("proof_of_concept") or attrs.get("summary") or ""
    if isinstance(vinfo, str) and vinfo.strip():
        desc_parts.append(vinfo.strip())
    for key in sorted(attrs.keys()):
        if key in ("description", "log", "proof_of_concept", "summary", "title"):
            continue
        v = attrs.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    pentest = record_pentest(record)
    if pentest:
        desc_parts.append(f"pentest: {pentest}")
    pentester = record_pentester(record)
    if pentester:
        desc_parts.append(f"pentester: {pentester}")

    record_id = str(record.get("id") or record.get("uuid") or record.get("tag") or name)

    if is_closed_state(state):
        resolution = (
            f"Cobalt has marked this finding as {state}; "
            "verify the underlying vulnerability is patched "
            "(for resolved findings) or that the platform's "
            "triage decision matches the operator's risk "
            "appetite (for invalid / out_of_scope / "
            "not_applicable / duplicate / accepted_risk / "
            "wont_fix) before closing the Faraday finding."
        )
    else:
        resolution = (
            "Triage this Cobalt finding in the pentest "
            "workspace, correlate the vulnerable_url "
            "against the operator's asset inventory, and "
            "coordinate with the pentester via the finding "
            "thread for any reproduction steps or "
            "proof-of-concept artefacts.  Validate the "
            "finding against the engagement's scope and "
            "remediate per the platform's suggested_fix "
            "guidance."
        )

    return {
        "name": name.strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"cobalt-finding::{record_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record),
        "cve": collect_cves(record),
        "cwe": collect_cwes(record),
        "cvss3": {},
        "tags": ["cobalt", "pentest-platforms", "finding"],
    }


def build_host_from_finding(record, min_severity=None):
    """Build a Faraday host dict from a Cobalt finding record."""
    if not isinstance(record, dict):
        return None
    vuln = build_finding_vulnerability(record, min_severity)
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
    pentest = record_pentest(record)
    desc_parts = []
    if pentest:
        desc_parts.append(f"pentest={pentest}")
    state = record_state(record)
    if state:
        desc_parts.append(f"state={state}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts) or "Cobalt pentest finding",
        "vulnerabilities": [vuln],
    }


def fetch_pages(requests_module, url, headers, pentest_ids, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk the Cobalt /v2/findings surface page-by-page.

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
        qs = build_query(page, page_size=page_size, pentest_ids=pentest_ids)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Cobalt request rejected (401); check COBALT_TOKEN / COBALT_ORG_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Cobalt request rejected (403); check the token's org / pentest scope.")
            return out
        if resp.status_code == 429:
            log("Cobalt rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Cobalt request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Cobalt response was not JSON ({full_url})")
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
        log(f"hit COBALT_PAGES={max_pages}; stopping pagination")
    return out


def validate_pages(value):
    """Coerce COBALT_PAGES into a clamped integer.

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

    pentest_ids = parse_pentest_ids(env("EXECUTOR_CONFIG_COBALT_PENTEST_ID"))
    min_severity = parse_min_severity(env("EXECUTOR_CONFIG_COBALT_MIN_SEVERITY"))
    pages = validate_pages(env("COBALT_PAGES"))

    host = env("COBALT_HOST", default=DEFAULT_HOST)
    api_token = env("COBALT_TOKEN", required=True)
    org_token = env("COBALT_ORG_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = request_headers(api_token, org_token)
    findings_url = build_findings_url(host)

    findings = fetch_pages(
        requests,
        findings_url,
        headers,
        pentest_ids,
        max_pages=pages,
    )
    log(
        f"Cobalt discovered {len(findings)} findings "
        f"(pentests={','.join(pentest_ids) or '(all)'}, "
        f"min_severity={min_severity or '(none)'})"
    )

    hosts_out = []
    for record in findings:
        built = build_host_from_finding(record, min_severity)
        if built is not None:
            hosts_out.append(built)

    log(
        f"Processed {len(hosts_out)} Cobalt hosts "
        f"(findings={len(findings)}, "
        f"min_severity={min_severity or '(none)'})"
    )

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "cobalt",
            "command": "cobalt",
            "params": (
                f"pentests={','.join(pentest_ids)} "
                f"min_severity={min_severity or ''} "
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
