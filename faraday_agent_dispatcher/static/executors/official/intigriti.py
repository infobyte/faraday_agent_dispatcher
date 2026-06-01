#!/usr/bin/env python
"""Intigriti crowd-sourced bug-bounty submission importer.

Pulls validated submissions from the Intigriti Researcher
REST API and emits Faraday bulk-create JSON to stdout.
Intigriti is a European crowd-sourced security platform —
external researchers submit vulnerability reports against
a program's scope and the program triages, validates,
prioritises, and pays out on the resulting findings.
This executor surfaces validated submissions under the
operator's existing Faraday workspace so the external
bug-bounty pipeline joins the dispatcher's internal
scanner output.

Endpoints used:
  GET {INTIG_HOST}/external/researcher/v1/submissions?programId=<uuid>&statusId=<status>&limit=N&offset=M
      -> Paginated bug-bounty submission feed.  Intigriti
      wraps the record list under ``records`` and exposes
      the total result count under ``maxCount`` (Intigriti's
      published envelope is
      ``{"records": [{"id": "...", "code": "...",
      "title": "...", "state": {"id": 1, "value": "Open"},
      "severity": {"id": 5, "value": "High"},
      "type": {"id": 1, "value": "Vulnerability"},
      "endpoint": "...", "programId": "...",
      "researcher": {"username": "..."},
      "createdAt": 1234567890, "lastUpdatedAt": 1234567890,
      ...}], "maxCount": N}``).  Each record's top-level
      keys carry ``title``, ``description`` /
      ``proofOfConcept``, ``state`` (``Open`` / ``Closed``
      with substate detail under ``state.value`` —
      Intigriti's published state machine includes
      ``New`` / ``Triage`` / ``Triaged`` / ``Accepted`` /
      ``Pending review`` / ``Resolved`` / ``Closed`` /
      ``Duplicate`` / ``Out of scope`` / ``Spam`` /
      ``Informative`` / ``Won't fix``), ``severity``
      (label or ``{"id": N, "value": "..."}`` shape with
      the canonical Intigriti ladder ``Exceptional`` /
      ``Critical`` / ``High`` / ``Medium`` / ``Low`` /
      ``None`` / ``Informational``), ``type`` (issue-type
      ontology pointer with CWE mapping), ``endpoint``
      (URL / asset the researcher targeted), ``programId``
      (uuid pointer to the program), ``researcher``
      (``{"username": "..."}``), ``createdAt`` /
      ``lastUpdatedAt`` / ``closedAt`` (epoch seconds),
      ``bountyAmount`` / ``bountyCurrency`` (payout
      breakdown), ``cvssScore`` / ``cvssVector``, ``cve``
      (attributed CVE strings), ``cwe`` (attributed CWE
      strings, or a nested ``{"id": "...", "value": "..."}``
      shape on newer programs).

  GET {INTIG_HOST}/external/researcher/v1/submissions/<id>
      -> Individual submission fetch (used only when the
      operator pastes a single submission id into
      ``INTIG_PROGRAM_ID`` — not wired in the canonical
      flow but tolerated by ``extract_records`` so a
      misconfigured id that happens to be a submission
      id still surfaces a record rather than a silent
      zero-result run).

Auth: Intigriti's Researcher API surface uses a single
long-lived API token in the ``Authorization: Bearer <token>``
header (no username — the token alone is the identity).
The token is provisioned per identity in Intigriti's API
settings and scopes the run to the programs the identity
has access to; ``INTIG_PROGRAM_ID`` narrows the scope
further but cannot widen it.

Args:
  ``INTIG_PROGRAM_ID`` (optional) — server-side program
  scope forwarded as the ``programId=<uuid>`` query
  parameter on ``/external/researcher/v1/submissions``.
  Empty / blank walks the entire token's program scope
  (the typical operational mode for a single-program
  identity).  Comma-separated uuids are split + forwarded
  as multiple ``programId=<uuid>`` entries so a single
  agent can pull from several programs in one run
  (e.g. ``11111111-2222-3333-4444-555555555555,acme-prod,acme-mobile``).
  Intigriti accepts either the program's uuid or its
  slug (``handle``) — the dispatcher forwards whatever
  the operator pasted in verbatim.  Whitespace is
  trimmed around each entry.

  ``INTIG_STATUS`` (optional) — server-side submission
  status filter (CSV: ``open`` / ``new`` / ``triage`` /
  ``triaged`` / ``accepted`` / ``pending-review`` /
  ``resolved`` / ``closed`` / ``duplicate`` /
  ``out-of-scope`` / ``spam`` / ``informative`` /
  ``wont-fix``).  Forwarded as repeated
  ``statusId=<status>`` query entries (Intigriti accepts
  either the canonical label or the integer id; the
  dispatcher forwards the canonical label so a future
  Intigriti id renumbering does not silently warp the
  filter).  Operator-friendly aliases (``new`` ->
  ``open``, ``open`` -> ``open``, ``triaging`` ->
  ``triage``, ``in-triage`` -> ``triage``,
  ``in-progress`` -> ``triaged``, ``fixed`` ->
  ``resolved``, ``pending`` -> ``pending-review``,
  ``oos`` / ``out_of_scope`` / ``outofscope`` ->
  ``out-of-scope``, ``dup`` -> ``duplicate``,
  ``na`` / ``not_applicable`` / ``notapplicable`` ->
  ``out-of-scope``, ``info`` / ``informational`` ->
  ``informative``, ``wontfix`` / ``won't-fix`` /
  ``wont_fix`` -> ``wont-fix``) are normalised.  Blank /
  missing walks every status (the typical operational
  mode for first-time imports).  Unknown / unparseable
  entries are dropped silently rather than crashing the
  run.

Env vars:
  ``INTIG_TOKEN`` (mandatory) — the long-lived API token
  (provisioned in Intigriti's API settings).  Forwarded
  verbatim as the ``Authorization: Bearer <token>``
  header value — never logged or stored on the
  dispatcher.  The token's scope determines which
  programs the run can read; the ``INTIG_PROGRAM_ID``
  filter narrows the scope further but cannot widen it.

  ``INTIG_HOST`` (optional, env-only) — base URL override
  (defaults to ``https://api.intigriti.com``).  Useful
  for the rare enterprise mirror and for staging tests
  against an Intigriti-provided sandbox endpoint.
  Whitespace is trimmed; ``https://`` is added when the
  operator pasted in a bare FQDN.

Each Intigriti submission becomes one Faraday host.  The
host ``ip`` falls back to the ``0.0.0.0`` sentinel
because bug-bounty submissions are keyed on a URL /
asset path rather than an IP address; the URL is
surfaced as the ``hostname`` and embedded in the
vulnerability description.  The submission itself
becomes one Faraday vulnerability with the
``[BUG-BOUNTY]`` engine prefix so external researcher
reports land alongside the other crowd-sourced feeds.

Severity bucketing:
  - Intigriti's published label vocabulary is
    ``Exceptional`` / ``Critical`` / ``High`` /
    ``Medium`` / ``Low`` / ``None`` / ``Informational``.
    ``Exceptional`` is mapped to Faraday's ``critical``
    bucket (Intigriti's most-severe rating sits above
    CVSS-style critical so the two collapse together
    for Faraday's ladder).  ``None`` and
    ``Informational`` are mapped to Faraday's ``info``
    bucket so the submission is still visible.
  - The nested ``severity.value`` shape (used on the
    canonical Intigriti envelope) is preferred; scalar
    label inputs are tolerated for federated mirrors
    that flatten the envelope.
  - Terminal Intigriti states (``closed`` / ``resolved``
    / ``duplicate`` / ``out-of-scope`` / ``spam`` /
    ``informative`` / ``wont-fix``) floor the severity
    to ``info`` regardless of the published rating; the
    closed state is preserved via an explicit
    ``INTIG-Status`` pivot in the refs.

Tags: ``[intigriti, pentest-platforms, submission]``.
Status is always ``open`` (Intigriti's terminal states
are preserved via the info-severity floor + an explicit
``INTIG-Status`` pivot in the refs).
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

SUBMISSIONS_PATH = "/external/researcher/v1/submissions"
DEFAULT_HOST = "https://api.intigriti.com"

DEFAULT_PAGE_SIZE = 50
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100  # Intigriti caps limit at 100
DEFAULT_PAGES = 10
MAX_PAGES = 100
INTER_REQUEST_SLEEP = 0.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)

ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(ALLOWED_SEVERITIES)}

# Intigriti's published severity vocabulary.  ``Exceptional``
# sits above CVSS-style ``Critical`` on the Intigriti ladder
# but collapses to Faraday's ``critical`` bucket; ``None`` /
# ``Informational`` map to ``info`` so the submission is still
# visible in the workspace.
SEVERITY_ALIASES = {
    "exceptional": "critical",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
    "high": "high",
    "elevated": "high",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
}

# Intigriti's published submission-status machine.  Operator-
# friendly aliases are normalised to the canonical hyphen
# form Intigriti documents.
STATUS_ALIASES = {
    "open": "open",
    "new": "open",
    "active": "open",
    "triage": "triage",
    "triaging": "triage",
    "in-triage": "triage",
    "in_triage": "triage",
    "intriage": "triage",
    "triaged": "triaged",
    "in-progress": "triaged",
    "in_progress": "triaged",
    "inprogress": "triaged",
    "accepted": "accepted",
    "pending-review": "pending-review",
    "pending_review": "pending-review",
    "pendingreview": "pending-review",
    "pending": "pending-review",
    "resolved": "resolved",
    "fixed": "resolved",
    "closed": "closed",
    "duplicate": "duplicate",
    "dup": "duplicate",
    "out-of-scope": "out-of-scope",
    "out_of_scope": "out-of-scope",
    "outofscope": "out-of-scope",
    "oos": "out-of-scope",
    "not-applicable": "out-of-scope",
    "not_applicable": "out-of-scope",
    "notapplicable": "out-of-scope",
    "na": "out-of-scope",
    "spam": "spam",
    "informative": "informative",
    "info": "informative",
    "informational": "informative",
    "wont-fix": "wont-fix",
    "wont_fix": "wont-fix",
    "wontfix": "wont-fix",
    "won't-fix": "wont-fix",
    "wnt-fix": "wont-fix",
}

# Intigriti terminal submission statuses — preserved via an
# explicit INTIG-Status pivot ref but floored to ``info``
# severity (the submission is no longer actionable).
CLOSED_STATUSES = {
    "closed",
    "resolved",
    "duplicate",
    "out-of-scope",
    "spam",
    "informative",
    "wont-fix",
}


def log(msg):
    print(f"{datetime.utcnow()} - Intigriti: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on INTIG_HOST.

    Intigriti's public API is at ``api.intigriti.com``;
    the env-only ``INTIG_HOST`` knob exists for the rare
    enterprise mirror and the staging endpoint.  Empty /
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


def parse_program_ids(value):
    """Parse INTIG_PROGRAM_ID into a list of program ids / slugs.

    None / blank / bool -> ``[]`` (no program narrowing;
    walk every program in the token's scope).
    Comma-separated ids / slugs are split and trimmed.
    Forwarded as multiple ``programId=<uuid>`` query
    entries so a single agent can pull from several
    programs in one run.
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


def parse_statuses(value):
    """Parse INTIG_STATUS into a list of canonical Intigriti submission statuses.

    None / blank / bool -> ``[]`` (no status narrowing;
    walk every status).  Comma-separated statuses are
    split, trimmed, normalised via STATUS_ALIASES, and
    deduplicated.  Unknown entries are dropped silently
    (a typo never crashes the dispatcher).  Returns the
    canonical list ready to forward as repeated
    ``statusId=<status>`` query entries.
    """
    if value is None or isinstance(value, bool):
        return []
    if not isinstance(value, str):
        return []
    out = []
    seen = set()
    for entry in value.split(","):
        s = entry.strip().lower()
        if not s:
            continue
        canonical = STATUS_ALIASES.get(s)
        if canonical is None:
            continue
        if canonical not in seen:
            seen.add(canonical)
            out.append(canonical)
    return out


def normalize_severity_label(value):
    """Coerce an Intigriti severity label to Faraday's ladder.

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


def severity_from_submission(value):
    """Bucket Faraday severity from an Intigriti severity field.

    Accepts the scalar label form (``Exceptional`` /
    ``Critical`` / ``High`` / ``Medium`` / ``Low`` /
    ``None`` / ``Informational``) and the nested
    ``{"id": N, "value": "..."}`` shape (used in
    Intigriti's canonical envelope).  Returns ``"info"``
    for missing / unparseable inputs so the submission is
    still visible in the workspace.
    """
    if isinstance(value, dict):
        nested = value.get("value")
        label = normalize_severity_label(nested) if isinstance(nested, str) else None
        if label is not None:
            return label
        return "info"
    label = normalize_severity_label(value) if isinstance(value, str) else None
    if label is not None:
        return label
    return "info"


def is_closed_status(value):
    """True when an Intigriti submission ``status`` is terminally closed."""
    if isinstance(value, dict):
        value = value.get("value")
    if not isinstance(value, str):
        return False
    canonical = STATUS_ALIASES.get(value.strip().lower())
    return canonical in CLOSED_STATUSES


def build_submissions_url(host):
    return f"{normalize_base_url(host)}{SUBMISSIONS_PATH}"


def build_query(page, page_size=DEFAULT_PAGE_SIZE, program_ids=None, statuses=None):
    """Build the canonical Intigriti paging + filter query string.

    Intigriti's REST surface uses ``limit=N`` + ``offset=M``
    pagination (offset is the zero-based record count, not
    the page number).  Program ids are forwarded as
    repeated ``programId=<uuid>`` entries so a single run
    can pull from several programs.  Statuses are
    forwarded as repeated ``statusId=<status>`` entries
    so the operator can compose a multi-status filter.
    Bad page / page_size inputs are coerced to safe
    defaults so a typo never crashes the dispatcher.
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
    if program_ids:
        for pid in program_ids:
            text = str(pid).strip()
            if text:
                params.append(("programId", text))
    if statuses:
        for st in statuses:
            text = str(st).strip()
            if text:
                params.append(("statusId", text))
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

    Intigriti's REST surface documents single-token bearer
    auth on every request.  Missing / blank tokens still
    produce a (well-formed but unauthorised) Bearer header
    so the server's 401 surfaces as a clear error rather
    than a silently-skipped header.
    """
    return {
        "Accept": "application/json",
        "Authorization": bearer_auth_header(token),
    }


def extract_records(body):
    """Pull the submission list from an Intigriti REST response envelope.

    Canonical envelope wraps the record list under
    ``records`` (Intigriti's published response shape).
    Federated mirrors / staging stacks also expose
    bare-list / ``data`` / ``results`` / ``items`` /
    ``submissions`` — all shapes are tolerated.  Non-dict
    entries are silently dropped.  A single-record fetch
    (e.g. ``GET /submissions/<id>``) returns the record
    directly; that case is collapsed into a one-element
    list so downstream pagination still works.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("records", "data", "results", "items", "submissions"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
        if isinstance(v, dict):
            return [v]
    if body.get("id") or body.get("code"):
        return [body]
    return []


def record_program_id(record):
    """Pick the submission's program uuid / handle.

    Intigriti carries the program identifier as the
    top-level ``programId`` field; federated mirrors
    also expose it under nested ``program`` /
    ``program.id`` / ``program.handle`` dicts.  Returns
    ``""`` when nothing usable is present.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("programId", "program_id"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    program = record.get("program")
    if isinstance(program, dict):
        for key in ("handle", "slug", "id", "name"):
            v = program.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def record_researcher(record):
    """Pick the submission's researcher username."""
    if not isinstance(record, dict):
        return ""
    researcher = record.get("researcher") or record.get("reporter")
    if isinstance(researcher, dict):
        for key in ("username", "handle", "name"):
            v = researcher.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    for key in ("researcher_username", "researcherUsername", "reporter_username"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_url(record):
    """Pick the vulnerable URL / endpoint the submission targets.

    Intigriti carries the vulnerable URL on the top-level
    ``endpoint`` field (the submission form's URL field);
    federated mirrors also expose ``url`` /
    ``vulnerable_url`` / ``target.endpoint`` for programs
    that require scoped URLs.  Returns ``""`` when
    nothing usable is present.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("endpoint", "url", "vulnerable_url", "vulnerableUrl"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    target = record.get("target")
    if isinstance(target, dict):
        for key in ("endpoint", "url", "name"):
            v = target.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def record_status(record):
    """Pick the submission's canonical Intigriti status label.

    Intigriti carries the status under ``state.value``
    (the canonical envelope shape); federated mirrors
    also expose ``status`` / ``status.value`` / bare
    string ``state``.  Returns ``""`` when nothing
    usable is present.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("state", "status"):
        v = record.get(key)
        if isinstance(v, dict):
            inner = v.get("value")
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def record_type(record):
    """Pick the submission's Intigriti issue-type label."""
    if not isinstance(record, dict):
        return ""
    t = record.get("type")
    if isinstance(t, dict):
        for key in ("value", "name", "id"):
            v = t.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(t, str) and t.strip():
        return t.strip()
    return ""


def record_severity_label(record):
    """Pick the submission's Intigriti severity label (raw, not bucketed)."""
    if not isinstance(record, dict):
        return ""
    sev = record.get("severity")
    if isinstance(sev, dict):
        v = sev.get("value")
        if isinstance(v, str) and v.strip():
            return v.strip()
    if isinstance(sev, str) and sev.strip():
        return sev.strip()
    return ""


def collect_cves(record):
    """Walk an Intigriti submission for CVE ids.

    Intigriti surfaces CVE attribution under top-level
    ``cve`` / ``cves`` (string or list of CVE strings)
    and embeds CVE refs in the title / description /
    proofOfConcept body.  All occurrences are
    deduplicated and uppercased to NVD's canonical form.
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

    for key in ("title", "description", "proofOfConcept", "proof_of_concept", "summary"):
        scan(record.get(key))

    return out


def collect_cwes(record):
    """Walk an Intigriti submission for CWE ids.

    Intigriti surfaces CWE attribution via the top-level
    ``cwe`` field (string, list of strings, or a nested
    ``{"id": "...", "value": "..."}`` shape on newer
    programs); the issue ``type`` ontology also carries
    a CWE mapping that federated mirrors expose under
    ``type.cwe``.  Researchers frequently embed CWE refs
    in the title / description body.  All occurrences
    are deduplicated and uppercased.
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

    t = record.get("type")
    if isinstance(t, dict):
        for key in ("cwe", "value", "name"):
            raw = t.get(key)
            if isinstance(raw, list):
                for entry in raw:
                    scan(entry if isinstance(entry, str) else str(entry))
            else:
                scan(raw)

    for key in ("title", "description", "proofOfConcept", "proof_of_concept", "summary"):
        scan(record.get(key))

    return out


def collect_refs(record):
    """Build the refs list for an Intigriti submission record."""
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

    rec_id = record.get("id") or record.get("uuid") or record.get("submissionId")
    if rec_id is not None and str(rec_id).strip():
        add(f"INTIG-SubmissionID: {str(rec_id).strip()}")

    code = record.get("code") or record.get("internalReference") or record.get("reference")
    if code is not None and str(code).strip():
        add(f"INTIG-Code: {str(code).strip()}")

    program_id = record_program_id(record)
    if program_id:
        add(f"INTIG-Program: {program_id}")
        add(f"https://app.intigriti.com/researcher/programs/{program_id}")

    researcher = record_researcher(record)
    if researcher:
        add(f"INTIG-Researcher: {researcher}")
        add(f"https://app.intigriti.com/researcher/profile/{researcher}")

    status = record_status(record)
    if status:
        add(f"INTIG-Status: {status}")

    issue_type = record_type(record)
    if issue_type:
        add(f"INTIG-Type: {issue_type}")

    severity_label = record_severity_label(record)
    if severity_label:
        add(f"INTIG-Severity: {severity_label}")

    for key, label in (
        ("createdAt", "INTIG-CreatedAt"),
        ("lastUpdatedAt", "INTIG-UpdatedAt"),
        ("closedAt", "INTIG-ClosedAt"),
        ("acceptedAt", "INTIG-AcceptedAt"),
        ("resolvedAt", "INTIG-ResolvedAt"),
        ("triagedAt", "INTIG-TriagedAt"),
        ("disclosedAt", "INTIG-DisclosedAt"),
        ("bountyAmount", "INTIG-Bounty"),
        ("bountyCurrency", "INTIG-Currency"),
        ("source", "INTIG-Source"),
        ("endpoint", "INTIG-Endpoint"),
        ("cvssVector", "INTIG-CVSSVector"),
        ("cvssScore", "INTIG-CVSSScore"),
    ):
        v = record.get(key)
        if v in (None, ""):
            continue
        add(f"{label}: {v}")

    rec_id_str = str(rec_id).strip() if rec_id is not None else ""
    if rec_id_str:
        add(f"https://app.intigriti.com/researcher/submissions/{rec_id_str}")

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


def build_submission_vulnerability(record):
    """Build a Faraday vulnerability dict for one Intigriti submission.

    Terminal Intigriti statuses (``closed`` / ``resolved``
    / ``duplicate`` / ``out-of-scope`` / ``spam`` /
    ``informative`` / ``wont-fix``) floor the severity to
    ``info`` regardless of the published rating.  The
    submission is surfaced as a Faraday vulnerability
    with the ``[BUG-BOUNTY]`` engine prefix so external
    researcher reports land alongside the other
    crowd-sourced feeds.
    """
    if not isinstance(record, dict):
        return None
    status_value = record_status(record)
    sev_value = record.get("severity")
    severity = severity_from_submission(sev_value)
    if is_closed_status(status_value):
        severity = "info"

    title = record.get("title") or record.get("code") or record.get("id") or "Intigriti submission"
    name = f"[BUG-BOUNTY] Intigriti submission: {str(title).strip()}"

    desc_parts = []
    vinfo = (
        record.get("description")
        or record.get("proofOfConcept")
        or record.get("proof_of_concept")
        or record.get("summary")
        or ""
    )
    if isinstance(vinfo, str) and vinfo.strip():
        desc_parts.append(vinfo.strip())
    for key in sorted(record.keys()):
        if key in ("description", "proofOfConcept", "proof_of_concept", "summary", "title"):
            continue
        v = record.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    program_id = record_program_id(record)
    if program_id and not any(p.startswith("programId:") or p.startswith("program:") for p in desc_parts):
        desc_parts.append(f"program: {program_id}")
    researcher = record_researcher(record)
    if researcher:
        desc_parts.append(f"researcher: {researcher}")

    record_id = str(record.get("id") or record.get("uuid") or record.get("code") or name)

    if is_closed_status(status_value):
        resolution = (
            f"Intigriti has marked this submission as {status_value}; "
            "verify the underlying vulnerability is patched "
            "(for resolved / closed submissions) or that the "
            "platform's triage decision matches the operator's "
            "risk appetite (for duplicate / out-of-scope / "
            "spam / informative / wont-fix) before closing the "
            "Faraday finding."
        )
    else:
        resolution = (
            "Triage this Intigriti submission in the program's "
            "inbox, correlate the endpoint URL against the "
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
        "external_id": f"intig-submission::{record_id}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record),
        "cve": collect_cves(record),
        "cwe": collect_cwes(record),
        "cvss3": {},
        "tags": ["intigriti", "pentest-platforms", "submission"],
    }


def build_host_from_submission(record):
    """Build a Faraday host dict from an Intigriti submission record."""
    if not isinstance(record, dict):
        return None
    vuln = build_submission_vulnerability(record)
    if vuln is None:
        return None
    hostnames = []
    title = record.get("title")
    if isinstance(title, str) and title.strip():
        hostnames.append(title.strip())
    url = record_url(record)
    if url and url not in hostnames:
        hostnames.append(url)
    program_id = record_program_id(record)
    desc_parts = []
    if program_id:
        desc_parts.append(f"program={program_id}")
    status = record_status(record)
    if status:
        desc_parts.append(f"status={status}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts) or "Intigriti bug-bounty submission",
        "vulnerabilities": [vuln],
    }


def fetch_pages(requests_module, url, headers, program_ids, statuses, max_pages, page_size=DEFAULT_PAGE_SIZE):
    """Walk the Intigriti /submissions surface page-by-page.

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
        qs = build_query(page, page_size=page_size, program_ids=program_ids, statuses=statuses)
        full_url = f"{url}?{qs}"
        try:
            resp = requests_module.get(full_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {full_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Intigriti request rejected (401); check INTIG_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Intigriti request rejected (403); check the token's program scope.")
            return out
        if resp.status_code == 429:
            log("Intigriti rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Intigriti request failed ({resp.status_code}) for {full_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Intigriti response was not JSON ({full_url})")
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
        log(f"hit INTIG_PAGES={max_pages}; stopping pagination")
    return out


def validate_pages(value):
    """Coerce INTIG_PAGES into a clamped integer.

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

    program_ids = parse_program_ids(env("EXECUTOR_CONFIG_INTIG_PROGRAM_ID"))
    statuses = parse_statuses(env("EXECUTOR_CONFIG_INTIG_STATUS"))
    pages = validate_pages(env("INTIG_PAGES"))

    host = env("INTIG_HOST", default=DEFAULT_HOST)
    api_token = env("INTIG_TOKEN", required=True)

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
        program_ids,
        statuses,
        max_pages=pages,
    )
    log(
        f"Intigriti discovered {len(submissions)} submissions "
        f"(programs={','.join(program_ids) or '(all)'}, "
        f"statuses={','.join(statuses) or '(all)'})"
    )

    hosts_out = []
    for record in submissions:
        built = build_host_from_submission(record)
        if built is not None:
            hosts_out.append(built)

    log(f"Processed {len(hosts_out)} Intigriti hosts " f"(submissions={len(submissions)})")

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "intigriti",
            "command": "intigriti",
            "params": (
                f"programs={','.join(program_ids)} "
                f"statuses={','.join(statuses)} "
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
