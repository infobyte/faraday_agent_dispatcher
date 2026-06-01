#!/usr/bin/env python
"""Splunk REST search-job importer.

Runs an SPL (Search Processing Language) saved-search query against a
Splunk Enterprise / Splunk Cloud REST tenant and emits Faraday
bulk-create JSON to stdout.  The SPL query is the unit of work — the
dispatcher dispatches one search per scan, waits for the search job to
finish, paginates the result rows, and emits each row as a Faraday
vulnerability attached to a single synthetic host record keyed on the
Splunk hostname (Splunk's surface is search-scoped, not asset-scoped,
so the host record is a synthetic per-query bucket rather than an
IP-keyed asset).  Each result row attaches as a Faraday vulnerability
with the engine prefix ``[SIEM]``.

Endpoints used:
  POST {SPLUNK_HOST}/services/search/jobs
      -> create a synchronous search job.  Form-encoded with
      ``search=<SPL>`` + ``earliest_time`` + ``latest_time`` +
      ``output_mode=json``.  Returns ``{"sid": "<search id>"}``.
  GET  {SPLUNK_HOST}/services/search/jobs/{sid}?output_mode=json
      -> poll job state.  Body carries
      ``entry[0].content.isDone`` (bool) +
      ``entry[0].content.dispatchState`` (QUEUED / PARSING / RUNNING /
      DONE / FAILED).  Polled until done with a 2-second sleep, capped
      at ``MAX_POLLS`` (~5 minutes by default).
  GET  {SPLUNK_HOST}/services/search/jobs/{sid}/results?output_mode=json&count=N&offset=M
      -> paginated result rows.  Pagination is ``count`` + ``offset``
      cursor; exhaustion is detected when fewer than ``count`` rows
      come back or the body carries ``results=[]``.  Each row maps
      onto a Faraday vulnerability — severity bucketed from the
      Splunk-ES freeform ``severity`` string enum (informational /
      low / medium / high / critical) and / or the numeric ``urgency``
      / ``severity_id`` (1-5) with a CVSS-style fallback.

Auth: Splunk accepts either an HTTP Authorization-token header
(Splunk 7.3+ — ``Authorization: Bearer <SPLUNK_TOKEN>``) or HTTP
Basic auth with the management-port credentials.  The dispatcher
prefers ``SPLUNK_TOKEN`` when present and falls back to
``SPLUNK_USER`` / ``SPLUNK_PASSWORD`` otherwise.  ``SPLUNK_TOKEN`` is
created in Splunk Web under ``Settings -> Tokens -> New Token``.
``SPLUNK_HOST`` is the management endpoint (typically port 8089 on
on-prem, e.g.  ``https://splunk.example.com:8089``; Splunk Cloud
deployments expose this as ``https://<stack>.splunkcloud.com:8089``).
"""

import base64
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Splunk SID strings on POST /services/search/jobs are timestamp +
# random suffix (e.g. ``1700000000.12345``) — restrict to the
# documented shape so a garbage sid can't fan out into junk URLs.
SID_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
# Lenient http(s)://host[:port] URL recogniser (used to validate
# SPLUNK_HOST client-side so a typo can't fan out into "None/services
# /search/jobs" calls).
HOST_RE = re.compile(r"^https?://[A-Za-z0-9_.\-]+(?::\d{1,5})?(?:/[^\s]*)?$")

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100
MAX_POLLS = 150  # ~5 minutes at POLL_INTERVAL=2s
POLL_INTERVAL = 2

# Splunk ES surfaces ``severity`` as a freeform string enum
# (informational / low / medium / high / critical) plus a numeric
# ``severity_id`` / ``urgency`` 1-5.  The string enum buckets onto
# Faraday tiers; numeric bucketing is used as a fallback when the
# string is missing / unrecognised.
SPLUNK_STRING_SEVERITY = {
    "critical": "critical",
    "fatal": "critical",
    "severe": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "minor": "low",
    "notice": "low",
    "info": "info",
    "informational": "info",
    "debug": "info",
    "unknown": "info",
    "none": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Splunk ES Notable Events lifecycle is exposed via ``status`` /
# ``event_status`` / ``disposition`` / ``notable_event_status``.  New /
# unassigned / in_progress / open map onto Faraday open; closed /
# resolved / fixed map onto closed; risk_accepted / suppressed map
# onto risk-accepted.
SPLUNK_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "unassigned": "open",
    "assigned": "open",
    "active": "open",
    "in_progress": "open",
    "inprogress": "open",
    "investigating": "open",
    "triaging": "open",
    "pending": "open",
    "remediated": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "closed": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "waived": "risk-accepted",
    "will_not_fix": "risk-accepted",
    "willnotfix": "risk-accepted",
    "wontfix": "risk-accepted",
    "won't_fix": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "suppressed": "risk-accepted",
    "dismissed": "risk-accepted",
    "ignored": "risk-accepted",
}

# Splunk ES ``urgency`` / ``severity_id`` are 1-5 with 5 being the
# most severe.  Map onto Faraday buckets.
SPLUNK_NUMERIC_SEVERITY_15 = {
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


def log(msg):
    print(f"{datetime.utcnow()} - Splunk: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
    """Bucket a numeric severity (0-10 CVSS-style) onto a Faraday tier."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "info"
    if score <= 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    if score > 10:
        return "info"
    return "critical"


def severity_from_splunk(value, numeric=None, urgency=None):
    """Map a Splunk severity string onto a Faraday bucket.

    Accepts the freeform string enum (informational / low / medium /
    high / critical / debug / warning), Faraday-side synonyms,
    numeric inputs (1-5 Splunk ES scale OR 0-10 CVSS-style), numeric
    strings, and falls back to numeric bucketing on ``numeric`` /
    ``urgency`` when the primary value is missing or unrecognised.
    """
    if isinstance(value, bool):
        if urgency is not None:
            return severity_from_splunk_15(urgency)
        if numeric is not None:
            return severity_from_cvss(numeric)
        return "info"
    if isinstance(value, (int, float)):
        as_int = int(value) if float(value).is_integer() else None
        if as_int in SPLUNK_NUMERIC_SEVERITY_15:
            return SPLUNK_NUMERIC_SEVERITY_15[as_int]
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower()
        if text in SPLUNK_STRING_SEVERITY:
            return SPLUNK_STRING_SEVERITY[text]
        try:
            as_int = int(text)
            if as_int in SPLUNK_NUMERIC_SEVERITY_15:
                return SPLUNK_NUMERIC_SEVERITY_15[as_int]
        except ValueError:
            pass
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if urgency is not None:
        return severity_from_splunk_15(urgency)
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def severity_from_splunk_15(value):
    """Bucket a Splunk-ES urgency (1-5) onto a Faraday tier.

    Out-of-range numeric input falls back through the CVSS-style
    bucketing so callers can pass either scale.
    """
    if isinstance(value, bool):
        return "info"
    if isinstance(value, (int, float)):
        try:
            as_int = int(value) if float(value).is_integer() else None
        except (TypeError, ValueError):
            as_int = None
        if as_int in SPLUNK_NUMERIC_SEVERITY_15:
            return SPLUNK_NUMERIC_SEVERITY_15[as_int]
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower()
        if text in SPLUNK_STRING_SEVERITY:
            return SPLUNK_STRING_SEVERITY[text]
        try:
            as_int = int(text)
            if as_int in SPLUNK_NUMERIC_SEVERITY_15:
                return SPLUNK_NUMERIC_SEVERITY_15[as_int]
        except ValueError:
            pass
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    return "info"


def status_from_splunk(item):
    """Derive Faraday status from a Splunk result row.

    Walks ``status`` / ``event_status`` / ``disposition`` /
    ``notable_event_status`` / ``state`` and accepts ES Notable Event
    numeric status ids (0 unassigned, 1 new, 2 in_progress, 3 pending,
    4 resolved, 5 closed) as a fallback.
    """
    if not isinstance(item, dict):
        return "open"
    for key in (
        "status",
        "event_status",
        "disposition",
        "notable_event_status",
        "state",
        "Status",
        "State",
        "Disposition",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in SPLUNK_STATUS_BY_STATE:
                return SPLUNK_STATUS_BY_STATE[compact]
            if squashed in SPLUNK_STATUS_BY_STATE:
                return SPLUNK_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in SPLUNK_STATUS_BY_STATE:
                        return SPLUNK_STATUS_BY_STATE[compact]
                    if squashed in SPLUNK_STATUS_BY_STATE:
                        return SPLUNK_STATUS_BY_STATE[squashed]
        elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
            # Splunk ES numeric status ids: 0 unassigned, 1 new, 2
            # in_progress, 3 pending, 4 resolved, 5 closed.
            try:
                as_int = int(raw)
            except (TypeError, ValueError):
                continue
            if as_int in (0, 1, 2, 3):
                return "open"
            if as_int in (4, 5):
                return "closed"
    return "open"


def validate_min_severity(value):
    """Validate SPLUNK_MIN_SEVERITY (optional severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus Splunk-side synonyms
    (informational / debug -> info, warning / moderate -> medium,
    notice / minor -> low, fatal / severe -> critical) plus numeric
    input bucketed via Splunk-ES 1-5 or CVSS 0-10 (best-effort).
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = SPLUNK_STRING_SEVERITY.get(text)
    if bucket is None:
        try:
            as_int = int(text)
            if as_int in SPLUNK_NUMERIC_SEVERITY_15:
                bucket = SPLUNK_NUMERIC_SEVERITY_15[as_int]
        except ValueError:
            pass
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"SPLUNK_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_search_query(value):
    """Validate SPLUNK_SEARCH_QUERY.

    None / blank -> sys.exit(1).  Splunk's REST contract is that the
    ``search`` parameter must start with either ``search`` (the
    canonical search command) or a leading ``|`` for a generating
    command (e.g. ``| tstats ...``, ``| inputlookup ...``).  We
    prepend ``search `` client-side when the caller omits both so a
    bare ``index=foo`` still posts cleanly.
    """
    if value is None or value == "":
        log("SPLUNK_SEARCH_QUERY is required")
        sys.exit(1)
    text = str(value).strip()
    if not text:
        log("SPLUNK_SEARCH_QUERY is required")
        sys.exit(1)
    lowered = text.lower()
    if lowered.startswith("search ") or lowered == "search" or text.startswith("|"):
        return text
    return f"search {text}"


def validate_time_modifier(value, name):
    """Validate SPLUNK_EARLIEST / SPLUNK_LATEST (Splunk time modifiers).

    None / blank -> "" (no time-range hint sent; Splunk applies the
    saved-search default or 'all time').  Accepts Splunk's documented
    time-modifier strings (``-24h``, ``-1d@d``, ``now``, absolute
    epoch like ``1700000000``, ISO timestamps like
    ``2026-05-30T00:00:00``) — we just sanity-check the shape for
    non-whitespace control characters and pass anything else through.
    """
    if value is None or value == "":
        return ""
    raw = str(value)
    # Reject control chars on the raw input before strip(), so
    # trailing newlines don't get silently trimmed away.
    if "\n" in raw or "\r" in raw or "\t" in raw:
        log(f"{name} contains a control character; ignoring")
        return ""
    text = raw.strip()
    if not text:
        return ""
    return text


def validate_host(value):
    """Validate SPLUNK_HOST.

    None / blank -> sys.exit(1).  Splunk's management endpoint is
    typically ``https://<host>:8089`` (on-prem) or
    ``https://<stack>.splunkcloud.com:8089`` (Splunk Cloud).  We
    hard-enforce the http(s)://host[:port] shape client-side so a
    typo can't fan out into "None/services/search/jobs" calls.
    Trailing slashes are stripped.
    """
    if value is None or value == "":
        log("SPLUNK_HOST is required")
        sys.exit(1)
    text = str(value).strip()
    if not text:
        log("SPLUNK_HOST is required")
        sys.exit(1)
    if not HOST_RE.match(text):
        log(f"SPLUNK_HOST '{text}' is not a valid http(s)://host[:port] URL")
        sys.exit(1)
    return text.rstrip("/")


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def auth_headers(token=None, user=None, password=None):
    """Build the Splunk REST auth header.

    Prefers ``SPLUNK_TOKEN`` (Authorization: Bearer ...) when set;
    falls back to HTTP Basic auth with ``SPLUNK_USER`` /
    ``SPLUNK_PASSWORD`` otherwise.  Returns the headers dict plus the
    auth-mode string (for logging).
    """
    headers = {"Accept": "application/json"}
    if isinstance(token, str) and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
        return headers, "token"
    if (isinstance(user, str) and user.strip()) and (isinstance(password, str) and password is not None):
        raw = f"{user}:{password or ''}".encode("utf-8")
        encoded = base64.b64encode(raw).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
        return headers, "basic"
    return headers, "anonymous"


def build_jobs_url(host):
    return f"{host}/services/search/jobs"


def build_job_status_url(host, sid):
    return f"{host}/services/search/jobs/{sid}"


def build_job_results_url(host, sid):
    return f"{host}/services/search/jobs/{sid}/results"


def build_job_create_params(search, earliest, latest):
    """Build the form-encoded body for POST /services/search/jobs.

    ``output_mode=json`` so the SID comes back as JSON instead of XML;
    ``exec_mode=normal`` so the job runs asynchronously (we'll poll).
    ``earliest_time`` / ``latest_time`` are only included when set so
    Splunk applies the saved-search default otherwise.
    """
    params = {
        "search": search,
        "output_mode": "json",
        "exec_mode": "normal",
    }
    if earliest:
        params["earliest_time"] = earliest
    if latest:
        params["latest_time"] = latest
    return params


def build_job_status_params():
    return {"output_mode": "json"}


def build_job_results_params(offset, count):
    return {
        "output_mode": "json",
        "count": int(count),
        "offset": int(offset),
    }


def extract_sid(body):
    """Pull the search-job sid out of a Splunk POST /jobs response."""
    if isinstance(body, dict):
        sid = body.get("sid")
        if isinstance(sid, str) and sid.strip():
            return sid.strip()
    if isinstance(body, str) and body.strip():
        # Splunk falls back to XML when output_mode=json is ignored —
        # try a coarse <sid>...</sid> regex extraction.
        m = re.search(r"<sid>([^<]+)</sid>", body)
        if m:
            return m.group(1).strip()
    return ""


def extract_is_done(body):
    """Pull the search-job ``isDone`` flag from a status payload."""
    if not isinstance(body, dict):
        return False
    entries = body.get("entry")
    if isinstance(entries, list) and entries:
        first = entries[0]
        if isinstance(first, dict):
            content = first.get("content")
            if isinstance(content, dict):
                is_done = content.get("isDone")
                if isinstance(is_done, bool):
                    return is_done
                if isinstance(is_done, (int, float)):
                    return bool(int(is_done))
                if isinstance(is_done, str):
                    return is_done.strip().lower() in ("1", "true", "yes")
                state = content.get("dispatchState")
                if isinstance(state, str):
                    return state.strip().upper() in ("DONE", "FAILED", "FINALIZING")
    return False


def extract_dispatch_state(body):
    """Pull the search-job ``dispatchState`` from a status payload."""
    if not isinstance(body, dict):
        return ""
    entries = body.get("entry")
    if isinstance(entries, list) and entries:
        first = entries[0]
        if isinstance(first, dict):
            content = first.get("content")
            if isinstance(content, dict):
                state = content.get("dispatchState")
                if isinstance(state, str):
                    return state.strip().upper()
    return ""


def extract_results(body):
    """Pull the result-row list out of a Splunk /results envelope.

    Splunk uses ``{"results": [...], "preview": false, "init_offset":
    N}`` — accept ``rows`` / ``data`` as alt-keys for federated
    stacks.
    """
    if not isinstance(body, dict):
        return []
    for key in ("results", "rows", "data"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


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
    """Walk a Splunk result row for CVE-* ids.

    Splunk-ES Notable Events surface CVE references inline on
    ``cve`` / ``cve_id`` plus the ``message`` / ``description`` /
    ``signature`` freeform fields.
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
        "message",
        "description",
        "signature",
        "summary",
        "name",
        "title",
        "_raw",
        "rule_name",
        "rule",
    ):
        v = item.get(key)
        if isinstance(v, str):
            scan(v)
    return found


def collect_refs(item):
    """Walk a Splunk result row for advisory URLs and Splunk pivots."""
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

    event_id = item.get("event_id") or item.get("eventId") or item.get("orig_event_id")
    if event_id is not None:
        s = str(event_id).strip()
        if s:
            add(f"Splunk-Event: {s}")

    event_hash = item.get("event_hash") or item.get("eventHash")
    if event_hash is not None:
        s = str(event_hash).strip()
        if s:
            add(f"Splunk-EventHash: {s}")

    rule_name = item.get("rule_name") or item.get("ruleName") or item.get("rule")
    if isinstance(rule_name, str) and rule_name.strip():
        add(f"Splunk-Rule: {rule_name.strip()}")

    search_name = item.get("search_name") or item.get("savedsearch_name")
    if isinstance(search_name, str) and search_name.strip():
        add(f"Splunk-SavedSearch: {search_name.strip()}")

    src_index = item.get("index") or item.get("_index") or item.get("sourcetype")
    if isinstance(src_index, str) and src_index.strip():
        add(f"Splunk-Index: {src_index.strip()}")

    source = item.get("source") or item.get("_source")
    if isinstance(source, str) and source.strip():
        add(f"Splunk-Source: {source.strip()}")

    host = item.get("host") or item.get("_host")
    if isinstance(host, str) and host.strip():
        add(f"Splunk-Host: {host.strip()}")

    for key in ("references", "url", "urls", "advisory_urls", "links"):
        entry = item.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("link") or it.get("name")
                    if href:
                        add(href)
                elif isinstance(it, str):
                    add(it)
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def result_label(item):
    """Build the leading title fragment for a Splunk result row."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "rule_name",
        "ruleName",
        "rule",
        "signature",
        "title",
        "name",
        "savedsearch_name",
        "search_name",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("message", "summary", "description"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().split("\n", 1)[0][:200]
    return "Splunk result"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from a Splunk result row."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    raw_numeric = item.get("severity_score") or item.get("severityScore") or item.get("cvss") or item.get("cvss_score")
    if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
        severity_numeric = float(raw_numeric)
    elif isinstance(raw_numeric, str) and raw_numeric.strip():
        try:
            severity_numeric = float(raw_numeric.strip())
        except ValueError:
            severity_numeric = None

    urgency_value = None
    raw_urgency = item.get("urgency") or item.get("severity_id") or item.get("severityId") or item.get("priority")
    if isinstance(raw_urgency, (int, float)) and not isinstance(raw_urgency, bool):
        urgency_value = raw_urgency
    elif isinstance(raw_urgency, str) and raw_urgency.strip():
        urgency_value = raw_urgency.strip()

    severity_string = (
        item.get("severity") or item.get("severity_label") or item.get("severityLabel") or item.get("level")
    )
    severity = severity_from_splunk(severity_string, severity_numeric, urgency_value)
    status = status_from_splunk(item)

    label = result_label(item)
    name = f"[SIEM] {label}" if label else "[SIEM] Splunk result"

    desc_parts = []
    description = item.get("description") or item.get("Description") or item.get("message") or item.get("summary")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("event_id", "event_id"),
        ("event_hash", "event_hash"),
        ("orig_event_id", "orig_event_id"),
        ("rule_name", "rule_name"),
        ("search_name", "search_name"),
        ("savedsearch_name", "savedsearch_name"),
        ("signature", "signature"),
        ("index", "index"),
        ("sourcetype", "sourcetype"),
        ("source", "source"),
        ("host", "host"),
        ("src", "src"),
        ("src_ip", "src_ip"),
        ("dest", "dest"),
        ("dest_ip", "dest_ip"),
        ("user", "user"),
        ("severity", "severity"),
        ("severity_id", "severity_id"),
        ("urgency", "urgency"),
        ("priority", "priority"),
        ("status", "status"),
        ("disposition", "disposition"),
        ("event_status", "event_status"),
        ("_time", "_time"),
        ("first_seen", "first_seen"),
        ("last_seen", "last_seen"),
        ("count", "count"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    raw_event = item.get("_raw")
    if isinstance(raw_event, str) and raw_event.strip():
        snippet = raw_event.strip()
        if len(snippet) > 2000:
            snippet = snippet[:2000] + "...(truncated)"
        desc_parts.append(f"_raw: {snippet}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    remediation = item.get("remediation") or item.get("recommendation") or item.get("resolution")
    if isinstance(remediation, str) and remediation.strip():
        resolution = remediation.strip()
    if not resolution:
        resolution = (
            "Investigate the Notable Event / search row in the Splunk "
            "portal (Apps -> Enterprise Security -> Incident Review or "
            "the source saved-search) and drive remediation through the "
            "owning detection / asset team; close the event via the "
            "Splunk-ES Notable Event workflow once handled so the row "
            "lifecycle stays in sync."
        )

    external_id = str(
        item.get("event_id")
        or item.get("eventId")
        or item.get("event_hash")
        or item.get("eventHash")
        or item.get("_cd")
        or item.get("_serial")
        or (cves[0] if cves else "")
    )

    return {
        "name": str(name).strip()[:200] or f"Splunk result {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["splunk", "siem", "siem-analytics"],
    }


def synthetic_hostname(host):
    """Pick the synthetic host's hostname from the Splunk endpoint URL."""
    if not isinstance(host, str):
        return ""
    text = host.strip()
    if not text:
        return ""
    # Strip scheme + port + path so we land on the bare FQDN.
    m = re.match(r"^https?://([^:/]+)", text)
    if m:
        return m.group(1).strip().lower()
    return text


def build_host(host, search, earliest, latest, sid, vulns):
    """Build a Faraday host record for the synthetic Splunk-search bucket."""
    hostname = synthetic_hostname(host)
    os_str = f"Splunk ({hostname})" if hostname else "Splunk"

    desc_parts = [f"splunk_host={host}"]
    if hostname:
        desc_parts.append(f"hostname={hostname}")
    desc_parts.append(f"search={search}")
    if earliest:
        desc_parts.append(f"earliest={earliest}")
    if latest:
        desc_parts.append(f"latest={latest}")
    if sid:
        desc_parts.append(f"sid={sid}")
    if vulns:
        desc_parts.append(f"results={len(vulns)}")

    return {
        "ip": "0.0.0.0",
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def create_search_job(requests_module, host, headers, search, earliest, latest):
    """POST /services/search/jobs and return the sid."""
    url = build_jobs_url(host)
    data = build_job_create_params(search, earliest, latest)
    try:
        resp = requests_module.post(url, headers=headers, data=data, timeout=TIMEOUT, verify=True)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"POST {url} failed: {exc}")
        return ""
    if resp.status_code == 401:
        log("Splunk request rejected (401). Check SPLUNK_TOKEN / SPLUNK_USER / SPLUNK_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        log("Splunk request rejected (403). Check the token / user's role / capabilities.")
        return ""
    if resp.status_code >= 400:
        log(f"Splunk job creation failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return ""
    sid = ""
    try:
        sid = extract_sid(resp.json())
    except ValueError:
        sid = extract_sid(resp.text)
    if not sid:
        log("Splunk job creation succeeded but no sid was returned")
        return ""
    if not SID_RE.match(sid):
        log(f"Splunk returned a malformed sid '{sid}'; refusing to poll")
        return ""
    log(f"created search job sid={sid}")
    return sid


def wait_for_job(
    requests_module, host, sid, headers, max_polls=MAX_POLLS, interval=POLL_INTERVAL, sleep_fn=time.sleep
):
    """Poll /services/search/jobs/{sid} until isDone, FAILED, or timeout."""
    url = build_job_status_url(host, sid)
    params = build_job_status_params()
    polls = 0
    while polls < max_polls:
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=True)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            return False
        if resp.status_code == 401:
            log("Splunk request rejected (401). Check SPLUNK_TOKEN / SPLUNK_USER / SPLUNK_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Splunk request rejected (403). Check the token / user's role / capabilities.")
            return False
        if resp.status_code == 404:
            log(f"Splunk job {sid} not found (404).")
            return False
        if resp.status_code >= 400:
            log(f"Splunk job status request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return False
        try:
            payload = resp.json()
        except ValueError:
            log(f"Splunk job status response was not JSON ({url})")
            return False
        state = extract_dispatch_state(payload)
        if extract_is_done(payload):
            if state == "FAILED":
                log(f"Splunk job {sid} ended in dispatchState=FAILED")
                return False
            return True
        polls += 1
        sleep_fn(interval)
    log(f"hit MAX_POLLS={max_polls}; abandoning sid={sid}")
    return False


def fetch_results(requests_module, host, sid, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE):
    """Walk /services/search/jobs/{sid}/results via count + offset cursor."""
    out = []
    url = build_job_results_url(host, sid)
    offset = 0
    pages_walked = 0
    while pages_walked < max_pages:
        params = build_job_results_params(offset, page_size)
        try:
            resp = requests_module.get(url, headers=headers, params=params, timeout=TIMEOUT, verify=True)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Splunk request rejected (401). Check SPLUNK_TOKEN / SPLUNK_USER / SPLUNK_PASSWORD.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Splunk request rejected (403). Check the token / user's role / capabilities.")
            return out
        if resp.status_code == 204:
            # No results — Splunk returns 204 No Content for empty results.
            return out
        if resp.status_code >= 400:
            log(f"Splunk results request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Splunk results response was not JSON ({url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        if len(results) < page_size:
            break
        offset += page_size
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination")
    return out


def main():
    started = time.time()

    search = validate_search_query(env("EXECUTOR_CONFIG_SPLUNK_SEARCH_QUERY"))
    earliest = validate_time_modifier(env("EXECUTOR_CONFIG_SPLUNK_EARLIEST"), "SPLUNK_EARLIEST")
    latest = validate_time_modifier(env("EXECUTOR_CONFIG_SPLUNK_LATEST"), "SPLUNK_LATEST")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_SPLUNK_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    host = validate_host(env("SPLUNK_HOST", required=True))
    token = env("SPLUNK_TOKEN")
    user = env("SPLUNK_USER")
    password = env("SPLUNK_PASSWORD")
    if not token and not (user and password is not None):
        log("Provide SPLUNK_TOKEN, or both SPLUNK_USER and SPLUNK_PASSWORD")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers, auth_mode = auth_headers(token=token, user=user, password=password)
    log(f"auth_mode={auth_mode}")

    sid = create_search_job(requests, host, headers, search, earliest, latest)
    if not sid:
        # Emit an empty bulk-create envelope so the dispatcher still
        # receives well-formed JSON even when the job didn't take.
        host_record = build_host(host, search, earliest, latest, "", [])
        print(
            json.dumps(
                {
                    "hosts": [host_record],
                    "command": {
                        "tool": "splunk",
                        "command": "splunk",
                        "params": f"search={search},earliest={earliest},latest={latest},min_severity={min_severity}",
                        "user": os.environ.get("USER", ""),
                        "hostname": socket.gethostname(),
                        "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
                        "duration": int((time.time() - started) * 1000),
                        "import_source": "report",
                    },
                }
            )
        )
        return

    if not wait_for_job(requests, host, sid, headers):
        host_record = build_host(host, search, earliest, latest, sid, [])
        print(
            json.dumps(
                {
                    "hosts": [host_record],
                    "command": {
                        "tool": "splunk",
                        "command": "splunk",
                        "params": (
                            f"search={search},earliest={earliest},latest={latest},"
                            f"sid={sid},min_severity={min_severity}"
                        ),
                        "user": os.environ.get("USER", ""),
                        "hostname": socket.gethostname(),
                        "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
                        "duration": int((time.time() - started) * 1000),
                        "import_source": "report",
                    },
                }
            )
        )
        return

    results = fetch_results(requests, host, sid, headers)
    log(f"Processing {len(results)} Splunk result rows for sid={sid} " f"(min_severity={min_severity})")

    vulns = []
    for row in results:
        built = build_vulnerability(row)
        if built is None:
            continue
        if allowed_severities and built["severity"] not in allowed_severities:
            continue
        vulns.append(built)

    host_record = build_host(host, search, earliest, latest, sid, vulns)

    params_bits = [
        f"search={search}",
        f"earliest={earliest or 'default'}",
        f"latest={latest or 'default'}",
        f"sid={sid}",
        f"min_severity={min_severity}",
    ]

    output = {
        "hosts": [host_record],
        "command": {
            "tool": "splunk",
            "command": "splunk",
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
