#!/usr/bin/env python
"""Sekoia.io Defend importer.

Pulls alert + observable records from the Sekoia.io
REST API (https://api.sekoia.io) and emits Faraday
bulk-create JSON to stdout.  Sekoia.io is a French
commercial XDR + CTI platform — analysts curate SOC
alerts around operator-side intakes and publish IOC-
level observables tied to wider campaigns.

Endpoints used:
  GET {SEKOIA_HOST}/v1/sic/alerts
      ?limit=N&offset=N[&filter=<expr>]
      -> Paginated SIC alert inventory under the
      operator's tenant.  Canonical envelope is
      ``{"items": [...], "total": N}``; federated /
      mirror stacks also expose bare-list +
      ``{"data": [...]}`` / ``{"results": [...]}`` /
      ``{"alerts": [...]}`` shapes.  Each alert
      carries ``uuid`` / ``short_id``, ``title``,
      ``urgency`` (0..100 numeric — Sekoia's
      proprietary 0..100 priority score), ``status``
      (``{"name": "Open"|"Closed"|"Acknowledged"|
      "Rejected"|"Mitigated", ...}`` or bare string),
      ``rule`` (the detection rule that fired —
      ``{"uuid": "...", "name": "..."}``), ``assets``
      (operator-side assets the alert pivots on),
      ``entity`` (the Sekoia entity the alert belongs
      to — usually the customer's tenant entity),
      ``created_at`` / ``updated_at`` / ``first_seen_at``
      / ``last_seen_at`` ISO timestamps, ``intake_uuid``
      (the operator's data-intake the alert was
      raised against), ``kill_chain_short_id``, and
      optional ``stix.objects`` (STIX 2.1 sub-graph).

  GET {SEKOIA_HOST}/v1/iocs/observables
      ?limit=N&offset=N[&filter=<expr>]
      -> Paginated CTI observable inventory.
      Canonical envelope is ``{"items": [...], "total":
      N}`` (same as the SIC surface).  Each observable
      carries ``id``, ``value`` (the canonical IOC
      value), ``type`` (``ipv4-addr`` / ``ipv6-addr``
      / ``domain-name`` / ``url`` / ``email-addr`` /
      ``file:hashes.MD5`` / ``file:hashes.SHA-1`` /
      ``file:hashes.SHA-256``), ``confidence`` (0..100
      numeric — Sekoia analyst confidence), ``labels``
      (tags the analyst attached), ``valid_from`` /
      ``valid_until`` ISO timestamps, ``created_at`` /
      ``updated_at``, optional ``description`` and
      ``pattern`` (STIX 2.1 pattern expression).

Auth: Sekoia.io uses Bearer-token authentication —
the operator creates an API key in the Sekoia.io
console (Settings -> API Keys -> Generate) and pastes
the returned token into ``SEKOIA_TOKEN``.  The
dispatcher sends ``Authorization: Bearer <token>`` on
every request.

Args:
  ``SEKOIA_FILTER`` (optional) — a Sekoia.io filter
  expression forwarded server-side as the ``filter=``
  query parameter on both endpoints.  Sekoia.io's
  filter DSL supports field-equality + boolean
  composition (e.g.  ``urgency:>=70 AND
  status.name:"Open"`` for the alerts surface;
  ``type:"ipv4-addr" AND confidence:>=80`` for the
  observables surface).  Blank / missing / unparseable
  input keeps every record (the typical operational
  mode); whitespace is trimmed and the value is
  URL-encoded before being placed in the query
  string.

  ``SEKOIA_LIMIT`` (optional) — per-request page size
  (default 100, clamped ``[1, 100]`` per Sekoia.io's
  documented per-page ceiling on both endpoints).
  Garbage / bool / unparseable input falls back to
  the default.  Pagination walks ``offset`` /
  ``limit`` until either the result set is exhausted,
  ``MAX_RESULTS`` (5000) is reached, or ``MAX_PAGES``
  (100) is hit.

Env vars:
  ``SEKOIA_HOST`` (optional) — defaults to
  ``https://api.sekoia.io`` (the canonical Sekoia.io
  REST host).  Settable to a regional / on-prem
  Sekoia.io mirror.  Whitespace is trimmed and
  ``https://`` is added when the operator pasted in
  a bare FQDN.

  ``SEKOIA_TOKEN`` (mandatory) — the Bearer token
  issued by Sekoia.io at API-key creation time.  The
  executor exits cleanly when missing.

Each alert / observable becomes one Faraday
vulnerability under a single synthetic ``0.0.0.0``
host with hostname ``sekoia-defend`` (Sekoia.io
records are tenant-keyed not host-keyed — the
operator's other agents emit the host-side findings
this feed is correlated against), tagged exactly
``[sekoia-defend]`` per the playbook spec, with a
``[Sekoia][Alert]`` / ``[Sekoia][IOC]`` engine
prefix on the name (so operators can filter the two
streams independently in the Faraday UI), the
canonical Sekoia record id in ``external_id``
(``alert::<id>`` / ``ioc::<id>`` so records with the
same id under different streams don't collide), and
the canonical metadata surfaced in both the
description and the refs list.

Severity for alerts is bucketed from the published
``urgency`` 0..100 score via ``severity_from_urgency()``:
``>=80 -> critical`` / ``>=60 -> high`` / ``>=40 ->
medium`` / ``>=20 -> low`` / ``<20 -> info``.
Severity for observables is bucketed from
``confidence`` via the same ladder.  Records in the
terminal ``Closed`` / ``Rejected`` / ``Mitigated``
states are floored to ``info`` regardless of the
published bucket (the case is no longer live).

Status is always ``open`` (a Sekoia record can be
closed in the console but the underlying SOC alert /
CTI observable lives on; Faraday surfaces the
finding as open so the operator's remediation
workflow takes over — the Sekoia state is preserved
via the info-severity floor + an explicit
``Sekoia-Status`` pivot in the refs).

Resolution variants: closed alerts -> "Sekoia has
marked this alert as {status}; verify the
remediation is reflected on the affected asset
before closing the Faraday finding."; live alerts ->
"Triage in the Sekoia.io console and apply the
analyst-recommended remediation per the detection
rule playbook."; IOCs -> type-appropriate blocking
recommendation (hashes -> EDR / AV; IPs ->
firewall + egress proxy + EDR containment; URLs ->
egress proxy + endpoint web-filter; domains -> DNS
sinkhole + perimeter blocklist).

Refs include the canonical Sekoia.io console deep-
link (``https://app.sekoia.io/operations/alerts/
<short_id>`` for alerts, ``/intelligence/objects/
<id>`` for observables), the canonical NVD CVE
permalink for any CVE ids surfaced in the title /
description / rule name / labels, and explicit
``Sekoia-AlertID`` / ``Sekoia-IocID`` / ``Sekoia-
Title`` / ``Sekoia-Urgency`` / ``Sekoia-Confidence``
/ ``Sekoia-Status`` / ``Sekoia-Rule`` / ``Sekoia-
Type`` / ``Sekoia-Asset`` / ``Sekoia-Entity`` /
``Sekoia-IntakeUUID`` / ``Sekoia-KillChain`` /
``Sekoia-Label`` / ``Sekoia-CVE`` / ``Sekoia-
ValidFrom`` / ``Sekoia-ValidUntil`` / ``Sekoia-
CreatedAt`` / ``Sekoia-UpdatedAt`` / ``Sekoia-
FirstSeen`` / ``Sekoia-LastSeen`` pivots so
operators can pivot from a Faraday finding back to
the exact Sekoia record.
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

DEFAULT_HOST = "https://api.sekoia.io"
ALERTS_PATH = "/v1/sic/alerts"
OBSERVABLES_PATH = "/v1/iocs/observables"

DEFAULT_LIMIT = 100
MIN_LIMIT = 1
MAX_LIMIT = 100
MAX_PAGES = 100
MAX_RESULTS = 5000
INTER_REQUEST_SLEEP = 0.4

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Sekoia.io closed alert statuses — alerts in these
# terminal states are floored to ``info`` regardless of
# the published urgency ladder (the case is no longer
# live).
CLOSED_STATUSES = {
    "closed",
    "rejected",
    "mitigated",
    "resolved",
    "false_positive",
    "false-positive",
    "falsepositive",
    "fp",
}

# Sekoia.io IOC type vocabulary — used by
# resolution_for_record to pick a type-appropriate
# blocking recommendation.
IP_TYPES = {"ipv4-addr", "ipv6-addr", "ip", "ipv4", "ipv6"}
URL_TYPES = {"url", "uri"}
DOMAIN_TYPES = {"domain-name", "domain", "fqdn", "hostname"}
HASH_TYPES = {
    "file:hashes.md5",
    "file:hashes.sha-1",
    "file:hashes.sha-256",
    "file:hashes.sha-512",
    "md5",
    "sha1",
    "sha256",
    "sha512",
}
EMAIL_TYPES = {"email-addr", "email-address", "email"}


def log(msg):
    print(f"{datetime.utcnow()} - SekoiaDefend: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on SEKOIA_HOST.

    Defaults to ``https://api.sekoia.io`` (the canonical
    Sekoia.io REST host) when the env override is missing /
    blank / non-string.  Whitespace is trimmed and
    ``https://`` is added automatically when the operator
    pasted in a bare FQDN.
    """
    if not host:
        return DEFAULT_HOST
    if not isinstance(host, str):
        return DEFAULT_HOST
    text = host.strip().rstrip("/")
    if not text:
        return DEFAULT_HOST
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def normalize_filter(value):
    """Coerce SEKOIA_FILTER into a stripped string (or '').

    Sekoia.io's filter DSL is forwarded server-side via
    the ``filter=`` query parameter on both endpoints; an
    empty filter is the canonical "match every record"
    operational mode.  ``None`` / bool / non-string inputs
    return ``""`` (no filter).
    """
    if value is None or isinstance(value, bool):
        return ""
    if not isinstance(value, str):
        return ""
    return value.strip()


def validate_limit(value):
    """Coerce SEKOIA_LIMIT into a clamped integer.

    Defaults to ``DEFAULT_LIMIT`` (100) when missing /
    blank / unparseable.  Values < ``MIN_LIMIT`` (1) are
    floored to 1; values > ``MAX_LIMIT`` (100) are capped
    at Sekoia.io's documented per-page ceiling.  Booleans
    are rejected (Python booleans are ints but coercing
    ``True`` -> 1 silently masks a manifest mis-binding).
    """
    if value is None or isinstance(value, bool):
        return DEFAULT_LIMIT
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return DEFAULT_LIMIT
        try:
            n = int(text)
        except ValueError:
            try:
                n = int(float(text))
            except ValueError:
                return DEFAULT_LIMIT
    else:
        try:
            n = int(value)
        except (TypeError, ValueError):
            return DEFAULT_LIMIT
    if n < MIN_LIMIT:
        return MIN_LIMIT
    if n > MAX_LIMIT:
        return MAX_LIMIT
    return n


def build_url(host, path, limit=DEFAULT_LIMIT, offset=0, filter_expr=""):
    """Build a paginated Sekoia.io URL with optional filter.

    Both endpoints share the same query-string shape:
    ``?limit=N&offset=N[&filter=<...>]``.  Bad inputs are
    coerced to safe defaults so a typo never crashes the
    dispatcher.
    """
    base = normalize_base_url(host)
    try:
        lim = int(limit)
    except (TypeError, ValueError):
        lim = DEFAULT_LIMIT
    if lim < MIN_LIMIT:
        lim = MIN_LIMIT
    if lim > MAX_LIMIT:
        lim = MAX_LIMIT
    try:
        off = int(offset)
    except (TypeError, ValueError):
        off = 0
    if off < 0:
        off = 0
    params = [("limit", lim), ("offset", off)]
    if isinstance(filter_expr, str):
        text = filter_expr.strip()
        if text:
            params.append(("filter", text))
    return f"{base}{path}?{urlencode(params)}"


def build_alerts_url(host, limit=DEFAULT_LIMIT, offset=0, filter_expr=""):
    """Build the /v1/sic/alerts URL."""
    return build_url(host, ALERTS_PATH, limit=limit, offset=offset, filter_expr=filter_expr)


def build_observables_url(host, limit=DEFAULT_LIMIT, offset=0, filter_expr=""):
    """Build the /v1/iocs/observables URL."""
    return build_url(host, OBSERVABLES_PATH, limit=limit, offset=offset, filter_expr=filter_expr)


def request_headers(token):
    """Build the request-header dict for one Sekoia.io GET.

    Sekoia.io uses Bearer-token auth; ``Accept:
    application/json`` is always sent.  Missing / blank
    tokens are coerced to an empty string and the
    ``Authorization`` header is omitted entirely (so a
    misconfigured token surfaces as an explicit 401 from
    the server rather than as an empty-header request
    that some Sekoia middleware silently rejects).
    """
    token_str = ""
    if isinstance(token, str):
        token_str = token.strip()
    elif token not in (None, False, True):
        token_str = str(token).strip()
    headers = {"Accept": "application/json"}
    if token_str:
        headers["Authorization"] = f"Bearer {token_str}"
    return headers


def parse_iso_datetime(value):
    """Parse an ISO-8601 timestamp into a UTC datetime."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
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


def extract_items(body):
    """Pull the record list from a Sekoia.io envelope.

    Canonical envelope is ``{"items": [...], "total": N}``.
    Federated / mirror stacks also expose bare-list +
    ``{"data": [...]}`` / ``{"results": [...]}`` /
    ``{"alerts": [...]}`` / ``{"observables": [...]}``
    shapes — all are tolerated.  Non-dict entries are
    dropped.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("items", "data", "results", "alerts", "observables"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_envelope_meta(body):
    """Pull pagination + status metadata from a Sekoia.io envelope.

    Returns ``{"total": int|None}`` with missing fields
    left as ``None``.  ``total`` is the canonical record
    counter; we use it both for pagination-stop logic
    and as a provenance breadcrumb in the synthetic-
    host description.
    """
    out = {"total": None}
    if not isinstance(body, dict):
        return out
    v = body.get("total")
    if v is None or isinstance(v, bool):
        return out
    try:
        out["total"] = int(v)
    except (TypeError, ValueError):
        out["total"] = None
    return out


def extract_record_id(record):
    """Pull the canonical Sekoia record id."""
    if not isinstance(record, dict):
        return ""
    for key in ("uuid", "id", "short_id", "_id"):
        v = record.get(key)
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, str):
            text = v.strip()
            if text:
                return text
        else:
            return str(v)
    return ""


def extract_short_id(record):
    """Pull the Sekoia short id (used for web-UI deep-links)."""
    if not isinstance(record, dict):
        return ""
    for key in ("short_id", "shortId"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_title(record):
    """Pull the alert / observable display title."""
    if not isinstance(record, dict):
        return ""
    for key in ("title", "name", "value"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_description(record):
    """Pull the free-text analyst description."""
    if not isinstance(record, dict):
        return ""
    for key in ("description", "details", "summary"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def parse_score(value):
    """Parse a Sekoia 0..100 numeric score into a float.

    Sekoia emits ``urgency`` / ``confidence`` as either a
    float / int (``75``) or a string (``"75"``).  Returns
    ``None`` for missing / non-numeric / bool inputs.
    Negative values are clamped to 0.0; values above 100
    are clamped to 100.0.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, dict):
        # Sekoia sometimes wraps numeric scores under
        # ``{"value": N}`` (e.g. urgency.value).
        v = value.get("value")
        if v is None or isinstance(v, bool):
            return None
        try:
            score = float(v)
        except (TypeError, ValueError):
            return None
    else:
        try:
            score = float(str(value).strip())
        except (TypeError, ValueError):
            return None
    if score != score:  # NaN check
        return None
    if score < 0:
        return 0.0
    if score > 100:
        return 100.0
    return score


def extract_urgency(record):
    """Pull the alert urgency 0..100 score (or None)."""
    if not isinstance(record, dict):
        return None
    for key in ("urgency", "priority", "score"):
        v = record.get(key)
        score = parse_score(v)
        if score is not None:
            return score
    return None


def extract_confidence(record):
    """Pull the observable confidence 0..100 score (or None)."""
    if not isinstance(record, dict):
        return None
    v = record.get("confidence")
    return parse_score(v)


def extract_status(record):
    """Pull the alert status string.

    Sekoia.io alerts carry ``status`` as either a bare
    string or a nested ``{"name": "Open"|"Closed"|...}``
    dict.  Returns ``''`` (not None) for missing /
    unknown inputs.
    """
    if not isinstance(record, dict):
        return ""
    v = record.get("status")
    if isinstance(v, dict):
        n = v.get("name")
        if isinstance(n, str) and n.strip():
            return n.strip()
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ""


def is_closed(record):
    """Return True when the record is in a closed / terminal state."""
    status = extract_status(record)
    if not status:
        return False
    return status.strip().lower().replace(" ", "_") in CLOSED_STATUSES


def extract_type(record):
    """Pull the observable type (or alert rule name)."""
    if not isinstance(record, dict):
        return ""
    for key in ("type", "alert_type", "kind"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_rule(record):
    """Pull the detection rule that fired (alerts only).

    Returns ``(rule_name, rule_uuid)`` strings, both
    possibly empty.
    """
    if not isinstance(record, dict):
        return "", ""
    rule = record.get("rule")
    name = ""
    uuid = ""
    if isinstance(rule, dict):
        n = rule.get("name")
        if isinstance(n, str) and n.strip():
            name = n.strip()
        u = rule.get("uuid") or rule.get("id")
        if isinstance(u, str) and u.strip():
            uuid = u.strip()
        elif u is not None and not isinstance(u, bool):
            uuid = str(u)
    elif isinstance(rule, str) and rule.strip():
        name = rule.strip()
    return name, uuid


def extract_assets(record):
    """Pull the operator-side assets the alert pivots on.

    Sekoia.io emits ``assets`` as a list of
    ``{"name": "...", "type": "..."}`` dicts; bare-string
    entries are surfaced too.  Returns a deduped list of
    ``{"type": str, "name": str}`` dicts.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    block = record.get("assets")
    if not isinstance(block, list):
        return out
    for entry in block:
        if isinstance(entry, dict):
            t_raw = entry.get("type")
            n_raw = entry.get("name") or entry.get("value")
            t = t_raw.strip() if isinstance(t_raw, str) else ""
            n = n_raw.strip() if isinstance(n_raw, str) else ""
            if not n:
                continue
            key = (t.lower(), n.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": t, "name": n})
        elif isinstance(entry, str) and entry.strip():
            n = entry.strip()
            key = ("", n.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": "", "name": n})
    return out


def extract_entity(record):
    """Pull the Sekoia entity name (tenant scope)."""
    if not isinstance(record, dict):
        return ""
    v = record.get("entity")
    if isinstance(v, dict):
        n = v.get("name")
        if isinstance(n, str) and n.strip():
            return n.strip()
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ""


def extract_labels(record):
    """Pull the analyst-applied label / tag list."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    for key in ("labels", "tags"):
        block = record.get(key)
        if not isinstance(block, list):
            continue
        for entry in block:
            text = None
            if isinstance(entry, dict):
                n = entry.get("name") or entry.get("value")
                if isinstance(n, str):
                    text = n.strip()
            elif isinstance(entry, str):
                text = entry.strip()
            if not text or text.lower() in seen:
                continue
            seen.add(text.lower())
            out.append(text)
    return out


def extract_kill_chain(record):
    """Pull the kill-chain id / phase (alerts only)."""
    if not isinstance(record, dict):
        return ""
    for key in ("kill_chain_short_id", "killChainShortId", "kill_chain"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_intake_uuid(record):
    """Pull the data-intake uuid the alert was raised against."""
    if not isinstance(record, dict):
        return ""
    for key in ("intake_uuid", "intakeUuid"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def severity_from_score(score):
    """Bucket a 0..100 Sekoia score onto Faraday's ladder."""
    if score is None:
        return "info"
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def severity_for_alert(record):
    """Final Faraday severity for one Sekoia alert.

    Buckets urgency onto Faraday's ladder; floors
    closed / rejected / mitigated alerts to ``info``
    regardless of the published urgency.  Defaults to
    ``info`` when the record carries no parseable
    urgency.
    """
    if not isinstance(record, dict):
        return "info"
    if is_closed(record):
        return "info"
    score = extract_urgency(record)
    return severity_from_score(score)


def severity_for_observable(record):
    """Final Faraday severity for one Sekoia observable.

    Buckets confidence onto Faraday's ladder.  Defaults
    to ``info`` when the record carries no parseable
    confidence — we don't synthesise a ranking Sekoia
    hasn't published.
    """
    if not isinstance(record, dict):
        return "info"
    score = extract_confidence(record)
    return severity_from_score(score)


def collect_cves(record):
    """Pull CVE ids from the title / description / rule / labels.

    Sekoia.io records do not carry a structured CVE
    field; analysts surface CVEs in the free-text title
    / description / rule name / labels.  Returns a
    deduped uppercase list preserving discovery order.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out

    def harvest(text):
        if not isinstance(text, str):
            return
        for match in CVE_RE.findall(text):
            cve = match.upper()
            if cve in seen:
                continue
            seen.add(cve)
            out.append(cve)

    harvest(extract_title(record))
    harvest(extract_description(record))
    rule_name, _ = extract_rule(record)
    harvest(rule_name)
    for label in extract_labels(record):
        harvest(label)
    # IOC value can carry a CVE id (e.g. analyst-tagged
    # CVE-referenced observable).
    v = record.get("value")
    if isinstance(v, str):
        harvest(v)
    return out


def web_link_for_alert(short_id):
    """Build the Sekoia.io console permalink for an alert."""
    sid = (short_id or "").strip() if isinstance(short_id, str) else ""
    if not sid:
        return "https://app.sekoia.io/operations/alerts"
    return f"https://app.sekoia.io/operations/alerts/{sid}"


def web_link_for_observable(observable_id):
    """Build the Sekoia.io console permalink for an observable."""
    oid = (observable_id or "").strip() if isinstance(observable_id, str) else ""
    if not oid:
        return "https://app.sekoia.io/intelligence/objects"
    return f"https://app.sekoia.io/intelligence/objects/{oid}"


def collect_alert_refs(record):
    """Build the refs list for one Sekoia alert.

    Includes the Sekoia.io portal deep-link, the
    canonical NVD CVE permalink for any CVE ids
    surfaced in the title / description / rule name /
    labels, and explicit ``Sekoia-*`` pivots so
    operators can pivot from a Faraday finding back to
    the exact Sekoia record.
    """
    refs = []
    seen = set()

    def add(text, ref_type="other"):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": ref_type})

    if not isinstance(record, dict):
        return refs

    rid = extract_record_id(record)
    if rid:
        add(f"Sekoia-AlertID: {rid}")

    sid = extract_short_id(record)
    if sid:
        add(web_link_for_alert(sid))
        add(f"Sekoia-ShortID: {sid}")

    title = extract_title(record)
    if title:
        add(f"Sekoia-Title: {title}")

    urgency = extract_urgency(record)
    if urgency is not None:
        add(f"Sekoia-Urgency: {urgency}")

    status = extract_status(record)
    if status:
        add(f"Sekoia-Status: {status}")

    rule_name, rule_uuid = extract_rule(record)
    if rule_name:
        add(f"Sekoia-Rule: {rule_name}")
    if rule_uuid:
        add(f"Sekoia-RuleUUID: {rule_uuid}")

    for asset in extract_assets(record):
        atype = asset.get("type") or ""
        aname = asset.get("name") or ""
        if atype:
            add(f"Sekoia-Asset: {atype}: {aname}")
        else:
            add(f"Sekoia-Asset: {aname}")

    entity = extract_entity(record)
    if entity:
        add(f"Sekoia-Entity: {entity}")

    intake = extract_intake_uuid(record)
    if intake:
        add(f"Sekoia-IntakeUUID: {intake}")

    kc = extract_kill_chain(record)
    if kc:
        add(f"Sekoia-KillChain: {kc}")

    for label in extract_labels(record):
        add(f"Sekoia-Label: {label}")

    for cve in collect_cves(record):
        add(f"Sekoia-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    for key, label in (
        ("created_at", "CreatedAt"),
        ("updated_at", "UpdatedAt"),
        ("first_seen_at", "FirstSeen"),
        ("last_seen_at", "LastSeen"),
    ):
        dt = parse_iso_datetime(record.get(key))
        if dt is not None:
            add(f"Sekoia-{label}: {dt.isoformat()}")

    return refs


def collect_observable_refs(record):
    """Build the refs list for one Sekoia observable."""
    refs = []
    seen = set()

    def add(text, ref_type="other"):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": ref_type})

    if not isinstance(record, dict):
        return refs

    rid = extract_record_id(record)
    if rid:
        add(web_link_for_observable(rid))
        add(f"Sekoia-IocID: {rid}")

    value = extract_title(record)
    if value:
        add(f"Sekoia-Value: {value}")

    type_text = extract_type(record)
    if type_text:
        add(f"Sekoia-Type: {type_text}")

    confidence = extract_confidence(record)
    if confidence is not None:
        add(f"Sekoia-Confidence: {confidence}")

    for label in extract_labels(record):
        add(f"Sekoia-Label: {label}")

    for cve in collect_cves(record):
        add(f"Sekoia-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    for key, label in (
        ("valid_from", "ValidFrom"),
        ("valid_until", "ValidUntil"),
        ("created_at", "CreatedAt"),
        ("updated_at", "UpdatedAt"),
    ):
        dt = parse_iso_datetime(record.get(key))
        if dt is not None:
            add(f"Sekoia-{label}: {dt.isoformat()}")

    pattern = record.get("pattern")
    if isinstance(pattern, str) and pattern.strip():
        add(f"Sekoia-Pattern: {pattern.strip()}")

    return refs


def resolution_for_alert(record):
    """Per-alert analyst recommendation.

    Closed / rejected alerts surface a "verify the
    remediation is reflected" reminder.  Live alerts
    surface a "triage in the console" recommendation;
    when a detection rule name is attached, that rule
    is named explicitly so the operator knows which
    playbook to consult.
    """
    if not isinstance(record, dict):
        return "Triage in the Sekoia.io console and apply the " "analyst-recommended remediation."
    status = extract_status(record)
    if is_closed(record):
        return (
            f"Sekoia has marked this alert as {status}; verify the "
            "remediation is reflected on the affected asset before "
            "closing the Faraday finding."
        )
    rule_name, _ = extract_rule(record)
    if rule_name:
        return (
            f"Triage in the Sekoia.io console — investigate the "
            f"'{rule_name}' detection rule firing per the rule's "
            "documented playbook, contain the affected assets, "
            "and update the alert status from Open -> Acknowledged "
            "-> Closed once remediation is confirmed."
        )
    return (
        "Triage in the Sekoia.io console and apply the analyst-"
        "recommended remediation per the detection rule playbook."
    )


def resolution_for_observable(record):
    """Per-IOC analyst recommendation by type."""
    if not isinstance(record, dict):
        return "Block this indicator on the operator's perimeter " "controls per Sekoia.io analyst guidance."
    type_text = extract_type(record).lower()
    if type_text in IP_TYPES:
        return (
            "Block this IP on the operator's perimeter firewall, "
            "egress proxy, and EDR network containment policies."
        )
    if type_text in URL_TYPES:
        return "Block this URL on the operator's egress proxy and " "endpoint web-filter policy."
    if type_text in DOMAIN_TYPES:
        return "Sinkhole this domain on the operator's DNS resolver " "and add to the perimeter blocklist."
    if type_text in HASH_TYPES:
        return "Block this file hash in the operator's EDR / AV / " "endpoint prevention policy."
    if type_text in EMAIL_TYPES:
        return "Add this email address to the mail-server blocklist " "and tighten DMARC / quarantine policy."
    return "Block this indicator on the operator's perimeter controls " "per Sekoia.io analyst guidance."


def build_alert_vulnerability(record):
    """Build a Faraday vulnerability dict for one Sekoia alert."""
    if not isinstance(record, dict):
        return None

    title = extract_title(record)
    rid = extract_record_id(record)
    if not title and not rid:
        return None

    severity = severity_for_alert(record)
    urgency = extract_urgency(record)
    status = extract_status(record)
    rule_name, rule_uuid = extract_rule(record)

    name_parts = ["[Sekoia][Alert]"]
    if title:
        name_parts.append(title)
    elif rid:
        name_parts.append(f"alert-{rid}")
    if urgency is not None:
        name_parts.append(f"(urgency={urgency})")
    name = " ".join(name_parts)

    desc_parts = []
    if rid:
        desc_parts.append(f"alertID: {rid}")
    if title:
        desc_parts.append(f"title: {title}")
    if urgency is not None:
        desc_parts.append(f"urgency: {urgency}")
    if status:
        desc_parts.append(f"status: {status}")
    if rule_name:
        desc_parts.append(f"rule: {rule_name}")
    if rule_uuid:
        desc_parts.append(f"ruleUUID: {rule_uuid}")
    entity = extract_entity(record)
    if entity:
        desc_parts.append(f"entity: {entity}")
    intake = extract_intake_uuid(record)
    if intake:
        desc_parts.append(f"intakeUUID: {intake}")
    kc = extract_kill_chain(record)
    if kc:
        desc_parts.append(f"killChain: {kc}")
    assets = extract_assets(record)
    if assets:
        desc_parts.append("assets: " + ", ".join(f"{a.get('type') or 'Asset'}={a.get('name')}" for a in assets[:20]))
    labels = extract_labels(record)
    if labels:
        desc_parts.append(f"labels: {', '.join(labels[:20])}")
    for key, label in (
        ("created_at", "created_at"),
        ("updated_at", "updated_at"),
        ("first_seen_at", "first_seen_at"),
        ("last_seen_at", "last_seen_at"),
    ):
        dt = parse_iso_datetime(record.get(key))
        if dt is not None:
            desc_parts.append(f"{label}: {dt.isoformat()}")
    description = extract_description(record)
    if description:
        desc_parts.append(f"description: {description}")

    external_id = f"alert::{rid or title[:200]}"
    resolution = resolution_for_alert(record)
    cves = collect_cves(record)

    return {
        "name": str(name).strip()[:200] or "Sekoia alert",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_alert_refs(record),
        "cve": cves,
        "cvss3": {},
        "tags": ["sekoia-defend"],
    }


def build_observable_vulnerability(record):
    """Build a Faraday vulnerability dict for one Sekoia observable."""
    if not isinstance(record, dict):
        return None

    value = extract_title(record)
    rid = extract_record_id(record)
    type_text = extract_type(record)
    if not value and not rid:
        return None

    severity = severity_for_observable(record)
    confidence = extract_confidence(record)

    name_parts = ["[Sekoia][IOC]"]
    if type_text:
        name_parts.append(type_text)
    if value:
        name_parts.append(value)
    if confidence is not None:
        name_parts.append(f"(confidence={confidence})")
    name = " ".join(name_parts)

    desc_parts = []
    if rid:
        desc_parts.append(f"iocID: {rid}")
    if value:
        desc_parts.append(f"value: {value}")
    if type_text:
        desc_parts.append(f"type: {type_text}")
    if confidence is not None:
        desc_parts.append(f"confidence: {confidence}")
    labels = extract_labels(record)
    if labels:
        desc_parts.append(f"labels: {', '.join(labels[:20])}")
    for key, label in (
        ("valid_from", "valid_from"),
        ("valid_until", "valid_until"),
        ("created_at", "created_at"),
        ("updated_at", "updated_at"),
    ):
        dt = parse_iso_datetime(record.get(key))
        if dt is not None:
            desc_parts.append(f"{label}: {dt.isoformat()}")
    description = extract_description(record)
    if description:
        desc_parts.append(f"description: {description}")
    pattern = record.get("pattern")
    if isinstance(pattern, str) and pattern.strip():
        desc_parts.append(f"pattern: {pattern.strip()}")

    external_id = f"ioc::{rid or value[:200]}"
    resolution = resolution_for_observable(record)
    cves = collect_cves(record)

    return {
        "name": str(name).strip()[:200] or "Sekoia observable",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_observable_refs(record),
        "cve": cves,
        "cvss3": {},
        "tags": ["sekoia-defend"],
    }


def build_host(vulns, host, filter_expr, limit, alert_total, ioc_total):
    """Build the single synthetic host that carries every Sekoia vuln."""
    desc_parts = ["source=sekoia-defend"]
    base = normalize_base_url(host)
    desc_parts.append(f"host={base}")
    if filter_expr:
        desc_parts.append(f"filter={filter_expr}")
    desc_parts.append(f"limit={limit}")
    if alert_total is not None:
        desc_parts.append(f"alert_total={alert_total}")
    if ioc_total is not None:
        desc_parts.append(f"ioc_total={ioc_total}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["sekoia-defend"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url, headers):
    """GET a single Sekoia.io URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never
    raised upstream so a transient Sekoia outage doesn't
    crash the dispatcher.  Returns ``None`` on any
    failure; the caller is expected to treat that as
    "no records" and break the pagination loop.
    """
    try:
        resp = requests_module.get(url, timeout=TIMEOUT, headers=headers)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"Sekoia record not found at {url} (404)")
        return None
    if resp.status_code == 401 or resp.status_code == 403:
        log(f"Sekoia auth failed ({resp.status_code}) for {url}: " "check SEKOIA_TOKEN")
        return None
    if resp.status_code >= 400:
        log(f"Sekoia request failed ({resp.status_code}) for {url}: " f"{getattr(resp, 'text', '')[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"Sekoia response was not JSON ({url})")
        return None


def fetch_collection(
    requests_module,
    host,
    path,
    headers,
    filter_expr="",
    limit=DEFAULT_LIMIT,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    max_results=MAX_RESULTS,
):
    """Page through one Sekoia endpoint and return the records.

    Pagination walks ``offset`` / ``limit`` forward in
    page-sized batches.  We break when (1) the page comes
    back empty, (2) ``total`` is reached, (3)
    ``max_results`` is hit, or (4) ``max_pages`` is hit.
    ``sleep_fn`` is injectable to keep unit tests fast.
    """
    records = []
    last_meta = {"total": None}
    offset = 0
    page = 0
    while page < max_pages and len(records) < max_results:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        remaining = max_results - len(records)
        page_limit = min(limit, remaining)
        if page_limit <= 0:
            break
        url = build_url(
            host,
            path,
            limit=page_limit,
            offset=offset,
            filter_expr=filter_expr,
        )
        body = fetch_url(requests_module, url, headers)
        if body is None:
            break
        meta = extract_envelope_meta(body)
        if meta.get("total") is not None:
            last_meta = meta
        page_records = extract_items(body)
        if not page_records:
            break
        for entry in page_records:
            records.append(entry)
            if len(records) >= max_results:
                break
        offset += len(page_records)
        total = last_meta.get("total")
        if total is not None and offset >= total:
            break
        # Server returned fewer records than requested -> we're past the end.
        if len(page_records) < page_limit:
            break
        page += 1
    return records, last_meta


def main():
    started = time.time()

    filter_expr = normalize_filter(env("EXECUTOR_CONFIG_SEKOIA_FILTER"))
    limit = validate_limit(env("EXECUTOR_CONFIG_SEKOIA_LIMIT"))
    host = env("SEKOIA_HOST", default=DEFAULT_HOST)
    token = env("SEKOIA_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = request_headers(token)

    alerts, alert_meta = fetch_collection(
        requests,
        host,
        ALERTS_PATH,
        headers,
        filter_expr=filter_expr,
        limit=limit,
    )
    observables, ioc_meta = fetch_collection(
        requests,
        host,
        OBSERVABLES_PATH,
        headers,
        filter_expr=filter_expr,
        limit=limit,
    )

    vulns = []
    for entry in alerts:
        vuln = build_alert_vulnerability(entry)
        if vuln is not None:
            vulns.append(vuln)
    for entry in observables:
        vuln = build_observable_vulnerability(entry)
        if vuln is not None:
            vulns.append(vuln)

    alert_total = alert_meta.get("total") if isinstance(alert_meta, dict) else None
    ioc_total = ioc_meta.get("total") if isinstance(ioc_meta, dict) else None
    log(
        f"Processed {len(vulns)} Sekoia records "
        f"(alerts={len(alerts)}, observables={len(observables)}, "
        f"alert_total={alert_total if alert_total is not None else '?'}, "
        f"ioc_total={ioc_total if ioc_total is not None else '?'}, "
        f"filter={filter_expr or 'none'}, limit={limit})"
    )

    hosts_out = [build_host(vulns, host, filter_expr, limit, alert_total, ioc_total)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "sekoia_defend",
            "command": "sekoia_defend",
            "params": f"filter={filter_expr or ''} limit={limit}",
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
