#!/usr/bin/env python
"""Recorded Future Vulnerability Intelligence importer.

Pulls CVE records from the canonical Recorded Future v2 REST
surface (``https://api.recordedfuture.com/v2/vulnerability/...``)
and emits Faraday bulk-create JSON to stdout.  The executor
exposes two mutually-exclusive operational modes via its manifest
args:

  * ``RF_CVE_LIST`` (CSV of CVE ids) — fetch each listed CVE in
    turn using the ``/v2/vulnerability/{cveId}`` lookup endpoint.
    One HTTP GET per CVE.  Malformed entries are dropped with a
    warning so a single typo doesn't abort the run.

  * (no ``RF_CVE_LIST``) — fall back to the search endpoint
    ``/v2/vulnerability/search`` which returns the most-recently
    surfaced vulnerabilities in the Recorded Future analyst graph.
    Paged 100 records at a time via ``from`` / ``limit`` until the
    full result set is walked (capped at ``MAX_SEARCH_PAGES``
    against runaway upstream).  When ``RF_MIN_RISK_SCORE`` is
    set, it is also forwarded server-side as the documented
    ``riskScore_gte`` filter so we don't pay for records that
    will be dropped client-side.

When both args are supplied ``RF_CVE_LIST`` wins (the per-CVE
mode is the narrower, more deterministic projection) and
``RF_MIN_RISK_SCORE`` is still applied client-side to the lookup
results.

Endpoints used:
  GET {RF_HOST}/v2/vulnerability/{cveId}
      -> Single-CVE lookup.  Returns the canonical RF envelope
      ``{"data": {"entity": {"id": "...", "name": "CVE-...",
      "type": "CyberVulnerability"}, "risk": {"score": 0..99,
      "level": 1..5, "riskString": "X/64",
      "criticalityLabel": "Very Malicious" | "Malicious" |
      "Suspicious" | "Unusual" | "No current evidence",
      "evidenceDetails": [{"rule": "...",
      "criticality": 1..5, "criticalityLabel": "...",
      "evidenceString": "...", "timestamp": "...",
      "mitigationString": "..."}, ...]}, "intelCard": "...",
      "commonNames": [...], "cpe": [...], "cpe22uri": [...],
      "cvss": {"accessComplexity": "...", "accessVector": "...",
      "availability": "...", "confidentiality": "...",
      "integrity": "...", "authentication": "...",
      "lastModified": "...", "published": "...",
      "score": 0..10}, "cvssv3": {"attackComplexity": "...",
      "attackVector": "...", "baseScore": 0..10,
      "baseSeverity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "vectorString": "..."}, "nvdDescription": "...",
      "description": "...", "timestamps":
      {"firstSeen": "...", "lastSeen": "...",
      "published": "...", "lastModified": "..."},
      "threatLists": [{"id": "...", "name": "...",
      "description": "...", "type": "..."}, ...],
      "lifecycleStages": [...], "relatedEntities":
      [{"type": "RelatedMalware", "entities": [...]}, ...],
      "references": [{"url": "...", "source": "...",
      "fragment": "..."}, ...]}}``.

  GET {RF_HOST}/v2/vulnerability/search?from=N&limit=N
       &riskScore_gte=N&fields=entity,risk,...
      -> Search.  Same envelope shape under
      ``{"data": {"results": [...], "counts": {...}}}``.

Auth: ``RF_TOKEN`` is mandatory and is sent as an ``X-RFToken``
HTTP header on every request — Recorded Future is a commercial
product, the v2 API is not anonymously accessible, and the
executor exits cleanly when the token is missing.  ``RF_HOST``
may optionally be overridden via env to point at a federated
mirror or an offline cache; defaults to
``https://api.recordedfuture.com``.

Severity is bucketed from the Recorded Future ``risk.score``
(0..99 — RF's proprietary risk scale where higher = more
malicious).  The explicit ``criticalityLabel`` text wins when
present; otherwise we fall back to a numeric bucket:
  * score >= 90 -> critical  (Very Malicious)
  * score >= 65 -> high      (Malicious)
  * score >= 25 -> medium    (Suspicious)
  * score >= 5  -> low       (Unusual)
  * score == 0  -> info      (No current evidence)

When the RF record carries no score at all (typical for very
recent CVEs RF has not yet analysed) severity defaults to
``info`` — we don't synthesise a ranking RF hasn't published.

Each CVE becomes one Faraday vulnerability under a single
synthetic ``0.0.0.0`` host with hostname ``recorded-future``.
RF entries are CVE-keyed not host-keyed — the operator's other
agents emit the host-side findings this feed is correlated
against.  The vulnerability carries ``tags: ['recorded-future']``
and surfaces the risk score, level, evidence rules, CVSS, IntelCard
URL, threat lists, and reference URLs in both the description and
the refs list so the operator can pivot from a Faraday finding
back to the canonical RF IntelCard.
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
DEFAULT_HOST = "https://api.recordedfuture.com"
CVE_PATH = "/v2/vulnerability"
SEARCH_PATH = "/v2/vulnerability/search"

# Recorded Future documents a 60 req/min throughput limit on
# the analyst-tier vulnerability endpoint — 1.1s between requests
# leaves us comfortably under the ceiling without burning more
# than ~1 second of wall-clock per per-CVE lookup.
INTER_REQUEST_SLEEP = 1.1

# Search endpoint paging — RF documents a 100 record / page
# ceiling; capped at MAX_SEARCH_PAGES against runaway upstreams.
SEARCH_PAGE_LIMIT = 100
MAX_SEARCH_PAGES = 200

# Default fields returned by the search endpoint.  Explicitly
# requested via the ``fields`` query string so the response shape
# is stable across RF subscription tiers (different tiers default
# to different field sets).
SEARCH_FIELDS = "entity,risk,intelCard,timestamps,cvss,cvssv3,commonNames,nvdDescription,threatLists,references"

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Recorded Future criticality labels -> Faraday severity.  RF
# publishes its own English-language label alongside every risk
# score; mapping the label keeps Faraday severity stable even if
# RF tweaks its numeric thresholds.
RF_LEVEL_LABEL_MAP = {
    "VERY MALICIOUS": "critical",
    "MALICIOUS": "high",
    "SUSPICIOUS": "medium",
    "UNUSUAL": "low",
    "NO CURRENT EVIDENCE": "info",
}


def log(msg):
    print(f"{datetime.utcnow()} - RecordedFuture: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on RF_HOST.

    Defaults to ``https://api.recordedfuture.com`` (the canonical
    Recorded Future REST host) when the env override is missing /
    blank.  Whitespace is trimmed and ``https://`` is added
    automatically when the operator pasted in a bare FQDN
    (federated / on-prem proxies typically use raw hostnames).
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


def parse_csv(value):
    """Parse a CSV string into a deduped, case-insensitive list.

    Whitespace is trimmed around every entry.  Empty / non-string
    inputs yield an empty list.  Order is preserved so a manifest
    arg like ``CVE-2024-1, CVE-2023-2, CVE-2024-1`` walks the
    listed CVEs in the operator's preferred order with the
    duplicate dropped.
    """
    if value is None:
        return []
    if not isinstance(value, str):
        return []
    out = []
    seen = set()
    for chunk in value.split(","):
        s = chunk.strip()
        if not s:
            continue
        key = s.upper()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def validate_cve_list(value):
    """Normalise RF_CVE_LIST into a list of well-formed CVE ids.

    Each entry is upper-cased and matched against ``CVE-YYYY-N+``;
    malformed entries are dropped with a warning so a single typo
    doesn't abort the run.  Returns an empty list when the CSV is
    empty / missing / unparseable.
    """
    parsed = parse_csv(value)
    out = []
    seen = set()
    for cve in parsed:
        upper = cve.upper()
        if not CVE_ID_RE.match(upper):
            log(f"RF_CVE_LIST entry {cve!r} is not a valid CVE id; skipping")
            continue
        if upper in seen:
            continue
        seen.add(upper)
        out.append(upper)
    return out


def validate_min_risk_score(value):
    """Coerce RF_MIN_RISK_SCORE into a 0..99 integer or None.

    None / blank / unparseable -> ``None`` (no filtering — every
    record returned by RF passes through).  Values below 0 are
    clamped to 0; values above the RF-documented 99 ceiling are
    clamped to 99.  Booleans are rejected (Python coerces
    ``True``/``False`` to 1/0 silently otherwise).
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        log(f"RF_MIN_RISK_SCORE {value!r} is a bool; ignoring (no filter)")
        return None
    try:
        score = int(str(value).strip())
    except (TypeError, ValueError):
        try:
            score = int(float(str(value).strip()))
        except (TypeError, ValueError):
            log(f"RF_MIN_RISK_SCORE {value!r} is not an integer; " "ignoring (no filter)")
            return None
    if score < 0:
        log(f"RF_MIN_RISK_SCORE {score} below 0; clamping to 0")
        return 0
    if score > 99:
        log(f"RF_MIN_RISK_SCORE {score} above 99; clamping to 99")
        return 99
    return score


def build_cve_url(host, cve_id):
    """Build the single-CVE lookup URL for Recorded Future.

    The path-segment CVE id is upper-cased per RF's documented
    canonical form (the API itself is case-insensitive but we
    canonicalise to keep audit logs consistent).
    """
    cve = str(cve_id).strip().upper()
    return f"{normalize_base_url(host)}{CVE_PATH}/{cve}"


def build_search_url(host, from_index=0, limit=SEARCH_PAGE_LIMIT, min_risk_score=None, fields=SEARCH_FIELDS):
    """Build a search query URL for Recorded Future.

    Includes pagination via ``from`` / ``limit`` so callers can
    walk multi-page result sets without rebuilding the query
    each iteration.  ``riskScore_gte`` is forwarded server-side
    when set so we don't pay for records that will be dropped
    client-side.
    """
    params = [
        ("from", int(from_index)),
        ("limit", int(limit)),
    ]
    if min_risk_score is not None:
        try:
            params.append(("riskScore_gte", int(min_risk_score)))
        except (TypeError, ValueError):
            pass
    if isinstance(fields, str) and fields.strip():
        params.append(("fields", fields.strip()))
    return f"{normalize_base_url(host)}{SEARCH_PATH}?{urlencode(params)}"


def request_headers(token):
    """Build the headers dict for a single RF GET.

    ``Accept: application/json`` is always sent.  ``X-RFToken``
    is included with the operator-supplied ``RF_TOKEN`` (the v2
    API rejects unauthenticated requests with HTTP 401).
    """
    headers = {"Accept": "application/json"}
    if isinstance(token, str) and token.strip():
        headers["X-RFToken"] = token.strip()
    return headers


def parse_iso_datetime(value):
    """Parse an ISO 8601 timestamp into a UTC-aware datetime.

    Returns ``None`` on non-string / unparseable / bool inputs.
    RF emits both ``...Z`` and ``...+00:00`` offset shapes across
    the ``timestamps`` block so we tolerate both.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    text = str(value).strip()
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


def extract_data(body):
    """Unwrap the canonical RF ``data`` envelope.

    RF wraps every response under a top-level ``data`` key.  We
    also accept pre-unwrapped dicts and bare-list / ``results`` /
    ``items`` envelopes for federated / mirror stacks.
    """
    if isinstance(body, dict):
        d = body.get("data")
        if isinstance(d, dict):
            return d
        if isinstance(d, list):
            return {"results": [entry for entry in d if isinstance(entry, dict)]}
        return body
    if isinstance(body, list):
        return {"results": [entry for entry in body if isinstance(entry, dict)]}
    return {}


def extract_search_results(body):
    """Pull the ``results`` list from a search-endpoint envelope."""
    data = extract_data(body)
    if not isinstance(data, dict):
        return []
    for key in ("results", "data", "items"):
        v = data.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_search_counts(body):
    """Pull the response ``counts`` metadata for the search envelope.

    RF returns ``{"counts": {"returned": N, "total": N}}`` under
    ``data`` for paginated queries — used to know when to stop
    paging.  Returns ``{}`` when missing.
    """
    data = extract_data(body)
    if not isinstance(data, dict):
        return {}
    counts = data.get("counts")
    if not isinstance(counts, dict):
        return {}
    out = {}
    for key in ("returned", "total"):
        v = counts.get(key)
        if v in (None, ""):
            continue
        out[key] = v
    return out


def extract_lookup_record(body):
    """Pull the single CVE record from a /v2/vulnerability/{cve} envelope.

    RF returns the CVE record directly under ``data`` (no wrapper
    list).  Pre-unwrapped payloads from federated mirrors are
    accepted as-is.  Returns ``None`` when the response body is
    not parseable as a CVE record dict.
    """
    data = extract_data(body)
    if isinstance(data, dict) and ("entity" in data or "risk" in data or "intelCard" in data):
        return data
    return None


def extract_cve_id(record):
    """Pull the canonical CVE id from an RF record.

    RF stores the CVE id under ``entity.name``; some federated
    mirrors / older subscription tiers surface it under ``cveId``
    or ``id`` so we walk those fallbacks too.
    """
    if not isinstance(record, dict):
        return ""
    entity = record.get("entity")
    if isinstance(entity, dict):
        name = entity.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip().upper()
        rid = entity.get("id")
        if isinstance(rid, str) and rid.strip().upper().startswith("CVE-"):
            return rid.strip().upper()
    for key in ("cveId", "cve_id", "id", "name"):
        v = record.get(key)
        if isinstance(v, str) and v.strip().upper().startswith("CVE-"):
            return v.strip().upper()
    return ""


def extract_description(record):
    """Return the NVD / RF analyst description for a CVE record.

    RF surfaces both an ``nvdDescription`` field (verbatim NVD
    text) and a ``description`` field (RF analyst summary).  We
    prefer the analyst summary when present (more current) and
    fall back to the NVD text.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("description", "nvdDescription"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_risk(record):
    """Pull the RF risk block as a normalised dict.

    Returns ``{"score": int|None, "level": int|None,
    "criticalityLabel": str, "riskString": str,
    "evidenceCount": int, "rules": [str]}`` with empty defaults
    for missing fields so the downstream severity / desc / refs
    builders can iterate uniformly.
    """
    out = {
        "score": None,
        "level": None,
        "criticalityLabel": "",
        "riskString": "",
        "evidenceCount": 0,
        "rules": [],
    }
    if not isinstance(record, dict):
        return out
    risk = record.get("risk")
    if not isinstance(risk, dict):
        return out
    score = risk.get("score")
    if score is not None:
        try:
            out["score"] = int(float(score))
        except (TypeError, ValueError):
            out["score"] = None
    level = risk.get("level")
    if level is not None:
        try:
            out["level"] = int(level)
        except (TypeError, ValueError):
            out["level"] = None
    label = risk.get("criticalityLabel")
    if isinstance(label, str) and label.strip():
        out["criticalityLabel"] = label.strip()
    rstring = risk.get("riskString")
    if isinstance(rstring, str) and rstring.strip():
        out["riskString"] = rstring.strip()
    evidence = risk.get("evidenceDetails")
    if isinstance(evidence, list):
        rules = []
        seen = set()
        for entry in evidence:
            if not isinstance(entry, dict):
                continue
            rule = entry.get("rule")
            if isinstance(rule, str) and rule.strip():
                text = rule.strip()
                if text in seen:
                    continue
                seen.add(text)
                rules.append(text)
        out["rules"] = rules
        out["evidenceCount"] = sum(1 for e in evidence if isinstance(e, dict))
    return out


def extract_cvss(record):
    """Pick the best-available CVSS metric block for a CVE.

    Prefers CVSSv3 over CVSSv2 (mirroring RF's own scoring
    ladder).  Returns a normalised dict with ``version``,
    ``baseScore``, ``baseSeverity`` (upper-cased when present)
    and ``vectorString``, or ``None`` when no scored block is
    attached.
    """
    if not isinstance(record, dict):
        return None
    cvssv3 = record.get("cvssv3")
    if isinstance(cvssv3, dict):
        score = cvssv3.get("baseScore")
        if score is not None:
            try:
                s = float(score)
            except (TypeError, ValueError):
                s = None
            if s is not None:
                sev_raw = cvssv3.get("baseSeverity")
                sev = sev_raw.strip().upper() if isinstance(sev_raw, str) else ""
                vector = cvssv3.get("vectorString") if isinstance(cvssv3.get("vectorString"), str) else ""
                return {
                    "version": "3",
                    "baseScore": s,
                    "baseSeverity": sev,
                    "vectorString": vector,
                }
    cvss = record.get("cvss")
    if isinstance(cvss, dict):
        score = cvss.get("score")
        if score is not None:
            try:
                s = float(score)
            except (TypeError, ValueError):
                s = None
            if s is not None:
                return {
                    "version": "2",
                    "baseScore": s,
                    "baseSeverity": "",
                    "vectorString": "",
                }
    return None


def extract_threat_lists(record):
    """Pull the list of RF threat-list names attached to a CVE.

    RF attaches every threat list the CVE appears in (e.g.
    "Actively Exploited In The Wild", "Recently Exploited In The
    Wild", "Vulnerability Linked to Ransomware").  Operators
    pivot off these names heavily — surface them in both the
    description and the refs list.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    lists = record.get("threatLists")
    if not isinstance(lists, list):
        return out
    for entry in lists:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        text = name.strip()
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def extract_references(record):
    """Pull RF's references list as ``{url, source}`` dicts."""
    out = []
    if not isinstance(record, dict):
        return out
    refs = record.get("references")
    if not isinstance(refs, list):
        return out
    for entry in refs:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        source = entry.get("source") if isinstance(entry.get("source"), str) else ""
        out.append({"url": url.strip(), "source": source.strip()})
    return out


def extract_common_names(record):
    """Pull commonNames (CVE aliases / vendor-published vuln names)."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    names = record.get("commonNames")
    if not isinstance(names, list):
        return out
    for n in names:
        if isinstance(n, str) and n.strip():
            text = n.strip()
            if text in seen:
                continue
            seen.add(text)
            out.append(text)
    return out


def extract_timestamps(record):
    """Pull the RF timestamps block as a string-only dict.

    RF surfaces ``firstSeen`` / ``lastSeen`` / ``published`` /
    ``lastModified`` under ``timestamps``.  Some fields may be
    missing for very recent CVEs — empty values are dropped.
    """
    out = {}
    if not isinstance(record, dict):
        return out
    ts = record.get("timestamps")
    if not isinstance(ts, dict):
        return out
    for key in ("firstSeen", "lastSeen", "published", "lastModified"):
        v = ts.get(key)
        if isinstance(v, str) and v.strip():
            out[key] = v.strip()
    return out


def severity_from_risk(risk):
    """Map an RF risk block to a Faraday severity bucket.

    Prefers the explicit ``criticalityLabel`` text when present
    (``Very Malicious`` / ``Malicious`` / ``Suspicious`` /
    ``Unusual`` / ``No current evidence``); falls back to
    numeric ``score`` bucketing otherwise.  Returns ``None``
    when the block is missing entirely so the caller can choose
    its own default (we surface unscored CVEs as ``info`` to
    avoid synthesising a ranking RF hasn't published).
    """
    if not isinstance(risk, dict):
        return None
    label = risk.get("criticalityLabel")
    if isinstance(label, str) and label.strip():
        mapped = RF_LEVEL_LABEL_MAP.get(label.strip().upper())
        if mapped:
            return mapped
    score = risk.get("score")
    if score is None:
        return None
    try:
        s = int(score)
    except (TypeError, ValueError):
        return None
    if s >= 90:
        return "critical"
    if s >= 65:
        return "high"
    if s >= 25:
        return "medium"
    if s >= 5:
        return "low"
    return "info"


def collect_cves(record):
    """Pull the canonical CVE id from an RF record.

    RF records are CVE-keyed (every entry has an ``entity.name``)
    so this is a single-element list under normal operation.  We
    still return a list for parity with the Faraday vulnerability
    schema's repeated-CVE shape.
    """
    out = []
    cve = extract_cve_id(record)
    if cve:
        out.append(cve)
    return out


def collect_refs(record):
    """Build the refs list for one RF CVE record.

    Includes the canonical NVD CVE permalink, the RF IntelCard
    URL, every advisory URL RF attached (with source vendor
    surfaced as a suffix), and explicit ``Rf-*`` pivots (CVE id,
    risk score / level / criticality label / rules, CVSS, threat
    lists, timestamps, common names) so operators can pivot from a
    Faraday finding back to the canonical RF IntelCard.
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

    cve = extract_cve_id(record)
    if cve:
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")
        add(f"Rf-CveID: {cve}")

    intel_card = record.get("intelCard")
    if isinstance(intel_card, str) and intel_card.strip():
        add(intel_card.strip())
        add(f"Rf-IntelCard: {intel_card.strip()}")

    risk = extract_risk(record)
    if risk["score"] is not None:
        add(f"Rf-RiskScore: {risk['score']}")
    if risk["level"] is not None:
        add(f"Rf-RiskLevel: {risk['level']}")
    if risk["criticalityLabel"]:
        add(f"Rf-Criticality: {risk['criticalityLabel']}")
    if risk["riskString"]:
        add(f"Rf-RiskString: {risk['riskString']}")
    for rule in risk["rules"]:
        add(f"Rf-Rule: {rule}")

    cvss = extract_cvss(record)
    if cvss is not None:
        add(f"Rf-CvssVersion: {cvss['version']}")
        add(f"Rf-CvssScore: {cvss['baseScore']}")
        if cvss.get("baseSeverity"):
            add(f"Rf-CvssSeverity: {cvss['baseSeverity']}")
        if cvss.get("vectorString"):
            add(f"Rf-CvssVector: {cvss['vectorString']}")

    for tl in extract_threat_lists(record):
        add(f"Rf-ThreatList: {tl}")

    for name in extract_common_names(record):
        add(f"Rf-CommonName: {name}")

    ts = extract_timestamps(record)
    for key in ("firstSeen", "lastSeen", "published", "lastModified"):
        v = ts.get(key)
        if v:
            add(f"Rf-{key[0].upper() + key[1:]}: {v}")

    for entry in extract_references(record):
        url = entry.get("url") or ""
        if not url:
            continue
        source = entry.get("source") or ""
        if source:
            add(f"{url} ({source})")
        else:
            add(url)

    return refs


def build_vulnerability(record, min_risk_score=None):
    """Build a Faraday vulnerability dict for one RF CVE record.

    Returns ``None`` when ``record`` is not parseable as a dict
    or when ``min_risk_score`` is set and the record's risk score
    is strictly below the threshold (or unscored — we cannot
    prove an unscored record meets the threshold).
    """
    if not isinstance(record, dict):
        return None

    risk = extract_risk(record)

    if min_risk_score is not None:
        score = risk.get("score")
        if score is None or score < min_risk_score:
            return None

    cve_id = extract_cve_id(record)
    description = extract_description(record)
    cvss = extract_cvss(record)
    intel_card = record.get("intelCard")
    intel_card = intel_card.strip() if isinstance(intel_card, str) else ""

    sev = severity_from_risk(risk)
    severity = sev if sev else "info"

    name_parts = []
    if cve_id:
        name_parts.append(cve_id)
    if risk["score"] is not None:
        name_parts.append(f"RF risk {risk['score']}")
    if risk["criticalityLabel"]:
        name_parts.append(risk["criticalityLabel"])
    summary = description.split(".")[0].strip() if description else ""
    if summary:
        name_parts.append(summary[:150])
    raw_name = ": ".join(name_parts) if name_parts else "Recorded Future vulnerability"
    name = f"[RF] {raw_name}"

    desc_parts = []
    if cve_id:
        desc_parts.append(f"cveID: {cve_id}")
    if risk["score"] is not None:
        desc_parts.append(f"riskScore: {risk['score']}")
    if risk["level"] is not None:
        desc_parts.append(f"riskLevel: {risk['level']}")
    if risk["criticalityLabel"]:
        desc_parts.append(f"criticalityLabel: {risk['criticalityLabel']}")
    if risk["riskString"]:
        desc_parts.append(f"riskString: {risk['riskString']}")
    if risk["evidenceCount"]:
        desc_parts.append(f"evidenceRules: {risk['evidenceCount']}")
    if risk["rules"]:
        desc_parts.append("rules: " + ", ".join(risk["rules"][:20]))
    if cvss is not None:
        desc_parts.append(
            f"cvss{cvss['version']}: baseScore={cvss['baseScore']} " f"severity={cvss['baseSeverity'] or 'n/a'}"
        )
        if cvss.get("vectorString"):
            desc_parts.append(f"cvssVector: {cvss['vectorString']}")
    threat_lists = extract_threat_lists(record)
    if threat_lists:
        desc_parts.append("threatLists: " + ", ".join(threat_lists))
    common_names = extract_common_names(record)
    if common_names:
        desc_parts.append("commonNames: " + ", ".join(common_names))
    ts = extract_timestamps(record)
    for key in ("firstSeen", "lastSeen", "published", "lastModified"):
        v = ts.get(key)
        if v:
            desc_parts.append(f"{key}: {v}")
    if intel_card:
        desc_parts.append(f"intelCard: {intel_card}")
    refs_inline = extract_references(record)
    if refs_inline:
        desc_parts.append(f"references: {len(refs_inline)}")
    if description:
        desc_parts.append(f"description: {description}")

    if risk["score"] is None and not risk["criticalityLabel"]:
        resolution = (
            f"Recorded Future has not yet scored {cve_id or 'this CVE'}; "
            "review the IntelCard once RF analysts publish a risk score."
        )
    else:
        resolution = (
            f"Prioritise patching {cve_id or 'this CVE'} per the RF risk score "
            f"and IntelCard guidance; cross-reference with the operator's asset "
            "inventory and the CISA KEV catalog before scheduling remediation."
        )

    external_id = cve_id or name[:200]

    return {
        "name": str(name).strip()[:200] or "Recorded Future vulnerability",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["recorded-future"],
    }


def build_host(vulns, mode_desc, search_counts):
    """Build the single synthetic host that carries every RF vuln.

    RF entries are CVE-keyed not host-keyed (the operator's
    other agents emit the host-side findings this feed is
    correlated against) so we collapse the whole feed under one
    synthetic ``0.0.0.0`` host with hostname ``recorded-future``.
    """
    desc_parts = ["source=recorded-future"]
    if mode_desc:
        desc_parts.append(mode_desc)
    if isinstance(search_counts, dict):
        for key in ("returned", "total"):
            v = search_counts.get(key)
            if v in (None, ""):
                continue
            desc_parts.append(f"{key}={v}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["recorded-future"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url, token):
    """GET a single RF URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient RF outage doesn't crash the
    dispatcher.  Returns ``None`` on any failure; the caller is
    expected to treat that as "no records" and continue.
    """
    try:
        resp = requests_module.get(
            url,
            timeout=TIMEOUT,
            headers=request_headers(token),
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"RF record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"RF request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"RF response was not JSON ({url})")
        return None


def fetch_cves(requests_module, host, cve_list, token, sleep_fn=time.sleep):
    """Walk RF_CVE_LIST and accumulate per-CVE records.

    Returns the list of unwrapped CVE records (one per successful
    lookup).  ``sleep_fn`` is injectable to keep unit tests fast.
    """
    records = []
    for idx, cve_id in enumerate(cve_list):
        if idx > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        url = build_cve_url(host, cve_id)
        body = fetch_url(requests_module, url, token)
        if body is None:
            continue
        record = extract_lookup_record(body)
        if record is None:
            continue
        records.append(record)
    return records


def fetch_search(requests_module, host, token, min_risk_score=None, sleep_fn=time.sleep, max_pages=MAX_SEARCH_PAGES):
    """Page through RF's vulnerability search endpoint.

    Returns ``(records, counts)`` where ``records`` is the
    accumulated CVE-record list and ``counts`` is the most-recent
    response's ``{"returned": N, "total": N}`` metadata (used for
    provenance on the synthetic host).
    """
    records = []
    counts = {}
    from_index = 0
    page = 0
    while page < max_pages:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        url = build_search_url(
            host,
            from_index=from_index,
            limit=SEARCH_PAGE_LIMIT,
            min_risk_score=min_risk_score,
        )
        body = fetch_url(requests_module, url, token)
        if body is None:
            break
        page_counts = extract_search_counts(body)
        if page_counts:
            counts = page_counts
        page_records = extract_search_results(body)
        if not page_records:
            break
        records.extend(page_records)
        from_index += SEARCH_PAGE_LIMIT
        total = counts.get("total")
        try:
            total_int = int(total)
        except (TypeError, ValueError):
            total_int = None
        if total_int is not None and from_index >= total_int:
            break
        page += 1
    return records, counts


def main():
    started = time.time()

    cve_list = validate_cve_list(env("EXECUTOR_CONFIG_RF_CVE_LIST"))
    min_risk_score = validate_min_risk_score(env("EXECUTOR_CONFIG_RF_MIN_RISK_SCORE"))
    host = env("RF_HOST", default=DEFAULT_HOST)
    token = env("RF_TOKEN", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    if cve_list:
        mode = "cves"
        mode_desc = f"cves={len(cve_list)}"
        records = fetch_cves(requests, host, cve_list, token)
        counts = {}
    else:
        mode = "search"
        mode_desc = "search"
        records, counts = fetch_search(requests, host, token, min_risk_score=min_risk_score)

    vulns = []
    for entry in records:
        vuln = build_vulnerability(entry, min_risk_score=min_risk_score)
        if vuln is not None:
            vulns.append(vuln)

    log(
        f"Processed {len(vulns)} RF records "
        f"(mode={mode}, min_risk_score="
        f"{min_risk_score if min_risk_score is not None else 'none'}, "
        f"total={counts.get('total', '?')})"
    )

    hosts_out = [build_host(vulns, mode_desc, counts)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "recorded_future",
            "command": "recorded_future",
            "params": (
                f"mode={mode} "
                f"cves={len(cve_list)} "
                f"min_risk_score="
                f"{min_risk_score if min_risk_score is not None else ''}"
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
