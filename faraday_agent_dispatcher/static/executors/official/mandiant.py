#!/usr/bin/env python
"""Mandiant Advantage Threat Intelligence importer.

Pulls vulnerability + indicator records from the canonical
Mandiant Advantage Threat Intelligence v4 REST surface
(``https://api.intelligence.mandiant.com/v4/...``) and emits
Faraday bulk-create JSON to stdout.  The executor exposes two
operational modes via its manifest args; both can be combined
in a single run when both lists are supplied:

  * ``MANDIANT_VULN_CVES`` (CSV of CVE ids) — fetch each listed
    CVE in turn via the ``/v4/vulnerability/{cve_id}`` lookup
    endpoint.  One HTTP GET per CVE.  Malformed entries are
    dropped with a warning so a single typo doesn't abort the run.

  * ``MANDIANT_INDICATOR_LIST`` (CSV of ``type:value`` pairs) —
    fetch each indicator in turn via the
    ``/v4/indicator/{type}/{value}`` lookup endpoint.  Supported
    indicator types are ``md5``, ``sha1``, ``sha256``, ``ip`` (alias
    for ``ipv4``), ``ipv4``, ``ipv6``, ``fqdn`` (alias for
    ``domain``), ``domain``, and ``url``.  Malformed entries are
    dropped with a warning.

Endpoints used:
  POST {MANDIANT_HOST}/token
      -> OAuth2 ``client_credentials`` token exchange.  Mandiant
      issues a short-lived (~1h) Bearer token; we cache it for
      the lifetime of a single executor invocation and re-send
      it as ``Authorization: Bearer ...`` on every subsequent
      request.  The credentials are sent as HTTP Basic
      (``key_id:key_secret``) with
      ``Content-Type: application/x-www-form-urlencoded`` and a
      ``grant_type=client_credentials`` body per RFC 6749.

  GET {MANDIANT_HOST}/v4/vulnerability/{cve_id}
      -> Single-CVE Mandiant Vulnerability Intelligence lookup.
      Returns the canonical Mandiant vulnerability envelope with
      ``id`` / ``cve_id`` / ``title`` / ``description`` /
      ``executive_summary`` / ``available_mitigation`` /
      ``risk_rating`` (LOW / MEDIUM / HIGH / CRITICAL) /
      ``exploitation_state`` (Available / Wild / No Known /
      Anticipated) / ``exploitation_consequence`` /
      ``cvss_base_score`` / ``cvss_temporal_score`` /
      ``cvssv3.base_score`` / ``cvssv3.base_severity`` /
      ``cvssv3.vector_string`` / ``vulnerable_products`` /
      ``vendor_fix_references`` / ``audit_publish_date`` /
      ``audit_update_date`` / ``was_zero_day`` /
      ``was_seen_in_the_wild`` / ``associated_threat_actors``
      / ``associated_malware`` / ``analysis`` / ``related_iocs``.

  GET {MANDIANT_HOST}/v4/indicator/{type}/{value}
      -> Single-indicator Mandiant Indicators-of-Compromise
      lookup.  Returns the canonical Mandiant indicator envelope
      with ``id`` / ``value`` / ``type`` / ``mscore`` (Mandiant
      Confidence Score 0..100 — higher = more malicious) /
      ``first_seen`` / ``last_seen`` / ``sources`` /
      ``attributed_associations`` (linked threat actors +
      malware families) / ``categories`` / ``misp`` /
      ``threat_rating`` / ``is_publishable`` /
      ``last_updated``.

  GET {MANDIANT_HOST}/v4/threat-actor/{actor_id}
      -> Threat-actor enrichment endpoint.  Used opportunistically
      to enrich each vuln / indicator with the names of associated
      actors when the vuln / indicator record carries
      ``associated_threat_actors`` / ``attributed_associations``
      entries that lack inline names.  Failure is non-fatal — the
      vuln / indicator is still emitted with the bare actor id.

Auth: ``MANDIANT_KEY_ID`` + ``MANDIANT_KEY_SECRET`` are both
mandatory env vars; the executor exits cleanly when either is
missing.  Credentials are issued via the Mandiant Advantage
developer portal.  ``MANDIANT_HOST`` may optionally be
overridden via env to point at a federated mirror or an offline
cache; defaults to ``https://api.intelligence.mandiant.com``.

Severity:
  * Vulnerabilities — the explicit ``risk_rating`` text (CRITICAL
    / HIGH / MEDIUM / LOW) wins when present; falls back to
    CVSSv3 ``base_severity`` text, then numeric ``base_score``
    bucketing (``>=9.0 critical / >=7.0 high / >=4.0 medium /
    >0.0 low / 0.0 info``).  Records flagged
    ``exploitation_state: "Wild"`` (active in-the-wild
    exploitation observed by Mandiant analysts) are bumped to
    ``critical`` regardless of the rating ladder — active
    exploitation overrides the calendar floor.  Unscored CVEs
    default to ``info``.

  * Indicators — the explicit Mandiant ``mscore`` (Mandiant
    Confidence Score, 0..100 where higher is more malicious) is
    bucketed via the canonical Mandiant rubric: ``>=80 critical
    / >=50 high / >=25 medium / >=10 low / <10 info``.  Unscored
    indicators default to ``info``.

Each Mandiant record becomes one Faraday vulnerability under a
single synthetic ``0.0.0.0`` host with hostname ``mandiant``.
Vulnerabilities + indicators are co-located under the same
synthetic host so a single Faraday workspace import covers the
full Mandiant feed in one shot.  Each Faraday vuln carries
``tags: ['mandiant']``; vuln entries additionally carry the
``[MANDIANT]`` engine prefix on the name and indicator entries
carry the ``[MANDIANT IOC]`` prefix so operators can filter the
two streams independently in the Faraday UI.  Refs include the
canonical NVD CVE permalink (for vuln entries), the Mandiant
Advantage detail-page permalink (the canonical pivot back into
the Mandiant analyst graph), and explicit ``Mandiant-*`` pivots
(CVE id, risk rating, exploitation state, CVSSv3, vulnerable
products, threat actors, malware families, mscore, indicator
type / value, first / last seen) so operators can pivot from a
Faraday finding back to the exact Mandiant Advantage payload.
"""

import json
import os
import re
import socket
import sys
import time
from base64 import b64encode
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

TIMEOUT = 60
DEFAULT_HOST = "https://api.intelligence.mandiant.com"
TOKEN_PATH = "/token"
VULN_PATH = "/v4/vulnerability"
INDICATOR_PATH = "/v4/indicator"
THREAT_ACTOR_PATH = "/v4/threat-actor"

# Mandiant Advantage documents ~5 req/s on the free-tier
# Vulnerability + Indicator endpoints — 0.3s between requests
# leaves us comfortably under the ceiling without burning more
# than ~0.3 second of wall-clock per per-CVE / per-indicator lookup.
INTER_REQUEST_SLEEP = 0.3

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Indicator-type aliases accepted in MANDIANT_INDICATOR_LIST.
# Keys are operator-facing prefixes; values are the canonical
# Mandiant indicator type segment used in the REST path.
INDICATOR_TYPE_ALIASES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "ip": "ipv4",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "fqdn": "fqdn",
    "domain": "fqdn",
    "url": "url",
}

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")

# Mandiant risk_rating text -> Faraday severity ladder.  The
# explicit rating wins over CVSS when both are present (Mandiant
# analysts adjust the rating against the in-the-wild exploitation
# context that the raw CVSS score doesn't capture).
MANDIANT_RISK_RATING_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
    "INFORMATIONAL": "info",
}


def log(msg):
    print(f"{datetime.utcnow()} - Mandiant: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on MANDIANT_HOST.

    Defaults to ``https://api.intelligence.mandiant.com`` (the
    canonical Mandiant Advantage REST host) when the env
    override is missing / blank.  Whitespace is trimmed and
    ``https://`` is added automatically when the operator pasted
    in a bare FQDN (federated / on-prem proxies typically use raw
    hostnames).
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
    """Parse a CSV string into a deduped, order-preserving list.

    Whitespace is trimmed around every entry.  Empty / non-string
    inputs yield an empty list.  Dedupe is case-insensitive against
    the trimmed entry so ``cve-2024-1, CVE-2024-1`` collapses to a
    single entry.
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
    """Normalise MANDIANT_VULN_CVES into a list of well-formed CVE ids.

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
            log(f"MANDIANT_VULN_CVES entry {cve!r} is not a valid CVE id; skipping")
            continue
        if upper in seen:
            continue
        seen.add(upper)
        out.append(upper)
    return out


def validate_indicator_list(value):
    """Normalise MANDIANT_INDICATOR_LIST into typed-indicator pairs.

    Operator-supplied entries are expected as ``type:value``;
    accepted types are ``md5``, ``sha1``, ``sha256``, ``ip`` (alias
    for ``ipv4``), ``ipv4``, ``ipv6``, ``fqdn`` (alias for
    ``domain``), ``domain``, ``url``.  Returns a list of
    ``{"type": canonical-type, "value": raw-value}`` dicts in the
    operator's preferred order with malformed / blank / duplicate
    entries dropped.  Dedupe is case-insensitive against the
    canonical-type plus raw-value pair.
    """
    parsed = parse_csv(value)
    out = []
    seen = set()
    for raw in parsed:
        # We split on the FIRST ':' only — URLs contain ':' inside
        # their scheme separator so over-eager splitting breaks them.
        if ":" not in raw:
            log(f"MANDIANT_INDICATOR_LIST entry {raw!r} missing 'type:' prefix; skipping")
            continue
        type_part, _, value_part = raw.partition(":")
        type_key = type_part.strip().lower()
        canonical = INDICATOR_TYPE_ALIASES.get(type_key)
        if canonical is None:
            log(f"MANDIANT_INDICATOR_LIST entry {raw!r} has unknown type " f"{type_part!r}; skipping")
            continue
        ind_value = value_part.strip()
        if not ind_value:
            log(f"MANDIANT_INDICATOR_LIST entry {raw!r} has empty value; skipping")
            continue
        key = (canonical, ind_value.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": canonical, "value": ind_value})
    return out


def build_token_url(host):
    """Build the OAuth2 token-exchange URL for Mandiant Advantage."""
    return f"{normalize_base_url(host)}{TOKEN_PATH}"


def build_vuln_url(host, cve_id):
    """Build the single-CVE Mandiant Vulnerability lookup URL.

    The path-segment CVE id is upper-cased per Mandiant's
    documented canonical form (the API itself is case-insensitive
    but we canonicalise to keep audit logs consistent).
    """
    cve = str(cve_id).strip().upper()
    return f"{normalize_base_url(host)}{VULN_PATH}/{cve}"


def build_indicator_url(host, ind_type, value):
    """Build the single-indicator Mandiant IOC lookup URL.

    URL-encodes the indicator value so URLs (which contain ``/``,
    ``?``, etc.) round-trip cleanly.
    """
    ind = INDICATOR_TYPE_ALIASES.get(str(ind_type).strip().lower(), str(ind_type).strip().lower())
    encoded = quote(str(value).strip(), safe="")
    return f"{normalize_base_url(host)}{INDICATOR_PATH}/{ind}/{encoded}"


def build_threat_actor_url(host, actor_id):
    """Build the threat-actor enrichment URL for Mandiant."""
    encoded = quote(str(actor_id).strip(), safe="")
    return f"{normalize_base_url(host)}{THREAT_ACTOR_PATH}/{encoded}"


def basic_auth_header(key_id, key_secret):
    """Build the HTTP Basic auth header for OAuth2 token exchange.

    Returns the canonical ``Basic <b64(key_id:key_secret)>`` string.
    Used inside ``fetch_token`` only; subsequent requests use the
    Bearer token returned by the token endpoint.
    """
    creds = f"{str(key_id or '').strip()}:{str(key_secret or '').strip()}"
    encoded = b64encode(creds.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def request_headers(token):
    """Build the headers dict for a single Mandiant GET.

    ``Accept: application/json`` is always sent.  ``X-App-Name``
    surfaces a stable client identifier so Mandiant's audit logs
    can attribute traffic to the Faraday agent.  ``Authorization:
    Bearer ...`` is included with the operator-supplied OAuth2
    token (every v4 endpoint requires it).
    """
    headers = {
        "Accept": "application/json",
        "X-App-Name": "faraday-agent-dispatcher",
    }
    if isinstance(token, str) and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    return headers


def parse_iso_datetime(value):
    """Parse an ISO 8601 timestamp into a UTC-aware datetime.

    Returns ``None`` on non-string / unparseable / bool inputs.
    Mandiant emits both ``...Z`` and ``...+00:00`` offset shapes
    across the ``audit_publish_date`` / ``first_seen`` blocks so
    we tolerate both.
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
    """Unwrap a Mandiant response envelope.

    Mandiant v4 returns the record directly at the top level for
    single-id lookups (no ``data`` wrapper), but some federated /
    mirror stacks wrap responses under ``data`` / ``result`` for
    parity with the v2 surface.  We accept either.
    """
    if isinstance(body, dict):
        for key in ("data", "result"):
            v = body.get(key)
            if isinstance(v, dict):
                return v
        return body
    return {}


def extract_vulnerability_record(body):
    """Pull the single vulnerability record from a Mandiant response.

    Mandiant returns the record at the envelope top-level with
    ``id`` / ``cve_id`` keys.  Pre-unwrapped / ``data``-wrapped
    payloads are accepted.  Returns ``None`` when the response
    body is not parseable as a vuln record.
    """
    data = extract_data(body)
    if not isinstance(data, dict):
        return None
    if "cve_id" in data or "id" in data or "title" in data or "risk_rating" in data:
        return data
    return None


def extract_indicator_record(body):
    """Pull the single indicator record from a Mandiant response.

    Mandiant returns the record at the envelope top-level with
    ``id`` / ``value`` / ``type`` keys.  Pre-unwrapped /
    ``data``-wrapped payloads are accepted.  Returns ``None`` when
    the response body is not parseable as an indicator record.
    """
    data = extract_data(body)
    if not isinstance(data, dict):
        return None
    if "value" in data or "id" in data or "mscore" in data or "type" in data:
        return data
    return None


def extract_cve_id(record):
    """Pull the canonical CVE id from a Mandiant vuln record.

    Mandiant stores the CVE id under ``cve_id``; some older /
    federated payloads use ``cveId`` / ``name`` / ``id``.
    """
    if not isinstance(record, dict):
        return ""
    for key in ("cve_id", "cveId", "cve"):
        v = record.get(key)
        if isinstance(v, str) and v.strip().upper().startswith("CVE-"):
            return v.strip().upper()
    for key in ("name", "id"):
        v = record.get(key)
        if isinstance(v, str) and v.strip().upper().startswith("CVE-"):
            return v.strip().upper()
    return ""


def extract_title(record):
    """Pull the human-readable vuln title from a Mandiant record."""
    if not isinstance(record, dict):
        return ""
    for key in ("title", "vulnerability_name"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_description(record):
    """Return the Mandiant analyst description for a vuln record.

    Prefers the long-form ``description`` then falls back to the
    ``executive_summary`` (shorter analyst snapshot) and finally
    ``analysis`` (Mandiant's free-text remediation guidance).
    """
    if not isinstance(record, dict):
        return ""
    for key in ("description", "executive_summary", "analysis"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def extract_cvss(record):
    """Pick the best-available CVSS metric block for a vuln.

    Mandiant publishes both v3 and v2 scores on a single record.
    We prefer CVSSv3 over CVSSv2 (mirroring NVD's own ladder).
    Returns a normalised dict with ``version`` / ``baseScore`` /
    ``baseSeverity`` (upper-cased when present) / ``vectorString``,
    or ``None`` when no scored block is attached.
    """
    if not isinstance(record, dict):
        return None
    cvssv3 = record.get("cvssv3")
    if isinstance(cvssv3, dict):
        score_raw = cvssv3.get("base_score")
        if score_raw is None:
            score_raw = cvssv3.get("baseScore")
        if score_raw is not None:
            try:
                s = float(score_raw)
            except (TypeError, ValueError):
                s = None
            if s is not None:
                sev_raw = cvssv3.get("base_severity") or cvssv3.get("baseSeverity")
                sev = sev_raw.strip().upper() if isinstance(sev_raw, str) else ""
                vec_raw = cvssv3.get("vector_string") or cvssv3.get("vectorString")
                vector = vec_raw.strip() if isinstance(vec_raw, str) else ""
                return {
                    "version": "3",
                    "baseScore": s,
                    "baseSeverity": sev,
                    "vectorString": vector,
                }
    cvss = record.get("cvss")
    if isinstance(cvss, dict):
        score_raw = cvss.get("base_score")
        if score_raw is None:
            score_raw = cvss.get("score")
        if score_raw is not None:
            try:
                s = float(score_raw)
            except (TypeError, ValueError):
                s = None
            if s is not None:
                vec_raw = cvss.get("vector_string") or cvss.get("vectorString")
                vector = vec_raw.strip() if isinstance(vec_raw, str) else ""
                return {
                    "version": "2",
                    "baseScore": s,
                    "baseSeverity": "",
                    "vectorString": vector,
                }
    flat = record.get("cvss_base_score")
    if flat is not None:
        try:
            s = float(flat)
        except (TypeError, ValueError):
            s = None
        if s is not None:
            return {
                "version": "?",
                "baseScore": s,
                "baseSeverity": "",
                "vectorString": "",
            }
    return None


def extract_exploitation_state(record):
    """Pull Mandiant's exploitation_state string (Wild / Available / ...).

    Returns the trimmed string or empty when missing.  Used to
    drive the in-the-wild severity bump in
    ``severity_from_vulnerability``.
    """
    if not isinstance(record, dict):
        return ""
    v = record.get("exploitation_state")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ""


def is_in_the_wild(record):
    """Return True when Mandiant has observed in-the-wild exploitation.

    Mandiant flags this via ``exploitation_state: "Wild"`` (the
    canonical signal) plus a redundant boolean
    ``was_seen_in_the_wild``.  We accept either.
    """
    if not isinstance(record, dict):
        return False
    state = extract_exploitation_state(record).lower()
    if state == "wild":
        return True
    seen = record.get("was_seen_in_the_wild")
    if isinstance(seen, bool) and seen:
        return True
    return False


def extract_vulnerable_products(record):
    """Pull the list of Mandiant 'vulnerable_products' as name strings.

    Mandiant publishes a list of ``{"name": "...",
    "affected_versions": [...]}`` dicts; we surface the names
    (deduped + sorted) for the description.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    products = record.get("vulnerable_products")
    if not isinstance(products, list):
        return out
    for entry in products:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("product")
        if isinstance(name, str) and name.strip():
            text = name.strip()
            if text in seen:
                continue
            seen.add(text)
            out.append(text)
    return sorted(out)


def extract_vendor_fix_references(record):
    """Pull Mandiant 'vendor_fix_references' URLs as plain strings.

    Mandiant publishes a list of ``{"url": "...", "name": "..."}``
    dicts pointing at the vendor's KB / patch advisory.  We
    surface the URLs deduped in the operator's order.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    refs = record.get("vendor_fix_references")
    if not isinstance(refs, list):
        return out
    for entry in refs:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if isinstance(url, str) and url.strip():
            text = url.strip()
            if text in seen:
                continue
            seen.add(text)
            out.append(text)
    return out


def extract_associated_actors(record):
    """Pull Mandiant 'associated_threat_actors' names.

    Mandiant publishes a list of ``{"id": "...", "name": "...",
    "country_name": "..."}`` dicts.  We surface the names
    (deduped + sorted).  When a record only carries the actor id
    without a name we keep the id so the operator still has a
    pivot.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    actors = record.get("associated_threat_actors") or record.get("threat_actors")
    if not isinstance(actors, list):
        return out
    for entry in actors:
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("id")
            if isinstance(name, str) and name.strip():
                text = name.strip()
                if text in seen:
                    continue
                seen.add(text)
                out.append(text)
        elif isinstance(entry, str) and entry.strip():
            text = entry.strip()
            if text in seen:
                continue
            seen.add(text)
            out.append(text)
    return sorted(out)


def extract_associated_malware(record):
    """Pull Mandiant 'associated_malware' family names."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    fams = record.get("associated_malware") or record.get("malware")
    if not isinstance(fams, list):
        return out
    for entry in fams:
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("id")
            if isinstance(name, str) and name.strip():
                text = name.strip()
                if text in seen:
                    continue
                seen.add(text)
                out.append(text)
        elif isinstance(entry, str) and entry.strip():
            text = entry.strip()
            if text in seen:
                continue
            seen.add(text)
            out.append(text)
    return sorted(out)


def severity_from_vulnerability(record):
    """Map a Mandiant vuln record to a Faraday severity bucket.

    Prefers the explicit ``risk_rating`` text (Mandiant analyst
    judgement); falls back to CVSSv3 ``base_severity`` text and
    then numeric CVSS bucketing.  Returns ``None`` when nothing
    is parseable so the caller can choose its own default.
    """
    if not isinstance(record, dict):
        return None
    rating = record.get("risk_rating")
    if isinstance(rating, str) and rating.strip():
        mapped = MANDIANT_RISK_RATING_MAP.get(rating.strip().upper())
        if mapped:
            return mapped
    cvss = extract_cvss(record)
    if cvss is None:
        return None
    sev = cvss.get("baseSeverity") or ""
    if sev:
        mapped = MANDIANT_RISK_RATING_MAP.get(sev)
        if mapped:
            return mapped
    score = cvss.get("baseScore")
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def extract_mscore(record):
    """Pull the Mandiant Confidence Score (mscore) from an indicator.

    Mandiant publishes mscore as either an int or numeric string
    between 0..100.  Garbage / missing returns ``None`` so the
    caller can choose its own default.
    """
    if not isinstance(record, dict):
        return None
    v = record.get("mscore")
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    try:
        s = int(float(v))
    except (TypeError, ValueError):
        return None
    if s < 0:
        return 0
    if s > 100:
        return 100
    return s


def severity_from_indicator(record):
    """Bucket a Mandiant indicator by mscore into the Faraday ladder.

    Mandiant's documented rubric: 80..100 critical (confirmed
    malicious), 50..79 high (probable), 25..49 medium (suspicious),
    10..24 low (low confidence), 0..9 info (likely benign).  When
    the indicator has no scored block we default to ``info`` —
    we don't synthesise a ranking Mandiant hasn't published.
    """
    score = extract_mscore(record)
    if score is None:
        return "info"
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def collect_cves(record):
    """Pull the canonical CVE id from a Mandiant vuln record."""
    out = []
    cve = extract_cve_id(record)
    if cve:
        out.append(cve)
    return out


def collect_refs_vuln(record):
    """Build the refs list for one Mandiant vuln record.

    Includes the canonical NVD CVE permalink, the Mandiant
    Advantage vulnerability-detail-page permalink, every
    ``vendor_fix_references`` URL, and explicit ``Mandiant-*``
    pivots (CVE id, risk rating, exploitation state, CVSS,
    vulnerable products, threat actors, malware families,
    publish / update dates) so operators can pivot from a Faraday
    finding back to the canonical Mandiant analyst record.
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
        add(f"https://advantage.mandiant.com/vulnerabilities/{cve}")
        add(f"Mandiant-CveID: {cve}")

    rating = record.get("risk_rating")
    if isinstance(rating, str) and rating.strip():
        add(f"Mandiant-RiskRating: {rating.strip()}")
    state = extract_exploitation_state(record)
    if state:
        add(f"Mandiant-ExploitationState: {state}")
    consequence = record.get("exploitation_consequence")
    if isinstance(consequence, str) and consequence.strip():
        add(f"Mandiant-ExploitationConsequence: {consequence.strip()}")

    cvss = extract_cvss(record)
    if cvss is not None:
        add(f"Mandiant-CvssVersion: {cvss['version']}")
        add(f"Mandiant-CvssScore: {cvss['baseScore']}")
        if cvss.get("baseSeverity"):
            add(f"Mandiant-CvssSeverity: {cvss['baseSeverity']}")
        if cvss.get("vectorString"):
            add(f"Mandiant-CvssVector: {cvss['vectorString']}")

    if record.get("was_zero_day"):
        add("Mandiant-ZeroDay: true")
    if record.get("was_seen_in_the_wild"):
        add("Mandiant-InTheWild: true")

    for product in extract_vulnerable_products(record):
        add(f"Mandiant-Product: {product}")

    for actor in extract_associated_actors(record):
        add(f"Mandiant-ThreatActor: {actor}")

    for malware in extract_associated_malware(record):
        add(f"Mandiant-Malware: {malware}")

    for key, label in (
        ("audit_publish_date", "AuditPublishDate"),
        ("audit_update_date", "AuditUpdateDate"),
    ):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            add(f"Mandiant-{label}: {v.strip()}")

    for url in extract_vendor_fix_references(record):
        add(url)

    return refs


def collect_refs_indicator(record, ind_type=None, ind_value=None):
    """Build the refs list for one Mandiant indicator record.

    Includes the Mandiant Advantage indicator-detail-page
    permalink (the canonical pivot) and explicit ``Mandiant-*``
    pivots (indicator type / value, mscore, first / last seen,
    threat actors, malware families, categories, sources) so
    operators can pivot from a Faraday finding back to the
    canonical Mandiant indicator record.
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

    if ind_type is None:
        ind_type = record.get("type") or ""
    if ind_value is None:
        ind_value = record.get("value") or ""

    type_key = str(ind_type).strip().lower()
    canonical = INDICATOR_TYPE_ALIASES.get(type_key, type_key)
    value = str(ind_value).strip()

    if canonical and value:
        encoded = quote(value, safe="")
        add(f"https://advantage.mandiant.com/indicator/{canonical}/{encoded}")
        add(f"Mandiant-IndicatorType: {canonical}")
        add(f"Mandiant-IndicatorValue: {value}")

    mscore = extract_mscore(record)
    if mscore is not None:
        add(f"Mandiant-Mscore: {mscore}")

    threat_rating = record.get("threat_rating")
    if isinstance(threat_rating, str) and threat_rating.strip():
        add(f"Mandiant-ThreatRating: {threat_rating.strip()}")

    for key, label in (
        ("first_seen", "FirstSeen"),
        ("last_seen", "LastSeen"),
        ("last_updated", "LastUpdated"),
    ):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            add(f"Mandiant-{label}: {v.strip()}")

    assoc = record.get("attributed_associations")
    if isinstance(assoc, list):
        for entry in assoc:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("type") or ""
            name = entry.get("name") or entry.get("id") or ""
            if isinstance(name, str) and name.strip():
                if isinstance(kind, str) and kind.strip():
                    add(f"Mandiant-Assoc-{kind.strip()}: {name.strip()}")
                else:
                    add(f"Mandiant-Assoc: {name.strip()}")

    cats = record.get("categories")
    if isinstance(cats, list):
        for c in cats:
            if isinstance(c, str) and c.strip():
                add(f"Mandiant-Category: {c.strip()}")

    sources = record.get("sources")
    if isinstance(sources, list):
        for entry in sources:
            if isinstance(entry, dict):
                src_name = entry.get("source_name") or entry.get("name")
                if isinstance(src_name, str) and src_name.strip():
                    add(f"Mandiant-Source: {src_name.strip()}")
            elif isinstance(entry, str) and entry.strip():
                add(f"Mandiant-Source: {entry.strip()}")

    return refs


def build_vulnerability(record):
    """Build a Faraday vulnerability dict for one Mandiant vuln record.

    Returns ``None`` when ``record`` is not parseable as a dict.
    """
    if not isinstance(record, dict):
        return None

    cve_id = extract_cve_id(record)
    title = extract_title(record)
    description = extract_description(record)
    cvss = extract_cvss(record)
    rating = record.get("risk_rating")
    rating_text = rating.strip() if isinstance(rating, str) and rating.strip() else ""
    state = extract_exploitation_state(record)

    sev = severity_from_vulnerability(record) or "info"
    if is_in_the_wild(record):
        sev = "critical"

    name_parts = ["[MANDIANT]"]
    if cve_id:
        name_parts.append(cve_id)
    if title:
        name_parts.append(title[:150])
    elif description:
        summary = description.split(".")[0].strip()
        if summary:
            name_parts.append(summary[:150])
    name = " ".join(name_parts).strip() if len(name_parts) > 1 else "[MANDIANT] vulnerability"

    desc_parts = []
    if cve_id:
        desc_parts.append(f"cveID: {cve_id}")
    if title:
        desc_parts.append(f"title: {title}")
    if rating_text:
        desc_parts.append(f"riskRating: {rating_text}")
    if state:
        desc_parts.append(f"exploitationState: {state}")
    consequence = record.get("exploitation_consequence")
    if isinstance(consequence, str) and consequence.strip():
        desc_parts.append(f"exploitationConsequence: {consequence.strip()}")
    if record.get("was_zero_day"):
        desc_parts.append("zeroDay: true")
    if record.get("was_seen_in_the_wild"):
        desc_parts.append("inTheWild: true")
    if cvss is not None:
        desc_parts.append(
            f"cvss{cvss['version']}: baseScore={cvss['baseScore']} " f"severity={cvss['baseSeverity'] or 'n/a'}"
        )
        if cvss.get("vectorString"):
            desc_parts.append(f"cvssVector: {cvss['vectorString']}")
    products = extract_vulnerable_products(record)
    if products:
        desc_parts.append(f"vulnerableProducts: {', '.join(products[:30])}")
    actors = extract_associated_actors(record)
    if actors:
        desc_parts.append(f"threatActors: {', '.join(actors)}")
    malware = extract_associated_malware(record)
    if malware:
        desc_parts.append(f"associatedMalware: {', '.join(malware)}")
    for key, label in (
        ("audit_publish_date", "auditPublishDate"),
        ("audit_update_date", "auditUpdateDate"),
    ):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            desc_parts.append(f"{label}: {v.strip()}")
    if description:
        desc_parts.append(f"description: {description}")

    mitigation = record.get("available_mitigation")
    fix_refs = extract_vendor_fix_references(record)
    if isinstance(mitigation, str) and mitigation.strip():
        resolution = mitigation.strip()
    elif fix_refs:
        resolution = (
            f"Apply vendor fixes for {cve_id or 'this CVE'} per the "
            f"{len(fix_refs)} Mandiant vendor-fix reference(s) attached."
        )
    else:
        resolution = (
            f"Prioritise patching {cve_id or 'this CVE'} per the Mandiant "
            "risk rating and exploitation-state guidance; cross-reference "
            "with the operator's asset inventory and the CISA KEV catalog "
            "before scheduling remediation."
        )

    external_id = cve_id or str(record.get("id") or name)[:200]

    return {
        "name": str(name).strip()[:200] or "[MANDIANT] vulnerability",
        "desc": "\n".join(desc_parts),
        "severity": sev if sev in VALID_SEVERITY else "info",
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs_vuln(record),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["mandiant"],
    }


def build_indicator_vulnerability(record, ind_type=None, ind_value=None):
    """Build a Faraday vulnerability dict for one Mandiant indicator.

    Returns ``None`` when ``record`` is not parseable as a dict.
    Indicators are surfaced as vulnerabilities (rather than the
    Faraday note / service shapes) so they slot into the same
    triage workflow as the Mandiant Vulnerability Intelligence
    stream — operators are filtering on the ``mandiant`` tag and
    the ``[MANDIANT IOC]`` engine prefix on the name anyway.
    """
    if not isinstance(record, dict):
        return None

    if ind_type is None:
        ind_type = record.get("type") or ""
    if ind_value is None:
        ind_value = record.get("value") or ""

    type_key = str(ind_type).strip().lower()
    canonical = INDICATOR_TYPE_ALIASES.get(type_key, type_key)
    value = str(ind_value).strip()

    sev = severity_from_indicator(record)
    mscore = extract_mscore(record)

    name_parts = ["[MANDIANT IOC]"]
    if canonical:
        name_parts.append(canonical)
    if value:
        name_parts.append(value[:120])
    if mscore is not None:
        name_parts.append(f"mscore={mscore}")
    name = " ".join(name_parts).strip()

    desc_parts = []
    if canonical:
        desc_parts.append(f"indicatorType: {canonical}")
    if value:
        desc_parts.append(f"indicatorValue: {value}")
    if mscore is not None:
        desc_parts.append(f"mscore: {mscore}")
    threat_rating = record.get("threat_rating")
    if isinstance(threat_rating, str) and threat_rating.strip():
        desc_parts.append(f"threatRating: {threat_rating.strip()}")
    for key, label in (
        ("first_seen", "firstSeen"),
        ("last_seen", "lastSeen"),
        ("last_updated", "lastUpdated"),
    ):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            desc_parts.append(f"{label}: {v.strip()}")

    assoc = record.get("attributed_associations")
    if isinstance(assoc, list):
        actor_names = []
        malware_names = []
        for entry in assoc:
            if not isinstance(entry, dict):
                continue
            kind = (entry.get("type") or "").strip().lower()
            name_v = entry.get("name") or entry.get("id") or ""
            if not isinstance(name_v, str) or not name_v.strip():
                continue
            if "actor" in kind:
                actor_names.append(name_v.strip())
            elif "malware" in kind:
                malware_names.append(name_v.strip())
        if actor_names:
            desc_parts.append(f"threatActors: {', '.join(sorted(set(actor_names)))}")
        if malware_names:
            desc_parts.append(f"associatedMalware: {', '.join(sorted(set(malware_names)))}")

    cats = record.get("categories")
    if isinstance(cats, list):
        cat_names = [c.strip() for c in cats if isinstance(c, str) and c.strip()]
        if cat_names:
            desc_parts.append(f"categories: {', '.join(sorted(set(cat_names)))}")

    sources = record.get("sources")
    if isinstance(sources, list):
        source_names = []
        for entry in sources:
            if isinstance(entry, dict):
                src_name = entry.get("source_name") or entry.get("name")
                if isinstance(src_name, str) and src_name.strip():
                    source_names.append(src_name.strip())
            elif isinstance(entry, str) and entry.strip():
                source_names.append(entry.strip())
        if source_names:
            desc_parts.append(f"sources: {', '.join(sorted(set(source_names)))}")

    if mscore is None:
        resolution = (
            "Mandiant has not yet scored this indicator; review the "
            "Mandiant Advantage IOC detail page once analysts publish "
            "a confidence score."
        )
    else:
        resolution = (
            f"Block / monitor the indicator ({canonical or 'unknown-type'} "
            f"{value or '?'}) per Mandiant's confidence score ({mscore}); "
            "cross-reference with the operator's SOC playbooks before "
            "deploying detection signatures."
        )

    record_id = record.get("id")
    external_id_text = ""
    if canonical and value:
        external_id_text = f"{canonical}:{value}"
    elif isinstance(record_id, str) and record_id.strip():
        external_id_text = record_id.strip()
    else:
        external_id_text = name

    return {
        "name": str(name).strip()[:200] or "[MANDIANT IOC]",
        "desc": "\n".join(desc_parts),
        "severity": sev if sev in VALID_SEVERITY else "info",
        "external_id": str(external_id_text)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs_indicator(record, ind_type=canonical, ind_value=value),
        "cve": [],
        "cvss3": {},
        "tags": ["mandiant"],
    }


def build_host(vulns, mode_desc, counts):
    """Build the single synthetic host that carries every Mandiant vuln.

    Mandiant entries (both CVE + indicator) are CVE / IOC keyed
    not host-keyed (the operator's other agents emit the
    host-side findings this feed is correlated against) so we
    collapse the whole feed under one synthetic ``0.0.0.0`` host
    with hostname ``mandiant``.
    """
    desc_parts = ["source=mandiant"]
    if mode_desc:
        desc_parts.append(mode_desc)
    if isinstance(counts, dict):
        for key in ("vulnerabilities_fetched", "indicators_fetched"):
            v = counts.get(key)
            if v in (None, ""):
                continue
            desc_parts.append(f"{key}={v}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["mandiant"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_token(requests_module, host, key_id, key_secret):
    """Exchange Mandiant client credentials for an OAuth2 Bearer token.

    Returns the bare token string on success or ``None`` on any
    failure (the caller treats that as a hard exit since every
    subsequent v4 request requires the Bearer header).
    """
    url = build_token_url(host)
    headers = {
        "Accept": "application/json",
        "Authorization": basic_auth_header(key_id, key_secret),
        "Content-Type": "application/x-www-form-urlencoded",
        "X-App-Name": "faraday-agent-dispatcher",
    }
    body = urlencode({"grant_type": "client_credentials", "scope": "mandiant-advantage"})
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


def fetch_url(requests_module, url, token):
    """GET a single Mandiant URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient Mandiant outage doesn't crash the
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
        log(f"Mandiant record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"Mandiant request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"Mandiant response was not JSON ({url})")
        return None


def fetch_cves(requests_module, host, cve_list, token, sleep_fn=time.sleep):
    """Walk MANDIANT_VULN_CVES and accumulate per-CVE records.

    Returns the list of unwrapped Mandiant vuln records (one per
    successful lookup).  ``sleep_fn`` is injectable to keep unit
    tests fast.
    """
    records = []
    for idx, cve_id in enumerate(cve_list):
        if idx > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        url = build_vuln_url(host, cve_id)
        body = fetch_url(requests_module, url, token)
        if body is None:
            continue
        record = extract_vulnerability_record(body)
        if record is None:
            continue
        records.append(record)
    return records


def fetch_indicators(requests_module, host, indicator_list, token, sleep_fn=time.sleep):
    """Walk MANDIANT_INDICATOR_LIST and accumulate per-indicator records.

    Returns a list of ``(record, type, value)`` tuples so the
    downstream builder can preserve the operator-supplied type /
    value even when the Mandiant response omits them.
    """
    out = []
    for idx, entry in enumerate(indicator_list):
        if idx > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        ind_type = entry.get("type", "")
        ind_value = entry.get("value", "")
        url = build_indicator_url(host, ind_type, ind_value)
        body = fetch_url(requests_module, url, token)
        if body is None:
            continue
        record = extract_indicator_record(body)
        if record is None:
            continue
        out.append((record, ind_type, ind_value))
    return out


def main():
    started = time.time()

    cve_list = validate_cve_list(env("EXECUTOR_CONFIG_MANDIANT_VULN_CVES"))
    indicator_list = validate_indicator_list(env("EXECUTOR_CONFIG_MANDIANT_INDICATOR_LIST"))
    host = env("MANDIANT_HOST", default=DEFAULT_HOST)
    key_id = env("MANDIANT_KEY_ID", required=True)
    key_secret = env("MANDIANT_KEY_SECRET", required=True)

    if not cve_list and not indicator_list:
        log("Neither MANDIANT_VULN_CVES nor MANDIANT_INDICATOR_LIST supplied; " "emitting an empty Faraday document")

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_token(requests, host, key_id, key_secret)
    if not token:
        log("Could not obtain a Mandiant OAuth2 token; aborting")
        sys.exit(1)

    vuln_records = fetch_cves(requests, host, cve_list, token) if cve_list else []
    indicator_records = fetch_indicators(requests, host, indicator_list, token) if indicator_list else []

    vulns = []
    for entry in vuln_records:
        v = build_vulnerability(entry)
        if v is not None:
            vulns.append(v)
    for record, ind_type, ind_value in indicator_records:
        v = build_indicator_vulnerability(record, ind_type=ind_type, ind_value=ind_value)
        if v is not None:
            vulns.append(v)

    counts = {
        "vulnerabilities_fetched": len(vuln_records),
        "indicators_fetched": len(indicator_records),
    }

    mode_parts = []
    if cve_list:
        mode_parts.append(f"cves={len(cve_list)}")
    if indicator_list:
        mode_parts.append(f"indicators={len(indicator_list)}")
    mode_desc = " ".join(mode_parts) if mode_parts else "empty"

    log(
        f"Processed {len(vulns)} Mandiant records "
        f"(cves={len(cve_list)}, indicators={len(indicator_list)}, "
        f"vulns_fetched={counts['vulnerabilities_fetched']}, "
        f"indicators_fetched={counts['indicators_fetched']})"
    )

    hosts_out = [build_host(vulns, mode_desc, counts)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "mandiant",
            "command": "mandiant",
            "params": (f"cves={len(cve_list)} indicators={len(indicator_list)}"),
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
