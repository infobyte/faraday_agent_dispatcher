#!/usr/bin/env python
"""CrowdStrike Falcon Intel indicator importer.

Pulls indicator-of-compromise (IOC) records from the
CrowdStrike Falcon Intel REST API and emits Faraday
bulk-create JSON to stdout.  Falcon Intel is the analyst /
threat-intelligence side of CrowdStrike's platform (separate
from the host-side Spotlight / Detects feeds the sibling
``crowdstrike`` executor consumes from JSON exports) — it
publishes hashes, IPs, domains, and URLs CrowdStrike
analysts have associated with named threat actors / malware
families.

Endpoints used:
  POST {FALCON_HOST}/oauth2/token
      -> Standard Falcon OAuth2 client_credentials grant.
      Form body ``client_id=...&client_secret=...``; returns
      ``{"access_token": "...", "token_type": "bearer",
      "expires_in": 1800}``.  The token is sent as
      ``Authorization: Bearer ...`` on every subsequent call.
      Falcon Intel is a paid product — the executor exits
      cleanly when the client_id / client_secret are missing.

  GET {FALCON_HOST}/intel/combined/indicators/v1
      ?limit=N&offset=N&filter=type:'{type}'&sort=last_updated.desc
      -> The combined endpoint returns full indicator records
      in one round-trip (vs. the two-call ids + entities
      pattern via /intel/queries/indicators/v1 +
      /intel/entities/indicators/GET/v1).  Response envelope
      is ``{"meta": {"pagination": {"offset": N, "limit": N,
      "total": N}, "trace_id": "..."}, "resources": [...],
      "errors": []}``.  Each ``resources`` entry carries
      ``id`` (CrowdStrike's natural key e.g.
      ``domain_evil.example.com``), ``indicator`` (the raw
      IOC value), ``type`` (one of hash_md5 / hash_sha256 /
      hash_sha1 / ip_address / domain / url / ...),
      ``published_date`` + ``last_updated`` (epoch seconds),
      ``malicious_confidence`` (high / medium / low /
      unverified), and optional ``actors`` (named threat
      actors), ``malware_families``, ``kill_chains``
      (reconnaissance / weaponization / delivery /
      exploitation / installation / c2 / actionOnObjectives),
      ``threat_types`` (Commodity / Targeted / ...),
      ``targets`` (industries), ``reports``
      (Falcon Intel report ids — CSIR-... / CSA-... /
      CSIT-...), ``labels``, ``relations`` (linked IOCs),
      and ``vulnerabilities`` (linked CVE ids).

  (The two-step /intel/queries/indicators/v1 +
  /intel/entities/indicators/GET/v1 path is the alternative
  pattern when the operator wants to page IDs first and
  fetch entities for a subset; the /intel/combined endpoint
  returns the same record shape in one round-trip so we
  prefer it for the typical "pull last N indicators of
  type X" operational mode this executor targets.)

Auth: ``FALCON_CLIENT_ID`` + ``FALCON_CLIENT_SECRET`` are
mandatory (the same OAuth2 client credentials Falcon
operators wire into every Falcon API tool).  ``FALCON_HOST``
may optionally be overridden via env to point at one of the
regional Falcon endpoints (``api.us-2.crowdstrike.com``,
``api.eu-1.crowdstrike.com``, ``api.laggar.gcw.crowdstrike.com``)
or a federated mirror; defaults to
``https://api.crowdstrike.com`` (the US-1 default).

Args:
  ``INTEL_INDICATOR_TYPE`` (mandatory) — one of
  ``hash_md5`` / ``hash_sha256`` / ``ip_address`` /
  ``domain`` / ``url``.  Forwarded to Falcon as
  ``filter=type:'{type}'`` so the API itself does the
  type-narrowing.  Anything else is rejected client-side
  with a hard error so a typo doesn't silently pull every
  indicator type.

  ``INTEL_MAX_RESULTS`` (optional integer, default 500) —
  upper bound on the total number of indicator records the
  executor will accumulate.  Falcon caps each page at 5000
  (the documented ``limit`` ceiling); we page 500 records
  at a time via ``offset`` / ``limit`` until either
  ``INTEL_MAX_RESULTS`` is reached or the result set is
  exhausted.  Values <= 0 are clamped to the default; very
  large values are clamped to 10000 to keep the dispatcher
  responsive on chatty tenants.

Each indicator becomes one Faraday vulnerability under a
single synthetic ``0.0.0.0`` host with hostname
``crowdstrike-intel``.  Falcon Intel indicators are IOC-keyed
not host-keyed — the operator's other agents emit the
host-side findings this feed is correlated against.  The
vulnerability carries ``tags: ['crowdstrike-intel']`` and
surfaces the indicator value + type + malicious_confidence +
actors + malware_families + kill_chains + threat_types +
report ids + linked CVEs in both the description and the
refs list so operators can pivot from a Faraday finding back
to the Falcon Intel record.

Severity is bucketed from Falcon's ``malicious_confidence``:
  - ``high``       -> high
  - ``medium``     -> medium
  - ``low``        -> low
  - ``unverified`` -> info
  - missing / unparseable -> info

Records whose ``actors`` list names a known APT (any actor
at all — Falcon only attaches actor labels with high
analyst confidence) are bumped one severity tier (low ->
medium / medium -> high / high -> critical).  Records
flagged ``kill_chains: ['actionOnObjectives']`` are also
bumped (these are post-exploitation IOCs that imply an
attacker has already achieved their goal on at least one
victim).

Status is always ``open`` (a Falcon Intel indicator cannot
be "fixed" in the catalog — it can only be blocked on the
operator's perimeter / EDR).  Resolution defaults to a
type-appropriate blocking recommendation
(domains / IPs / URLs -> "block on the perimeter and EDR";
hashes -> "block in EDR / AV").
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

TIMEOUT = 60

DEFAULT_HOST = "https://api.crowdstrike.com"
TOKEN_PATH = "/oauth2/token"
QUERY_PATH = "/intel/queries/indicators/v1"
COMBINED_PATH = "/intel/combined/indicators/v1"

# Falcon documents a per-tenant 6000 req/min ceiling on the
# /intel endpoints — pacing at 0.4s between pages keeps a
# single executor invocation well under the ceiling without
# burning more than ~0.4s of wall-clock per page.
INTER_REQUEST_SLEEP = 0.4

# Falcon's documented per-page limit ceiling on the /intel
# endpoints is 5000 records; we default to 500 per page to
# keep individual responses small and recoverable on flaky
# links.
PAGE_LIMIT = 500
MAX_PAGES = 200

# Default upper bound when the operator leaves INTEL_MAX_RESULTS
# blank — 500 is one full page and roughly matches the volume
# the rest of the threat-intel executors emit on a typical
# tenant.
DEFAULT_MAX_RESULTS = 500

# Hard ceiling on INTEL_MAX_RESULTS — large enough for any
# realistic operational mode (Falcon publishes ~ low-millions
# of indicators in the lifetime catalog; pulling 10k at a
# time is enough for incremental scoops) without giving an
# operator the rope to spin the dispatcher for hours.
MAX_INTEL_RESULTS = 10000

# Falcon's published indicator type vocabulary.  We expose
# the five most-requested types via the manifest arg; the
# Falcon API supports more (hash_sha1, ip_address_block,
# mutex_name, file_name, ...) but the per-task spec narrows
# the executor's contract to these five.
ALLOWED_INDICATOR_TYPES = (
    "hash_md5",
    "hash_sha256",
    "ip_address",
    "domain",
    "url",
)

# Falcon "malicious_confidence" -> Faraday severity.  Falcon
# also publishes a numeric ``high`` / ``medium`` / ``low``
# tier; mapping the named label keeps Faraday severity
# stable even if CrowdStrike tweaks its scoring.
CONFIDENCE_SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNVERIFIED": "info",
}

SEVERITY_BUMP = {
    "info": "low",
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")


def log(msg):
    print(f"{datetime.utcnow()} - CrowdStrikeIntel: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on FALCON_HOST.

    Defaults to ``https://api.crowdstrike.com`` (the US-1
    Falcon host) when the env override is missing / blank.
    Whitespace is trimmed and ``https://`` is added
    automatically when the operator pasted in a bare FQDN
    (regional Falcon hosts are typically copied as raw
    hostnames from the Falcon console).
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


def validate_indicator_type(value):
    """Coerce INTEL_INDICATOR_TYPE into one of the allowed types.

    Falcon's filter grammar is case-sensitive on the value
    side (``type:'domain'`` works, ``type:'Domain'`` does not)
    so we lower-case + strip.  Returns ``None`` for missing /
    blank / unknown inputs so the caller can hard-fail with a
    helpful error rather than pulling every indicator type.
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text not in ALLOWED_INDICATOR_TYPES:
        return None
    return text


def validate_max_results(value):
    """Coerce INTEL_MAX_RESULTS into a 1..MAX_INTEL_RESULTS integer.

    None / blank / unparseable -> ``DEFAULT_MAX_RESULTS``.
    Values <= 0 are clamped to the default (the operator most
    likely fat-fingered a sign / forgot a digit); values
    above the hard ceiling are clamped to ``MAX_INTEL_RESULTS``
    so a stray "100000" doesn't lock the dispatcher up for
    minutes.  Booleans are rejected (Python coerces
    ``True``/``False`` to 1/0 silently otherwise).
    """
    if value is None or value == "":
        return DEFAULT_MAX_RESULTS
    if isinstance(value, bool):
        log(f"INTEL_MAX_RESULTS {value!r} is a bool; using default")
        return DEFAULT_MAX_RESULTS
    try:
        cap = int(str(value).strip())
    except (TypeError, ValueError):
        try:
            cap = int(float(str(value).strip()))
        except (TypeError, ValueError):
            log(f"INTEL_MAX_RESULTS {value!r} is not an integer; using default")
            return DEFAULT_MAX_RESULTS
    if cap <= 0:
        log(f"INTEL_MAX_RESULTS {cap} is not positive; using default")
        return DEFAULT_MAX_RESULTS
    if cap > MAX_INTEL_RESULTS:
        log(f"INTEL_MAX_RESULTS {cap} above {MAX_INTEL_RESULTS}; clamping")
        return MAX_INTEL_RESULTS
    return cap


def build_token_url(host):
    """Build the OAuth2 token URL for a Falcon tenant."""
    return f"{normalize_base_url(host)}{TOKEN_PATH}"


def build_query_url(host, indicator_type, offset=0, limit=PAGE_LIMIT):
    """Build the /intel/queries/indicators/v1 URL (ids-only mode)."""
    params = [
        ("filter", f"type:'{str(indicator_type).strip().lower()}'"),
        ("offset", int(offset)),
        ("limit", int(limit)),
        ("sort", "last_updated.desc"),
    ]
    return f"{normalize_base_url(host)}{QUERY_PATH}?{urlencode(params)}"


def build_combined_url(host, indicator_type, offset=0, limit=PAGE_LIMIT):
    """Build the /intel/combined/indicators/v1 URL (full records).

    The combined endpoint returns the full record envelope in
    one round-trip so we prefer it over the two-call
    ids + entities pattern.  ``sort=last_updated.desc`` keeps
    the newest indicators at the head of the result set —
    important for the "give me the last N indicators of type
    X" operational mode.
    """
    params = [
        ("filter", f"type:'{str(indicator_type).strip().lower()}'"),
        ("offset", int(offset)),
        ("limit", int(limit)),
        ("sort", "last_updated.desc"),
    ]
    return f"{normalize_base_url(host)}{COMBINED_PATH}?{urlencode(params)}"


def auth_headers(token):
    """Build the headers dict for an authenticated Falcon GET."""
    headers = {"Accept": "application/json"}
    if isinstance(token, str) and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    return headers


def token_request_headers():
    """Headers for the OAuth2 token POST (form-encoded body)."""
    return {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }


def parse_epoch(value):
    """Parse a Falcon epoch-seconds timestamp into a UTC datetime.

    Falcon emits ``published_date`` / ``last_updated`` as
    integer epoch seconds.  Returns ``None`` for missing /
    non-numeric / bool inputs.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds != seconds:  # NaN
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def fetch_token(requests_module, host, client_id, client_secret):
    """POST the OAuth2 token endpoint and return the bearer token.

    Returns ``None`` on any failure (network / HTTP / JSON
    parse / missing access_token field) so the caller can log
    and exit cleanly without raising.
    """
    url = build_token_url(host)
    try:
        resp = requests_module.post(
            url,
            timeout=TIMEOUT,
            headers=token_request_headers(),
            data={
                "client_id": str(client_id or "").strip(),
                "client_secret": str(client_secret or "").strip(),
            },
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"OAuth2 POST {url} failed: {exc}")
        return None
    if resp.status_code >= 400:
        log(f"OAuth2 token request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log(f"OAuth2 response was not JSON ({url})")
        return None
    if not isinstance(body, dict):
        log(f"OAuth2 response was not a dict ({url})")
        return None
    token = body.get("access_token")
    if not isinstance(token, str) or not token.strip():
        log(f"OAuth2 response missing access_token ({url})")
        return None
    return token.strip()


def fetch_url(requests_module, url, token):
    """GET a single Falcon URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient Falcon outage doesn't crash the
    dispatcher.  Returns ``None`` on any failure; the caller
    is expected to treat that as "no records" and continue.
    """
    try:
        resp = requests_module.get(
            url,
            timeout=TIMEOUT,
            headers=auth_headers(token),
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"Falcon record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"Falcon request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"Falcon response was not JSON ({url})")
        return None


def extract_resources(body):
    """Pull the ``resources`` list from a Falcon envelope.

    Falcon wraps every response under ``{"meta": ..., "resources":
    [...], "errors": [...]}``.  Pre-unwrapped payloads from
    federated mirrors and bare-list fallbacks are accepted
    too for robustness.
    """
    if isinstance(body, dict):
        res = body.get("resources")
        if isinstance(res, list):
            return [entry for entry in res if isinstance(entry, dict)]
        data = body.get("data")
        if isinstance(data, list):
            return [entry for entry in data if isinstance(entry, dict)]
        return []
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    return []


def extract_pagination(body):
    """Pull ``meta.pagination`` from a Falcon envelope.

    Returns ``{"offset": int|None, "limit": int|None,
    "total": int|None}``; missing fields stay ``None``.
    """
    out = {"offset": None, "limit": None, "total": None}
    if not isinstance(body, dict):
        return out
    meta = body.get("meta")
    if not isinstance(meta, dict):
        return out
    pag = meta.get("pagination")
    if not isinstance(pag, dict):
        return out
    for key in ("offset", "limit", "total"):
        v = pag.get(key)
        if v is None:
            continue
        try:
            out[key] = int(v)
        except (TypeError, ValueError):
            out[key] = None
    return out


def extract_errors(body):
    """Pull the ``errors`` list from a Falcon envelope.

    Falcon returns errors as ``[{"code": N, "message": "..."}]``
    even on partial success; we surface them in logs to help
    operators debug filter / permission issues.
    """
    if not isinstance(body, dict):
        return []
    errs = body.get("errors")
    if not isinstance(errs, list):
        return []
    return [e for e in errs if isinstance(e, dict)]


def extract_string_list(record, key):
    """Pull a list-of-strings field from a Falcon indicator record."""
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    values = record.get(key)
    if not isinstance(values, list):
        return out
    for v in values:
        if not isinstance(v, str):
            continue
        text = v.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def extract_actors(record):
    """Pull the ``actors`` list (named threat actors)."""
    return extract_string_list(record, "actors")


def extract_malware_families(record):
    """Pull the ``malware_families`` list."""
    return extract_string_list(record, "malware_families")


def extract_kill_chains(record):
    """Pull the ``kill_chains`` list (Lockheed Martin Kill Chain phases)."""
    return extract_string_list(record, "kill_chains")


def extract_threat_types(record):
    """Pull the ``threat_types`` list (Commodity / Targeted / ...)."""
    return extract_string_list(record, "threat_types")


def extract_targets(record):
    """Pull the ``targets`` list (industry verticals)."""
    return extract_string_list(record, "targets")


def extract_reports(record):
    """Pull the ``reports`` list (Falcon Intel report ids)."""
    return extract_string_list(record, "reports")


def extract_labels(record):
    """Pull label names from the Falcon ``labels`` block.

    Falcon emits labels as ``[{"name": "Actor/FANCY BEAR",
    "created_on": ..., "last_valid_on": ...}]``; we surface
    just the names since the timestamps are already covered
    by ``published_date`` / ``last_updated``.
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    labels = record.get("labels")
    if not isinstance(labels, list):
        return out
    for entry in labels:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        text = name.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def extract_vulnerabilities(record):
    """Pull the linked-CVE list from a Falcon indicator record.

    Falcon attaches a ``vulnerabilities`` field with the CVE
    ids the indicator has been observed exploiting (rare for
    raw IOCs, common for hashes / URLs of weaponised
    artefacts).
    """
    out = []
    seen = set()
    if not isinstance(record, dict):
        return out
    vulns = record.get("vulnerabilities")
    if not isinstance(vulns, list):
        return out
    for v in vulns:
        if not isinstance(v, str):
            continue
        text = v.strip().upper()
        if not text.startswith("CVE-") or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def severity_from_confidence(record):
    """Map Falcon's ``malicious_confidence`` to a Faraday severity.

    Defaults to ``info`` when the field is missing /
    unparseable / unknown so the indicator still surfaces in
    the workspace (the absence is itself a signal).
    """
    if not isinstance(record, dict):
        return "info"
    conf = record.get("malicious_confidence")
    if not isinstance(conf, str):
        return "info"
    return CONFIDENCE_SEVERITY_MAP.get(conf.strip().upper(), "info")


def bump_severity(severity):
    """Bump severity one tier (low -> medium -> high -> critical)."""
    if not isinstance(severity, str):
        return "info"
    return SEVERITY_BUMP.get(severity.strip().lower(), severity)


def severity_for_record(record):
    """Final severity for an indicator after actor / kill-chain bumps.

    Records flagged with any named actor get bumped one tier
    (Falcon only attaches actor labels with high analyst
    confidence so the bump is well-justified).  Records
    flagged ``kill_chains: ['actionOnObjectives']`` also get
    bumped — these are post-exploitation IOCs.  Bumps
    compound: an actor-named action-on-objectives IOC gets
    two bumps.
    """
    base = severity_from_confidence(record)
    final = base
    if extract_actors(record):
        final = bump_severity(final)
    if "actionOnObjectives" in extract_kill_chains(record):
        final = bump_severity(final)
    if final not in VALID_SEVERITY:
        return base if base in VALID_SEVERITY else "info"
    return final


def resolution_for_record(record):
    """Type-appropriate blocking recommendation for an indicator."""
    if not isinstance(record, dict):
        return "Block this indicator on the operator's perimeter " "controls per CrowdStrike Intel guidance."
    type_raw = record.get("type")
    type_text = type_raw.strip().lower() if isinstance(type_raw, str) else ""
    if type_text in ("hash_md5", "hash_sha1", "hash_sha256"):
        return "Block this file hash in the operator's EDR / AV / " "Falcon prevention policy."
    if type_text == "ip_address":
        return (
            "Block this IP on the operator's perimeter firewall, "
            "egress proxy, and EDR network containment policies."
        )
    if type_text == "domain":
        return "Sinkhole this domain on the operator's DNS resolver " "and add to the perimeter blocklist."
    if type_text == "url":
        return "Block this URL on the operator's egress proxy and " "endpoint web-filter policy."
    return "Block this indicator on the operator's perimeter " "controls per CrowdStrike Intel guidance."


def collect_cves(record):
    """Pull linked CVE ids from a Falcon indicator record."""
    return extract_vulnerabilities(record)


def collect_refs(record):
    """Build the refs list for one Falcon indicator record.

    Includes the indicator value itself, the type, the
    malicious_confidence label, named actors / malware
    families / kill chains / threat types / targets / report
    ids / labels / linked CVE ids (each as explicit ``Cs-*``
    pivots), the canonical Falcon Intel record id, and
    timestamps so operators can pivot from a Faraday finding
    back to the Falcon Intel record.
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

    rid = record.get("id")
    if isinstance(rid, str) and rid.strip():
        add(f"Cs-IndicatorID: {rid.strip()}")

    indicator = record.get("indicator")
    if isinstance(indicator, str) and indicator.strip():
        add(f"Cs-Indicator: {indicator.strip()}")

    type_raw = record.get("type")
    if isinstance(type_raw, str) and type_raw.strip():
        add(f"Cs-Type: {type_raw.strip()}")

    conf = record.get("malicious_confidence")
    if isinstance(conf, str) and conf.strip():
        add(f"Cs-Confidence: {conf.strip()}")

    for actor in extract_actors(record):
        add(f"Cs-Actor: {actor}")

    for fam in extract_malware_families(record):
        add(f"Cs-MalwareFamily: {fam}")

    for phase in extract_kill_chains(record):
        add(f"Cs-KillChain: {phase}")

    for tt in extract_threat_types(record):
        add(f"Cs-ThreatType: {tt}")

    for target in extract_targets(record):
        add(f"Cs-Target: {target}")

    for report in extract_reports(record):
        add(f"Cs-Report: {report}")

    for label in extract_labels(record):
        add(f"Cs-Label: {label}")

    for cve in extract_vulnerabilities(record):
        add(f"Cs-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    published = parse_epoch(record.get("published_date"))
    if published is not None:
        add(f"Cs-Published: {published.isoformat()}")

    updated = parse_epoch(record.get("last_updated"))
    if updated is not None:
        add(f"Cs-LastUpdated: {updated.isoformat()}")

    return refs


def build_vulnerability(record):
    """Build a Faraday vulnerability dict for one Falcon indicator.

    Returns ``None`` when ``record`` is not a dict or carries
    no indicator value (defensive — the API only returns
    records with both ``id`` and ``indicator`` populated but
    we don't want to emit a vuln we can't even name).
    """
    if not isinstance(record, dict):
        return None

    indicator_raw = record.get("indicator")
    indicator = indicator_raw.strip() if isinstance(indicator_raw, str) else ""
    type_raw = record.get("type")
    type_text = type_raw.strip().lower() if isinstance(type_raw, str) else ""

    if not indicator and not type_text:
        return None

    severity = severity_for_record(record)
    base_conf = severity_from_confidence(record)

    rid = record.get("id")
    rid_text = rid.strip() if isinstance(rid, str) else ""

    name_parts = ["[CS-Intel]"]
    if type_text:
        name_parts.append(type_text)
    if indicator:
        name_parts.append(indicator)
    actors = extract_actors(record)
    if actors:
        name_parts.append(f"actor={actors[0]}")
    name = " ".join(name_parts)

    desc_parts = []
    if rid_text:
        desc_parts.append(f"indicatorID: {rid_text}")
    if indicator:
        desc_parts.append(f"indicator: {indicator}")
    if type_text:
        desc_parts.append(f"type: {type_text}")
    conf_raw = record.get("malicious_confidence")
    if isinstance(conf_raw, str) and conf_raw.strip():
        desc_parts.append(f"maliciousConfidence: {conf_raw.strip()}")
    desc_parts.append(f"severity: {severity} (base={base_conf})")
    if actors:
        desc_parts.append("actors: " + ", ".join(actors))
    fams = extract_malware_families(record)
    if fams:
        desc_parts.append("malwareFamilies: " + ", ".join(fams))
    phases = extract_kill_chains(record)
    if phases:
        desc_parts.append("killChains: " + ", ".join(phases))
    tts = extract_threat_types(record)
    if tts:
        desc_parts.append("threatTypes: " + ", ".join(tts))
    targets = extract_targets(record)
    if targets:
        desc_parts.append("targets: " + ", ".join(targets))
    reports = extract_reports(record)
    if reports:
        desc_parts.append("reports: " + ", ".join(reports))
    labels = extract_labels(record)
    if labels:
        desc_parts.append("labels: " + ", ".join(labels[:20]))
    cves = extract_vulnerabilities(record)
    if cves:
        desc_parts.append("vulnerabilities: " + ", ".join(cves))
    published = parse_epoch(record.get("published_date"))
    if published is not None:
        desc_parts.append(f"publishedDate: {published.isoformat()}")
    updated = parse_epoch(record.get("last_updated"))
    if updated is not None:
        desc_parts.append(f"lastUpdated: {updated.isoformat()}")
    if record.get("deleted") is True:
        desc_parts.append("deleted: True")

    external_id = rid_text or indicator or name
    resolution = resolution_for_record(record)

    return {
        "name": str(name).strip()[:200] or "CrowdStrike Intel indicator",
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
        "tags": ["crowdstrike-intel"],
    }


def build_host(vulns, indicator_type, max_results, total):
    """Build the single synthetic host that carries every IOC vuln.

    Falcon Intel indicators are IOC-keyed not host-keyed —
    the operator's other agents emit the host-side findings
    this feed is correlated against — so we collapse the
    whole feed under one synthetic ``0.0.0.0`` host with
    hostname ``crowdstrike-intel``.
    """
    desc_parts = ["source=crowdstrike-intel"]
    if indicator_type:
        desc_parts.append(f"type={indicator_type}")
    desc_parts.append(f"max_results={max_results}")
    if total is not None:
        desc_parts.append(f"falcon_total={total}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["crowdstrike-intel"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_indicators(
    requests_module,
    host,
    token,
    indicator_type,
    max_results,
    sleep_fn=time.sleep,
    max_pages=MAX_PAGES,
    page_limit=PAGE_LIMIT,
):
    """Page through /intel/combined/indicators/v1 up to max_results.

    Returns ``(records, last_pagination)`` where ``records``
    is the accumulated indicator list and ``last_pagination``
    is the most-recent response's ``meta.pagination`` block
    (used for provenance on the synthetic host).  Stops when
    ``max_results`` is hit, when Falcon returns no resources,
    when the running offset >= ``total``, or when
    ``max_pages`` is exhausted.
    """
    records = []
    last_pagination = {"offset": None, "limit": None, "total": None}
    offset = 0
    page = 0
    while page < max_pages and len(records) < max_results:
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        remaining = max_results - len(records)
        limit = min(page_limit, remaining)
        if limit <= 0:
            break
        url = build_combined_url(
            host,
            indicator_type,
            offset=offset,
            limit=limit,
        )
        body = fetch_url(requests_module, url, token)
        if body is None:
            break
        for err in extract_errors(body):
            log(f"Falcon error: {err}")
        pagination = extract_pagination(body)
        if pagination:
            last_pagination = pagination
        page_records = extract_resources(body)
        if not page_records:
            break
        for entry in page_records:
            records.append(entry)
            if len(records) >= max_results:
                break
        offset += len(page_records)
        total = last_pagination.get("total")
        if total is not None and offset >= total:
            break
        page += 1
    return records, last_pagination


def main():
    started = time.time()

    indicator_type = validate_indicator_type(env("EXECUTOR_CONFIG_INTEL_INDICATOR_TYPE", required=True))
    if indicator_type is None:
        log("INTEL_INDICATOR_TYPE must be one of " f"{list(ALLOWED_INDICATOR_TYPES)}")
        sys.exit(1)
    max_results = validate_max_results(env("EXECUTOR_CONFIG_INTEL_MAX_RESULTS"))
    host = env("FALCON_HOST", default=DEFAULT_HOST)
    client_id = env("FALCON_CLIENT_ID", required=True)
    client_secret = env("FALCON_CLIENT_SECRET", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    token = fetch_token(requests, host, client_id, client_secret)
    if not token:
        log("Falcon OAuth2 authentication failed")
        sys.exit(1)

    records, pagination = fetch_indicators(
        requests,
        host,
        token,
        indicator_type,
        max_results,
    )

    vulns = []
    for entry in records:
        vuln = build_vulnerability(entry)
        if vuln is not None:
            vulns.append(vuln)

    total = pagination.get("total") if isinstance(pagination, dict) else None
    log(
        f"Processed {len(vulns)} Falcon Intel indicators "
        f"(type={indicator_type}, max_results={max_results}, "
        f"falcon_total={total if total is not None else '?'})"
    )

    hosts_out = [build_host(vulns, indicator_type, max_results, total)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "crowdstrike_intel",
            "command": "crowdstrike_intel",
            "params": (f"type={indicator_type} max_results={max_results}"),
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
