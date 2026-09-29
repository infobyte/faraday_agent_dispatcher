#!/usr/bin/env python
"""NIST National Vulnerability Database (NVD) 2.0 REST API importer.

Pulls CVE records from the canonical NIST NVD 2.0 REST surface
(``https://services.nvd.nist.gov/rest/json/cves/2.0``) and emits
Faraday bulk-create JSON to stdout.  The executor exposes two
mutually-exclusive operational modes via its manifest args:

  * ``NVD_CVE_LIST`` (CSV of CVE ids) — fetch each listed CVE in
    turn using the ``?cveId=CVE-YYYY-NNNN`` query string.  One
    HTTP GET per CVE, paced under the NVD rate limit (see below).
    Invalid-shaped entries are dropped silently.

  * ``NVD_LAST_MOD_DAYS`` (integer, default 7) — fetch every CVE
    modified in the trailing N days using the
    ``?lastModStartDate=...&lastModEndDate=...`` window query
    string.  Bounded to NVD's documented 1..120 day span.  Pages
    of up to 2000 records via ``startIndex`` / ``resultsPerPage``
    until the entire window is walked.

When both args are supplied ``NVD_CVE_LIST`` wins (the per-CVE
mode is the narrower, more deterministic projection).  When
neither arg is supplied the executor falls back to the trailing
7-day window.

Endpoints used:
  GET {NVD_HOST}/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN
      -> Single-CVE lookup.  Returns the canonical NVD envelope
      ``{"resultsPerPage": N, "startIndex": 0,
      "totalResults": N, "format": "NVD_CVE", "version": "2.0",
      "timestamp": "...", "vulnerabilities":
      [{"cve": {...}}, ...]}`` with a ``totalResults: 0`` body
      when the CVE id is unknown / malformed.

  GET {NVD_HOST}/rest/json/cves/2.0?lastModStartDate=...
       &lastModEndDate=...&startIndex=0&resultsPerPage=2000
      -> Window query.  Same envelope shape.  Pagination loops
      until ``startIndex + resultsPerPage >= totalResults``.  The
      window span is capped at 120 days client-side because the
      NVD API rejects longer spans with HTTP 400.

Each ``vulnerabilities`` entry wraps the CVE record under a
``cve`` key.  The CVE record carries ``id``,
``sourceIdentifier``, ``published`` (ISO 8601 timestamp the CVE
was first published), ``lastModified`` (ISO 8601 timestamp of the
most recent NVD modification), ``vulnStatus`` (one of
``Received`` / ``Awaiting Analysis`` / ``Undergoing Analysis`` /
``Analyzed`` / ``Modified`` / ``Deferred`` / ``Rejected``),
``descriptions`` (list of ``{"lang": "en", "value": "..."}``),
``metrics`` (CVSS v3.1 / v3.0 / v2 score blocks under
``cvssMetricV31`` / ``cvssMetricV30`` / ``cvssMetricV2``),
``weaknesses`` (list of CWE descriptions), and ``references``
(list of advisory URLs with optional ``tags`` like ``Patch`` /
``Vendor Advisory`` / ``Exploit``).

Severity is derived from CVSS, preferring v3.1 over v3.0 over
v2.  Each metric block carries an explicit ``baseSeverity`` text
(``CRITICAL`` / ``HIGH`` / ``MEDIUM`` / ``LOW`` / ``NONE``) which
we map to Faraday's ladder; when the text is missing or
unrecognised we fall back to a numeric ``baseScore`` bucket:
  * baseScore >= 9.0 -> critical
  * baseScore >= 7.0 -> high
  * baseScore >= 4.0 -> medium
  * baseScore  > 0.0 -> low
  * baseScore == 0.0 -> info

When the CVE record carries no metrics at all (typical for
``Received`` / ``Awaiting Analysis`` entries that NVD has not
yet scored) severity defaults to ``info`` — we don't want to
synthesise a ranking NVD hasn't published.  ``Rejected`` CVEs
are surfaced as ``info`` with a ``[REJECTED]`` annotation in the
name and description so the operator can see that NVD has
withdrawn the entry while keeping it visible in their workspace.

Each CVE becomes one Faraday vulnerability under a single
synthetic ``0.0.0.0`` host with hostname ``nist-nvd``.  NVD
entries are CVE-keyed not host-keyed — the operator's other
agents emit the host-side findings this feed is correlated
against.  The vulnerability carries ``tags: ['nist-nvd']`` and
surfaces the CVSS score, status, publication / modification
dates, CWE list, and NVD reference URLs in both the description
and the refs list so the operator can pivot from a Faraday
finding back to the canonical NVD record.

Rate limiting: NVD permits 5 requests per 30 seconds without an
``apiKey`` header and 50 requests per 30 seconds with one.  This
executor injects a small sleep between every HTTP GET to stay
under the limit — 6 seconds when no key is configured and 0.7
seconds when ``NVD_API_KEY`` is set.  The sleep is suppressed
before the very first request so a single-CVE invocation is
still snappy.

Auth: ``NVD_API_KEY`` is optional and is sent as an ``apiKey``
HTTP header on every request.  The NVD API also accepts requests
with no key (subject to the lower rate limit) so the executor is
fully functional without one — supplying a key just raises the
throughput ceiling.  ``NVD_HOST`` may optionally be overridden
via env to point at a federated mirror or an offline cache;
defaults to ``https://services.nvd.nist.gov``.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

TIMEOUT = 60
DEFAULT_HOST = "https://services.nvd.nist.gov"
CVE_PATH = "/rest/json/cves/2.0"

MAX_WINDOW_DAYS = 120
DEFAULT_WINDOW_DAYS = 7
RESULTS_PER_PAGE = 2000

# NVD documents 5 requests / 30s without a key and 50 requests
# / 30s with one.  A small buffer keeps us comfortably under the
# ceiling without burning more than one wall-clock second per
# authenticated request.
SLEEP_NO_KEY = 6.0
SLEEP_WITH_KEY = 0.7

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

NVD_BASE_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
}


def log(msg):
    print(f"{datetime.utcnow()} - NistNvd: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on NVD_HOST.

    Defaults to ``https://services.nvd.nist.gov`` (the canonical
    NVD REST host) when the env override is missing / blank.
    Whitespace is trimmed and ``https://`` is added automatically
    when the operator pasted in a bare FQDN (on-prem mirrors
    typically use raw hostnames).
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
    """Normalise NVD_CVE_LIST into a list of well-formed CVE ids.

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
            log(f"NVD_CVE_LIST entry {cve!r} is not a valid CVE id; skipping")
            continue
        if upper in seen:
            continue
        seen.add(upper)
        out.append(upper)
    return out


def validate_last_mod_days(value):
    """Coerce NVD_LAST_MOD_DAYS into a 1..120 integer.

    Defaults to ``DEFAULT_WINDOW_DAYS`` (7) when the arg is
    missing / blank / unparseable.  Values below 1 are clamped to
    1; values above the NVD-documented 120-day ceiling are clamped
    to 120 (the API rejects longer spans with HTTP 400).
    """
    if value is None or value == "":
        return DEFAULT_WINDOW_DAYS
    try:
        if isinstance(value, bool):
            raise TypeError
        days = int(str(value).strip())
    except (TypeError, ValueError):
        log(f"NVD_LAST_MOD_DAYS {value!r} is not an integer; " f"defaulting to {DEFAULT_WINDOW_DAYS}")
        return DEFAULT_WINDOW_DAYS
    if days < 1:
        log(f"NVD_LAST_MOD_DAYS {days} below 1; clamping to 1")
        return 1
    if days > MAX_WINDOW_DAYS:
        log(f"NVD_LAST_MOD_DAYS {days} above {MAX_WINDOW_DAYS} " f"(NVD API hard limit); clamping")
        return MAX_WINDOW_DAYS
    return days


def format_nvd_timestamp(dt):
    """Format a datetime as the ISO 8601 shape NVD's window query expects.

    NVD accepts both ``...Z`` and ``...+00:00`` offsets; we emit
    UTC ``Z``-suffixed timestamps with millisecond precision for
    maximum compatibility with the documented examples.  Naive
    datetimes are interpreted as UTC.
    """
    if not isinstance(dt, datetime):
        raise TypeError("format_nvd_timestamp expects a datetime")
    if dt.tzinfo is None:
        aware = dt.replace(tzinfo=timezone.utc)
    else:
        aware = dt.astimezone(timezone.utc)
    return aware.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def compute_window(now_dt, days):
    """Compute (start, end) datetimes for the lastModified window.

    ``end`` is ``now_dt`` (clamped to UTC) and ``start`` is
    ``end - timedelta(days=days)``.  Both values are UTC-aware
    datetimes ready for ``format_nvd_timestamp``.
    """
    if not isinstance(now_dt, datetime):
        raise TypeError("compute_window expects a datetime for now_dt")
    if now_dt.tzinfo is None:
        end = now_dt.replace(tzinfo=timezone.utc)
    else:
        end = now_dt.astimezone(timezone.utc)
    start = end - timedelta(days=int(days))
    return start, end


def build_cve_url(host, cve_id):
    """Build the single-CVE lookup URL for NVD.

    The ``cveId`` query string is upper-cased per the NVD
    documentation (the API itself is case-insensitive but we
    canonicalise to keep audit logs consistent).
    """
    query = urlencode({"cveId": str(cve_id).strip().upper()})
    return f"{normalize_base_url(host)}{CVE_PATH}?{query}"


def build_window_url(host, start_dt, end_dt, start_index=0, results_per_page=RESULTS_PER_PAGE):
    """Build a window query URL for NVD.

    Includes pagination via ``startIndex`` / ``resultsPerPage``
    so callers can walk multi-page result sets without rebuilding
    the start/end timestamps each iteration.
    """
    query = urlencode(
        [
            ("lastModStartDate", format_nvd_timestamp(start_dt)),
            ("lastModEndDate", format_nvd_timestamp(end_dt)),
            ("startIndex", int(start_index)),
            ("resultsPerPage", int(results_per_page)),
        ]
    )
    return f"{normalize_base_url(host)}{CVE_PATH}?{query}"


def request_headers(api_key):
    """Build the headers dict for a single NVD GET.

    ``Accept: application/json`` is always sent.  ``apiKey`` is
    included only when the operator supplied a non-blank
    ``NVD_API_KEY``; the NVD API tolerates the header being
    absent (subject to the lower rate limit).
    """
    headers = {"Accept": "application/json"}
    if isinstance(api_key, str) and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def rate_limit_sleep_seconds(api_key):
    """Return the inter-request sleep window for the current auth mode.

    NVD documents 5 requests / 30s without an apiKey and 50
    requests / 30s with one.  We sleep 6 seconds without a key
    (5 requests in 30s = one every 6s) and 0.7 seconds with one
    (50 requests in 30s = one every 0.6s, plus 100ms buffer).
    """
    if isinstance(api_key, str) and api_key.strip():
        return SLEEP_WITH_KEY
    return SLEEP_NO_KEY


def parse_iso_datetime(value):
    """Parse an ISO 8601 timestamp into a UTC-aware datetime.

    Returns ``None`` on non-string / unparseable / bool inputs.
    Accepts the canonical ``...Z`` suffix as well as the
    ``...+00:00`` offset shape NVD uses on the ``timestamp`` /
    ``published`` / ``lastModified`` fields.
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


def extract_vulnerabilities(body):
    """Pull the inner ``cve`` records from an NVD response envelope.

    The canonical NVD envelope wraps each entry as
    ``{"cve": {...}}``; we unwrap and return the inner dicts so
    downstream helpers can treat them uniformly.  Federated /
    mirror stacks that emit bare-list / ``data`` / ``results`` /
    ``items`` envelopes are accepted for resilience, as are
    payloads that already pre-unwrapped the ``cve`` key.
    """
    raw = []
    if isinstance(body, list):
        raw = [entry for entry in body if isinstance(entry, dict)]
    elif isinstance(body, dict):
        for key in ("vulnerabilities", "data", "results", "items"):
            v = body.get(key)
            if isinstance(v, list):
                raw = [entry for entry in v if isinstance(entry, dict)]
                break
    out = []
    for entry in raw:
        if "cve" in entry and isinstance(entry["cve"], dict):
            out.append(entry["cve"])
        elif "id" in entry:
            out.append(entry)
    return out


def extract_response_meta(body):
    """Pull envelope-level metadata for provenance.

    Returns whatever NVD-documented fields are present.  Used to
    embed catalog-version style breadcrumbs in the per-finding
    description and on the synthetic host so operators can pivot
    from a Faraday finding back to the exact NVD response that
    produced it.
    """
    out = {}
    if not isinstance(body, dict):
        return out
    for key in (
        "resultsPerPage",
        "startIndex",
        "totalResults",
        "format",
        "version",
        "timestamp",
    ):
        v = body.get(key)
        if v in (None, ""):
            continue
        out[key] = v
    return out


def extract_description(cve):
    """Return the English-language description for a CVE record.

    NVD always emits at least one ``descriptions`` entry but only
    ``lang: en`` is guaranteed to be present for federal-civilian
    CVEs — we still fall back to the first non-empty value when
    English is missing so we don't drop a translated-only entry
    in non-canonical mirrors.
    """
    if not isinstance(cve, dict):
        return ""
    descs = cve.get("descriptions")
    if not isinstance(descs, list):
        return ""
    english = ""
    fallback = ""
    for entry in descs:
        if not isinstance(entry, dict):
            continue
        value = entry.get("value")
        if not isinstance(value, str) or not value.strip():
            continue
        lang = entry.get("lang")
        if isinstance(lang, str) and lang.lower() == "en":
            english = value.strip()
            break
        if not fallback:
            fallback = value.strip()
    return english or fallback


def extract_cvss(cve):
    """Pick the best-available CVSS metric block for a CVE.

    Order of preference is v3.1 -> v3.0 -> v2, mirroring NIST's
    own scoring ladder.  Returns a normalised dict with
    ``version``, ``baseScore``, ``baseSeverity`` (upper-cased
    when present) and ``vectorString``, or ``None`` when no
    scored metric block is attached.
    """
    if not isinstance(cve, dict):
        return None
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    for key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            base_score = data.get("baseScore")
            if base_score is None:
                continue
            try:
                score = float(base_score)
            except (TypeError, ValueError):
                continue
            sev_raw = data.get("baseSeverity") or entry.get("baseSeverity")
            sev = sev_raw.strip().upper() if isinstance(sev_raw, str) else ""
            vector = data.get("vectorString") if isinstance(data.get("vectorString"), str) else ""
            return {
                "version": version,
                "baseScore": score,
                "baseSeverity": sev,
                "vectorString": vector,
            }
    return None


def extract_cwes(cve):
    """Pull every CWE-NNN string attached to a CVE's weaknesses block.

    NVD's ``weaknesses`` is a list of ``{source, type, description}``
    where ``description`` is itself a list of language-tagged
    values.  Some entries carry the value ``NVD-CWE-noinfo`` /
    ``NVD-CWE-Other`` which we surface as-is — operators want
    to see "NVD wasn't able to map a CWE" instead of a silent drop.
    """
    out = []
    seen = set()
    if not isinstance(cve, dict):
        return out
    weaknesses = cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        return out
    for entry in weaknesses:
        if not isinstance(entry, dict):
            continue
        descs = entry.get("description")
        if not isinstance(descs, list):
            continue
        for desc in descs:
            if not isinstance(desc, dict):
                continue
            value = desc.get("value")
            if not isinstance(value, str):
                continue
            text = value.strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(text)
    return out


def extract_references(cve):
    """Pull the list of advisory references attached to a CVE.

    Returns a list of ``{"url": str, "source": str, "tags": [str]}``
    dicts with empty defaults for missing fields so the downstream
    refs builder can iterate uniformly.
    """
    out = []
    if not isinstance(cve, dict):
        return out
    refs = cve.get("references")
    if not isinstance(refs, list):
        return out
    for entry in refs:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        source = entry.get("source") if isinstance(entry.get("source"), str) else ""
        tags = entry.get("tags") if isinstance(entry.get("tags"), list) else []
        tag_list = [t.strip() for t in tags if isinstance(t, str) and t.strip()]
        out.append({"url": url.strip(), "source": source.strip(), "tags": tag_list})
    return out


def severity_from_cvss(cvss):
    """Map an NVD CVSS metric block to a Faraday severity bucket.

    Prefers the explicit ``baseSeverity`` text when present
    (``CRITICAL`` / ``HIGH`` / ``MEDIUM`` / ``LOW`` / ``NONE``);
    falls back to numeric ``baseScore`` bucketing otherwise.
    Returns ``None`` when the block is missing entirely so the
    caller can choose its own default (we surface unscored CVEs
    as ``info`` to avoid synthesising a ranking NVD hasn't
    published).
    """
    if not isinstance(cvss, dict):
        return None
    sev_text = cvss.get("baseSeverity")
    if isinstance(sev_text, str):
        mapped = NVD_BASE_SEVERITY_MAP.get(sev_text.strip().upper())
        if mapped:
            return mapped
    score = cvss.get("baseScore")
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


def is_rejected(cve):
    """Return True when NVD has withdrawn the CVE record."""
    if not isinstance(cve, dict):
        return False
    status = cve.get("vulnStatus")
    if isinstance(status, str) and status.strip().lower() == "rejected":
        return True
    desc = extract_description(cve)
    return desc.startswith("** REJECT **") or desc.startswith("** REJECTED **")


def collect_cves(cve):
    """Pull the canonical CVE id from an NVD record.

    NVD records are CVE-keyed (every entry has an ``id``) so this
    is a single-element list under normal operation.  We still
    return a list for parity with the Faraday vulnerability
    schema's repeated-CVE shape.
    """
    out = []
    if not isinstance(cve, dict):
        return out
    raw = cve.get("id")
    if isinstance(raw, str) and raw.strip():
        out.append(raw.strip().upper())
    return out


def collect_refs(cve, response_meta):
    """Build the refs list for one NVD CVE record.

    Includes the canonical NVD CVE permalink, every advisory URL
    NVD attached (with the source vendor + tag set surfaced as a
    suffix), and explicit ``Nvd-*`` pivots (cve id, status,
    published / lastModified, source identifier, CVSS score +
    severity + version + vector, CWE list, response timestamp)
    so operators can pivot from a Faraday finding back to the
    exact NVD response field set.
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

    if not isinstance(cve, dict):
        return refs

    cve_id = str(cve.get("id") or "").strip()
    if cve_id:
        add(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        add(f"Nvd-CveID: {cve_id}")

    status = cve.get("vulnStatus")
    if isinstance(status, str) and status.strip():
        add(f"Nvd-Status: {status.strip()}")

    source_id = cve.get("sourceIdentifier")
    if isinstance(source_id, str) and source_id.strip():
        add(f"Nvd-Source: {source_id.strip()}")

    published = cve.get("published")
    if isinstance(published, str) and published.strip():
        add(f"Nvd-Published: {published.strip()}")

    last_mod = cve.get("lastModified")
    if isinstance(last_mod, str) and last_mod.strip():
        add(f"Nvd-LastModified: {last_mod.strip()}")

    cvss = extract_cvss(cve)
    if cvss is not None:
        add(f"Nvd-CvssVersion: {cvss['version']}")
        add(f"Nvd-CvssScore: {cvss['baseScore']}")
        if cvss.get("baseSeverity"):
            add(f"Nvd-CvssSeverity: {cvss['baseSeverity']}")
        if cvss.get("vectorString"):
            add(f"Nvd-CvssVector: {cvss['vectorString']}")

    for cwe in extract_cwes(cve):
        add(f"Nvd-CWE: {cwe}")

    for entry in extract_references(cve):
        url = entry.get("url") or ""
        if not url:
            continue
        tag_text = ""
        tags = entry.get("tags") or []
        if tags:
            tag_text = f" [{', '.join(tags)}]"
        source = entry.get("source") or ""
        if source:
            tag_text = f" ({source}){tag_text}"
        add(f"{url}{tag_text}")

    if isinstance(response_meta, dict):
        timestamp = response_meta.get("timestamp")
        if timestamp not in (None, ""):
            add(f"Nvd-ResponseTimestamp: {timestamp}")
        version = response_meta.get("version")
        if version not in (None, ""):
            add(f"Nvd-FeedVersion: {version}")
    return refs


def build_vulnerability(cve, response_meta):
    """Build a Faraday vulnerability dict for one NVD CVE record."""
    if not isinstance(cve, dict):
        return None

    cve_id = str(cve.get("id") or "").strip()
    description = extract_description(cve)
    status = cve.get("vulnStatus") if isinstance(cve.get("vulnStatus"), str) else ""
    status = status.strip() if status else ""
    rejected = is_rejected(cve)
    cvss = extract_cvss(cve)

    if rejected:
        severity = "info"
    else:
        sev = severity_from_cvss(cvss)
        severity = sev if sev else "info"

    summary = description.split(".")[0].strip() if description else ""
    name_parts = []
    if rejected:
        name_parts.append("[REJECTED]")
    if cve_id:
        name_parts.append(cve_id)
    if summary:
        name_parts.append(summary[:150])
    raw_name = ": ".join(name_parts) if name_parts else "NVD CVE entry"
    name = f"[NVD] {raw_name}"

    desc_parts = []
    if cve_id:
        desc_parts.append(f"id: {cve_id}")
    if status:
        desc_parts.append(f"vulnStatus: {status}")
    if rejected:
        desc_parts.append("note: NVD has withdrawn this CVE")
    source_id = cve.get("sourceIdentifier")
    if isinstance(source_id, str) and source_id.strip():
        desc_parts.append(f"sourceIdentifier: {source_id.strip()}")
    published = cve.get("published")
    if isinstance(published, str) and published.strip():
        desc_parts.append(f"published: {published.strip()}")
    last_mod = cve.get("lastModified")
    if isinstance(last_mod, str) and last_mod.strip():
        desc_parts.append(f"lastModified: {last_mod.strip()}")
    if cvss is not None:
        desc_parts.append(
            f"cvss{cvss['version']}: baseScore={cvss['baseScore']} " f"severity={cvss['baseSeverity'] or 'n/a'}"
        )
        if cvss.get("vectorString"):
            desc_parts.append(f"cvssVector: {cvss['vectorString']}")
    cwes = extract_cwes(cve)
    if cwes:
        desc_parts.append(f"cwes: {', '.join(cwes)}")
    refs_inline = extract_references(cve)
    if refs_inline:
        desc_parts.append(f"references: {len(refs_inline)}")
    if description:
        desc_parts.append(f"description: {description}")
    if isinstance(response_meta, dict):
        version = response_meta.get("version")
        if version not in (None, ""):
            desc_parts.append(f"feedVersion: {version}")
        timestamp = response_meta.get("timestamp")
        if timestamp not in (None, ""):
            desc_parts.append(f"responseTimestamp: {timestamp}")

    has_patch_ref = any(any(t.lower() == "patch" for t in (entry.get("tags") or [])) for entry in refs_inline)
    if rejected:
        resolution = "NVD has withdrawn this CVE; no remediation action required."
    elif has_patch_ref:
        resolution = (
            f"Apply vendor patches for {cve_id or 'the affected product'} " "per the Patch-tagged NVD references."
        )
    else:
        resolution = (
            f"Track {cve_id or 'this CVE'} via the NVD references and apply "
            "vendor mitigations as they are published."
        )

    external_id = cve_id or name[:200]

    return {
        "name": str(name).strip()[:200] or "NVD CVE entry",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(cve, response_meta),
        "cve": collect_cves(cve),
        "cvss3": {},
        "tags": ["nist-nvd"],
    }


def build_host(vulns, response_meta, mode_desc):
    """Build the single synthetic host that carries every NVD vuln.

    NVD entries are CVE-keyed not host-keyed (the operator's
    other agents emit the host-side findings this feed is
    correlated against) so we collapse the whole feed under one
    synthetic ``0.0.0.0`` host with hostname ``nist-nvd``.  The
    host description carries the response envelope metadata + the
    operational mode (``cves=...`` or ``window_days=...``) so
    operators can pivot from the host page back to the exact NVD
    response that produced the run.
    """
    desc_parts = ["source=nist-nvd"]
    if mode_desc:
        desc_parts.append(mode_desc)
    if isinstance(response_meta, dict):
        for key in ("totalResults", "format", "version", "timestamp"):
            v = response_meta.get(key)
            if v in (None, ""):
                continue
            desc_parts.append(f"{key}={v}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["nist-nvd"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url, api_key):
    """GET a single NVD URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient NVD outage doesn't crash the
    dispatcher.  Returns ``None`` on any failure; the caller is
    expected to treat that as "no records" and continue.
    """
    try:
        resp = requests_module.get(
            url,
            timeout=TIMEOUT,
            headers=request_headers(api_key),
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"NVD record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"NVD request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"NVD response was not JSON ({url})")
        return None


def fetch_cves(requests_module, host, cve_list, api_key, sleep_fn=time.sleep):
    """Walk NVD_CVE_LIST and accumulate per-CVE records + meta.

    Returns a tuple ``(records, response_meta)`` where ``records``
    is the unwrapped ``cve`` list and ``response_meta`` is pulled
    from the most-recent successful response (used for provenance
    on the synthetic host).  ``sleep_fn`` is injectable to keep
    unit tests fast.
    """
    records = []
    meta = {}
    sleep_for = rate_limit_sleep_seconds(api_key)
    for idx, cve_id in enumerate(cve_list):
        if idx > 0 and sleep_for > 0:
            sleep_fn(sleep_for)
        url = build_cve_url(host, cve_id)
        body = fetch_url(requests_module, url, api_key)
        if body is None:
            continue
        meta = extract_response_meta(body) or meta
        for entry in extract_vulnerabilities(body):
            records.append(entry)
    return records, meta


def fetch_window(requests_module, host, start_dt, end_dt, api_key, sleep_fn=time.sleep, max_pages=200):
    """Page through NVD's lastModified window and accumulate records.

    Loops while ``startIndex + resultsPerPage < totalResults``,
    capped at ``max_pages`` to prevent runaway loops on a broken
    upstream that always reports a huge totalResults.  Returns
    the same ``(records, response_meta)`` tuple as ``fetch_cves``.
    """
    records = []
    meta = {}
    sleep_for = rate_limit_sleep_seconds(api_key)
    start_index = 0
    page = 0
    while page < max_pages:
        if page > 0 and sleep_for > 0:
            sleep_fn(sleep_for)
        url = build_window_url(host, start_dt, end_dt, start_index, RESULTS_PER_PAGE)
        body = fetch_url(requests_module, url, api_key)
        if body is None:
            break
        meta = extract_response_meta(body) or meta
        for entry in extract_vulnerabilities(body):
            records.append(entry)
        total = meta.get("totalResults")
        try:
            total_int = int(total)
        except (TypeError, ValueError):
            break
        start_index += RESULTS_PER_PAGE
        if start_index >= total_int:
            break
        page += 1
    return records, meta


def main():
    started = time.time()

    cve_list = validate_cve_list(env("EXECUTOR_CONFIG_NVD_CVE_LIST"))
    days = validate_last_mod_days(env("EXECUTOR_CONFIG_NVD_LAST_MOD_DAYS"))
    host = env("NVD_HOST", default=DEFAULT_HOST)
    api_key = env("NVD_API_KEY")

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    if cve_list:
        mode = "cves"
        mode_desc = f"cves={len(cve_list)}"
        records, response_meta = fetch_cves(requests, host, cve_list, api_key)
    else:
        mode = "window"
        now_dt = datetime.now(tz=timezone.utc)
        start_dt, end_dt = compute_window(now_dt, days)
        mode_desc = f"window_days={days}"
        records, response_meta = fetch_window(requests, host, start_dt, end_dt, api_key)

    vulns = []
    for entry in records:
        vuln = build_vulnerability(entry, response_meta)
        if vuln is not None:
            vulns.append(vuln)

    log(
        f"Processed {len(vulns)} NVD records "
        f"(mode={mode}, totalResults={response_meta.get('totalResults', '?')}, "
        f"api_key={'set' if (isinstance(api_key, str) and api_key.strip()) else 'none'})"
    )

    hosts_out = [build_host(vulns, response_meta, mode_desc)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "nist_nvd",
            "command": "nist_nvd",
            "params": (f"mode={mode} " f"cves={len(cve_list)} " f"window_days={days if not cve_list else ''}"),
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
