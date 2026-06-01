#!/usr/bin/env python
"""FIRST EPSS (Exploit Prediction Scoring System) importer.

Pulls per-CVE Exploit Prediction Scoring System (EPSS) scores
from the FIRST EPSS REST API
(``https://api.first.org/data/v1/epss``) and emits Faraday
bulk-create JSON to stdout.  EPSS is a stochastic model
maintained by the FIRST.org EPSS SIG that estimates the
probability a CVE will be exploited in the next 30 days; the
catalog is re-scored daily and the data is fully public and
unauthenticated.

Each requested CVE becomes one Faraday vulnerability under a
single synthetic ``0.0.0.0`` host with hostname ``first-epss``.
EPSS entries are CVE-keyed not host-keyed — the operator's
other agents emit the host-side findings this feed is correlated
against.  The vulnerability carries ``tags: ['first-epss']`` and
surfaces the EPSS probability + percentile + scoring date in
both the description and the refs list so the operator can pivot
from a Faraday finding back to the FIRST EPSS scoring snapshot.

Endpoint used:
  GET {EPSS_HOST}/data/v1/epss?cve=CVE-1,CVE-2,...
      -> Returns the canonical envelope:
      ``{"status": "OK", "status-code": 200, "version": "1.0",
        "access": "public", "total": N, "offset": 0, "limit": M,
        "data": [{"cve": "CVE-...", "epss": "0.NNNNN",
                   "percentile": "0.NNNNN", "date": "YYYY-MM-DD"}]}``

``EPSS_CVES`` is a mandatory CSV of CVE ids — the executor
batches them up to 100 per request (the FIRST EPSS documented
``limit`` ceiling) and issues one HTTP GET per batch via the
``?cve=CVE-1,CVE-2,...`` comma-list shape.  Malformed entries
(not matching ``CVE-YYYY-N+``) are dropped with a warning so a
single typo doesn't abort the run.  Whitespace is trimmed and
duplicate CVEs (case-insensitive) are deduped while preserving
the operator's preferred order.

``EPSS_MIN_PROBABILITY`` is an optional client-side filter
(``0.0`` .. ``1.0`` as a string-coerceable float).  Records
whose EPSS probability is strictly below the filter are dropped
client-side after the catalog is fetched (the FIRST EPSS API
also supports server-side filtering via ``epss-gt=`` but we
keep filtering client-side for parity with the rest of the
threat-intel executors in this group).  Blank / missing /
unparseable input keeps every scored record.

Severity is bucketed by EPSS probability:
  - prob >= 0.9   -> critical  (top ~0.1% of CVEs by exploitability)
  - prob >= 0.5   -> high
  - prob >= 0.1   -> medium
  - prob >= 0.01  -> low
  - prob <  0.01  -> info

EPSS records returned without a parseable probability are
surfaced as ``info`` — we don't synthesise a ranking the model
hasn't published.  CVEs the operator listed but that the FIRST
EPSS catalog has no record of (typical for very recent CVEs the
model has not yet scored) are skipped silently; the count is
logged so the operator can correlate input vs. output.

Auth: none — the FIRST EPSS API is fully public and
unauthenticated.  ``EPSS_HOST`` may optionally be overridden via
env to point at a mirror or an offline cache; defaults to
``https://api.first.org``.  The executor does NOT consume any
secrets / credentials / tokens.
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
DEFAULT_HOST = "https://api.first.org"
EPSS_PATH = "/data/v1/epss"
MAX_CVES_PER_REQUEST = 100

# Small inter-batch sleep to be a friendly neighbour to the
# FIRST EPSS public API; the documented limit is generous but a
# 300ms pause keeps a 100-CVE multi-batch run polite without
# meaningfully extending wall-clock for typical inputs.
SLEEP_BETWEEN_BATCHES = 0.3

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(f"{datetime.utcnow()} - FirstEpss: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on EPSS_HOST.

    Defaults to ``https://api.first.org`` (the canonical FIRST
    EPSS host) when the env override is missing / blank.
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
    """Normalise EPSS_CVES into a list of well-formed CVE ids.

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
            log(f"EPSS_CVES entry {cve!r} is not a valid CVE id; skipping")
            continue
        if upper in seen:
            continue
        seen.add(upper)
        out.append(upper)
    return out


def validate_min_probability(value):
    """Coerce EPSS_MIN_PROBABILITY into a 0.0..1.0 float.

    None / blank / unparseable -> ``None`` (no filtering — every
    scored record is kept).  Values below 0.0 are clamped to 0.0
    (effectively keeping every record); values above 1.0 are
    clamped to 1.0 (effectively dropping every record — explicit
    operator choice, not a silent no-op).
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        log(f"EPSS_MIN_PROBABILITY {value!r} is a bool, not a float; " "ignoring (every scored record will be kept)")
        return None
    try:
        prob = float(str(value).strip())
    except (TypeError, ValueError):
        log(f"EPSS_MIN_PROBABILITY {value!r} is not a float; " "ignoring (every scored record will be kept)")
        return None
    if prob < 0.0:
        log(f"EPSS_MIN_PROBABILITY {prob} below 0.0; clamping to 0.0")
        return 0.0
    if prob > 1.0:
        log(f"EPSS_MIN_PROBABILITY {prob} above 1.0; clamping to 1.0")
        return 1.0
    return prob


def chunk_cves(cves, size=MAX_CVES_PER_REQUEST):
    """Split a CVE list into batches of ``size`` (default 100).

    The FIRST EPSS API caps each response at ``limit=100`` so we
    batch into 100-CVE chunks; smaller chunks are supported for
    test fixtures.  Non-list / empty input yields an empty
    iterator.
    """
    if not isinstance(cves, list):
        return
    try:
        step = int(size)
    except (TypeError, ValueError):
        step = MAX_CVES_PER_REQUEST
    if step <= 0:
        step = MAX_CVES_PER_REQUEST
    for i in range(0, len(cves), step):
        yield cves[i : i + step]


def build_url(host, cves, offset=0, limit=MAX_CVES_PER_REQUEST):
    """Build the EPSS query URL for one batch of CVEs.

    The ``cve`` parameter is comma-separated per FIRST's
    documentation; we url-encode the whole comma-list so the
    response query string is unambiguous in audit logs.
    ``offset`` / ``limit`` keep us compatible with paged
    responses for futureproofing — under the current FIRST API
    a 100-CVE batch fits in a single response.
    """
    if not isinstance(cves, list):
        cves = []
    cve_param = ",".join(str(c).strip().upper() for c in cves if str(c).strip())
    query_pairs = []
    if cve_param:
        query_pairs.append(("cve", cve_param))
    try:
        query_pairs.append(("offset", int(offset)))
    except (TypeError, ValueError):
        query_pairs.append(("offset", 0))
    try:
        query_pairs.append(("limit", int(limit)))
    except (TypeError, ValueError):
        query_pairs.append(("limit", MAX_CVES_PER_REQUEST))
    query = urlencode(query_pairs)
    return f"{normalize_base_url(host)}{EPSS_PATH}?{query}"


def parse_probability(value):
    """Parse an EPSS probability / percentile field into a float.

    FIRST EPSS returns scores as strings (``"0.97534"``); we
    coerce defensively and return ``None`` for missing /
    unparseable / bool / out-of-range values so the caller can
    bucket safely.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        prob = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if prob != prob:  # NaN check
        return None
    if prob < 0.0 or prob > 1.0:
        return None
    return prob


def severity_from_epss(prob):
    """Bucket Faraday severity by EPSS probability.

    The thresholds reflect the FIRST EPSS SIG's recommended
    prioritisation guidance — anything above 0.5 is treated as a
    high-confidence exploit prediction; anything below 0.01 is
    the long-tail noise floor where the model has effectively no
    signal.

    Returns ``info`` when ``prob`` is ``None`` so unscored CVEs
    still appear in the workspace (the operator can use the
    absence as a signal in its own right).
    """
    if prob is None:
        return "info"
    if prob >= 0.9:
        return "critical"
    if prob >= 0.5:
        return "high"
    if prob >= 0.1:
        return "medium"
    if prob >= 0.01:
        return "low"
    return "info"


def extract_data(body):
    """Pull the ``data`` records list from an EPSS response envelope.

    FIRST EPSS wraps records under ``data``; federated / mirror
    stacks may use bare-list / top-level ``vulnerabilities`` /
    ``results`` / ``items`` — accept all for resilience.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("data", "vulnerabilities", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_envelope_meta(body):
    """Pull envelope-level metadata for provenance.

    Returns whatever FIRST-documented fields are present (status,
    version, access, total, offset, limit).  Used to embed
    catalog-version-style breadcrumbs on the synthetic host so
    operators can pivot from a Faraday finding back to the
    response that produced it.
    """
    out = {}
    if not isinstance(body, dict):
        return out
    for key in (
        "status",
        "status-code",
        "version",
        "access",
        "total",
        "offset",
        "limit",
    ):
        v = body.get(key)
        if v in (None, ""):
            continue
        out[key] = v
    return out


def filter_by_min_probability(items, min_prob):
    """Apply the EPSS_MIN_PROBABILITY filter client-side.

    Drops records whose ``epss`` probability is strictly below
    ``min_prob``.  Records with missing / unparseable ``epss``
    are DROPPED when a filter is set (we cannot prove they meet
    the threshold) but KEPT when ``min_prob`` is ``None`` (the
    typical operational mode where the operator wants every
    scored CVE).  When ``min_prob`` is ``None`` the whole list
    passes through unchanged.
    """
    if min_prob is None:
        return list(items) if isinstance(items, list) else []
    out = []
    if not isinstance(items, list):
        return out
    for entry in items:
        if not isinstance(entry, dict):
            continue
        prob = parse_probability(entry.get("epss"))
        if prob is None:
            continue
        if prob >= min_prob:
            out.append(entry)
    return out


def collect_refs(record, envelope_meta):
    """Build the refs list for one EPSS record.

    Includes the canonical NVD CVE permalink, the FIRST EPSS API
    query URL for the CVE, and explicit ``Epss-*`` pivots
    (probability / percentile / scoring date / model version) so
    operators can pivot from a Faraday finding back to the exact
    EPSS scoring snapshot.
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

    cve = str(record.get("cve") or "").strip().upper()
    if cve:
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")
        add(f"https://api.first.org/data/v1/epss?cve={cve}")
        add(f"Epss-CveID: {cve}")

    prob = parse_probability(record.get("epss"))
    if prob is not None:
        add(f"Epss-Probability: {prob}")
    pct = parse_probability(record.get("percentile"))
    if pct is not None:
        add(f"Epss-Percentile: {pct}")
    score_date = str(record.get("date") or "").strip()
    if score_date:
        add(f"Epss-ScoringDate: {score_date}")

    if isinstance(envelope_meta, dict):
        version = envelope_meta.get("version")
        if version not in (None, ""):
            add(f"Epss-ModelVersion: {version}")
        access = envelope_meta.get("access")
        if access not in (None, ""):
            add(f"Epss-Access: {access}")
    return refs


def collect_cves(record):
    """Pull the canonical CVE id from an EPSS record.

    EPSS records are CVE-keyed (every entry has a ``cve``) so
    this is a single-element list under normal operation.  We
    still return a list for parity with the Faraday vulnerability
    schema's repeated-CVE shape.
    """
    out = []
    if not isinstance(record, dict):
        return out
    raw = record.get("cve")
    if isinstance(raw, str) and raw.strip():
        out.append(raw.strip().upper())
    return out


def build_vulnerability(record, envelope_meta):
    """Build a Faraday vulnerability dict for one EPSS record."""
    if not isinstance(record, dict):
        return None

    cve = str(record.get("cve") or "").strip().upper()
    prob = parse_probability(record.get("epss"))
    pct = parse_probability(record.get("percentile"))
    score_date = str(record.get("date") or "").strip()
    severity = severity_from_epss(prob)

    title_parts = []
    if cve:
        title_parts.append(cve)
    if prob is not None:
        title_parts.append(f"EPSS={prob:.5f}")
    elif score_date:
        title_parts.append(f"scored {score_date}")
    raw_name = ": ".join(title_parts) if title_parts else "FIRST EPSS record"
    name = f"[EPSS] {raw_name}"

    desc_parts = []
    if cve:
        desc_parts.append(f"cve: {cve}")
    if prob is not None:
        desc_parts.append(f"epss: {prob}")
    else:
        desc_parts.append("epss: (unscored)")
    if pct is not None:
        desc_parts.append(f"percentile: {pct}")
    if score_date:
        desc_parts.append(f"date: {score_date}")
    if prob is not None:
        if prob >= 0.9:
            desc_parts.append(
                "interpretation: very high probability of exploitation " "in the next 30 days (top ~0.1% by EPSS)"
            )
        elif prob >= 0.5:
            desc_parts.append("interpretation: high probability of exploitation in " "the next 30 days")
        elif prob >= 0.1:
            desc_parts.append("interpretation: meaningful probability of exploitation " "in the next 30 days")
        elif prob >= 0.01:
            desc_parts.append("interpretation: low but non-trivial probability of " "exploitation in the next 30 days")
        else:
            desc_parts.append(
                "interpretation: negligible probability of exploitation " "in the next 30 days (long-tail noise floor)"
            )
    if isinstance(envelope_meta, dict):
        version = envelope_meta.get("version")
        if version not in (None, ""):
            desc_parts.append(f"modelVersion: {version}")
        access = envelope_meta.get("access")
        if access not in (None, ""):
            desc_parts.append(f"access: {access}")

    if prob is not None:
        resolution = (
            f"Prioritise patching {cve or 'this CVE'} according to the "
            f"FIRST EPSS probability ({prob:.5f}); cross-reference with "
            "your asset inventory and the CISA KEV catalog before "
            "scheduling remediation."
        )
    else:
        resolution = (
            f"FIRST EPSS has not yet scored {cve or 'this CVE'}; track "
            "the scoring date below and re-run the executor once a score "
            "is published."
        )

    external_id = cve or name[:200]

    return {
        "name": str(name).strip()[:200] or "FIRST EPSS record",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(record, envelope_meta),
        "cve": collect_cves(record),
        "cvss3": {},
        "tags": ["first-epss"],
    }


def build_host(vulns, envelope_meta, cve_count):
    """Build the single synthetic host that carries every EPSS vuln.

    EPSS entries are CVE-keyed not host-keyed (the operator's
    other agents emit the host-side findings this feed is
    correlated against) so we collapse the whole batch under one
    synthetic ``0.0.0.0`` host with hostname ``first-epss``.  The
    host description carries the envelope metadata + the
    requested CVE count so operators can pivot from the host
    page back to the exact EPSS response that produced the run.
    """
    desc_parts = ["source=first-epss"]
    try:
        desc_parts.append(f"cves_requested={int(cve_count)}")
    except (TypeError, ValueError):
        desc_parts.append("cves_requested=?")
    if isinstance(envelope_meta, dict):
        for key in ("version", "access", "total"):
            v = envelope_meta.get(key)
            if v in (None, ""):
                continue
            desc_parts.append(f"{key}={v}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["first-epss"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url):
    """GET a single FIRST EPSS URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient FIRST EPSS outage doesn't crash the
    dispatcher.  Returns ``None`` on any failure; the caller is
    expected to treat that as "no records" and continue with the
    next batch.
    """
    try:
        resp = requests_module.get(
            url,
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"EPSS record not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"EPSS request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"EPSS response was not JSON ({url})")
        return None


def fetch_batches(requests_module, host, cve_list, sleep_fn=time.sleep, batch_size=MAX_CVES_PER_REQUEST):
    """Walk EPSS_CVES in batches and accumulate records + meta.

    Returns a tuple ``(records, envelope_meta)`` where ``records``
    is the accumulated ``data`` list across every batch and
    ``envelope_meta`` is pulled from the most-recent successful
    response (used for provenance on the synthetic host).
    ``sleep_fn`` is injectable to keep unit tests fast.
    """
    records = []
    meta = {}
    if not isinstance(cve_list, list) or not cve_list:
        return records, meta
    batches = list(chunk_cves(cve_list, batch_size))
    for idx, batch in enumerate(batches):
        if idx > 0 and SLEEP_BETWEEN_BATCHES > 0:
            sleep_fn(SLEEP_BETWEEN_BATCHES)
        url = build_url(host, batch, offset=0, limit=batch_size)
        body = fetch_url(requests_module, url)
        if body is None:
            continue
        meta = extract_envelope_meta(body) or meta
        for entry in extract_data(body):
            records.append(entry)
    return records, meta


def main():
    started = time.time()

    cve_list = validate_cve_list(env("EXECUTOR_CONFIG_EPSS_CVES", required=True))
    if not cve_list:
        log("EPSS_CVES yielded no valid CVE ids; nothing to fetch")
        sys.exit(1)
    min_prob = validate_min_probability(env("EXECUTOR_CONFIG_EPSS_MIN_PROBABILITY"))
    host = env("EPSS_HOST", default=DEFAULT_HOST)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    records, envelope_meta = fetch_batches(requests, host, cve_list)
    records = filter_by_min_probability(records, min_prob)

    vulns = []
    for entry in records:
        vuln = build_vulnerability(entry, envelope_meta)
        if vuln is not None:
            vulns.append(vuln)

    log(
        f"Processed {len(vulns)} EPSS records "
        f"(cves_requested={len(cve_list)}, "
        f"min_probability={min_prob if min_prob is not None else 'none'}, "
        f"total={envelope_meta.get('total', '?')})"
    )

    hosts_out = [build_host(vulns, envelope_meta, len(cve_list))]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "first_epss",
            "command": "first_epss",
            "params": (f"cves={len(cve_list)} " f"min_probability={min_prob if min_prob is not None else ''}"),
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
