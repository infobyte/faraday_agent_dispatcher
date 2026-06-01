#!/usr/bin/env python
"""CISA Known Exploited Vulnerabilities (KEV) catalog importer.

Pulls the public CISA KEV catalog from
``https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json``
and emits Faraday bulk-create JSON to stdout.  The KEV catalog is
CISA's authoritative list of CVEs that are actively exploited in
the wild — federal civilian agencies are required to remediate
every KEV entry by the catalog-published ``dueDate`` under BOD
22-01, so the catalog doubles as both a "this is being exploited
right now" feed and a regulatory deadline tracker for any operator
who has chosen to align with BOD 22-01.

Each KEV record becomes one Faraday vulnerability under a single
synthetic ``0.0.0.0`` host (KEV entries are CVE-keyed not host-
keyed — the operator's other agents emit the host-side findings
this feed is correlated against).  The vulnerability carries
``tags: ['cisa-kev']`` and surfaces ``dateAdded`` / ``dueDate`` in
both the description and the refs list so the deadline is one
projection away from the Faraday workspace UI.

Endpoint used:
  GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      -> Returns the canonical KEV catalog envelope:
      ``{"title": "...", "catalogVersion": "...",
      "dateReleased": "...", "count": N,
      "vulnerabilities": [{...}, ...]}`` where each
      ``vulnerabilities`` record carries ``cveID``,
      ``vendorProject``, ``product``, ``vulnerabilityName``,
      ``dateAdded`` (YYYY-MM-DD — the date CISA added the CVE to
      the KEV catalog), ``shortDescription``, ``requiredAction``,
      ``dueDate`` (YYYY-MM-DD — the BOD 22-01 remediation
      deadline for federal civilian agencies), optional
      ``knownRansomwareCampaignUse`` (``Known`` / ``Unknown``),
      optional ``notes`` (free-form text), and optional ``cwes``
      (list of ``CWE-NNN`` strings).

``KEV_MIN_DATE`` is an optional date filter (YYYY-MM-DD) — when
supplied, KEV entries whose ``dateAdded`` is strictly older than
the filter are dropped client-side (the CISA feed has no server-
side filtering; this knob is purely a "I only care about KEVs
added since X" delta-import lever for operators who run the
executor on a schedule).  Blank / missing / unparseable input
walks the whole catalog (the typical operational mode).

Severity is bucketed by how close the BOD 22-01 ``dueDate`` is:
  - ``dueDate`` in the past             -> critical (overdue)
  - ``dueDate`` within the next 14 days -> high
  - ``dueDate`` within the next 60 days -> medium
  - ``dueDate`` further out             -> low
  - ``dueDate`` missing / unparseable   -> high (default; KEV
                                          entries are by
                                          definition actively
                                          exploited so the floor
                                          is high, not info)

KEV records flagged ``knownRansomwareCampaignUse: "Known"`` are
bumped to ``critical`` regardless of the dueDate ladder — active
ransomware exploitation overrides the calendar floor.

Auth: none — the CISA KEV feed is fully public and unauthenticated.
``CISA_KEV_HOST`` may optionally be overridden via env to point at
a mirror or an offline cache; defaults to
``https://www.cisa.gov``.  The executor does NOT consume any
secrets / credentials / tokens.
"""

import json
import os
import socket
import sys
import time
from datetime import date, datetime, timezone

TIMEOUT = 60
DEFAULT_HOST = "https://www.cisa.gov"
KEV_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(f"{datetime.utcnow()} - CisaKev: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on CISA_KEV_HOST.

    Defaults to ``https://www.cisa.gov`` (the canonical CISA KEV
    host) when the env override is missing / blank.  Whitespace is
    trimmed and ``https://`` is added automatically when the
    operator pasted in a bare FQDN (on-prem mirrors typically use
    raw hostnames).
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


def build_kev_url(host):
    """Build the canonical KEV catalog URL."""
    return f"{normalize_base_url(host)}{KEV_PATH}"


def parse_iso_date(value):
    """Parse a YYYY-MM-DD (or full ISO 8601) string into a ``date``.

    Returns ``None`` for non-string / unparseable / bool inputs.
    CISA dates are canonical YYYY-MM-DD but we accept the same
    permissive shape as the other executors in this repo so a
    federated mirror that re-emits timestamps doesn't break the
    parse.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    text = str(value).strip()
    if not text:
        return None
    head = text[:10]
    try:
        return datetime.strptime(head, "%Y-%m-%d").date()
    except ValueError:
        return None


def validate_min_date(value):
    """Validate KEV_MIN_DATE (YYYY-MM-DD).

    None / blank / unparseable -> ``None`` (no filtering — the
    whole catalog is walked).  Whitespace is trimmed.  Forwarded
    as a client-side filter against each KEV record's
    ``dateAdded``; the CISA feed has no server-side filter so this
    is the only narrowing knob exposed by the manifest.
    """
    if value is None or value == "":
        return None
    parsed = parse_iso_date(value)
    if parsed is None:
        log(f"KEV_MIN_DATE '{value}' is not a YYYY-MM-DD date; " "ignoring (the whole catalog will be walked)")
        return None
    return parsed


def extract_vulnerabilities(body):
    """Pull the vulnerabilities list from a KEV catalog envelope.

    CISA wraps the records under ``vulnerabilities``.  Federated /
    mirror stacks may use bare-list / top-level ``data`` /
    ``results`` / ``items`` — accept all for resilience.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("vulnerabilities", "data", "results", "items"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_catalog_meta(body):
    """Pull catalog-level metadata (title / version / dateReleased / count).

    Returns a dict with whatever keys are present.  Used to embed
    catalog provenance in the per-vulnerability description so the
    operator can pivot from a Faraday finding back to the exact
    catalog version that produced it.
    """
    out = {}
    if not isinstance(body, dict):
        return out
    for key in ("title", "catalogVersion", "dateReleased", "count"):
        v = body.get(key)
        if v in (None, ""):
            continue
        out[key] = v
    return out


def severity_from_due_date(due_date, today, ransomware=False):
    """Bucket severity by how close the BOD 22-01 ``dueDate`` is.

    The ladder picks intentionally coarse cut-offs so the executor
    produces stable severity across runs even as ``today`` advances:
      - ``dueDate`` in the past             -> critical
      - ``dueDate`` within the next 14 days -> high
      - ``dueDate`` within the next 60 days -> medium
      - ``dueDate`` further out             -> low
      - ``dueDate`` missing / unparseable   -> high

    KEV records flagged ``knownRansomwareCampaignUse: "Known"``
    are bumped to ``critical`` regardless of the dueDate — active
    ransomware exploitation overrides the calendar floor.
    """
    if ransomware:
        return "critical"
    if due_date is None:
        return "high"
    delta = (due_date - today).days
    if delta < 0:
        return "critical"
    if delta <= 14:
        return "high"
    if delta <= 60:
        return "medium"
    return "low"


def ransomware_flag(item):
    """Return True when ``knownRansomwareCampaignUse`` is ``Known``."""
    if not isinstance(item, dict):
        return False
    raw = item.get("knownRansomwareCampaignUse")
    if not isinstance(raw, str):
        return False
    return raw.strip().lower() == "known"


def collect_refs(item, catalog_meta):
    """Build the refs list for one KEV record.

    Includes the canonical CISA KEV permalink, the NVD CVE
    pivot, the catalog version pivot, and explicit ``Kev-*`` refs
    so operators can pivot from a Faraday finding back to the
    catalog field set (dateAdded / dueDate / vendor / product /
    cwe / ransomware flag).
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

    if not isinstance(item, dict):
        return refs

    cve = str(item.get("cveID") or "").strip()
    if cve:
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")
        add(f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cve}")
        add(f"Kev-CveID: {cve}")
    date_added = str(item.get("dateAdded") or "").strip()
    if date_added:
        add(f"Kev-DateAdded: {date_added}")
    due_date = str(item.get("dueDate") or "").strip()
    if due_date:
        add(f"Kev-DueDate: {due_date}")
    vendor = str(item.get("vendorProject") or "").strip()
    if vendor:
        add(f"Kev-Vendor: {vendor}")
    product = str(item.get("product") or "").strip()
    if product:
        add(f"Kev-Product: {product}")
    if ransomware_flag(item):
        add("Kev-Ransomware: Known")
    cwes = item.get("cwes")
    if isinstance(cwes, list):
        for cwe in cwes:
            if isinstance(cwe, str) and cwe.strip():
                add(f"Kev-CWE: {cwe.strip()}")
    if isinstance(catalog_meta, dict):
        version = catalog_meta.get("catalogVersion")
        if version not in (None, ""):
            add(f"Kev-CatalogVersion: {version}")
        released = catalog_meta.get("dateReleased")
        if released not in (None, ""):
            add(f"Kev-CatalogReleased: {released}")
    return refs


def collect_cves(item):
    """Pull the canonical CVE id from a KEV record.

    The KEV catalog is CVE-keyed (every entry has a ``cveID``) so
    this is a single-element list under normal operation.  We
    still return a list for parity with the Faraday vulnerability
    schema's repeated-CVE shape.
    """
    out = []
    if not isinstance(item, dict):
        return out
    raw = item.get("cveID")
    if isinstance(raw, str) and raw.strip():
        out.append(raw.strip().upper())
    return out


def build_vulnerability(item, catalog_meta, today):
    """Build a Faraday vulnerability dict for one KEV record."""
    if not isinstance(item, dict):
        return None

    cve = str(item.get("cveID") or "").strip()
    name_field = str(item.get("vulnerabilityName") or "").strip()
    vendor = str(item.get("vendorProject") or "").strip()
    product = str(item.get("product") or "").strip()
    short_desc = str(item.get("shortDescription") or "").strip()
    required_action = str(item.get("requiredAction") or "").strip()
    notes = str(item.get("notes") or "").strip()
    date_added_raw = str(item.get("dateAdded") or "").strip()
    due_date_raw = str(item.get("dueDate") or "").strip()
    ransomware = ransomware_flag(item)

    due_date = parse_iso_date(due_date_raw) if due_date_raw else None
    severity = severity_from_due_date(due_date, today, ransomware=ransomware)

    title_parts = []
    if cve:
        title_parts.append(cve)
    vendor_product = " ".join(p for p in (vendor, product) if p)
    if vendor_product:
        title_parts.append(vendor_product)
    if name_field:
        title_parts.append(name_field)
    raw_name = ": ".join(title_parts) if title_parts else "CISA KEV entry"
    name = f"[KEV] {raw_name}"

    desc_parts = []
    if cve:
        desc_parts.append(f"cveID: {cve}")
    if vendor:
        desc_parts.append(f"vendorProject: {vendor}")
    if product:
        desc_parts.append(f"product: {product}")
    if name_field:
        desc_parts.append(f"vulnerabilityName: {name_field}")
    if date_added_raw:
        desc_parts.append(f"dateAdded: {date_added_raw}")
    if due_date_raw:
        if due_date is not None:
            delta = (due_date - today).days
            if delta < 0:
                desc_parts.append(f"dueDate: {due_date_raw} ({-delta} days overdue under BOD 22-01)")
            elif delta == 0:
                desc_parts.append(f"dueDate: {due_date_raw} (due today under BOD 22-01)")
            else:
                desc_parts.append(f"dueDate: {due_date_raw} ({delta} days remaining under BOD 22-01)")
        else:
            desc_parts.append(f"dueDate: {due_date_raw}")
    if ransomware:
        desc_parts.append("knownRansomwareCampaignUse: Known")
    if short_desc:
        desc_parts.append(f"shortDescription: {short_desc}")
    if required_action:
        desc_parts.append(f"requiredAction: {required_action}")
    if notes:
        desc_parts.append(f"notes: {notes}")
    cwes = item.get("cwes")
    if isinstance(cwes, list) and cwes:
        cwe_text = ", ".join(str(c).strip() for c in cwes if isinstance(c, str) and c.strip())
        if cwe_text:
            desc_parts.append(f"cwes: {cwe_text}")
    if isinstance(catalog_meta, dict):
        version = catalog_meta.get("catalogVersion")
        if version not in (None, ""):
            desc_parts.append(f"catalogVersion: {version}")
        released = catalog_meta.get("dateReleased")
        if released not in (None, ""):
            desc_parts.append(f"dateReleased: {released}")

    resolution = required_action or (
        f"Apply vendor patches for {vendor_product or cve or 'the affected product'} "
        "per CISA's KEV remediation guidance."
    )

    external_id = cve or name[:200]

    return {
        "name": str(name).strip()[:200] or "CISA KEV entry",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(item, catalog_meta),
        "cve": collect_cves(item),
        "cvss3": {},
        "tags": ["cisa-kev"],
    }


def build_host(vulns, catalog_meta):
    """Build the single synthetic host that carries every KEV vuln.

    KEV entries are CVE-keyed not host-keyed (the operator's other
    agents emit the host-side findings this feed is correlated
    against) so we collapse the whole catalog under one synthetic
    ``0.0.0.0`` host with hostname ``cisa-kev``.  The host
    description carries the catalog metadata so operators can
    pivot from the host page back to the catalog version.
    """
    desc_parts = ["source=cisa-kev"]
    if isinstance(catalog_meta, dict):
        for key in ("catalogVersion", "dateReleased", "count"):
            v = catalog_meta.get(key)
            if v in (None, ""):
                continue
            desc_parts.append(f"{key}={v}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["cisa-kev"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def filter_by_min_date(items, min_date):
    """Apply the KEV_MIN_DATE filter client-side.

    Drops KEV records whose ``dateAdded`` is strictly older than
    ``min_date``.  Records with missing / unparseable ``dateAdded``
    are KEPT (the conservative default — we don't want to silently
    drop entries the executor can't date-stamp).  When
    ``min_date`` is ``None`` the whole list passes through.
    """
    if min_date is None:
        return list(items) if isinstance(items, list) else []
    out = []
    if not isinstance(items, list):
        return out
    for entry in items:
        if not isinstance(entry, dict):
            continue
        added = parse_iso_date(entry.get("dateAdded"))
        if added is None or added >= min_date:
            out.append(entry)
    return out


def fetch_catalog(requests_module, url):
    """GET the KEV catalog JSON.

    Returns the parsed JSON body or ``None`` on any failure.
    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient CISA outage doesn't crash the
    dispatcher.
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
        log(f"KEV catalog not found at {url} (404)")
        return None
    if resp.status_code >= 400:
        log(f"KEV request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"KEV response was not JSON ({url})")
        return None


def main():
    started = time.time()

    min_date = validate_min_date(env("EXECUTOR_CONFIG_KEV_MIN_DATE"))
    host = env("CISA_KEV_HOST", default=DEFAULT_HOST)
    today = date.today()

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    url = build_kev_url(host)
    body = fetch_catalog(requests, url)
    if body is None:
        body = {}

    catalog_meta = extract_catalog_meta(body)
    records = extract_vulnerabilities(body)
    records = filter_by_min_date(records, min_date)

    vulns = []
    for entry in records:
        vuln = build_vulnerability(entry, catalog_meta, today)
        if vuln is not None:
            vulns.append(vuln)

    log(
        f"Processed {len(vulns)} KEV records "
        f"(min_date={min_date.isoformat() if min_date else 'none'}, "
        f"catalogVersion={catalog_meta.get('catalogVersion', '?')})"
    )

    hosts_out = [build_host(vulns, catalog_meta)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "cisa_kev",
            "command": "cisa_kev",
            "params": (f"min_date={min_date.isoformat() if min_date else ''}"),
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
