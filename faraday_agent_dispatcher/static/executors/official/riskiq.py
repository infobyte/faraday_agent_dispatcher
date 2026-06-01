#!/usr/bin/env python
"""RiskIQ PassiveTotal EASM importer.

Pulls externally-discovered enrichment data from the RiskIQ
PassiveTotal REST API (now branded Microsoft Defender EASM after
Microsoft's acquisition of RiskIQ in 2021 — the v2 PassiveTotal
endpoints are still the canonical OEM surface as of this writing)
and emits Faraday bulk-create JSON to stdout.  The single
``RISKIQ_QUERY`` (a domain / IP / hostname) becomes one Faraday host
(``ip`` = the query itself when ``RISKIQ_TYPE=ip``, or the synthetic
``0.0.0.0`` sentinel for domain / host queries since PassiveTotal's
domain enrichment is not IP-keyed); per-host attack-surface findings
(everCompromised, classification, malicious tags, hosting-history
anomalies) attach as Faraday vulnerabilities with the ``[EASM]``
engine prefix so the data lands in the Faraday workspace alongside
the other attack-surface management feeds.

Endpoints used:
  GET {RISKIQ_HOST}/v2/account/sources
      -> the operator's enabled PassiveTotal data sources (Whois,
      Passive DNS, Malware, OSINT, SSL Certificates, Trackers, etc.)
      Surfaced as a log line so the operator can confirm which
      enrichment surfaces are wired up in their tenant.  Failure
      here is non-fatal — we still hit /v2/enrichment.

  GET {RISKIQ_HOST}/v2/account/quotas
      -> the operator's current quota state (per-source daily /
      monthly call quotas).  Surfaced as a log line so the operator
      knows how much budget the run consumed.  Failure here is
      non-fatal.

  GET {RISKIQ_HOST}/v2/enrichment?query=<RISKIQ_QUERY>&type=<RISKIQ_TYPE>
      -> the canonical enrichment surface for a single asset.
      Returns the asset's primaryDomain, classification (malicious /
      suspicious / non_malicious / unknown), everCompromised flag,
      tags (with per-tag category — malware / suspicious / etc.),
      subdomains (when type=domain), TLDs registered against the
      same name, ASNs, and hostingHistory.  PassiveTotal's
      enrichment surface is single-record (no pagination) — the
      response is the enrichment payload for the single query.

Auth: PassiveTotal uses HTTP Basic with the API user email as the
username and the API key as the password — the operator creates a
key pair in the PassiveTotal / RI Defender EASM console (Account ->
API) and the dispatcher carries the credentials in the standard
``Authorization: Basic <base64(USER:API_KEY)>`` header on every
``/v2/`` call.  ``RISKIQ_HOST`` defaults to
``https://api.passivetotal.org`` and is settable for federated /
on-prem Defender EASM deployments without surfacing it as a
canonical mandatory env var (the playbook only mandates the user +
api key pair plus the query).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

TIMEOUT = 60
DEFAULT_HOST = "https://api.passivetotal.org"

VALID_TYPES = ("domain", "ip", "host")

RISKIQ_TYPE_ALIASES = {
    "domain": "domain",
    "domains": "domain",
    "fqdn": "domain",
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "ip_address": "ip",
    "ipaddress": "ip",
    "address": "ip",
    "host": "host",
    "hostname": "host",
}

# PassiveTotal classification enum -> Faraday severity bucket.
# ``malicious`` is a confirmed-bad verdict from at least one
# PassiveTotal data source (the OSINT articles surface, the malware
# surface, etc.) so we bump it to ``high``; ``suspicious`` is a
# lower-confidence verdict so we bump it to ``medium``; everything
# else lands on ``info`` (PassiveTotal classifications are
# attack-surface verdicts, not CVSS-scored vulnerabilities).
CLASSIFICATION_SEVERITY = {
    "malicious": "high",
    "suspicious": "medium",
    "non_malicious": "info",
    "non-malicious": "info",
    "benign": "info",
    "clean": "info",
    "unknown": "info",
    "": "info",
}

# PassiveTotal tag category enum -> Faraday severity bucket.  Tags
# are surfaced as separate findings when their category bumps the
# severity above ``info`` (malware / suspicious / phishing / fraud
# tags are actionable EASM signals; OSINT / whois / system tags are
# enrichment-only).
TAG_CATEGORY_SEVERITY = {
    "malware": "high",
    "malicious": "high",
    "phishing": "high",
    "fraud": "high",
    "ransomware": "high",
    "c2": "high",
    "exploit": "high",
    "suspicious": "medium",
    "tor": "medium",
    "proxy": "low",
    "vpn": "low",
}


def log(msg):
    print(f"{datetime.utcnow()} - RiskIQ: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host, default=DEFAULT_HOST):
    """Trim trailing slash + tolerate operator typos on RISKIQ_HOST.

    None / blank / non-string -> ``default`` (the public
    ``https://api.passivetotal.org`` SaaS host).  Whitespace-trims,
    strips trailing slashes and adds ``https://`` when the operator
    pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return default or ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_query(value):
    """Validate RISKIQ_QUERY (mandatory).

    Whitespace-trims; ``sys.exit(1)`` on blank (PassiveTotal v2
    rejects empty ``query`` with HTTP 400 — the query is mandatory).
    """
    if value is None:
        log("RISKIQ_QUERY is required")
        sys.exit(1)
    text = str(value).strip()
    if not text:
        log("RISKIQ_QUERY is required")
        sys.exit(1)
    return text


def validate_type(value):
    """Validate RISKIQ_TYPE (one of domain | ip | host).

    None / blank -> ``"domain"`` (PassiveTotal's default enrichment
    surface — most EASM workflows target a registered domain).
    Accepts the canonical enum (domain / ip / host) plus
    operator-friendly aliases (fqdn / domains -> domain; ipv4 /
    ipv6 / ip_address / address -> ip; hostname -> host).  Garbage
    -> ``"domain"`` with a log line.
    """
    if value is None:
        return "domain"
    text = str(value).strip().lower()
    if not text:
        return "domain"
    if text in VALID_TYPES:
        return text
    bucket = RISKIQ_TYPE_ALIASES.get(text)
    if bucket is not None:
        return bucket
    log(f"RISKIQ_TYPE '{value}' not recognised; defaulting to 'domain'")
    return "domain"


def build_enrichment_url(host):
    return f"{normalize_base_url(host)}/v2/enrichment"


def build_sources_url(host):
    return f"{normalize_base_url(host)}/v2/account/sources"


def build_quotas_url(host):
    return f"{normalize_base_url(host)}/v2/account/quotas"


def build_enrichment_params(query, qtype):
    """Build the query-param dict for /v2/enrichment."""
    return {"query": str(query), "type": str(qtype)}


def auth_credentials(user, api_key):
    """Return the PassiveTotal auth tuple (HTTP Basic user / key)."""
    return (str(user), str(api_key))


def auth_headers():
    """Return the PassiveTotal Accept / Content-Type header set."""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def classification_severity(value):
    """Bucket a PassiveTotal classification onto a Faraday severity."""
    if not isinstance(value, str):
        return "info"
    return CLASSIFICATION_SEVERITY.get(value.strip().lower(), "info")


def tag_severity(category):
    """Bucket a PassiveTotal tag category onto a Faraday severity."""
    if not isinstance(category, str):
        return "info"
    return TAG_CATEGORY_SEVERITY.get(category.strip().lower(), "info")


def collect_cves(item):
    """Walk a PassiveTotal item for CVE-* ids.

    PassiveTotal enrichment payloads don't normally carry CVEs (the
    surface is attack-surface fingerprinting, not vuln scoring) but
    we still scan defensively in case the OSINT / malware references
    mention CVEs in free-form text.
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

    for list_key in ("cves", "cve_ids", "vulnerabilities", "matched_vulnerabilities"):
        v = item.get(list_key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, dict):
                    add(entry.get("cve") or entry.get("cve_id") or entry.get("cveId") or entry.get("id"))
                elif isinstance(entry, str):
                    add(entry)

    for key in ("description", "summary", "details", "name", "label", "value"):
        scan(item.get(key))
    return found


def collect_refs(enrichment, finding_label=None):
    """Walk a PassiveTotal enrichment payload for advisory URLs / pivots."""
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

    if isinstance(enrichment, dict):
        q = enrichment.get("queryValue") or enrichment.get("query")
        if isinstance(q, str) and q.strip():
            add(f"RiskIQ-Query: {q.strip()}")
            add(f"https://community.riskiq.com/search/{q.strip()}")
        qt = enrichment.get("queryType") or enrichment.get("type")
        if isinstance(qt, str) and qt.strip():
            add(f"RiskIQ-Type: {qt.strip()}")
        pd = enrichment.get("primaryDomain")
        if isinstance(pd, str) and pd.strip():
            add(f"RiskIQ-PrimaryDomain: {pd.strip()}")
        classification = enrichment.get("classification")
        if isinstance(classification, str) and classification.strip():
            add(f"RiskIQ-Classification: {classification.strip()}")
        for asn in enrichment.get("asns", []) or []:
            if isinstance(asn, str) and asn.strip():
                add(f"RiskIQ-ASN: {asn.strip()}")
            elif isinstance(asn, (int, float)):
                add(f"RiskIQ-ASN: AS{int(asn)}")
            elif isinstance(asn, dict):
                num = asn.get("asn") or asn.get("number") or asn.get("asNumber")
                if num is not None:
                    add(f"RiskIQ-ASN: AS{num}")

    if finding_label:
        add(f"RiskIQ-Finding: {finding_label}")

    return refs


def enrichment_query(enrichment):
    """Pick the query field from a PassiveTotal enrichment payload."""
    if not isinstance(enrichment, dict):
        return ""
    for key in ("queryValue", "query", "value", "name"):
        v = enrichment.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def enrichment_subdomains(enrichment):
    """Pull the subdomains list off a PassiveTotal enrichment payload."""
    if not isinstance(enrichment, dict):
        return []
    out = []
    seen = set()
    base = enrichment_query(enrichment) or enrichment.get("primaryDomain") or ""
    base = base.strip().lower() if isinstance(base, str) else ""

    def add(text):
        if not isinstance(text, str):
            return
        s = text.strip()
        if not s or s.lower() in seen:
            return
        seen.add(s.lower())
        out.append(s)

    subs = enrichment.get("subdomains")
    if isinstance(subs, list):
        for s in subs:
            if isinstance(s, str):
                # PassiveTotal returns subdomain prefixes (e.g. "www");
                # join with base domain so Faraday gets full FQDNs.
                if base and "." not in s:
                    add(f"{s}.{base}")
                else:
                    add(s)
            elif isinstance(s, dict):
                add(s.get("subdomain") or s.get("name") or s.get("hostname"))
    return out


def host_ip(enrichment, qtype):
    """Pick the Faraday host IP for a PassiveTotal enrichment payload.

    For ``type=ip`` queries the IP is the query itself.  For domain /
    host queries PassiveTotal doesn't return an IP-keyed envelope so
    we fall back to the synthetic ``0.0.0.0`` sentinel — Faraday
    pivots on the hostnames list in that case.
    """
    if qtype == "ip":
        q = enrichment_query(enrichment)
        if q and q not in ("0.0.0.0", "127.0.0.1"):
            return q
    return "0.0.0.0"


def host_hostnames(enrichment, qtype):
    """Walk a PassiveTotal enrichment payload for hostname candidates."""
    if not isinstance(enrichment, dict):
        return []
    out = []
    seen = set()

    def add(text):
        if not isinstance(text, str):
            return
        s = text.strip()
        if not s or s.lower() in seen:
            return
        seen.add(s.lower())
        out.append(s)

    # For domain / host queries the query itself is a hostname; for
    # ip queries the query is an IP and only the subdomains list (if
    # any) carries hostnames.
    if qtype != "ip":
        add(enrichment_query(enrichment))

    pd = enrichment.get("primaryDomain")
    if isinstance(pd, str):
        add(pd)

    for sub in enrichment_subdomains(enrichment):
        add(sub)

    return out


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


def build_classification_vulnerability(enrichment):
    """Build a Faraday vuln for a malicious / suspicious classification.

    Returns ``None`` when the classification is benign / unknown
    (those are info-level enrichment signals, not findings — they
    surface in the host description instead).
    """
    if not isinstance(enrichment, dict):
        return None
    classification = enrichment.get("classification")
    if not isinstance(classification, str) or not classification.strip():
        return None
    text = classification.strip().lower()
    if text not in ("malicious", "suspicious"):
        return None

    severity = classification_severity(classification)
    q = enrichment_query(enrichment) or "asset"
    label = f"[EASM] RiskIQ classified {q} as {classification.strip()}"

    desc_parts = [
        f"queryValue: {q}",
        f"classification: {classification.strip()}",
    ]
    for key in ("primaryDomain", "everCompromised", "queryType"):
        v = enrichment.get(key)
        if v in (None, ""):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")

    refs = collect_refs(enrichment, finding_label="classification")
    cves = collect_cves(enrichment)

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"riskiq:classification:{q}:{classification.strip().lower()}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Review the asset in the RiskIQ / Defender EASM console "
            "(community.riskiq.com).  Confirm the classification, "
            "investigate any associated malware / phishing tags, and "
            "either take the asset down or accept the risk."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["riskiq", "easm"],
    }


def build_ever_compromised_vulnerability(enrichment):
    """Build a Faraday vuln when ``everCompromised`` is true."""
    if not isinstance(enrichment, dict):
        return None
    flag = enrichment.get("everCompromised")
    if flag is not True:
        return None
    q = enrichment_query(enrichment) or "asset"
    label = f"[EASM] RiskIQ reports {q} as previously compromised"
    desc_parts = [
        f"queryValue: {q}",
        "everCompromised: True",
    ]
    for key in ("primaryDomain", "classification", "queryType"):
        v = enrichment.get(key)
        if v in (None, ""):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")

    refs = collect_refs(enrichment, finding_label="everCompromised")
    cves = collect_cves(enrichment)

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": "high",
        "external_id": f"riskiq:everCompromised:{q}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Pivot through the RiskIQ / Defender EASM compromise "
            "timeline to identify the compromise window and the "
            "attacker infrastructure that touched the asset; rotate "
            "credentials and re-image any systems that may still be "
            "trusting the compromise-era keys."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["riskiq", "easm"],
    }


def build_tag_vulnerability(enrichment, tag):
    """Build a Faraday vuln for one PassiveTotal tag.

    Returns ``None`` for low-signal tag categories (whois / osint /
    system / passive-dns) — those are surfaced in the host
    description instead.
    """
    if not isinstance(enrichment, dict) or not isinstance(tag, dict):
        return None
    name = tag.get("tag") or tag.get("name") or tag.get("label")
    if not isinstance(name, str) or not name.strip():
        return None
    category = tag.get("category") or tag.get("type") or ""
    severity = tag_severity(category)
    if severity == "info":
        return None

    q = enrichment_query(enrichment) or "asset"
    label = f"[EASM] RiskIQ tag '{name.strip()}' on {q}"

    desc_parts = [
        f"queryValue: {q}",
        f"tag: {name.strip()}",
    ]
    if isinstance(category, str) and category.strip():
        desc_parts.append(f"category: {category.strip()}")
    for key in ("notes", "source", "lastObserved", "added", "createdAt"):
        v = tag.get(key)
        if v in (None, ""):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")

    refs = collect_refs(enrichment, finding_label=f"tag:{name.strip()}")
    cves = collect_cves(tag)

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"riskiq:tag:{q}:{name.strip().lower()}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Pivot through the tag in the RiskIQ / Defender EASM "
            "console to confirm the verdict (each tag carries the "
            "originating data source — community-reported, OSINT, "
            "malware analysis, etc.).  If confirmed, take the asset "
            "down or move it behind a WAF / blocklist; if a "
            "false-positive, request tag removal through the console."
        ),
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["riskiq", "easm"],
    }


def collect_tag_vulnerabilities(enrichment):
    """Build Faraday vulns for every actionable PassiveTotal tag."""
    out = []
    if not isinstance(enrichment, dict):
        return out
    tags = enrichment.get("tags")
    if not isinstance(tags, list):
        return out
    for tag in tags:
        if isinstance(tag, str):
            v = build_tag_vulnerability(enrichment, {"tag": tag, "category": ""})
        elif isinstance(tag, dict):
            v = build_tag_vulnerability(enrichment, tag)
        else:
            v = None
        if v is not None:
            out.append(v)
    return out


def build_host_from_enrichment(enrichment, qtype, sources=None, quotas=None):
    """Build a Faraday host dict from a PassiveTotal enrichment payload."""
    if not isinstance(enrichment, dict):
        return None

    ip = host_ip(enrichment, qtype)
    hostnames = host_hostnames(enrichment, qtype)

    desc_parts = []
    for key in (
        "queryValue",
        "queryType",
        "primaryDomain",
        "classification",
        "everCompromised",
        "tldExtension",
    ):
        v = enrichment.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{key}={_serialise(v)}")
        else:
            desc_parts.append(f"{key}={v}")

    asns = enrichment.get("asns")
    if isinstance(asns, list) and asns:
        desc_parts.append(f"asns={_serialise(asns)}")

    subs = enrichment_subdomains(enrichment)
    if subs:
        desc_parts.append(f"subdomains={len(subs)}")

    hh = enrichment.get("hostingHistory")
    if isinstance(hh, list) and hh:
        desc_parts.append(f"hostingHistory={len(hh)}")

    if isinstance(sources, dict) and sources.get("sources"):
        src_list = sources["sources"]
        if isinstance(src_list, list):
            desc_parts.append(f"sources={len(src_list)}")

    if isinstance(quotas, dict):
        quota_section = quotas.get("user") or quotas.get("quota") or quotas
        if isinstance(quota_section, dict):
            current = quota_section.get("current")
            limit = quota_section.get("limit")
            if current is not None and limit is not None:
                desc_parts.append(f"quota={current}/{limit}")

    vulns = []
    cls_vuln = build_classification_vulnerability(enrichment)
    if cls_vuln is not None:
        vulns.append(cls_vuln)
    ec_vuln = build_ever_compromised_vulnerability(enrichment)
    if ec_vuln is not None:
        vulns.append(ec_vuln)
    vulns.extend(collect_tag_vulnerabilities(enrichment))

    return {
        "ip": ip,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_json(requests_module, url, auth, params=None, fatal_on_unauthorized=True):
    """Single-shot GET that returns the parsed JSON body or ``None``.

    PassiveTotal's surfaces don't paginate per query so we don't
    walk pages; we just GET the URL once and return the body.  401
    sys.exits when ``fatal_on_unauthorized`` is set (the canonical
    enrichment surface — bad creds means no data at all); 403 / 429
    / 4xx / 5xx / non-JSON / network exceptions all log and return
    ``None`` so a partial outage on one surface still produces
    output from the others.
    """
    try:
        resp = requests_module.get(
            url,
            auth=auth,
            headers=auth_headers(),
            params=params or {},
            timeout=TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 401:
        if fatal_on_unauthorized:
            log("RiskIQ request rejected (401). Check RISKIQ_USER / RISKIQ_API_KEY.")
            sys.exit(1)
        log(f"RiskIQ request rejected (401) for {url}; continuing.")
        return None
    if resp.status_code == 403:
        log(f"RiskIQ request rejected (403) for {url}. Check API key scope.")
        return None
    if resp.status_code == 429:
        log(f"RiskIQ rate-limited (429) for {url}.")
        return None
    if resp.status_code >= 400:
        log(f"RiskIQ request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"RiskIQ response was not JSON ({url})")
        return None


def main():
    started = time.time()

    query = validate_query(env("EXECUTOR_CONFIG_RISKIQ_QUERY"))
    qtype = validate_type(env("EXECUTOR_CONFIG_RISKIQ_TYPE"))

    user = env("RISKIQ_USER", required=True)
    api_key = env("RISKIQ_API_KEY", required=True)

    host = env("RISKIQ_HOST", default=DEFAULT_HOST)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    auth = auth_credentials(user, api_key)

    # /v2/account/sources + /v2/account/quotas are best-effort
    # context — never fatal — so we fetch them before the canonical
    # enrichment hit and surface their summaries in the host
    # description.
    sources = fetch_json(
        requests,
        build_sources_url(host),
        auth,
        fatal_on_unauthorized=False,
    )
    quotas = fetch_json(
        requests,
        build_quotas_url(host),
        auth,
        fatal_on_unauthorized=False,
    )

    if isinstance(sources, dict) and isinstance(sources.get("sources"), list):
        log(f"PassiveTotal sources available: {len(sources['sources'])}")
    if isinstance(quotas, dict):
        log(f"PassiveTotal quotas snapshot: {_serialise(quotas)[:200]}")

    enrichment = fetch_json(
        requests,
        build_enrichment_url(host),
        auth,
        params=build_enrichment_params(query, qtype),
        fatal_on_unauthorized=True,
    )

    if enrichment is None:
        enrichment = {"queryValue": query, "queryType": qtype}

    log(f"Processing RiskIQ enrichment for query={query!r} type={qtype!r}")

    hosts_out = []
    built = build_host_from_enrichment(enrichment, qtype, sources=sources, quotas=quotas)
    if built is not None:
        hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "riskiq",
            "command": "riskiq",
            "params": f"query={query},type={qtype}",
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
