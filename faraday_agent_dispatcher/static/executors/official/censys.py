#!/usr/bin/env python
"""Censys Search v2 EASM importer.

Pulls hosts and certificates that match a Censys query from the
Censys Search v2 REST API and emits Faraday bulk-create JSON to
stdout.  Each Censys ``hits[]`` row becomes one Faraday host —
``ip`` (or ``name`` for virtual-host shapes) maps onto ``host.ip``,
the autonomous-system / OS / location enrichment lands on
``host.description``, and each exposed service / certificate
becomes one Faraday vulnerability with the ``[EASM]`` engine prefix
so the data lands in the Faraday workspace alongside the other
attack-surface management feeds.

Endpoints used:
  GET {CENSYS_HOST}/api/v2/hosts/search
      -> paginated host search. Query params carry ``q`` (the
      operator-supplied CENSYS_QUERY), ``per_page=100`` (Censys'
      v2 cap), ``virtual_hosts`` (INCLUDE / EXCLUDE / ONLY) and a
      ``cursor`` token.  The response envelope is
      ``{"code": 200, "status": "OK", "result": {"hits": [...],
      "total": N, "links": {"next": "...", "prev": ""}}}`` walked
      page-by-page until ``links.next`` empties or CENSYS_PAGES is
      reached.
  GET {CENSYS_HOST}/api/v2/certificates/search
      -> paginated certificate search. Same query shape minus
      ``virtual_hosts`` (Censys certificates are server-side
      certificate records, not host shapes — the virtual-hosts
      flag is meaningless there).  Walked the same way as the
      hosts surface.

Auth: Censys uses HTTP Basic with the API ID as the username and
the API Secret as the password — the operator creates a key pair
in the Censys console (Account -> API) and the dispatcher carries
the credentials in the standard ``Authorization: Basic
<base64(API_ID:API_SECRET)>`` header on every ``/api/v2/`` call.
``CENSYS_HOST`` is optional and defaults to
``https://search.censys.io``; on-prem / federated Censys
deployments override it via the agent env vars.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

DEFAULT_HOST = "https://search.censys.io"
TIMEOUT = 60
PER_PAGE = 100  # Censys v2 caps per_page at 100 on /hosts/search and /certificates/search.
DEFAULT_PAGES = 5
MAX_PAGES = 50

VIRTUAL_HOSTS_VALUES = ("INCLUDE", "EXCLUDE", "ONLY")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(f"{datetime.utcnow()} - Censys: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on CENSYS_HOST.

    Defaults to ``https://search.censys.io`` (the public Censys
    cloud); on-prem deployments override the env var.
    """
    if not isinstance(host, str) or not host.strip():
        return DEFAULT_HOST
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_query(value):
    """Validate CENSYS_QUERY (the operator-supplied Censys query).

    None / blank -> sys.exit(1) (the query is mandatory; Censys v2
    rejects an empty ``q`` with HTTP 400).  Whitespace is trimmed.
    Anything else is forwarded verbatim — Censys' query language is
    free-form (e.g. ``services.service_name: HTTP and location.country_code: AR``).
    """
    if value is None:
        log("CENSYS_QUERY is required")
        sys.exit(1)
    text = str(value).strip()
    if not text:
        log("CENSYS_QUERY is required")
        sys.exit(1)
    return text


def validate_virtual_hosts(value):
    """Validate CENSYS_VIRTUAL_HOSTS (the virtual-hosts flag).

    None / blank -> EXCLUDE (Censys' default; virtual hosts are
    domain-keyed shapes, EXCLUDE keeps the result set IP-keyed which
    is what most EASM workflows expect).  Accepts the canonical
    Censys enum (INCLUDE / EXCLUDE / ONLY) plus operator-friendly
    boolean aliases (``true`` / ``1`` / ``yes`` / ``on`` -> INCLUDE,
    ``false`` / ``0`` / ``no`` / ``off`` -> EXCLUDE, ``only`` -> ONLY).
    Garbage -> EXCLUDE with a log line.
    """
    if value is None:
        return "EXCLUDE"
    if isinstance(value, bool):
        return "INCLUDE" if value else "EXCLUDE"
    text = str(value).strip()
    if not text:
        return "EXCLUDE"
    upper = text.upper()
    if upper in VIRTUAL_HOSTS_VALUES:
        return upper
    lower = text.lower()
    if lower in ("true", "1", "yes", "on", "include"):
        return "INCLUDE"
    if lower in ("false", "0", "no", "off", "exclude"):
        return "EXCLUDE"
    if lower == "only":
        return "ONLY"
    log(f"CENSYS_VIRTUAL_HOSTS '{value}' not recognised; defaulting to 'EXCLUDE'")
    return "EXCLUDE"


def validate_pages(value):
    """Validate CENSYS_PAGES (the per-surface page-walk cap).

    None / blank -> DEFAULT_PAGES.  Accepts an int / numeric string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Censys API (which is rate-limited per account).
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"CENSYS_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"CENSYS_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def build_hosts_url(host):
    return f"{normalize_base_url(host)}/api/v2/hosts/search"


def build_certs_url(host):
    return f"{normalize_base_url(host)}/api/v2/certificates/search"


def build_hosts_params(query, virtual_hosts, cursor):
    """Build the GET query params for /api/v2/hosts/search.

    ``virtual_hosts`` is the Censys-canonical INCLUDE / EXCLUDE / ONLY
    enum; ``cursor`` is the opaque next-page token Censys hands back
    on the previous page (omitted on the first request).
    """
    params = {"q": query, "per_page": PER_PAGE, "virtual_hosts": virtual_hosts}
    if cursor:
        params["cursor"] = cursor
    return params


def build_certs_params(query, cursor):
    """Build the GET query params for /api/v2/certificates/search."""
    params = {"q": query, "per_page": PER_PAGE}
    if cursor:
        params["cursor"] = cursor
    return params


def auth_credentials(api_id, api_secret):
    """Return the ``(user, password)`` tuple consumed by requests.auth."""
    return (str(api_id), str(api_secret))


def extract_hits(body):
    """Pull the hits list from a Censys v2 search envelope.

    Censys uses ``{"result": {"hits": [...], "links": {...},
    "total": N}}`` on every v2 search surface.  Some federated /
    legacy stacks expose the hits at the envelope root or under
    ``results`` / ``data`` — accept all three for resilience.
    """
    if not isinstance(body, dict):
        return []
    result = body.get("result")
    if isinstance(result, dict):
        hits = result.get("hits")
        if isinstance(hits, list):
            return hits
    for key in ("hits", "results", "data"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


def extract_next_cursor(body):
    """Pull the next-page cursor from a Censys v2 search envelope.

    Censys' canonical shape is ``{"result": {"links": {"next": "...",
    "prev": ""}}}``.  An empty / missing ``next`` signals end-of-stream
    (Censys never returns ``null`` here — empty string is the sentinel).
    """
    if not isinstance(body, dict):
        return ""
    result = body.get("result")
    if isinstance(result, dict):
        links = result.get("links")
        if isinstance(links, dict):
            nxt = links.get("next")
            if isinstance(nxt, str):
                return nxt.strip()
    links = body.get("links")
    if isinstance(links, dict):
        nxt = links.get("next")
        if isinstance(nxt, str):
            return nxt.strip()
    return ""


def extract_total(body):
    if not isinstance(body, dict):
        return None
    result = body.get("result")
    if isinstance(result, dict):
        for key in ("total", "totalHits", "totalResults"):
            v = result.get(key)
            if isinstance(v, int):
                return v
    for key in ("total", "totalHits", "totalResults"):
        v = body.get(key)
        if isinstance(v, int):
            return v
    return None


def severity_from_service(service):
    """Bucket a Censys service shape onto a Faraday severity.

    Censys hits aren't vulnerability findings — they're attack-surface
    discoveries — so the default is ``info``.  We bump to ``low`` for
    services that historically carry an outsized risk profile when
    found unauthenticated and exposed to the public internet: legacy
    Telnet, FTP, SMB, RDP, the database protocols (MySQL / PostgreSQL
    / MongoDB / Redis / Elasticsearch / Memcached), VNC, Docker /
    Kubernetes API surfaces, and bare IPMI.  ``medium`` is reserved
    for TLS findings that the Censys ``tls.certificate.validation``
    block flags as broken / self-signed / expired (because the
    operator likely intends those certificates to be trusted).
    """
    if not isinstance(service, dict):
        return "info"
    name = service.get("service_name") or service.get("serviceName") or ""
    ext = service.get("extended_service_name") or service.get("extendedServiceName") or ""
    label = f"{name} {ext}".lower()
    for token in (
        "telnet",
        "rsh ",
        "rlogin",
        "ftp",
        "tftp",
        "smb",
        "netbios",
        "rdp",
        "vnc",
        "mysql",
        "postgres",
        "mongodb",
        "redis",
        "memcached",
        "elasticsearch",
        "rethinkdb",
        "cassandra",
        "couchdb",
        "docker",
        "kubernetes",
        "kubelet",
        "etcd",
        "ipmi",
        "ldap ",
        " ldap",
    ):
        if token.strip() in label:
            return "low"
    tls = service.get("tls")
    if isinstance(tls, dict):
        cert = tls.get("certificate") or tls.get("Certificate")
        if isinstance(cert, dict):
            validation = cert.get("validation") or cert.get("Validation")
            if isinstance(validation, dict):
                if validation.get("self_signed") is True:
                    return "medium"
                if validation.get("expired") is True:
                    return "medium"
                if validation.get("trusted") is False:
                    return "medium"
                browser = validation.get("browser_trusted")
                if browser is False:
                    return "medium"
    return "info"


def collect_cves(item):
    """Walk a Censys hit for CVE-* ids.

    Censys' ``services[].vulnerabilities[]`` block (rare, but lands
    on services that ran a Censys-side fingerprint match) carries
    ``cve_id`` directly; the rest get scraped from any free-form
    label / software-name / fingerprint string via a strict
    ``CVE-\\d{4}-\\d+`` regex.
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

    vulns = item.get("vulnerabilities") or item.get("matched_vulnerabilities")
    if isinstance(vulns, list):
        for entry in vulns:
            if isinstance(entry, dict):
                add(entry.get("cve_id") or entry.get("cveId") or entry.get("id"))
            elif isinstance(entry, str):
                add(entry)

    services = item.get("services")
    if isinstance(services, list):
        for svc in services:
            if not isinstance(svc, dict):
                continue
            sub = svc.get("vulnerabilities") or svc.get("matched_vulnerabilities")
            if isinstance(sub, list):
                for entry in sub:
                    if isinstance(entry, dict):
                        add(entry.get("cve_id") or entry.get("cveId") or entry.get("id"))
                    elif isinstance(entry, str):
                        add(entry)

    for key in ("banner", "software", "label", "name", "extended_service_name", "service_name"):
        if not isinstance(item, dict):
            continue
        scan(item.get(key))
    return found


def collect_refs(hit, service=None):
    """Walk a Censys hit + service for advisory URLs / pivots."""
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

    if not isinstance(hit, dict):
        return refs

    ip = hit.get("ip") or hit.get("ipAddress")
    if isinstance(ip, str) and ip.strip():
        add(f"Censys-Host: https://search.censys.io/hosts/{ip.strip()}")

    name = hit.get("name") or hit.get("virtual_host_name")
    if isinstance(name, str) and name.strip():
        add(f"Censys-VHost: {name.strip()}")

    autosys = hit.get("autonomous_system")
    if isinstance(autosys, dict):
        asn = autosys.get("asn")
        if asn is not None:
            add(f"Censys-ASN: AS{asn}")
        org = autosys.get("organization") or autosys.get("description")
        if isinstance(org, str) and org.strip():
            add(f"Censys-ASOrg: {org.strip()}")

    if isinstance(service, dict):
        port = service.get("port")
        proto = service.get("transport_protocol") or service.get("transportProtocol")
        if port is not None:
            add(f"Censys-Port: {port}/{(proto or 'tcp').lower()}")
        for key in ("service_name", "serviceName", "extended_service_name", "extendedServiceName"):
            v = service.get(key)
            if isinstance(v, str) and v.strip():
                add(f"Censys-Service: {v.strip()}")
                break
        tls = service.get("tls")
        if isinstance(tls, dict):
            cert = tls.get("certificate") or tls.get("Certificate")
            if isinstance(cert, dict):
                for key in ("fingerprint_sha256", "fingerprintSha256"):
                    v = cert.get(key)
                    if isinstance(v, str) and v.strip():
                        add(f"Censys-CertSha256: {v.strip()}")
                        break

    return refs


def host_ip(hit):
    """Pick the host IP from a Censys hit.

    Censys hosts always carry ``ip`` at the top level (it's the
    document key).  Virtual-host shapes carry ``name`` (a domain)
    plus ``ip`` of the underlying server — we honour both.  Loopback
    / zero are explicitly skipped because Censys would not return
    them in real data; the sentinel guards against re-emitted
    fixtures.
    """
    if not isinstance(hit, dict):
        return "0.0.0.0"
    for key in ("ip", "ipAddress", "ip_address"):
        v = hit.get(key)
        if isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1"):
            return v.strip()
    return "0.0.0.0"


def host_hostnames(hit):
    """Walk a Censys hit for hostname candidates."""
    out = []
    seen = set()

    def add(text):
        if not isinstance(text, str):
            return
        s = text.strip()
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if not isinstance(hit, dict):
        return out

    add(hit.get("name") or hit.get("virtual_host_name"))

    dns = hit.get("dns")
    if isinstance(dns, dict):
        reverse = dns.get("reverse_dns") or dns.get("reverseDns")
        if isinstance(reverse, dict):
            names = reverse.get("names") or reverse.get("Names")
            if isinstance(names, list):
                for n in names:
                    add(n)
        records = dns.get("records")
        if isinstance(records, list):
            for r in records:
                if isinstance(r, dict):
                    add(r.get("name") or r.get("Name"))
        names = dns.get("names")
        if isinstance(names, list):
            for n in names:
                add(n)

    return out


def host_os(hit):
    """Build the ``host.os`` string from Censys' OS fingerprint block."""
    if not isinstance(hit, dict):
        return ""
    os_block = hit.get("operating_system") or hit.get("operatingSystem")
    if not isinstance(os_block, dict):
        return ""
    vendor = os_block.get("vendor") or ""
    product = os_block.get("product") or ""
    version = os_block.get("version") or ""
    bits = [str(b).strip() for b in (vendor, product, version) if str(b).strip()]
    return " ".join(bits)


def service_to_faraday_service(service):
    """Build a Faraday service dict from a Censys service block."""
    if not isinstance(service, dict):
        return None
    try:
        port = int(service.get("port"))
    except (TypeError, ValueError):
        return None
    proto = service.get("transport_protocol") or service.get("transportProtocol") or "tcp"
    name = (
        service.get("extended_service_name")
        or service.get("extendedServiceName")
        or service.get("service_name")
        or service.get("serviceName")
        or "unknown"
    )
    return {
        "name": str(name).lower(),
        "protocol": str(proto).lower(),
        "port": port,
        "status": "open",
    }


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


def build_service_vulnerability(hit, service):
    """Build a Faraday vulnerability dict for one Censys service exposure."""
    if not isinstance(service, dict):
        return None
    name = (
        service.get("extended_service_name")
        or service.get("extendedServiceName")
        or service.get("service_name")
        or service.get("serviceName")
        or "unknown service"
    )
    port = service.get("port")
    proto = (service.get("transport_protocol") or service.get("transportProtocol") or "tcp").lower()
    label = f"[EASM] Censys exposed {str(name).strip()} on {port}/{proto}"

    desc_parts = []
    for label_key, key in (
        ("service_name", "service_name"),
        ("extended_service_name", "extended_service_name"),
        ("transport_protocol", "transport_protocol"),
        ("port", "port"),
        ("software", "software"),
        ("banner", "banner"),
        ("observed_at", "observed_at"),
        ("perspective_id", "perspective_id"),
        ("source_ip", "source_ip"),
        ("truncated", "truncated"),
    ):
        v = service.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    tls = service.get("tls")
    if isinstance(tls, dict):
        cert = tls.get("certificate") or tls.get("Certificate")
        if isinstance(cert, dict):
            for sub_key in ("subject_dn", "issuer_dn", "fingerprint_sha256", "fingerprint_sha1"):
                sv = cert.get(sub_key)
                if isinstance(sv, str) and sv.strip():
                    desc_parts.append(f"cert_{sub_key}: {sv.strip()}")
            validation = cert.get("validation")
            if isinstance(validation, dict):
                for sub_key in ("self_signed", "expired", "trusted", "browser_trusted"):
                    sv = validation.get(sub_key)
                    if sv is None:
                        continue
                    desc_parts.append(f"tls_{sub_key}: {sv}")
        version = tls.get("version_selected") or tls.get("version")
        if isinstance(version, str) and version.strip():
            desc_parts.append(f"tls_version: {version.strip()}")

    severity = severity_from_service(service)
    cves = collect_cves(service)
    if not cves:
        cves = collect_cves(hit)
    refs = collect_refs(hit, service)

    external_id_bits = []
    ip = host_ip(hit)
    if ip and ip != "0.0.0.0":
        external_id_bits.append(ip)
    if port is not None:
        external_id_bits.append(f"{port}/{proto}")
    external_id = ":".join(external_id_bits) if external_id_bits else label

    resolution = (
        "Verify whether this service should be reachable from the public "
        "internet.  If not, restrict access via firewall rules / security "
        "groups or shut down the listener.  If the exposure is intentional, "
        "confirm the service is patched + authentication-gated and that the "
        "underlying TLS certificate is trusted."
    )

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["censys", "easm"],
    }


def build_certificate_vulnerability(hit):
    """Build a Faraday vulnerability dict for a Censys certificate hit."""
    if not isinstance(hit, dict):
        return None
    parsed = hit.get("parsed") if isinstance(hit.get("parsed"), dict) else {}
    subject_dn = parsed.get("subject_dn") or hit.get("subject_dn") or hit.get("subjectDn") or ""
    issuer_dn = parsed.get("issuer_dn") or hit.get("issuer_dn") or hit.get("issuerDn") or ""
    sha256 = parsed.get("fingerprint_sha256") or hit.get("fingerprint_sha256") or hit.get("fingerprintSha256") or ""
    label = f"[EASM] Censys certificate: {subject_dn or sha256 or 'unknown'}"

    desc_parts = []
    if subject_dn:
        desc_parts.append(f"subject_dn: {subject_dn}")
    if issuer_dn:
        desc_parts.append(f"issuer_dn: {issuer_dn}")
    if sha256:
        desc_parts.append(f"fingerprint_sha256: {sha256}")

    validity = parsed.get("validity") if isinstance(parsed, dict) else None
    if isinstance(validity, dict):
        for key in ("start", "end", "length"):
            v = validity.get(key)
            if v not in (None, ""):
                desc_parts.append(f"validity_{key}: {v}")

    names = parsed.get("names") if isinstance(parsed, dict) else None
    if isinstance(names, list) and names:
        desc_parts.append(f"names: {', '.join(str(n) for n in names if n)}")

    refs = []
    if sha256:
        refs.append({"name": f"Censys-Cert: https://search.censys.io/certificates/{sha256}", "type": "other"})

    severity = "info"
    if isinstance(parsed, dict):
        validation = parsed.get("validation") or parsed.get("Validation")
        if isinstance(validation, dict):
            if validation.get("self_signed") is True:
                severity = "medium"
            elif validation.get("expired") is True:
                severity = "medium"

    return {
        "name": str(label).strip()[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(sha256 or label)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Review the certificate in the Censys console (Certificates -> "
            "search by fingerprint).  Rotate / revoke if it represents an "
            "out-of-rotation or compromised key."
        ),
        "data": "",
        "refs": refs,
        "cve": [],
        "cvss3": {},
        "tags": ["censys", "easm"],
    }


def build_host_from_hit(hit):
    """Build a Faraday host dict from a Censys host hit."""
    if not isinstance(hit, dict):
        return None

    ip = host_ip(hit)
    hostnames = host_hostnames(hit)
    os_str = host_os(hit)

    desc_parts = []
    autosys = hit.get("autonomous_system")
    if isinstance(autosys, dict):
        asn = autosys.get("asn")
        if asn is not None:
            desc_parts.append(f"asn=AS{asn}")
        org = autosys.get("organization") or autosys.get("description")
        if org:
            desc_parts.append(f"asn_org={org}")
        country = autosys.get("country_code") or autosys.get("countryCode")
        if country:
            desc_parts.append(f"asn_country={country}")

    location = hit.get("location")
    if isinstance(location, dict):
        for key in ("country", "city", "country_code"):
            v = location.get(key)
            if v:
                desc_parts.append(f"location_{key}={v}")

    services = hit.get("services") if isinstance(hit.get("services"), list) else []
    if services:
        desc_parts.append(f"services={len(services)}")

    vulns = []
    faraday_services = []
    for svc in services:
        v = build_service_vulnerability(hit, svc)
        if v is not None:
            vulns.append(v)
        fs = service_to_faraday_service(svc)
        if fs is not None:
            faraday_services.append(fs)

    host = {
        "ip": ip,
        "os": os_str,
        "hostnames": hostnames,
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }
    if faraday_services:
        host["services"] = faraday_services
    return host


def build_host_from_certificate(hit):
    """Build a Faraday host dict for a Censys certificate hit.

    Certificates aren't IP-keyed (a single cert can cover many SANs
    on many IPs).  We synthesise a 0.0.0.0 host so the workspace
    still surfaces the finding, and hang the SAN list on
    ``host.hostnames`` so Faraday's hostname index still pivots on
    it.
    """
    if not isinstance(hit, dict):
        return None
    parsed = hit.get("parsed") if isinstance(hit.get("parsed"), dict) else {}
    sans = parsed.get("names") if isinstance(parsed.get("names"), list) else []
    hostnames = []
    seen = set()
    for n in sans:
        if isinstance(n, str) and n.strip():
            s = n.strip()
            if s not in seen:
                seen.add(s)
                hostnames.append(s)
    vuln = build_certificate_vulnerability(hit)
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": "Censys certificate hit",
        "vulnerabilities": [vuln] if vuln else [],
    }


def fetch_pages(requests_module, url, auth, params_builder, max_pages):
    """Walk a Censys v2 search envelope.

    ``params_builder`` is a callable ``(cursor) -> dict`` that builds
    each GET query-param dict.  We page until either the response
    carries an empty / missing ``links.next`` cursor or
    ``max_pages`` is reached.
    """
    out = []
    cursor = ""
    walked = 0
    while walked < max_pages:
        params = params_builder(cursor)
        try:
            resp = requests_module.get(url, auth=auth, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Censys request rejected (401). Check CENSYS_API_ID / CENSYS_API_SECRET.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Censys request rejected (403). Check the key's tier / scope.")
            return out
        if resp.status_code == 429:
            log("Censys rate-limited (429); stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Censys request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Censys response was not JSON ({url})")
            return out
        hits = extract_hits(payload)
        for entry in hits:
            if isinstance(entry, dict):
                out.append(entry)
        cursor = extract_next_cursor(payload)
        walked += 1
        if not cursor:
            break
    if walked >= max_pages and cursor:
        log(f"hit CENSYS_PAGES={max_pages}; stopping pagination (cursor not exhausted)")
    return out


def main():
    started = time.time()

    query = validate_query(env("EXECUTOR_CONFIG_CENSYS_QUERY"))
    virtual_hosts = validate_virtual_hosts(env("EXECUTOR_CONFIG_CENSYS_VIRTUAL_HOSTS"))
    pages = validate_pages(env("EXECUTOR_CONFIG_CENSYS_PAGES"))

    host = env("CENSYS_HOST", default=DEFAULT_HOST)
    api_id = env("CENSYS_API_ID", required=True)
    api_secret = env("CENSYS_API_SECRET", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    auth = auth_credentials(api_id, api_secret)
    hosts_url = build_hosts_url(host)
    certs_url = build_certs_url(host)

    host_hits = fetch_pages(
        requests,
        hosts_url,
        auth,
        lambda cursor: build_hosts_params(query, virtual_hosts, cursor),
        max_pages=pages,
    )
    cert_hits = fetch_pages(
        requests,
        certs_url,
        auth,
        lambda cursor: build_certs_params(query, cursor),
        max_pages=pages,
    )

    log(
        f"Processing {len(host_hits)} Censys host hits + {len(cert_hits)} certificate hits "
        f"(query={query!r}, virtual_hosts={virtual_hosts}, pages={pages})"
    )

    hosts_out = []
    for hit in host_hits:
        built = build_host_from_hit(hit)
        if built is not None:
            hosts_out.append(built)
    for hit in cert_hits:
        built = build_host_from_certificate(hit)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "censys",
            "command": "censys",
            "params": f"query={query},virtual_hosts={virtual_hosts},pages={pages}",
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
