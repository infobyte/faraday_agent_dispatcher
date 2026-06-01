#!/usr/bin/env python
"""IBM QRadar SOAR (Resilient) REST API importer.

Pulls security incidents from a QRadar SOAR / IBM Resilient organization and
emits Faraday bulk-create JSON to stdout. Each incident is mapped to a Faraday
vulnerability — one host per affected asset (resolved from the incident's
``artifacts`` block, falling back to a synthetic ``0.0.0.0`` host when no
asset can be derived).

Endpoints used:
  POST /rest/orgs/{org_id}/incidents/query_paged
      -> paginate incidents using the Resilient query DSL. Body is the
         standard ``IncidentsQueryDTO`` payload:
            {
              "filters": [{"conditions": [...]}],
              "sorts":   [{"field_name": "create_date", "type": "desc"}],
              "start":   <offset>,
              "length":  <page_size>
            }
         The QRADAR_SOAR_QUERY argument, when set, is parsed as JSON and
         merged on top of the default payload so it can carry either a full
         IncidentsQueryDTO or just a ``filters`` block.

  GET  /rest/orgs/{org_id}/incidents/{id}/artifacts
      -> per-incident artifact list. Artifacts (IP addresses, hostnames,
         URLs, MAC addresses, OS strings, ...) are how Resilient pins an
         incident to one or more affected assets.

Auth: HTTP Basic with QRADAR_SOAR_API_KEY_ID as username and
QRADAR_SOAR_API_KEY_SECRET as password (the standard Resilient API-key auth
pattern). QRADAR_SOAR_HOST is the SOAR base URL (e.g.
https://soar.example.com).
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 100
MAX_PAGES = 200

# IBM Resilient default severity codes (severity_code on the incident).
# The classic out-of-the-box scale is High=4, Medium=5, Low=6; some tenants
# customise these, so we also map the more intuitive ``severity`` string
# field when present and accept arbitrary numeric / textual values.
SEVERITY_CODE_TO_FARADAY = {
    4: "high",
    5: "medium",
    6: "low",
}

QRADAR_SOAR_TO_FARADAY = {
    "unknown": "info",
    "informational": "info",
    "info": "info",
    "none": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}

# Resilient incident ``plan_status`` is "A" (Active) or "C" (Closed).
PLAN_STATUS_CLOSED = {"C", "c", "closed"}
PLAN_STATUS_OPEN = {"A", "a", "active", "open"}


def log(msg):
    print(f"{datetime.utcnow()} - QRadar SOAR: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_qradar(severity_code, severity_str):
    if severity_str is not None:
        text = str(severity_str).strip().lower()
        if text in QRADAR_SOAR_TO_FARADAY:
            return QRADAR_SOAR_TO_FARADAY[text]
    if severity_code is None:
        return "info"
    try:
        code = int(severity_code)
    except (TypeError, ValueError):
        text = str(severity_code).strip().lower()
        return QRADAR_SOAR_TO_FARADAY.get(text, "info")
    return SEVERITY_CODE_TO_FARADAY.get(code, "info")


def status_from_qradar(plan_status, resolution_id):
    if resolution_id:
        return "closed"
    if plan_status is None:
        return "open"
    text = str(plan_status).strip()
    if text in PLAN_STATUS_CLOSED:
        return "closed"
    if text in PLAN_STATUS_OPEN:
        return "open"
    return "open"


def post(base_url, path, auth, payload):
    url = f"{base_url}{path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json=payload, auth=auth, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check QRADAR_SOAR_API_KEY_ID / QRADAR_SOAR_API_KEY_SECRET.")
        sys.exit(1)
    if resp.status_code == 403:
        log("Authorization rejected (403). The API key lacks access to this organization.")
        sys.exit(1)
    if resp.status_code == 404:
        log(f"POST {path} returned 404")
        return None
    if resp.status_code >= 400:
        log(f"POST {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"POST {path} returned non-JSON body")
        return None


def get(base_url, path, auth):
    url = f"{base_url}{path}"
    headers = {"Accept": "application/json"}
    resp = requests.get(url, headers=headers, auth=auth, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check QRADAR_SOAR_API_KEY_ID / QRADAR_SOAR_API_KEY_SECRET.")
        sys.exit(1)
    if resp.status_code == 403:
        log(f"GET {path} returned 403 (key lacks access).")
        return None
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def build_query_payload(user_query):
    """Build the IncidentsQueryDTO payload sent to query_paged.

    QRADAR_SOAR_QUERY, when set, is parsed as JSON. We accept either:
      * a full IncidentsQueryDTO (e.g. with its own ``filters`` / ``sorts``)
      * a bare ``filters`` list, which is wrapped into the standard payload
      * a single filter object with its own ``conditions``
    The default ordering is most-recently-created first so partial pulls
    still see the freshest data.
    """
    payload = {"sorts": [{"field_name": "create_date", "type": "desc"}]}
    if not user_query:
        return payload
    try:
        parsed = json.loads(user_query)
    except ValueError:
        log("QRADAR_SOAR_QUERY is not valid JSON; ignoring filter.")
        return payload
    if isinstance(parsed, list):
        payload["filters"] = parsed
        return payload
    if isinstance(parsed, dict):
        if "filters" in parsed or "sorts" in parsed:
            payload.update(parsed)
        elif "conditions" in parsed:
            payload["filters"] = [parsed]
        else:
            payload["filters"] = [{"conditions": [parsed]}]
    return payload


def search_incidents(base_url, org_id, auth, user_query):
    incidents = []
    base_payload = build_query_payload(user_query)
    for page in range(MAX_PAGES):
        payload = dict(base_payload)
        payload["start"] = page * PAGE_SIZE
        payload["length"] = PAGE_SIZE
        body = post(base_url, f"/rest/orgs/{org_id}/incidents/query_paged", auth, payload)
        if not isinstance(body, dict):
            break
        chunk = body.get("data") or body.get("incidents") or []
        if not chunk:
            break
        incidents.extend(chunk)
        # Resilient reports both ``recordsTotal`` (post-filter) and
        # ``recordsFiltered`` depending on the API version; either signals
        # that we have walked the full result set.
        total = body.get("recordsTotal")
        if not isinstance(total, int):
            total = body.get("recordsFiltered")
        if isinstance(total, int) and len(incidents) >= total:
            break
        if len(chunk) < PAGE_SIZE:
            break
    return incidents


def fetch_artifacts(base_url, org_id, auth, incident_id):
    body = get(base_url, f"/rest/orgs/{org_id}/incidents/{incident_id}/artifacts", auth)
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        return body.get("data") or body.get("artifacts") or []
    return []


# Resilient artifact ``type`` values are integers in newer tenants and
# strings in older ones; we look at both. Strings we recognise:
IP_TYPES = {
    "ip address",
    "ip",
    "ipaddress",
    "source ip address",
    "destination ip address",
    "host ip",
}

HOSTNAME_TYPES = {
    "dns name",
    "hostname",
    "host",
    "fqdn",
    "asset",
    "computer name",
    "device name",
    "endpoint",
}

MAC_TYPES = {"mac address", "mac"}

OS_TYPES = {"operating system", "os", "os type", "platform"}


def _artifact_type_text(artifact):
    type_field = artifact.get("type")
    if isinstance(type_field, dict):
        return str(type_field.get("name") or type_field.get("value") or "").strip().lower()
    if type_field is not None:
        return str(type_field).strip().lower()
    return ""


def _artifact_value(artifact):
    value = artifact.get("value")
    if value is None:
        value = artifact.get("description")
    if isinstance(value, dict):
        # Older API returns rich-text dicts: {"format": "text", "content": "..."}
        value = value.get("content") or value.get("value") or ""
    if value is None:
        return ""
    return str(value).strip()


def asset_identity(artifacts):
    ip = None
    hostname = None
    mac = None
    os_name = None
    for artifact in artifacts or []:
        if not isinstance(artifact, dict):
            continue
        type_text = _artifact_type_text(artifact)
        value = _artifact_value(artifact)
        if not value:
            continue
        if not ip and type_text in IP_TYPES:
            ip = value
        elif not hostname and type_text in HOSTNAME_TYPES:
            hostname = value
        elif not mac and type_text in MAC_TYPES:
            mac = value
        elif not os_name and type_text in OS_TYPES:
            os_name = value
    return ip, hostname, mac, os_name


def collect_cves(incident, artifacts):
    cves = []
    seen = set()

    def _add(candidate):
        text = str(candidate).strip().upper()
        if text.startswith("CVE-") and text not in seen:
            seen.add(text)
            cves.append(text)

    for artifact in artifacts or []:
        if not isinstance(artifact, dict):
            continue
        if _artifact_type_text(artifact) in ("cve", "cve id", "vulnerability"):
            _add(_artifact_value(artifact))
    # Custom properties area: properties is a list of {name, value} entries
    # on classic Resilient and a dict on QRadar SOAR.
    properties = incident.get("properties") or {}
    if isinstance(properties, dict):
        for name, value in properties.items():
            if "cve" in str(name).lower() and value:
                _add(value)
    elif isinstance(properties, list):
        for entry in properties:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or ""
            value = entry.get("value")
            if "cve" in str(name).lower() and value:
                _add(value)
    return cves


def collect_refs(incident):
    refs = []
    if incident.get("workspace"):
        refs.append({"name": f"workspace: {incident['workspace']}", "type": "other"})
    if incident.get("plan_status"):
        refs.append({"name": f"plan_status: {incident['plan_status']}", "type": "other"})
    for entry in incident.get("incident_type_ids") or []:
        refs.append({"name": f"incident_type_id: {entry}", "type": "other"})
    return refs


def _flatten_description(value):
    if not value:
        return ""
    if isinstance(value, dict):
        return str(value.get("content") or value.get("text") or value.get("value") or "")
    return str(value)


def build_vulnerability(incident, artifacts):
    severity = severity_from_qradar(incident.get("severity_code"), incident.get("severity"))
    status = status_from_qradar(incident.get("plan_status"), incident.get("resolution_id"))
    name = incident.get("name") or f"QRadar SOAR incident {incident.get('id', '')}"
    desc_parts = []
    description = _flatten_description(incident.get("description"))
    if description:
        desc_parts.append(description)
    if incident.get("discovered_date"):
        desc_parts.append(f"discovered_date: {incident['discovered_date']}")
    if incident.get("create_date"):
        desc_parts.append(f"create_date: {incident['create_date']}")
    if incident.get("due_date"):
        desc_parts.append(f"due_date: {incident['due_date']}")
    if incident.get("owner_id"):
        desc_parts.append(f"owner_id: {incident['owner_id']}")
    if incident.get("phase_id"):
        desc_parts.append(f"phase_id: {incident['phase_id']}")
    resolution_parts = []
    resolution_summary = _flatten_description(incident.get("resolution_summary"))
    if resolution_summary:
        resolution_parts.append(resolution_summary)
    if incident.get("resolution_id"):
        resolution_parts.append(f"resolution_id: {incident['resolution_id']}")
    return {
        "name": str(name).strip()[:200] or f"QRadar SOAR incident {incident.get('id', '')}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(incident.get("id") or ""),
        "type": "Vulnerability",
        "status": status,
        "resolution": "\n".join(resolution_parts),
        "data": str(incident.get("inc_training") or ""),
        "refs": collect_refs(incident),
        "cve": collect_cves(incident, artifacts),
        "cvss3": {},
        "tags": ["qradar_soar"],
    }


def build_host(ip, hostname, mac, os_name, vulns):
    return {
        "ip": str(ip) if ip else "0.0.0.0",
        "os": os_name or "",
        "hostnames": [hostname] if hostname else [],
        "mac": mac or "",
        "description": "IBM QRadar SOAR affected asset",
        "vulnerabilities": vulns,
    }


def synthetic_host(vulns):
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [],
        "mac": "",
        "description": "IBM QRadar SOAR incidents without a resolvable asset",
        "vulnerabilities": vulns,
    }


def main():
    started = time.time()
    host = env("QRADAR_SOAR_HOST", required=True).rstrip("/")
    org_id = env("QRADAR_SOAR_ORG_ID", required=True)
    api_key_id = env("QRADAR_SOAR_API_KEY_ID", required=True)
    api_key_secret = env("QRADAR_SOAR_API_KEY_SECRET", required=True)
    user_query = env("EXECUTOR_CONFIG_QRADAR_SOAR_QUERY")

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    auth = HTTPBasicAuth(api_key_id, api_key_secret)

    incidents = search_incidents(base_url, org_id, auth, user_query)
    log(f"Fetched {len(incidents)} incidents (org_id={org_id}, query={'custom' if user_query else 'all'})")

    grouped = {}
    orphan_vulns = []
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        incident_id = incident.get("id")
        if incident_id is None:
            continue
        artifacts = fetch_artifacts(base_url, org_id, auth, incident_id)
        ip, hostname, mac, os_name = asset_identity(artifacts)
        vuln = build_vulnerability(incident, artifacts)
        if not ip and not hostname:
            orphan_vulns.append(vuln)
            continue
        key = (ip or "", hostname or "")
        bucket = grouped.setdefault(
            key,
            {"ip": ip, "hostname": hostname, "mac": mac, "os": os_name, "vulns": []},
        )
        if not bucket["mac"] and mac:
            bucket["mac"] = mac
        if not bucket["os"] and os_name:
            bucket["os"] = os_name
        bucket["vulns"].append(vuln)

    hosts = []
    for bucket in grouped.values():
        hosts.append(build_host(bucket["ip"], bucket["hostname"], bucket["mac"], bucket["os"], bucket["vulns"]))
    if orphan_vulns:
        hosts.append(synthetic_host(orphan_vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "qradar_soar",
            "command": "qradar_soar",
            "params": f"org_id={org_id} query={'custom' if user_query else 'all'}",
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
