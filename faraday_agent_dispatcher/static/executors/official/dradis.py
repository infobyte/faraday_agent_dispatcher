#!/usr/bin/env python
"""Dradis Pro REST API importer.

Pulls nodes (assets) and issues (vulnerabilities) from a Dradis Pro project
and emits Faraday bulk-create JSON to stdout. One Faraday host is emitted
per Dradis node, with the issues evidenced against that node attached as
vulnerabilities. When no evidence ties an issue to a node, the issue is
attached to a synthetic ``0.0.0.0`` host so the data is still imported.

Endpoints used:
  GET /pro/api/projects/{id}/nodes                          -> list nodes
  GET /pro/api/projects/{id}/issues                         -> list issues
  GET /pro/api/projects/{id}/nodes/{node_id}/evidence       -> per-node
                                                               evidence (each
                                                               entry references
                                                               an issue id)

Auth: token in the ``Authorization: Token token="<DRADIS_TOKEN>"`` header.
The project-scoped endpoints additionally require the ``Dradis-Project-Id``
header set to DRADIS_PROJECT_ID.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Dradis ships with a default rating field (Critical / High / Medium / Low /
# Info) but the field name and casing depends on the project's issue library.
# We normalise generously and fall back to "info".
DRADIS_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
    "unknown": "info",
}

# Field keys (case-insensitive) Dradis uses for the rating / severity column
# in its default issue libraries.
SEVERITY_FIELD_KEYS = (
    "rating",
    "severity",
    "risk",
    "risk rating",
    "cvss rating",
    "cvss severity",
)

TITLE_FIELD_KEYS = ("title", "name", "issue", "finding")
DESCRIPTION_FIELD_KEYS = ("description", "details", "summary", "background")
RESOLUTION_FIELD_KEYS = ("recommendation", "recommendations", "remediation", "solution", "mitigation")
EVIDENCE_FIELD_KEYS = ("evidence", "proof", "output", "details", "notes")
CVSS_FIELD_KEYS = ("cvss", "cvss score", "cvss_v3", "cvss v3", "cvss3", "cvssv3 score", "cvss_v3_score")
CVE_FIELD_KEYS = ("cve", "cves", "cve id", "cve_id")
REFERENCE_FIELD_KEYS = ("references", "reference", "links", "url", "see also")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def log(msg):
    print(f"{datetime.utcnow()} - Dradis: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "info"
    if score <= 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def severity_from_dradis(value):
    if value is None:
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    text = str(value).strip().lower()
    if not text:
        return "info"
    if text in DRADIS_TO_FARADAY:
        return DRADIS_TO_FARADAY[text]
    # Strip leading "rating: " / numeric prefixes Dradis sometimes embeds
    # ("4 - High", "High (4)", "#[Rating]# High").
    for token in re.split(r"[\s\-:()/#\[\]]+", text):
        if token in DRADIS_TO_FARADAY:
            return DRADIS_TO_FARADAY[token]
    try:
        return severity_from_cvss(float(text))
    except ValueError:
        return "info"


def parse_fields(raw):
    """Dradis issues / evidence expose a ``fields`` block.

    The block is sometimes returned pre-parsed as a dict and sometimes as a
    serialised string (``#[Title]#\\nFoo\\n\\n#[Description]#\\nBar``). Return
    a case-insensitive lookup dict keyed by lower-cased field name.
    """
    fields = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key is None:
                continue
            fields[str(key).strip().lower()] = value if isinstance(value, str) else json.dumps(value)
        return fields
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                key = entry.get("name") or entry.get("label") or entry.get("key")
                value = entry.get("value") or entry.get("content")
                if key is None:
                    continue
                fields[str(key).strip().lower()] = value if isinstance(value, str) else json.dumps(value)
        return fields
    if isinstance(raw, str):
        current = None
        buffer = []
        for line in raw.splitlines():
            match = re.match(r"^\s*#\[(.+?)\]#\s*$", line)
            if match:
                if current is not None:
                    fields[current.strip().lower()] = "\n".join(buffer).strip()
                current = match.group(1)
                buffer = []
            elif current is not None:
                buffer.append(line)
        if current is not None:
            fields[current.strip().lower()] = "\n".join(buffer).strip()
    return fields


def lookup_field(fields, keys):
    for key in keys:
        if key in fields and fields[key]:
            return fields[key]
    return ""


def collect_refs(fields, issue):
    refs = []
    raw_refs = lookup_field(fields, REFERENCE_FIELD_KEYS)
    if raw_refs:
        for line in re.split(r"[\s,;]+", raw_refs):
            line = line.strip()
            if line:
                refs.append({"name": line, "type": "other"})
    for entry in issue.get("references") or issue.get("links") or []:
        if isinstance(entry, str):
            refs.append({"name": entry, "type": "other"})
        elif isinstance(entry, dict):
            url = entry.get("url") or entry.get("href") or entry.get("value") or entry.get("name")
            if url:
                refs.append({"name": url, "type": entry.get("type", "other") or "other"})
    return refs


def collect_cves(fields, issue):
    cves = []
    raw_cves = lookup_field(fields, CVE_FIELD_KEYS)
    if raw_cves:
        for token in re.split(r"[\s,;]+", raw_cves):
            token = token.strip().upper()
            if token.startswith("CVE-"):
                cves.append(token)
    for entry in issue.get("cves") or issue.get("cve") or []:
        if isinstance(entry, str) and entry.upper().startswith("CVE-"):
            cves.append(entry.upper())
        elif isinstance(entry, dict):
            value = entry.get("name") or entry.get("id") or entry.get("value")
            if value and str(value).upper().startswith("CVE-"):
                cves.append(str(value).upper())
    return cves


def get_json(base_url, path, headers):
    url = f"{base_url}{path}"
    resp = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
    if resp.status_code == 401:
        log("Authentication rejected (401). Check DRADIS_TOKEN.")
        sys.exit(1)
    if resp.status_code == 404:
        log(f"GET {path} returned 404 (not found)")
        return None
    if resp.status_code != 200:
        log(f"GET {path} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"GET {path} returned non-JSON body")
        return None


def extract_list(body, *keys):
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys:
            value = body.get(key)
            if isinstance(value, list):
                return value
        for candidate in ("data", "results", "items"):
            value = body.get(candidate)
            if isinstance(value, list):
                return value
    return []


def get_issues(base_url, headers, project_id):
    body = get_json(base_url, f"/pro/api/projects/{project_id}/issues", headers)
    return extract_list(body, "issues")


def get_nodes(base_url, headers, project_id):
    body = get_json(base_url, f"/pro/api/projects/{project_id}/nodes", headers)
    return extract_list(body, "nodes")


def get_evidence(base_url, headers, project_id, node_id):
    body = get_json(
        base_url,
        f"/pro/api/projects/{project_id}/nodes/{node_id}/evidence",
        headers,
    )
    return extract_list(body, "evidence")


def build_vulnerability(issue):
    fields = parse_fields(issue.get("fields"))
    name = (
        lookup_field(fields, TITLE_FIELD_KEYS)
        or issue.get("title")
        or issue.get("name")
        or f"Dradis issue {issue.get('id', '')}"
    )
    description = lookup_field(fields, DESCRIPTION_FIELD_KEYS) or issue.get("text") or ""
    resolution = lookup_field(fields, RESOLUTION_FIELD_KEYS)
    evidence_text = lookup_field(fields, EVIDENCE_FIELD_KEYS)
    cvss = lookup_field(fields, CVSS_FIELD_KEYS) or issue.get("cvss") or issue.get("cvss_score")
    severity = severity_from_dradis(lookup_field(fields, SEVERITY_FIELD_KEYS) or issue.get("severity"))
    return {
        "name": str(name).strip()[:200] or f"Dradis issue {issue.get('id', '')}",
        "desc": description,
        "severity": severity,
        "external_id": str(issue.get("id") or ""),
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": evidence_text,
        "refs": collect_refs(fields, issue),
        "cve": collect_cves(fields, issue),
        "cvss3": {"base_score": str(cvss)} if cvss else {},
        "tags": ["dradis"],
    }


def node_ip(node):
    label = node.get("label") or node.get("name") or ""
    properties = node.get("properties") or {}
    for key in ("ip", "ip_address", "address", "host", "hostname"):
        value = properties.get(key) if isinstance(properties, dict) else None
        if value:
            match = IP_RE.search(str(value))
            if match:
                return match.group(0)
    match = IP_RE.search(str(label))
    if match:
        return match.group(0)
    return None


def node_hostname(node):
    label = node.get("label") or node.get("name") or ""
    properties = node.get("properties") or {}
    if isinstance(properties, dict):
        for key in ("hostname", "host", "dns_name", "fqdn"):
            value = properties.get(key)
            if value:
                return str(value)
    if label and not IP_RE.fullmatch(str(label).strip()):
        return str(label)
    return None


def build_host(node, vulns):
    properties = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    ip = node_ip(node) or "0.0.0.0"
    hostname = node_hostname(node)
    os_name = ""
    if isinstance(properties, dict):
        os_name = properties.get("os") or properties.get("operating_system") or properties.get("os_name") or ""
    desc_parts = [f"Dradis node id={node.get('id', 'N/A')}"]
    label = node.get("label") or node.get("name")
    if label:
        desc_parts.append(f"label={label}")
    parent_id = node.get("parent_id")
    if parent_id is not None:
        desc_parts.append(f"parent_id={parent_id}")
    return {
        "ip": ip,
        "os": os_name,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def synthetic_host(vulns):
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [],
        "mac": "",
        "description": "Dradis issues without node evidence",
        "vulnerabilities": vulns,
    }


def evidence_issue_id(entry):
    raw = (
        entry.get("issue_id") or entry.get("issueId") or (entry.get("issue") or {}).get("id")
        if isinstance(entry, dict)
        else None
    )
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def main():
    started = time.time()
    host = env("DRADIS_HOST", required=True).rstrip("/")
    token = env("DRADIS_TOKEN", required=True)
    project_id = env("EXECUTOR_CONFIG_DRADIS_PROJECT_ID", required=True)

    base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    headers = {
        "Authorization": f'Token token="{token}"',
        "Dradis-Project-Id": str(project_id),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    issues = get_issues(base_url, headers, project_id)
    log(f"Found {len(issues)} issues in project {project_id}")
    issues_by_id = {}
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        try:
            issues_by_id[int(issue.get("id"))] = issue
        except (TypeError, ValueError):
            continue

    nodes = get_nodes(base_url, headers, project_id)
    log(f"Found {len(nodes)} nodes in project {project_id}")

    used_issue_ids = set()
    hosts = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = node.get("id")
        if node_id is None:
            continue
        evidence_entries = get_evidence(base_url, headers, project_id, node_id)
        node_issue_ids = []
        seen = set()
        for entry in evidence_entries:
            if not isinstance(entry, dict):
                continue
            issue_id = evidence_issue_id(entry)
            if issue_id is None or issue_id in seen:
                continue
            seen.add(issue_id)
            node_issue_ids.append(issue_id)
        if not node_issue_ids:
            continue
        vulns = []
        for issue_id in node_issue_ids:
            issue = issues_by_id.get(issue_id)
            if not issue:
                continue
            vulns.append(build_vulnerability(issue))
            used_issue_ids.add(issue_id)
        if vulns:
            hosts.append(build_host(node, vulns))

    orphan_vulns = [build_vulnerability(issue) for iid, issue in issues_by_id.items() if iid not in used_issue_ids]
    if orphan_vulns:
        hosts.append(synthetic_host(orphan_vulns))

    output = {
        "hosts": hosts,
        "command": {
            "tool": "dradis",
            "command": "dradis",
            "params": f"project_id={project_id}",
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
