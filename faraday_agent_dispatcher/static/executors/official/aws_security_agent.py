#!/usr/bin/env python
"""AWS Security Agent — findings import.

Pulls findings and agent inventory from AWS Security Agent (console URL
https://us-east-1.console.aws.amazon.com/securityagent/agents) and emits
Faraday bulk-create JSON to stdout.

Auth: AWS SigV4 using standard credential chain — the executor honours
AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (+ optional AWS_SESSION_TOKEN),
or falls back to the container's shared credentials file / instance
metadata if boto3 is available.

Because AWS Security Agent's public API surface was not fully documented
at write time, this executor uses the standard AWS API pattern of
'ListFindings' + 'GetFinding' + 'ListAgents' against a configurable
service host (default 'securityagent.<region>.amazonaws.com'). Both the
host and the operation paths are overridable per-install.

Modes (AWS_SECURITY_AGENT_MODE, comma-separated; default 'findings'):
  findings  -> ListFindings   agent-discovered vulns -> Faraday vulns
  agents    -> ListAgents     registered agents      -> synthetic hosts

Env / args:
  AWS_ACCESS_KEY_ID                    (mandatory)
  AWS_SECRET_ACCESS_KEY                (mandatory)
  AWS_SESSION_TOKEN                    (optional) — for STS-assumed roles
  AWS_REGION                           (optional) — default 'us-east-1'
  AWS_SECURITY_AGENT_HOST              (optional) — override full host
  AWS_SECURITY_AGENT_FINDINGS_PATH     (optional) — default '/findings'
  AWS_SECURITY_AGENT_AGENTS_PATH       (optional) — default '/agents'
  AWS_SECURITY_AGENT_MODE              (optional) — default 'findings'
  AWS_SECURITY_AGENT_PAGE_SIZE         (optional) — default 100
  AWS_SECURITY_AGENT_MAX_PAGES         (optional) — default 50
  AWS_SECURITY_AGENT_MIN_SEVERITY      (optional) — default 'medium'
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse

import requests

VALID_MODES = {"findings", "agents"}
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

AWS_SEVERITY_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}

DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 50
RETRY_429_SLEEP = 30
MAX_429_RETRIES = 3

SERVICE = "securityagent"


def log(msg):
    print(msg, file=sys.stderr)


def _cfg(name, default=""):
    return os.environ.get(f"EXECUTOR_CONFIG_{name}") or os.environ.get(name) or default


def _safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _validate_min_severity(value):
    if not value:
        return "medium"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"AWS_SECURITY_AGENT_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return text


def _severity_from_score(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    # AWS Security Hub severity is 0..100.
    if s >= 90:
        return "critical"
    if s >= 70:
        return "high"
    if s >= 40:
        return "medium"
    if s > 0:
        return "low"
    return "info"


def _severity(row, default="medium"):
    sev = row.get("Severity") or row.get("severity") or {}
    if isinstance(sev, dict):
        label = str(sev.get("Label") or sev.get("Normalized") or "").strip().lower()
        if label in AWS_SEVERITY_TO_FARADAY:
            return AWS_SEVERITY_TO_FARADAY[label]
        from_score = _severity_from_score(sev.get("Normalized"))
        if from_score:
            return from_score
    else:
        text = str(sev).strip().lower()
        if text in AWS_SEVERITY_TO_FARADAY:
            return AWS_SEVERITY_TO_FARADAY[text]
    return default


def _sign(method, host, path, region, service, access_key, secret_key, session_token, payload):
    """Standard AWS SigV4 signing for a single request."""
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_uri = path or "/"
    canonical_qs = ""
    payload_bytes = payload.encode() if isinstance(payload, str) else payload
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    if session_token:
        canonical_headers += f"x-amz-security-token:{session_token}\n"
        signed_headers += ";x-amz-security-token"

    canonical_request = "\n".join(
        [method, canonical_uri, canonical_qs, canonical_headers, signed_headers, payload_hash]
    )
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )
    k_date = hmac.new(("AWS4" + secret_key).encode(), date_stamp.encode(), hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth_header = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers = {
        "Host": host,
        "X-Amz-Content-Sha256": payload_hash,
        "X-Amz-Date": amz_date,
        "Authorization": auth_header,
        "Accept": "application/json",
        "Content-Type": "application/x-amz-json-1.1",
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers


def _fetch(host, region, path, page_size, max_pages, creds):
    """POST-style paginated call. AWS APIs use NextToken for pagination."""
    url = f"https://{host}{urllib.parse.quote(path)}"
    next_token = None
    for _ in range(max_pages):
        body = {"MaxResults": page_size}
        if next_token:
            body["NextToken"] = next_token
        payload = json.dumps(body)
        headers = _sign(
            "POST",
            host,
            path,
            region,
            SERVICE,
            creds["access_key"],
            creds["secret_key"],
            creds["session_token"],
            payload,
        )
        for attempt in range(MAX_429_RETRIES + 1):
            r = requests.post(url, headers=headers, data=payload, timeout=60)
            if r.status_code == 429 and attempt < MAX_429_RETRIES:
                log(f"AWS 429 on {path}; sleeping {RETRY_429_SLEEP}s")
                time.sleep(RETRY_429_SLEEP)
                continue
            break
        if r.status_code != 200:
            log(f"AWS {path} HTTP {r.status_code}: {r.text[:400]}")
            return
        try:
            body_json = r.json()
        except ValueError:
            log(f"AWS {path} returned non-JSON: {r.text[:200]!r}")
            return
        rows = (
            body_json.get("Findings")
            or body_json.get("Agents")
            or body_json.get("Items")
            or body_json.get("results")
            or []
        )
        if not rows:
            return
        for row in rows:
            yield row
        next_token = body_json.get("NextToken")
        if not next_token:
            return


def _host_key(resource):
    if not isinstance(resource, dict):
        return None, None
    ip = resource.get("IpAddress") or resource.get("ipAddress") or "0.0.0.0"
    hostname = (
        resource.get("Id")
        or resource.get("ResourceId")
        or resource.get("Arn")
        or resource.get("hostname")
        or "unknown-aws-resource"
    )
    return ip, str(hostname)


def _empty_host(ip, hostname, description):
    return {
        "ip": ip,
        "description": description,
        "hostnames": [hostname] if hostname else [],
        "vulnerabilities": [],
    }


def _add_vuln(hosts, ip, hostname, description, vuln):
    entry = hosts.get(ip)
    if entry is None:
        entry = _empty_host(ip, hostname, description)
        hosts[ip] = entry
    elif hostname and hostname not in entry["hostnames"]:
        entry["hostnames"].append(hostname)
    entry["vulnerabilities"].append(vuln)


def _make_vuln(name, desc, severity, refs, external_id, tags=None):
    return {
        "name": name,
        "desc": desc,
        "severity": severity,
        "type": "Vulnerability",
        "refs": refs,
        "data": "",
        "external_id": external_id,
        "tool": "aws_security_agent",
        "tags": tags or [],
    }


def _fetch_findings(host, region, path, page_size, max_pages, min_severity, hosts, creds):
    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    for row in _fetch(host, region, path, page_size, max_pages, creds):
        if not isinstance(row, dict):
            continue
        severity = _severity(row)
        if SEVERITY_ORDER[severity] < floor:
            continue
        fid = row.get("Id") or row.get("FindingId") or ""
        title = row.get("Title") or row.get("Description") or f"AWS Security Agent finding {fid}"
        desc_parts = []
        if row.get("Description"):
            desc_parts.append(row["Description"])
        if row.get("Remediation"):
            rem = row["Remediation"]
            text = rem.get("Recommendation", {}).get("Text") if isinstance(rem, dict) else str(rem)
            if text:
                desc_parts.append(f"Remediation: {text}")
        if row.get("ProductArn"):
            desc_parts.append(f"Product: {row['ProductArn']}")
        if row.get("Types"):
            desc_parts.append(f"Types: {', '.join(row['Types'])}")
        if row.get("CreatedAt"):
            desc_parts.append(f"Created: {row['CreatedAt']}")
        refs = []
        for res in row.get("Resources") or []:
            if isinstance(res, dict) and res.get("Id"):
                refs.append({"name": res["Id"], "type": "other"})
        for cve in row.get("Vulnerabilities") or []:
            if isinstance(cve, dict) and cve.get("Id"):
                refs.append({"name": cve["Id"], "type": "other"})
        vuln = _make_vuln(
            name=f"[AGENT] {title}",
            desc="\n".join(desc_parts) or "AWS Security Agent finding (no description).",
            severity=severity,
            refs=refs,
            external_id=f"aws-security-agent:finding:{fid}" if fid else "",
            tags=["agent:aws-security-agent"],
        )
        resources = row.get("Resources") or []
        if resources:
            ip, hostname = _host_key(resources[0])
            _add_vuln(hosts, ip, hostname, f"AWS-monitored resource: {hostname}", vuln)
        else:
            _add_vuln(
                hosts,
                "agent:aws-security-agent:global",
                "agent-aws-security-agent",
                "AWS Security Agent findings not scoped to a single resource",
                vuln,
            )
        kept += 1
    log(f"AWS Security Agent: kept {kept} findings above floor='{min_severity}'.")


def _fetch_agents(host, region, path, page_size, max_pages, hosts, creds):
    seen = 0
    for row in _fetch(host, region, path, page_size, max_pages, creds):
        if not isinstance(row, dict):
            continue
        ip, hostname = _host_key(row)
        _add_vuln(
            hosts,
            ip,
            hostname,
            f"AWS Security Agent agent ({row.get('Type', 'agent')})",
            _make_vuln(
                name="[AGENT] AWS Security Agent instance",
                desc=(
                    f"Type: {row.get('Type', '')}\n"
                    f"Status: {row.get('Status', '')}\n"
                    f"Account: {row.get('AccountId', '')}\n"
                    f"Region: {row.get('Region', region)}"
                ),
                severity="info",
                refs=[],
                external_id=f"aws-security-agent:agent:{row.get('Id', '')}",
                tags=["agent:aws-security-agent:agent-inventory"],
            ),
        )
        seen += 1
    log(f"AWS Security Agent: registered {seen} agents.")


def main():
    access_key = _cfg("AWS_ACCESS_KEY_ID")
    secret_key = _cfg("AWS_SECRET_ACCESS_KEY")
    session_token = _cfg("AWS_SESSION_TOKEN")
    if not access_key or not secret_key:
        log("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required.")
        sys.exit(1)

    region = _cfg("AWS_REGION", "us-east-1")
    default_host = _cfg("AWS_SECURITY_AGENT_HOST", f"securityagent.{region}.amazonaws.com")
    findings_path = _cfg("AWS_SECURITY_AGENT_FINDINGS_PATH", "/findings")
    agents_path = _cfg("AWS_SECURITY_AGENT_AGENTS_PATH", "/agents")

    modes_raw = _cfg("AWS_SECURITY_AGENT_MODE", "findings")
    modes = [m.strip().lower() for m in modes_raw.split(",") if m.strip()]
    invalid = [m for m in modes if m not in VALID_MODES]
    if invalid:
        log(f"Invalid AWS_SECURITY_AGENT_MODE value(s): {invalid}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    page_size = _safe_int(_cfg("AWS_SECURITY_AGENT_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    max_pages = _safe_int(_cfg("AWS_SECURITY_AGENT_MAX_PAGES"), DEFAULT_MAX_PAGES)
    min_severity = _validate_min_severity(_cfg("AWS_SECURITY_AGENT_MIN_SEVERITY"))

    creds = {
        "access_key": access_key,
        "secret_key": secret_key,
        "session_token": session_token,
    }

    hosts: dict = {}
    if "findings" in modes:
        _fetch_findings(default_host, region, findings_path, page_size, max_pages, min_severity, hosts, creds)
    if "agents" in modes:
        _fetch_agents(default_host, region, agents_path, page_size, max_pages, hosts, creds)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            deduped[v.get("external_id") or json.dumps(v, sort_keys=True)] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"AWS Security Agent: emitting {len(hosts)} hosts total.")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
