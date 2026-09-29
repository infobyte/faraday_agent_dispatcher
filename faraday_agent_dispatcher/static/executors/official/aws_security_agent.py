#!/usr/bin/env python
"""AWS Security Agent — real securityagent boto3 client.

Pulls pentest findings + discovered endpoints from AWS Security Agent
(the real GA service under `securityagent.global.app.aws` / boto3
`securityagent` — endpoint_prefix `securityagent`, sigv4). The service
model was published in boto3 1.43.x (September 2025 API version).

Walks the account:
  ListAgentSpaces
  -> for each space:
       ListPentests
       -> for each pentest:
            ListPentestJobsForPentest
            -> for each COMPLETED job:
                 ListFindings + BatchGetFindings (rich detail)
                 ListDiscoveredEndpoints (asset URLs)
                 BatchGetPentestJobs (overview + target endpoint)

Each finding becomes one Faraday vuln bucketed under the pentest's
target host (parsed from the pentest job's `endpoints[0].uri`).
Discovered endpoints become info-level records on the same host,
naming the URI + operation + description.

Auth: standard AWS credential chain (env, ~/.aws/credentials, IAM
role, IMDS). The three headline env vars (AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) are all pre-configurable
on the dispatcher as varenvs — the WebUI Run form can leave them
blank.

Env / args (all read from EXECUTOR_CONFIG_* first, then raw env):
  AWS_ACCESS_KEY_ID                (optional if using IAM role)
  AWS_SECRET_ACCESS_KEY            (optional if using IAM role)
  AWS_SESSION_TOKEN                (optional — for STS AssumeRole)
  AWS_REGION                       (optional — default 'us-east-1')
  AWS_SECURITY_AGENT_AGENT_SPACE   (optional — restrict to one agent space id)
  AWS_SECURITY_AGENT_PENTEST_ID    (optional — restrict to one pentest)
  AWS_SECURITY_AGENT_JOB_ID        (optional — restrict to one pentest job)
  AWS_SECURITY_AGENT_MODE          (optional — default 'findings,endpoints')
                                    Valid: findings, endpoints, jobs
  AWS_SECURITY_AGENT_MAX_SPACES    (optional — default 20)
  AWS_SECURITY_AGENT_MAX_PENTESTS  (optional — default 20)
  AWS_SECURITY_AGENT_MAX_JOBS      (optional — default 20)
  AWS_SECURITY_AGENT_MAX_PAGES     (optional — default 20)
  AWS_SECURITY_AGENT_PAGE_SIZE     (optional — default 100)
  AWS_SECURITY_AGENT_MIN_SEVERITY  (optional — default 'info')
  AWS_SECURITY_AGENT_ONLY_COMPLETED (optional — default 'true'; set 'false'
                                     to include IN_PROGRESS/FAILED jobs)
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlparse

# Defer the boto3 hard-fail to main() so this module stays importable in
# test environments that don't have boto3 installed (the executor is only
# actually invoked with boto3 present in the dispatcher container).
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    _BOTO3_IMPORT_ERROR = None
except ImportError as _e:
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception
    _BOTO3_IMPORT_ERROR = _e


VALID_MODES = {"findings", "endpoints", "jobs"}
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# securityagent's riskLevel enum: CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL | UNKNOWN
RISK_TO_FARADAY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
    "UNKNOWN": "info",
}

DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_SPACES = 20
DEFAULT_MAX_PENTESTS = 20
DEFAULT_MAX_JOBS = 20


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
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"AWS_SECURITY_AGENT_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'.")
        return "info"
    return text


def _severity_from_risk(risk_level, default="info"):
    return RISK_TO_FARADAY.get(str(risk_level or "").upper(), default)


def _paginate(fn, kwargs, item_key, max_pages, page_size):
    """Yield every item across a securityagent list operation."""
    call_kwargs = dict(kwargs or {})
    call_kwargs.setdefault("maxResults", page_size)
    for _ in range(max_pages):
        resp = fn(**call_kwargs)
        for row in resp.get(item_key, []) or []:
            yield row
        token = resp.get("nextToken")
        if not token:
            return
        call_kwargs["nextToken"] = token


def _host_from_endpoint_uri(uri):
    """Parse a URL to (ip, hostname). Falls back to the raw string on failure."""
    if not uri:
        return "0.0.0.0", "aws-security-agent"
    text = str(uri)
    if "://" not in text:
        return "0.0.0.0", text
    parsed = urlparse(text)
    return "0.0.0.0", parsed.netloc or text


def _empty_host(ip, hostname, description):
    return {
        "ip": ip,
        "description": description,
        "hostnames": [hostname] if hostname else [],
        "vulnerabilities": [],
    }


def _add_vuln(hosts, ip, hostname, description, vuln):
    """Bucket by hostname when ip is a placeholder. Faraday keys hosts by ip
    server-side, so leaving every asset at 0.0.0.0 collapses them into one row.
    Promote the hostname into the ip field for one row per real asset."""
    if ip in ("0.0.0.0", "", None) and hostname:
        effective_ip = hostname
    else:
        effective_ip = ip
    entry = hosts.get(effective_ip)
    if entry is None:
        entry = _empty_host(effective_ip, hostname, description)
        hosts[effective_ip] = entry
    elif hostname and hostname not in entry["hostnames"]:
        entry["hostnames"].append(hostname)
    entry["vulnerabilities"].append(vuln)


def _make_vuln(name, desc, severity, refs, external_id, tags=None, data="", resolution=""):
    v = {
        "name": name,
        "desc": desc,
        "severity": severity,
        "type": "Vulnerability",
        "refs": refs,
        "data": data,
        "external_id": external_id,
        "tool": "aws_security_agent",
        "tags": tags or [],
    }
    if resolution:
        v["resolution"] = resolution
    return v


def _process_finding(f, host_ip, hostname, min_floor, hosts, space_id, pentest_id, job_id):
    severity = _severity_from_risk(f.get("riskLevel"))
    if SEVERITY_ORDER[severity] < min_floor:
        return False
    fid = f.get("findingId") or ""
    risk_type = f.get("riskType") or ""
    confidence = f.get("confidence") or ""
    status = f.get("status") or ""
    desc_parts = []
    if f.get("description"):
        desc_parts.append(str(f["description"]))
    if risk_type:
        desc_parts.append(f"Risk type: {risk_type}")
    if confidence:
        desc_parts.append(f"Confidence: {confidence}")
    if status:
        desc_parts.append(f"Status: {status}")
    if f.get("attackScript"):
        script = str(f["attackScript"])
        if len(script) > 3500:
            script = script[:3500] + "…(truncated)"
        desc_parts.append(f"Attack script / reproduction:\n{script}")
    data_parts = []
    for k in ("evidence", "impact", "proofOfConcept", "poc", "notes"):
        if f.get(k):
            v = str(f[k])
            if len(v) > 1500:
                v = v[:1500] + "…(truncated)"
            data_parts.append(f"# {k}\n{v}")
    resolution_parts = []
    for k in ("remediation", "recommendation", "recommendations"):
        if f.get(k):
            resolution_parts.append(str(f[k]))
    refs = [
        {"name": f"AWS-SecurityAgent-Finding-{fid}", "type": "other"},
        {"name": f"AWS-SecurityAgent-Space-{space_id}", "type": "other"},
        {"name": f"AWS-SecurityAgent-Pentest-{pentest_id}", "type": "other"},
        {"name": f"AWS-SecurityAgent-Job-{job_id}", "type": "other"},
    ]
    if risk_type:
        refs.append({"name": f"AWS-SecurityAgent-Risk-{risk_type}", "type": "other"})
    if confidence:
        refs.append({"name": f"AWS-SecurityAgent-Confidence-{confidence}", "type": "other"})
    vuln = _make_vuln(
        name=f.get("name") or f"AWS Security Agent finding {fid}",
        desc="\n\n".join(desc_parts) or "AWS Security Agent finding (no description).",
        severity=severity,
        refs=refs,
        external_id=f"aws-security-agent:finding:{fid}" if fid else "",
        tags=[
            "agent:aws-security-agent",
            f"agent:aws-security-agent:space:{space_id}",
            f"agent:aws-security-agent:pentest:{pentest_id}",
            f"agent:aws-security-agent:job:{job_id}",
        ],
        data="\n\n".join(data_parts),
        resolution="\n\n".join(resolution_parts),
    )
    _add_vuln(hosts, host_ip, hostname, f"AWS Security Agent pentest target: {hostname}", vuln)
    return True


def _process_endpoint(ep, host_ip, hostname, hosts, space_id, pentest_id, job_id):
    """Represent a discovered endpoint as an info-level record."""
    ep_uri = ep.get("uri") or ""
    op = ep.get("operation") or ""
    task_id = ep.get("taskId") or ""
    description = ep.get("description") or ""
    evidence = ep.get("evidence") or ""
    desc_parts = []
    if op:
        desc_parts.append(f"Operation: {op}")
    if description:
        desc_parts.append(description)
    if evidence:
        ev = str(evidence)
        if len(ev) > 1500:
            ev = ev[:1500] + "…(truncated)"
        desc_parts.append(f"Evidence:\n{ev}")
    ext = f"aws-security-agent:endpoint:{job_id}:{task_id}:{ep_uri}"
    _add_vuln(
        hosts,
        host_ip,
        hostname,
        f"AWS Security Agent discovered endpoint on {hostname}",
        _make_vuln(
            name=f"AWS Security Agent discovered endpoint: {op} {ep_uri}".strip(),
            desc="\n\n".join(desc_parts) or "Discovered endpoint (no description).",
            severity="info",
            refs=[
                {"name": f"AWS-SecurityAgent-Job-{job_id}", "type": "other"},
                {"name": f"AWS-SecurityAgent-Task-{task_id}", "type": "other"},
            ],
            external_id=ext,
            tags=[
                "agent:aws-security-agent:discovered-endpoint",
                f"agent:aws-security-agent:job:{job_id}",
            ],
        ),
    )


def _process_job_summary(job, host_ip, hostname, hosts, space_id, pentest_id):
    """Info-level 'this pentest job ran' record."""
    job_id = job.get("pentestJobId") or ""
    title = job.get("title") or ""
    status = job.get("status") or ""
    overview = job.get("overview") or ""
    if len(overview) > 3500:
        overview = overview[:3500] + "…(truncated)"
    _add_vuln(
        hosts,
        host_ip,
        hostname,
        f"AWS Security Agent pentest job: {hostname}",
        _make_vuln(
            name=f"AWS Security Agent pentest: {title} ({status})",
            desc=overview or f"Pentest job {job_id} status {status}.",
            severity="info",
            refs=[
                {"name": f"AWS-SecurityAgent-Space-{space_id}", "type": "other"},
                {"name": f"AWS-SecurityAgent-Pentest-{pentest_id}", "type": "other"},
                {"name": f"AWS-SecurityAgent-Job-{job_id}", "type": "other"},
                {"name": f"AWS-SecurityAgent-Status-{status}", "type": "other"},
            ],
            external_id=f"aws-security-agent:job:{job_id}",
            tags=[
                "agent:aws-security-agent:pentest-job",
                f"agent:aws-security-agent:job:{job_id}",
            ],
        ),
    )


def _walk_job(sa, space_id, pentest_id, job, modes, page_size, max_pages, min_floor, hosts):
    job_id = job.get("pentestJobId") or ""
    host_ip, hostname = "0.0.0.0", "aws-security-agent"
    for ep in job.get("endpoints") or []:
        uri = ep.get("uri") if isinstance(ep, dict) else ep
        if uri:
            host_ip, hostname = _host_from_endpoint_uri(uri)
            break
    kept_findings = 0
    if "findings" in modes:
        finding_ids = [
            row.get("findingId")
            for row in _paginate(
                sa.list_findings,
                {"agentSpaceId": space_id, "pentestJobId": job_id},
                "findingsSummaries",
                max_pages,
                page_size,
            )
            if row.get("findingId")
        ]
        for i in range(0, len(finding_ids), 25):
            batch = finding_ids[i : i + 25]
            try:
                detail = sa.batch_get_findings(agentSpaceId=space_id, findingIds=batch)
            except (BotoCoreError, ClientError) as e:
                log(f"batch_get_findings({batch[:2]}...): {e}")
                continue
            for f in detail.get("findings", []) or []:
                if _process_finding(f, host_ip, hostname, min_floor, hosts, space_id, pentest_id, job_id):
                    kept_findings += 1
    if "endpoints" in modes:
        for ep in _paginate(
            sa.list_discovered_endpoints,
            {"agentSpaceId": space_id, "pentestJobId": job_id},
            "discoveredEndpoints",
            max_pages,
            page_size,
        ):
            _process_endpoint(ep, host_ip, hostname, hosts, space_id, pentest_id, job_id)
    if "jobs" in modes:
        _process_job_summary(job, host_ip, hostname, hosts, space_id, pentest_id)
    log(
        f"space={space_id} pentest={pentest_id} job={job_id} host={hostname} "
        f"kept={kept_findings} findings above floor"
    )
    return kept_findings


def main():
    if _BOTO3_IMPORT_ERROR is not None:
        log(f"boto3 is required for aws_security_agent (pip install boto3): {_BOTO3_IMPORT_ERROR}")
        sys.exit(1)
    region = _cfg("AWS_REGION", "us-east-1") or "us-east-1"
    access_key = _cfg("AWS_ACCESS_KEY_ID")
    secret_key = _cfg("AWS_SECRET_ACCESS_KEY")
    session_token = _cfg("AWS_SESSION_TOKEN")
    modes_raw = _cfg("AWS_SECURITY_AGENT_MODE", "findings,endpoints")
    modes = {m.strip().lower() for m in modes_raw.split(",") if m.strip()}
    invalid = modes - VALID_MODES
    if invalid:
        log(f"Invalid AWS_SECURITY_AGENT_MODE value(s): {sorted(invalid)}. Use any of: {sorted(VALID_MODES)}")
        sys.exit(1)

    max_spaces = _safe_int(_cfg("AWS_SECURITY_AGENT_MAX_SPACES"), DEFAULT_MAX_SPACES)
    max_pentests = _safe_int(_cfg("AWS_SECURITY_AGENT_MAX_PENTESTS"), DEFAULT_MAX_PENTESTS)
    max_jobs = _safe_int(_cfg("AWS_SECURITY_AGENT_MAX_JOBS"), DEFAULT_MAX_JOBS)
    max_pages = _safe_int(_cfg("AWS_SECURITY_AGENT_MAX_PAGES"), DEFAULT_MAX_PAGES)
    page_size = _safe_int(_cfg("AWS_SECURITY_AGENT_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    min_severity = _validate_min_severity(_cfg("AWS_SECURITY_AGENT_MIN_SEVERITY"))
    min_floor = SEVERITY_ORDER[min_severity]
    only_completed = _cfg("AWS_SECURITY_AGENT_ONLY_COMPLETED", "true").lower() != "false"

    only_space = _cfg("AWS_SECURITY_AGENT_AGENT_SPACE")
    only_pentest = _cfg("AWS_SECURITY_AGENT_PENTEST_ID")
    only_job = _cfg("AWS_SECURITY_AGENT_JOB_ID")

    session_kwargs = {"region_name": region}
    if access_key and secret_key:
        session_kwargs.update(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        if session_token:
            session_kwargs["aws_session_token"] = session_token
    sa = boto3.client("securityagent", **session_kwargs)

    hosts: dict = {}

    def process_space(space_id):
        pentests = []
        if only_pentest:
            pentests = [{"pentestId": only_pentest, "agentSpaceId": space_id}]
        else:
            for p in _paginate(
                sa.list_pentests,
                {"agentSpaceId": space_id},
                "pentestSummaries",
                max_pages,
                page_size,
            ):
                pentests.append(p)
                if len(pentests) >= max_pentests:
                    break
        log(f"space {space_id}: {len(pentests)} pentest(s).")
        for p in pentests:
            pid = p.get("pentestId")
            if not pid:
                continue
            job_ids = []
            if only_job:
                job_ids = [only_job]
            else:
                for j in _paginate(
                    sa.list_pentest_jobs_for_pentest,
                    {"agentSpaceId": space_id, "pentestId": pid},
                    "pentestJobSummaries",
                    max_pages,
                    page_size,
                ):
                    if only_completed and str(j.get("status") or "").upper() != "COMPLETED":
                        continue
                    job_ids.append(j.get("pentestJobId"))
                    if len(job_ids) >= max_jobs:
                        break
            job_ids = [j for j in job_ids if j]
            if not job_ids:
                log(f"  pentest {pid}: no eligible jobs.")
                continue
            for i in range(0, len(job_ids), 25):
                batch = job_ids[i : i + 25]
                try:
                    resp = sa.batch_get_pentest_jobs(agentSpaceId=space_id, pentestJobIds=batch)
                except (BotoCoreError, ClientError) as e:
                    log(f"batch_get_pentest_jobs({batch[:2]}...): {e}")
                    continue
                for job in resp.get("pentestJobs", []) or []:
                    _walk_job(sa, space_id, pid, job, modes, page_size, max_pages, min_floor, hosts)

    try:
        if only_space:
            process_space(only_space)
        else:
            spaces = []
            for s in _paginate(
                sa.list_agent_spaces,
                {},
                "agentSpaceSummaries",
                max_pages,
                page_size,
            ):
                spaces.append(s.get("agentSpaceId"))
                if len(spaces) >= max_spaces:
                    break
            log(f"AWS Security Agent: iterating {len(spaces)} agent space(s).")
            for sid in spaces:
                if sid:
                    process_space(sid)
    except ClientError as e:
        log(f"AWS Security Agent ClientError: {e}")
        sys.exit(1)
    except BotoCoreError as e:
        log(f"AWS Security Agent BotoCoreError: {e}")
        sys.exit(1)

    for host in hosts.values():
        deduped: dict = {}
        for v in host.get("vulnerabilities") or []:
            key = v.get("external_id") or json.dumps(v, sort_keys=True)
            deduped[key] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"AWS Security Agent: emitting {len(hosts)} host(s).")
    print(json.dumps({"hosts": list(hosts.values())}))


if __name__ == "__main__":
    main()
