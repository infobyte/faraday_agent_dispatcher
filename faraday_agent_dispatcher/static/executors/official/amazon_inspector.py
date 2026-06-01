#!/usr/bin/env python
"""AWS Inspector v2 (Amazon Inspector) vendor-native CSPM importer.

Pulls security findings from AWS Inspector v2 via the canonical
``inspector2.list_findings`` boto3 API and emits Faraday bulk-create
JSON to stdout. Each affected AWS resource (EC2 instance / ECR container
image / Lambda function) becomes one Faraday host (``ip`` = synthetic
``0.0.0.0`` for non-EC2 resources; EC2 instances surface the public /
private IPv4 address from ``resource.details.awsEc2Instance`` when
present); per-resource findings are attached as Faraday vulnerabilities
— one per Inspector ``findingArn`` with engine prefix ``[CNAPP]``.

Endpoints used:
  ``boto3.client('inspector2').list_findings(filterCriteria=..., maxResults=...)``
      -> paginated via ``nextToken`` cursor (the boto3 paginator handles
      this). Filters built as a dict — ``resourceType`` (single value)
      and ``severity`` (list of values), both expressed as
      ``{'comparison': 'EQUALS', 'value': '...'}`` entries.

Auth: AWS Inspector v2 uses the standard AWS SigV4 credential chain.
A service account ("IAM principal") with the
``inspector2:ListFindings`` permission is required, with credentials
exposed to the dispatcher as ``AWS_ACCESS_KEY_ID`` /
``AWS_SECRET_ACCESS_KEY`` (+ optional ``AWS_SESSION_TOKEN`` for STS-vended
session credentials). The ``AWS_REGION`` arg pins the regional Inspector
endpoint (Inspector v2 is regional).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

VALID_RESOURCE_TYPES = (
    "AWS_EC2_INSTANCE",
    "AWS_ECR_CONTAINER_IMAGE",
    "AWS_LAMBDA_FUNCTION",
)

# Inspector v2 severity enum: CRITICAL / HIGH / MEDIUM / LOW /
# INFORMATIONAL / UNTRIAGED. Map to Faraday's five-bucket scheme.
INSPECTOR_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "untriaged": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Inspector v2 API severity tokens (UPPERCASE). UNTRIAGED is excluded
# from the filter because forwarding it would surface uncategorised
# findings the operator hasn't asked for; client-side bucketing still
# maps untriaged -> info if the operator floor is `info`.
INSPECTOR_API_SEVERITY = {
    "info": "INFORMATIONAL",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}

# Inspector v2 status enum: ACTIVE / SUPPRESSED / CLOSED. Map to Faraday
# (open / risk-accepted / closed).
INSPECTOR_STATUS_TO_FARADAY = {
    "active": "open",
    "open": "open",
    "new": "open",
    "reopened": "open",
    "in_progress": "open",
    "inprogress": "open",
    "closed": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "remediated": "closed",
    "mitigated": "closed",
    "patched": "closed",
    "suppressed": "risk-accepted",
    "muted": "risk-accepted",
    "ignored": "risk-accepted",
    "dismissed": "risk-accepted",
    "wont_fix": "risk-accepted",
    "wontfix": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "expired": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - AmazonInspector: {msg}", file=sys.stderr, flush=True)


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
    if score > 10:
        return "info"
    return "critical"


def severity_from_inspector(value, cvss=None):
    """Map an Inspector v2 severity to a Faraday bucket.

    Accepts Inspector's UPPERCASE enum (CRITICAL / HIGH / MEDIUM / LOW /
    INFORMATIONAL / UNTRIAGED) and falls back to CVSS bucketing on
    ``cvss`` when the primary value is missing or unrecognised. Numeric
    inputs are interpreted as CVSS base scores.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in INSPECTOR_STRING_SEVERITY:
            return INSPECTOR_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_inspector(finding):
    """Derive Faraday status from an Inspector v2 finding payload."""
    if not isinstance(finding, dict):
        return "open"
    for key in ("status", "state", "findingStatus", "finding_status"):
        raw = finding.get(key)
        if isinstance(raw, dict):
            raw = raw.get("name") or raw.get("value")
        if isinstance(raw, str):
            mapped = INSPECTOR_STATUS_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
            if mapped:
                return mapped
            compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if compact in INSPECTOR_STATUS_TO_FARADAY:
                return INSPECTOR_STATUS_TO_FARADAY[compact]
    return "open"


def validate_resource_type(value):
    """Validate INSPECTOR_RESOURCE_TYPE.

    Accepts the canonical UPPERCASE enum
    (AWS_EC2_INSTANCE | AWS_ECR_CONTAINER_IMAGE | AWS_LAMBDA_FUNCTION)
    plus short friendly aliases (ec2 / instance, ecr / image / container,
    lambda / function). Whitespace and case-insensitive. None / blank /
    garbage -> None (no resourceType filter, the tenant returns
    findings for every resource type the IAM principal can read).
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    normalised = text.upper().replace(" ", "_").replace("-", "_")
    aliases = {
        "EC2": "AWS_EC2_INSTANCE",
        "INSTANCE": "AWS_EC2_INSTANCE",
        "EC2_INSTANCE": "AWS_EC2_INSTANCE",
        "ECR": "AWS_ECR_CONTAINER_IMAGE",
        "IMAGE": "AWS_ECR_CONTAINER_IMAGE",
        "CONTAINER": "AWS_ECR_CONTAINER_IMAGE",
        "ECR_IMAGE": "AWS_ECR_CONTAINER_IMAGE",
        "ECR_CONTAINER": "AWS_ECR_CONTAINER_IMAGE",
        "ECR_CONTAINER_IMAGE": "AWS_ECR_CONTAINER_IMAGE",
        "LAMBDA": "AWS_LAMBDA_FUNCTION",
        "FUNCTION": "AWS_LAMBDA_FUNCTION",
        "LAMBDA_FUNCTION": "AWS_LAMBDA_FUNCTION",
    }
    if normalised in VALID_RESOURCE_TYPES:
        return normalised
    if normalised in aliases:
        return aliases[normalised]
    log(f"INSPECTOR_RESOURCE_TYPE '{value}' not recognised; ignored (no filter)")
    return None


def validate_severities(value):
    """Validate INSPECTOR_SEVERITIES (CSV / list).

    Returns the list of Inspector-API severity tokens (UPPERCASE) to
    forward in ``filterCriteria.severity``. None / blank / all-garbage
    -> None (no severity filter, the tenant returns every severity).
    Dash / underscore / whitespace tolerated, case-insensitive, deduped.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (list, tuple, set)):
        text = ",".join(str(v) for v in value)
    else:
        text = str(value)
    raw = [t.strip().upper().replace("-", "_").replace(" ", "_") for t in text.split(",") if t.strip()]
    out = []
    for token in raw:
        if token in INSPECTOR_API_SEVERITY.values():
            if token not in out:
                out.append(token)
            continue
        bucket = INSPECTOR_STRING_SEVERITY.get(token.lower())
        if bucket:
            api = INSPECTOR_API_SEVERITY.get(bucket)
            if api and api not in out:
                out.append(api)
            continue
        log(f"INSPECTOR_SEVERITIES token '{token}' not recognised; ignored")
    return out or None


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"min_severity '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def severities_at_or_above(min_severity):
    """Return the Inspector-API severity tokens at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for bucket, order in SEVERITY_ORDER.items():
        if order >= floor:
            api = INSPECTOR_API_SEVERITY.get(bucket)
            if api and api not in out:
                out.append(api)
    return out


def build_filter(resource_type, severities):
    """Build the Inspector v2 ``filterCriteria`` dict.

    Returns ``{}`` (no filter) when neither resource_type nor severities
    is set. Both criteria are expressed as
    ``{'comparison': 'EQUALS', 'value': '...'}`` entries — boto3 accepts
    a list of such entries per criterion key.
    """
    flt = {}
    if resource_type:
        flt["resourceType"] = [{"comparison": "EQUALS", "value": resource_type}]
    if severities:
        flt["severity"] = [{"comparison": "EQUALS", "value": s} for s in severities]
    return flt


def cvss_score(finding):
    """Pull a numeric CVSS score out of an Inspector v2 finding payload.

    Walks the canonical top-level ``inspectorScore`` first, then the
    nested ``packageVulnerabilityDetails.cvss`` list (Inspector v2's
    canonical CVSS surface — list of {baseScore, scoringVector, source,
    version}), then the usual ``baseScore`` / ``score`` synonyms.
    """
    if not isinstance(finding, dict):
        return None
    score = finding.get("inspectorScore")
    if score is not None and not isinstance(score, (dict, list, bool)):
        try:
            return float(score)
        except (TypeError, ValueError):
            pass
    pvd = finding.get("packageVulnerabilityDetails")
    if isinstance(pvd, dict):
        cvss_list = pvd.get("cvss")
        if isinstance(cvss_list, list):
            for entry in cvss_list:
                if not isinstance(entry, dict):
                    continue
                for k in ("baseScore", "base_score", "score"):
                    v = entry.get(k)
                    if v is None or isinstance(v, (dict, list, bool)):
                        continue
                    try:
                        return float(v)
                    except (TypeError, ValueError):
                        continue
    for key in ("cvssScore", "cvss_score", "score", "baseScore", "base_score"):
        v = finding.get(key)
        if v is None or isinstance(v, (dict, list, bool)):
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = finding.get(nested_key)
        if isinstance(nested, dict):
            for k in ("score", "baseScore", "base_score"):
                v = nested.get(k)
                if v is None or isinstance(v, (dict, list, bool)):
                    continue
                try:
                    return float(v)
                except (TypeError, ValueError):
                    continue
    return None


def cvss_vector(finding):
    if not isinstance(finding, dict):
        return ""
    pvd = finding.get("packageVulnerabilityDetails")
    if isinstance(pvd, dict):
        cvss_list = pvd.get("cvss")
        if isinstance(cvss_list, list):
            for entry in cvss_list:
                if isinstance(entry, dict):
                    for k in ("scoringVector", "vector", "vectorString", "vector_string"):
                        v = entry.get(k)
                        if isinstance(v, str) and v.strip():
                            return v.strip()
    for key in ("cvssVector", "cvss_vector", "vector"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2", "cvssV2", "cvss_v2"):
        nested = finding.get(nested_key)
        if isinstance(nested, dict):
            for k in ("vector", "vectorString", "vector_string"):
                v = nested.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def collect_cves(finding):
    """Pull CVE-* ids out of an Inspector v2 finding payload.

    Walks the canonical ``packageVulnerabilityDetails.vulnerabilityId``
    + ``relatedVulnerabilities`` surfaces, then falls back to title /
    description token scans (defensive — Inspector v2 sometimes surfaces
    a CVE only in the title for code-vulnerability findings).
    """
    found = []
    seen = set()

    def add_token(text):
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
        for match in CVE_RE.findall(text):
            add_token(match)

    if not isinstance(finding, dict):
        return found

    pvd = finding.get("packageVulnerabilityDetails")
    if isinstance(pvd, dict):
        add_token(pvd.get("vulnerabilityId"))
        related = pvd.get("relatedVulnerabilities")
        if isinstance(related, list):
            for entry in related:
                if isinstance(entry, str):
                    add_token(entry)
                elif isinstance(entry, dict):
                    add_token(entry.get("id") or entry.get("vulnerabilityId") or entry.get("cve"))

    for key in ("title", "description", "name", "summary"):
        v = finding.get(key)
        if isinstance(v, str):
            scan(v)
    for key in ("cve", "cveId", "cve_id"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            add_token(v)
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = finding.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add_token(entry)
                elif isinstance(entry, dict):
                    add_token(entry.get("id") or entry.get("name") or entry.get("cve") or entry.get("cveId"))

    cvd = finding.get("codeVulnerabilityDetails")
    if isinstance(cvd, dict):
        for key in ("ruleId", "rule_id", "detectorId", "detector_id"):
            v = cvd.get(key)
            if isinstance(v, str):
                scan(v)

    return found


def collect_refs(finding):
    """Walk an Inspector v2 finding for CWE / advisory URL refs."""
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

    if not isinstance(finding, dict):
        return refs

    def add_cwe(value):
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, (int, float)):
            add(f"CWE-{int(value)}")
            return
        if isinstance(value, str) and value.strip():
            s = value.strip()
            add(s if s.upper().startswith("CWE-") else f"CWE-{s}")
            return
        if isinstance(value, dict):
            cid = value.get("id") or value.get("value") or value.get("name")
            if cid is not None:
                add_cwe(cid)

    for source_key in ("cweId", "cwe_id", "cwe"):
        add_cwe(finding.get(source_key))
    for source_key in ("cwes", "cweIds", "cwe_ids"):
        items = finding.get(source_key)
        if isinstance(items, list):
            for it in items:
                add_cwe(it)

    cvd = finding.get("codeVulnerabilityDetails")
    if isinstance(cvd, dict):
        cwes = cvd.get("cwes")
        if isinstance(cwes, list):
            for it in cwes:
                add_cwe(it)
        rule_id = cvd.get("ruleId") or cvd.get("rule_id")
        if isinstance(rule_id, str) and rule_id.strip():
            add(f"Inspector-Rule: {rule_id.strip()}")
        detector_id = cvd.get("detectorId") or cvd.get("detector_id")
        if isinstance(detector_id, str) and detector_id.strip():
            add(f"Inspector-Detector: {detector_id.strip()}")
        urls = cvd.get("referenceUrls")
        if isinstance(urls, list):
            for u in urls:
                if isinstance(u, str) and u.strip():
                    add(u.strip())

    pvd = finding.get("packageVulnerabilityDetails")
    if isinstance(pvd, dict):
        vid = pvd.get("vulnerabilityId")
        if isinstance(vid, str) and vid.strip():
            add(f"Inspector-Vuln: {vid.strip()}")
        for u_key in ("sourceUrl", "source_url"):
            u = pvd.get(u_key)
            if isinstance(u, str) and u.strip():
                add(u.strip())
        urls = pvd.get("referenceUrls")
        if isinstance(urls, list):
            for u in urls:
                if isinstance(u, str) and u.strip():
                    add(u.strip())

    for key in ("references", "links", "externalReferences", "external_references"):
        entry = finding.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("name") or it.get("value")
                    if href:
                        add(href)
                elif it:
                    add(str(it))
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    remediation = finding.get("remediation")
    if isinstance(remediation, dict):
        recommendation = remediation.get("recommendation")
        if isinstance(recommendation, dict):
            url = recommendation.get("Url") or recommendation.get("url")
            if isinstance(url, str) and url.strip():
                add(url.strip())

    return refs


def resource_label(resource):
    """Build a friendly label for an Inspector v2 affected resource."""
    if not isinstance(resource, dict):
        return ""
    rid = resource.get("id") or ""
    rtype = resource.get("type") or ""
    region = resource.get("region") or ""
    details = resource.get("details") if isinstance(resource.get("details"), dict) else {}
    name = ""
    if isinstance(details, dict):
        ec2 = details.get("awsEc2Instance") if isinstance(details.get("awsEc2Instance"), dict) else {}
        ecr = details.get("awsEcrContainerImage") if isinstance(details.get("awsEcrContainerImage"), dict) else {}
        lam = details.get("awsLambdaFunction") if isinstance(details.get("awsLambdaFunction"), dict) else {}
        if ec2:
            name = ec2.get("instanceId") or ec2.get("imageId") or ""
        elif ecr:
            repo = ecr.get("repositoryName") or ""
            tag = ""
            tags = ecr.get("imageTags")
            if isinstance(tags, list) and tags:
                tag = str(tags[0])
            digest = ecr.get("imageHash") or ""
            if repo and tag:
                name = f"{repo}:{tag}"
            elif repo and digest:
                name = f"{repo}@{digest[:12]}"
            else:
                name = repo or digest
        elif lam:
            name = lam.get("functionName") or lam.get("name") or ""
    if name and rtype:
        label = f"{rtype} {name}"
    elif name:
        label = name
    elif rtype and rid:
        label = f"{rtype} {rid}"
    else:
        label = rid or rtype or ""
    if region:
        label = f"{label} [{region}]" if label else f"[{region}]"
    return str(label).strip()


def vuln_label(finding):
    """Build the leading title fragment for a finding."""
    if not isinstance(finding, dict):
        return ""
    pvd = finding.get("packageVulnerabilityDetails")
    if isinstance(pvd, dict):
        vid = pvd.get("vulnerabilityId")
        if isinstance(vid, str) and vid.strip():
            return vid.strip()
    title = finding.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()
    return str(finding.get("findingArn") or finding.get("id") or "Inspector finding").strip()


def _serialise(obj):
    """Best-effort to-string for boto3 datetime / decimal values."""
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


def build_vulnerability(finding):
    """Build a Faraday vulnerability dict from one Inspector v2 finding."""
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding)
    severity = severity_from_inspector(finding.get("severity"), score)
    status = status_from_inspector(finding)

    resources = finding.get("resources") if isinstance(finding.get("resources"), list) else []
    primary_resource = next((r for r in resources if isinstance(r, dict)), {})
    rlabel = resource_label(primary_resource)
    vlabel = vuln_label(finding)
    raw_name = f"{vlabel} on {rlabel}" if rlabel else vlabel
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = finding.get("description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    pvd = finding.get("packageVulnerabilityDetails")
    if isinstance(pvd, dict):
        vid = pvd.get("vulnerabilityId")
        if vid:
            desc_parts.append(f"vulnerability_id: {vid}")
        source = pvd.get("source")
        if source:
            desc_parts.append(f"source: {source}")
        vendor_sev = pvd.get("vendorSeverity")
        if vendor_sev:
            desc_parts.append(f"vendor_severity: {vendor_sev}")
        vuln_pkgs = pvd.get("vulnerablePackages")
        if isinstance(vuln_pkgs, list) and vuln_pkgs:
            pkg_lines = []
            for pkg in vuln_pkgs:
                if not isinstance(pkg, dict):
                    continue
                pname = pkg.get("name") or pkg.get("packageName") or ""
                pver = pkg.get("version") or pkg.get("packageVersion") or ""
                parch = pkg.get("arch") or ""
                fixed = pkg.get("fixedInVersion") or pkg.get("fixed_in_version") or ""
                bits = []
                if pname:
                    bits.append(pname)
                if pver:
                    bits.append(f"version={pver}")
                if parch:
                    bits.append(f"arch={parch}")
                if fixed:
                    bits.append(f"fixed_in={fixed}")
                if bits:
                    pkg_lines.append("  " + " ".join(bits))
            if pkg_lines:
                desc_parts.append("vulnerable_packages:")
                desc_parts.extend(pkg_lines)

    cvd = finding.get("codeVulnerabilityDetails")
    if isinstance(cvd, dict):
        rule_id = cvd.get("ruleId") or cvd.get("rule_id")
        if rule_id:
            desc_parts.append(f"rule_id: {rule_id}")
        detector_id = cvd.get("detectorId") or cvd.get("detector_id")
        if detector_id:
            desc_parts.append(f"detector_id: {detector_id}")
        detector_name = cvd.get("detectorName") or cvd.get("detector_name")
        if detector_name:
            desc_parts.append(f"detector_name: {detector_name}")
        file_path = cvd.get("filePath") if isinstance(cvd.get("filePath"), dict) else None
        if file_path:
            fp = file_path.get("filePath") or file_path.get("file_path") or ""
            start = file_path.get("startLine") or file_path.get("start_line")
            end = file_path.get("endLine") or file_path.get("end_line")
            if fp:
                rng = ""
                if start is not None and end is not None:
                    rng = f":{start}-{end}"
                desc_parts.append(f"file_path: {fp}{rng}")

    nrd = finding.get("networkReachabilityDetails")
    if isinstance(nrd, dict):
        proto = nrd.get("protocol")
        port_range = nrd.get("openPortRange") if isinstance(nrd.get("openPortRange"), dict) else None
        if proto:
            desc_parts.append(f"protocol: {proto}")
        if port_range:
            begin = port_range.get("begin")
            end = port_range.get("end")
            if begin is not None and end is not None:
                desc_parts.append(f"open_port_range: {begin}-{end}")

    if rlabel:
        desc_parts.append(f"resource: {rlabel}")
    if isinstance(primary_resource, dict):
        for label, key in (
            ("resource_id", "id"),
            ("resource_type", "type"),
            ("region", "region"),
            ("partition", "partition"),
        ):
            val = primary_resource.get(key)
            if val:
                desc_parts.append(f"{label}: {val}")
    acct = finding.get("awsAccountId")
    if acct:
        desc_parts.append(f"aws_account_id: {acct}")
    f_type = finding.get("type")
    if f_type:
        desc_parts.append(f"type: {f_type}")
    f_status = finding.get("status")
    if f_status:
        desc_parts.append(f"status: {f_status}")
    f_sev = finding.get("severity")
    if f_sev:
        desc_parts.append(f"severity: {f_sev}")
    fix_avail = finding.get("fixAvailable")
    if fix_avail:
        desc_parts.append(f"fix_available: {fix_avail}")
    exploit_avail = finding.get("exploitAvailable")
    if exploit_avail:
        desc_parts.append(f"exploit_available: {exploit_avail}")
    epss = finding.get("epss")
    if isinstance(epss, dict):
        epss_score = epss.get("score")
        if epss_score is not None:
            desc_parts.append(f"epss_score: {epss_score}")
    for label, key in (
        ("first_observed", "firstObservedAt"),
        ("last_observed", "lastObservedAt"),
        ("updated", "updatedAt"),
    ):
        val = finding.get(key)
        if val:
            desc_parts.append(f"{label}: {_serialise(val)}")
    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(finding)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(finding)
    refs = collect_refs(finding)

    resolution = ""
    remediation = finding.get("remediation")
    if isinstance(remediation, dict):
        recommendation = remediation.get("recommendation")
        if isinstance(recommendation, dict):
            text = recommendation.get("text") or recommendation.get("Text")
            if isinstance(text, str) and text.strip():
                resolution = text.strip()
        elif isinstance(recommendation, str) and recommendation.strip():
            resolution = recommendation.strip()
    if not resolution and isinstance(pvd, dict):
        vps = pvd.get("vulnerablePackages")
        if isinstance(vps, list):
            fixes = []
            for pkg in vps:
                if not isinstance(pkg, dict):
                    continue
                pname = pkg.get("name") or pkg.get("packageName")
                fixed = pkg.get("fixedInVersion") or pkg.get("fixed_in_version")
                if pname and fixed:
                    fixes.append(f"Upgrade {pname} to {fixed}.")
            if fixes:
                resolution = " ".join(fixes)

    external_id = str(finding.get("findingArn") or finding.get("id") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Inspector finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["amazon_inspector", "cnapp", "cloud-native-posture"],
    }


def host_bucket_key(finding):
    """Pick a stable bucket key for a finding's primary resource."""
    if not isinstance(finding, dict):
        return "__unknown__"
    resources = finding.get("resources") if isinstance(finding.get("resources"), list) else []
    for r in resources:
        if not isinstance(r, dict):
            continue
        rid = r.get("id")
        if isinstance(rid, str) and rid.strip():
            return rid.strip()
    return "__unknown__"


def _resource_ip(resource):
    """Best-effort IP harvest from an EC2 resource details payload."""
    if not isinstance(resource, dict):
        return ""
    details = resource.get("details") if isinstance(resource.get("details"), dict) else {}
    ec2 = details.get("awsEc2Instance") if isinstance(details.get("awsEc2Instance"), dict) else {}
    for key in ("ipV4Addresses", "ipv4Addresses", "ipV4Address", "ipv4Address"):
        val = ec2.get(key)
        if isinstance(val, list) and val:
            first = val[0]
            if isinstance(first, str) and first.strip():
                return first.strip()
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def build_host(bucket_key, sample_resource, vulns):
    """Build a Faraday host record for the supplied resource bucket."""
    rtype = ""
    region = ""
    details_blob = {}
    if isinstance(sample_resource, dict):
        rtype = sample_resource.get("type") or ""
        region = sample_resource.get("region") or ""
        details_blob = sample_resource.get("details") if isinstance(sample_resource.get("details"), dict) else {}

    label = resource_label(sample_resource) if sample_resource else ""
    hostname = ""
    if label and bucket_key and bucket_key != "__unknown__":
        hostname = f"{label}@{bucket_key}"
    elif label:
        hostname = label
    elif bucket_key and bucket_key != "__unknown__":
        hostname = bucket_key
    ip = _resource_ip(sample_resource) or "0.0.0.0"

    desc_parts = []
    if bucket_key and bucket_key != "__unknown__":
        desc_parts.append(f"resource_id={bucket_key}")
    if rtype:
        desc_parts.append(f"resource_type={rtype}")
    if region:
        desc_parts.append(f"region={region}")
    if isinstance(details_blob, dict):
        ec2 = details_blob.get("awsEc2Instance") if isinstance(details_blob.get("awsEc2Instance"), dict) else {}
        ecr = (
            details_blob.get("awsEcrContainerImage")
            if isinstance(details_blob.get("awsEcrContainerImage"), dict)
            else {}
        )
        lam = details_blob.get("awsLambdaFunction") if isinstance(details_blob.get("awsLambdaFunction"), dict) else {}
        if ec2:
            for label_k, key in (
                ("instance_id", "instanceId"),
                ("image_id", "imageId"),
                ("platform", "platform"),
                ("vpc_id", "vpcId"),
                ("type", "type"),
            ):
                v = ec2.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
        if ecr:
            for label_k, key in (
                ("repository", "repositoryName"),
                ("registry", "registry"),
                ("image_hash", "imageHash"),
            ):
                v = ecr.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
            tags = ecr.get("imageTags")
            if isinstance(tags, list) and tags:
                desc_parts.append(f"image_tags={','.join(str(t) for t in tags)}")
        if lam:
            for label_k, key in (
                ("function_name", "functionName"),
                ("runtime", "runtime"),
                ("layers", "layers"),
                ("version", "version"),
            ):
                v = lam.get(key)
                if v:
                    if isinstance(v, list):
                        desc_parts.append(f"{label_k}={','.join(str(x) for x in v)}")
                    else:
                        desc_parts.append(f"{label_k}={v}")
    if vulns:
        desc_parts.append(f"findings={len(vulns)}")

    return {
        "ip": ip,
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_findings(client, filter_criteria, max_pages=200, page_size=100):
    """Paginate ``inspector2.list_findings`` with the supplied filter."""
    findings = []
    paginator = client.get_paginator("list_findings")
    kwargs = {"maxResults": page_size}
    if filter_criteria:
        kwargs["filterCriteria"] = filter_criteria
    pages = 0
    for page in paginator.paginate(**kwargs):
        pages += 1
        page_findings = page.get("findings") if isinstance(page, dict) else None
        if isinstance(page_findings, list):
            for f in page_findings:
                if isinstance(f, dict):
                    findings.append(f)
        if pages >= max_pages:
            log(f"hit MAX_PAGES={max_pages}; stopping pagination")
            break
    return findings


def main():
    started = time.time()
    region = env("EXECUTOR_CONFIG_AWS_REGION") or env("AWS_REGION") or env("AWS_DEFAULT_REGION")
    if not region:
        log("AWS_REGION is required (Inspector v2 endpoints are regional)")
        sys.exit(1)

    resource_type = validate_resource_type(env("EXECUTOR_CONFIG_INSPECTOR_RESOURCE_TYPE"))
    severities = validate_severities(env("EXECUTOR_CONFIG_INSPECTOR_SEVERITIES"))

    access_key = env("AWS_ACCESS_KEY_ID")
    secret_key = env("AWS_SECRET_ACCESS_KEY")
    session_token = env("AWS_SESSION_TOKEN")
    if not access_key or not secret_key:
        log("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required")
        sys.exit(1)

    try:
        import boto3  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("boto3 is not installed in the executor environment")
        sys.exit(1)

    client = boto3.client(
        "inspector2",
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )

    filter_criteria = build_filter(resource_type, severities)
    findings = fetch_findings(client, filter_criteria)
    log(
        f"Processing {len(findings)} Inspector v2 findings "
        f"(region={region}, resource_type={resource_type or 'ALL'}, "
        f"severities={','.join(severities) if severities else 'ALL'})"
    )

    buckets = {}
    sample_resources = {}
    for finding in findings:
        key = host_bucket_key(finding)
        buckets.setdefault(key, []).append(finding)
        if key not in sample_resources:
            resources = finding.get("resources") if isinstance(finding.get("resources"), list) else []
            for r in resources:
                if isinstance(r, dict) and (r.get("id") or "").strip() == key:
                    sample_resources[key] = r
                    break

    hosts = []
    for key, items in buckets.items():
        vulns = []
        for finding in items:
            built = build_vulnerability(finding)
            if built is None:
                continue
            vulns.append(built)
        if not vulns:
            continue
        sample = sample_resources.get(key)
        hosts.append(build_host(key, sample, vulns))

    params_bits = [f"region={region}"]
    if resource_type:
        params_bits.append(f"resource_type={resource_type}")
    if severities:
        params_bits.append(f"severities={'|'.join(severities)}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "amazon_inspector",
            "command": "amazon_inspector",
            "params": ",".join(params_bits),
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
