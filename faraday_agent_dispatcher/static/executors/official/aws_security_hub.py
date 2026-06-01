#!/usr/bin/env python
"""AWS Security Hub vendor-native CSPM importer.

Pulls security findings from AWS Security Hub via the canonical
``securityhub.get_findings`` boto3 API and emits Faraday bulk-create
JSON to stdout. Security Hub aggregates findings from native AWS
services (GuardDuty, Inspector, Macie, IAM Access Analyzer, Firewall
Manager) and third-party partner integrations using the AWS Security
Finding Format (ASFF). Each affected AWS resource
(``Finding.Resources[0]``) becomes one Faraday host (synthetic
``0.0.0.0`` ip; EC2 instances surface the first
``Resources[].Details.AwsEc2Instance.IpV4Addresses`` entry as the host
IP when present); per-resource findings attach as Faraday
vulnerabilities — one per Security Hub finding ``Id`` with engine
prefix ``[CNAPP]``.

Endpoints used:
  ``boto3.client('securityhub').get_findings(Filters=..., MaxResults=...)``
      -> paginated via boto3's ``get_findings`` paginator (Security Hub
      caps page size at 100). Filters are passed through verbatim as
      the JSON-encoded ``AwsSecurityFindingFilters`` document the
      operator supplies via ``SECHUB_FILTERS_JSON``.

Auth: AWS Security Hub uses the standard AWS SigV4 credential chain.
A service account ("IAM principal") with the ``securityhub:GetFindings``
permission is required, with credentials exposed to the dispatcher as
``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` (+ optional
``AWS_SESSION_TOKEN`` for STS-vended session credentials). The
``AWS_REGION`` arg pins the regional Security Hub endpoint (Security
Hub is regional and only returns findings ingested into the queried
region).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# ASFF severity Label enum: CRITICAL / HIGH / MEDIUM / LOW /
# INFORMATIONAL. Map to Faraday's five-bucket scheme, plus the usual
# vendor synonyms operators encounter.
SECHUB_STRING_SEVERITY = {
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
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
}

# Workflow.Status enum (ASFF): NEW / NOTIFIED / RESOLVED / SUPPRESSED.
SECHUB_WORKFLOW_TO_FARADAY = {
    "new": "open",
    "notified": "open",
    "in_progress": "open",
    "inprogress": "open",
    "open": "open",
    "active": "open",
    "resolved": "closed",
    "closed": "closed",
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

DEFAULT_MAX_RESULTS = 1000
PAGE_SIZE = 100  # Security Hub caps get_findings at 100/page.


def log(msg):
    print(f"{datetime.utcnow()} - AwsSecurityHub: {msg}", file=sys.stderr, flush=True)


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
    if score > 10:
        return "info"
    return "critical"


def severity_from_normalized(value):
    """Map ASFF Severity.Normalized (0-100) to a Faraday bucket."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "info"
    if score <= 0:
        return "info"
    if score < 40:
        return "low"
    if score < 70:
        return "medium"
    if score < 90:
        return "high"
    if score > 100:
        return "info"
    return "critical"


def severity_from_sechub(severity, cvss=None):
    """Map a Security Hub severity blob to a Faraday bucket.

    Accepts the ASFF ``Severity`` dict
    ({``Label``, ``Normalized``, ``Original``, ``Product``}), a bare
    string label (CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL plus
    the usual Faraday synonyms), or a numeric Normalized score (0-100).
    Falls back to ``cvss`` (0-10 CVSS base score) when the primary
    value is missing or unrecognised.
    """
    if isinstance(severity, dict):
        label = severity.get("Label") or severity.get("label")
        if isinstance(label, str):
            mapped = SECHUB_STRING_SEVERITY.get(label.strip().lower())
            if mapped:
                return mapped
        for key in ("Normalized", "normalized"):
            v = severity.get(key)
            if v is None or isinstance(v, (dict, list, bool)):
                continue
            try:
                return severity_from_normalized(float(v))
            except (TypeError, ValueError):
                continue
        for key in ("Product", "product"):
            v = severity.get(key)
            if v is None or isinstance(v, (dict, list, bool)):
                continue
            try:
                return severity_from_normalized(float(v))
            except (TypeError, ValueError):
                continue
        original = severity.get("Original") or severity.get("original")
        if isinstance(original, str):
            mapped = SECHUB_STRING_SEVERITY.get(original.strip().lower())
            if mapped:
                return mapped
            try:
                return severity_from_normalized(float(original))
            except (TypeError, ValueError):
                pass
    elif severity is not None and not isinstance(severity, bool):
        if isinstance(severity, (int, float)):
            return severity_from_normalized(severity)
        text = str(severity).strip().lower()
        if text in SECHUB_STRING_SEVERITY:
            return SECHUB_STRING_SEVERITY[text]
        try:
            return severity_from_normalized(float(text))
        except (TypeError, ValueError):
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_sechub(finding):
    """Derive Faraday status from an ASFF finding payload.

    Reads ``Workflow.Status`` first (NEW / NOTIFIED / RESOLVED /
    SUPPRESSED). Falls back to top-level ``RecordState`` (ARCHIVED ->
    closed). Defaults to ``open`` when no recognisable status is
    present.
    """
    if not isinstance(finding, dict):
        return "open"
    workflow = finding.get("Workflow") or finding.get("workflow")
    if isinstance(workflow, dict):
        for key in ("Status", "status"):
            raw = workflow.get(key)
            if isinstance(raw, dict):
                raw = raw.get("name") or raw.get("value") or raw.get("Name") or raw.get("Value")
            if isinstance(raw, str):
                mapped = SECHUB_WORKFLOW_TO_FARADAY.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))
                if mapped:
                    return mapped
                compact = raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
                if compact in SECHUB_WORKFLOW_TO_FARADAY:
                    return SECHUB_WORKFLOW_TO_FARADAY[compact]
    for key in ("RecordState", "recordState", "record_state"):
        rs = finding.get(key)
        if isinstance(rs, str):
            text = rs.strip().lower()
            if text == "archived":
                return "closed"
            if text == "active":
                return "open"
    return "open"


def validate_filters(value):
    """Validate SECHUB_FILTERS_JSON.

    Accepts a JSON object (or dict passthrough) matching the ASFF
    ``AwsSecurityFindingFilters`` shape. Forwarded verbatim as the
    ``Filters`` arg to ``get_findings``. None / blank / invalid JSON /
    non-object -> None (no filter; the tenant returns every finding
    the IAM principal can read).
    """
    if value is None:
        return None
    if isinstance(value, dict):
        return value or None
    if not isinstance(value, str):
        log(f"SECHUB_FILTERS_JSON must be a JSON object string; ignoring (got {type(value).__name__})")
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError) as exc:
        log(f"SECHUB_FILTERS_JSON is not valid JSON ({exc}); ignoring")
        return None
    if not isinstance(parsed, dict):
        log(f"SECHUB_FILTERS_JSON must be a JSON object; ignoring (got {type(parsed).__name__})")
        return None
    return parsed or None


def validate_max_results(value):
    """Validate SECHUB_MAX_RESULTS.

    Accepts a positive integer. None / blank / non-numeric / non-positive
    -> ``DEFAULT_MAX_RESULTS`` (1000). The boto3 paginator still emits
    pages of ``PAGE_SIZE`` (100) — this cap stops iteration as soon as
    the requested number of findings has been collected.
    """
    if value is None or value == "":
        return DEFAULT_MAX_RESULTS
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        log(f"SECHUB_MAX_RESULTS '{value}' not a valid integer; defaulting to {DEFAULT_MAX_RESULTS}")
        return DEFAULT_MAX_RESULTS
    if n <= 0:
        log(f"SECHUB_MAX_RESULTS must be positive; defaulting to {DEFAULT_MAX_RESULTS}")
        return DEFAULT_MAX_RESULTS
    return n


def cvss_score(finding):
    """Pull a numeric CVSS score out of an ASFF finding payload.

    Walks ``Vulnerabilities[].Cvss[].BaseScore`` first (ASFF's
    canonical CVSS surface), then falls back to top-level
    ``Severity.Product`` (the vendor-native 0-100 raw score) when no
    CVSS entry is present.
    """
    if not isinstance(finding, dict):
        return None
    vulns = finding.get("Vulnerabilities") or finding.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cvss_list = v.get("Cvss") or v.get("cvss")
            if isinstance(cvss_list, list):
                for entry in cvss_list:
                    if not isinstance(entry, dict):
                        continue
                    for k in ("BaseScore", "baseScore", "base_score", "Score", "score"):
                        val = entry.get(k)
                        if val is None or isinstance(val, (dict, list, bool)):
                            continue
                        try:
                            return float(val)
                        except (TypeError, ValueError):
                            continue
    for key in ("BaseScore", "baseScore", "base_score", "Score", "score"):
        v = finding.get(key)
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
    vulns = finding.get("Vulnerabilities") or finding.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cvss_list = v.get("Cvss") or v.get("cvss")
            if isinstance(cvss_list, list):
                for entry in cvss_list:
                    if not isinstance(entry, dict):
                        continue
                    for k in (
                        "BaseVector",
                        "baseVector",
                        "base_vector",
                        "Vector",
                        "vector",
                        "VectorString",
                        "vectorString",
                    ):
                        s = entry.get(k)
                        if isinstance(s, str) and s.strip():
                            return s.strip()
    for k in ("Vector", "vector", "VectorString", "vectorString"):
        s = finding.get(k)
        if isinstance(s, str) and s.strip():
            return s.strip()
    return ""


def collect_cves(finding):
    """Pull CVE-* ids out of an ASFF finding payload.

    Walks the canonical ``Vulnerabilities[].Id`` +
    ``Vulnerabilities[].RelatedVulnerabilities[]`` surfaces, then falls
    back to title / description token scans (defensive — Security Hub
    often surfaces a CVE only in the title for ingested findings from
    partner products that don't populate the Vulnerabilities array).
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

    if not isinstance(finding, dict):
        return found

    vulns = finding.get("Vulnerabilities") or finding.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            add(v.get("Id") or v.get("id"))
            rel = (
                v.get("RelatedVulnerabilities") or v.get("relatedVulnerabilities") or v.get("related_vulnerabilities")
            )
            if isinstance(rel, list):
                for r in rel:
                    if isinstance(r, str):
                        add(r)
                    elif isinstance(r, dict):
                        add(r.get("Id") or r.get("id") or r.get("vulnerabilityId") or r.get("cve"))

    for key in ("Title", "title", "Description", "description"):
        scan(finding.get(key))

    for key in ("cve", "cveId", "cve_id"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            add(v)
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = finding.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(
                        entry.get("Id")
                        or entry.get("id")
                        or entry.get("name")
                        or entry.get("cve")
                        or entry.get("cveId")
                    )

    return found


def collect_refs(finding):
    """Walk an ASFF finding for CWE / advisory URL refs."""
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
            cid = value.get("Id") or value.get("id") or value.get("value") or value.get("name")
            if cid is not None:
                add_cwe(cid)

    if not isinstance(finding, dict):
        return refs

    for source_key in ("cweId", "cwe_id", "cwe"):
        add_cwe(finding.get(source_key))
    for source_key in ("cwes", "cweIds", "cwe_ids"):
        items = finding.get(source_key)
        if isinstance(items, list):
            for it in items:
                add_cwe(it)

    src = finding.get("SourceUrl") or finding.get("sourceUrl")
    if isinstance(src, str) and src.strip():
        add(src.strip())

    gid = finding.get("GeneratorId") or finding.get("generatorId")
    if isinstance(gid, str) and gid.strip():
        add(f"SecHub-Generator: {gid.strip()}")

    parn = finding.get("ProductArn") or finding.get("productArn")
    if isinstance(parn, str) and parn.strip():
        add(f"SecHub-Product: {parn.strip()}")

    vulns = finding.get("Vulnerabilities") or finding.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vid = v.get("Id") or v.get("id")
            if isinstance(vid, str) and vid.strip():
                add(f"SecHub-Vuln: {vid.strip()}")
            urls = v.get("ReferenceUrls") or v.get("referenceUrls")
            if isinstance(urls, list):
                for u in urls:
                    if isinstance(u, str) and u.strip():
                        add(u.strip())
            vendor = v.get("Vendor") or v.get("vendor")
            if isinstance(vendor, dict):
                u = vendor.get("Url") or vendor.get("url")
                if isinstance(u, str) and u.strip():
                    add(u.strip())
            code_vulns = v.get("CodeVulnerabilities") or v.get("codeVulnerabilities")
            if isinstance(code_vulns, list):
                for cv in code_vulns:
                    if not isinstance(cv, dict):
                        continue
                    cwes = cv.get("Cwes") or cv.get("cwes")
                    if isinstance(cwes, list):
                        for c in cwes:
                            add_cwe(c)
                    src_arn = cv.get("SourceArn") or cv.get("sourceArn")
                    if isinstance(src_arn, str) and src_arn.strip():
                        add(src_arn.strip())

    rem = finding.get("Remediation") or finding.get("remediation")
    if isinstance(rem, dict):
        rec = rem.get("Recommendation") or rem.get("recommendation")
        if isinstance(rec, dict):
            for k in ("Url", "url"):
                u = rec.get(k)
                if isinstance(u, str) and u.strip():
                    add(u.strip())

    comp = finding.get("Compliance") or finding.get("compliance")
    if isinstance(comp, dict):
        reqs = comp.get("RelatedRequirements") or comp.get("relatedRequirements")
        if isinstance(reqs, list):
            for r in reqs:
                if isinstance(r, str) and r.strip():
                    add(f"Compliance: {r.strip()}")

    for key in ("References", "references", "Links", "links"):
        entry = finding.get(key)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = (
                        it.get("Url")
                        or it.get("url")
                        or it.get("Href")
                        or it.get("href")
                        or it.get("name")
                        or it.get("value")
                    )
                    if href:
                        add(href)
                elif it:
                    add(str(it))
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def resource_label(resource):
    """Build a friendly label for an ASFF Resource entry."""
    if not isinstance(resource, dict):
        return ""
    rid = resource.get("Id") or resource.get("id") or ""
    rtype = resource.get("Type") or resource.get("type") or ""
    region = resource.get("Region") or resource.get("region") or ""
    details = resource.get("Details") or resource.get("details")
    name = ""
    if isinstance(details, dict):
        ec2 = details.get("AwsEc2Instance") or details.get("awsEc2Instance")
        s3 = details.get("AwsS3Bucket") or details.get("awsS3Bucket")
        iam_user = details.get("AwsIamUser") or details.get("awsIamUser")
        iam_role = details.get("AwsIamRole") or details.get("awsIamRole")
        lam = details.get("AwsLambdaFunction") or details.get("awsLambdaFunction")
        rds = details.get("AwsRdsDbInstance") or details.get("awsRdsDbInstance")
        ecr = details.get("AwsEcrContainerImage") or details.get("awsEcrContainerImage")
        eks = details.get("AwsEksCluster") or details.get("awsEksCluster")
        if isinstance(ec2, dict):
            name = ec2.get("InstanceId") or ec2.get("ImageId") or ""
        elif isinstance(ecr, dict):
            repo = ecr.get("RepositoryName") or ""
            tag = ""
            tags = ecr.get("ImageTags")
            if isinstance(tags, list) and tags:
                tag = str(tags[0])
            digest = ecr.get("ImageDigest") or ecr.get("ImageHash") or ""
            if repo and tag:
                name = f"{repo}:{tag}"
            elif repo and digest:
                name = f"{repo}@{digest[:12]}"
            else:
                name = repo or digest
        elif isinstance(lam, dict):
            name = lam.get("FunctionName") or lam.get("Name") or ""
        elif isinstance(s3, dict):
            name = s3.get("Name") or s3.get("OwnerName") or ""
        elif isinstance(iam_user, dict):
            name = iam_user.get("UserName") or iam_user.get("UserId") or ""
        elif isinstance(iam_role, dict):
            name = iam_role.get("RoleName") or iam_role.get("RoleId") or ""
        elif isinstance(rds, dict):
            name = rds.get("DBInstanceIdentifier") or rds.get("DbInstanceIdentifier") or ""
        elif isinstance(eks, dict):
            name = eks.get("Name") or ""
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
    title = finding.get("Title") or finding.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()
    vulns = finding.get("Vulnerabilities") or finding.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if isinstance(v, dict):
                vid = v.get("Id") or v.get("id")
                if isinstance(vid, str) and vid.strip():
                    return vid.strip()
    return str(finding.get("Id") or finding.get("id") or "SecurityHub finding").strip()


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
    """Build a Faraday vulnerability dict from one ASFF finding."""
    if not isinstance(finding, dict):
        return None

    score = cvss_score(finding)
    sev_blob = finding.get("Severity") or finding.get("severity")
    severity = severity_from_sechub(sev_blob, score)
    status = status_from_sechub(finding)

    resources = finding.get("Resources") or finding.get("resources") or []
    if not isinstance(resources, list):
        resources = []
    primary_resource = next((r for r in resources if isinstance(r, dict)), {})
    rlabel = resource_label(primary_resource)
    vlabel = vuln_label(finding)
    raw_name = f"{vlabel} on {rlabel}" if rlabel else vlabel
    name = f"[CNAPP] {raw_name}"

    desc_parts = []
    description = finding.get("Description") or finding.get("description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    vulns = finding.get("Vulnerabilities") or finding.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vid = v.get("Id") or v.get("id")
            if vid:
                desc_parts.append(f"vulnerability_id: {vid}")
            vendor = v.get("Vendor") or v.get("vendor")
            if isinstance(vendor, dict):
                vname = vendor.get("Name") or vendor.get("name")
                if vname:
                    desc_parts.append(f"vendor: {vname}")
                vsev = vendor.get("VendorSeverity") or vendor.get("vendorSeverity")
                if vsev:
                    desc_parts.append(f"vendor_severity: {vsev}")
            pkgs = v.get("VulnerablePackages") or v.get("vulnerablePackages")
            if isinstance(pkgs, list) and pkgs:
                pkg_lines = []
                for pkg in pkgs:
                    if not isinstance(pkg, dict):
                        continue
                    pname = pkg.get("Name") or pkg.get("name") or ""
                    pver = pkg.get("Version") or pkg.get("version") or ""
                    parch = pkg.get("Architecture") or pkg.get("architecture") or ""
                    fixed = pkg.get("FixedInVersion") or pkg.get("fixedInVersion") or ""
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
            fix = v.get("FixAvailable") or v.get("fixAvailable")
            if fix:
                desc_parts.append(f"fix_available: {fix}")
            epss = v.get("EpssScore") or v.get("epssScore")
            if epss is not None:
                desc_parts.append(f"epss_score: {epss}")
            exploit = v.get("ExploitAvailable") or v.get("exploitAvailable")
            if exploit:
                desc_parts.append(f"exploit_available: {exploit}")

    comp = finding.get("Compliance") or finding.get("compliance")
    if isinstance(comp, dict):
        cstatus = comp.get("Status") or comp.get("status")
        if cstatus:
            desc_parts.append(f"compliance_status: {cstatus}")
        reqs = comp.get("RelatedRequirements") or comp.get("relatedRequirements")
        if isinstance(reqs, list) and reqs:
            desc_parts.append(f"related_requirements: {', '.join(str(r) for r in reqs)}")
        sec_ctrl = comp.get("SecurityControlId") or comp.get("securityControlId")
        if sec_ctrl:
            desc_parts.append(f"security_control_id: {sec_ctrl}")

    if rlabel:
        desc_parts.append(f"resource: {rlabel}")
    if isinstance(primary_resource, dict):
        for label, key, alt in (
            ("resource_id", "Id", "id"),
            ("resource_type", "Type", "type"),
            ("partition", "Partition", "partition"),
            ("region", "Region", "region"),
        ):
            v = primary_resource.get(key) or primary_resource.get(alt)
            if v:
                desc_parts.append(f"{label}: {v}")

    acct = finding.get("AwsAccountId") or finding.get("awsAccountId")
    if acct:
        desc_parts.append(f"aws_account_id: {acct}")

    region = finding.get("Region") or finding.get("region")
    if region:
        desc_parts.append(f"finding_region: {region}")

    pname = finding.get("ProductName") or finding.get("productName")
    if pname:
        desc_parts.append(f"product: {pname}")
    company = finding.get("CompanyName") or finding.get("companyName")
    if company:
        desc_parts.append(f"company: {company}")
    types = finding.get("Types") or finding.get("types")
    if isinstance(types, list) and types:
        desc_parts.append(f"types: {', '.join(str(t) for t in types)}")

    workflow = finding.get("Workflow") or finding.get("workflow")
    if isinstance(workflow, dict):
        ws = workflow.get("Status") or workflow.get("status")
        if ws:
            desc_parts.append(f"workflow_status: {ws}")
    record_state = finding.get("RecordState") or finding.get("recordState")
    if record_state:
        desc_parts.append(f"record_state: {record_state}")

    if isinstance(sev_blob, dict):
        for label, key, alt in (
            ("severity_label", "Label", "label"),
            ("severity_normalized", "Normalized", "normalized"),
            ("severity_original", "Original", "original"),
            ("severity_product", "Product", "product"),
        ):
            v = sev_blob.get(key)
            if v is None:
                v = sev_blob.get(alt)
            if v is not None and not isinstance(v, (dict, list)):
                desc_parts.append(f"{label}: {v}")

    for label, key in (
        ("first_observed", "FirstObservedAt"),
        ("last_observed", "LastObservedAt"),
        ("created", "CreatedAt"),
        ("updated", "UpdatedAt"),
    ):
        v = finding.get(key)
        if v:
            desc_parts.append(f"{label}: {_serialise(v)}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(finding)
    if vector:
        desc_parts.append(f"vector: {vector}")

    cves = collect_cves(finding)
    refs = collect_refs(finding)

    resolution = ""
    rem = finding.get("Remediation") or finding.get("remediation")
    if isinstance(rem, dict):
        rec = rem.get("Recommendation") or rem.get("recommendation")
        if isinstance(rec, dict):
            text = rec.get("Text") or rec.get("text")
            if isinstance(text, str) and text.strip():
                resolution = text.strip()
        elif isinstance(rec, str) and rec.strip():
            resolution = rec.strip()
    if not resolution and isinstance(vulns, list):
        fixes = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            pkgs = v.get("VulnerablePackages") or v.get("vulnerablePackages")
            if not isinstance(pkgs, list):
                continue
            for pkg in pkgs:
                if not isinstance(pkg, dict):
                    continue
                pname = pkg.get("Name") or pkg.get("name")
                fixed = pkg.get("FixedInVersion") or pkg.get("fixedInVersion")
                if pname and fixed:
                    fixes.append(f"Upgrade {pname} to {fixed}.")
        if fixes:
            resolution = " ".join(fixes)

    external_id = str(finding.get("Id") or finding.get("id") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"SecurityHub finding {external_id}",
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
        "tags": ["aws_security_hub", "cnapp", "cloud-native-posture"],
    }


def host_bucket_key(finding):
    """Pick a stable bucket key for a finding's primary resource."""
    if not isinstance(finding, dict):
        return "__unknown__"
    resources = finding.get("Resources") or finding.get("resources") or []
    if isinstance(resources, list):
        for r in resources:
            if not isinstance(r, dict):
                continue
            rid = r.get("Id") or r.get("id")
            if isinstance(rid, str) and rid.strip():
                return rid.strip()
    return "__unknown__"


def _resource_ip(resource):
    """Best-effort IP harvest from an ASFF EC2 resource details payload."""
    if not isinstance(resource, dict):
        return ""
    details = resource.get("Details") or resource.get("details")
    if not isinstance(details, dict):
        return ""
    ec2 = details.get("AwsEc2Instance") or details.get("awsEc2Instance")
    if isinstance(ec2, dict):
        for key in ("IpV4Addresses", "ipV4Addresses", "ipv4Addresses"):
            val = ec2.get(key)
            if isinstance(val, list) and val:
                first = val[0]
                if isinstance(first, str) and first.strip():
                    return first.strip()
        for key in ("IpV4Address", "ipv4Address", "PrivateIpAddress", "PublicIpAddress"):
            v = ec2.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def build_host(bucket_key, sample_resource, vulns):
    """Build a Faraday host record for the supplied resource bucket."""
    rtype = ""
    region = ""
    details_blob = {}
    if isinstance(sample_resource, dict):
        rtype = sample_resource.get("Type") or sample_resource.get("type") or ""
        region = sample_resource.get("Region") or sample_resource.get("region") or ""
        details_blob = sample_resource.get("Details") or sample_resource.get("details") or {}
        if not isinstance(details_blob, dict):
            details_blob = {}

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
        ec2 = details_blob.get("AwsEc2Instance") or details_blob.get("awsEc2Instance")
        s3 = details_blob.get("AwsS3Bucket") or details_blob.get("awsS3Bucket")
        lam = details_blob.get("AwsLambdaFunction") or details_blob.get("awsLambdaFunction")
        iam_user = details_blob.get("AwsIamUser") or details_blob.get("awsIamUser")
        iam_role = details_blob.get("AwsIamRole") or details_blob.get("awsIamRole")
        rds = details_blob.get("AwsRdsDbInstance") or details_blob.get("awsRdsDbInstance")
        ecr = details_blob.get("AwsEcrContainerImage") or details_blob.get("awsEcrContainerImage")
        eks = details_blob.get("AwsEksCluster") or details_blob.get("awsEksCluster")
        if isinstance(ec2, dict):
            for label_k, key in (
                ("instance_id", "InstanceId"),
                ("image_id", "ImageId"),
                ("type", "Type"),
                ("vpc_id", "VpcId"),
                ("subnet_id", "SubnetId"),
                ("key_name", "KeyName"),
            ):
                v = ec2.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
        if isinstance(s3, dict):
            for label_k, key in (
                ("bucket_name", "Name"),
                ("owner", "OwnerName"),
                ("created", "CreatedAt"),
            ):
                v = s3.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
        if isinstance(lam, dict):
            for label_k, key in (
                ("function_name", "FunctionName"),
                ("runtime", "Runtime"),
                ("version", "Version"),
            ):
                v = lam.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
        if isinstance(iam_user, dict):
            for label_k, key in (
                ("user_name", "UserName"),
                ("user_id", "UserId"),
            ):
                v = iam_user.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
        if isinstance(iam_role, dict):
            for label_k, key in (
                ("role_name", "RoleName"),
                ("role_id", "RoleId"),
            ):
                v = iam_role.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
        if isinstance(rds, dict):
            for label_k, key in (
                ("db_instance_id", "DBInstanceIdentifier"),
                ("engine", "Engine"),
                ("engine_version", "EngineVersion"),
            ):
                v = rds.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
        if isinstance(ecr, dict):
            for label_k, key in (
                ("repository", "RepositoryName"),
                ("image_hash", "ImageHash"),
                ("image_digest", "ImageDigest"),
            ):
                v = ecr.get(key)
                if v:
                    desc_parts.append(f"{label_k}={v}")
            tags = ecr.get("ImageTags")
            if isinstance(tags, list) and tags:
                desc_parts.append(f"image_tags={','.join(str(t) for t in tags)}")
        if isinstance(eks, dict):
            for label_k, key in (
                ("cluster_name", "Name"),
                ("version", "Version"),
            ):
                v = eks.get(key)
                if v:
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


def fetch_findings(client, filters, max_results, page_size=PAGE_SIZE):
    """Paginate ``securityhub.get_findings`` with the supplied filter."""
    findings = []
    paginator = client.get_paginator("get_findings")
    kwargs = {"MaxResults": page_size}
    if filters:
        kwargs["Filters"] = filters
    for page in paginator.paginate(**kwargs):
        page_findings = page.get("Findings") if isinstance(page, dict) else None
        if isinstance(page_findings, list):
            for f in page_findings:
                if isinstance(f, dict):
                    findings.append(f)
                    if len(findings) >= max_results:
                        break
        if len(findings) >= max_results:
            log(f"hit MAX_RESULTS={max_results}; stopping pagination")
            break
    return findings


def main():
    started = time.time()
    region = env("EXECUTOR_CONFIG_AWS_REGION") or env("AWS_REGION") or env("AWS_DEFAULT_REGION")
    if not region:
        log("AWS_REGION is required (Security Hub endpoints are regional)")
        sys.exit(1)

    filters = validate_filters(env("EXECUTOR_CONFIG_SECHUB_FILTERS_JSON"))
    max_results = validate_max_results(env("EXECUTOR_CONFIG_SECHUB_MAX_RESULTS"))

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
        "securityhub",
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )

    findings = fetch_findings(client, filters, max_results)
    log(
        f"Processing {len(findings)} Security Hub findings "
        f"(region={region}, filters={'present' if filters else 'none'}, max_results={max_results})"
    )

    buckets = {}
    sample_resources = {}
    for finding in findings:
        key = host_bucket_key(finding)
        buckets.setdefault(key, []).append(finding)
        if key not in sample_resources:
            resources = finding.get("Resources") or finding.get("resources") or []
            if isinstance(resources, list):
                for r in resources:
                    if isinstance(r, dict) and str(r.get("Id") or r.get("id") or "").strip() == key:
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

    params_bits = [f"region={region}", f"max_results={max_results}"]
    if filters:
        params_bits.append("filters=present")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "aws_security_hub",
            "command": "aws_security_hub",
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
