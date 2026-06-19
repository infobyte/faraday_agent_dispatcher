#!/usr/bin/env python
"""npm audit executor — runs ``npm audit --json`` against a node project.

Either point NPM_AUDIT_TARGET at a directory that already contains a
package-lock.json / npm-shrinkwrap.json, or set NPM_AUDIT_GIT_URL to
shallow-clone a repo first (private repos authenticate with
GIT_USERNAME / GIT_TOKEN). One Faraday host is emitted per scan
(synthetic 0.0.0.0; hostname = package name from package.json or the
target's basename); one Faraday vulnerability per audit advisory, with
the affected package, severity bucket, CVE / CWE references, fixable-in
version and a remediation summary.

npm audit output shape:
  npm >= 7:  {"vulnerabilities": {"<pkg>": {severity, range, via: [...]
             , effects, fixAvailable, ...}}, "metadata": {...}}
  npm <= 6:  {"advisories": {"<id>": {title, severity, cwe, cves, ...}},
             "metadata": {...}}
We parse both.
"""

import json
import os
import re
import subprocess
import sys

from faraday_agent_dispatcher.utils.source_target import resolve_source_path

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

NPM_SEVERITY_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
}


def log(msg):
    print(msg, file=sys.stderr)


def normalise_severity(value):
    if value is None:
        return "info"
    return NPM_SEVERITY_TO_FARADAY.get(str(value).strip().lower(), "info")


def validate_min_severity(value):
    if not value:
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"NPM_AUDIT_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def severity_at_or_above(bucket, floor):
    return SEVERITY_ORDER.get(bucket, 0) >= SEVERITY_ORDER.get(floor, 0)


def package_name(project_dir):
    pkg_json = os.path.join(project_dir, "package.json")
    if not os.path.isfile(pkg_json):
        return os.path.basename(os.path.normpath(project_dir)) or "npm-project"
    try:
        with open(pkg_json, encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, ValueError):
        return os.path.basename(os.path.normpath(project_dir)) or "npm-project"
    name = data.get("name") or os.path.basename(os.path.normpath(project_dir))
    return str(name) or "npm-project"


def run_npm_audit(project_dir, production_only):
    cmd = ["npm", "audit", "--json"]
    if production_only:
        cmd.append("--omit=dev")
    try:
        proc = subprocess.run(
            cmd, cwd=project_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600
        )
    except FileNotFoundError:
        log("npm binary not found in PATH; install Node/npm in the agent image.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log("npm audit timed out after 10 minutes.")
        sys.exit(1)
    # npm exits with code 1 when vulns are present — that's the expected
    # path for us; stdout still contains the JSON report.
    if not proc.stdout.strip():
        log(f"npm audit produced no JSON. stderr: {proc.stderr.strip()[:400]}")
        sys.exit(proc.returncode or 1)
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        log(f"npm audit returned non-JSON output: {exc}; head: {proc.stdout[:200]!r}")
        sys.exit(1)


def collect_refs(advisory):
    """Pull CVE / CWE / URL refs out of an advisory (handles both formats)."""
    refs = []
    seen = set()

    def add(value):
        if not value:
            return
        text = str(value).strip()
        if not text or text in seen:
            return
        seen.add(text)
        refs.append(text)

    # npm 7+: advisory has cwe (list) and url; CVEs live in via[].source
    for cwe in advisory.get("cwe") or []:
        add(cwe)
    add(advisory.get("url"))
    # npm 6: cves (list of strings), cwe (single string), references (newline-delimited)
    for cve in advisory.get("cves") or []:
        add(cve)
    cwe = advisory.get("cwe")
    if isinstance(cwe, str):
        add(cwe)
    for ref in re.split(r"\s+", advisory.get("references", "") or ""):
        add(ref if ref.startswith(("http://", "https://", "CVE-", "CWE-")) else None)
    # Last-resort CVE harvest from title / overview text
    for blob in (advisory.get("title", ""), advisory.get("overview", "")):
        for m in CVE_RE.findall(blob or ""):
            add(m.upper())
    return refs


def parse_npm7(audit_json):
    """npm >= 7 shape — {"vulnerabilities": {"<pkg>": {...}}}.

    Each entry's ``via`` is a list of either advisory dicts (root cause)
    or pkg-name strings (transitive). We surface one Faraday vuln per
    advisory dict, deduped by source id.
    """
    out = []
    seen_sources = set()
    vulns = audit_json.get("vulnerabilities") or {}
    for pkg_name, entry in vulns.items():
        # Fall-through severity used inside the loop is per-advisory (via_sev);
        # the entry-level severity is only consulted as a fallback there.
        fix = entry.get("fixAvailable")
        if isinstance(fix, dict):
            fixed_in = fix.get("version")
        elif isinstance(fix, bool):
            fixed_in = None
        else:
            fixed_in = fix
        for via in entry.get("via") or []:
            if not isinstance(via, dict):
                continue
            source = via.get("source") or via.get("name") or via.get("title")
            if source in seen_sources:
                continue
            if source is not None:
                seen_sources.add(source)
            via_sev = normalise_severity(via.get("severity") or entry.get("severity"))
            title = via.get("title") or f"{pkg_name}: {entry.get('range') or 'vulnerable version'}"
            refs = collect_refs(via)
            desc_lines = [
                f"Package: {pkg_name}",
                f"Vulnerable range: {entry.get('range') or '(unknown)'}",
            ]
            if via.get("range"):
                desc_lines.append(f"Advisory range: {via['range']}")
            if entry.get("nodes"):
                desc_lines.append(f"Dependency paths: {', '.join(entry['nodes'][:5])}")
            if via.get("overview"):
                desc_lines.append("")
                desc_lines.append(via["overview"].strip())
            out.append(
                {
                    "name": f"[npm-audit] {title}",
                    "desc": "\n".join(desc_lines),
                    "severity": via_sev,
                    "type": "Vulnerability",
                    "refs": [{"name": r, "type": "other"} for r in refs],
                    "data": (f"package={pkg_name}; fixed_in={fixed_in}" if fixed_in else f"package={pkg_name}"),
                    "resolution": (via.get("recommendation") or "").strip(),
                    "external_id": str(source) if source is not None else "",
                    "tool": "npm-audit",
                }
            )
    return out


def parse_npm6(audit_json):
    """npm <= 6 shape — {"advisories": {"<id>": {...}}}."""
    out = []
    advisories = audit_json.get("advisories") or {}
    for advisory_id, advisory in advisories.items():
        severity = normalise_severity(advisory.get("severity"))
        module = advisory.get("module_name") or advisory.get("name") or "unknown"
        refs = collect_refs(advisory)
        desc_lines = [
            f"Package: {module}",
            f"Vulnerable range: {advisory.get('vulnerable_versions') or '(unknown)'}",
            f"Patched in: {advisory.get('patched_versions') or '(no fix)'}",
        ]
        if advisory.get("overview"):
            desc_lines.append("")
            desc_lines.append(advisory["overview"].strip())
        out.append(
            {
                "name": f"[npm-audit] {advisory.get('title') or module}",
                "desc": "\n".join(desc_lines),
                "severity": severity,
                "type": "Vulnerability",
                "refs": [{"name": r, "type": "other"} for r in refs],
                "data": f"package={module}; patched={advisory.get('patched_versions') or '(none)'}",
                "resolution": (advisory.get("recommendation") or "").strip(),
                "external_id": str(advisory_id),
                "tool": "npm-audit",
            }
        )
    return out


def main():
    project_dir = resolve_source_path("NPM_AUDIT")
    if not os.path.isdir(project_dir):
        log(f"npm_audit: target directory does not exist: {project_dir}")
        sys.exit(1)
    production_only = os.environ.get("EXECUTOR_CONFIG_NPM_AUDIT_PRODUCTION_ONLY", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    min_severity = validate_min_severity(os.environ.get("EXECUTOR_CONFIG_NPM_AUDIT_MIN_SEVERITY"))

    audit_json = run_npm_audit(project_dir, production_only)

    vulns_raw = audit_json.get("vulnerabilities")
    if isinstance(vulns_raw, dict) and vulns_raw:
        vulns = parse_npm7(audit_json)
    else:
        vulns = parse_npm6(audit_json)

    # Severity floor (client-side; npm has no server-side severity arg)
    floor = SEVERITY_ORDER.get(min_severity, 0)
    vulns = [v for v in vulns if SEVERITY_ORDER.get(v["severity"], 0) >= floor]

    host = {
        "ip": "0.0.0.0",
        "description": f"npm audit on {project_dir}",
        "hostnames": [package_name(project_dir)],
        "vulnerabilities": vulns,
    }
    print(json.dumps({"hosts": [host]}))


if __name__ == "__main__":
    main()
