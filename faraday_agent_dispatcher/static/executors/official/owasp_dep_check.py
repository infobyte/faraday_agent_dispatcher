#!/usr/bin/env python
"""OWASP Dependency-Check CLI wrapper.

Runs the OWASP Dependency-Check CLI against a checked-out source tree
or a directly-supplied target path and ingests its JSON report into
Faraday. Each scan becomes one Faraday host (synthetic ``0.0.0.0``
ip because SCA findings live in dependency manifests, not on IPs);
per-dependency vulnerabilities attach as Faraday vulnerabilities — one
per ``(dependency, vulnerability.name)`` pair with engine prefix
``[SCA]``.

CLI invocation::

    dependency-check.sh --scan <target> --format JSON --out <out_dir> \
        [--suppression <DEPCHECK_SUPPRESSION_FILE>]

Dependency-Check writes ``dependency-check-report.json`` into
``<out_dir>``; that file is then parsed for ``dependencies[]`` and
each dependency's ``vulnerabilities[]``.

Args:
  DEPCHECK_TARGET           — filesystem path to scan. When
                              DEPCHECK_GIT_URL is also set, this is
                              treated as a subpath inside the clone
                              (so you can scan a single module of a
                              large repo).
  DEPCHECK_SUPPRESSION_FILE — optional path to an OWASP
                              ``suppressions.xml`` file. Forwarded to
                              ``--suppression`` verbatim.
  DEPCHECK_GIT_URL          — optional. When set, the repo is
                              shallow-cloned to a temp dir and
                              scanned; private repos authenticate
                              with GIT_USERNAME / GIT_TOKEN.
  DEPCHECK_GIT_REF          — optional branch / tag passed to
                              ``git clone --branch``.

Env vars (process-level):
  GIT_USERNAME / GIT_TOKEN  — credentials for private-repo clones.

Severity is taken from each Dependency-Check vulnerability's
``severity`` enum (CRITICAL / HIGH / MEDIUM / LOW + UNKNOWN /
MODERATE / NEGLIGIBLE / INFORMATIONAL etc.) with CVSS v3 / v2 base
score bucketing as a fallback (≤0 / >10 → info, <4 low, <7 medium,
<9 high, ≥9 critical). Status is always ``open`` — Dependency-Check
doesn't track triage state (suppressions are filtered out by the
scanner itself before they reach the report). Refs include CWE-*
ids, each vulnerability's ``references[].url`` and the dependency's
package URL (``pkg:...``). CVEs are the ``name`` field when it
starts with ``CVE-``.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from faraday_agent_dispatcher.utils.source_target import resolve_source_path

TIMEOUT_RUN = 3600
DEFAULT_REPORT_NAME = "dependency-check-report.json"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# OWASP Dependency-Check emits severity as an upper-case enum from the
# NVD ladder (CRITICAL / HIGH / MEDIUM / LOW). Some advisory sources
# surfaced through dep-check (RetireJS, OSS Index, Sonatype) use
# adjacent vocabularies — keep the table permissive so we don't drop
# data on unfamiliar vendor strings.
DC_STRING_SEVERITY = {
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
    "negligible": "info",
    "trivial": "info",
    "unspecified": "info",
    "unknown": "info",
}


def log(msg):
    print(f"{datetime.utcnow()} - OwaspDepCheck: {msg}", file=sys.stderr, flush=True)


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


def severity_from_dc(value, cvss=None):
    """Map a Dependency-Check severity to a Faraday bucket.

    Accepts dep-check's string enum and falls back to CVSS bucketing
    on the provided ``cvss`` argument when the primary value is
    missing or unrecognised. Numeric inputs are interpreted as CVSS
    base scores so vendor-shaped reports that surface a bare score
    still bucket correctly.
    """
    if value is not None and not isinstance(value, bool):
        if isinstance(value, (int, float)):
            return severity_from_cvss(value)
        text = str(value).strip().lower()
        if text in DC_STRING_SEVERITY:
            return DC_STRING_SEVERITY[text]
        try:
            return severity_from_cvss(float(text))
        except ValueError:
            pass
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def cvss_score(vuln):
    """Pick the highest CVSS base score across v3 / v2 nestings.

    dep-check shapes CVSS sub-objects as ``cvssv3.baseScore`` /
    ``cvssv2.score`` (legacy reports), but some advisory sources also
    surface a bare ``baseScore`` at the top level — handle each.
    """
    if not isinstance(vuln, dict):
        return None
    candidates = []
    for key in ("cvssv3", "cvssv2", "cvssV3", "cvssV2", "cvss3", "cvss2"):
        sub = vuln.get(key)
        if isinstance(sub, dict):
            for sk in ("baseScore", "base_score", "score"):
                v = sub.get(sk)
                if v is not None:
                    candidates.append(v)
    for sk in ("baseScore", "base_score", "score"):
        v = vuln.get(sk)
        if v is not None:
            candidates.append(v)
    best = None
    for raw in candidates:
        try:
            n = float(raw)
        except (TypeError, ValueError):
            continue
        if best is None or n > best:
            best = n
    return best


def cvss_vector(vuln):
    if not isinstance(vuln, dict):
        return ""
    for key in ("cvssv3", "cvssv2", "cvssV3", "cvssV2", "cvss3", "cvss2"):
        sub = vuln.get(key)
        if isinstance(sub, dict):
            for vk in ("vectorString", "vector_string", "vector"):
                value = sub.get(vk)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    for vk in ("vectorString", "vector_string", "vector"):
        value = vuln.get(vk)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def normalise_cwe(value):
    """Return ``CWE-<digits>`` or ``''`` for malformed inputs.

    dep-check surfaces CWEs as either bare ids (``"CWE-79"``) or as
    full CWE strings with names (``"CWE-79 Improper Neutralization"``).
    Both shapes are collapsed to the bare id.
    """
    if not value:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    head = text.split()[0]
    upper = head.upper()
    if upper.startswith("CWE-"):
        digits = upper[4:].split(":")[0]
        if digits.isdigit():
            return f"CWE-{digits}"
        return ""
    if upper.isdigit():
        return f"CWE-{upper}"
    return ""


def collect_cwes(vuln):
    """Extract CWE-* refs from a dep-check vulnerability.

    dep-check shapes CWEs as ``cwes[]`` (list of strings) but some
    advisory sources surface a single ``cwe`` key or list-of-dict
    entries — handle each.
    """
    seen = set()
    out = []

    def add(raw):
        norm = normalise_cwe(raw)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)

    if not isinstance(vuln, dict):
        return out
    for key in ("cwes", "cwe", "CWE", "CWEs"):
        value = vuln.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            add(value)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                if isinstance(item, dict):
                    add(item.get("id") or item.get("name") or item.get("value"))
                else:
                    add(item)
        elif isinstance(value, dict):
            add(value.get("id") or value.get("name") or value.get("value"))
    return out


def collect_cves(vuln):
    """Collect CVE-* identifiers from a dep-check vulnerability.

    dep-check tags each vulnerability with the advisory id in
    ``name``; when the id is CVE-shaped we surface it as a CVE. Some
    advisory sources also expose ``cve``, ``cves`` or ``aliases`` —
    walk each so we don't drop CVE attribution from non-NVD sources.
    """
    seen = set()
    out = []

    def add(value):
        if value is None:
            return
        if isinstance(value, dict):
            for key in ("id", "name", "cve", "cveId", "cve_id"):
                v = value.get(key)
                if v:
                    add(v)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                add(item)
            return
        text = str(value).strip().upper()
        if not text.startswith("CVE-"):
            return
        if text in seen:
            return
        seen.add(text)
        out.append(text)

    if not isinstance(vuln, dict):
        return out
    add(vuln.get("name"))
    add(vuln.get("cve"))
    add(vuln.get("cveId"))
    add(vuln.get("cve_id"))
    add(vuln.get("cves"))
    add(vuln.get("aliases"))
    return out


def collect_refs(vuln, dep):
    """Build the dedup'd ref list for a vulnerability.

    Includes CWE-* refs, each ``references[].url`` (string + dict
    shape), and a ``DepCheck-Package: pkg:...`` pivot label that
    surfaces the dep-check ``packages[].id`` purl when present so
    Faraday users can pivot back to the dependency manifest.
    """
    seen = set()
    refs = []

    def add(text, ref_type="other"):
        if text is None:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": ref_type})

    for cwe in collect_cwes(vuln):
        add(cwe)

    if isinstance(vuln, dict):
        references = vuln.get("references")
        if isinstance(references, list):
            for ref in references:
                if isinstance(ref, str):
                    add(ref)
                elif isinstance(ref, dict):
                    add(ref.get("url") or ref.get("href") or ref.get("name"))
        source = vuln.get("source")
        if isinstance(source, str) and source.strip():
            name = vuln.get("name")
            if isinstance(name, str) and name.strip() and not name.strip().upper().startswith("CVE-"):
                add(f"{source.strip()}: {name.strip()}")

    if isinstance(dep, dict):
        packages = dep.get("packages")
        if isinstance(packages, list):
            for pkg in packages:
                if not isinstance(pkg, dict):
                    continue
                purl = pkg.get("id") or pkg.get("url")
                if isinstance(purl, str) and purl.strip():
                    add(f"DepCheck-Package: {purl.strip()}")

    return refs


def dependency_label(dep):
    """Pick the most informative coordinate label for a dependency.

    Prefers a ``pkg:`` purl (carries group / artifact / version),
    falls back to ``fileName`` and then to the file's basename.
    Returns ``''`` for non-dict inputs.
    """
    if not isinstance(dep, dict):
        return ""
    packages = dep.get("packages")
    if isinstance(packages, list):
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            purl = pkg.get("id") or pkg.get("url")
            if isinstance(purl, str) and purl.strip():
                return purl.strip()
    file_name = dep.get("fileName") or dep.get("file_name")
    if isinstance(file_name, str) and file_name.strip():
        return file_name.strip()
    file_path = dep.get("filePath") or dep.get("file_path")
    if isinstance(file_path, str) and file_path.strip():
        return os.path.basename(file_path.strip()) or file_path.strip()
    return ""


def dependency_meta(dep):
    """Surface dependency coordinates / hashes / license for the desc."""
    if not isinstance(dep, dict):
        return []
    parts = []
    label = dependency_label(dep)
    if label:
        parts.append(f"dependency: {label}")
    file_path = dep.get("filePath") or dep.get("file_path")
    if isinstance(file_path, str) and file_path.strip():
        parts.append(f"filePath: {file_path.strip()}")
    file_name = dep.get("fileName") or dep.get("file_name")
    if isinstance(file_name, str) and file_name.strip() and file_name.strip() != label:
        parts.append(f"fileName: {file_name.strip()}")
    description = dep.get("description")
    if isinstance(description, str) and description.strip():
        parts.append(f"componentDescription: {description.strip()}")
    license_ = dep.get("license")
    if isinstance(license_, str) and license_.strip():
        parts.append(f"license: {license_.strip()}")
    for hash_key in ("sha256", "sha1", "md5"):
        h = dep.get(hash_key)
        if isinstance(h, str) and h.strip():
            parts.append(f"{hash_key}: {h.strip()}")
    return parts


def build_vulnerability(dep, vuln):
    """Build a Faraday vulnerability dict for one dep-check finding."""
    if not isinstance(vuln, dict):
        return None
    name_raw = vuln.get("name")
    if not isinstance(name_raw, str) or not name_raw.strip():
        return None
    cve_id = name_raw.strip()
    label = dependency_label(dep)

    cvss = cvss_score(vuln)
    severity = severity_from_dc(vuln.get("severity"), cvss=cvss)

    title_label = label or "(unknown dependency)"
    raw_name = f"{cve_id} in {title_label}"
    name = f"[SCA] {raw_name}"

    desc_parts = []
    desc_parts.extend(dependency_meta(dep))
    source = vuln.get("source")
    if isinstance(source, str) and source.strip():
        desc_parts.append(f"source: {source.strip()}")
    desc_parts.append(f"vulnerability: {cve_id}")
    severity_raw = vuln.get("severity")
    if severity_raw not in (None, ""):
        desc_parts.append(f"severity (raw): {severity_raw}")
    if cvss is not None:
        desc_parts.append(f"cvssScore: {cvss}")
    vector = cvss_vector(vuln)
    if vector:
        desc_parts.append(f"cvssVector: {vector}")
    description = vuln.get("description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(f"description: {description.strip()[:2000]}")
    notes = vuln.get("notes")
    if isinstance(notes, str) and notes.strip():
        desc_parts.append(f"notes: {notes.strip()[:1000]}")

    refs = collect_refs(vuln, dep)
    cves = collect_cves(vuln)

    cvss3 = {}
    cvss3_sub = vuln.get("cvssv3") or vuln.get("cvssV3") or vuln.get("cvss3")
    if isinstance(cvss3_sub, dict):
        vector_string = cvss3_sub.get("vectorString") or cvss3_sub.get("vector_string") or cvss3_sub.get("vector")
        if isinstance(vector_string, str) and vector_string.strip():
            cvss3["vector_string"] = vector_string.strip()
        base_score = cvss3_sub.get("baseScore") or cvss3_sub.get("base_score") or cvss3_sub.get("score")
        if base_score is not None:
            try:
                cvss3["base_score"] = float(base_score)
            except (TypeError, ValueError):
                pass

    external_id = f"DEPCHECK:{cve_id}:{label}" if label else f"DEPCHECK:{cve_id}"

    return {
        "name": str(name).strip()[:200] or f"DepCheck {cve_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": "open",
        "resolution": "",
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["owasp_dep_check", "dependency_check", "sca"],
    }


def extract_dependencies(report):
    if not isinstance(report, dict):
        return []
    deps = report.get("dependencies")
    if isinstance(deps, list):
        return deps
    return []


def project_name(report, target):
    if isinstance(report, dict):
        info = report.get("projectInfo")
        if isinstance(info, dict):
            name = info.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
    if target:
        return os.path.basename(os.path.normpath(target)) or target
    return "owasp_dep_check"


def build_host(report, target, vulnerabilities, dep_count):
    name = project_name(report, target)
    desc_parts = [f"project={name}"]
    if target:
        desc_parts.append(f"target={target}")
    desc_parts.append(f"dependencies={dep_count}")
    report_date = ""
    if isinstance(report, dict):
        info = report.get("projectInfo")
        if isinstance(info, dict):
            rd = info.get("reportDate")
            if isinstance(rd, str) and rd.strip():
                report_date = rd.strip()
                desc_parts.append(f"reportDate={report_date}")
        scan_info = report.get("scanInfo")
        if isinstance(scan_info, dict):
            engine = scan_info.get("engineVersion") or scan_info.get("engine_version")
            if isinstance(engine, str) and engine.strip():
                desc_parts.append(f"engineVersion={engine.strip()}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [name] if name else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulnerabilities,
    }


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"DEPCHECK_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def parse_report(report, target, min_severity="info"):
    """Walk the dep-check JSON report and emit one Faraday host.

    Returns ``(host, vuln_count)``. Vulnerabilities are filtered
    client-side by ``min_severity`` floor.
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    dependencies = extract_dependencies(report)
    vulns = []
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        dep_vulns = dep.get("vulnerabilities")
        if not isinstance(dep_vulns, list):
            continue
        for dv in dep_vulns:
            built = build_vulnerability(dep, dv)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            vulns.append(built)
    host = build_host(report, target, vulns, len(dependencies))
    return host, len(vulns)


def build_command(target, suppression_file, out_dir, binary):
    cmd = [binary, "--scan", target, "--format", "JSON", "--out", out_dir]
    if suppression_file:
        cmd += ["--suppression", suppression_file]
    return cmd


def find_report(out_dir):
    """Locate the JSON report dep-check wrote to ``out_dir``.

    Default name is ``dependency-check-report.json`` but some
    dep-check versions also accept ``--out`` pointing at a file —
    handle both.
    """
    default = os.path.join(out_dir, DEFAULT_REPORT_NAME)
    if os.path.isfile(default):
        return default
    if os.path.isfile(out_dir):
        return out_dir
    if os.path.isdir(out_dir):
        for entry in os.listdir(out_dir):
            if entry.lower().endswith(".json"):
                return os.path.join(out_dir, entry)
    return None


def main():
    started = time.time()
    target = resolve_source_path("DEPCHECK")
    suppression_file = env("EXECUTOR_CONFIG_DEPCHECK_SUPPRESSION_FILE")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_DEPCHECK_MIN_SEVERITY"))
    binary = env("DEPCHECK_BINARY", default="dependency-check.sh")

    out_dir = tempfile.mkdtemp(prefix="oc_depcheck_")
    try:
        cmd = build_command(target, suppression_file, out_dir, binary)
        log(f"running {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=TIMEOUT_RUN,
            )
        except FileNotFoundError:
            log(f"dependency-check binary not found: {binary}")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            log(f"dependency-check timed out after {TIMEOUT_RUN}s")
            sys.exit(1)
        if result.stderr:
            print(result.stderr, file=sys.stderr)

        report_path = find_report(out_dir)
        if not report_path:
            log("dependency-check produced no JSON report")
            sys.exit(result.returncode or 1)
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                report = json.load(fh)
        except (OSError, ValueError) as exc:
            log(f"failed to read dependency-check report at {report_path}: {exc}")
            sys.exit(1)

        host, vuln_count = parse_report(report, target, min_severity)
        log(
            f"Parsed {len(extract_dependencies(report))} dependencies "
            f"({vuln_count} vulnerabilities emitted, min_severity={min_severity})"
        )

        output = {
            "hosts": [host],
            "command": {
                "tool": "owasp_dep_check",
                "command": "owasp_dep_check",
                "params": f"target={target},min_severity={min_severity}",
                "user": os.environ.get("USER", ""),
                "hostname": socket.gethostname(),
                "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
                "duration": int((time.time() - started) * 1000),
                "import_source": "report",
            },
        }
        print(json.dumps(output))
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
