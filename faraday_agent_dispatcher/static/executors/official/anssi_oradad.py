#!/usr/bin/env python
"""ANSSI ORADAD Active Directory assessment importer.

Wraps the ANSSI ORADAD Windows binary against a target Active Directory
domain, then parses the JSON output produced by the run and emits
Faraday bulk-create JSON to stdout.

Command form::

    oradad -c <ORADAD_CONFIG_PATH> [-s <ORADAD_DOMAIN>] -o <output_dir>

ORADAD reads its target forest, output directory and the list of
templates to collect from an XML config file. ``ORADAD_DOMAIN`` is
forwarded as ``-s`` so a specific LDAP server / domain FQDN in the
target forest can be hit, and ``-o`` overrides the output root to a
per-run temporary directory so each invocation is self-contained.

Auth: domain credentials in the container (Windows integrated auth /
machine account ticket); no env vars are read by this executor.

Output mapping: every ORADAD template that produced one or more LDAP
entries becomes one Faraday vulnerability. All findings are attached to
a single host representing the target AD domain. Severity is bucketed
from the template ``Type`` when ORADAD flags it as ``Control`` /
``Warning`` / ``Information``, and otherwise from keyword heuristics on
the template name (Krbtgt / DCSync / AdminSDHolder /
UnconstrainedDelegation → critical, Trust / Kerberos / AdminCount /
WeakEncryption → high, Stale / Inactive / GPO → medium, Schema → low,
everything else → info).
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ORADAD_BINARY = os.environ.get("ORADAD_BIN", "oradad")

# ORADAD template ``Type`` strings, lowercased. The tool annotates every
# template definition in the XML config with one of these labels.
TYPE_TO_SEVERITY = {
    "control": "high",
    "warning": "medium",
    "information": "info",
    "info": "info",
}

# Keyword buckets applied against the template name when ``Type`` is
# missing or unknown. Ordered: the first bucket whose keyword appears
# in the template name wins.
SEVERITY_KEYWORDS = (
    (
        "critical",
        (
            "krbtgt",
            "dcsync",
            "adminsdholder",
            "unconstraineddelegation",
            "unconstrained_delegation",
            "dsrm",
            "sidhistory",
            "sid_history",
            "golden",
            "silver",
            "skeleton",
        ),
    ),
    (
        "high",
        (
            "trust",
            "kerberos",
            "admincount",
            "admin_count",
            "weakencryption",
            "weak_encryption",
            "rc4",
            "des",
            "smbv1",
            "smb1",
            "lmnt",
            "ntlm",
            "anonymous",
            "password",
        ),
    ),
    (
        "medium",
        (
            "stale",
            "inactive",
            "gpo",
            "share",
            "dns",
            "delegation",
            "spn",
            "kerberoast",
        ),
    ),
    (
        "low",
        (
            "schema",
            "rodc",
            "fsmo",
        ),
    ),
)


def log(msg):
    print(f"{datetime.utcnow()} - ORADAD: {msg}", file=sys.stderr, flush=True)


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


def severity_from_type(type_value):
    if not type_value:
        return None
    return TYPE_TO_SEVERITY.get(str(type_value).strip().lower())


def severity_from_name(name):
    lowered = (name or "").lower()
    for severity, keywords in SEVERITY_KEYWORDS:
        for keyword in keywords:
            if keyword in lowered:
                return severity
    return "info"


def severity_for(template_name, type_value):
    return severity_from_type(type_value) or severity_from_name(template_name)


def build_command(config_path, server, output_dir):
    cmd = [ORADAD_BINARY, "-c", config_path, "-o", str(output_dir)]
    if server:
        cmd += ["-s", server]
    return cmd


def iter_template_results(payload):
    """Yield ``(template_name, type_value, entries)`` tuples from one parsed JSON file.

    ORADAD's JSON output shape varies across templates and ORADAD versions:
    some files are a single template dict, some wrap many templates under
    ``Output``/``Templates``/``Results``. Be tolerant of all the shapes we
    have seen in the wild.
    """
    if isinstance(payload, list):
        for item in payload:
            yield from iter_template_results(item)
        return
    if not isinstance(payload, dict):
        return

    for container_key in ("Output", "Templates", "Results", "Controls"):
        container = payload.get(container_key)
        if isinstance(container, list):
            for item in container:
                yield from iter_template_results(item)
            return
        if isinstance(container, dict):
            for item in container.values():
                yield from iter_template_results(item)
            return

    name = payload.get("Template") or payload.get("Name") or payload.get("Id")
    type_value = payload.get("Type") or payload.get("Category")
    entries = payload.get("Entries") or payload.get("Result") or payload.get("Items") or payload.get("Findings") or []
    if not isinstance(entries, list):
        entries = []

    if name:
        yield name, type_value, entries


def entry_label(entry):
    if isinstance(entry, dict):
        for key in (
            "dn",
            "DistinguishedName",
            "distinguishedName",
            "name",
            "Name",
            "sAMAccountName",
            "objectName",
            "cn",
        ):
            value = entry.get(key)
            if value:
                return str(value)
        return json.dumps(entry, default=str)[:200]
    return str(entry)[:200]


def build_vulnerability(template_name, type_value, entries):
    severity = severity_for(template_name, type_value)
    desc_parts = [f"ORADAD template: {template_name}"]
    if type_value:
        desc_parts.append(f"Type: {type_value}")
    desc_parts.append(f"Matching entries: {len(entries)}")
    if entries:
        sample = [entry_label(e) for e in entries[:25]]
        desc_parts.append("Affected: " + "; ".join(sample))

    return {
        "name": f"ORADAD {template_name}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(template_name),
        "type": "Vulnerability",
        "status": "open",
        "resolution": "",
        "data": "",
        "refs": [
            {
                "name": "https://github.com/ANSSI-FR/ORADAD",
                "type": "other",
            }
        ],
        "cve": [],
        "tags": [t for t in ["oradad", str(type_value).lower() if type_value else ""] if t],
    }


def find_json_files(output_dir):
    return sorted(Path(output_dir).rglob("*.json"), key=lambda p: p.stat().st_mtime)


def collect_vulns(output_dir):
    vulns = []
    seen = set()
    for path in find_json_files(output_dir):
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError) as exc:
            log(f"Skipping unreadable JSON {path}: {exc}")
            continue
        for name, type_value, entries in iter_template_results(payload):
            if not entries:
                continue
            key = (str(name), str(type_value or ""))
            if key in seen:
                continue
            seen.add(key)
            vulns.append(build_vulnerability(name, type_value, entries))
    return vulns


def main():
    started = time.time()
    domain = env("EXECUTOR_CONFIG_ORADAD_DOMAIN", required=True)
    config_path = env("EXECUTOR_CONFIG_ORADAD_CONFIG_PATH", required=True)
    if not Path(config_path).is_file():
        log(f"ORADAD_CONFIG_PATH does not point to a file: {config_path}")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="oradad-") as output_dir:
        cmd = build_command(config_path, domain, output_dir)
        log(f"Running ORADAD against {domain} (output={output_dir})")
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            log(f"ORADAD exited with {proc.returncode}: {proc.stderr[:500]}")

        vulns = collect_vulns(output_dir)

    log(f"Parsed {len(vulns)} ORADAD finding(s) for domain={domain}")

    host = {
        "ip": domain,
        "hostnames": [domain],
        "description": f"ANSSI ORADAD assessment (domain={domain})",
        "os": "Windows",
        "mac": "",
        "vulnerabilities": vulns,
    }

    output = {
        "hosts": [host],
        "command": {
            "tool": "anssi_oradad",
            "command": " ".join(cmd),
            "params": f"domain={domain} config={config_path}",
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
