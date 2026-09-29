#!/usr/bin/env python
"""ANSSI SILENE Linux hardening assessment importer.

Wraps the ANSSI SILENE CLI against a target Linux host (typically over
SSH), parses the JSON output produced by the run and emits Faraday
bulk-create JSON to stdout.

Command form::

    silene --target <SILENE_TARGET_HOST>
           [--profile <SILENE_PROFILE>]
           [--ssh-user <SILENE_SSH_USER>]
           [--ssh-key <SILENE_SSH_KEY>]
           --output <output_dir>
           --format json

SILENE evaluates a Linux host against the ANSSI BP-028 hardening
guidelines. Each guideline is a Recommendation (R1..R69) tagged with
the lowest profile at which it applies (minimal / intermediate /
enhanced / high). The tool reports, for every recommendation in the
selected profile scope, whether the target is compliant.

Auth: SSH key authentication. ``SILENE_SSH_USER`` and ``SILENE_SSH_KEY``
(absolute path to a private key file inside the container) are read
from the environment and forwarded to the binary; when only one of the
two is set the executor aborts so we never accidentally fall back to
agent-forwarding or password prompts in a non-interactive context.

Output mapping: every recommendation that the tool flagged as
non-compliant (or that errored out) becomes one Faraday vulnerability.
Compliant / skipped recommendations are dropped. All findings attach
to a single Faraday host representing the target. Severity is bucketed
from the recommendation level — ``minimal`` failures are the most
critical (the bare-minimum baseline is not met) and ``high`` failures
are the least critical (only the strictest hardening level requires
them):

* minimal       -> critical
* intermediate  -> high
* enhanced      -> medium
* high          -> low

When the level is missing or unknown, a keyword heuristic on the rule
title is used as a last-resort fallback. Errored recommendations
(status=error) are surfaced as ``info``.
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

SILENE_BINARY = os.environ.get("SILENE_BIN", "silene")

VALID_PROFILES = (
    "anssi-bp-028-minimal",
    "intermediate",
    "enhanced",
    "high",
)

# ANSSI BP-028 recommendation levels. ``minimal`` is the bare-minimum
# baseline (failing it means even the lowest hardening profile is not
# met), ``high`` only applies in the strictest profile.
LEVEL_TO_SEVERITY = {
    "minimal": "critical",
    "anssi-bp-028-minimal": "critical",
    "intermediate": "high",
    "anssi-bp-028-intermediate": "high",
    "enhanced": "medium",
    "anssi-bp-028-enhanced": "medium",
    "high": "low",
    "anssi-bp-028-high": "low",
}

# Statuses SILENE may emit for a recommendation.
NON_COMPLIANT_STATUSES = {
    "non-compliant",
    "non_compliant",
    "noncompliant",
    "fail",
    "failed",
    "ko",
    "false",
}
COMPLIANT_STATUSES = {
    "compliant",
    "pass",
    "passed",
    "ok",
    "true",
    "skipped",
    "skip",
    "not-applicable",
    "not_applicable",
    "n/a",
    "na",
}
ERROR_STATUSES = {
    "error",
    "errored",
    "unknown",
}

# Last-resort keyword bucket for rule titles when no level is reported.
TITLE_KEYWORDS = (
    (
        "critical",
        (
            "root",
            "sudo",
            "ssh root",
            "password",
            "uefi",
            "secure boot",
            "kernel",
        ),
    ),
    (
        "high",
        (
            "selinux",
            "apparmor",
            "umask",
            "pam",
            "tls",
            "tcp",
            "firewall",
            "iptables",
            "nftables",
        ),
    ),
    (
        "medium",
        (
            "syslog",
            "audit",
            "logging",
            "logrotate",
            "logfile",
            "ntp",
            "rsyslog",
            "journald",
            "cron",
        ),
    ),
    (
        "low",
        (
            "banner",
            "motd",
            "issue",
            "comment",
        ),
    ),
)


def log(msg):
    print(f"{datetime.utcnow()} - SILENE: {msg}", file=sys.stderr, flush=True)


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


def severity_from_level(level):
    if not level:
        return None
    return LEVEL_TO_SEVERITY.get(str(level).strip().lower())


def severity_from_title(title):
    lowered = (title or "").lower()
    for severity, keywords in TITLE_KEYWORDS:
        for keyword in keywords:
            if keyword in lowered:
                return severity
    return "info"


def severity_for(level, title, status):
    if normalise_status(status) == "error":
        return "info"
    return severity_from_level(level) or severity_from_title(title)


def normalise_status(status):
    if status is None:
        return ""
    text = str(status).strip().lower()
    if text in NON_COMPLIANT_STATUSES:
        return "non-compliant"
    if text in COMPLIANT_STATUSES:
        return "compliant"
    if text in ERROR_STATUSES:
        return "error"
    return text


def is_failing(status):
    state = normalise_status(status)
    return state in ("non-compliant", "error")


def build_command(target, profile, ssh_user, ssh_key, output_dir):
    cmd = [SILENE_BINARY, "--target", target, "--output", str(output_dir), "--format", "json"]
    if profile:
        cmd += ["--profile", profile]
    if ssh_user:
        cmd += ["--ssh-user", ssh_user]
    if ssh_key:
        cmd += ["--ssh-key", ssh_key]
    return cmd


def iter_recommendations(payload):
    """Yield ``(recommendation_dict,)`` tuples from one parsed JSON file.

    SILENE-style outputs come in a few shapes across versions / report
    modes: a single recommendation dict, a list of them, or a wrapper
    object with the recommendations grouped under one of a few common
    keys. Be tolerant of all of them.
    """
    if isinstance(payload, list):
        for item in payload:
            yield from iter_recommendations(item)
        return
    if not isinstance(payload, dict):
        return

    for container_key in (
        "recommendations",
        "rules",
        "results",
        "findings",
        "checks",
        "items",
    ):
        container = payload.get(container_key)
        if isinstance(container, list):
            for item in container:
                yield from iter_recommendations(item)
            return
        if isinstance(container, dict):
            for item in container.values():
                yield from iter_recommendations(item)
            return

    rec_id = payload.get("id") or payload.get("rule_id") or payload.get("recommendation") or payload.get("name")
    if rec_id:
        yield payload


def get_first(rec, *keys):
    for key in keys:
        value = rec.get(key)
        if value not in (None, ""):
            return value
    return None


def build_vulnerability(rec):
    rec_id = get_first(rec, "id", "rule_id", "recommendation", "name") or "SILENE"
    title = get_first(rec, "title", "name", "summary", "description") or str(rec_id)
    level = get_first(rec, "level", "profile", "severity", "applies_to")
    status = get_first(rec, "status", "result", "outcome", "state")
    rationale = get_first(rec, "rationale", "description", "details", "explanation")
    remediation = get_first(rec, "remediation", "fix", "recommendation_text", "solution")
    evidence = get_first(rec, "evidence", "output", "stdout", "actual")

    severity = severity_for(level, title, status)

    desc_parts = [f"SILENE recommendation: {rec_id}"]
    if title and str(title) != str(rec_id):
        desc_parts.append(f"Title: {title}")
    if level:
        desc_parts.append(f"Level: {level}")
    if status:
        desc_parts.append(f"Status: {status}")
    if rationale and str(rationale) != str(title):
        desc_parts.append(f"Rationale: {rationale}")
    if remediation:
        desc_parts.append(f"Remediation: {remediation}")
    if evidence:
        text = evidence if isinstance(evidence, str) else json.dumps(evidence, default=str)
        desc_parts.append("Evidence: " + text[:500])

    tags = ["silene"]
    if level:
        tags.append(str(level).lower())
    state = normalise_status(status)
    if state:
        tags.append(state)

    return {
        "name": f"SILENE {rec_id}: {title}" if title and str(title) != str(rec_id) else f"SILENE {rec_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(rec_id),
        "type": "Vulnerability",
        "status": "open",
        "resolution": remediation or "",
        "data": "",
        "refs": [
            {
                "name": (
                    "https://www.ssi.gouv.fr/administration/guide/"
                    "recommandations-de-securite-relatives-a-un-systeme-gnulinux/"
                ),
                "type": "other",
            },
            {
                "name": "https://github.com/ANSSI-FR/SILENE",
                "type": "other",
            },
        ],
        "cve": [],
        "tags": [t for t in tags if t],
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
        for rec in iter_recommendations(payload):
            status = get_first(rec, "status", "result", "outcome", "state")
            if not is_failing(status):
                continue
            rec_id = get_first(rec, "id", "rule_id", "recommendation", "name") or "SILENE"
            key = (str(rec_id), normalise_status(status))
            if key in seen:
                continue
            seen.add(key)
            vulns.append(build_vulnerability(rec))
    return vulns


def main():
    started = time.time()
    target = env("EXECUTOR_CONFIG_SILENE_TARGET_HOST", required=True)
    profile = (env("EXECUTOR_CONFIG_SILENE_PROFILE") or "").strip()
    if profile and profile not in VALID_PROFILES:
        log(f"SILENE_PROFILE must be one of {VALID_PROFILES}, got {profile!r}")
        sys.exit(1)
    ssh_user = env("SILENE_SSH_USER")
    ssh_key = env("SILENE_SSH_KEY")
    if (ssh_user and not ssh_key) or (ssh_key and not ssh_user):
        log("SILENE_SSH_USER and SILENE_SSH_KEY must both be set or both be empty")
        sys.exit(1)
    if ssh_key and not Path(ssh_key).is_file():
        log(f"SILENE_SSH_KEY does not point to a readable file: {ssh_key}")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="silene-") as output_dir:
        cmd = build_command(target, profile, ssh_user, ssh_key, output_dir)
        log(f"Running SILENE against {target} (profile={profile or 'default'}, output={output_dir})")
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            log(f"SILENE exited with {proc.returncode}: {proc.stderr[:500]}")

        vulns = collect_vulns(output_dir)

    log(f"Parsed {len(vulns)} SILENE finding(s) for target={target}")

    host = {
        "ip": target,
        "hostnames": [target],
        "description": (
            f"ANSSI SILENE Linux hardening assessment (target={target}, " f"profile={profile or 'default'})"
        ),
        "os": "Linux",
        "mac": "",
        "vulnerabilities": vulns,
    }

    safe_cmd = [SILENE_BINARY, "--target", target, "--output", "<tmpdir>", "--format", "json"]
    if profile:
        safe_cmd += ["--profile", profile]
    if ssh_user:
        safe_cmd += ["--ssh-user", ssh_user]
    if ssh_key:
        safe_cmd += ["--ssh-key", "<redacted>"]

    output = {
        "hosts": [host],
        "command": {
            "tool": "anssi_silene",
            "command": " ".join(safe_cmd),
            "params": f"target={target} profile={profile or 'default'}",
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
