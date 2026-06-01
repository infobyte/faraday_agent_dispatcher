#!/usr/bin/env python
"""PingCastle Active Directory healthcheck import executor.

Wraps the PingCastle CLI in ``--healthcheck`` mode against a target
domain controller, parses the resulting XML report (``ad_hc_<domain>.xml``)
and emits Faraday bulk-create JSON to stdout.

Command form::

    pingcastle --healthcheck --no-enum-limit --server <DC>
               [--healthcheck-level Light|Normal|Full]
               [--user <PINGCASTLE_USER> --password <PINGCASTLE_PASSWORD>]

Auth: Windows integrated authentication by default (kerberos / the
container's machine account). When ``PINGCASTLE_USER`` /
``PINGCASTLE_PASSWORD`` are set in the environment they are forwarded to
the binary.

Each ``HealthcheckRiskRule`` element that triggered is mapped to a
Faraday vulnerability; severity is bucketed from the PingCastle rule
``Maturity`` level (1 = critical, 5 = info) with a fallback to the
rule ``Points`` score when no maturity is reported.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

VALID_LEVELS = ("Light", "Normal", "Full")

# PingCastle maturity scale: lower maturity = worse posture. 1 is the
# most insecure baseline, 5 is best-practice / informational.
MATURITY_TO_SEVERITY = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
    5: "info",
}

CATEGORY_FALLBACK = {
    "anomalies": "high",
    "privilegedaccounts": "high",
    "staleobjects": "medium",
    "trusts": "medium",
}

PINGCASTLE_BINARY = os.environ.get("PINGCASTLE_BIN", "pingcastle")


def log(msg):
    print(f"{datetime.utcnow()} - PingCastle: {msg}", file=sys.stderr, flush=True)


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


def _local(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def find_local(node, tag):
    if node is None:
        return None
    for child in node:
        if _local(child.tag) == tag:
            return child
    return None


def findall_local(node, tag):
    if node is None:
        return []
    return [child for child in node if _local(child.tag) == tag]


def text_of(node, tag, default=""):
    child = find_local(node, tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def severity_from_maturity(maturity):
    try:
        return MATURITY_TO_SEVERITY.get(int(maturity))
    except (TypeError, ValueError):
        return None


def severity_from_points(points):
    try:
        value = float(points)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return "info"
    if value < 10:
        return "low"
    if value < 25:
        return "medium"
    if value < 50:
        return "high"
    return "critical"


def severity_from_category(category):
    return CATEGORY_FALLBACK.get((category or "").lower(), "info")


def collect_details(rule):
    details = find_local(rule, "Details")
    out = []
    if details is None:
        return out
    for child in details:
        if child.text:
            text = child.text.strip()
            if text:
                out.append(text)
    return out


def build_vulnerability(rule):
    risk_id = text_of(rule, "RiskId") or "PingCastle"
    category = text_of(rule, "Category")
    model = text_of(rule, "Model")
    rationale = text_of(rule, "Rationale")
    points = text_of(rule, "Points")
    maturity = text_of(rule, "Maturity")

    severity = severity_from_maturity(maturity) or severity_from_points(points) or severity_from_category(category)

    details = collect_details(rule)
    desc_parts = []
    if rationale:
        desc_parts.append(rationale)
    if category:
        desc_parts.append(f"Category: {category}")
    if model:
        desc_parts.append(f"Model: {model}")
    if points:
        desc_parts.append(f"Points: {points}")
    if maturity:
        desc_parts.append(f"Maturity: {maturity}")
    if details:
        desc_parts.append("Affected: " + "; ".join(details[:25]))

    return {
        "name": f"PingCastle {risk_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": risk_id,
        "type": "Vulnerability",
        "status": "open",
        "resolution": "",
        "data": "",
        "refs": [
            {
                "name": f"https://www.pingcastle.com/PingCastleFiles/{risk_id}.html",
                "type": "other",
            }
        ],
        "cve": [],
        "tags": [t for t in ["pingcastle", category] if t],
    }


def build_command(server, level, user, password):
    cmd = [PINGCASTLE_BINARY, "--healthcheck", "--no-enum-limit", "--server", server]
    if level:
        cmd += ["--healthcheck-level", level]
    if user and password:
        cmd += ["--user", user, "--password", password]
    return cmd


def find_report_xml(workdir):
    matches = sorted(
        Path(workdir).glob("ad_hc_*.xml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return matches[0] if matches else None


def parse_report(path):
    tree = ET.parse(path)
    root = tree.getroot()
    rules_root = find_local(root, "RiskRules")
    rules = findall_local(rules_root, "HealthcheckRiskRule")
    domain = text_of(root, "DomainFQDN") or text_of(root, "NetBIOSName")
    return domain, rules


def main():
    started = time.time()
    server = env("EXECUTOR_CONFIG_PINGCASTLE_SERVER", required=True)
    level = (env("EXECUTOR_CONFIG_PINGCASTLE_HEALTHCHECK_LEVEL") or "").strip()
    if level and level not in VALID_LEVELS:
        log(f"PINGCASTLE_HEALTHCHECK_LEVEL must be one of {VALID_LEVELS}, got {level!r}")
        sys.exit(1)
    user = env("PINGCASTLE_USER")
    password = env("PINGCASTLE_PASSWORD")

    cmd = build_command(server, level, user, password)
    safe_cmd = " ".join(cmd[:5] + (["--healthcheck-level", level] if level else []))

    with tempfile.TemporaryDirectory(prefix="pingcastle-") as workdir:
        log(f"Running PingCastle against {server} (cwd={workdir})")
        proc = subprocess.run(
            cmd,
            cwd=workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            log(f"PingCastle exited with {proc.returncode}: {proc.stderr[:500]}")

        report = find_report_xml(workdir)
        if report is None:
            log("No PingCastle XML report produced; aborting")
            print(json.dumps({"hosts": []}))
            return

        try:
            domain, rules = parse_report(report)
        except ET.ParseError as exc:
            log(f"Could not parse {report}: {exc}")
            sys.exit(1)

    vulns = [build_vulnerability(rule) for rule in rules]
    log(f"Parsed {len(vulns)} PingCastle rule(s) for domain={domain or 'unknown'}")

    host = {
        "ip": server,
        "hostnames": [h for h in [server, domain] if h],
        "description": (f"PingCastle healthcheck (domain={domain or 'unknown'}, " f"level={level or 'Normal'})"),
        "os": "Windows",
        "mac": "",
        "vulnerabilities": vulns,
    }

    output = {
        "hosts": [host],
        "command": {
            "tool": "pingcastle",
            "command": safe_cmd,
            "params": f"level={level or 'Normal'} server={server}",
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
