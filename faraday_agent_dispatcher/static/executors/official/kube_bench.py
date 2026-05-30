#!/usr/bin/env python3
import os
import sys
import json
import socket
import subprocess
import time
from datetime import datetime, timezone

from faraday_agent_dispatcher.utils import arg_helpers

SEVERITY_MAP = {"FAIL": "high", "WARN": "med", "INFO": "info", "PASS": "info"}


def faraday_command(params: str, started: float) -> dict:
    return {
        "tool": "kube-bench",
        "command": "kube-bench",
        "params": params,
        "user": os.environ.get("USER", ""),
        "hostname": socket.gethostname(),
        "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
        "duration": int((time.time() - started) * 1000),
        "import_source": "report",
    }


def build_command():
    benchmark = arg_helpers.single("EXECUTOR_CONFIG_KUBEBENCH_BENCHMARK")
    targets = arg_helpers.csv("EXECUTOR_CONFIG_KUBEBENCH_TARGETS")
    config_dir = os.environ.get("EXECUTOR_CONFIG_KUBEBENCH_CONFIG_DIR")

    cmd = ["kube-bench", "run", "--json"]
    if benchmark:
        cmd += ["--benchmark", benchmark]
    if targets:
        cmd += ["--targets", targets]
    if config_dir:
        cmd += ["--config-dir", config_dir]
    return cmd


def to_vuln(test: dict) -> dict:
    status = (test.get("status") or "WARN").upper()
    test_number = test.get("test_number", "")
    desc = test.get("test_desc") or test.get("desc") or "kube-bench finding"
    return {
        "name": f"kube-bench {test_number}: {desc[:80]}",
        "desc": (
            f"Test: {test_number}\n"
            f"Status: {status}\n"
            f"Description: {desc}\n"
            f"Audit: {test.get('audit', '')}\n"
            f"Remediation: {test.get('remediation', '')}"
        ),
        "severity": SEVERITY_MAP.get(status, "unclassified"),
        "type": "Vulnerability",
        "external_id": f"kube-bench:{test_number}",
        "resolution": test.get("remediation", ""),
    }


def main():
    started = time.time()
    cmd = build_command()

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)

    if not proc.stdout.strip():
        print("kube-bench produced no output", file=sys.stderr)
        sys.exit(proc.returncode or 1)

    data = json.loads(proc.stdout)
    hostname = socket.gethostname()

    vulns = []
    for control in data.get("Controls", []):
        for test in control.get("tests", []):
            for result in test.get("results", []):
                status = (result.get("status") or "").upper()
                if status in {"PASS", "INFO"}:
                    continue
                vulns.append(to_vuln(result))

    host = {
        "ip": hostname,
        "hostnames": [hostname],
        "description": f"kube-bench results ({data.get('id', 'cis-benchmark')})",
        "vulnerabilities": vulns,
    }

    print(json.dumps({"hosts": [host], "command": faraday_command("kube-bench run", started)}))


if __name__ == "__main__":
    main()
