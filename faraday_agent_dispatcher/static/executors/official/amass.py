#!/usr/bin/env python3
"""OWASP Amass subdomain enumeration executor.

Runs `amass enum -json` and emits the discovered subdomains + resolved
IPs as Faraday hosts (one host per unique IP; all subdomains pointing at
that IP become its hostnames).
"""

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def build_command(output_path: Path) -> list[str]:
    domain = os.environ.get("EXECUTOR_CONFIG_AMASS_DOMAIN")
    if not domain:
        print("AMASS_DOMAIN is required", file=sys.stderr)
        sys.exit(1)
    cmd = ["amass", "enum", "-d", domain, "-json", str(output_path), "-nocolor"]
    if os.environ.get("EXECUTOR_CONFIG_AMASS_PASSIVE", "").lower() == "true":
        cmd.append("-passive")
    timeout = os.environ.get("EXECUTOR_CONFIG_AMASS_TIMEOUT")
    if timeout:
        cmd += ["-timeout", str(timeout)]
    resolvers = os.environ.get("EXECUTOR_CONFIG_AMASS_RESOLVERS")
    if resolvers:
        cmd += ["-r", resolvers]
    return cmd


def main():
    start = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "amass.jsonl"
        proc = subprocess.run(build_command(out), capture_output=True, text=True)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        hosts_by_ip: dict[str, dict] = {}
        if out.exists():
            for line in out.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                name = entry.get("name", "")
                for addr in entry.get("addresses", []) or []:
                    ip = addr.get("ip", "")
                    if not ip:
                        continue
                    h = hosts_by_ip.setdefault(
                        ip,
                        {
                            "ip": ip,
                            "os": "unknown",
                            "hostnames": [],
                            "description": "",
                            "mac": None,
                            "credentials": [],
                            "services": [],
                            "vulnerabilities": [],
                            "tags": [],
                        },
                    )
                    if name and name not in h["hostnames"]:
                        h["hostnames"].append(name)
    duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    print(
        json.dumps(
            {
                "hosts": list(hosts_by_ip.values()),
                "command": {
                    "tool": "amass",
                    "command": "amass enum",
                    "params": "",
                    "user": "",
                    "hostname": "",
                    "start_date": start.isoformat(),
                    "duration": duration_ms,
                    "import_source": "report",
                },
            }
        )
    )


if __name__ == "__main__":
    main()
