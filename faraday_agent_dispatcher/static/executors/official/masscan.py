#!/usr/bin/env python3
"""masscan high-rate TCP/UDP port scanner executor.

Runs `masscan -oJ` and emits one Faraday host per scanned IP with a
service entry per open port.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ALLOWED_PROTO = {"tcp", "udp"}


def build_command(output_path: Path) -> list[str]:
    target = os.environ.get("EXECUTOR_CONFIG_MASSCAN_TARGET")
    ports = os.environ.get("EXECUTOR_CONFIG_MASSCAN_PORTS")
    if not target:
        print("MASSCAN_TARGET is required", file=sys.stderr)
        sys.exit(1)
    if not ports:
        print("MASSCAN_PORTS is required", file=sys.stderr)
        sys.exit(1)
    rate = os.environ.get("EXECUTOR_CONFIG_MASSCAN_RATE", "1000")
    cmd = ["masscan", "-oJ", str(output_path), "-p", ports, "--rate", str(rate), target]
    exclude = os.environ.get("EXECUTOR_CONFIG_MASSCAN_EXCLUDE")
    if exclude:
        cmd += ["--exclude", exclude]
    return cmd


def main():
    start = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "masscan.json"
        proc = subprocess.run(build_command(out), capture_output=True, text=True)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        hosts_by_ip: dict[str, dict] = {}
        if out.exists():
            for line in out.read_text().splitlines():
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ip = entry.get("ip", "")
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
                for p in entry.get("ports", []) or []:
                    proto = p.get("proto", "tcp")
                    h["services"].append(
                        {
                            "name": str(p.get("port", "")),
                            "protocol": proto if proto in ALLOWED_PROTO else "tcp",
                            "port": int(p.get("port", 0)),
                            "status": "open" if p.get("status") == "open" else "closed",
                            "version": "",
                            "description": "",
                            "credentials": [],
                            "vulnerabilities": [],
                            "tags": [],
                        }
                    )
    duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    print(
        json.dumps(
            {
                "hosts": list(hosts_by_ip.values()),
                "command": {
                    "tool": "masscan",
                    "command": "masscan",
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
