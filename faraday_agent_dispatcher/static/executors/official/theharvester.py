#!/usr/bin/env python3
"""theHarvester OSINT executor.

Runs theHarvester and parses its XML output directly into Faraday
bulk-create JSON. Each unique IP becomes a host with the discovered
subdomains as its hostnames; emails are attached as tags so downstream
workflows can act on them. Stdlib-only — does not depend on a
faraday_plugins theharvester parser (not all builds ship it).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from faraday_agent_dispatcher.utils import arg_helpers


def build_command(basepath: Path) -> list[str]:
    domain = os.environ.get("EXECUTOR_CONFIG_THEHARVESTER_DOMAIN")
    if not domain:
        print("THEHARVESTER_DOMAIN is required", file=sys.stderr)
        sys.exit(1)
    sources = arg_helpers.csv(
        "EXECUTOR_CONFIG_THEHARVESTER_SOURCES",
        "anubis,crtsh,duckduckgo,hackertarget",
    )
    cmd = ["theHarvester", "-d", domain, "-b", sources, "-f", str(basepath)]
    limit = os.environ.get("EXECUTOR_CONFIG_THEHARVESTER_LIMIT")
    if limit:
        cmd += ["-l", str(limit)]
    start = os.environ.get("EXECUTOR_CONFIG_THEHARVESTER_START")
    if start:
        cmd += ["-S", str(start)]
    return cmd


def parse_xml(raw: str) -> list[dict]:
    """Map theHarvester XML into Faraday host dicts."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        print(f"theHarvester XML parse error: {exc}", file=sys.stderr)
        return []

    hosts_by_ip: dict[str, dict] = {}

    def _ensure(ip: str) -> dict:
        return hosts_by_ip.setdefault(
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

    # Bare <ip>1.2.3.4</ip> entries (no associated hostname).
    for el in root.iter("ip"):
        ip = (el.text or "").strip()
        if ip:
            _ensure(ip)

    # <host><ip>...</ip><hostname>...</hostname></host> and bare <host>name</host>.
    for h in root.iter("host"):
        ip_el = h.find("ip")
        hostname_el = h.find("hostname")
        if ip_el is not None and (ip_el.text or "").strip():
            ip = ip_el.text.strip()
            host = _ensure(ip)
            if hostname_el is not None and (hostname_el.text or "").strip():
                name = hostname_el.text.strip()
                if name not in host["hostnames"]:
                    host["hostnames"].append(name)
        else:
            name = (h.text or "").strip()
            if name:
                host = _ensure(name)
                if name not in host["hostnames"]:
                    host["hostnames"].append(name)

    # Emails — record as tags on a synthetic 'emails' host so they're searchable.
    emails: list[str] = []
    for e in root.iter("email"):
        v = (e.text or "").strip()
        if v:
            emails.append(v)
    if emails:
        host = _ensure("emails")
        host["description"] = "theHarvester email harvest"
        host["tags"] = sorted({f"email:{e}" for e in emails})

    return list(hosts_by_ip.values())


def main() -> None:
    start = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory() as tmp:
        basepath = Path(tmp) / "harvester"
        proc = subprocess.run(build_command(basepath), capture_output=True, text=True)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        xml = Path(f"{basepath}.xml")
        if not xml.exists():
            print("theHarvester produced no XML output", file=sys.stderr)
            sys.exit(proc.returncode or 1)
        hosts = parse_xml(xml.read_text())
    duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    print(
        json.dumps(
            {
                "hosts": hosts,
                "command": {
                    "tool": "theharvester",
                    "command": "theHarvester",
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
