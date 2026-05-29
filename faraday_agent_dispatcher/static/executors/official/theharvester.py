#!/usr/bin/env python3
"""theHarvester OSINT executor.

Runs theHarvester and parses the XML output via faraday_plugins'
TheHarvesterPlugin so emails / subdomains / hosts land in Faraday in
the canonical bulk-create shape.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from faraday_plugins.plugins.repo.theharvester.plugin import TheHarvesterPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def build_command(basepath: Path) -> list[str]:
    domain = os.environ.get("EXECUTOR_CONFIG_THEHARVESTER_DOMAIN")
    if not domain:
        print("THEHARVESTER_DOMAIN is required", file=sys.stderr)
        sys.exit(1)
    sources = os.environ.get(
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


def main():
    agent_config = get_common_parameters()
    with tempfile.TemporaryDirectory() as tmp:
        basepath = Path(tmp) / "harvester"
        proc = subprocess.run(build_command(basepath), capture_output=True, text=True)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        xml = Path(f"{basepath}.xml")
        if not xml.exists():
            print("theHarvester produced no XML output", file=sys.stderr)
            sys.exit(proc.returncode or 1)
        raw = xml.read_text()
    plugin = TheHarvesterPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
