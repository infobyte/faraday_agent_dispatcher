#!/usr/bin/env python3
import os
import sys
import json
import tempfile
import subprocess
from pathlib import Path

from faraday_plugins.plugins.repo.naabu.plugin import NaabuPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def build_command(output_path: Path):
    host = os.environ.get("EXECUTOR_CONFIG_NAABU_HOST")
    host_list = os.environ.get("EXECUTOR_CONFIG_NAABU_HOST_LIST")
    if not host and not host_list:
        print("NAABU_HOST or NAABU_HOST_LIST is required", file=sys.stderr)
        sys.exit(1)

    ports = os.environ.get("EXECUTOR_CONFIG_NAABU_PORTS")
    top_ports = os.environ.get("EXECUTOR_CONFIG_NAABU_TOP_PORTS")
    rate = os.environ.get("EXECUTOR_CONFIG_NAABU_RATE")
    threads = os.environ.get("EXECUTOR_CONFIG_NAABU_THREADS")

    cmd = ["naabu", "-json", "-o", str(output_path), "-silent"]

    if host_list:
        host_file = output_path.parent / "hosts.txt"
        host_file.write_text("\n".join(json.loads(host_list)))
        cmd += ["-list", str(host_file)]
    else:
        cmd += ["-host", host]

    if ports:
        cmd += ["-p", ports]
    if top_ports:
        cmd += ["-top-ports", str(top_ports)]
    if rate:
        cmd += ["-rate", str(rate)]
    if threads:
        cmd += ["-c", str(threads)]

    return cmd


def main():
    agent_config = get_common_parameters()

    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "naabu.json"
        cmd = build_command(output_path)

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if proc.stderr:
            print(proc.stderr, file=sys.stderr)

        if not output_path.exists():
            print("Naabu produced no output file", file=sys.stderr)
            sys.exit(proc.returncode or 1)

        raw = output_path.read_text()

    plugin = NaabuPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
