#!/usr/bin/env python3
import os
import sys
import json
import tempfile
import subprocess
from pathlib import Path

from faraday_plugins.plugins.repo.subfinderjson.plugin import SubfinderPluginJSON

from faraday_agent_dispatcher.utils import arg_helpers
from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def build_command(output_path: Path):
    domain = os.environ.get("EXECUTOR_CONFIG_SUBFINDER_DOMAIN")
    domain_list = os.environ.get("EXECUTOR_CONFIG_SUBFINDER_DOMAIN_LIST")
    if not domain and not domain_list:
        print("SUBFINDER_DOMAIN or SUBFINDER_DOMAIN_LIST is required", file=sys.stderr)
        sys.exit(1)

    sources = arg_helpers.csv("EXECUTOR_CONFIG_SUBFINDER_SOURCES")
    threads = os.environ.get("EXECUTOR_CONFIG_SUBFINDER_THREADS")
    recursive = os.environ.get("EXECUTOR_CONFIG_SUBFINDER_RECURSIVE")

    cmd = ["subfinder", "-oJ", "-o", str(output_path), "-silent"]

    if domain_list:
        domain_file = output_path.parent / "domains.txt"
        domain_file.write_text("\n".join(json.loads(domain_list)))
        cmd += ["-dL", str(domain_file)]
    else:
        cmd += ["-d", domain]

    if sources:
        cmd += ["-s", sources]
    if threads:
        cmd += ["-t", str(threads)]
    if recursive and recursive.lower() == "true":
        cmd.append("-recursive")

    return cmd


def main():
    agent_config = get_common_parameters()

    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "subfinder.json"
        cmd = build_command(output_path)

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if proc.stderr:
            print(proc.stderr, file=sys.stderr)

        if not output_path.exists():
            print("Subfinder produced no output file", file=sys.stderr)
            sys.exit(proc.returncode or 1)

        raw = output_path.read_text()

    plugin = SubfinderPluginJSON(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
