#!/usr/bin/env python3
import os
import sys
import json
import subprocess

from faraday_plugins.plugins.repo.semgrep.plugin import SemgrepPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def build_command():
    target = os.environ.get("EXECUTOR_CONFIG_SEMGREP_TARGET")
    if not target:
        print("SEMGREP_TARGET is required", file=sys.stderr)
        sys.exit(1)

    configs = os.environ.get("EXECUTOR_CONFIG_SEMGREP_CONFIG", "auto")
    exclude = os.environ.get("EXECUTOR_CONFIG_SEMGREP_EXCLUDE")
    timeout = os.environ.get("EXECUTOR_CONFIG_SEMGREP_TIMEOUT")

    cmd = ["semgrep", "scan", "--json"]
    for config in [c.strip() for c in configs.split(",") if c.strip()]:
        cmd += ["--config", config]

    if exclude:
        for pattern in json.loads(exclude):
            cmd += ["--exclude", pattern]

    if timeout:
        cmd += ["--timeout", str(timeout)]

    cmd.append(target)
    return cmd


def main():
    agent_config = get_common_parameters()
    cmd = build_command()

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if not result.stdout.strip():
        print("Semgrep produced no output", file=sys.stderr)
        sys.exit(result.returncode or 1)

    plugin = SemgrepPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(result.stdout)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
