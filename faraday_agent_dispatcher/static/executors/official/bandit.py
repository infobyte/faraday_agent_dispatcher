#!/usr/bin/env python3
import os
import sys
import subprocess

from faraday_plugins.plugins.repo.bandit.plugin import BanditPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters
from faraday_agent_dispatcher.utils.source_target import resolve_source_path


def build_command():
    target = resolve_source_path("BANDIT")

    confidence = os.environ.get("EXECUTOR_CONFIG_BANDIT_CONFIDENCE")
    severity = os.environ.get("EXECUTOR_CONFIG_BANDIT_SEVERITY")
    skip = os.environ.get("EXECUTOR_CONFIG_BANDIT_SKIP")

    cmd = ["bandit", "-r", "-f", "xml", "-q"]

    if confidence:
        cmd += ["--confidence-level", confidence]
    if severity:
        cmd += ["--severity-level", severity]
    if skip:
        cmd += ["-s", skip]

    cmd.append(target)
    return cmd


def main():
    agent_config = get_common_parameters()
    cmd = build_command()

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if not result.stdout.strip():
        print("Bandit produced no output", file=sys.stderr)
        sys.exit(result.returncode or 1)

    plugin = BanditPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(result.stdout)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
