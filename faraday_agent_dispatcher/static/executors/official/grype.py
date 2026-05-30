#!/usr/bin/env python3
import os
import sys
import subprocess

from faraday_plugins.plugins.repo.grype.plugin import GrypePlugin

from faraday_agent_dispatcher.utils import arg_helpers
from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def build_command():
    target = os.environ.get("EXECUTOR_CONFIG_GRYPE_TARGET")
    if not target:
        print("GRYPE_TARGET is required", file=sys.stderr)
        sys.exit(1)

    fail_on = arg_helpers.single("EXECUTOR_CONFIG_GRYPE_FAIL_ON")
    only_fixed = os.environ.get("EXECUTOR_CONFIG_GRYPE_ONLY_FIXED")
    scope = arg_helpers.single("EXECUTOR_CONFIG_GRYPE_SCOPE")

    cmd = ["grype", target, "-o", "json", "-q"]

    if fail_on:
        cmd += ["--fail-on", fail_on]
    if only_fixed and only_fixed.lower() == "true":
        cmd.append("--only-fixed")
    if scope:
        cmd += ["--scope", scope]

    return cmd


def main():
    agent_config = get_common_parameters()
    cmd = build_command()

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if not result.stdout.strip():
        print("Grype produced no output", file=sys.stderr)
        sys.exit(result.returncode or 1)

    plugin = GrypePlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(result.stdout)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
