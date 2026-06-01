#!/usr/bin/env python3
import json
import sys
import subprocess

from faraday_plugins.plugins.repo.bandit.plugin import BanditPlugin

from faraday_agent_dispatcher.utils import arg_helpers
from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters
from faraday_agent_dispatcher.utils.source_target import resolve_source_path


def build_command():
    target = resolve_source_path("BANDIT")

    confidence = arg_helpers.single("EXECUTOR_CONFIG_BANDIT_CONFIDENCE")
    severity = arg_helpers.single("EXECUTOR_CONFIG_BANDIT_SEVERITY")
    skip = arg_helpers.csv("EXECUTOR_CONFIG_BANDIT_SKIP")

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
        # Bandit's -q + XML formatter writes nothing to stdout when there are
        # no findings (or when every match was suppressed by `# nosec`).
        # That's a successful, empty scan — emit an empty Faraday payload
        # and exit 0 rather than letting the dispatcher flag the run as
        # "finished with exit code 1". Only escalate when bandit itself
        # signalled a real error (returncode 2+).
        if result.returncode in (0, 1):
            print(json.dumps({"hosts": [], "command": {"tool": "bandit", "command": "bandit", "duration": 0}}))
            return
        print(f"Bandit failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)

    plugin = BanditPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(result.stdout)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
