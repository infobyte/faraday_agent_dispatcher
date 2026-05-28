#!/usr/bin/env python3
import os
import sys
import json
import subprocess

from faraday_plugins.plugins.repo.crowdstrike.plugin import Crowdstrike

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters

"""
This executor expects a CrowdStrike Falcon export already on disk
(e.g. obtained from the Falcon UI as JSON or via the falconpy SDK).
For an API-pull variant, replace `read_report()` with a falconpy
client that calls /detects/queries/detects/v1 + /devices/entities/devices/v1.
"""


def read_report() -> str:
    report_path = os.environ.get("EXECUTOR_CONFIG_CROWDSTRIKE_REPORT")
    if not report_path:
        print("CROWDSTRIKE_REPORT path is required", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(report_path):
        print(f"CROWDSTRIKE_REPORT not found: {report_path}", file=sys.stderr)
        sys.exit(1)
    with open(report_path) as f:
        return f.read()


def main():
    agent_config = get_common_parameters()
    raw = read_report()

    plugin = Crowdstrike(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
