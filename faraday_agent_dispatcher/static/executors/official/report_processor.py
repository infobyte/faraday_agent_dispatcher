#!/usr/bin/env python
import os
import sys
from pathlib import Path
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer


def main():
    my_envs = os.environ
    # If the script is run outside the dispatcher
    # the environment variables
    # are checked.
    ignore_info = my_envs.get("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
    hostname_resolution = my_envs.get("AGENT_CONFIG_RESOLVE_HOSTNAME", "True").lower() == "true"
    vuln_tag = os.getenv("AGENT_CONFIG_VULN_TAG", None)
    if vuln_tag:
        vuln_tag = vuln_tag.split(",")
    service_tag = os.getenv("AGENT_CONFIG_SERVICE_TAG", None)
    if service_tag:
        service_tag = service_tag.split(",")
    host_tag = os.getenv("AGENT_CONFIG_HOSTNAME_TAG", None)
    if host_tag:
        host_tag = host_tag.split(",")
    tool = os.environ.get("EXECUTOR_CONFIG_TOOL", None)

    if "EXECUTOR_CONFIG_REPORT_NAME" in my_envs:
        report_name = os.environ.get("EXECUTOR_CONFIG_REPORT_NAME")
    else:
        print("Argument REPORT_NAME no set", file=sys.stderr)
        sys.exit()

    if "REPORTS_PATH" in my_envs:
        report_dir = os.environ.get("REPORTS_PATH")
    else:
        print("Environment variable REPORT_DIR no set", file=sys.stderr)
        sys.exit()

    filepath = Path(report_dir) / report_name
    manager = PluginsManager(
        ignore_info=ignore_info,
        hostname_resolution=hostname_resolution,
        host_tag=host_tag,
        service_tag=service_tag,
        vuln_tag=vuln_tag,
    )

    if tool is not None:
        plugin = manager.get_plugin(tool)
    else:
        plugin = ReportAnalyzer(manager).get_plugin(filepath)
        print(f"Detector found it as an {plugin} report", file=sys.stderr)

    print(f"Parsing {filepath} report", file=sys.stderr)
    plugin.processReport(str(filepath))
    print(plugin.get_json())


if __name__ == "__main__":
    main()
