#!/usr/bin/env python
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from faraday_plugins.plugins.repo.nikto.plugin import NiktoPlugin

# Import the centralized agent configuration utility
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
try:
    from utils.agent_configuration import get_common_parameters

    USE_COMMON_PARAMS = True
except ImportError:
    USE_COMMON_PARAMS = False


def main():
    # Get centralized agent configuration if available, otherwise use manual parsing
    if USE_COMMON_PARAMS:
        agent_config = get_common_parameters()
    else:
        ignore_info = os.getenv("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
        min_severity = os.getenv("AGENT_CONFIG_MIN_SEVERITY", None)
        max_severity = os.getenv("AGENT_CONFIG_MAX_SEVERITY", None)
        hostname_resolution = os.getenv("AGENT_CONFIG_RESOLVE_HOSTNAME", "True").lower() == "true"
        vuln_tag = os.getenv("AGENT_CONFIG_VULN_TAG", None)
        if vuln_tag:
            vuln_tag = vuln_tag.split(",")
        service_tag = os.getenv("AGENT_CONFIG_SERVICE_TAG", None)
        if service_tag:
            service_tag = service_tag.split(",")
        host_tag = os.getenv("AGENT_CONFIG_HOSTNAME_TAG", None)
        if host_tag:
            host_tag = host_tag.split(",")

    url_target = os.environ.get("EXECUTOR_CONFIG_TARGET_URL")
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    with tempfile.TemporaryDirectory() as tempdirname:
        tmpdir = Path(tempdirname)
        name_result = tmpdir / "output.xml"

        cmd = [
            "nikto",
            "-h",
            url_target,
            "-o",
            name_result,
        ]

        nikto_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if len(nikto_process.stdout) > 0:
            print(
                f"Nikto stdout: {nikto_process.stdout.decode('utf-8')}",
                file=sys.stderr,
            )
        if len(nikto_process.stderr) > 0:
            print(f"Nikto stderr: {nikto_process.stderr.decode('utf-8')}", file=sys.stderr)

        if USE_COMMON_PARAMS:
            plugin = NiktoPlugin(**agent_config.to_plugin_kwargs())
        else:
            plugin = NiktoPlugin(
                ignore_info=ignore_info,
                min_severity=min_severity,
                max_severity=max_severity,
                hostname_resolution=hostname_resolution,
                host_tag=host_tag,
                service_tag=service_tag,
                vuln_tag=vuln_tag,
            )
        with open(name_result, "r") as f:
            plugin.parseOutputString(f.read())
            print(plugin.get_json())


if __name__ == "__main__":
    main()
