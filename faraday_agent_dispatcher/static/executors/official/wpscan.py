#!/usr/bin/env python
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from faraday_plugins.plugins.repo.wpscan.plugin import WPScanPlugin

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
        # Manual parsing for backwards compatibility
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

    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_WPSCAN_TARGET_URL']
    url_target = os.environ.get("EXECUTOR_CONFIG_WPSCAN_TARGET_URL")
    api_token = os.environ.get("EXECUTOR_CONFIG_WPSCAN_API_TOKEN")
    random_user_agent = os.environ.get("EXECUTOR_CONFIG_WPSCAN_RANDOM_USER_AGENT")
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    with tempfile.TemporaryDirectory() as tempdirname:
        tempdir = Path(tempdirname)
        name_output_file = "wpscan-output.json"
        out_file = tempdir / name_output_file
        cmd = [
            "wpscan",
            "-o",
            out_file,
            "--url",
            url_target,
            "-f",
            "json",
        ]
        if api_token:
            cmd += ["--api-token", api_token]
        if random_user_agent:
            cmd += ["--random_user_agent"]
        wpscan_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if len(wpscan_process.stdout) > 0:
            print(
                f"Wpscan stdout: {wpscan_process.stdout.decode('utf-8')}",
                file=sys.stderr,
            )
        if len(wpscan_process.stderr) > 0:
            print(
                f"Wpscan stderr: {wpscan_process.stderr.decode('utf-8')}",
                file=sys.stderr,
            )

        if USE_COMMON_PARAMS:
            plugin = WPScanPlugin(**agent_config.to_plugin_kwargs())
        else:
            plugin = WPScanPlugin(
                ignore_info=ignore_info,
                min_severity=min_severity,
                max_severity=max_severity,
                hostname_resolution=hostname_resolution,
                host_tag=host_tag,
                service_tag=service_tag,
                vuln_tag=vuln_tag,
            )
        with open(out_file, "r") as f:
            plugin.parseOutputString(f.read())
            print(plugin.get_json())


if __name__ == "__main__":
    main()
