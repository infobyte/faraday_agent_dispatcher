#!/usr/bin/env python
import os
import re
import sys
import tempfile
import subprocess
from urllib.parse import urlparse
from faraday_plugins.plugins.repo.arachni.plugin import ArachniPlugin

# Import the centralized agent configuration utility
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
try:
    from utils.agent_configuration import get_common_parameters

    USE_COMMON_PARAMS = True
except ImportError:
    USE_COMMON_PARAMS = False


def remove_multiple_new_line(text: str):
    return re.sub(r"\n+", "\n", text)


def flush_messages(process):
    if len(process.stdout) > 0:
        stdout = remove_multiple_new_line(process.stdout.decode("utf-8"))
        print(f"Arachni stdout: {stdout}", file=sys.stderr)
    if len(process.stderr) > 0:
        stderr = remove_multiple_new_line(process.stderr.decode("utf-8"))
        print(f"Arachni stderr: {stderr}", file=sys.stderr)


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

    my_envs = os.environ
    # If the script is run outside the dispatcher
    # the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_NAME_URL', 'ARACHNI_PATH']
    if "EXECUTOR_CONFIG_NAME_URL" in my_envs:
        url_analyze = os.environ.get("EXECUTOR_CONFIG_NAME_URL")
        url = urlparse(url_analyze)
        if url.scheme != "http" and url.scheme != "https":
            url_analyze = f"http://{url_analyze}"
    else:
        print("Param NAME_URL no passed", file=sys.stderr)
        sys.exit()

    if "ARACHNI_PATH" in my_envs:
        path_arachni = os.environ.get("ARACHNI_PATH")
        if path_arachni is None:
            print("Environment variable ARACHNI_PATH no set", file=sys.stderr)
            sys.exit()
    else:
        print("Environment variable ARACHNI_PATH no set", file=sys.stderr)
        sys.exit()
    os.chdir(path_arachni)
    file_afr = tempfile.NamedTemporaryFile(mode="w", suffix=".afr")

    timeout = os.environ.get("EXECUTOR_CONFIG_TIMEOUT", "")
    if re.match(r"(\d\d:[0-5][0-9]:[0-5][0-9])", timeout):
        cmd = [
            "./arachni",
            url_analyze,
            "--timeout",
            timeout,
            "--report-save-path",
            file_afr.name,
        ]
    else:
        cmd = ["./arachni", url_analyze, "--report-save-path", file_afr.name]
    arachni_command = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    flush_messages(arachni_command)

    name_xml = tempfile.NamedTemporaryFile(mode="w", suffix=".xml")

    cmd = [
        "./arachni_reporter",
        file_afr.name,
        "--reporter",
        f"xml:outfile={name_xml.name}",
    ]

    arachni_reporter_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    flush_messages(arachni_reporter_process)

    if USE_COMMON_PARAMS:
        plugin = ArachniPlugin(**agent_config.to_plugin_kwargs())
    else:
        plugin = ArachniPlugin(
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
            min_severity=min_severity,
            max_severity=max_severity,
        )
    with open(name_xml.name, "r", encoding="utf-8") as f:
        plugin.parseOutputString(f.read())
        print(plugin.get_json())

    name_xml.close()
    file_afr.close()


if __name__ == "__main__":
    main()
