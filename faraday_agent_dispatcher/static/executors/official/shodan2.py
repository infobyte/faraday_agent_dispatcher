#!/usr/bin/env python3

import os
import gzip
import sys
import subprocess
import tempfile
from pathlib import Path

from faraday_plugins.plugins.repo.shodan.plugin import ShodanPlugin


def main():
    ignore_info = os.getenv("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
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
    shodan_query = os.environ.get("EXECUTOR_CONFIG_SHODAN_QUERY")
    with tempfile.TemporaryDirectory() as tempdirname:
        tmpdir = Path(tempdirname)
        tmpfile = tempfile.NamedTemporaryFile(dir=tmpdir, suffix=".json.gz")
        name_result = tmpfile.name
        cmd = [
            "shodan",
            "download",
            name_result,
            f'"{shodan_query}"',
        ]

        shodan_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if len(shodan_process.stdout) > 0:
            print(
                f"Shodan stdout: {shodan_process.stdout.decode('utf-8')}",
                file=sys.stderr,
            )
        if len(shodan_process.stderr) > 0:
            print(
                f"Shodan stderr: {shodan_process.stderr.decode('utf-8')}",
                file=sys.stderr,
            )
        plugin = ShodanPlugin(
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
        )
        with gzip.open(name_result, "rb") as f:
            plugin.parseOutputString(f.read().decode("utf-8"))
            print(plugin.get_json())


if __name__ == "__main__":
    main()
