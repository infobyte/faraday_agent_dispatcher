#!/usr/bin/env python
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from faraday_plugins.plugins.repo.nikto.plugin import NiktoPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def main():
    agent_config = get_common_parameters()

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

        plugin = NiktoPlugin(**agent_config.to_plugin_kwargs())
        with open(name_result, "r") as f:
            plugin.parseOutputString(f.read())
            print(plugin.get_json())


if __name__ == "__main__":
    main()
