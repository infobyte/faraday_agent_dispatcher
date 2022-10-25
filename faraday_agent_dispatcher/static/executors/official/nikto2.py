#!/usr/bin/env python
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from faraday_plugins.plugins.repo.nikto.plugin import NiktoPlugin
from faraday_agent_dispatcher.utils.executor_utils import get_plugins_args

def main():
    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_TARGET_URL', 'EXECUTOR_CONFIG_TARGET_PORT']
    my_envs = os.environ
    plugins_args = get_plugins_args(my_envs)
    url_target = os.environ.get("EXECUTOR_CONFIG_TARGET_URL")
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit(1)

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
            print("Nikto stderr", file=sys.stderr)
            print(f"{nikto_process.stderr.decode('utf-8')}", file=sys.stderr)
        plugin = NiktoPlugin(**plugins_args)
        with open(name_result, "r") as f:
            plugin.parseOutputString(f.read())
            print(plugin.get_json())


if __name__ == "__main__":
    main()
