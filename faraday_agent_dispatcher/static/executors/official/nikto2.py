#!/usr/bin/env python
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from faraday_plugins.plugins.repo.nikto.plugin import NiktoPlugin


def main():
    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_TARGET_URL', 'EXECUTOR_CONFIG_TARGET_PORT']
    url_target = os.environ.get('EXECUTOR_CONFIG_TARGET_URL')
    url_port = os.environ.get('EXECUTOR_CONFIG_TARGET_PORT')
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    with tempfile.TemporaryDirectory() as tempdirname:
        tmpdir = Path(tempdirname)
        name_result = tmpdir / 'output.xml'

        cmd = [
            'nikto',
            '-h', url_target,
            '-o', name_result,
        ]
        if url_port:
            cmd += [
                '-p',
                url_port,
            ]

        nikto_process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if len(nikto_process.stdout) > 0:
            print(
                f"Nikto stdout: {nikto_process.stdout.decode('utf-8')}",
                file=sys.stderr
            )
        if len(nikto_process.stderr) > 0:
            print(
                f"Nikto stderr: {nikto_process.stderr.decode('utf-8')}",
                file=sys.stderr
            )
        plugin = NiktoPlugin()
        with open(name_result, 'r') as f:
            plugin.parseOutputString(f.read())
            print(plugin.get_json())


if __name__ == '__main__':
    main()
