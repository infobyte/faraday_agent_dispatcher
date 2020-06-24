#!/usr/bin/env python
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from faraday_plugins.plugins.repo.wpscan.plugin import WPScanPlugin


def main():
    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_WPSCAN_TARGET_URL']
    url_target = os.environ.get('EXECUTOR_CONFIG_WPSCAN_TARGET_URL')
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    with tempfile.TemporaryDirectory() as tempdirname:
        tempdir = Path(tempdirname)
        name_output_file = 'wpscan-output.json'
        cmd = [
            'docker', 'run',
            '--rm',
            '--mount', f'type=bind,source={tempdirname},target=/output',
            'wpscanteam/wpscan:latest',
            '-o', f'/output/{name_output_file}',
            '--url', url_target,
            '-f', 'json',
        ]

        wpscan_process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if len(wpscan_process.stdout) > 0:
            print(
                f"Wpscan stdout: {wpscan_process.stdout.decode('utf-8')}",
                file=sys.stderr
            )
        if len(wpscan_process.stderr) > 0:
            print(
                f"Wpscan stderr: {wpscan_process.stderr.decode('utf-8')}",
                file=sys.stderr
            )

        plugin = WPScanPlugin()
        out_file = tempdir / name_output_file
        with open(out_file, 'r') as f:
            plugin.parseOutputString(f.read())
            print(plugin.get_json())


if __name__ == '__main__':
    main()
