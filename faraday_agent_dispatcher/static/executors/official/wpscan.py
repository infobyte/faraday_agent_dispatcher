#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.repo.wpscan.plugin import WPScanPlugin
import subprocess
import tempfile
from subprocess import Popen, PIPE


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['EXECUTOR_CONFIG_WPSCAN_TARGET_URL']
    url_target = os.environ.get('EXECUTOR_CONFIG_WPSCAN_TARGET_URL')
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    p = Popen(['docker', 'images'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate(b"input data that is passed to subprocess' stdin")
    if str(output).find('wpscanteam/wpscan') >= 0:
        with tempfile.TemporaryDirectory() as tempdirname:
            name_output_file = 'wpscan-output.json'
            command = f'docker run --rm --mount type=bind,source={tempdirname},target=/output ' \
                      f'wpscanteam/wpscan:latest -o /output/{name_output_file} --url {url_target} -f json'

            wpscan_proccess = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"Wpscan stdout: {wpscan_proccess.stdout.decode('utf-8')}", file=sys.stderr)
            print(f"Wpscan stderr: {wpscan_proccess.stderr.decode('utf-8')}", file=sys.stderr)

            plugin = WPScanPlugin()
            f = open(f'{tempdirname}/{name_output_file}', 'r')
            f.seek(0)
            plugin.parseOutputString(f.read())
            print(plugin.get_json())
    else:
        print("Docker image is not found", file=sys.stderr)
        sys.exit()


if __name__ == '__main__':
    main()
