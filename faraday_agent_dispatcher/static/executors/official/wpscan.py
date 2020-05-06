#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.repo.wpscan.plugin import WPScanPlugin
import subprocess
import tempfile
from subprocess import Popen, PIPE


def main():
    # Se esta usando la imagen de docker.
    # docker pull wpscanteam/wpscan
    url_target = os.environ.get('EXECUTOR_CONFIG_WPSCAN_TARGET_URL')
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    p = Popen(['sudo', 'docker', 'images'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate(b"input data that is passed to subprocess' stdin")
    if str(output).find('wpscanteam/wpscan') >= 0:
        with tempfile.TemporaryDirectory() as tempdirname:
            name_ouput_file = 'wpscan-output.json'
            command = f'sudo docker run --rm --mount type=bind,source={tempdirname},target=/output ' \
                      f'wpscanteam/wpscan:latest -o /output/{name_ouput_file} --url {url_target} -f json'

            subprocess.run(command, shell=True)
            plugin = WPScanPlugin()
            f = open(f'{tempdirname}/{name_ouput_file}', 'r')
            f.seek(0)
            plugin.parseOutputString(f.read())
            print(plugin.get_json())
    else:
        print("Docker image is not found", file=sys.stderr)
        sys.exit()


if __name__ == '__main__':
    main()
