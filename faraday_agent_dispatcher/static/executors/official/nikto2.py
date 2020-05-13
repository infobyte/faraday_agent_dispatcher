#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.repo.nikto.plugin import NiktoPlugin
import subprocess
import tempfile


def main():
    url_target = os.environ.get('EXECUTOR_CONFIG_TARGET_URL')
    url_port = os.environ.get('EXECUTOR_CONFIG_TARGET_PORT')
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    with tempfile.TemporaryDirectory() as tempdirname:
        name_result = f'{tempdirname}/output.xml'
        if not url_port:
            command = f'nikto -h {url_target} -o {name_result}'
        else:
            command = f'nikto -h {url_target} -p {url_port} -o {name_result}'

        subprocess.run(command, shell=True)
        plugin = NiktoPlugin()
        f = open(name_result, 'r')
        f.seek(0)
        plugin.parseOutputString(f.read())
        print(plugin.get_json())


if __name__ == '__main__':
    main()
