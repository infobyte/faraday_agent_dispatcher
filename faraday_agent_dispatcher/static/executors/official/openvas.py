#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.repo.openvas.plugin import OpenvasPlugin
import subprocess
import tempfile
from subprocess import Popen, PIPE
from pathlib import Path


def main():
    # Imagen Docker
    # https://hub.docker.com/r/ictu/openvas-docker
    url_target = os.environ.get('EXECUTOR_CONFIG_OPENVAS_TARGET_URL')
    if not url_target:
        print("git URL not provided", file=sys.stderr)
        sys.exit()

    p = Popen(['sudo', 'docker', 'images'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate(b"input data that is passed to subprocess' stdin")
    if str(output).find('ictu/openvas-docker') >= 0:
        with tempfile.TemporaryDirectory() as tempdirname:
            command = f'docker run --rm -v {tempdirname}:/openvas/results/ ictu/openvas-docker ' \
                      f'/openvas/run_scan.py 123.123.123.123,{url_target} openvas_scan_report'
            subprocess.run(command, shell=True)
            plugin = OpenvasPlugin()
            name_xml = Path(tempdirname) / 'openvas_scan_report.xml'
            if name_xml.exists():
                f = open(name_xml, 'r')
                f.seek(0)
                plugin.parseOutputString(f.read())
                print(plugin.get_json())
            else:
                print("File no exists", file=sys.stderr)
                sys.exit()

    else:
        print("Docker image is not found", file=sys.stderr)
        sys.exit()


if __name__ == '__main__':
    main()
