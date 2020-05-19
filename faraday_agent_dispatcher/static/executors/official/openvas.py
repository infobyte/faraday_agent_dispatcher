#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.repo.openvas.plugin import OpenvasPlugin
import subprocess
import tempfile
from pathlib import Path


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['EXECUTOR_CONFIG_OPENVAS_SCAN_NAME']
    #url_target = os.environ.get('EXECUTOR_CONFIG_OPENVAS_SCAN_NAME')
    url_target = 'http://pidgr.com/'
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    with tempfile.TemporaryDirectory() as tempdirname:
        tempdir = Path(tempdirname)
        command = f'sudo docker run --rm -v $(pwd):/openvas/results/ ictu/openvas-docker ' \
                  f'/openvas/run_scan.py 123.123.123.123,{url_target} openvas_scan_report'

        openvas_process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if len(openvas_process.stdout) > 0:
            print(f"Openvas stdout: {openvas_process.stdout.decode('utf-8')}", file=sys.stderr)
        if len(openvas_process.stderr) > 0:
            print(f"Openvas stderr: {openvas_process.stderr.decode('utf-8')}", file=sys.stderr)
        plugin = OpenvasPlugin()
        name_xml = tempdir / 'openvas_scan_report.xml'
        if name_xml.exists():
            with open(name_xml, 'r') as f:
                plugin.parseOutputString(f.read())
                print(plugin.get_json())
        else:
            print("File no exists", file=sys.stderr)
            sys.exit()


if __name__ == '__main__':
    main()
