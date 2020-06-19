#!/usr/bin/env python
import os
import sys
import subprocess
from pathlib import Path
from faraday_plugins.plugins.manager import PluginsManager


def main():
    my_envs = os.environ
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['EXECUTOR_CONFIG_NAME_URL', 'ARACHNI_PATH']
    if 'EXECUTOR_CONFIG_NAME_URL' in my_envs:
        url_analyze = os.environ.get('EXECUTOR_CONFIG_NAME_URL')
    else:
        print("Param NAME_URL no passed", file=sys.stderr)
        sys.exit()

    if 'ARACHNI_PATH' in my_envs:
        path_arachni = os.environ.get('ARACHNI_PATH')
    else:
        print("Environment variable ARACHNI_PATH no set", file=sys.stderr)
        sys.exit()

    os.chdir(path_arachni)
    name_result = Path(path_arachni) / 'report.afr'
    cmd = ['./arachni',
            url_analyze,
            '--report-save-path',
            name_result
    ]
    arachni_command = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if len(arachni_command.stdout) > 0:
        print(f"Arachni stdout: {arachni_command.stdout.decode('utf-8')}", file=sys.stderr)
    if len(arachni_command.stderr) > 0:
        print(f"Arachni stderr: {arachni_command.stderr.decode('utf-8')}", file=sys.stderr)

    cmd = [
        './arachni_reporter',
        name_result,
        '--reporter',
        'xml:outfile=xml_arachni_report.xml'
    ]

    arachni_reporter_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if len(arachni_reporter_process.stdout) > 0:
        print(f"Arachni stdout: {arachni_reporter_process.stdout.decode('utf-8')}", file=sys.stderr)
    if len(arachni_reporter_process.stderr) > 0:
        print(f"Arachni stderr: {arachni_reporter_process.stderr.decode('utf-8')}", file=sys.stderr)

    plugin = PluginsManager().get_plugin("arachni")

    with open("xml_arachni_report.xml", 'r') as f:
        plugin.parseOutputString(f.read())
        print(plugin.get_json())

    os.remove(name_result)
    os.remove("xml_arachni_report.xml")


if __name__ == '__main__':
    main()
