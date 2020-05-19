#!/usr/bin/env python
import os
from faraday_plugins.plugins.manager import PluginsManager
import sys
import tempfile
import subprocess


def main():
    my_envs = os.environ
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['EXECUTOR_CONFIG_NAME_URL', 'ARACHNI_PATH']
    if 'EXECUTOR_CONFIG_NAME_URL' in my_envs:
        url_analyze = os.environ.get('EXECUTOR_CONFIG_NAME_URL')
    else:
        print("Environment variables no set", file=sys.stderr)
        sys.exit()

    if 'ARACHNI_PATH' in my_envs:
        path_arachni = os.environ.get('ARACHNI_PATH')
    else:
        print("Environment variables no set", file=sys.stderr)
        sys.exit()

    os.chdir(path_arachni)
    with tempfile.TemporaryDirectory() as tempdirname:
        name_result = f'{tempdirname}/report.afr'
        xml_result = f'{tempdirname}/xml_arachni_report.xml'
        arachni_process = subprocess.Popen([f'./arachni {url_analyze} --report-save-path={name_result}'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = arachni_process.communicate()
        print(f"Arachni stdout: {out}", file=sys.stderr)
        print(f"Arachni stderr: {err}", file=sys.stderr)

        arachni_reporter_process = subprocess.Popen([f'./arachni_reporter {name_result} '
                                                     f'--reporter=xml:outfile={xml_result}'],
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = arachni_reporter_process.communicate()
        print(f"Arachni Reporter stdout: {out}", file=sys.stderr)
        print(f"Arachni Reporter stderr: {err}", file=sys.stderr)
        plugin = PluginsManager().get_plugin("arachni")
        plugin.parseOutputString(xml_result)
        print(plugin.get_json())


if __name__ == '__main__':
    main()