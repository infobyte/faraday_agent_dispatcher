#!/usr/bin/env python
import os
from faraday_plugins.plugins.manager import PluginsManager
import sys
import tempfile
import time



def main():
    my_envs = os.environ
    if 'EXECUTOR_CONFIG_NAME_URL' in my_envs:
        url_analyze = os.environ.get('EXECUTOR_CONFIG_NAME_URL')
    else:
        print("Environment variables no set", file=sys.stderr)
        sys.exit()

    if 'RUN_ARACHNI' in my_envs:
        path_arachni = os.environ.get('RUN_ARACHNI')
    else:
        print("Environment variables no set", file=sys.stderr)
        sys.exit()

    os.chdir(path_arachni)
    with tempfile.TemporaryDirectory() as tempdirname:
        name_result = f'{tempdirname}/report.afr'
        xml_result = f'{tempdirname}/xml_arachni_report.xml'
        os.system(f'./arachni {url_analyze} --report-save-path={name_result}')
        os.system(f'./arachni_reporter {name_result} --reporter=xml:outfile={xml_result}')
        plugin = PluginsManager().get_plugin("arachni")
        plugin.parseOutputString(xml_result)
        print(plugin.get_json())


if __name__ == '__main__':
    main()

