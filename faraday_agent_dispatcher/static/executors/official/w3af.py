#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.manager import PluginsManager
import subprocess
import tempfile


def main():
    url_target = os.environ.get('EXECUTOR_CONFIG_W3AF_TARGET_URL')
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    if 'W3AF_PATH' in os.environ:
        with tempfile.TemporaryDirectory() as tempdirname:
            name_result = f'{tempdirname}/config_report_file.w3af'
            file_w3af = open(name_result, "w")
            command_text = f'plugins\n output console,xml_file\n output\n output config xml_file\n ' \
                           f'set output_file {tempdirname}/output-w3af.xml\n set verbose True\n back\n ' \
                           f'output config console\n set verbose False\n back\n crawl all, !bing_spider, !google_spider,' \
                           f' !spider_man\n crawl\n grep all\n grep\n audit all\n audit\n bruteforce all\n bruteforce\n ' \
                           f'back\n target\n set target {url_target}\n back\n start\n exit'

            file_w3af.write(command_text)
            file_w3af.close()
            try:
                os.chdir(path=os.environ.get('W3AF_PATH'))
            except FileNotFoundError:
                print("No such file or directory", file=sys.stderr)
                sys.exit()

            subprocess.run(f'./w3af_console -s {name_result}', shell=True)
            plugin = PluginsManager().get_plugin("w3af")
            plugin.parseOutputString(f'{tempdirname}/output-w3af.xml')
            print(plugin.get_json())

    else:
        print("W3AF_PATH not set", file=sys.stderr)
        sys.exit()


if __name__ == '__main__':
    main()