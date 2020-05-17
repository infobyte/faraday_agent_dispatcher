#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.manager import PluginsManager
import time
from zapv2 import ZAPv2
import subprocess
import tempfile


def run_zap_proxy(path):
    pid = subprocess.Popen(path, shell=True).pid
    return pid


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['API_KEY', 'EXECUTOR_CONFIG_TARGET_URL', 'ZAP_PATH']
    try:
        target = os.environ.get('EXECUTOR_CONFIG_TARGET_URL')
        api_key = os.environ.get('API_KEY')
    except KeyError:
        print("environment variable not found", file=sys.stderr)
        sys.exit()

    my_env = os.environ
    if 'ZAP_PATH' in my_env:
        path = my_env["ZAP_PATH"]
        pid_zap = run_zap_proxy(path)

        if pid_zap == 0:
            print("Zap Proxy not found", file=sys.stderr)
            sys.exit()
        else:
            zap = ZAPv2(apikey=api_key)
            scanID = zap.spider.scan(target)
            while int(zap.spider.status(scanID)) < 100:
                time.sleep(1)

            ft = tempfile.TemporaryFile('w+t')
            ft.write(zap.core.xmlreport())
            ft.seek(0)
            zap.core.shutdown()
            plugin = PluginsManager().get_plugin("zap")
            plugin.parseOutputString(ft.read())
            ft.close()
            print(plugin.get_json())
    else:
        print("ZAP environment variable not found", file=sys.stderr)
        sys.exit()


if __name__ == '__main__':
    main()