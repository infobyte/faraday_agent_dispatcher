#!/usr/bin/env python
import os
import sys
import time
import subprocess
import tempfile
from zapv2 import ZAPv2
from faraday_plugins.plugins.manager import PluginsManager


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['EXECUTOR_CONFIG_API_KEY', 'EXECUTOR_CONFIG_TARGET_URL']
    try:
        target = os.environ['EXECUTOR_CONFIG_TARGET_URL']
        api_key = os.environ['EXECUTOR_CONFIG_API_KEY']
    except KeyError:
        print("environment variable not found", file=sys.stderr)
        sys.exit()

    zap_run = subprocess.check_output('pgrep -f zap', shell=True)

    if len(zap_run.decode('utf-8').split('\n')) > 3:
        zap = ZAPv2(apikey=api_key)
        scanID = zap.spider.scan(target)
        while int(zap.spider.status(scanID)) < 100:
            time.sleep(1)

        with tempfile.TemporaryFile('w+t') as f:
            f.write(zap.core.xmlreport())
            f.seek(0)
            plugin = PluginsManager().get_plugin("zap")
            plugin.parseOutputString(f.read())
            print(plugin.get_json())

    else:
        print("ZAP not running", file=sys.stderr)
        sys.exit()


if __name__ == '__main__':
    main()
