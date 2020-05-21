#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.manager import PluginsManager
import time
from zapv2 import ZAPv2
import tempfile


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['API_KEY', 'EXECUTOR_CONFIG_TARGET_URL', 'ZAP_PATH']
    try:
        target = os.environ['EXECUTOR_CONFIG_TARGET_URL']
        api_key = os.environ['API_KEY']
    except KeyError:
        print("environment variable not found", file=sys.stderr)
        sys.exit()

    # Chequear que este levantado, sino exitear de manera feliz

    my_env = os.environ
    zap = ZAPv2(apikey=api_key)
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        time.sleep(1)

    with tempfile.TemporaryFile('w+t') as ft:
        ft.write(zap.core.xmlreport())
        zap.core.shutdown()
        plugin = PluginsManager().get_plugin("zap")
        plugin.parseOutputString(ft.read())
        print(plugin.get_json())


if __name__ == '__main__':
    main()
