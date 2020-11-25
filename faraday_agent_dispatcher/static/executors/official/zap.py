#!/usr/bin/env python
import os
import sys
import time
import subprocess
from zapv2 import ZAPv2
from faraday_plugins.plugins.manager import PluginsManager


def main():
    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_API_KEY', 'EXECUTOR_CONFIG_TARGET_URL']
    try:
        target = os.environ["EXECUTOR_CONFIG_TARGET_URL"]
        api_key = os.environ["EXECUTOR_CONFIG_API_KEY"]
    except KeyError:
        print("environment variable not found", file=sys.stderr)
        sys.exit()

    # zap is required to be started
    zap_run = subprocess.check_output("pgrep -f zap", shell=True)

    if len(zap_run.decode("utf-8").split("\n")) > 3:
        # the apikey from ZAP->Tools->Options-API
        zap = ZAPv2(apikey=api_key)
        # it passes the url to scan and starts
        scanID = zap.spider.scan(target)
        # Wait for the scan to finish
        while int(zap.spider.status(scanID)) < 100:
            time.sleep(1)
        # If finish the scan and the xml is generated
        zap_result = zap.core.xmlreport()
        plugin = PluginsManager().get_plugin("zap")
        plugin.parseOutputString(zap_result)
        print(plugin.get_json())

    else:
        print("ZAP not running", file=sys.stderr)
        sys.exit()


if __name__ == "__main__":
    main()
