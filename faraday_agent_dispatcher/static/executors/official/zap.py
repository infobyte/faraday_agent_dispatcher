#!/usr/bin/env python
import os
import sys
import time
import psutil
from zapv2 import ZAPv2
from faraday_plugins.plugins.repo.zap.plugin import ZapPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def main():
    agent_config = get_common_parameters()

    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['ZAP_API_KEY', 'EXECUTOR_CONFIG_TARGET_URL']
    try:
        target = os.environ["EXECUTOR_CONFIG_TARGET_URL"]
        api_key = os.environ["ZAP_API_KEY"]
    except KeyError:
        print("environment variable not found", file=sys.stderr)
        sys.exit()

    # zap is required to be started
    if zap_is_running():
        # the apikey from ZAP->Tools->Options-API
        zap = ZAPv2(apikey=api_key)
        # it passes the url to scan and starts
        scanID = zap.spider.scan(target)
        # Wait for the scan to finish
        while int(zap.spider.status(scanID)) < 100:
            time.sleep(1)
        # If finish the scan and the xml is generated
        zap_result = zap.core.xmlreport()

        plugin = ZapPlugin(**agent_config.to_plugin_kwargs())
        plugin.parseOutputString(zap_result)
        print(plugin.get_json())

    else:
        print("ZAP not running", file=sys.stderr)
        sys.exit()


def zap_is_running():
    try:
        for proc in psutil.process_iter():
            if ("zap" in proc.cmdline()[-1]) if len(proc.cmdline()) > 0 else False:
                return True
    finally:
        return False


if __name__ == "__main__":
    main()
