#!/usr/bin/env python
import os
import sys
import time
import psutil
from zapv2 import ZAPv2
from faraday_plugins.plugins.repo.zap.plugin import ZapPlugin

# Import the centralized agent configuration utility
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
try:
    from utils.agent_configuration import get_common_parameters

    USE_COMMON_PARAMS = True
except ImportError:
    USE_COMMON_PARAMS = False


def main():
    # Get centralized agent configuration if available, otherwise use manual parsing
    if USE_COMMON_PARAMS:
        agent_config = get_common_parameters()
    else:
        # Manual parsing for backwards compatibility
        ignore_info = os.getenv("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
        min_severity = os.getenv("AGENT_CONFIG_MIN_SEVERITY", None)
        max_severity = os.getenv("AGENT_CONFIG_MAX_SEVERITY", None)
        hostname_resolution = os.getenv("AGENT_CONFIG_RESOLVE_HOSTNAME", "True").lower() == "true"
        vuln_tag = os.getenv("AGENT_CONFIG_VULN_TAG", None)
        if vuln_tag:
            vuln_tag = vuln_tag.split(",")
        service_tag = os.getenv("AGENT_CONFIG_SERVICE_TAG", None)
        if service_tag:
            service_tag = service_tag.split(",")
        host_tag = os.getenv("AGENT_CONFIG_HOSTNAME_TAG", None)
        if host_tag:
            host_tag = host_tag.split(",")

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

        if USE_COMMON_PARAMS:
            plugin = ZapPlugin(**agent_config.to_plugin_kwargs())
        else:
            plugin = ZapPlugin(
                ignore_info=ignore_info,
                min_severity=min_severity,
                max_severity=max_severity,
                hostname_resolution=hostname_resolution,
                host_tag=host_tag,
                service_tag=service_tag,
                vuln_tag=vuln_tag,
            )
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
