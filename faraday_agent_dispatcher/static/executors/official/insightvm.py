#!/usr/bin/env python
import os
import sys
import tempfile
import requests
from requests.auth import HTTPBasicAuth
import time
import datetime
import socket
import re
import xml.etree.cElementTree as ET
from urllib.parse import urlparse
from faraday_plugins.plugins.repo.nexpose_full.plugin import NexposeFullPlugin
from faraday_plugins.plugins.repo.nexpose_full.plugin import NexposeFullXmlParser




def log(message):
    print(f"{datetime.datetime.utcnow()} - INSISGHTVM-NEXPOSE: {message}", file=sys.stderr)



def main():
    # If the script is run outside the dispatcher
    # the environment variables are checked.
    # ['TARGET_URL', 'EXECUTIVE_REPORT_ID']
    INSIGHTVM_HOST = os.getenv("INSIGHTVM_HOST")
    INSIGHTVM_USR = os.getenv("INSIGHTVM_USR")
    INSIGHTVM_PASSWD = os.getenv("INSIGHTVM_PASSWD")
    EXECUTIVE_REPORT_ID = os.getenv("EXECUTOR_CONFIG_EXECUTIVE_REPORT_ID")
    host_re = re.compile(r"^https?://.+:\d+$")

    if not INSIGHTVM_USR:
        log("INSIGHTVM_USR not provided")
        sys.exit(1)

    if not INSIGHTVM_PASSWD:
        log("INSIGHTVM_PASSWD not provided")
        sys.exit(1)

    if not EXECUTIVE_REPORT_ID:
        EXECUTIVE_REPORT_ID = "00000000"

    if not INSIGHTVM_HOST:
        log("INSIGHTVM_HOST not provided")
        sys.exit(1)

    if not host_re.match(INSIGHTVM_HOST):
        log(f"INSIGHTVM_HOST is invalid, must be http(s)://HOST:PORT [{INSIGHTVM_HOST}]")
        sys.exit(1)
    # handling multiple targets, can be provided with: "https://example.com, https://test.com"
    target = INSIGHTVM_HOST

    if target:
        log(f"Fetching {target} with insightvm on: {INSIGHTVM_HOST}")
        report_xml = f"{INSIGHTVM_HOST}/api/3/reports/{EXECUTIVE_REPORT_ID}/history/latest/output"
        log(f"Connecting to insightvm on {INSIGHTVM_HOST}")
        try:
            rg_report_xml = requests.get(report_xml, verify=False, auth=HTTPBasicAuth(INSIGHTVM_USR,INSIGHTVM_PASSWD))
            if rg_report_xml.status_code != 200:
                log(f"API gets no response. Status code: {rg_report_xml.status_code}")
                sys.exit()
        except Exception as e:
            log(f"ERROR connecting to insightvm api on {INSIGHTVM_HOST} [{e}]")
            sys.exit()
        plugin = NexposeFullPlugin()
        plugin.parseOutputString(rg_report_xml.text)
        print(plugin.get_json())
        
    else:
        log("Nothing to display.")
        sys.exit(1)


if __name__ == "__main__":
    main()
