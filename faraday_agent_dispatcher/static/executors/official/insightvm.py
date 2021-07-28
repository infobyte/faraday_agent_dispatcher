#!/usr/bin/env python
import os
import sys
import requests
from requests.auth import HTTPBasicAuth
import datetime
import re
from faraday_plugins.plugins.repo.nexpose_full.plugin import NexposeFullPlugin


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

    if not INSIGHTVM_HOST:
        log("INSIGHTVM_HOST not provided")
        sys.exit(1)

    if not host_re.match(INSIGHTVM_HOST):
        log(f"INSIGHTVM_HOST is invalid, must be http(s)://HOST(:PORT) [{INSIGHTVM_HOST}]")
        sys.exit(1)
    log(f"Fetching from: {INSIGHTVM_HOST}")
    report_url = f"{INSIGHTVM_HOST}/api/3/reports/{EXECUTIVE_REPORT_ID}/history/latest/output"
    log(f"Connecting to insightvm on {INSIGHTVM_HOST}")
    try:
        report_response = requests.get(report_url, verify=False, auth=HTTPBasicAuth(INSIGHTVM_USR, INSIGHTVM_PASSWD))
        if report_response.status_code != 200:
            log(f"API gets no response. Status code: {report_response.status_code}")
            sys.exit()
    except Exception as e:
        log(f"ERROR connecting to insightvm api on {INSIGHTVM_HOST} [{e}]")
        sys.exit()
    plugin = NexposeFullPlugin()
    plugin.parseOutputString(report_response.text)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
