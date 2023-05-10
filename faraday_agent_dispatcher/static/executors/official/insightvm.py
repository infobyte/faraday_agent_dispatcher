#!/usr/bin/env python
import os
import sys
import time

import requests
from requests.auth import HTTPBasicAuth
import datetime
import re
from faraday_plugins.plugins.repo.nexpose_full.plugin import NexposeFullPlugin


def log(message):
    print(
        f"{datetime.datetime.utcnow()} - INSISGHTVM-NEXPOSE: {message}",
        file=sys.stderr,
    )


def main():
    # If the script is run outside the dispatcher
    # the environment variables are checked.
    # ['INSIGHTVM_HOST', 'INSIGHTVM_USR', 'INSIGHTVM_PASSWD', 'EXECUTOR_CONFIG_SITE_ID'
    # or 'EXECUTOR_CONFIG_EXECUTIVE_REPORT_ID']
    ignore_info = os.getenv("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
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
    INSIGHTVM_HOST = os.getenv("INSIGHTVM_HOST")
    INSIGHTVM_USR = os.getenv("INSIGHTVM_USR")
    INSIGHTVM_PASSWD = os.getenv("INSIGHTVM_PASSWD")
    EXECUTIVE_REPORT_ID = os.getenv("EXECUTOR_CONFIG_EXECUTIVE_REPORT_ID")
    SITE_ID = os.getenv("EXECUTOR_CONFIG_SITE_ID")
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
        log(f"INSIGHTVM_HOST is invalid, must be " f"http(s)://HOST(:PORT) [{INSIGHTVM_HOST}]")
        sys.exit(1)

    if SITE_ID:
        scan_id = run_scan(INSIGHTVM_USR, INSIGHTVM_PASSWD, INSIGHTVM_HOST, SITE_ID)
        scan_status = wait_scan(INSIGHTVM_USR, INSIGHTVM_PASSWD, INSIGHTVM_HOST, scan_id)
        if scan_status == "finished":
            report_id = create_and_generate_report(INSIGHTVM_USR, INSIGHTVM_PASSWD, INSIGHTVM_HOST, scan_id)
            report_response_text = get_report(INSIGHTVM_USR, INSIGHTVM_PASSWD, INSIGHTVM_HOST, report_id)
        else:
            log(f"Scan ended with status {scan_status}")
            sys.exit(1)
    elif EXECUTIVE_REPORT_ID:
        report_response_text = get_report(INSIGHTVM_USR, INSIGHTVM_PASSWD, INSIGHTVM_HOST, EXECUTIVE_REPORT_ID)
    else:
        log("site_id or executive_id is required")
        sys.exit(1)
    plugin = NexposeFullPlugin(
        ignore_info=ignore_info,
        hostname_resolution=hostname_resolution,
        host_tag=host_tag,
        service_tag=service_tag,
        vuln_tag=vuln_tag,
    )
    plugin.parseOutputString(report_response_text)
    print(plugin.get_json())


def get_report(user, passwd, host, report_id):
    log(f"Fetching from: {host}")
    report_url = f"{host}/api/3/reports/{report_id}/history/latest/output"
    log(f"Connecting to insightvm on {host}")
    try:
        report_response = requests.get(report_url, verify=False, auth=HTTPBasicAuth(user, passwd), timeout=60)
        if report_response.status_code != 200:
            log(f"API gets no response. " f"Status code: {report_response.status_code}")
            sys.exit()
    except Exception as e:
        log(f"ERROR connecting to insightvm api on {host} [{e}]")
        sys.exit()
    return report_response.text


def run_scan(user, passwd, host, site_id):
    start_scan_url = f"{host}/api/3/sites/{site_id}/scans"
    log("Running new scan")
    try:
        scan_response = requests.post(start_scan_url, verify=False, auth=HTTPBasicAuth(user, passwd), timeout=60)
        if scan_response.status_code != 201:
            log(f"API gets no response. Status code: {scan_response.status_code}")
            sys.exit()
    except Exception as e:
        log(f"ERROR connecting to insightvm api on {host} [{e}]")
        sys.exit()
    return scan_response.json()["id"]


def wait_scan(user, passwd, host, scan_id):
    check_scan_url = f"{host}/api/3/scans/{scan_id}"
    scan_status = "running"
    log(f"Waiting scan {scan_id} to finish")
    while scan_status == "running":
        try:
            scan_status_response = requests.get(
                check_scan_url, verify=False, auth=HTTPBasicAuth(user, passwd), timeout=60
            )
            scan_status = scan_status_response.json()["status"]
            if scan_status_response.status_code != 200:
                log(f"API gets no response. Status code: {scan_status_response.status_code}")
                sys.exit()
        except Exception as e:
            log(f"ERROR connecting to insightvm api on {host} [{e}]")
            sys.exit()
        time.sleep(20)
    return scan_status


def create_and_generate_report(user, passwd, host, scan_id):
    create_report_url = f"{host}/api/3/reports"
    body = {
        "format": "xml-export-v2",
        "filters": {"severity": "all", "statuses": ["vulnerable", "potentially-vulnerable", "vulnerable-version"]},
        "name": f"Report with scan {scan_id}",
        "scope": {"scan": scan_id},
    }
    try:
        log("Creating the report")
        report_create_response = requests.post(
            create_report_url, verify=False, auth=HTTPBasicAuth(user, passwd), json=body, timeout=60
        )
        if report_create_response.status_code != 201:
            log(f"Couldnt create report, Status codae {report_create_response.status_code}")
            sys.exit()
        else:
            report_id = report_create_response.json()["id"]
            log(report_create_response.json())
            generate_report_url = f"{host}/api/3/reports/{report_id}/generate"
            report_generate_response = requests.post(
                generate_report_url, verify=False, auth=HTTPBasicAuth(user, passwd), timeout=60
            )
            if report_generate_response.status_code != 200:
                log(f"Couldnt create report, Status code {report_generate_response.status_code}")
                sys.exit()
            # Wait till the report is generated
            time.sleep(60)
            return report_id
    except Exception as e:
        log(f"ERROR connecting to insightvm api on {host} [{e}]")
        sys.exit()


if __name__ == "__main__":
    main()
