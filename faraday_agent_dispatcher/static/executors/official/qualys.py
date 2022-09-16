#!/usr/bin/env python
import os
import sys
import requests
from requests.auth import HTTPBasicAuth
import datetime
import time
from faraday_plugins.plugins.repo.qualysguard.plugin import QualysguardPlugin
import xml.etree.ElementTree as ET
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://qualysguard.qg4.apps.qualys.com"


def log(message):
    print(
        f"{datetime.datetime.utcnow()} - QualysGuard: {message}",
        file=sys.stderr,
    )


def main():
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
    # If the script is run outside the dispatcher
    # the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_TARGET_IP', EXECUTOR_CONFIG_OPTION_PROFILE, 'QUALYS_USERNAME', 'QUALYS_PASSWORD']
    ip = os.getenv("EXECUTOR_CONFIG_TARGET_IP")
    option_profile = os.getenv("EXECUTOR_CONFIG_OPTION_PROFILE")
    username = os.getenv("QUALYS_USERNAME")
    password = os.getenv("QUALYS_PASSWORD")
    if not ip:
        log("Param TARGET_IP no passed")
        sys.exit()
    if not option_profile:
        log("Param OPTION_PROFILE no passed")
        sys.exit()
    if not username:
        log("Environment variable USERNAME no set")
        sys.exit()
    if not password:
        log("Environment variable PASSWORD no set")
        sys.exit()
    auth = HTTPBasicAuth(username, password)
    get_or_create_ip(ip, auth)
    scan_ref = launch_scan(ip, option_profile, auth)
    wait_scan_to_finish(scan_ref, auth)
    log(f"Wait over")
    log(f"{scan_ref}")
    scan_report = get_scan_report(scan_ref, auth)
    log(f"Report Downloaded")

    plugin = QualysguardPlugin(
        ignore_info=ignore_info,
        hostname_resolution=hostname_resolution,
        host_tag=host_tag,
        service_tag=service_tag,
        vuln_tag=vuln_tag,
    )
    plugin.parseOutputString(scan_report)
    log(f"Parcing report")
    log(f"{plugin.get_json()}")
    print(plugin.get_json())


def get_or_create_ip(target, auth):
    url = BASE_URL + "/api/2.0/fo/asset/ip/?action=list"
    ip_response = requests.get(url, verify=False, auth=auth, headers={"X-Requested-With": "Faraday-executor"})
    response_xml = ET.fromstring(ip_response.text)
    ips = response_xml.findall("RESPONSE/IP_SET/IP")
    if len(ips) == 0:
        ips = response_xml.findall("RESPONSE/IP_SET/IP_RANGE")
    for ip in ips:
        if target in ip.text:
            log("ip found")
            return
    else:
        log("ip not found")
        create_ip(target, auth)


def create_ip(target, auth):
    url = BASE_URL + f"/api/2.0/fo/asset/ip/?action=add&ips={target}&enable_vm=1&enable_pc=1"
    requests.post(url, verify=False, auth=auth, headers={"X-Requested-With": "Faraday-executor"})
    log("ip created")


def launch_scan(ip, option_profile, auth):
    url = BASE_URL + f"/api/2.0/fo/scan/?action=launch&scan_title=Faraday-Scan&ip={ip}"
    if option_profile.isdigit():
        url += f"&option_id={option_profile}"
    else:
        url += f"&option_title={option_profile}"
    launch_scan_response = requests.post(
        url, verify=False, auth=auth, headers={"X-Requested-With": "Faraday-executor"}
    )
    log("scan launched")
    response_xml = ET.fromstring(launch_scan_response.text)
    scan_ref = response_xml.findall("RESPONSE/ITEM_LIST/ITEM/VALUE")[-1].text
    return scan_ref


def wait_scan_to_finish(scan_ref, auth):
    url = BASE_URL + f"/api/2.0/fo/scan/?action=list&scan_ref={scan_ref}"
    while True:
        launch_scan_response = requests.get(
            url, verify=False, auth=auth, headers={"X-Requested-With": "Faraday-executor"}
        )
        response_xml = ET.fromstring(launch_scan_response.text)
        scan_status = response_xml.find("RESPONSE/SCAN_LIST/SCAN/STATUS/STATE").text
        if scan_status == "Finished":
            return
        elif not (scan_status in ["Queued", "Running"]):
            log("scan ended with errors")
            sys.exit()
        else:
            log("scan still running")
            time.sleep(180)


def get_scan_report(scan_ref, auth):
    url = BASE_URL + f"/msp/scan_report.php?ref={scan_ref}"
    scan_report = requests.get(url, verify=False, auth=auth, headers={"X-Requested-With": "Faraday-executor"})
    log("Downloading Report")
    return scan_report.text


if __name__ == "__main__":
    main()
