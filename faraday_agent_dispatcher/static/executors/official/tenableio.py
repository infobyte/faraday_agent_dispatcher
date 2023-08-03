import os
import sys
import time
import re

from tenable.io import TenableIO
from faraday_plugins.plugins.repo.nessus.plugin import NessusPlugin

from faraday_agent_dispatcher.utils.url_utils import resolve_hostname

HTTP_REGEX = re.compile("^(http|https)://")


def log(msg):
    print(msg, file=sys.stderr)


def search_scan_id(tio, TENABLE_SCAN_ID):
    scans = tio.scans.list()
    scans_id = ""
    for scan in scans:
        scans_id += f"{scan['id']} {scan['name']}\n"
        if str(scan["id"]) == str(TENABLE_SCAN_ID):
            log(
                f"Scan found: {scan['name']}",
            )
            break
    else:
        log(
            f"Scan id {TENABLE_SCAN_ID} not found, the current scans available are: {scans_id}",
        )
        exit(1)
    return scan


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

    TENABLE_SCAN_NAME = os.getenv("EXECUTOR_CONFIG_TENABLE_SCAN_NAME", "faraday-scan")
    TENABLE_SCANNER_NAME = os.getenv("EXECUTOR_CONFIG_TENABLE_SCANNER_NAME")
    TENABLE_SCAN_ID = os.getenv("EXECUTOR_CONFIG_TENABLE_SCAN_ID")
    TENABLE_RELAUNCH_SCAN = os.getenv("EXECUTOR_CONFIG_RELAUNCH_SCAN", "False").lower() == "true"
    TENABLE_SCAN_TARGET = os.getenv("EXECUTOR_CONFIG_TENABLE_SCAN_TARGET")
    TENABLE_SCAN_TEMPLATE = os.getenv(
        "EXECUTOR_CONFIG_TENABLE_SCAN_TEMPLATE",
        "basic",
    )
    TENABLE_PULL_INTERVAL = os.getenv("TENABLE_PULL_INTERVAL", 30)
    TENABLE_ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
    TENABLE_SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")
    if not (TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY):
        log("TenableIo access_key and secret_key were not provided")
        exit(1)
    tio = TenableIO(TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY)
    if TENABLE_SCAN_ID and not TENABLE_RELAUNCH_SCAN:
        scan = search_scan_id(tio, TENABLE_SCAN_ID)
        report = tio.scans.export(scan["id"])
        plugin = NessusPlugin(
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
        )
        plugin.parseOutputString(report.read())
        print(plugin.get_json())
        return
    if TENABLE_SCAN_ID:
        scan = search_scan_id(tio, TENABLE_SCAN_ID)
    else:
        if HTTP_REGEX.match(TENABLE_SCAN_TARGET):
            target = re.sub(HTTP_REGEX, "", TENABLE_SCAN_TARGET)
        else:
            target = TENABLE_SCAN_TARGET
        target_ip = resolve_hostname(target)
        log(f"The target ip is {target_ip}")
        if TENABLE_SCANNER_NAME:
            scan = tio.scans.create(
                name=TENABLE_SCAN_NAME,
                targets=[target_ip],
                template=TENABLE_SCAN_TEMPLATE,
                scanner=TENABLE_SCANNER_NAME,
            )
        else:
            scan = tio.scans.create(
                name=TENABLE_SCAN_NAME,
                targets=[target_ip],
                template=TENABLE_SCAN_TEMPLATE,
            )
    tio.scans.launch(scan["id"])
    status = "pending"
    while status[-2:] != "ed":
        time.sleep(int(TENABLE_PULL_INTERVAL))
        status = tio.scans.status(scan["id"])
    if status != "completed":
        log(f"Scanner ended with status {status}")
        exit(1)
    report = tio.scans.export(scan["id"])
    plugin = NessusPlugin(
        ignore_info=ignore_info,
        hostname_resolution=hostname_resolution,
        host_tag=host_tag,
        service_tag=service_tag,
        vuln_tag=vuln_tag,
    )
    plugin.parseOutputString(report.read())
    print(plugin.get_json())


if __name__ == "__main__":
    main()
