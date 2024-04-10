import os
import sys
import time
import zipfile as zp
from urllib.parse import urlparse
from tenable.sc import TenableSC
from faraday_plugins.plugins.repo.nessus_sc.plugin import NessusScPlugin

from faraday_agent_dispatcher.utils.url_utils import resolve_hostname


def log(msg):
    print(msg, file=sys.stderr)


def search_scan_id(tio, TENABLE_SCAN_ID):
    scans = tio.scan_instances.list()
    scans_id = ""
    for scan in scans["usable"]:
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
    TENABLE_SCAN_TARGETS = os.getenv("EXECUTOR_CONFIG_TENABLE_SCAN_TARGETS")
    TENABLE_SCAN_REPO = os.getenv("EXECUTOR_CONFIG_TENABLE_SCAN_REPO")
    TENABLE_SCAN_TEMPLATE = os.getenv(
        "EXECUTOR_CONFIG_TENABLE_SCAN_TEMPLATE",
        "basic",
    )
    TENABLE_PULL_INTERVAL = os.getenv("TENABLE_PULL_INTERVAL", 30)
    TENABLE_ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
    TENABLE_SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")
    TENABLE_URL = os.getenv("TENABLE_URL")
    if not (TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY):
        log("TenableIo access_key and secret_key were not provided")
        exit(1)

    # if not TENABLE_SCAN_TARGETS:
    #     log("Scan Target were not provided")
    #     exit(1)
    if not TENABLE_URL:
        log("Tenable Url not provided")
        exit(1)
    targets = []
    if TENABLE_SCAN_TARGETS:
        for target in TENABLE_SCAN_TARGETS.split(","):
            parse_target = urlparse(target)
            if parse_target.netloc:
                targets.append(resolve_hostname(parse_target.netloc))
            else:
                targets.append(resolve_hostname(target))
    log(f"Targets ip {targets}")
    tsc = TenableSC(host=TENABLE_URL, access_key=TENABLE_ACCESS_KEY, secret_key=TENABLE_SECRET_KEY)
    if TENABLE_SCAN_ID:
        scan = search_scan_id(tsc, TENABLE_SCAN_ID)
        report = tsc.scan_instances.export_scan(scan["id"])
        with zp.ZipFile(report.read(), "r") as zip_ref:
            file_name = zip_ref.namelist()[0]
            with zip_ref.open(file_name):
                plugin = NessusScPlugin(
                    ignore_info=ignore_info,
                    hostname_resolution=hostname_resolution,
                    host_tag=host_tag,
                    service_tag=service_tag,
                    vuln_tag=vuln_tag,
                )
                plugin.parseOutputString(file_name)
        return
    elif TENABLE_SCANNER_NAME:
        scan = tsc.scans.create(
            name=TENABLE_SCAN_NAME,
            repo=TENABLE_SCAN_REPO,
            targets=targets,
            template=TENABLE_SCAN_TEMPLATE,
            scanner=TENABLE_SCANNER_NAME,
        )
    else:
        scan = tsc.scans.create(
            name=TENABLE_SCAN_NAME, repo=TENABLE_SCAN_REPO, targets=targets, template=TENABLE_SCAN_TEMPLATE
        )
    tsc.scans.launch(scan["id"])
    status = "pending"
    while status[-2:] != "ed":
        time.sleep(int(TENABLE_PULL_INTERVAL))
        status = tsc.scans.status(scan["id"])
    if status != "completed":
        log(f"Scanner ended with status {status}")
        exit(1)
    report = tsc.scans.export(scan["id"])
    plugin = NessusScPlugin(
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
