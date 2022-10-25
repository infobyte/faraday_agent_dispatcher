#!/usr/bin/env python
import os
import sys
import time
import subprocess
import xml.etree.ElementTree as ET
from faraday_plugins.plugins.repo.openvas.plugin import OpenvasPlugin


def main():
    """
    Openvas Port: web: 9392  , openvasmd: 9390
    Openvas Scan takes a while
    """
    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ["EXECUTOR_CONFIG_OPENVAS_USER", "EXECUTOR_CONFIG_OPENVAS_PASSW",
    # "EXECUTOR_CONFIG_OPENVAS_HOST", "EXECUTOR_CONFIG_OPENVAS_PORT",
    # "EXECUTOR_CONFIG_OPENVAS_SCAN_URL", "EXECUTOR_CONFIG_OPENVAS_SCAN_ID"]
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
    user = os.environ.get("EXECUTOR_CONFIG_OPENVAS_USER")
    passw = os.environ.get("EXECUTOR_CONFIG_OPENVAS_PASSW")
    host = os.environ.get("EXECUTOR_CONFIG_OPENVAS_HOST")
    port = os.environ.get("EXECUTOR_CONFIG_OPENVAS_PORT")
    scan_url = os.environ.get("EXECUTOR_CONFIG_OPENVAS_SCAN_URL")
    scan_id = os.environ.get("EXECUTOR_CONFIG_OPENVAS_SCAN_ID")
    xml_format = "a994b278-1f62-11e1-96ac-406186ea4fc5"
    if not user or not passw or not host or not port:
        print(
            "Data config ['Host', 'Port', 'User', 'Passw'] OpenVas not " "provided",
            file=sys.stderr,
        )
        sys.exit()

    if not scan_url:
        print("Scan Url not provided", file=sys.stderr)
        sys.exit()

    if not scan_id:
        # Scan_ID Full and fast
        scan_id = "daba56c8-73ec-11df-a475-002264764cea"

    # Create task and get task_id
    xml_create_task = "<create_target><name>Suspect Host</name><hosts>" f"{scan_url}</hosts></create_target>"
    cmd_create_task = [
        "omp",
        "-u",
        user,
        "-w",
        passw,
        "-h",
        host,
        "-p",
        port,
        "-X",
        xml_create_task,
    ]
    p = subprocess.run(cmd_create_task, stdout=subprocess.PIPE, shell=False)
    task_create = ET.XML(p.stdout)
    task_id = task_create.get("id")
    if task_id is None:
        print("Target Id not found", file=sys.stderr)
        sys.exit()

    # Config and get scan
    cmd_create_scan = [
        "omp",
        "-u",
        user,
        "-w",
        passw,
        "-h",
        host,
        "-p",
        port,
        "-C",
        "-c",
        scan_id,
        "--name",
        '"ScanSuspectHost"',
        "--target",
        task_id,
    ]
    p_scan = subprocess.run(cmd_create_scan, stdout=subprocess.PIPE, shell=False)
    scan = p_scan.stdout.decode().split("\n")

    # Start task get id for use report XML
    cmd_start_scan = [
        "omp",
        "-u",
        user,
        "-w",
        passw,
        "-h",
        host,
        "-p",
        port,
        "-S",
        scan[0],
    ]

    p_start_scan = subprocess.run(cmd_start_scan, stdout=subprocess.PIPE, shell=False)
    id_for_xml = p_start_scan.stdout.decode().split("\n")

    cmd_status = [
        "omp",
        "-u",
        user,
        "-w",
        passw,
        "-h",
        host,
        "-p",
        port,
        "--get-tasks",
        scan[0],
    ]
    status_level = -1
    while status_level <= 0:
        p_status = subprocess.run(cmd_status, stdout=subprocess.PIPE, shell=False)
        status_level = p_status.stdout.decode().find("Done")
        time.sleep(5)

    cmd_get_xml = [
        "omp",
        "-u",
        user,
        "-w",
        passw,
        "-h",
        host,
        "-p",
        port,
        "--get-report",
        id_for_xml[0],
        "--format",
        xml_format,
    ]
    p_xml = subprocess.run(cmd_get_xml, stdout=subprocess.PIPE, shell=False)
    plugin = OpenvasPlugin(
        ignore_info=ignore_info,
        hostname_resolution=hostname_resolution,
        host_tag=host_tag,
        service_tag=service_tag,
        vuln_tag=vuln_tag,
    )
    plugin.parseOutputString(p_xml.stdout)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
