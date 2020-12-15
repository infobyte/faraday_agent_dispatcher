#!/usr/bin/env python
import os
import sys
import time
import subprocess
import xml.etree.ElementTree as ET
from faraday_plugins.plugins.repo.openvas.plugin import OpenvasPlugin


def main():
    user = os.environ.get("EXECUTOR_CONFIG_USER")
    passw = os.environ.get("EXECUTOR_CONFIG_PASSW")
    host = os.environ.get("EXECUTOR_CONFIG_HOST")
    port = os.environ.get("EXECUTOR_CONFIG_PORT")
    connection_type = os.environ.get("EXECUTOR_CONFIG_CONNECTION_TYPE")
    scan_url = os.environ.get("EXECUTOR_CONFIG_SCAN_URL")
    scan_id = os.environ.get("EXECUTOR_CONFIG_SCAN_ID")
    port_list = os.environ.get("EXECUTOR_CONFIG_PORT_LIST_ID")
    xml_format = "a994b278-1f62-11e1-96ac-406186ea4fc5"
    if not user or not passw or not connection_type:
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

    if not port_list:
        # Port List: All IANA assigned TCP
        port_list = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

    # Create task and get task_id
    xml_create_task = f"<create_target><name>Suspect Host</name><port_list id='{port_list}' /><hosts>{scan_url}</hosts></create_target>"
    cmd_create_task = [
        "gvm-cli",
        "--gmp-username",
        user,
        "--gmp-password",
        passw,
        connection_type,
        "--xml",
        xml_create_task,
    ]
    p = subprocess.run(cmd_create_task, stdout=subprocess.PIPE, shell=False)
    task_create = ET.XML(p.stdout)
    task_id = task_create.get("id")
    if task_id is None:
        print("Target Id not found", file=sys.stderr)
        sys.exit()

    xml_create_scan = f"<create_task><name>Scan Suspect Host</name> \
<target id=\"{task_id}\"></target> \
<config id=\"{scan_id}\"></config></create_task>"
    # Config and get scan
    cmd_create_scan = [
        "gvm-cli",
        "--gmp-username",
        user,
        "--gmp-password",
        passw,
        connection_type,
        "--xml",
        xml_create_scan
    ]
    p_scan = subprocess.run(cmd_create_scan, stdout=subprocess.PIPE, shell=False)
    scan_create = ET.XML(p_scan.stdout)
    scan_id = scan_create.get("id")
    # scan = p_scan.stdout.decode().split("\n")

    xml_run_task = f"<start_task task_id='{scan_id}'/>"

    # Start task get id for use report XML
    cmd_start_scan = [
        "gvm-cli",
        "--gmp-username",
        user,
        "--gmp-password",
        passw,
        connection_type,
        "--xml",
        xml_run_task
    ]

    p_start_scan = subprocess.run(cmd_start_scan, stdout=subprocess.PIPE, shell=False)
    scan_start = ET.XML(p_start_scan.stdout)
    report_id = scan_start.find("report_id").text
    # id_for_xml = p_start_scan.stdout.decode().split("\n")

    xml_check_scan = f'<get_tasks task_id="{scan_id}"/>'

    cmd_status = [
        "gvm-cli",
        "--gmp-username",
        user,
        "--gmp-password",
        passw,
        connection_type,
        "--xml",
        xml_check_scan
    ]
    status_level = -1
    while status_level <= 0:
        p_status = subprocess.run(cmd_status, stdout=subprocess.PIPE, shell=False)
        status_level = p_status.stdout.decode().find("Done")
        time.sleep(5)

    xml_get_report = f'<get_reports report_id="{report_id}" format_id="{xml_format}"/>'

    cmd_get_xml = [
        "gvm-cli",
        "--gmp-username",
        user,
        "--gmp-password",
        passw,
        connection_type,
        "--xml",
        xml_get_report
    ]
    p_xml = subprocess.run(cmd_get_xml, stdout=subprocess.PIPE, shell=False)
    plugin = OpenvasPlugin()
    plugin.parseOutputString(p_xml.stdout)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
