#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.repo.openvas.plugin import OpenvasPlugin
import subprocess
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET
import time


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ["EXECUTOR_CONFIG_OPENVAS_USER", "EXECUTOR_CONFIG_OPENVAS_PASSW",
    # "EXECUTOR_CONFIG_OPENVAS_HOST", "EXECUTOR_CONFIG_OPENVAS_PORT",
    # "EXECUTOR_CONFIG_OPENVAS_SCAN_URL", "EXECUTOR_CONFIG_OPENVAS_SCAN_ID"]
    user = os.environ.get('EXECUTOR_CONFIG_OPENVAS_USER')
    passw = os.environ.get('EXECUTOR_CONFIG_OPENVAS_PASSW')
    host = os.environ.get('EXECUTOR_CONFIG_OPENVAS_HOST')
    port = os.environ.get('EXECUTOR_CONFIG_OPENVAS_PORT')
    scan_url = os.environ.get('EXECUTOR_CONFIG_OPENVAS_SCAN_URL')
    scan_id = os.environ.get('EXECUTOR_CONFIG_OPENVAS_SCAN_ID')
    xml_format = 'a994b278-1f62-11e1-96ac-406186ea4fc5'
    if not user or not passw or not host or not port:
        print("Data config ['Host', 'Port', 'User', 'Passw'] OpenVas not provided",
              file=sys.stderr)
        sys.exit()

    if not scan_url:
        print("Scan Url not provided", file=sys.stderr)
        sys.exit()

    if not scan_id:
        # Scan_ID Full and fast
        scan_id = 'daba56c8-73ec-11df-a475-002264764cea'

    # Create task and get task_id
    cmd_create_task = [
        'omp',
        '-u', user,
        '-w', passw,
        '-h', host,
        '-p', port,
        '-X', f'"<create_target><name>Suspect Host</name><hosts>{scan_url}</hosts></create_target>"'
    ]
    p = subprocess.run(cmd_create_task, stdout=subprocess.PIPE, shell=True)
    task_create = ET.XML(p.stdout)
    task_id = task_create.get('id')
    if task_id is None:
        print("Target Id not found", file=sys.stderr)
        sys.exit()

    # Config and get scan
    cmd_create_scan = [
        'omp',
        '-u', user,
        '-w', passw,
        '-h', host,
        '-p', port,
        '-C',
        '-c', scan_id,
        '--name', '"ScanSuspectHost"',
        '--target', task_id,
    ]
    p_scan = subprocess.run(cmd_create_scan, stdout=subprocess.PIPE, shell=True)
    scan = p_scan.stdout.decode().split('\n')

    # Start task get id for use report XML
    cmd_start_scan = [
        'omp',
        '-u', user,
        '-w', passw,
        '-h', host,
        '-p', port,
        '-S', scan[0],
    ]

    p_start_scan = subprocess.run(cmd_start_scan, stdout=subprocess.PIPE, shell=True)
    id_for_xml = p_start_scan.stdout.decode().split('\n')

    cmd_status = [
        'omp',
        '-u', user,
        '-w', passw,
        '-h', host,
        '-p', port,
        '--get-task', scan[0],
    ]
    status_level = 0
    while status_level <= 0:
        p_status = subprocess.run(cmd_status, stdout=subprocess.PIPE, shell=True)
        status_level = p_status.stdout.decode().find('Done')
        time.sleep(10)

    cmd_get_xml = [
        'omp',
        '-u', user,
        '-w', passw,
        '-h', host,
        '-p', port,
        '--get-report', id_for_xml[0],
        '--format', xml_format,
    ]
    p_xml = subprocess.run(cmd_get_xml, stdout=subprocess.PIPE, shell=True)
    plugin = OpenvasPlugin()
    plugin.parseOutputString(p_xml.stdout)
    print(plugin.get_json())


if __name__ == '__main__':
    main()
