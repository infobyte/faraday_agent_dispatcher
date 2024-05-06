import json
import os
import io
import sys
import zipfile as zp
from tenable.sc import TenableSC
from faraday_plugins.plugins.repo.nessus.plugin import NessusPlugin


def log(msg):
    print(msg, file=sys.stderr)


def get_only_usable_ids(tio, scan_ids):
    tenable_scans = tio.scan_instances.list()
    usable_tenable_scans = [int(scan["id"]) for scan in tenable_scans["usable"]]
    log(usable_tenable_scans)
    return [id for id in scan_ids if id in usable_tenable_scans]


def process_scan(
    tsc, scan_id, ignore_info=False, hostname_resolution=False, host_tag=False, service_tag=False, vuln_tag=False
):
    log(f"Processing scan id {scan_id}")
    try:
        report = tsc.scan_instances.export_scan(scan_id)
    except Exception as e:
        log(e)
        return {}
    with zp.ZipFile(io.BytesIO(report.read()), "r") as zip_ref:
        with zip_ref.open(zip_ref.namelist()[0]) as file:
            plugin = NessusPlugin(
                ignore_info=ignore_info,
                hostname_resolution=hostname_resolution,
                host_tag=host_tag,
                service_tag=service_tag,
                vuln_tag=vuln_tag,
            )
            plugin.parseOutputString(file.read())
            return plugin.get_json()
    return {}


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

    tenable_scan_ids = os.getenv("EXECUTOR_CONFIG_TENABLE_SCAN_ID")
    TENABLE_ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
    TENABLE_SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")
    TENABLE_HOST = os.getenv("TENABLE_HOST")

    if not (TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY):
        log("TenableSC access_key and secret_key were not provided")
        exit(1)

    if not TENABLE_HOST:
        log("TenableSC Host not provided")
        exit(1)

    if not tenable_scan_ids:
        log("TenableSC Scan ID not provided")
        exit(1)

    # it should be a list but the it is save as a str in the environment
    try:
        tenable_scan_ids_list = json.loads(tenable_scan_ids)
    except Exception as e:
        log(f"TenableSC Scan IDs could not be parsed {e}")
        exit(1)

    tsc = TenableSC(host=TENABLE_HOST, access_key=TENABLE_ACCESS_KEY, secret_key=TENABLE_SECRET_KEY)
    usable_scan_ids = get_only_usable_ids(tsc, tenable_scan_ids_list)
    log(usable_scan_ids)

    responses = []
    for scan_id in usable_scan_ids:
        processed_scan = process_scan(
            tsc,
            scan_id,
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
        )
        if processed_scan:
            responses.append(processed_scan)
    if responses:
        final_response = json.loads(responses.pop(0))
        for response in responses:
            json_response = json.loads(response)
            final_response["hosts"] += [host for host in json_response["hosts"]]
        print(json.dumps(final_response), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"Agent execution failed. {e}")
