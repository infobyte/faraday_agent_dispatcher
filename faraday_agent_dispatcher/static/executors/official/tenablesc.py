import json
import os
import io
import sys
import zipfile as zp
from typing import List, Optional

from tenable.sc import TenableSC
from faraday_plugins.plugins.repo.nessus.plugin import NessusPlugin


def log(msg: str) -> None:
    """Prints a log message to stderr."""
    print(msg, file=sys.stderr)


def get_only_usable_ids(tsc: TenableSC, scan_ids: List[str], fetch_all_scans: bool = False) -> List[str]:
    """
    Return a list of completed scan IDs based on accessibility.

    If fetch_all_scans is True, the function returns all scans with status 'Completed'
    from both 'usable' and 'manageable' categories. If False, it returns only those
    matching the input scan_ids and are also completed.
    """
    scan_data = tsc.scan_instances.list()
    usable_scans = scan_data.get("usable", [])
    manageable_scans = scan_data.get("manageable", [])
    all_scans = usable_scans + manageable_scans

    completed_scan_ids = {str(scan["id"]) for scan in all_scans if scan.get("status") == "Completed"}

    if fetch_all_scans:
        return list(completed_scan_ids)

    return [scan_id for scan_id in scan_ids if str(scan_id) in completed_scan_ids]


def process_scan(
    tsc: TenableSC,
    scan_id: str,
    ignore_info: bool = False,
    hostname_resolution: bool = False,
    host_tag: Optional[List[str]] = None,
    service_tag: Optional[List[str]] = None,
    vuln_tag: Optional[List[str]] = None,
) -> dict:
    """
    Downloads and parses a scan report by its ID using the Nessus plugin.

    Returns the parsed scan report as a dictionary.
    """
    log(f"Processing scan ID {scan_id}")
    try:
        report = tsc.scan_instances.export_scan(scan_id)
    except Exception as error:
        log(f"Failed to export scan ID {scan_id}: {error}")
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


def load_environment_list(var_name: str) -> Optional[List[str]]:
    """Loads a comma-separated list from environment variable, or returns None."""
    value = os.getenv(var_name)
    return value.split(",") if value else None


def main() -> None:
    """Main execution logic for loading and processing TenableSC scans."""
    ignore_info = os.getenv("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
    hostname_resolution = os.getenv("AGENT_CONFIG_RESOLVE_HOSTNAME", "True").lower() == "true"
    vuln_tag = load_environment_list("AGENT_CONFIG_VULN_TAG")
    service_tag = load_environment_list("AGENT_CONFIG_SERVICE_TAG")
    host_tag = load_environment_list("AGENT_CONFIG_HOSTNAME_TAG")

    scan_ids_str = os.getenv("EXECUTOR_CONFIG_TENABLE_SCAN_ID", "[]")
    fetch_all = os.getenv("EXECUTOR_CONFIG_COMPLETED_SCANS", "False").lower() == "true"
    access_key = os.getenv("TENABLE_ACCESS_KEY")
    secret_key = os.getenv("TENABLE_SECRET_KEY")
    host = os.getenv("TENABLE_HOST")

    if not access_key or not secret_key:
        log("TenableSC credentials not provided")
        sys.exit(1)

    if not host:
        log("TenableSC host not provided")
        sys.exit(1)

    try:
        scan_ids = json.loads(scan_ids_str)
    except Exception as error:
        log(f"Failed to parse scan IDs: {error}")
        sys.exit(1)

    if not fetch_all and not scan_ids:
        log("No scan IDs provided and fetch_all is False")
        sys.exit(1)

    tsc = TenableSC(host=host, access_key=access_key, secret_key=secret_key)
    usable_scan_ids = get_only_usable_ids(tsc, scan_ids, fetch_all_scans=fetch_all)

    if not usable_scan_ids:
        log("No usable scan IDs found")
        sys.exit(1)

    log("Processing scan IDs:")
    log(str(usable_scan_ids))

    results = []
    for scan_id in usable_scan_ids:
        result = process_scan(
            tsc,
            scan_id,
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
        )
        if result:
            results.append(result)

    if results:
        combined = json.loads(results.pop(0))
        for r in results:
            data = json.loads(r)
            combined["hosts"].extend(data.get("hosts", []))
        print(json.dumps(combined))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        log(f"Agent execution failed: {error}")
