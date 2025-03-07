#!/usr/bin/env python

import json
import os
import sys
import warnings
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Iterator
from datetime import datetime
import requests
from requests.exceptions import HTTPError, RequestException
from urllib3.exceptions import InsecureRequestWarning

from faraday_plugins.plugins.repo.faraday_json.plugin import FaradayJsonPlugin

warnings.simplefilter("ignore", InsecureRequestWarning)


def log(msg, end="\n"):
    print(msg, file=sys.stderr, flush=True, end=end)


SEVERITY_MAPPING = {
    "Critical": "critical",
    "Important": "high",
    "Moderate": "medium",
    "Low": "low",
    "Info": "info",
}

VALID_STATUSES = {"open", "closed", "re-opened", "risk-accepted", "opened"}
DEFAULT_STATUS = "open"


@dataclass
class Vulnerability:
    name: str
    desc: str
    severity: str
    refs: List[str]
    external_id: str
    resolution: str = "No resolution provided"
    status: str = DEFAULT_STATUS
    cve: List[str] = field(default_factory=list)
    cvss2: Dict[str, Any] = field(default_factory=dict)
    cvss3: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class Host:
    ip: str
    name: str
    hostnames: List[str] = field(default_factory=list)
    services: List[Any] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


def fetch_all_system_reports(
        session: requests.Session,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        page_limit: int = 100,
) -> Iterator[Dict[str, Any]]:
    """
    Fetch all system reports from the API using pagination.

    Args:
        session (requests.Session): The requests session to use for the HTTP request.
        url (str): The URL to fetch system reports from.
        params (Dict[str, Any], optional): Query parameters to filter system reports.
        page_limit (int): Number of system reports per page.

    Yields:
        Iterator[Dict[str, Any]]: An iterator over system reports.
    """
    if params is None:
        params = {}
    params["pageLimit"] = page_limit
    page = 1

    while True:
        params["page"] = page
        try:
            log(f"Fetching page {page} with page limit {page_limit}")
            response = session.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            if "message_response" not in data or "systemreport" not in data["message_response"]:
                log(f"Unexpected response structure: {data}")
                raise ValueError("Invalid response format")

            systems = data["message_response"]["systemreport"]
            log(f"Fetched {len(systems)} systems from page {page}")

            for system in systems:
                yield system

            metadata = data.get("metadata", {})
            total_pages = metadata.get("totalPages", 1)
            if page >= total_pages:
                log("All pages fetched.")
                break
            page += 1
        except (HTTPError, RequestException, ValueError) as err:
            log(f"An error occurred while fetching system reports: {err}")
            raise


def parse_cvss_score(score_raw: Optional[str]) -> Dict[str, Any]:
    """
    Parse CVSS score from raw string input.

    Args:
        score_raw (Optional[str]): The raw CVSS score string.

    Returns:
        Dict[str, Any]: A dictionary with the base_score.
    """
    try:
        return {"base_score": float(score_raw)}
    except (TypeError, ValueError) as e:
        log(f"Invalid CVSS score '{score_raw}': {e}")
        return {}


def build_description(vuln: Dict[str, Any]) -> str:
    """
    Build a description string from vulnerability details.

    Args:
        vuln (Dict[str, Any]): The vulnerability data.

    Returns:
        str: The formatted description string.
    """
    description_fields = [
        ("Updated Time", vuln.get("updatedtime", "N/A")),
        ("Patch", vuln.get("patch", "N/A")),
        ("Reference Links", vuln.get("reference_links", "N/A")),
        ("Vulnerability Status", vuln.get("vulnerability_status", "Unknown")),
    ]
    return "\n".join(f"{key}: {value}" for key, value in description_fields)


def process_single_vulnerability(vuln: Dict[str, Any]) -> Vulnerability:
    """
    Process a single vulnerability dictionary into a Vulnerability dataclass.

    Args:
        vuln (Dict[str, Any]): The vulnerability data.

    Returns:
        Vulnerability: The processed vulnerability object.
    """
    severity = vuln.get("severity", "Moderate")
    vuln_severity = SEVERITY_MAPPING.get(severity, "medium")

    cve_ids = vuln.get("cveids", "")
    cve_ids_list = [cve.strip() for cve in cve_ids.split(",") if cve.strip()]

    references = [vuln.get("reference_links", "")] + cve_ids_list

    description = build_description(vuln)

    status = vuln.get("vulnerability_status", DEFAULT_STATUS).lower()
    if status not in VALID_STATUSES:
        status = DEFAULT_STATUS

    vulnerability = Vulnerability(
        name=vuln.get("vulnerabilityname", "No Name"),
        desc=description,
        severity=vuln_severity,
        refs=references,
        external_id=vuln.get("vulnerabilityid", ""),
        resolution=vuln.get("patch", "No resolution provided"),
        status=status,
        cve=cve_ids_list,
        tags=["endpoint-central", "vulnerability-management", "meec"]
    )

    # Parse and add CVSS scores if available
    cvss2_raw = vuln.get("cvss2", None)
    if cvss2_raw:
        vulnerability.cvss2 = parse_cvss_score(cvss2_raw)

    cvss3_raw = vuln.get("cvss3", None)
    if cvss3_raw:
        vulnerability.cvss3 = parse_cvss_score(cvss3_raw)

    return vulnerability


def process_single_system(system: Dict[str, Any]) -> Host:
    """
    Process a single system dictionary into a Host dataclass.

    Args:
        system (Dict[str, Any]): The system data.

    Returns:
        Host: The processed host object.
    """
    resource_name = system.get("resource_name", "Unknown").lower()
    ip_address = system.get("ip_address", "")
    fqdn_name = system.get("fqdn_name", "").lower()

    # Convert name to lowercase as per AssetsDB pattern
    host = Host(
        ip=fqdn_name,
        name=fqdn_name,
        tags=["endpoint-central", "meec", "managed-endpoint"]
    )

    hostnames = [ip.strip() for ip in ip_address.split(",") if ip.strip()] + [resource_name]
    if fqdn_name:
        hostnames.append(fqdn_name)
    host.hostnames = hostnames

    # Add additional system information to tags if available
    system_os = system.get("os_name")
    if system_os:
        host.tags.append(f"os:{system_os.lower()}")

    vulnerabilities = system.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        vulnerability = process_single_vulnerability(vuln)
        host.vulnerabilities.append(vulnerability)

    return host


def host_to_dict(host: Host) -> Dict[str, Any]:
    """
    Convert Host dataclass to dictionary, including nested vulnerabilities.

    Args:
        host (Host): The Host object.

    Returns:
        Dict[str, Any]: The dictionary representation.
    """
    return {
        "ip": host.ip,
        "name": host.name,
        "hostnames": host.hostnames,
        "services": host.services,
        "vulnerabilities": [vuln.__dict__ for vuln in host.vulnerabilities],
        "tags": host.tags
    }


def process_system_reports(systems_iterator: Iterator[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process system reports from an iterator and structure them for Faraday integration.

    Args:
        systems_iterator (Iterator[Dict[str, Any]]): An iterator over system reports.

    Returns:
        Dict[str, Any]: The processed data ready for Faraday.
    """
    hosts = []

    for system in systems_iterator:
        host = process_single_system(system)
        hosts.append(host_to_dict(host))

    # Include the tool name in the command output
    faraday_data = {
        "hosts": hosts,
        "command": "ManageEngine Endpoint Central",
    }
    return faraday_data


def main():
    """
    Main function to fetch vulnerabilities from ManageEngine Endpoint Central and process them.
    """
    meec_ip = os.environ.get("MEEC_IP")
    meec_apikey = os.environ.get("MEEC_APIKEY")
    verify_ssl_env = os.environ.get("EXECUTOR_CONFIG_VERIFY_SSL", "True").lower()

    if not meec_ip or not meec_apikey:
        log("Environment variables MEEC_IP and MEEC_APIKEY must be set.")
        sys.exit(1)

    if verify_ssl_env in ["true", "t", "yes", "y", "1"]:
        verify_ssl = True
    elif verify_ssl_env in ["false", "f", "no", "n", "0"]:
        verify_ssl = False
    else:
        log(f"Invalid value for EXECUTOR_CONFIG_VERIFY_SSL: '{verify_ssl_env}'. Defaulting to True.")
        verify_ssl = True

    # Ensure the URL includes the endpoint path
    url = f"{meec_ip}/dcapi/threats/systemreport/vulnerabilities"

    with requests.Session() as session:
        session.verify = verify_ssl
        session.headers.update({"Authorization": meec_apikey})

        log(f"Fetching vulnerabilities from {url} with SSL verification set to {verify_ssl}")
        try:
            systems_iterator = fetch_all_system_reports(session, url)
            # Process systems as they are fetched
            faraday_data = process_system_reports(systems_iterator)
        except requests.exceptions.SSLError as ssl_error:
            log(f"SSL error occurred: {ssl_error}")
            sys.exit(1)
        except Exception as e:
            log(f"An error occurred while fetching system reports: {e}")
            sys.exit(1)

    total_vulnerabilities = sum(len(host["vulnerabilities"]) for host in faraday_data["hosts"])
    if total_vulnerabilities == 0:
        log("No vulnerabilities found.")
        sys.exit(0)

    log(f"Processed {total_vulnerabilities} vulnerabilities.")

    try:
        faraday_json = json.dumps(faraday_data)
        plugin = FaradayJsonPlugin()
        plugin.parseOutputString(faraday_json)
        output_json = plugin.get_json()
        print(output_json)  # Print to stdout, not stderr
    except Exception as e:
        log(f"Error processing data with FaradayJsonPlugin: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
