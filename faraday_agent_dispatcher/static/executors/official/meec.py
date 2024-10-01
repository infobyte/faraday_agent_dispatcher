#!/usr/bin/env python

import json
import logging
import os
import sys
import warnings
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Iterator

import requests
from requests.exceptions import HTTPError, RequestException
from urllib3.exceptions import InsecureRequestWarning

from faraday_plugins.plugins.repo.faraday_json.plugin import FaradayJsonPlugin

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

warnings.simplefilter("ignore", InsecureRequestWarning)

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
    type: str = "Vulnerability"
    resolution: str = "No resolution provided"
    data: str = ""
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    status: str = DEFAULT_STATUS
    impact: Dict[str, Any] = field(default_factory=dict)
    policyviolations: List[Any] = field(default_factory=list)
    cve: List[str] = field(default_factory=list)
    cvss2: Dict[str, Any] = field(default_factory=dict)
    cvss3: Dict[str, Any] = field(default_factory=dict)
    confirmed: bool = False
    tags: List[str] = field(default_factory=list)
    cwe: str = ""


@dataclass
class Host:
    ip: str
    name: str = "ManageEngineEndpointCentral"
    services: List[Any] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


def fetch_all_vulnerabilities(
    session: requests.Session,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    page_limit: int = 100,
) -> Iterator[Dict[str, Any]]:
    """
    Fetch all vulnerabilities from the API using pagination.

    Args:
        session (requests.Session): The requests session to use for the HTTP request.
        url (str): The URL to fetch vulnerabilities from.
        params (Dict[str, Any], optional): Query parameters to filter vulnerabilities.
        page_limit (int): Number of vulnerabilities per page.

    Yields:
        Iterator[Dict[str, Any]]: An iterator over vulnerabilities.
    """
    if params is None:
        params = {}
    params["pageLimit"] = page_limit
    page = 1

    while True:
        params["page"] = page
        try:
            response = session.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            if "message_response" not in data or "vulnerabilities" not in data["message_response"]:
                logger.error(f"Unexpected response structure: {data}")
                raise ValueError("Invalid response format")

            vulnerabilities = data["message_response"]["vulnerabilities"]
            for vulnerability in vulnerabilities:
                yield vulnerability

            metadata = data.get("metadata", {})
            total_pages = metadata.get("totalPages", 1)
            if page >= total_pages:
                break
            page += 1
        except (HTTPError, RequestException, ValueError) as err:
            logger.error(f"An error occurred while fetching vulnerabilities: {err}")
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
        logger.warning(f"Invalid CVSS score '{score_raw}': {e}")
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
        ("Published Time", vuln.get("publishedtime", "N/A")),
        ("Updated Time", vuln.get("updatedtime", "N/A")),
        ("Exploit Status", vuln.get("exploit_status", "Unknown")),
        ("Solution", vuln.get("solution", "No solution available")),
        ("Reboot Required", vuln.get("reboot_required", "Unknown")),
        ("Patch Availability", vuln.get("patch_availability", "Unknown")),
        ("OS Platform", vuln.get("os_platform", "Unknown")),
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
    refs = [cve.strip() for cve in cve_ids.split(",") if cve.strip()]

    description = build_description(vuln)

    status = vuln.get("status", DEFAULT_STATUS).lower()
    if status not in VALID_STATUSES:
        status = DEFAULT_STATUS

    impact = vuln.get("impact") if isinstance(vuln.get("impact"), dict) else {}

    policy_violations = vuln.get("policyviolations") or []
    if not isinstance(policy_violations, list):
        policy_violations = []

    cvss2 = parse_cvss_score(vuln.get("cvss_2_score"))
    cvss3 = parse_cvss_score(vuln.get("cvss_3_score"))

    vulnerability = Vulnerability(
        name=vuln.get("vulnerabilityname", "No Name"),
        desc=description,
        severity=vuln_severity,
        refs=refs,
        external_id=vuln.get("external_id", vuln.get("vulnerabilityid", "")),
        resolution=vuln.get("solution", "No resolution provided"),
        custom_fields=vuln.get("custom_fields", {}),
        status=status,
        impact=impact,
        policyviolations=policy_violations,
        cve=refs,
        cvss2=cvss2,
        cvss3=cvss3,
        confirmed=vuln.get("confirmed", False),
        tags=vuln.get("tags", []),
        cwe=vuln.get("cwe", ""),
    )

    return vulnerability


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
        "services": host.services,
        "vulnerabilities": [vuln.__dict__ for vuln in host.vulnerabilities],
    }


def process_vulnerabilities(vulnerabilities_iterator: Iterator[Dict[str, Any]], meec_ip: str) -> Dict[str, Any]:
    """
    Process vulnerabilities from an iterator and structure them for Faraday integration.

    Args:
        vulnerabilities_iterator (Iterator[Dict[str, Any]]): An iterator over vulnerabilities.
        meec_ip (str): The IP address of the ManageEngine Endpoint Central server.

    Returns:
        Dict[str, Any]: The processed data ready for Faraday.
    """
    host = Host(ip=meec_ip)

    for vuln in vulnerabilities_iterator:
        vulnerability = process_single_vulnerability(vuln)
        host.vulnerabilities.append(vulnerability)

    faraday_data = {
        "hosts": [host_to_dict(host)],
        "command": f"Fetched from ManageEngineEndpointCentral at {meec_ip}",
    }
    return faraday_data


def main():
    """
    Main function to fetch vulnerabilities from ManageEngine Endpoint Central and process them.
    """
    meec_ip = os.environ.get("EXECUTOR_CONFIG_MEEC_IP")
    meec_apikey = os.environ.get("EXECUTOR_CONFIG_MEEC_APIKEY")
    verify_ssl_env = os.environ.get("EXECUTOR_CONFIG_VERIFY_SSL", "True").lower()

    if not meec_ip or not meec_apikey:
        logger.error("Environment variables EXECUTOR_CONFIG_MEEC_IP and EXECUTOR_CONFIG_MEEC_APIKEY must be set.")
        sys.exit(1)

    if verify_ssl_env in ["true", "t", "yes", "y", "1"]:
        verify_ssl = True
    elif verify_ssl_env in ["false", "f", "no", "n", "0"]:
        verify_ssl = False
    else:
        logger.warning(f"Invalid value for EXECUTOR_CONFIG_VERIFY_SSL: '{verify_ssl_env}'. Defaulting to True.")
        verify_ssl = True

    # Ensure the URL includes the endpoint path
    url = f"{meec_ip}/dcapi/threats/vulnerabilities"

    with requests.Session() as session:
        session.verify = verify_ssl
        session.headers.update({"Authorization": meec_apikey})

        logger.info(f"Fetching vulnerabilities from {url} with SSL verification set to {verify_ssl}")
        try:
            vulnerabilities_iterator = fetch_all_vulnerabilities(session, url)
        except requests.exceptions.SSLError as ssl_error:
            logger.error(f"SSL error occurred: {ssl_error}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"An error occurred while fetching vulnerabilities: {e}")
            sys.exit(1)

        # Process vulnerabilities as they are fetched
        faraday_data = process_vulnerabilities(vulnerabilities_iterator, meec_ip)

    if not faraday_data["hosts"][0]["vulnerabilities"]:
        logger.info("No vulnerabilities found.")
        sys.exit(0)

    total_vulnerabilities = len(faraday_data["hosts"][0]["vulnerabilities"])
    logger.info(f"Processed {total_vulnerabilities} vulnerabilities.")

    try:
        faraday_json = json.dumps(faraday_data)
        plugin = FaradayJsonPlugin()
        plugin.parseOutputString(faraday_json)
        output_json = plugin.get_json()
        print(output_json)
    except Exception as e:
        logger.error(f"Error processing data with FaradayJsonPlugin: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
