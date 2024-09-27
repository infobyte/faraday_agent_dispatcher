#!/usr/bin/env python

import json
import logging
import os
import sys
import warnings
from typing import List, Dict, Any

import requests
from faraday_plugins.plugins.repo.faraday_json.plugin import FaradayJsonPlugin
from requests.exceptions import HTTPError, RequestException
from urllib3.exceptions import InsecureRequestWarning

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning if verify=False is used
warnings.simplefilter('ignore', InsecureRequestWarning)


def fetch_vulnerabilities(session: requests.Session, url: str) -> List[Dict[str, Any]]:
    try:
        response = session.get(url)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get('message_response', {}).get('vulnerabilities', [])
        return vulnerabilities
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
        sys.exit(1)
    except RequestException as req_err:
        logger.error(f"Request error occurred: {req_err}")
        sys.exit(1)
    except ValueError as json_err:
        logger.error(f"JSON decoding failed: {json_err}")
        sys.exit(1)
    except Exception as err:
        logger.error(f"An unexpected error occurred: {err}")
        sys.exit(1)


def process_vulnerabilities(vulnerabilities: List[Dict[str, Any]], meec_ip: str) -> Dict[str, Any]:
    severity_mapping = {
        'Critical': 'critical',
        'Important': 'high',
        'Moderate': 'medium',
        'Low': 'low',
        'Info': 'info'
    }

    valid_easeofresolution = {'trivial', 'simple', 'moderate', 'difficult', 'infeasible'}
    default_easeofresolution = 'moderate'

    valid_statuses = {'open', 'closed', 're-opened', 'risk-accepted', 'opened'}
    default_status = 'open'

    host = {
        'ip': meec_ip,
        'name': 'ManageEngineEndpointCentral',
        'services': [],
        'vulnerabilities': []
    }

    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'Moderate')
        vuln_severity = severity_mapping.get(severity, 'medium')

        cve_ids = vuln.get('cveids', '')
        refs = [cve.strip() for cve in cve_ids.split(',') if cve.strip()]

        description_fields = [
            ('Published Time', vuln.get('publishedtime', 'N/A')),
            ('Updated Time', vuln.get('updatedtime', 'N/A')),
            ('Exploit Status', vuln.get('exploit_status', 'Unknown')),
            ('Solution', vuln.get('solution', 'No solution available')),
            ('Reboot Required', vuln.get('reboot_required', 'Unknown')),
            ('Patch Availability', vuln.get('patch_availability', 'Unknown')),
            ('OS Platform', vuln.get('os_platform', 'Unknown'))
        ]
        description = '\n'.join(f"{key}: {value}" for key, value in description_fields)

        easeofresolution = vuln.get('easeofresolution', default_easeofresolution).lower()
        if easeofresolution not in valid_easeofresolution:
            easeofresolution = default_easeofresolution

        status = vuln.get('status', default_status).lower()
        if status not in valid_statuses:
            status = default_status

        impact = vuln.get('impact') if isinstance(vuln.get('impact'), dict) else {}

        policyviolations = vuln.get('policyviolations')
        if not isinstance(policyviolations, list):
            policyviolations = []

        def parse_cvss_score(score_raw):
            try:
                return {'base_score': float(score_raw)}
            except (TypeError, ValueError):
                return {}

        cvss2 = parse_cvss_score(vuln.get('cvss_2_score'))
        cvss3 = parse_cvss_score(vuln.get('cvss_3_score'))

        vulnerability = {
            'name': vuln.get('vulnerabilityname', 'No Name'),
            'desc': description,
            'severity': vuln_severity,
            'refs': refs,
            'external_id': vuln.get('external_id', vuln.get('vulnerabilityid', '')),
            'type': 'Vulnerability',
            'resolution': vuln.get('solution', 'No resolution provided'),
            'data': '',
            'custom_fields': vuln.get('custom_fields', {}),
            'status': status,
            'impact': impact,
            'policyviolations': policyviolations,
            'cve': refs,  # List of CVE IDs
            'cvss2': cvss2,
            'cvss3': cvss3,
            'confirmed': vuln.get('confirmed', False),
            'easeofresolution': easeofresolution,
            'tags': vuln.get('tags', []),
            'cwe': vuln.get('cwe', '')
        }

        host['vulnerabilities'].append(vulnerability)

    faraday_data = {
        'hosts': [host],
        'command': f"Fetched from ManageEngineEndpointCentral at {meec_ip}"
    }
    return faraday_data


def main():
    MEEC_IP = os.environ.get("EXECUTOR_CONFIG_MEEC_IP")
    MEEC_APIKEY = os.environ.get("EXECUTOR_CONFIG_MEEC_APIKEY")

    if not MEEC_IP or not MEEC_APIKEY:
        logger.error("Environment variables MEEC_IP and MEEC_APIKEY must be set.")
        sys.exit(1)

    url = f"https://{MEEC_IP}:8383/dcapi/threats/vulnerabilities"

    with requests.Session() as session:
        session.verify = False  # Not recommended, but assuming needed
        session.headers.update({"Authorization": MEEC_APIKEY})

        vulnerabilities = fetch_vulnerabilities(session, url)

    if not vulnerabilities:
        logger.info("No vulnerabilities found.")
        sys.exit(0)

    faraday_data = process_vulnerabilities(vulnerabilities, MEEC_IP)

    faraday_json = json.dumps(faraday_data)

    try:
        plugin = FaradayJsonPlugin()
        plugin.parseOutputString(faraday_json)
        output_json = plugin.get_json()
        print(output_json)
    except Exception as e:
        logger.error(f"Error processing data with FaradayJsonPlugin: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
