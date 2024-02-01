import http
import json
from pprint import pprint

import requests
import os
import logging

logger = logging.getLogger(__name__)

host_data = {
    "ip": "192.168.0.{}",
    "description": "test",
    "hostnames": ["test.com", "test2.org"],
}

service_data = {
    "name": "http",
    "port": 80,
    "protocol": "tcp",
}

vuln_data = {
    "name": "sql injection",
    "desc": "test",
    "severity": "high",
    "type": "Vulnerability",
    "impact": {
        "accountability": True,
        "availability": False,
    },
    "refs": ["CVE-1234"],
}

vuln_web_data = {
    "name": "Web vuln",
    "severity": "low",
    "type": "VulnerabilityWeb",
    "method": "POST",
    "website": "https://example.com",
    "path": "/search",
    "parameter_name": "q",
    "status_code": 200,
}

def main():
    DEPENDABOT_OWNER = os.getenv("EXECUTOR_CONFIG_DEPENDABOT_OWNER")
    DEPENDABOT_REPO = os.getenv("EXECUTOR_CONFIG_DEPENDABOT_REPO")
    DEPENDABOT_TOKEN = os.getenv("DEPENDABOT_TOKEN")

    # TODO: should validate config?
    dependabot_url = f"https://api.github.com/repos/{DEPENDABOT_OWNER}/{DEPENDABOT_REPO}/dependabot/alerts"
    dependabot_auth = {'Authorization': f"Bearer {DEPENDABOT_TOKEN}"}

    response = requests.get(dependabot_url, headers=dependabot_auth)

    if response.status_code == http.HTTPStatus.OK:
        security_events = response.json()
        hosts_ips = list({security_event['dependency']['manifest_path'] for security_event in security_events})
        hosts = []

        for ip in hosts_ips:
            host_vulns = []
            for security_event in security_events:
                if security_event['dependency']['manifest_path'] == ip:
                    vulnerability_data = security_event['security_advisory']

                    extended_description = ""
                    if security_event['state'] != 'open':
                        logger.warning(f"Vulnerability {security_event['number']} already closed...")
                        continue
                    security_vulnerability = vulnerability_data.get('security_vulnerability')

                    if security_vulnerability:
                        first_patched_version = security_vulnerability.get('first_patched_version', 'N/A')
                        first_patched_version_identifier = first_patched_version.get('identifier')
                        package = security_vulnerability.get('package', None)
                        ecosystem = package.get('ecosystem', 'N/A')
                        name = package.get('name', 'N/A')
                        vulnerable_version_range = security_vulnerability.get('vulnerable_version_range', 'N/A')
                        extended_description = f"```\n" \
                                               f"Package: {name} ({ecosystem})\n" \
                                               f"Affected versions: {vulnerable_version_range} \n" \
                                               f"Patched version: {first_patched_version_identifier}\n" \
                                               f"```"

                    vulnerability = {
                        "name": f"{vulnerability_data['summary']}",
                        "desc": f"{extended_description}\n{vulnerability_data['description']}\n",
                        "severity": f"{vulnerability_data['severity']}",
                        "type": "Vulnerability",
                        "impact": {
                            "accountability": False,
                            "availability": False,
                        },
                        "cvss": {'cvss3': vulnerability_data['cvss']['vector_string']},
                        "cwe": [cwe['cwe_id'] for cwe in vulnerability_data['cwes']],
                        "cve": [cve['value'] for cve in vulnerability_data['identifiers']
                                if cve['type'] == 'CVE'],
                        "refs": [{'name': reference['url'], 'type': 'other'} for reference in
                                 vulnerability_data['references']],
                        "status": 'open' if security_event['state'] == 'open' else 'closed',
                        "tags": []
                    }
                    host_vulns.append(vulnerability)
                    break

            hosts.append(
                {
                    "ip": ip,
                    "description": "",
                    "hostnames": [],
                    "vulnerabilities": host_vulns,
                    "tags": []
                }
            )

        data = {'hosts': hosts,
                "command": {
                    "tool": "dependabot",
                    "command": "dependabot",
                    "params": "",
                    "user": "agent",
                    "hostname": "",
                    "start_date": "2022-08-11T18:35:16.645160",
                    "duration": 16334,
                    "import_source": "report"}
                }
        # pprint(data)
        print(json.dumps(data))


if __name__ == '__main__':
    main()