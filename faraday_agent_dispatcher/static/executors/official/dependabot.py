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
    logger.info(f"{os.environ}")

    # TODO: should validate config?
    dependabot_url = f"https://api.github.com/repos/{DEPENDABOT_OWNER}/{DEPENDABOT_REPO}/dependabot/alerts"
    dependabot_auth = {'Authorization': f"Bearer {DEPENDABOT_TOKEN}"}
    logger.error(f"{dependabot_url}, {dependabot_auth}")

    response = requests.get(dependabot_url, headers=dependabot_auth)
    if response.status_code == http.HTTPStatus.OK:
        security_events = response.json()
        for security_event in security_events:
            # print("#"*10)
            # pprint(security_event)
            # print("#"*10)
            # continue
            host_data = {
                "ip": security_event['dependency']['manifest_path'],
                "description": "",
                "hostnames": [],
                "vulnerabilities": []
            }
            vulnerability_data = security_event['security_advisory']

            extended_description = ""
            if 'vulnerabilities' in vulnerability_data:
                # if len(vulnerability_data['vulnerabilities']) > 1:
                #     print("mayooooooor")
                #     pprint(security_event)
                #     break
                # else:
                #     continue
                # TODO: Sacar de security_vulnerability
                for extended_vuln_description in vulnerability_data['vulnerabilities']:
                    first_patcher_version = extended_vuln_description.get('first_patched_version', 'N/A')
                    package = extended_vuln_description.get('package', None)
                    ecosystem = package.get('ecosystem', 'N/A')
                    name = package.get('name', 'N/A')
                    vulnerable_version_range = vulnerability_data.get('vulnerable_version_range', 'N/A')
                    extended_description = f"Pkg Ecosystem: {ecosystem}\n" \
                                           f"Pkg Name: {name}\n" \
                                           f"Vulnerable Version range: {vulnerable_version_range}\n" \
                                           f"First Patcher version: {first_patcher_version}\n" \
                                           f"{extended_description}"
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
                "refs": [{'name': reference['url'], 'type': 'other'} for reference in vulnerability_data['references']],
                "status": 'open' if security_event['state'] == 'open' else 'closed'
            }
            host_data['vulnerabilities'].append(vulnerability)
            # print("#" * 10)
            # pprint(host_data)
            # print("#"*10)
        data = {'hosts': [host_data],
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
        print(json.dumps(data))


if __name__ == '__main__':
    main()