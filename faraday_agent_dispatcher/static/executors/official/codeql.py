import http
import json
import re
from pprint import pprint

import requests
import os
import logging

logger = logging.getLogger(__name__)

CWE_PATTERN = ".*(cwe-\d+)"


def get_codeql_alerts(owner, repository, token, vuln_tag=None, host_tag=None):
    url = f"https://api.github.com/repos/{owner}/{repository}/code-scanning/alerts"
    auth = {"Authorization": f"Bearer {token}"}

    response = requests.get(url, headers=auth)
    if response.status_code != http.HTTPStatus.OK:
        print(f"Response from server {response.status_code} / repo {repository} / owner {owner}")
        return []

    if response.status_code == http.HTTPStatus.OK:
        security_events = response.json()
        pprint(security_events)
        hosts_ips = list({security_event["most_recent_instance"]["location"]['path']
                          for security_event in security_events})
        hosts = []

        for ip in hosts_ips:
            host_vulns = []
            for security_event in security_events:
                if security_event["most_recent_instance"]["location"]['path'] == ip:
                    if security_event["state"] != "open":
                        logger.warning(f"Vulnerability {security_event['number']} already closed...")
                        continue
                    cwe_list = []
                    _vuln_tag = set()
                    for tag in security_event['rule']['tags']:
                        if 'cwe-' in tag:
                            cwe = re.search(CWE_PATTERN, tag)[1]
                            cwe_list.append(cwe)
                        else:
                            _vuln_tag.add(tag)

                    vulnerability = {
                        "name": f"{security_event['rule']['name']}",
                        "desc": f"{security_event['rule']['description']}\n",
                        "severity": f"{security_event['rule']['security_severity_level']}",
                        "type": "Vulnerability",
                        "impact": {
                            "accountability": False,
                            "availability": False,
                        },
                        "cwe": cwe_list,
                        "cve": [],
                        "refs": [],
                        "tags": vuln_tag + list(_vuln_tag),
                    }
                    host_vulns.append(vulnerability)

            hosts.append(
                {
                    "ip": f"{owner}/{repository}/{ip}",
                    "description": "",
                    "hostnames": [],
                    "vulnerabilities": host_vulns,
                    "tags": host_tag,
                }
            )


def main():
    token = os.getenv("GITHUB_TOKEN")
    owner = os.getenv("GITHUB_OWNER")
    repository = os.getenv("EXECUTOR_CONFIG_GITHUB_REPOSITORY")

    vuln_tag = os.getenv("AGENT_CONFIG_VULN_TAG", [])
    if vuln_tag:
        vuln_tag = vuln_tag.split(",")
    host_tag = os.getenv("AGENT_CONFIG_HOSTNAME_TAG", [])
    if host_tag:
        host_tag = host_tag.split(",")

    hosts = get_codeql_alerts(owner, repository, token, vuln_tag, host_tag)
    data = {"hosts": hosts}
    print(json.dumps(data))


if __name__ == "__main__":
    main()
