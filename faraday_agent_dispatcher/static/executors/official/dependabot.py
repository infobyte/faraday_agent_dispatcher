import json
import sys

import requests
import os
import logging

logger = logging.getLogger(__name__)


def make_report(json_response, repo_owner, repo_name, extra_vuln_tags, extra_hostname_tags):
    security_events = json_response
    hosts_ips = list({security_event["dependency"]["manifest_path"] for security_event in security_events})
    hosts = []

    for ip in hosts_ips:
        host_vulns = []
        for security_event in security_events:
            if security_event["dependency"]["manifest_path"] == ip:
                vulnerability_data = security_event["security_advisory"]

                if security_event["state"] != "open":
                    logger.warning(f"Vulnerability {security_event['number']} already closed...")
                    continue

                security_vulnerability = security_event.get("security_vulnerability")

                extended_description = ""
                if security_vulnerability:
                    first_patched_version = security_vulnerability.get("first_patched_version", "N/A")
                    first_patched_version_identifier = first_patched_version.get("identifier")
                    package = security_vulnerability.get("package", None)
                    ecosystem = package.get("ecosystem", "N/A")
                    name = package.get("name", "N/A")
                    vulnerable_version_range = security_vulnerability.get("vulnerable_version_range", "N/A")
                    extended_description = (
                        f"URL: [{security_event['html_url']}]({security_event['html_url']})\n"
                        f"```\n"
                        f"Package: {name} ({ecosystem})\n"
                        f"Affected versions: {vulnerable_version_range} \n"
                        f"Patched version: {first_patched_version_identifier}\n"
                        f"```"
                    )
                vulnerability = {
                    "name": f"{vulnerability_data['summary']}",
                    "desc": f"{extended_description}\n{vulnerability_data['description']}\n",
                    "severity": f"{vulnerability_data['severity']}",
                    "type": "Vulnerability",
                    "impact": {
                        "accountability": False,
                        "availability": False,
                    },
                    "cwe": [cwe["cwe_id"] for cwe in vulnerability_data["cwes"]],
                    "cve": [cve["value"] for cve in vulnerability_data["identifiers"] if cve["type"] == "CVE"],
                    "refs": [
                        {"name": reference["url"], "type": "other"} for reference in vulnerability_data["references"]
                    ],
                    "status": "open" if security_event["state"] == "open" else "closed",
                    "tags": extra_vuln_tags + ["dependabot"],
                }

                cvss_vector_string = vulnerability_data["cvss"]["vector_string"]

                if cvss_vector_string:
                    if cvss_vector_string.startswith("CVSS:3"):
                        vulnerability.update({"cvss3": {"vector_string": cvss_vector_string}})
                    else:
                        vulnerability.update({"cvss2": {"vector_string": cvss_vector_string.strip("CVSS:")[-1]}})

                host_vulns.append(vulnerability)
        repo_url = f"https://github.com/{repo_owner}/{repo_name}"
        hosts.append(
            {
                "ip": f"{repo_owner}/{repo_name}/{ip}",
                "description": f"Dependabot recommendations on file {ip}\n\nRepository: {repo_url}",
                "hostnames": [],
                "vulnerabilities": host_vulns,
                "tags": extra_hostname_tags + ["dependabot"],
            }
        )

    data = {"hosts": hosts}
    print(json.dumps(data))


def main():
    GITHUB_REPOSITORY = os.getenv("EXECUTOR_CONFIG_GITHUB_REPOSITORY")
    GITHUB_OWNER = os.getenv("GITHUB_OWNER")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

    vuln_tag = os.getenv("AGENT_CONFIG_VULN_TAG", [])
    if vuln_tag:
        vuln_tag = vuln_tag.split(",")
    host_tag = os.getenv("AGENT_CONFIG_HOSTNAME_TAG", [])
    if host_tag:
        host_tag = host_tag.split(",")

    # TODO: should validate config?
    dependabot_url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPOSITORY}/dependabot/alerts"
    github_auth = {"Authorization": f"Bearer {GITHUB_TOKEN}"}

    security_events = []
    page = 1

    while True:
        params = {"page": page, "per_page": 100}
        try:
            req = requests.get(dependabot_url, params=params, headers=github_auth, timeout=60)
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Network Error: {e}", file=sys.stderr)
            return
        if req.status_code != 200:
            print(f"ERROR: Network status code {req.status_code}", file=sys.stderr)
            return
        page_events = req.json()
        if not page_events:
            break
        security_events.extend(page_events)
        page += 1

    make_report(security_events, GITHUB_OWNER, GITHUB_REPOSITORY, vuln_tag, host_tag)


if __name__ == "__main__":
    main()
