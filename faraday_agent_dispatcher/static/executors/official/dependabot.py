import http
import json

import requests
import os
import logging

logger = logging.getLogger(__name__)


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
    repo_url = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPOSITORY}"

    CVSS_3_PREFIX = "CVSS:3"

    response = requests.get(dependabot_url, headers=github_auth, timeout=60)

    if response.status_code == http.HTTPStatus.OK:
        security_events = response.json()
        hosts_ips = list(
            {security_event.get("dependency", {}).get("manifest_path", "N/A") for security_event in security_events}
        )
        hosts = []

        for ip in hosts_ips:
            host_vulns = []
            for security_event in security_events:
                if security_event.get("dependency", {}).get("manifest_path", "N/A") == ip:
                    vulnerability_data = security_event.get("security_advisory", "N/A")

                    if security_event.get("state", "open") != "open":
                        logger.warning(f"Vulnerability {security_event['number']} already closed...")
                        continue

                    security_vulnerability = security_event.get("security_vulnerability", {})

                    extended_description = ""
                    if security_vulnerability:
                        first_patched_version = security_vulnerability.get("first_patched_version", "N/A")
                        first_patched_version_identifier = first_patched_version.get("identifier"), "N/A"
                        package = security_vulnerability.get("package", None)
                        ecosystem = package.get("ecosystem", "N/A")
                        name = package.get("name", "N/A")
                        vulnerable_version_range = security_vulnerability.get("vulnerable_version_range", "N/A")
                        extended_description = (
                            f"URL: [{security_event.get('html_url', 'N/A')}]"
                            f"({security_event.get('html_url', 'N/A')})\n"
                            f"```\n"
                            f"Package: {name} ({ecosystem})\n"
                            f"Affected versions: {vulnerable_version_range} \n"
                            f"Patched version: {first_patched_version_identifier}\n"
                            f"```"
                        )
                    vulnerability = {
                        "name": f"{vulnerability_data['summary']}",
                        "desc": f"{extended_description}\n{vulnerability_data.get('description', 'N/A')}\n",
                        "severity": f"{vulnerability_data.get('severity', 'unclassified')}",
                        "type": "Vulnerability",
                        "impact": {
                            "accountability": False,
                            "availability": False,
                        },
                        "cwe": [cwe.get("cwe_id", "N/A") for cwe in vulnerability_data.get("cwes", [])],
                        "cve": [
                            cve.get("value", "N/A")
                            for cve in vulnerability_data.get("identifiers", [])
                            if cve.get("type", "") == "CVE"
                        ],
                        "refs": [
                            {"name": reference.get("url", "N/A"), "type": "other"}
                            for reference in vulnerability_data.get("references", [])
                        ],
                        "status": "open" if security_event.get("state", "open") == "open" else "closed",
                        "tags": vuln_tag,
                    }

                    cvss_vector_string = vulnerability_data.get("cvss", {}).get("vector_string", None)

                    if cvss_vector_string:
                        if cvss_vector_string.startswith(CVSS_3_PREFIX):
                            vulnerability.update({"cvss3": {"vector_string": cvss_vector_string}})
                        else:
                            vulnerability.update({"cvss2": {"vector_string": cvss_vector_string.strip("CVSS:")[-1]}})

                    host_vulns.append(vulnerability)

            hosts.append(
                {
                    "ip": f"{GITHUB_OWNER}/{GITHUB_REPOSITORY}/{ip}",
                    "description": f"Dependabot recommendations on file {ip}\n\nRepository: {repo_url}",
                    "hostnames": [],
                    "vulnerabilities": host_vulns,
                    "tags": host_tag,
                }
            )

        data = {"hosts": hosts}
        print(json.dumps(data))


if __name__ == "__main__":
    main()
