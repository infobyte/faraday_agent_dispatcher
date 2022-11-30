import json
import os
import sys
import requests
from faraday_plugins.plugins.repo.sonarqubeapi.plugin import SonarQubeAPIPlugin

# ATTENTION: We only want to find vulnerabilities. Code smell and bugs doesn't matters for us.
TYPE_VULNS = "VULNERABILITY"
PAGE_SIZE = 500


def main():
    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_TOKEN', 'EXECUTOR_CONFIG_URL', 'EXECUTOR_CONFIG_PROJECT']
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

    try:
        sonar_qube_url = os.environ["SONAR_URL"]
        token = os.environ["EXECUTOR_CONFIG_TOKEN"]
        component_key = os.environ.get("EXECUTOR_CONFIG_COMPONENT_KEY", None)
    except KeyError:
        print("Environment variable not found", file=sys.stderr)
        sys.exit()

    session = requests.Session()

    # ATTENTION: SonarQube API requires an empty password when auth method is via token
    session.auth = (token, "")

    # Issues api config
    page = 0
    has_more_vulns = True

    vulnerabilities = []

    while has_more_vulns:
        page += 1

        params = {"types": TYPE_VULNS, "p": page, "ps": PAGE_SIZE}
        if component_key:
            params["componentKeys"] = component_key
        try:
            response = session.get(
                url=f"{sonar_qube_url}/api/issues/search",
                params=params,
            )
            response_json = response.json()
        except Exception:
            print(
                f"There was an error finding issues. Component Key {component_key}; "
                f"Status Code {response.status_code} - {response.content}",
                file=sys.stderr,
            )
            sys.exit(1)

        issues = response_json.get("issues")
        vulnerabilities.extend(issues)
        total_items = response_json.get("paging").get("total")

        has_more_vulns = page * PAGE_SIZE < total_items

    response_json["issues"] = vulnerabilities
    sonar = SonarQubeAPIPlugin(
        ignore_info=ignore_info,
        hostname_resolution=hostname_resolution,
        host_tag=host_tag,
        service_tag=service_tag,
        vuln_tag=vuln_tag,
    )
    sonar.parseOutputString(json.dumps(response_json))
    print(sonar.get_json())


if __name__ == "__main__":
    main()
