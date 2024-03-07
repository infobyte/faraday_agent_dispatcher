import json
import os
import sys
import requests
from faraday_plugins.plugins.repo.sonarqubeapi.plugin import SonarQubeAPIPlugin

# ATTENTION: We only want to find vulnerabilities. Code smell and bugs doesn't matters for us.
TYPE_VULNS = "VULNERABILITY"
PAGE_SIZE = 500


def get_hotspost_info(session, sonar_qube_url, hotspots_ids):
    hotspots_data = []
    for hotspot_id in hotspots_ids:
        params = {"hotspot": hotspot_id}
        try:
            response = session.get(f"{sonar_qube_url}/api/hotspots/show", params=params)
            hotspots_data.append(response.json())
        except Exception:
            print(
                f"There was an error finding hotspots. Hotspot Key {hotspot_id}; "
                f"Status Code {response.status_code} - {response.content}",
                file=sys.stderr,
            )
            sys.exit(1)
    return hotspots_data


def get_hotspots_ids(session, sonar_qube_url, component_key):
    has_more_hotspots = True
    hotspots_ids = []
    params = {"p": 0, "ps": PAGE_SIZE, "sinceLeakPeriod": False, "status": "TO_REVIEW", "projectKey": component_key}

    while has_more_hotspots:
        params["p"] += 1
        try:
            response = session.get(url=f"{sonar_qube_url}/api/hotspots/search", params=params)
            response_json = response.json()
        except Exception:
            print(
                f"There was an error finding issues. Component Key {component_key}; "
                f"Status Code {response.status_code} - {response.content}",
                file=sys.stderr,
            )
            sys.exit(1)

        hotspots = response_json.get("hotspots", [])
        for hotspot in hotspots:
            hotspots_ids.append(hotspot.get("key", ""))
        total_items = response_json.get("paging", {}).get("total", 0)

        has_more_hotspots = params["p"] * PAGE_SIZE < total_items
    return hotspots_ids


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
        get_hotspot = os.environ.get("EXECUTOR_CONFIG_GET_HOTSPOT", "false").lower() == "true"
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
    if get_hotspot:
        hotspots_ids = get_hotspots_ids(session, sonar_qube_url, component_key)
        if hotspots_ids:
            response_json["hotspots"] = get_hotspost_info(session, sonar_qube_url, hotspots_ids)
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
