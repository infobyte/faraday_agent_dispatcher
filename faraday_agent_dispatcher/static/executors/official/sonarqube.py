import json
import os
import sys
import requests
from faraday_plugins.plugins.repo.sonarqubeapi.plugin import SonarQubeAPIPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters

# ATTENTION: We only want to find security-related issues, maintainability and reliability don't matter for us
ISSUE_IMPACT = "SECURITY"
PAGE_SIZE = 500


def get_hotspots_info(session, sonar_qube_url, hotspot_ids):
    hotspots_data = []
    for hotspot_id in hotspot_ids:
        params = {"hotspot": hotspot_id}
        try:
            response = session.get(f"{sonar_qube_url}/api/hotspots/show", params=params, timeout=30)
        except requests.RequestException as e:
            print(f"Network error fetching hotspot {hotspot_id}: {e}", file=sys.stderr)
            continue
        if response.status_code != 200:
            print(
                f"SonarQube returned an error for hotspot {hotspot_id}: " f"{response.status_code} - {response.text}",
                file=sys.stderr,
            )
            continue
        try:
            data = response.json()
        except ValueError:
            print(f"Invalid JSON in response for hotspot {hotspot_id}: {response.text}", file=sys.stderr)
            continue
        hotspots_data.append(data)
    return hotspots_data


def get_hotspots_ids(session, sonar_qube_url, component_key):
    has_more_hotspots = True
    hotspots_ids = []
    params = {"p": 1, "ps": PAGE_SIZE, "sinceLeakPeriod": False, "status": "TO_REVIEW", "projectKey": component_key}

    while has_more_hotspots:
        try:
            response = session.get(url=f"{sonar_qube_url}/api/hotspots/search", params=params, timeout=30)
        except requests.RequestException as e:
            print(f"Network error fetching component key {component_key}: {e}", file=sys.stderr)
            return hotspots_ids
        if response.status_code != 200:
            print(
                f"SonarQube returned an error for component key {component_key}: "
                f"{response.status_code} - {response.text}",
                file=sys.stderr,
            )
            return hotspots_ids
        try:
            response_json = response.json()
        except ValueError:
            print(f"Invalid JSON in response for component key {component_key}: {response.text}", file=sys.stderr)
            return hotspots_ids

        hotspots = response_json.get("hotspots", [])
        for hotspot in hotspots:
            hotspots_ids.append(hotspot.get("key", ""))
        total_items = response_json.get("paging", {}).get("total", 0)

        has_more_hotspots = params["p"] * PAGE_SIZE < total_items
        params["p"] += 1
    return hotspots_ids


def main():
    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_TOKEN', 'EXECUTOR_CONFIG_URL', 'EXECUTOR_CONFIG_PROJECT']
    agent_config = get_common_parameters()

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
    print(token, file=sys.stderr)

    # Issues api config
    page = 1
    has_more_vulns = True

    vulnerabilities = []
    response_json = {}

    while has_more_vulns:
        params = {"impactSoftwareQualities": ISSUE_IMPACT, "p": page, "ps": PAGE_SIZE}
        if component_key:
            params["componentKeys"] = component_key
        try:
            response = session.get(url=f"{sonar_qube_url}/api/issues/search", params=params, timeout=30)
        except requests.RequestException as e:
            print(f"Network error fetching issues. Component key {component_key}: {e}", file=sys.stderr)
            break
        if response.status_code != 200:
            print(
                f"SonarQube returned an error for issue search. Component key {component_key}: "
                f"{response.status_code} - {response.text}",
                file=sys.stderr,
            )
            break
        try:
            response_json = response.json()
        except ValueError:
            print(
                f"Invalid JSON in response for issue search. " f"Component key {component_key}: {response.text}",
                file=sys.stderr,
            )
            continue

        issues = response_json.get("issues", [])
        vulnerabilities.extend(issues)
        total_items = response_json.get("paging", {}).get("total", 0)

        has_more_vulns = page * PAGE_SIZE < total_items
        page += 1

    response_json["issues"] = vulnerabilities
    if get_hotspot:
        hotspots_ids = get_hotspots_ids(session, sonar_qube_url, component_key)
        if hotspots_ids:
            response_json["hotspots"] = get_hotspots_info(session, sonar_qube_url, hotspots_ids)

    sonar = SonarQubeAPIPlugin(**agent_config.to_plugin_kwargs())
    sonar.parseOutputString(json.dumps(response_json))
    print(sonar.get_json())


if __name__ == "__main__":
    main()
