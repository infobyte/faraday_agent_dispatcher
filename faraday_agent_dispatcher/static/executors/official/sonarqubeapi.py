#!/usr/bin/env python
import json
import os
import sys
import requests
from faraday_plugins.plugins.manager import PluginsManager

#ATTENTION: We only want to find vulnerabilities. Code smell and bugs doesn't matters for us.
TYPE_VULNS = 'VULNERABILITY'
PAGE_SIZE = 500

def main():
    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_TOKEN', 'EXECUTOR_CONFIG_URL', 'EXECUTOR_CONFIG_PROJECT']
    try:
        sonar_qube_url = os.environ["EXECUTOR_CONFIG_URL"]
        token = os.environ["EXECUTOR_CONFIG_TOKEN"]
        component_key = os.environ['EXECUTOR_CONFIG_COMPONENT_KEY']
    except KeyError:
        print("Environment variable not found", file=sys.stderr)
        sys.exit()

    session = requests.Session()

    # ATTENTION: SonarQube API requires an empty password when auth method is via token
    session.auth = (token, '')

    # Issues api config
    page = 0
    has_more_vulns = True

    vulnerabilities = []

    while has_more_vulns:
        page += 1

        params = {
            'componentKeys': component_key,
            'types': TYPE_VULNS,
            'p': page,
            'ps': PAGE_SIZE
        }

        response = session.get(
            url=f'{sonar_qube_url}/api/issues/search',
            params=params,
        )

        if not response.ok:
            print(
                f"There was an error finding issues. Component Key {component_key}; Status Code {response.status_code} - {response.content}",
                file=sys.stderr)
            sys.exit()

        response_json = response.json()
        issues = response_json.get('issues')
        vulnerabilities.extend(issues)
        total_items = response_json.get('paging').get('total')

        has_more_vulns = page * PAGE_SIZE < total_items

    plugin = PluginsManager().get_plugin("sonarqubeapi")

    vulns_json = json.dumps({'issues': vulnerabilities})
    plugin.parseOutputString(vulns_json)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
