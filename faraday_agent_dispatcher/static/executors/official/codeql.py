import http
import json
import re
import sys
from dataclasses import dataclass

import requests
import os
import logging

logger = logging.getLogger(__name__)

CVE_PATTERN = r".*(CVE-\d{4}-\d{4,7}).*"
CWE_PATTERN = r".*(cwe-\d+)"
REFS_PATTERN = r".*?\((https://.*?)\).*"

token = os.getenv("GITHUB_TOKEN")
owner = os.getenv("GITHUB_OWNER")
repository = os.getenv("EXECUTOR_CONFIG_GITHUB_REPOSITORY")


@dataclass
class SecurityEvent:
    name: str
    description: str
    severity: str
    data: str
    resolution: str
    tags: list
    cwe: list
    cve: list
    refs: list


def get_custom_description(vulnerability_data):
    custom_description = f'{vulnerability_data.get("rule", {}).get("full_description", "N/A")}'
    most_recent_instance_data = vulnerability_data.get("most_recent_instance", {})

    if "location" in most_recent_instance_data:
        location_data = most_recent_instance_data["location"]
        if location_data:
            commit_sha = None
            path = None
            github_link = ""
            if "commit_sha" in most_recent_instance_data:
                commit_sha = most_recent_instance_data["commit_sha"]
            if "path" in most_recent_instance_data["location"]:
                path = most_recent_instance_data["location"]["path"]
            if commit_sha and path:
                github_link = (
                    f"[View it on Github](https://github.com/{owner}/{repository}/blob/{commit_sha}/{path}"
                    f"#L{location_data.get('start_line', 'N/A')}-{location_data.get('end_line', 'N/A')})"
                )

            custom_description = (
                f"{custom_description}\n\n"
                f'Column: {location_data.get("start_column", "N/A")} - {location_data.get("end_column", "N/A")}\n'
                f'Line: {location_data.get("start_line", "N/A")} - {location_data.get("end_line", "N/A")}\n\n'
                f"{github_link}"
            )
    return custom_description


def get_security_event_obj(event_id):
    url = f"https://api.github.com/repos/{owner}/{repository}/code-scanning/alerts/{event_id}"
    auth = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=auth, timeout=60)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network Error: {e}", file=sys.stderr)
        return
    if response.status_code != http.HTTPStatus.OK:
        print(
            f"Response from server {response.status_code} / repo {repository} / owner {owner}",
            file=sys.stderr,
        )
        return None
    security_event_obj = None
    event = response.json()
    if event:
        name = event.get("rule", {}).get("description", "N/A")
        description = get_custom_description(event)
        tags = get_tags(event)
        cwe = get_cwe(event)

        resolution, unparsed_data = parse_resolution(event)

        cve = []
        refs = []
        # unparsed data contains cve and references
        if unparsed_data:
            cve = parse_cve(unparsed_data)
            refs = parse_references(unparsed_data)

        security_event_obj = SecurityEvent(
            name=name,
            description=description,
            tags=tags,
            cwe=cwe,
            severity=event.get("rule", {}).get("security_severity_level", "unclassified"),
            data=event.get("most_recent_instance", {}).get("message", {}).get("text", "N/A"),
            refs=refs,
            cve=cve,
            resolution=resolution,
        )

    return security_event_obj


def get_cwe(alert):
    cwe_set = set()
    for cwe in alert.get("rule", {}).get("tags", []):
        if "cwe-" in cwe:
            try:
                parsed_cwe = re.search(CWE_PATTERN, cwe)[1]
                cwe_set.add(parsed_cwe)
            except ValueError:
                print(f"Could not parse cwe {cwe}", file=sys.stderr)
                continue
    return list(cwe_set)


def get_tags(alert):
    tags = set()
    for tag in alert.get("rule", {}).get("tags", []):
        if "cwe-" in tag:
            continue
        else:
            tags.add(tag)
    if alert.get("most_recent_instance", {}).get("category", "N/A").startswith("/language"):
        tags.add(alert["most_recent_instance"]["category"].split(":")[1])
    return list(tags)


def get_resolution(alert):
    try:
        resolution, _ = alert.get("rule", {}).get("help", "N/A").split("## References")
    except ValueError:
        resolution = alert.get("rule", {}).get("help", "N/A")
    return resolution


def parse_resolution(alert):
    try:
        resolution, unparsed_data = alert.get("rule", {}).get("help", "N/A").split("## References")
    except ValueError:
        resolution = alert.get("rule", {}).get("help", "N/A")
        unparsed_data = ""
    return resolution, unparsed_data


def parse_references(unparsed_data):
    refs = []
    for ref in re.findall(REFS_PATTERN, unparsed_data):
        if "cwe.mitre" in ref:
            continue
        refs.append({"type": "other", "name": ref})
    return refs


def parse_cve(unparsed_data):
    cves_found = re.findall(CVE_PATTERN, unparsed_data)

    return list(set(cves_found))


def get_security_events():
    url = f"https://api.github.com/repos/{owner}/{repository}/code-scanning/alerts"
    auth = {"Authorization": f"Bearer {token}"}
    security_events = []
    page = 1
    while True:
        params = {"page": page, "per_page": 100, "state": "open"}
        response = requests.get(url, headers=auth, params=params, timeout=60)
        if response.status_code != http.HTTPStatus.OK:
            print(
                f"Could not get {owner} alerts "
                f"from {repository} repository. "
                f"Response code was {response.status_code}",
                file=sys.stderr,
            )
            break
        page_events = response.json()
        if not page_events:
            break
        security_events.extend(page_events)
        page += 1
    return security_events


def get_assets_to_create(vulnerability_tags: list, asset_tags: list) -> list:
    security_events = get_security_events()
    assets = list(
        {
            security_event.get("most_recent_instance", {}).get("location", {}).get("path", "N/A")
            for security_event in security_events
        }
    )
    assets_to_create = []

    for asset in assets:
        asset_vulnerabilities = []
        for security_event in security_events:
            if security_event.get("most_recent_instance", {}).get("location", {}).get("path", "N/A") == asset:
                security_event_obj = get_security_event_obj(security_event.get("number", None))
                if not security_event_obj:
                    print(f"Could not get details of event with id {security_event['number']}")
                    continue
                vulnerability = {
                    "name": f"{security_event_obj.name}",
                    "desc": f"{security_event_obj.description}\n",
                    "severity": f"{security_event_obj.severity}",
                    "data": f"{security_event_obj.data}",
                    "type": "Vulnerability",
                    "cwe": security_event_obj.cwe,
                    "cve": security_event_obj.cve,
                    "refs": security_event_obj.refs,
                    "tags": vulnerability_tags + list(security_event_obj.tags),
                    "resolution": security_event_obj.resolution,
                }
                asset_vulnerabilities.append(vulnerability)
        assets_to_create.append(
            {
                "ip": f"{owner}/{repository}/{asset}",
                "description": "",
                "hostnames": [],
                "vulnerabilities": asset_vulnerabilities,
                "tags": asset_tags,
            }
        )
    return assets_to_create


def main():
    vulnerability_tags = os.getenv("AGENT_CONFIG_VULN_TAG") or []
    if vulnerability_tags:
        vulnerability_tags = vulnerability_tags.split(",")
    asset_tags = os.getenv("AGENT_CONFIG_HOSTNAME_TAG") or []
    if asset_tags:
        asset_tags = asset_tags.split(",")
    assets = get_assets_to_create(vulnerability_tags, asset_tags)
    print(json.dumps({"hosts": assets}))


if __name__ == "__main__":
    main()
