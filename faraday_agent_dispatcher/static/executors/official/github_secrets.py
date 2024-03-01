#!/usr/bin/env python
import os
import re
import sys
import json
import requests

DEFAULT_SEVERITY_LEVEL = "high"  # default severity level assigned by the script


def fail_m(msg):
    print(msg, file=sys.stderr)

def html_locations_finder(locations_api_link, headers, git_env):
    repo_owner, repo_name = git_env
    html_locations = set()
    raw_locations = requests.get(locations_api_link, headers=headers)
    for location in raw_locations.json():
        if location["type"] == "commit":
            html_locations.add(f"https://github.com/{repo_owner}/{repo_name}/{location['details']['path']}")
            continue
        _url = location["details"][ list(location['details'].keys())[0] ]
        if not "api.github.com" in _url:
            html_locations.add(_url)
            continue
        _apidat = requests.get(_url, headers=headers)

        if (_apidat.status_code != 200):
            return None

        _apidat = _apidat.json()
        html_locations.add(_apidat["html_url"])

    return [x.replace("https://", "") for x in html_locations]

def make_report(json_response, git_env):
    faraday_hosts = []

    for detection in json_response:
        if detection["state"] != "open":
            continue

        repo_owner, repo_name = git_env

        custom_desc = (
            f"Secret Information\n"
            f"Secret found: {detection['secret']}\n"
            f"Secret type: {detection['secret_type']}\n"
            f"Validity: {detection['validity']}\n\n"

            f"Detection Information\n"
            f"Id: {detection['number']}\n"
            f"Created at: {detection['created_at']}\n"
            f"Last update: {'Never updated' if (detection['updated_at'] == None) else detection['updated_at']}\n"
        )

        vulnerability = {
            "name": f"{detection['secret_type_display_name']}",
            "desc": f"{custom_desc}",
            "severity": DEFAULT_SEVERITY_LEVEL,
            "type": "Vulnerability",
            "status": "open",
            "data": "The severity information was missing, so it was defaulted to 'High'.",
            "tags": "secret_detection",
            "refs": [
                detection["html_url"]
            ],
        }

        for host_ip in detection["locs"]:
            if (host_ip in [item['ip'] for item in faraday_hosts]):
                index = [x[0] for x in enumerate(faraday_hosts) if (x[1]['ip'] == host_ip)][0]
                faraday_hosts[index]["vulnerabilities"].append(vulnerability)
            else:
                faraday_hosts.append({
                        "ip": host_ip,
                        "description": f"Secret detection on {repo_name} by {repo_owner}",
                        "vulnerabilities": [vulnerability],
                        "tags": "github_secrets",
                    }
                )

    data = {"hosts": faraday_hosts}
    print(json.dumps(data))

def main():
    params_github_token = os.getenv("EXECUTOR_CONFIG_GITHUB_REPOSITORY")
    params_github_owner = os.getenv("GITHUB_OWNER")
    params_github_repo  = os.getenv("GITHUB_TOKEN")

    gitenv_data = [params_github_owner, params_github_repo]

    req_header = {'Authorization': 'Bearer ' + params_github_token, 'X-GitHub-Api-Version': '2022-11-28', 'Accept': 'application/vnd.github+json'}
    req_link = f"https://api.github.com/repos/{params_github_owner}/{params_github_repo}/secret-scanning/alerts"

    req = requests.get(req_link, headers=req_header)

    if req.status_code != 200:
        fail_m("Failed: cannot reach github.com")
        return

    req_json = req.json()

    for i in range(len(req_json)):
        locs = html_locations_finder(req_json[i]["locations_url"], req_header, gitenv_data)
        if locs == None:
            fail_m("Failed: cannot reach github.com")
            return
        req_json[i]["locs"] = locs

    make_report(req_json, gitenv_data)


if __name__ == "__main__":
    main()
