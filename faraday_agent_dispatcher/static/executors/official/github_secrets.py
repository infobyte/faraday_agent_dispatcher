#!/usr/bin/env python
import os
import sys
import json
import requests

DEFAULT_SEVERITY_LEVEL = "high"


def make_report(json_response, repo_owner, repo_name, extra_vuln_tags, extra_hostname_tags):

    main_host = {
        "ip": f"github.com/{repo_owner}/{repo_name}",
        "description": f"GitHub Secret Scan performed on {repo_name} by {repo_owner}",
        "vulnerabilities": [],
        "tags": ["github_secrets"] + extra_hostname_tags,
    }

    for detection in json_response:
        if detection["state"] != "open":
            continue

        custom_desc = f"Secret found: **{detection['secret']}**\n\n" f"[View more on Github]({detection['html_url']})"

        vulnerability = {
            "name": f"{detection['secret_type_display_name']}",
            "desc": f"{custom_desc}",
            "severity": DEFAULT_SEVERITY_LEVEL,
            "type": "Vulnerability",
            "status": "open",
            "data": "The severity information was missing, so it was defaulted to 'High'.",
            "tags": ["secret_detection"] + extra_vuln_tags,
        }

        main_host["vulnerabilities"].append(vulnerability)

    data = {"hosts": [main_host]}

    print(json.dumps(data))


def main():

    params_github_token = os.getenv("GITHUB_TOKEN")
    params_github_owner = os.getenv("GITHUB_OWNER")
    params_github_repo = os.getenv("EXECUTOR_CONFIG_GITHUB_REPOSITORY")

    params_vuln_tags = os.getenv("AGENT_CONFIG_VULN_TAG")
    if params_vuln_tags != "":
        params_vuln_tags = params_vuln_tags.split(",")
    else:
        params_vuln_tags = []

    params_host_tags = os.getenv("AGENT_CONFIG_HOSTNAME_TAG")
    if params_host_tags != "":
        params_host_tags = params_host_tags.split(",")
    else:
        params_host_tags = []

    req_header = {
        "Authorization": f"Bearer {params_github_token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Accept": "application/vnd.github+json",
    }
    req_link = f"https://api.github.com/repos/{params_github_owner}/" f"{params_github_repo}/secret-scanning/alerts"

    try:
        req = requests.get(req_link, headers=req_header, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network Error: {e}", file=sys.stderr)
        return

    if req.status_code != 200:
        print(f"ERROR: Network status code {req.status_code}", file=sys.stderr)
        return

    make_report(req.json(), params_github_owner, params_github_repo, params_vuln_tags, params_host_tags)


if __name__ == "__main__":
    main()
