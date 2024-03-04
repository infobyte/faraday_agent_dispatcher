#!/usr/bin/env python
import os
import re
import sys
import json
import requests

DEFAULT_SEVERITY_LEVEL = "high"

glob_repo_owner, glob_repo_name = "", ""


def make_report(json_response):

    main_host = {
        "ip": f"github.com/{glob_repo_owner}/{glob_repo_name}",
        "description": f"GitHub Secret Scan performed on {glob_repo_name} by {glob_repo_owner}",
        "vulnerabilities": [],
        "tags": "github_secrets",
    }

    for detection in json_response:
        if detection["state"] != "open":
            continue

        custom_desc = (
            f"Secret detected: {detection['secret']}\n\n"
            f"[View more on Github]({detection['html_url']})"
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
            ]
        }

        main_host["vulnerabilities"].append(vulnerability)

    data = {"hosts": main_host}

    print(json.dumps(data))


def main():
    
    params_github_token = os.getenv("GITHUB_TOKEN")
    params_github_owner = os.getenv("GITHUB_OWNER")
    params_github_repo  = os.getenv("EXECUTOR_CONFIG_GITHUB_REPOSITORY")

    global glob_repo_owner, glob_repo_name
    glob_repo_owner, glob_repo_name = params_github_owner, params_github_repo

    req_header = {'Authorization': 'Bearer ' + params_github_token, 'X-GitHub-Api-Version': '2022-11-28', 'Accept': 'application/vnd.github+json'}
    req_link = f"https://api.github.com/repos/{params_github_owner}/{params_github_repo}/secret-scanning/alerts"

    try:
        req = requests.get(req_link, headers=req_header)
    except Exception:
        print(f"ERROR: Network Error, can't reach github.com", file=sys.stderr)
        return

    if req.status_code != 200:
        print(f"ERROR: Network status code {req.status_code}", file=sys.stderr)
        return

    make_report(req.json())


if __name__ == "__main__":
    main()
