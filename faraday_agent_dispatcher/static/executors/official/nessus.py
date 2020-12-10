#!/usr/bin/env python3

import os
import re
import sys
import time
import requests
import datetime

from faraday_plugins.plugins.manager import PluginsManager

MAX_TRIES = 3
TIME_BETWEEN_TRIES = 5


def get_report_name():
    return f"{datetime.datetime.now().timestamp()}-faraday-agent"


def nessus_login(url, user, password):
    payload = {"username": user, "password": password}
    response = requests.post(url + "/session", payload, verify=False)

    if response.status_code == 200:
        if response.headers["content-type"].lower() == "application/json" and "token" in response.json():
            return response.json()["token"]
        print("Nessus did not response with a valid token", file=sys.stderr)
    else:
        print(f"Login failed with status {response.status_code}", file=sys.stderr)

    return None


def nessus_templates(url, token, x_token="", target=""):
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token}
    payload = {}
    response = requests.get(url + "/editor/scan/templates", json=payload, headers=headers, verify=False)

    if (
        response.status_code == 200
        and "templates" in response.json()
        and response.headers["content-type"].lower() == "application/json"
    ):
        return {
            template["name"]: template["uuid"]
            for template in response.json()["templates"]
            if "uuid" in template and "name" in template
        }

    return None


def nessus_add_target(url, token, x_token="", target="", template="basic", name="nessus_scan"):
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token}
    templates = nessus_templates(url, token, x_token)
    if not templates:
        print("Templates not available", file=sys.stderr)
        return None
    if template not in templates:
        print(f"Template {template} not valid. Setting basic as default", file=sys.stderr)
        template = "basic"

    payload = {
        "uuid": "{}".format(templates[template]),
        "settings": {
            "name": "{}".format(name),
            "enabled": True,
            "text_targets": target,
            "agent_group_id": [],
        },
    }

    response = requests.post(url + "/scans", json=payload, headers=headers, verify=False)
    if (
        response.status_code == 200
        and response.headers["content-type"].lower() == "application" "/json"
        and "scan" in response.json()
        and "id" in response.json()["scan"]
    ):
        return response.json()["scan"]["id"]
    else:
        print(
            f"Could not create scan. Response from server was " f"{response.status_code}, {response.text}",
            file=sys.stderr,
        )
    return None


def nessus_scan_run(url, scan_id, token, x_token="", target="basic", policies=""):
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token}

    response = requests.post(url + f"/scans/{scan_id}/launch", headers=headers, verify=False)
    if response.status_code != 200:
        print(
            "Could not launch scan. Response from server was" f" {response.status_code}",
            file=sys.stderr,
        )
        return None

    status = "running"
    tries = 0
    while status == "running":
        response = requests.get(url + f"/scans/{scan_id}", headers=headers, verify=False)
        if response.status_code == 200:
            if (
                response.headers["content-type"].lower() == "application/json"
                and "info" in response.json()
                and "status" in response.json()["info"]
            ):
                status = response.json()["info"]["status"]
            else:
                print(
                    "The nessus server give a 200 with unexpected response",
                    file=sys.stderr,
                )
                status = "error"
        else:
            if tries == MAX_TRIES:
                status = "error"
                print(
                    "Could not get scan status. Response from server was "
                    f"{response.status_code}. This error ocurred {tries} "
                    f"time[s]",
                    file=sys.stderr,
                )
            tries += 1
        time.sleep(TIME_BETWEEN_TRIES)
    return status


def nessus_scan_export(url, scan_id, token, x_token=""):
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token}

    response = requests.post(
        url + f"/scans/{scan_id}/export?limit=2500",
        data={"format": "nessus"},
        headers=headers,
        verify=False,
    )
    if (
        response.status_code == 200
        and response.headers["content-type"].lower() == "application" "/json"
        and "token" in response.json()
    ):
        export_token = response.json()["token"]
    else:
        print(f"Export failed with status {response.status_code}", file=sys.stderr)
        return None

    status = "processing"
    tries = 0
    while status != "ready":
        response = requests.get(url + f"/tokens/{export_token}/status", verify=False)
        if response.status_code == 200:
            if response.headers["content-type"].lower() == "application/json" and "status" in response.json():
                status = response.json()["status"]
            else:
                print(
                    "The nessus server give a 200 with unexpected response",
                    file=sys.stderr,
                )
                status = "error"
        else:
            if tries == MAX_TRIES:
                status = "error"
                print(
                    "Could not get export status. Response from server was "
                    f"{response.status_code}. This error ocurred {tries}"
                    f"time[s]",
                    file=sys.stderr,
                )
            tries += 1

        time.sleep(TIME_BETWEEN_TRIES)

    print("Report export status {}".format(status), file=sys.stderr)
    response = requests.get(url + f"/tokens/{export_token}/download", allow_redirects=True, verify=False)
    if response.status_code == 200:
        return response.content

    return None


def get_x_api_token(url, token):
    x_token = None

    headers = {"X-Cookie": "token={}".format(token)}

    pattern = (
        r"\{key:\"getApiToken\",value:function\(\)\{"
        r"return\"([a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*-"
        r"[a-zA-Z0-9]*-[a-zA-Z0-9]*)\"\}"
    )
    response = requests.get(url + "/nessus6.js", headers=headers, verify=False)

    if response.status_code == 200:
        matched = re.search(pattern, str(response.content))
        if matched:
            x_token = matched.group(1)
        else:
            print("X-api-token not found :(", file=sys.stderr)
    else:
        print(
            "Could not get x-api-token. Response from server was " f"{response.status_code}",
            file=sys.stderr,
        )

    return x_token


def main():
    NESSUS_SCAN_NAME = os.getenv("EXECUTOR_CONFIG_NESSUS_SCAN_NAME", get_report_name())
    NESSUS_URL = os.getenv("EXECUTOR_CONFIG_NESSUS_URL")  # https://nessus:port
    NESSUS_USERNAME = os.getenv("NESSUS_USERNAME")
    NESSUS_PASSWORD = os.getenv("NESSUS_PASSWORD")
    NESSUS_SCAN_TARGET = os.getenv(
        # ip, domain, range
        "EXECUTOR_CONFIG_NESSUS_SCAN_TARGET"
    )
    NESSUS_SCAN_TEMPLATE = os.getenv(
        # name field
        "EXECUTOR_CONFIG_NESSUS_SCAN_TEMPLATE",
        "basic",
    )

    if not NESSUS_URL:
        NESSUS_URL = os.getenv("NESSUS_URL")
        if not NESSUS_URL:
            print("URL not provided", file=sys.stderr)
            sys.exit(1)

    scan_file = None

    token = nessus_login(NESSUS_URL, NESSUS_USERNAME, NESSUS_PASSWORD)
    if not token:
        sys.exit(1)

    x_token = get_x_api_token(NESSUS_URL, token)
    if not x_token:
        sys.exit(1)

    scan_id = nessus_add_target(
        NESSUS_URL,
        token,
        x_token,
        NESSUS_SCAN_TARGET,
        NESSUS_SCAN_TEMPLATE,
        NESSUS_SCAN_NAME,
    )
    if not scan_id:
        sys.exit(1)

    status = nessus_scan_run(NESSUS_URL, scan_id, token, x_token)
    if status != "error":
        scan_file = nessus_scan_export(NESSUS_URL, scan_id, token, x_token)

    if scan_file:
        plugin = PluginsManager().get_plugin("nessus")
        plugin.parseOutputString(scan_file)
        print(plugin.get_json())
    else:
        print("Scan file was empty", file=sys.stderr)


if __name__ == "__main__":
    main()
