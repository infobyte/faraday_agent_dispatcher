#!/usr/bin/env python3

import os
import re
import sys
import time
import requests
import datetime
from posixpath import join as urljoin

from faraday_plugins.plugins.repo.nessus.plugin import NessusPlugin

import urllib3

urllib3.disable_warnings()

MAX_TRIES = 1000
TIME_BETWEEN_TRIES = 5


def get_report_name():
    return f"{datetime.datetime.now().timestamp()}-faraday-agent"


def log(msg):
    print(msg, file=sys.stderr)


def get_token_and_x_token(url, username, password):
    token = nessus_login(url, username, password)
    if not token:
        sys.exit(1)

    x_token = get_x_api_token(url, token)
    if not x_token:
        sys.exit(1)
    return token, x_token


def get_scans(url, scan_name, token, x_token):
    headers = {"X-Cookie": f"token={token}", "X-API-Token": x_token}
    response = requests.get(urljoin(url, "scans/"), headers=headers, verify=False, timeout=600)
    if response.status_code != 200:
        log("Could not get scan list. Response from server was" f" {response.status_code}")
        return None
    for scan in response.json().get("scans", []):
        if scan["name"] == scan_name:
            if scan["status"].lower() == "running":
                log(
                    "A scan with the NESSUS_SCAN_NAME provided was found but is running,"
                    "choose a different NESSUS_SCAN_NAME, cancel the scan manually or wait to finish"
                )
                exit(1)
            log(f'Scan {scan_name} was found with id {scan["id"]}')
            return scan["id"]


def nessus_login(url, user, password):
    payload = {"username": user, "password": password}
    response = requests.post(urljoin(url, "session"), payload, verify=False, timeout=60)

    if response.status_code == 200:
        if response.headers["content-type"].lower() == "application/json" and "token" in response.json():
            return response.json()["token"]
        log("Nessus did not response with a valid token")
    else:
        log(f"Login failed with status {response.status_code}")

    return None


def nessus_templates(url, token, x_token):
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token}
    payload = {}
    response = requests.get(
        urljoin(url, "editor/scan/templates"), json=payload, headers=headers, verify=False, timeout=60
    )
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


def nessus_add_target(url, token, x_token, target="", template="basic", name="nessus_scan"):
    headers = {"X-Cookie": f"token={token}", "X-API-Token": x_token}
    templates = nessus_templates(url, token, x_token)
    if not templates:
        log("Templates not available")
        return None
    if template not in templates:
        log(f"Template {template} not valid. Setting basic as default")
        log(f"The templates available are {list(templates.keys())}")
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

    response = requests.post(urljoin(url, "scans"), json=payload, headers=headers, verify=False, timeout=60)
    if (
        response.status_code == 200
        and response.headers["content-type"].lower() == "application" "/json"
        and "scan" in response.json()
        and "id" in response.json()["scan"]
    ):
        return response.json()["scan"]["id"]
    else:
        log(f"Could not create scan. Response from server was " f"{response.status_code}, {response.text}")
    return None


def nessus_scan_run(url, scan_id, token, x_token, username, password):
    headers = {"X-Cookie": f"token={token}", "X-API-Token": x_token}

    response = requests.post(urljoin(url, f"scans/{scan_id}/launch"), headers=headers, verify=False, timeout=600)
    if response.status_code != 200:
        log("Could not launch scan. Response from server was" f" {response.status_code}")
        return None

    status = "running"
    tries = 0
    while status == "running":
        response = requests.get(urljoin(url, f"scans/{scan_id}"), headers=headers, verify=False, timeout=600)
        if response.status_code == 200:
            if (
                response.headers["content-type"].lower() == "application/json"
                and "info" in response.json()
                and "status" in response.json()["info"]
            ):
                status = response.json()["info"]["status"]
            else:
                log("The nessus server give a 200 with unexpected response")
                status = "error"
        else:
            if tries == MAX_TRIES:
                status = "error"
                log(
                    "Could not get scan status. Response from server was "
                    f"{response.status_code}. This error ocurred {tries} "
                    f"time[s]"
                )
            if response.status_code == 401:
                log("The nessus respond with a 401 status code, I'm login and try again")
                # Some scans take too long and the token expires
                token = nessus_login(url, username, password)
                if not token:
                    sys.exit(1)

                x_token = get_x_api_token(url, token)
                if not x_token:
                    sys.exit(1)
                headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token}
            else:
                log(f"Try number {tries}")
            tries += 1
        time.sleep(TIME_BETWEEN_TRIES)
    return status


def nessus_scan_export(url, scan_id, token, x_token, username, password):
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token}

    response = requests.post(
        urljoin(url, f"scans/{scan_id}/export?limit=500000"),
        data={"format": "nessus"},
        headers=headers,
        verify=False,
        timeout=600,
    )
    if (
        response.status_code == 200
        and response.headers["content-type"].lower() == "application" "/json"
        and "token" in response.json()
    ):
        export_token = response.json()["token"]
    else:
        log(f"Export failed with status {response.status_code}")
        return None

    status = "processing"
    tries = 0
    while status != "ready":
        response = requests.get(urljoin(url, f"tokens/{export_token}/status"), verify=False, timeout=600)
        if response.status_code == 200:
            if response.headers["content-type"].lower() == "application/json" and "status" in response.json():
                status = response.json()["status"]
            else:
                log("The nessus server give a 200 with unexpected response")
                status = "error"
        else:
            if tries == MAX_TRIES:
                status = "error"
                log(
                    "Could not get export status. Response from server was "
                    f"{response.status_code}. This error ocurred {tries}"
                    f"time[s]"
                )
            if response.status_code == 401:
                log("The nessus respond with a 401 status code, I'm login and try again")
                # Some scans take too long and the token expires
                nessus_login(url, username, password)
            else:
                log(f"Try number {tries}")

            tries += 1

        time.sleep(TIME_BETWEEN_TRIES)

    log(f"Report export status {status}")
    response = requests.get(
        urljoin(url, f"tokens/{export_token}/download"), allow_redirects=True, verify=False, timeout=60
    )
    if response.status_code == 200:
        return response.content

    return None


def get_x_api_token(url, token):
    x_token = None

    headers = {"X-Cookie": f"token={token}"}

    pattern = (
        r"\{key:\"getApiToken\",value:function\(\)\{"
        r"return\"([a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*-"
        r"[a-zA-Z0-9]*-[a-zA-Z0-9]*)\"\}"
    )
    response = requests.get(urljoin(url, "nessus6.js"), headers=headers, verify=False, timeout=60)

    if response.status_code == 200:
        matched = re.search(pattern, str(response.content))
        if matched:
            x_token = matched.group(1)
        else:
            log("X-api-token not found :(")
    else:
        log("Could not get x-api-token. Response from server was " f"{response.status_code}")

    return x_token


def main():
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
            log("URL not provided")
            sys.exit(1)

    scan_file = None

    token, x_token = get_token_and_x_token(NESSUS_URL, NESSUS_USERNAME, NESSUS_PASSWORD)
    scan_id = get_scans(NESSUS_URL, NESSUS_SCAN_NAME, token, x_token)
    # If NESSUS_SCAN_NAME is not found launch a new scan else relaunch the scan
    if not scan_id:
        if not NESSUS_SCAN_TARGET:
            log("Scan name wasn't found and scan target wasn't provided. Exiting executor")
            exit(1)
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
    status = nessus_scan_run(NESSUS_URL, scan_id, token, x_token, NESSUS_USERNAME, NESSUS_PASSWORD)
    if status != "error":
        token, x_token = get_token_and_x_token(NESSUS_URL, NESSUS_USERNAME, NESSUS_PASSWORD)
        scan_file = nessus_scan_export(NESSUS_URL, scan_id, token, x_token, NESSUS_USERNAME, NESSUS_PASSWORD)

    if scan_file:
        plugin = NessusPlugin(
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
        )
        plugin.parseOutputString(scan_file)
        print(plugin.get_json())
    else:
        log("Scan file was empty")


if __name__ == "__main__":
    main()
