import os
import sys
import time
import requests
import datetime
from posixpath import join as urljoin

from faraday_plugins.plugins.repo.appscan.plugin import AppScanPlugin

TIME_BETWEEN_TRIES = 5
BASE_URL = "https://cloud.appscan.com"


def get_report_name():
    return f"{datetime.datetime.now().timestamp()}-faraday-agent"


def get_report(report_id, key_id, key_secret):
    print(report_id)
    token = get_api_token(key_id, key_secret)
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(urljoin(BASE_URL, f"api/v2/Reports/Download/{report_id}"), headers=headers, timeout=60)
    if response.status_code == 200:
        report_file = response.content
    else:
        print("Couldn't generate report. Response from server was " f"{response.status_code}", file=sys.stderr)
        exit(1)
    return report_file


def wait_for_report(report_id, token, key_id, key_secret):
    tries = 0
    status = "Running"
    while status in ("Pending", "Starting", "Running"):
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(urljoin(BASE_URL, f"api/V2/Reports/{report_id}"), headers=headers, timeout=60)
        if response.status_code == 200:
            status = response.json().get("Status")
            tries = 0
        elif response.status_code == 401 and tries == 0:
            token = get_api_token(key_id, key_secret)
            tries += 1
        else:
            status = "error"
            print(
                "Could not get report status. Response from server was " f"{response.status_code}",
                file=sys.stderr,
            )
        time.sleep(TIME_BETWEEN_TRIES)
    return status


def generate_report(execution_id, key_id, key_secret):
    token = get_api_token(key_id, key_secret)
    headers = {"Authorization": f"Bearer {token}"}
    body = {
        "Configuration": {
            "Summary": True,
            "Details": True,
            "Discussion": True,
            "Overview": True,
            "TableOfContent": True,
            "Advisories": True,
            "FixRecommendation": True,
            "History": True,
            "Coverage": True,
            "MinimizeDetails": True,
            "Articles": True,
            "ReportFileType": "xml",
            "Title": "string",
            "Notes": "string",
            "Locale": "string",
        },
        "ApplyPolicies": "All",
    }
    response = requests.post(
        urljoin(BASE_URL, f"api/v2/Reports/Security/ScanExecution/{execution_id}"),
        json=body,
        headers=headers,
        timeout=60,
    )
    if response.status_code == 200:
        report_id = response.json().get("Id")
    else:
        print("Couldn't generate report. Response from server was " f"{response.status_code}", file=sys.stderr)
        exit(1)
    return report_id


def wait_for_execution(execution_id, token, key_id, key_secret, scan_type):
    tries = 0
    status = "Running"
    if scan_type == "DAST":
        url = urljoin(BASE_URL, f"api/v2/Scans/DynamicAnalyzerExecution/{execution_id}")
    else:
        url = urljoin(BASE_URL, f"api/v2/Scans/StaticAnalyzerExecution/{execution_id}")

    while status in ("InQueue", "Running"):
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(url, headers=headers, timeout=60)
        if response.status_code == 200:
            status = response.json().get("Status")
            tries = 0
        elif response.status_code == 401 and tries == 0:
            token = get_api_token(key_id, key_secret)
            tries += 1
        else:
            status = "error"
            print(
                "Could not get scan status. Response from server was " f"{response.status_code}",
                file=sys.stderr,
            )
        time.sleep(TIME_BETWEEN_TRIES)
    return status


def execute_scan(token, scan_id, target, scan_type):
    headers = {"Authorization": f"Bearer {token}"}
    if scan_type == "SAST":
        body = {"FileId": target}
        response = requests.post(
            urljoin(BASE_URL, f"api/v2/Scans/{scan_id}/Executions"), json=body, headers=headers, timeout=60
        )
    else:
        response = requests.post(urljoin(BASE_URL, f"api/v2/Scans/{scan_id}/Executions"), headers=headers, timeout=60)
    if response.status_code == 201:
        return response.json()["Id"]
    elif response.status_code == 403:
        print(
            f"Couldn't execute the scan, {response.json()['Message']}",
            file=sys.stderr,
        )
        exit(1)
    else:
        print(response.json())
        print(
            f"Couldn't execute scan, server response with code {response.status_code}",
            file=sys.stderr,
        )
        exit(1)


def create_and_execute_dast_scan(token, target_url, app_id, scan_name):
    body = {
        "ScanType": "Staging",
        "StartingUrl": target_url,
        "TestPolicy": "Default.policy",
        "TestOptimizationLevel": "NoOptimization",
        "ScanName": scan_name,
        "AppId": app_id,
        "Execute": True,
        "Comment": "Scan Created from faraday",
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(urljoin(BASE_URL, "api/v2/Scans/DynamicAnalyzer"), json=body, headers=headers, timeout=60)

    if response.status_code == 201:
        return response.json()["ExecutionsIds"][0]
    elif response.status_code == 403:
        print(
            f"Couldn't create scan, {response.json()['Message']}",
            file=sys.stderr,
        )
        exit(1)
    else:
        print(
            f"Couldn't create scan {response.status_code}",
            file=sys.stderr,
        )
        exit(1)


def create_and_execute_sast_scan(token, app_target_id, app_id, scan_name):
    body = {
        "ApplicationFileId": app_target_id,
        "ScanName": scan_name,
        "AppId": app_id,
        "Execute": True,
        "Comment": "Scan Created from faraday",
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(urljoin(BASE_URL, "api/v2/Scans/StaticAnalyzer"), json=body, headers=headers, timeout=60)

    if response.status_code == 201:
        return response.json()["ExecutionsIds"][0]
    elif response.status_code == 403:
        print(
            f"Couldn't create scan, {response.json()['Message']}",
            file=sys.stderr,
        )
        exit(1)
    else:
        print(
            f"Couldn't create scan {response.status_code}",
            file=sys.stderr,
        )
        exit(1)


def get_api_token(key_id, key_secret):
    body = {"KeyId": key_id, "KeySecret": key_secret}
    response = requests.post(urljoin(BASE_URL, "api/v2/Account/ApiKeyLogin"), json=body, timeout=60)
    if response.status_code == 200:
        return response.json()["Token"]
    else:
        print("Couldn't generate token")
        exit(1)


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
    HCL_SCAN_NAME = os.getenv("EXECUTOR_CONFIG_HCL_SCAN_NAME", get_report_name())
    HCL_SCAN_TYPE = os.getenv("EXECUTOR_CONFIG_HCL_SCAN_TYPE", "").upper()
    HCL_SCAN_ID = os.getenv("EXECUTOR_CONFIG_HCL_SCAN_ID")
    HCL_SCAN_TARGET = os.getenv("EXECUTOR_CONFIG_HCL_SCAN_TARGET")
    HCL_KEY_ID = os.getenv("HCL_KEY_ID")
    HCL_KEY_SECRET = os.getenv("HCL_KEY_SECRET")
    HCL_APP_ID = os.getenv("HCL_APP_ID")

    if not all([HCL_KEY_ID, HCL_KEY_SECRET, HCL_APP_ID]):
        print("Key id, key secret or app_id missing, check executor configuration", file=sys.stderr)

    if HCL_SCAN_TYPE not in ("DAST", "SAST"):
        print(f"Invalid SCAN TYPE, it mus be DAST OR SAST not {HCL_SCAN_TYPE}", file=sys.stderr)
    if not HCL_SCAN_TARGET and not HCL_SCAN_ID:
        print("Target not specified, the executor needs HCL_SCAN_TARGET or HCL_SCAN_ID", file=sys.stderr)

    token = get_api_token(HCL_KEY_ID, HCL_KEY_SECRET)
    if HCL_SCAN_ID:
        execution_id = execute_scan(token, HCL_SCAN_ID, HCL_SCAN_TARGET, HCL_SCAN_TYPE)
    elif HCL_SCAN_TYPE == "DAST":
        execution_id = create_and_execute_dast_scan(token, HCL_SCAN_TARGET, HCL_APP_ID, HCL_SCAN_NAME)
    else:
        execution_id = create_and_execute_sast_scan(token, HCL_SCAN_TARGET, HCL_APP_ID, HCL_SCAN_NAME)

    status = wait_for_execution(execution_id, token, HCL_KEY_ID, HCL_KEY_SECRET, HCL_SCAN_TYPE)
    if status == "Ready":
        report_id = generate_report(execution_id, HCL_KEY_ID, HCL_KEY_SECRET)
        wait_for_report(report_id, token, HCL_KEY_ID, HCL_KEY_SECRET)
        report_file = get_report(report_id, HCL_KEY_ID, HCL_KEY_SECRET)
        plugin = AppScanPlugin(
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
        )
        plugin.parseOutputString(report_file)
        print(plugin.get_json())
    else:
        print(f"Error, scan result with status {status}", file=sys.stderr)


if __name__ == "__main__":
    main()
