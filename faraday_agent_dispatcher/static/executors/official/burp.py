#!/usr/bin/env python
import os
import sys
import tempfile
import requests
import time
import datetime
import socket
import re
import xml.etree.cElementTree as ET
from urllib.parse import urlparse
from faraday_plugins.plugins.repo.burp.plugin import BurpPlugin


def log(message):
    print(f"{datetime.datetime.utcnow()} - BURP: {message}", file=sys.stderr)


def get_ip(url):
    url_data = urlparse(url)
    try:
        ip = socket.gethostbyname(url_data.netloc)
    except socket.error:
        ip = url_data.netloc
    return ip


def get_issue_data(issue_type_id, json_issue_definitions):
    desc = "No information"
    rem = "No information"

    info_list = [info for info in json_issue_definitions if info["issue_type_id"] == str(issue_type_id)]

    if len(info_list) == 1:
        if "remediation" in info_list[0]:
            rem = info_list[0]["remediation"]

        if "description" in info_list[0]:
            desc = info_list[0]["description"]

    json_issue = {"issueBackground": desc, "remediationBackground": rem}

    return json_issue


def generate_xml(issues, name_result, json_issue_definitions):
    xml_issues = ET.Element("issues")
    for issue in issues["issue_events"]:
        host_ip = get_ip(issue["issue"]["origin"])
        info_issue = get_issue_data(issue["issue"]["type_index"], json_issue_definitions)

        xml_issue = ET.SubElement(xml_issues, "issue")
        ET.SubElement(xml_issue, "serialNumber").text = str(issue["issue"]["serial_number"])
        ET.SubElement(xml_issue, "type").text = str(issue["issue"]["type_index"])
        ET.SubElement(xml_issue, "name").text = issue["issue"]["name"]
        ET.SubElement(xml_issue, "host", ip=host_ip).text = issue["issue"]["origin"]
        ET.SubElement(xml_issue, "path").text = issue["issue"]["path"]
        ET.SubElement(xml_issue, "location").text = issue["issue"]["caption"]
        ET.SubElement(xml_issue, "severity").text = issue["issue"]["severity"]
        ET.SubElement(xml_issue, "confidence").text = issue["issue"]["confidence"]
        ET.SubElement(xml_issue, "issueBackground").text = info_issue["issueBackground"]
        ET.SubElement(xml_issue, "remediationBackground").text = info_issue["remediationBackground"]
        xml_request_response = ET.SubElement(xml_issue, "requestresponse")

        try:
            evidence = issue["issue"]["evidence"][0]
            request = evidence["request_response"]["request"][0]["data"]
        except IndexError:
            request = "No information"
        except KeyError:
            request = "No information"

        try:
            evidence = issue["issue"]["evidence"][0]
            response = evidence["request_response"]["response"][0]["data"]
        except IndexError:
            response = "No information"
        except KeyError:
            response = "No information"

        try:
            evidence = issue["issue"]["evidence"][0]["request_response"]
            response_redirected = evidence["was_redirect_followed"]
        except IndexError:
            response_redirected = "No information"
        except KeyError:
            response_redirected = "No information"

        ET.SubElement(xml_request_response, "request").text = request
        ET.SubElement(xml_request_response, "response").text = response
        ET.SubElement(xml_request_response, "responseRedirected").text = response_redirected

    tree = ET.ElementTree(xml_issues)
    tree.write(name_result)


def main():
    # If the script is run outside the dispatcher
    # the environment variables are checked.
    # ['TARGET_URL', 'NAMED_CONFIGURATION']
    BURP_HOST = os.getenv("BURP_HOST")
    BURP_API_KEY = os.getenv("BURP_API_KEY")
    TARGET_URL = os.getenv("EXECUTOR_CONFIG_TARGET_URL")
    NAMED_CONFIGURATION = os.getenv("EXECUTOR_CONFIG_NAMED_CONFIGURATION")
    PULL_INTERVAL = 15
    host_re = re.compile(r"^https?://.+:\d+$")
    target_re = re.compile(r"^https?://.+")
    if not TARGET_URL:
        log("URL not provided")
        sys.exit()

    if not BURP_API_KEY:
        log("BURP_API_KEY not provided")
        sys.exit()

    if not NAMED_CONFIGURATION:
        NAMED_CONFIGURATION = "Crawl strategy - fastest"

    if not BURP_HOST:
        log("BURP_HOST not provided")
        sys.exit()

    if not host_re.match(BURP_HOST):
        log(f"BURP_HOST is invalid, must be http(s)://HOST:PORT [{BURP_HOST}]")
        sys.exit()

    check_api = requests.get(f"{BURP_HOST}/{BURP_API_KEY}/v0.1")
    if check_api.status_code != 200:
        log(f"API gets no response. Status code: {check_api.status_code}")
        sys.exit()
    # handling multiple targets, can be provided with: "https://example.com, https://test.com"
    targets = TARGET_URL.replace(" ", "").split(",")
    scope_include = []
    targets_urls = []
    for target in targets:
        if target_re.match(target):
            scope_include.append({"rule": target, "type": "SimpleScopeDef"})
            targets_urls.append(target)
        else:
            log(f"WARNING: Discard invalid target: {target}")

    if targets_urls:
        log(f"Scanning {targets_urls} with burp on: {BURP_HOST}")
        with tempfile.TemporaryFile() as tmp_file:
            issue_def = f"{BURP_HOST}/{BURP_API_KEY}" f"/v0.1/knowledge_base/issue_definitions"
            rg_issue_definitions = requests.get(issue_def)
            json_issue_definitions = rg_issue_definitions.json()
            json_scan = {
                "scan_configurations": [{"name": NAMED_CONFIGURATION, "type": "NamedConfiguration"}],
                "scope": {"include": scope_include},
                "urls": targets_urls,
            }

            rp_scan = requests.post(f"{BURP_HOST}/{BURP_API_KEY}/v0.1/scan", json=json_scan)
            if rp_scan.status_code == 201:
                location = rp_scan.headers["Location"]
                scan_status = ""
                while scan_status not in ("succeeded", "failed"):
                    try:
                        rg_issues = requests.get(f"{BURP_HOST}/{BURP_API_KEY}" f"/v0.1/scan/{location}")
                    except ConnectionError:
                        log("API gets no response.")
                        sys.exit()

                    issues = rg_issues.json()
                    scan_status = issues["scan_status"]
                    log(f"Waiting for results [{scan_status}]")
                    time.sleep(PULL_INTERVAL)

                log("Scan finished")
                generate_xml(issues, tmp_file, json_issue_definitions)
                plugin = BurpPlugin()
                tmp_file.seek(0)
                plugin.parseOutputString(tmp_file.read())
                print(plugin.get_json())
            else:
                log(f"ERROR: {rp_scan.text}")

    else:
        log("No targets to scan.")
        sys.exit()


if __name__ == "__main__":
    main()
