#!/usr/bin/env python
import os
import sys
import tempfile
import requests
import time
import socket
from pathlib import Path
import xml.etree.cElementTree as ET
from urllib.parse import urlparse
from faraday_plugins.plugins.repo.burp.plugin import BurpPlugin


def get_ip(host_name):
    try:
        ip = socket.gethostbyname(host_name)
    except socket.error:
        ip = '0.0.0.0'
    return ip


def get_issue_data(issue_type_id, json_issue_definitions):
    desc = 'No information'
    rem = 'No information'

    info_list = [
        info for info in json_issue_definitions
        if info['issue_type_id'] == str(issue_type_id)
    ]

    if len(info_list) == 1:
        if "remediation" in info_list[0]:
            rem = info_list[0]['remediation']

        if "description" in info_list[0]:
            desc = info_list[0]['description']

    json_issue = {
        "issueBackground": desc,
        "remediationBackground": rem
    }

    return json_issue


def generate_xml(issues, name_result, json_issue_definitions):
    xml_issues = ET.Element("issues")
    for issue in issues['issue_events']:
        host_ip = get_ip(issue['issue']['origin'])
        info_issue = get_issue_data(issue['issue']['type_index'],
                                    json_issue_definitions)

        xml_issue = ET.SubElement(xml_issues, "issue")
        ET.SubElement(xml_issue, "serialNumber").text = \
            str(issue['issue']['serial_number'])
        ET.SubElement(xml_issue, "type").text = \
            str(issue['issue']['type_index'])
        ET.SubElement(xml_issue, "name").text = issue['issue']['name']
        ET.SubElement(xml_issue, "host", ip=host_ip).text = \
            issue['issue']['origin']
        ET.SubElement(xml_issue, "path").text = issue['issue']['path']
        ET.SubElement(xml_issue, "location").text = issue['issue']['caption']
        ET.SubElement(xml_issue, "severity").text = issue['issue']['severity']
        ET.SubElement(xml_issue, "confidence").text = \
            issue['issue']['confidence']
        ET.SubElement(xml_issue, "issueBackground").text = \
            info_issue['issueBackground']
        ET.SubElement(xml_issue, "remediationBackground").text = \
            info_issue['remediationBackground']
        xml_request_response = ET.SubElement(xml_issue, "requestresponse")

        try:
            evidence = issue['issue']['evidence'][0]
            request = evidence['request_response']['request'][0]['data']
        except IndexError:
            request = 'No information'
        except KeyError:
            request = 'No information'

        try:
            evidence = issue['issue']['evidence'][0]
            response = evidence['request_response']['response'][0]['data']
        except IndexError:
            response = 'No information'
        except KeyError:
            response = 'No information'

        try:
            evidence = issue['issue']['evidence'][0]['request_response']
            response_redirected = evidence['was_redirect_followed']
        except IndexError:
            response_redirected = 'No information'
        except KeyError:
            response_redirected = 'No information'

        ET.SubElement(xml_request_response, "request").text = request
        ET.SubElement(xml_request_response, "response").text = response
        ET.SubElement(xml_request_response, "responseRedirected").text = \
            response_redirected

    tree = ET.ElementTree(xml_issues)
    tree.write(name_result)


def main():
    # If the script is run outside the dispatcher
    # the environment variables are checked.
    # ['API_KEY', 'TARGET_URL', 'NAMED_CONFIGURATION', 'API_HOST']
    api_host = os.environ.get('EXECUTOR_CONFIG_API_HOST')
    api_key = os.environ.get('EXECUTOR_CONFIG_API_KEY')
    url_target = os.environ.get('EXECUTOR_CONFIG_TARGET_URL')
    named_configuration = os.environ.get('EXECUTOR_CONFIG_NAMED_CONFIGURATION',
                                         None)
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    if not api_key:
        print("API KEY not provided", file=sys.stderr)
        sys.exit()

    if not named_configuration:
        named_configuration = 'Crawl strategy - fastest'

    if not api_host:
        print("API HOST not provided", file=sys.stderr)
        sys.exit()

    url_host = urlparse(api_host)
    if url_host.scheme != 'http' and url_host.scheme != 'https':
        api_host = f'http://{api_host}'

    check_api = requests.get(f'{api_host}/{api_key}/v0.1')
    if check_api.status_code != 200:
        print(f"API gets no response. Status code: {check_api.status_code}",
              file=sys.stderr)
        sys.exit()

    with tempfile.TemporaryDirectory() as tempdirname:
        tmpdir = Path(tempdirname)
        name_result = tmpdir / 'output.xml'
        issue_def = f'{api_host}/{api_key}' \
                    f'/v0.1/knowledge_base/issue_definitions'
        rg_issue_definitions = requests.get(issue_def)
        json_issue_definitions = rg_issue_definitions.json()
        json_scan = {
            "scan_configurations":
                [
                    {
                        "name": named_configuration,
                        "type": "NamedConfiguration"
                    }
                ],
            "scope":
                {
                    "include":
                        [
                            {
                                "rule": url_target,
                                "type": "SimpleScopeDef"
                            }
                        ]
                },
            "urls": [url_target]
        }

        rp_scan = requests.post(f'{api_host}/{api_key}/v0.1/scan',
                                json=json_scan)
        get_location = rp_scan.headers['Location']
        scan_status = ''
        while scan_status != 'succeeded':
            try:
                rg_issues = requests.get(f'{api_host}/{api_key}'
                                         f'/v0.1/scan/{get_location}')
            except ConnectionError:
                print("API gets no response.", file=sys.stderr)
                sys.exit()

            issues = rg_issues.json()
            scan_status = issues['scan_status']
            # Before checking back, wait 15 seconds.
            time.sleep(5)

        generate_xml(issues, name_result, json_issue_definitions)
        plugin = BurpPlugin()
        with open(name_result, 'r') as f:
            plugin.parseOutputString(f.read())
            print(plugin.get_json())


if __name__ == '__main__':
    main()
