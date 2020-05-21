#!/usr/bin/env python
import os
import sys
import tempfile
import requests
import time
from pathlib import Path
import xml.etree.cElementTree as ET
from faraday_plugins.plugins.repo.burp.plugin import BurpPlugin


def get_issue_data(issue_type_id, json_issue_definitions):
    for info in json_issue_definitions:
        if info['issue_type_id'] == str(issue_type_id):
            json_issue = {
                "issueBackground": info['description'],
                "remediationBackground": info['remediation']
            }
            return json_issue


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['API_KEY', 'TARGET_URL', 'NAMED_CONFIGURATION']
    host_api = 'http://127.0.0.1:1337/'
    api_key = '5D8LHHkhODInxHzEYVEHk86oOx9r8Nge'
    url_target = 'http://pidgr.com/'

    #url_target = os.environ.get('EXECUTOR_CONFIG_TARGET_URL')
    #api_key = os.environ.get('EXECUTOR_CONFIG_API_KEY')
    named_configuration = os.environ.get('NAMED_CONFIGURATION')
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    if not api_key:
        print("API KEY not provided", file=sys.stderr)
        sys.exit()

    if not named_configuration:
        named_configuration = 'Crawl strategy - fastest'

    with tempfile.TemporaryDirectory() as tempdirname:
        tmpdir = Path(tempdirname)
        name_result = tmpdir / 'output.xml'
        rg_issue_definitions = requests.get(f'{host_api}/{api_key}/v0.1/knowledge_base/issue_definitions')
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

        rp_scan = requests.post(f'{host_api}/{api_key}/v0.1/scan', json=json_scan)
        get_location = rp_scan.headers['Location']
        scan_status = ''
        while scan_status != 'succeeded':
            rg_issues = requests.get(f'{host_api}/{api_key}/v0.1/scan/{get_location}')
            issues = rg_issues.json()
            scan_status = issues['scan_status']
            print(scan_status)
            time.sleep(15)

        xml_issues = ET.Element("issues")
        for issue in issues['issue_events']:
            info_issue = get_issue_data(issue['issue']['type_index'], json_issue_definitions)

            xml_issue = ET.SubElement(xml_issues, "issue")
            ET.SubElement(xml_issue, "serialNumber").text = str(issue['issue']['serial_number'])
            ET.SubElement(xml_issue, "type").text = str(issue['issue']['type_index'])
            ET.SubElement(xml_issue, "name").text = issue['issue']['name']
            ET.SubElement(xml_issue, "host").text = issue['issue']['origin']
            ET.SubElement(xml_issue, "path").text = issue['issue']['path']
            ET.SubElement(xml_issue, "location").text = issue['issue']['caption']
            ET.SubElement(xml_issue, "severity").text = issue['issue']['severity']
            ET.SubElement(xml_issue, "confidence").text = issue['issue']['confidence']
            ET.SubElement(xml_issue, "issueBackground").text =info_issue['issueBackground']
            ET.SubElement(xml_issue, "remediationBackground").text = info_issue['remediationBackground']
            xml_request_response = ET.SubElement(xml_issue, "requestresponse")
            ET.SubElement(xml_request_response, "request").text = \
                issue['issue']['evidence'][0]['request_response']['request'][0]['data']
            ET.SubElement(xml_request_response, "response").text = \
                issue['issue']['evidence'][0]['request_response']['response'][0]['data']
            ET.SubElement(xml_request_response, "responseRedirected").text = \
                issue['issue']['evidence'][0]['request_response']['was_redirect_followed']
        tree = ET.ElementTree(xml_issues)
        tree.write(name_result)
        plugin = BurpPlugin()
        with open(name_result, 'r') as f:
            plugin.parseOutputString(f.read())
            print(plugin.get_json())


if __name__ == '__main__':
    main()
