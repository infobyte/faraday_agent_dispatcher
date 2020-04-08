#!/usr/bin/env python3

import os
import json
import socket
import struct

import requests

from shodan import Shodan
from shodan.exception import APIError

SHODAN_API_KEY = ""
TARGET = os.environ.get('EXECUTOR_CONFIG_TARGET')


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def fetch_from_shodan():
    try:
        api = Shodan(SHODAN_API_KEY)
        results = api.host(TARGET)
        services = []
        vulns = []
        for port in results["ports"]:
            services.append({
                "name": "unknown",
                "port": port,
                "protocol": "unknown"
            })

        for cve in results.get("vulns", []):
            cve_data_url = f'https://cve.circl.lu/api/cve/{cve}'
            cve_data = requests.get(cve_data_url).json()
            if 'cvss' not in cve_data or 'ip' not in cve_data:
                continue
            name = cve
            severity = 'med'
            # exampel severity mapping
            if cve_data['cvss'] > 6.5:
                severity = 'high'
            if cve_data['cvss'] > 8:
                severity = 'critical'
            if cve_data['capec']:
                name = cve_data['capec'][0]['name']
                desc = cve_data['capec'][0]['summary']

            vulns.append({
                "name": name,
                "desc": desc,
                "severity": severity,
                "refs": cve_data['references'],
                "type": "Vulnerability",
            })

        faraday_info = {
            "hosts": [{
                "ip": int2ip(results['ip']),
                "description": "hsot found using shodan api",
                "hostnames": results.get('hostnames', []),
                "os": results.get('os') or '',
                "services": services,
                "vulnerabilities": vulns
            }]}

        print(json.dumps(faraday_info))

    except APIError as exception:
        print('Error: {}'.format(exception))


if __name__ == '__main__':
    fetch_from_shodan()
