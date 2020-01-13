#!/usr/bin/env python
import os
import re
import sys
import time
import requests

from faraday_plugins.plugins.manager import PluginsManager


def nessus_login(url, user, password):
    payload = {'username': user, 'password': password}
    response = requests.post(url + '/session', payload, verify=False)

    if response.status_code == 200:
        if 'token' in response.json():
            return response.json()['token']
        print('Nessus did not response with a valid token', file=sys.stderr)
    else:
        print('Login failed with status {}'.format(response.status_code), file=sys.stderr)

    return None


def nessus_templates(url, token, x_token='', target=''):
    headers = {'X-Cookie': 'token={}'.format(token), 'X-API-Token': x_token}
    payload = {}
    response = requests.get(url + '/editor/scan/templates', json=payload, headers=headers, verify=False)

    if response.status_code == 200:
        return {template['name']: template['uuid'] for template in response.json()['templates']}

    return None


def nessus_add_target(url, token, x_token='', target='', template='basic', name='nessus_scan'):
    headers = {'X-Cookie': 'token={}'.format(token), 'X-API-Token': x_token}
    templates = nessus_templates(url, token, x_token)
    if not templates:
        print('Templates not available', file=sys.stderr)
        return None
    if template not in templates:
        print('Template {} not valid. Setting basic as default'.format(template), file=sys.stderr)
        template = 'basic'

    payload = {'uuid': '{}'.format(templates[template]),
               'settings': {'name': '{}'.format(name), 'enabled': True, 'text_targets': target, 'agent_group_id': []}}
    response = requests.post(url + '/scans', json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()['scan']['id']
    else:
        print('Could not create scan. Response from server was {}'.format(response.status_code), file=sys.stderr)
    return None


def nessus_scan_run(url, scan_id, token, x_token='', target='basic', policies=''):
    headers = {'X-Cookie': 'token={}'.format(token), 'X-API-Token': x_token}

    response = requests.post(url + '/scans/{scan_id}/launch'.format(scan_id=scan_id), headers=headers, verify=False)
    if response.status_code != 200:
        print("Could not launch scan. Response from server was {}".format(response.status_code), file=sys.stderr)
        return None

    status = 'running'
    tries = 0
    while status == 'running':
        response = requests.get(url + '/scans/{}'.format(scan_id), headers=headers, verify=False)
        if response.status_code == 200:
            tries = 0
            status = response.json()['info']['status']
        else:
            if tries == 3:
                status = 'error'
                tries += 1
            print('Could not get scan status. Response from server was {}. This error ocurred {} time[s]'.format(
                response.status_code, tries), file=sys.stderr)
        time.sleep(5)
    return status


def nessus_scan_export(url, scan_id, token, x_token='', target=''):
    content = None
    headers = {'X-Cookie': 'token={}'.format(token), 'X-API-Token': x_token}

    response = requests.post(url + '/scans/{scan_id}/export?limit=2500'.format(scan_id=scan_id),
                             data={'format': 'nessus'}, headers=headers, verify=False)
    if response.status_code == 200:
        if 'token' in response.json():
            export_token = response.json()['token']
    else:
        print('Export failed with status {}'.format(response.status_code), file=sys.stderr)
        return None

    status = 'processing'
    tries = 0
    while status != 'ready':
        response = requests.get(url + '/tokens/{token}/status'.format(token=export_token), verify=False)
        if response.status_code == 200:
            tries = 0
            status = response.json()['status']
        else:
            if tries == 3:
                status = 'error'
                tries += 1
            print('Could not get export status. Response from server was {}. This error ocurred {} time[s]'.format(
                response.status_code, tries), file=sys.stderr)
        time.sleep(5)

    print('Report export status {}'.format(status), file=sys.stderr)
    response = requests.get(url + '/tokens/{token}/download'.format(token=export_token), allow_redirects=True,
                            verify=False)
    if response.status_code == 200:
        return response.content

    return None


def get_x_api_token(url, token):
    x_token = None

    headers = {'X-Cookie': 'token={}'.format(token)}

    pattern = r"\{key:\"getApiToken\",value:function\(\)\{return\"([a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*)\"\}"
    response = requests.get(url + '/nessus6.js', headers=headers, verify=False)

    if response.status_code == 200:
        matched = re.search(pattern, str(response.content))
        if matched:
            x_token = matched.group(1)
        else:
            print("X-api-token not found :(")
    else:
        print('Could not get x-api-token. Response from server was {}'.format(response.status_code), file=sys.stderr)

    return x_token


def main():
    NESSUS_SCAN_NAME = os.getenv("EXECUTOR_CONFIG_NESSUS_SCAN_NAME", 'my_scan')
    NESSUS_URL = os.getenv("EXECUTOR_CONFIG_NESSUS_URL")  # https://nessus:port
    NESSUS_USERNAME = os.getenv("NESSUS_USERNAME")
    NESSUS_PASSWORD = os.getenv("NESSUS_PASSWORD")
    NESSUS_SCAN_TARGET = os.getenv("EXECUTOR_CONFIG_NESSUS_SCAN_TARGET")  # ip, domain, range
    NESSUS_SCAN_TEMPLATE = os.getenv("EXECUTOR_CONFIG_NESSUS_SCAN_TEMPLATE", "basic")  # name field

    if not NESSUS_URL:
        NESSUS_URL = os.getenv("NESSUS_URL")

    scan_file = None

    token = nessus_login(NESSUS_URL, NESSUS_USERNAME, NESSUS_PASSWORD)
    if not token:
        sys.exit(1)

    x_token = get_x_api_token(NESSUS_URL, token)
    if not x_token:
        sys.exit(1)

    scan_id = nessus_add_target(NESSUS_URL, token, x_token, NESSUS_SCAN_TARGET, NESSUS_SCAN_TEMPLATE, NESSUS_SCAN_NAME)
    if not scan_id:
        sys.exit(1)

    status = nessus_scan_run(NESSUS_URL, scan_id, token, x_token)
    if status != 'error':
        scan_file = nessus_scan_export(NESSUS_URL, scan_id, token, x_token)

    if scan_file:
        plugin = PluginsManager().get_plugin("nessus")
        plugin.parseOutputString(scan_file)
        print(plugin.get_json())
    else:
        print("Scan file was empty")


if __name__ == '__main__':
    main()
