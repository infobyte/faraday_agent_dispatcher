#!/usr/bin/env python
import os
import re
import sys
import time
import requests
import logging

from faraday_plugins.plugins.manager import PluginsManager

def nessus_login(url, user, password):
    payload = {'username': user, 'password': password}
    try:
        ret = requests.post(url + '/session', payload, verify=False).json()
        token = ret['token']
    except Exception as e:
        token = None

    return token

def nessus_templates(url, token, x_token = '', target = ''):
    headers = {'X-Cookie': 'token={}'.format(token), 'X-API-Token': x_token}
    try:
        payload = { }
        r = requests.get(url + '/editor/scan/templates', json=payload, headers=headers, verify=False).json()
        return { t['name']: t['uuid'] for t in r['templates']}
    except Exception as e:
        logging.error (e)

    return


def nessus_add_target(url, token, x_token = '', target = '', template = 'basic', name = 'nessus_scan'):
    headers = {'X-Cookie': 'token={}'.format(token), 'X-API-Token': x_token}
    templates = nessus_templates(url, token, x_token)

    if template not in templates:
        logging.error ('Template {} not valid. Setting basic as default.'.format(template))
        template = 'basic'

    try:
        payload = { 'uuid': '{}'.format(templates[template]), 'settings': { 'name': '{}'.format(name), 'enabled': True, 'text_targets': target, 'agent_group_id': [] }}
        r = requests.post(url + '/scans', json=payload, headers=headers, verify=False).json()
        return r['scan']['id']
    except Exception as e:
        logging.error (e)


def nessus_scan_run(url, scan_id, token, x_token = '', target = 'basic', policies=''):
    headers = {'X-Cookie': 'token={}'.format(token), 'X-API-Token': x_token }
    try:
        s = requests.post(url + '/scans/{scan_id}/launch'.format(scan_id=scan_id), headers=headers, verify=False).json()
        logging.error ('scan', s)
        scan_uuid = s['scan_uuid']

        read = { 'read': False }
        s = requests.get(url + '/scans/{scan_id}'.format(scan_id=scan_id), headers=headers, verify=False)
        #logging.error("scans ", s.json())
        status = s.json()['info']['status']
        while status == 'running':
            logging.error("scan status check ", s)
            time.sleep(5)
            s = requests.get(url + '/scans/{scan_id}'.format(scan_id=scan_id), headers=headers, verify=False)
            status = s.json()['info']['status']
        logging.error("scan status", status)
    except Exception as e:
        logging.error (e)

def nessus_scan_export(url, scan_id, token, x_token = '', target = ''):
    headers = {'X-Cookie': 'token={}'.format(token), 'X-API-Token': x_token}
    try:
        r = requests.post(url + '/scans/{scan_id}/export?limit=2500'.format(scan_id=scan_id), data={'format': 'nessus'}, headers=headers, verify=False).json()

        if r['token']:
            s = requests.get(url + '/tokens/{token}/status'.format(token = r['token']), verify=False).json()
            status = s['status']
            while status != 'ready':
                logging.error("report export status check ", s)
                time.sleep(5)
                s = requests.get(url + '/tokens/{token}/status'.format(token = r['token']), verify=False).json()
                status = s['status']
            logging.error ('report export status ', status)
            r = requests.get(url + '/tokens/{token}/download'.format(token = r['token']), allow_redirects=True, verify=False)
            return r.content
    except Exception as e:
        logging.error (e)

def get_x_api_token(url, token):
    headers = {'X-Cookie': 'token={}'.format(token)} 
    pattern = r"\{key:\"getApiToken\",value:function\(\)\{return\"([a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*)\"\}"
    try:
        r = requests.get(url + '/nessus6.js', headers=headers, verify=False)
        content = str(r.content)
        matched = re.search(pattern, str(r.content))
        if matched:
            x_token = matched.group(1)
    except Exception as e:
        x_token = None
        logging.error(e)

    return x_token

def main():
    """ main function """
    scan_file = ''
    NESSUS_SCAN_NAME = os.getenv("EXECUTOR_CONFIG_NESSUS_SCAN_NAME", 'my_scan')
    NESSUS_URL = os.getenv("EXECUTOR_CONFIG_NESSUS_URL") #  https://nessus:port
    NESSUS_USERNAME = os.getenv("EXECUTOR_CONFIG_NESSUS_USERNAME")
    NESSUS_PASSWORD = os.getenv("EXECUTOR_CONFIG_NESSUS_PASSWORD")
    NESSUS_SCAN_TARGET = os.getenv("EXECUTOR_CONFIG_NESSUS_SCAN_TARGET") #  ip, domain, range
    NESSUS_SCAN_TEMPLATE = os.getenv("EXECUTOR_CONFIG_NESSUS_SCAN_TEMPLATE", "basic") #  name field

    token = nessus_login(NESSUS_URL, NESSUS_USERNAME, NESSUS_PASSWORD)
    if not token:
        sys.exit(1)

    x_token = get_x_api_token(NESSUS_URL, token)
    if not x_token:
        sys.exit(1)

    scan_id = nessus_add_target(NESSUS_URL, token, x_token, NESSUS_SCAN_TARGET, NESSUS_SCAN_TEMPLATE,NESSUS_SCAN_NAME)
    if not scan_id:
        sys.exit(1)

    nessus_scan_run(NESSUS_URL, scan_id, token, x_token)
    scan_file = nessus_scan_export(NESSUS_URL, scan_id, token, x_token)

    plugin = PluginsManager().get_plugin("nessus")
    plugin.parseOutputString(scan_file)
    print(plugin.get_json())

if __name__ == '__main__':
    main()
