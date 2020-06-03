#!/usr/bin/env python
import os
import sys
import subprocess
import socket
import re


def report(output):
    faraday_host = []
    for line in output.split("\n"):
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
        if ip:
            info_domain = line.find(":")

            faraday_host_info = {
                "hosts": [{
                    "ip": ip[0],
                    "description": f'{line[info_domain:]}',
                    "hostnames": None,
                    "os": "",
                    "services": None,
                    "vulnerabilities": None
                }]}

            faraday_host.append(faraday_host_info)
        else:
            pass
    return faraday_host


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['EXECUTOR_CONFIG_CRACKMAPEXEC_IP', 'EXECUTOR_CONFIG_CRACKMAPEXEC_USER', 'EXECUTOR_CONFIG_CRACKMAPEXEC_PASS']
    ip = os.environ.get('EXECUTOR_CONFIG_CRACKMAPEXEC_IP')
    user = os.environ.get('EXECUTOR_CONFIG_CRACKMAPEXEC_USER')
    passw = os.environ.get('EXECUTOR_CONFIG_CRACKMAPEXEC_PASS')
    if not ip:
        print("IP not provided", file=sys.stderr)
        sys.exit()

    try:
        socket.inet_aton(ip)

    except socket.error:
        print("not valid IP", file=sys.stderr)
        sys.exit()

    command = [
        'cme',
        'smw', f"{ip}/24",
    ]

    if user and passw:
        command += [
            '-u', user,
            '-p', passw,
        ]

    else:
        command += [
            '-u', "",
            '-p', "",
        ]

    p = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
    output = p.stdout.decode('utf-8')
    faraday_json = report(output)
    print(faraday_json)


if __name__ == '__main__':
    main()
