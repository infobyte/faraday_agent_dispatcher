#!/usr/bin/env python
import os
import sys
import subprocess
import socket
import re


def main():
    # If the script is run outside the dispatcher the environment variables are checked.
    # ['EXECUTOR_CONFIG_CRACKMAPEXEC_IP', 'EXECUTOR_CONFIG_CRACKMAPEXEC_USER', 'EXECUTOR_CONFIG_CRACKMAPEXEC_PASS']
    ip = os.environ.get('EXECUTOR_CONFIG_CRACKMAPEXEC_IP')
    user = os.environ.get('EXECUTOR_CONFIG_CRACKMAPEXEC_USER')
    passw = os.environ.get('EXECUTOR_CONFIG_CRACKMAPEXEC_PASS')
    ip = "192.168.0.10"
    if not ip:
        print("IP not provided", file=sys.stderr)
        sys.exit()

    try:
        socket.inet_aton(ip)

    except socket.error:
        print("not valid IP", file=sys.stderr)
        sys.exit()

    if user and passw:
        command = f'cme smw {ip}/24 -u {user} -p {passw}'
        p = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
        output = p.stdout.decode('utf-8')
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
                print(faraday_host_info)
            else:
                pass
    else:
        command = f'cme smb {ip}/24 -u "" -p "" '
        p = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
        output = p.stdout.decode('utf-8')
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
                print(faraday_host_info)
            else:
                pass


if __name__ == '__main__':
    main()
