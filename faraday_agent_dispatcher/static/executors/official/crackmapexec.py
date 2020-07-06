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
        ip_port = re.findall(r'[0-9]+(?:\.[0-9]+){3}(?:\:[0-9]+)', line)
        os = []
        credential_passw = ''

        if line.find('Unix'):
            os.append('Unix')
        elif line.find('Windows'):
            os.append('Windows')

        if ip_port:
            sep = ip_port[0].index(':')
            port = ip_port[0][sep+1:]

        if line.find('(Pwn3d!)'):
            info_domain = line.find("[+]")
            credential_passw = f'{line[info_domain:]}'

        if ip:
            faraday_host_info = {
                "hosts": [{
                    "ip": ip[0],
                    "description":'CrackMapExec',
                    "hostnames": None,
                    "os": os,
                    "credentials": [
                        {
                            "name": "credential",
                            "password": credential_passw
                        }
                    ],
                    "services": [
                        {
                            "name": "",
                            "port": int(port),
                            "protocol": ""
                        }
                    ],
                    "vulnerabilities": None
                }]}

            faraday_host.append(faraday_host_info)
        else:
            pass

    return faraday_host


def main():
    # If the script is run outside the dispatcher
    # the environment variables are checked.
    # ['EXECUTOR_CONFIG_CRACKMAPEXEC_IP',
    # 'EXECUTOR_CONFIG_CRACKMAPEXEC_USER',
    # 'EXECUTOR_CONFIG_CRACKMAPEXEC_PASS']
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
        'crackmapexec',
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

    p = subprocess.run(command, stdout=subprocess.PIPE, shell=False)
    output = p.stdout.decode('utf-8')
    faraday_json = report(output)
    print(faraday_json)


if __name__ == '__main__':
    main()
