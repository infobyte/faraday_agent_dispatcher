#!/usr/bin/env python
import re
import json
import subprocess


host_data = {"ip": "{}", "description": "{}", "hostnames": []}

service_data = {"name": "smb", "port": 445, "protocol": "tcp", "version": "{}"}

vuln_data = {
    "name": "{}",
    "desc": "test",
    "severity": "critical",
    "type": "Vulnerability",
    "impact": {
        "accountability": True,
        "availability": True,
        "integrity": True,
        "confidentiality": True,
    },
    "refs": [],
}

"""You need to clone and install

git@github.com:lgandx/Responder.git

"""
RESPONDER_PATH = "PATH_TO/Responder/tools/RunFinger.py"

cmd = [
    "python2",
    RESPONDER_PATH,
    "-i",
    "192.168.20.1/24",
    "-a",
]


output_pattern = re.compile(
    r"Retrieving information for (?P<ip>.*)...\nSMB signing: "
    r"(?P<signing>False|True)\nNull Sessions Allowed: "
    r"(?P<null_session>False|True)\n(Vulnerable to MS17-010: "
    r"(?P<ms17>True|False)\n)?Server Time: (?P<time>.*)\nOS version: "
    r"'(?P<os>.*)'\nLanman Client: '(?P<version>.*)'\nMachine Hostname: "
    r"'(?P<hostname>.*)'\nThis machine is part of the '(?P<workgroup>.*)' "
    r"domain"
)


if __name__ == "__main__":
    results = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    data = dict()
    hosts = []
    for result in results.stdout.split("\n\n"):
        if result:
            m = output_pattern.match(result)
            if m:
                # host
                host_data_ = host_data.copy()
                host_data_["ip"] = host_data_["ip"].format(m.group("ip"))
                host_data_["description"] = host_data_["description"].format(m.group("os"))
                host_data_["hostnames"] = [m.group("hostname")]

                # service
                service_data_ = service_data.copy()
                service_data_["version"] = service_data_["version"].format(m.group("version"))
                host_data_["services"] = [service_data_]

                print(service_data_)

                # vuln
                host_data_["vulnerabilities"] = []

            if m.group("signing") == "False":
                vuln_data_ = vuln_data.copy()
                vuln_data_["name"] = "SMB Signing not required"
                vuln_data_["desc"] = (
                    "Signing is not required on the remote "
                    "SMB server.\nSigning is not required "
                    "on the remote SMB server. An "
                    "unauthenticated, remote attacker can "
                    "exploit this to conduct "
                    "man-in-the-middle attacks against the "
                    "SMB server."
                )
                vuln_data_["refs"] = [
                    "https://support.microsoft.com/en-us/help/887429/" "overview-of-server-message-block-signing",
                    "http://technet.microsoft.com/en-us/library/cc731957.aspx",
                    "https://www.samba.org/samba/docs/current/man-html" "/smb.conf.5.html",
                ]

                vuln_data_["severity"] = "medium"

                vuln_data_["impact"]["accountability"] = False
                vuln_data_["impact"]["availability"] = False
                vuln_data_["impact"]["integrity"] = False
                vuln_data_["impact"]["confidentiality"] = False

                host_data_["vulnerabilities"].append(vuln_data_)

            if m.group("ms17") == "True":
                vuln_data_ = vuln_data.copy()
                vuln_data_["name"] = "MS17-010: Security Update for " "Microsoft Windows SMB Server"
                vuln_data_["desc"] = (
                    "The remote Windows host is missing a security update. "
                    "It is, therefore, affected by the following "
                    "vulnerabilities : \n\n"
                    "- Multiple remote code execution vulnerabilities "
                    "exist in Microsoft Server Message Block 1.0 (SMBv1) "
                    "due to improper handling of certain requests. An "
                    "unauthenticated, remote attacker can exploit these "
                    "vulnerabilities, via a specially crafted packet, to "
                    "execute arbitrary code. (CVE-2017-0143, "
                    "CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, "
                    "CVE-2017-0148)\n\n"
                    "- An information disclosure vulnerability exists in "
                    "Microsoft Server Message Block 1.0 (SMBv1) due to "
                    "improper handling of certain requests. An "
                    "unauthenticated, remote attacker can exploit this, via "
                    "a specially crafted packet, to disclose sensitive "
                    "information. (CVE-2017-0147)\n\n"
                    "ETERNALBLUE, ETERNALCHAMPION, ETERNALROMANCE, and "
                    "ETERNALSYNERGY are four of multiple Equation Group "
                    "vulnerabilities and exploits disclosed on 2017/04/14 "
                    "by a group known as the Shadow Brokers. WannaCry / "
                    "WannaCrypt is a ransomware program utilizing the "
                    "ETERNALBLUE exploit, and EternalRocks is a worm that "
                    "utilizes seven Equation Group vulnerabilities. Petya "
                    "is a ransomware program that first utilizes "
                    "CVE-2017-0199, a vulnerability in Microsoft Office, "
                    "and then spreads via ETERNALBLUE."
                )
                vuln_data_["refs"] = [
                    "https://www.rapid7.com/db/modules/exploit/windows/smb/" "ms17_010_eternalblue",
                    "CVE-2017-0143",
                    "CVE-2017-0144",
                    "CVE-2017-0145",
                    "CVE-2017-0146",
                    "CVE-2017-0147",
                    "CVE-2017-0148",
                ]
                host_data_["vulnerabilities"] = [vuln_data_]

            hosts.append(host_data_)

            data = dict(hosts=hosts)
    print(json.dumps(data))
