# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import json
import sys
import subprocess

import asyncio

host_data = {
    "ip": "AWS - ",
    "description": "AWS test",
    "hostnames": ["aws-test.com", "aws-test2.org"],
}

level_map = {
    "Level 2": "high",
    "Level 1": "med",
}

END = False
MIN = 5


def get_check(control_str: str):
    a = control_str.split("]")
    return a[0][1:]


def vuln_parse(json_str: str):
    dic = json.loads(json_str)
    if dic["Status"] == "Pass":
        return None
    vuln = dict()
    vuln["name"] = dic["Control"]
    vuln["desc"] = dic["Message"]
    vuln["severity"] = level_map[dic["Level"]]
    vuln["type"] = "Vulnerability"
    vuln["impact"] = {
        "accountability": True,
        "availability": False,
    }
    vuln["policy_violations"] = [f"{get_check(dic['Control'])}:{dic['Control ID']}"]
    return vuln


REGION = None


def process_bytes_line(line):
    parts = line.decode("utf-8").split("\n")
    parts = list(filter(len, parts))
    global REGION
    if len(parts):
        if REGION is None:
            REGION = json.loads(parts[0])["Region"]
        return list(filter(lambda v: v is not None, [vuln_parse(part) for part in parts]))


async def main():

    command = f"{os.path.expanduser('~/tools/prowler/prowler')} -b -M json"
    prowler_cmd = await asyncio.create_subprocess_shell(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    to_send_vulns = []
    end = False
    while not end:
        line = await prowler_cmd.stdout.readline()
        if len(line) > 0:
            to_send_vulns.extend(process_bytes_line(line))
        else:
            end = True

        if len(to_send_vulns) >= MIN or (end and len(to_send_vulns) > 0):
            host_data_ = host_data.copy()
            host_data_["ip"] = f"{host_data_['ip']}{REGION}"
            host_data_["vulnerabilities"] = to_send_vulns
            data = dict(hosts=[host_data_])
            print(json.dumps(data))
            to_send_vulns = []


def main_sync():
    r = asyncio.run(main())
    sys.exit(r)  # pragma: no cover


if __name__ == "__main__":
    main_sync()
