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
import subprocess

host_data = {
    "ip": "AWS - ",
    "description": "AWS test",
    "hostnames": ["aws-test.com", "aws-test2.org"]
}

level_map = {
    "Level 2" : "high",
    "Level 1" : "med",
}

def get_check(control_str: str):
    a = control_str.split(']')
    return a[0][1:]

def vuln_parse(json_str :str):
    dic = json.loads(json_str)
    if dic['Status'] == "Pass":
        return None
    vuln = dict()
    vuln['name'] = dic['Control']
    vuln['desc'] = dic['Message']
    vuln['severity'] = level_map[dic['Level']]
    vuln['type'] = 'Vulnerability'
    vuln['impact'] = {
        'accountability': True,
        'availability': False,
    }
    vuln['policy_violations'] = [f"{get_check(dic['Control'])}:{dic['Control ID']}"]
    return vuln

if __name__ == '__main__':

    command = [os.path.expanduser('~/tools/prowler/prowler'), '-b', '-M', 'json', '-c', 'check310,check312']
    fifo_name = os.environ["FIFO_NAME"]
    with open(fifo_name, "w") as fifo_file:
        prowler_cmd = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = prowler_cmd.communicate()
        parts=out.decode('utf-8').split('\n')
        parts=list(filter(len,parts))
        if len(parts):
            host_data_ = host_data.copy()
            first = json.loads(parts[0])
            host_data_['ip'] = f"{host_data_['ip']}{first['Region']}"
            host_data_['vulnerabilities'] = list(filter(lambda v: v is not None, [vuln_parse(part) for part in parts]))
            data = dict(hosts=[host_data_])
            print(json.dumps(data), file=fifo_file)
