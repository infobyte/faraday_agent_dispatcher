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

import sys
import time
import random
import os
import json


host_data = {
    "ip": "192.168.0.{}",
    "description": "test",
    "hostnames": ["test.com", "test2.org"]
}

vuln_data = {
    'name': 'sql injection',
    'desc': 'test',
    'severity': 'high',
    'type': 'Vulnerability',
    'impact': {
        'accountability': True,
        'availability': False,
    },
    'refs': ['CVE-1234']
}

if __name__ == '__main__':

    for j in range(10):
        print("Esto va a stoerr", file=sys.stderr)
        time.sleep(random.choice([i * 0.1 for i in range(5,7)]))

        host_data_ = host_data.copy()
        host_data_['ip'] = host_data_['ip'].format(j+10)
        host_data_['vulnerabilities'] = [vuln_data]
        data = dict(hosts=[host_data_])
        print(json.dumps(data))
        time.sleep(random.choice([i * 0.1 for i in range(1,3)]))
