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
import json
import argparse


host_data = {
    "ip": "192.168.0.1",
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
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', action='store', help='if set prints by stdout')
    parser.add_argument('--err', action='store_true', help='if set prints by stderr')
    parser.add_argument('--fails', action='store_true', help='if true fails')
    args = parser.parse_args()

    if args.out:
        host_data_ = host_data.copy()
        host_data_['vulnerabilities'] = [vuln_data]
        data = dict(hosts=[host_data_])
        if args.out == "json":
            print(f"{json.dumps(data)}")
        elif args.out == "str":
            print("NO JSON OUTPUT")
        elif args.out == "bad_json":
            del data["hosts"][0]["ip"]
            print(f"{json.dumps(data)}")

    if args.err:
        print("Print by stderr", file=sys.stderr)
    if args.fails:
        sys.exit(1)