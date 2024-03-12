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
import sys
import json


host_data = {
    "ip": "192.168.0.1",
    "description": "test",
    "hostnames": ["test.com", "test2.org"],
}

vuln_data = {
    "name": "sql injection",
    "desc": "test",
    "severity": "high",
    "type": "Vulnerability",
    "impact": {
        "accountability": True,
        "availability": False,
    },
    "refs": [{"type": "other", "name": "http://www.ietf.org/rfc/rfc1323.txt"}],
}

if __name__ == "__main__":
    out = os.getenv("EXECUTOR_CONFIG_OUT")
    count = os.getenv("EXECUTOR_CONFIG_COUNT", 1)
    err = os.getenv("EXECUTOR_CONFIG_ERR") is not None
    fails = os.getenv("EXECUTOR_CONFIG_FAILS") is not None
    spaced_before = os.getenv("EXECUTOR_CONFIG_SPACED_BEFORE") is not None
    spaced_middle = os.getenv("EXECUTOR_CONFIG_SPACED_MIDDLE") is not None
    spare = os.getenv("EXECUTOR_CONFIG_SPARE") is not None
    omit_everything = os.getenv("DO_NOTHING", None)
    if out and omit_everything is None:
        host_data_ = host_data.copy()
        host_data_["vulnerabilities"] = [vuln_data]
        data = dict(hosts=[host_data_])
        if out == "json":
            prefix = "\n" if spaced_before else ""
            suffix = "\n" if spaced_middle else ""
            suffix += ("\n" if spare else "").join([""] + [json.dumps(data) for _ in range(int(count) - 1)])
            print(f"{prefix}{json.dumps(data)}{suffix}")
        elif out == "str":
            print("NO JSON OUTPUT")
        elif out == "bad_json":
            del data["hosts"][0]["ip"]
            print(f"{json.dumps(data)}")
        else:
            print("unexpected value in out parameter", file=sys.stderr)
    else:
        print(omit_everything, file=sys.stderr)

    if err:
        print("Print by stderr", file=sys.stderr)
    if fails:
        sys.exit(1)
