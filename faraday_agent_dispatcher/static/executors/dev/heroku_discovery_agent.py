# -*- coding: utf-8 -*-

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

"""
    heroku discovery faraday agent
    ~~~~~~~~~

    Simple agent to load host and service data from heroku to faraday.

    This requires having the "heroku" command in your machine, and
    being logged in with your account.

"""


import json
import re
import socket
import subprocess
from subprocess import CalledProcessError
import sys

# to be replaced with urllib.parse. Each segment of the connstring is matched
# by /([^:\/?#\s]+)/
MATCH_CONNSTRING = re.compile(
    r"^(?:([^:\/?#\s]+):\/{2})?(?:([^@\/?#\s]+)@)?([^\/?#\s]+)?:" r"(\d{2,5})(?:\/([^?#\s]*))?(?:[?]([^@#\s]+))?\S*$"
)

SERVICE_DATA = {
    "name": "",
    "port": 0,
    "protocol": "",
}

HOST_DATA = {
    "ip": "",
    "description": "heroku resource",
    "hostnames": [],
    "services": [],
}

KNOWN_SERVICES = ["redis", "postgres"]


def main():
    """heroku cli user must be logged to run this agent"""

    try:
        subprocess.run(["heroku", "auth:whoami"], stdout=subprocess.DEVNULL, check=True)  # nosec
    except CalledProcessError:

        sys.exit(1)

    apps = json.loads(
        subprocess.run(  # nosec
            ["heroku", "apps", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.decode("utf-8")
    )

    for app in apps:

        app_info = json.loads(
            subprocess.run(  # nosec
                ["heroku", "config", "--app", app["name"], "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout.decode("utf-8")
        )

        for _key, val in app_info.items():
            service_host_data = MATCH_CONNSTRING.match(val)
            if service_host_data:
                _service_data = SERVICE_DATA.copy()

                service_name = service_host_data.group(1)
                protocol = "unknown"
                if service_name in KNOWN_SERVICES:
                    protocol = "tcp"

                _service_data.update(
                    name=service_name,
                    port=service_host_data.group(4),
                    protocol=protocol,
                )

                _host_data = HOST_DATA.copy()

                try:
                    ipaddr = socket.gethostbyname(service_host_data.group(3))
                except socket.gaierror:
                    ipaddr = "0.0.0.0"  # nosec

                _host_data.update(ip=ipaddr, hostnames=[service_host_data.group(3)])
                _host_data.update(services=[_service_data])

                print(json.dumps(dict(hosts=[_host_data])))


if __name__ == "__main__":
    main()
