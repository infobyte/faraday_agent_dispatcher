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
import time

try:
    RUMBLE_BIN = os.environ["RUMBLE_BIN_PATH"]
    OUTPUT_DIR = os.environ["RUMBLE_OUTPUT_DIR"]
    NETWORK_RANGE = os.environ["RUMBLE_NETWORK_RANGE"]
except KeyError:
    print("You must set the environment variables RUMBLE_BIN_PATH, RUMBLE_OUTPUT_DIR and RUMBLE_NETWORK_RANGE",
          file=sys.stderr)
    sys.exit()


def convert_rumble_assets(assets: list):
    """
    Receives a list with all assets in the format rumble uses and converts it in a way
    we can add all of it into Faraday
    :return: dictionary with all assets data transformed in a way we can integrate with Faraday
    """

    hosts = []
    for asset in assets:
        host = dict(ip=asset["addresses"][0],
                    description="",
                    os="",
                    mac="",
                    hostnames=asset["names"],
                    services=[])

        if asset["macs"]:
            host["mac"] = asset["macs"][0]

        services = []
        for service in asset["services"].keys():

            ip_address, port, ip_protocol = service.split("/")
            service_name_parts = []
            data_keys = ["protocol", "service.product", "service.family", "service.vendor", "service.version", "banner"]
            service_data = asset["services"][service]
            print("\t" + " ,".join(service_data.keys()), file=sys.stderr)
            for dk in data_keys:
                if dk in service_data:
                    service_name_parts.append(service_data[dk])

            service_name = " ".join(service_name_parts).strip()

            # we cannot send an empty service name or it won't be possible to view it in the webui
            if not service_name:
                service_name = "unknown"

            # limit the service name length to avoid issues displaying it in the webui
            if len(service_name) > 120:
                service_name = service_name[:120]

            services.append(dict(name=service_name, protocol=ip_protocol, port=port))

        host["services"] = services

        hosts.append(host)

    faraday_assets = dict(hosts=hosts)

    return faraday_assets


async def main():
    if not os.path.exists(OUTPUT_DIR):
        os.mkdir(OUTPUT_DIR)

    # TODO: run with sudo for better results
    scan_output = os.path.join(OUTPUT_DIR, NETWORK_RANGE.replace('/','_')) + "_" + str(int(time.time()))
    command = f"{RUMBLE_BIN} {NETWORK_RANGE} -o {scan_output}"
    rumble_proc = await asyncio.create_subprocess_shell(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"Running Rumble: {command}", file=sys.stderr)
    exit_code = await rumble_proc.wait()

    # after rumble finished the scanning we will have several files with different formats
    # we only care about the json one:
    # assets.jsonl: The new optimized format for correlated, fingerprinted assets.

    assets = []
    try:
        with open(os.path.join(scan_output, "assets.jsonl"), 'r') as f:
            for line in f.readlines():
                assets.append(json.loads(line))
    except FileNotFoundError:
        print("Could not find assets.jsonl scan output!",
              file=sys.stderr)
        sys.exit()

    faraday_assets = convert_rumble_assets(assets)

    print(json.dumps(faraday_assets))


def main_sync():
    r = asyncio.run(main())
    sys.exit(r)  # pragma: no cover


if __name__ == "__main__":
    main_sync()

