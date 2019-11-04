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
    Nessus Scan ETL agent
    ~~~~~~~~~

    dependencies faraday_plugins, nessrest

"""
import sys
import os

from nessrest import ness6rest
from faraday_plugins.plugins.manager import PluginsManager


try:
    NESSUS_URL = os.environ["NESSUS_URL"]
    NESSUS_USERNAME = os.environ["NESSUS_USERNAME"]
    NESSUS_PASSWORD = os.environ["NESSUS_PASSWORD"]
except KeyError:
    print("You must set the enviroment variables NESSUS_URL, NESSUS_USERNAME and NESSUS_PASSWORD",
          file=sys.stderr)
    sys.exit()

class RedirectOutput():
    """ context manager for redirect output"""
    def __enter__(self):
        sys.stdout = sys.stderr
    def __exit__(self, type, value, traceback):
        sys.stdout = sys.__stdout__


def main():
    """ main function """

    with RedirectOutput():
        scanner = ness6rest.Scanner(url=NESSUS_URL, login=NESSUS_USERNAME,
                                    password=NESSUS_PASSWORD, insecure=True)

        last_scan = [0, 0]
        for scan in scanner.scan_list()['scans']:
            if scan['creation_date'] > last_scan[0]:
                last_scan = [scan['creation_date'], scan['id']]

        scanner.scan_id = last_scan[1]

        plugin = PluginsManager().get_plugin("nessus")
        plugin.parseOutputString(scanner.download_scan(export_format="nessus"))

    print(plugin.get_json())

if __name__ == '__main__':
    main()
