import os
import subprocess

"""You need to clone and install faraday plugins"""
from faraday_plugins.plugins.repo.nmap.plugin import NmapPlugin

cmd = [
    "nmap",
    "-p{}".format(os.environ.get('EXECUTOR_CONFIG_PORT_LIST')),
    os.environ.get('EXECUTOR_CONFIG_TARGET'),
    "-oX",
    "-",
]


def main():
    results = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    nmap = NmapPlugin()
    nmap.parseOutputString(results.stdout)
    print(nmap.get_json())

if __name__ == '__main__':
    main()
