import os
import subprocess

"""You need to clone and install faraday plugins"""
from faraday_plugins.plugins.repo.nmap.plugin import NmapPlugin


def command_create(lista_target):
    cmd = [
        "nmap",
        "-p {}".format(os.environ.get('EXECUTOR_CONFIG_PORT_LIST')),
        "-oX", "-",
        "--",
    ]
    cmd += lista_target

    return cmd


def main():
    targets = os.environ.get('EXECUTOR_CONFIG_TARGET')

    if ' ' in targets:
        lista_target = targets.split(" ")
    elif ',' in targets:
        lista_target = targets.split(",")
    else:
        lista_target = [targets]

    cmd = command_create(lista_target)
    results = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    nmap = NmapPlugin()
    nmap.parseOutputString(results.stdout.encode())
    print(nmap.get_json())


if __name__ == '__main__':
    main()
