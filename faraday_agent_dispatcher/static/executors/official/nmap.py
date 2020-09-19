import os
import subprocess

"""You need to clone and install faraday plugins"""
from faraday_plugins.plugins.repo.nmap.plugin import NmapPlugin


def command_create(lista_target):
    cmd = [
        "nmap",
        "-oX", "-",
        "--",
    ]

    cmd += '' if os.environ.get('EXECUTOR_CONFIG_PORT_LIST', None) is None\
        else [f'-p {os.environ.get("EXECUTOR_CONFIG_PORT_LIST")}']
    cmd += '' if os.environ.get('EXECUTOR_CONFIG_OPTION_SC', None) is None\
        else ['-sC']
    cmd += '' if os.environ.get('EXECUTOR_CONFIG_OPTION_SV', None) is None \
        else ['-sV']
    cmd += '' if os.environ.get('EXECUTOR_CONFIG_OPTION_PN', None) is None \
        else ['-Pn']
    cmd += '' \
        if os.environ.get('EXECUTOR_CONFIG_SCRIPT_TIMEOUT', None) is None \
        else [f'--script-timeout '
              f'{os.environ.get("EXECUTOR_CONFIG_SCRIPT_TIMEOUT")}']
    cmd += '' if os.environ.get('EXECUTOR_CONFIG_HOST_TIMEOUT', None) is None \
        else [f'--host-timeout '
              f'{os.environ.get("EXECUTOR_CONFIG_HOST_TIMEOUT")}']
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
