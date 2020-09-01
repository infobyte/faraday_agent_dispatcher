#!/usr/bin/env python
import os
import re
import sys
import tempfile
import subprocess
from urllib.parse import urlparse
from faraday_plugins.plugins.manager import PluginsManager


def remove_multiple_new_line(text: str):
    return re.sub(r'\n+', '\n', text)


def flush_messages(process):
    if len(process.stdout) > 0:
        stdout = remove_multiple_new_line(
            process.stdout.decode('utf-8')
        )
        print(
            f"Arachni stdout: {stdout}",
            file=sys.stderr
        )
    if len(process.stderr) > 0:
        stderr = remove_multiple_new_line(
            process.stderr.decode('utf-8')
        )
        print(
            f"Arachni stderr: {stderr}",
            file=sys.stderr
        )


def main():
    my_envs = os.environ
    # If the script is run outside the dispatcher
    # the environment variables
    # are checked.
    # ['EXECUTOR_CONFIG_NAME_URL', 'ARACHNI_PATH']
    if 'EXECUTOR_CONFIG_NAME_URL' in my_envs:
        url_analyze = os.environ.get('EXECUTOR_CONFIG_NAME_URL')
        url = urlparse(url_analyze)
        if url.scheme != 'http' and url.scheme != 'https':
            url_analyze = f'http://{url_analyze}'
    else:
        print("Param NAME_URL no passed", file=sys.stderr)
        sys.exit()

    if 'ARACHNI_PATH' in my_envs:
        path_arachni = os.environ.get('ARACHNI_PATH')
    else:
        print("Environment variable ARACHNI_PATH no set", file=sys.stderr)
        sys.exit()
    os.chdir(path_arachni)
    file_afr = tempfile.NamedTemporaryFile(mode="w", suffix='.afr')

    cmd = ['./arachni',
           url_analyze,
           '--report-save-path',
           file_afr.name
           ]

    arachni_command = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    flush_messages(arachni_command)

    name_xml = tempfile.NamedTemporaryFile(mode="w", suffix='.xml')

    cmd = [
        './arachni_reporter',
        file_afr.name,
        '--reporter',
        f'xml:outfile={name_xml.name}'
    ]

    arachni_reporter_process = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    flush_messages(arachni_reporter_process)

    plugin = PluginsManager().get_plugin("arachni")

    with open(name_xml.name, 'r') as f:
        plugin.parseOutputString(f.read())
        print(plugin.get_json())

    name_xml.close()
    file_afr.close()


if __name__ == '__main__':
    main()
