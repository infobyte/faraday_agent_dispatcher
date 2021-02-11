import os
import sys
import tempfile
import ipaddress
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from faraday_plugins.plugins.manager import PluginsManager


def is_ip(url):
    try:
        ipaddress.ip_address(url)
        return True
    except ValueError:
        return False


def main():
    # separate the target list with comma
    NUCLEI_TARGET = os.getenv("EXECUTOR_CONFIG_NUCLEI_TARGET")
    # separate the exclude list with comma
    NUCLEI_EXCLUDE = os.getenv("EXECUTOR_CONFIG_NUCLEI_EXCLUDE", None)
    NUCLEI_TEMPLATES = os.getenv("NUCLEI_TEMPLATES")

    target_list = NUCLEI_TARGET.split(",")

    with tempfile.TemporaryDirectory() as tempdirname:
        name_urls = Path(tempdirname) / "urls.txt"
        name_output = Path(tempdirname) / "output.json"

        if len(target_list) > 1:
            with open(name_urls, "w") as f:
                for url in target_list:
                    url_parse = urlparse(url)
                    if is_ip(url_parse.netloc) or is_ip(url_parse.path):
                        print(f"Is {url} not valid.", file=sys.stderr)
                    else:
                        if not url_parse.scheme:
                            f.write(f"http://{url}\n")
                        else:
                            f.write(f"{url}\n")
            cmd = [
                "nuclei",
                "-l",
                name_urls,
                "-t",
                NUCLEI_TEMPLATES,
            ]

        else:
            url_parse = urlparse(NUCLEI_TARGET)
            if is_ip(url_parse.hostname) or is_ip(url_parse.path):
                print(f"Is {NUCLEI_TARGET} not valid.", file=sys.stderr)
                sys.exit()
            else:
                if not url_parse.scheme:
                    url = f"http://{NUCLEI_TARGET}"
                else:
                    url = f"{NUCLEI_TARGET}"
                cmd = [
                    "nuclei",
                    "-target",
                    url,
                    "-t",
                    NUCLEI_TEMPLATES,
                ]

        if NUCLEI_EXCLUDE:
            exclude_list = NUCLEI_EXCLUDE.split(",")
            for exclude in exclude_list:
                cmd += ["-exclude", str(Path(NUCLEI_TEMPLATES) / exclude)]

        cmd += ["-json", "-o", name_output]
        nuclei_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if len(nuclei_process.stdout) > 0:
            print(f"Nuclei stdout: {nuclei_process.stdout.decode('utf-8')}", file=sys.stderr)

        if len(nuclei_process.stderr) > 0:
            print(f"Nuclei stderr: {nuclei_process.stderr.decode('utf-8')}", file=sys.stderr)

        plugin = PluginsManager().get_plugin("nuclei")
        plugin.parseOutputString(nuclei_process.stdout.decode("utf-8"))
        print(plugin.get_json())


if __name__ == "__main__":
    main()
