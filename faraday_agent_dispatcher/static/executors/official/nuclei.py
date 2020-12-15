import os
import sys
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from faraday_plugins.plugins.manager import PluginsManager


def main():
    # separate the target list with comma
    NUCLEI_TARGET = os.getenv("EXECUTOR_CONFIG_NUCLEI_TARGET")
    # separate the exclude list with comma
    NUCLEI_EXCLUDE = os.getenv("EXECUTOR_CONFIG_NUCLEI_EXCLUDE", None)
    NUCLEI_TEMPLATES = os.getenv("NUCLEI_TEMPLATES")

    lista_target = NUCLEI_TARGET.split(",")
    if NUCLEI_EXCLUDE is not None:
        lista_exclude = NUCLEI_EXCLUDE.split(",")

    with tempfile.TemporaryDirectory() as tempdirname:
        name_urls = Path(tempdirname) / "urls.txt"
        name_output = Path(tempdirname) / "output.json"
        if len(lista_target) > 1:
            with open(name_urls, "w") as f:
                for url in lista_target:
                    url_parse = urlparse(url)
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
            if len(lista_exclude) > 1:
                for exclude in lista_exclude:
                    cmd += ["-exclude", exclude]
            else:
                cmd += ["-exclude", NUCLEI_EXCLUDE]
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
