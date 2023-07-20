import os
import sys
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from faraday_plugins.plugins.repo.nuclei.plugin import NucleiPlugin


def main():
    ignore_info = os.getenv("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
    hostname_resolution = os.getenv("AGENT_CONFIG_RESOLVE_HOSTNAME", "True").lower() == "true"
    vuln_tag = os.getenv("AGENT_CONFIG_VULN_TAG", None)
    if vuln_tag:
        vuln_tag = vuln_tag.split(",")
    service_tag = os.getenv("AGENT_CONFIG_SERVICE_TAG", None)
    if service_tag:
        service_tag = service_tag.split(",")
    host_tag = os.getenv("AGENT_CONFIG_HOSTNAME_TAG", None)
    if host_tag:
        host_tag = host_tag.split(",")
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
            exclude_list = NUCLEI_EXCLUDE.split(",")
            for exclude in exclude_list:
                cmd += ["-exclude", str(Path(NUCLEI_TEMPLATES) / exclude)]

        cmd += ["-j", "-o", name_output]
        nuclei_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if len(nuclei_process.stdout) > 0:
            print(
                f"Nuclei stdout: {nuclei_process.stdout.decode('utf-8')}",
                file=sys.stderr,
            )

        if len(nuclei_process.stderr) > 0:
            print(
                f"Nuclei stderr: {nuclei_process.stderr.decode('utf-8')}",
                file=sys.stderr,
            )

        plugin = NucleiPlugin(
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
        )
        plugin.parseOutputString(nuclei_process.stdout.decode("utf-8"))
        print(plugin.get_json())


if __name__ == "__main__":
    main()
