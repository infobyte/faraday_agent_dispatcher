#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.repo.w3af.plugin import W3afPlugin
import subprocess
import tempfile
from pathlib import Path


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
    url_target = os.environ.get("EXECUTOR_CONFIG_W4AF_TARGET_URL")
    if not url_target:
        print("URL not provided", file=sys.stderr)
        sys.exit()

    # If the script is run outside the dispatcher the environment variables
    # are checked.
    # ['W4AF_PATH']
    print("Yendo a correr")
    if "W4AF_PATH" in os.environ:
        with tempfile.TemporaryDirectory() as tempdirname:
            name_result = Path(tempdirname) / "config_report_file.w4af"

            with open(name_result, "w") as f:
                commands = [
                    "plugins",
                    "output console,xml_file",
                    "output",
                    "output config xml_file",
                    f"set output_file {tempdirname}/output-w4af.xml",
                    "back",
                    "output config console",
                    "set verbose False",
                    "back",
                    "crawl all, !bing_spider, !google_spider, !spider_man",
                    "crawl",
                    "grep all",
                    "grep",
                    "audit all",
                    "audit",
                    "bruteforce all",
                    "bruteforce",
                    "back",
                    "target",
                    f"set target {url_target}",
                    "back",
                    "start",
                    "exit",
                ]
                f.write("\n".join(commands))
                print("\n".join(commands))

            try:
                os.chdir(path=os.environ.get("W4AF_PATH"))

            except FileNotFoundError:
                print(
                    "The directory where w4af is located could not be found. "
                    "Check environment variable W4AF_PATH = "
                    f'{os.environ.get("W4AF_PATH")}',
                    file=sys.stderr,
                )
                sys.exit()

            if os.path.isfile("w4af_console"):
                cmd = ["python", "./w4af_console", "-y", "-s", name_result]
                print(cmd)
                w4af_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(cmd)
                if len(w4af_process.stdout) > 0:
                    print(
                        f"W4AF stdout: {w4af_process.stdout.decode('utf-8')}",
                        file=sys.stderr,
                    )
                if len(w4af_process.stderr) > 0:
                    print(
                        f"W4AF stderr: {w4af_process.stderr.decode('utf-8')}",
                        file=sys.stderr,
                    )

                plugin = W3afPlugin(
                    ignore_info=ignore_info,
                    hostname_resolution=hostname_resolution,
                    host_tag=host_tag,
                    service_tag=service_tag,
                    vuln_tag=vuln_tag,
                )
                plugin.parseOutputString(f"{tempdirname}/output-w4af.xml")
                print(plugin.get_json())
            else:
                print(
                    "w4af_console file could not be found. For this reason the"
                    " command cannot be run. Actual value = "
                    f'{os.environ.get("W4AF_PATH")}/w4af_console ',
                    file=sys.stderr,
                )
                sys.exit()

    else:
        print("W4AF_PATH not set", file=sys.stderr)
        sys.exit()


if __name__ == "__main__":
    main()
