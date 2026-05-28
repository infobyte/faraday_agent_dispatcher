#!/usr/bin/env python3
import os
import sys
import tempfile
import subprocess
from pathlib import Path

from faraday_plugins.plugins.repo.sarif.plugin import SarifPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def build_command(output_dir: Path):
    target = os.environ.get("EXECUTOR_CONFIG_CHECKOV_TARGET")
    if not target:
        print("CHECKOV_TARGET is required", file=sys.stderr)
        sys.exit(1)

    frameworks = os.environ.get("EXECUTOR_CONFIG_CHECKOV_FRAMEWORK")
    skip_check = os.environ.get("EXECUTOR_CONFIG_CHECKOV_SKIP_CHECK")
    check = os.environ.get("EXECUTOR_CONFIG_CHECKOV_CHECK")

    cmd = [
        "checkov",
        "--directory",
        target,
        "--output",
        "sarif",
        "--output-file-path",
        str(output_dir),
        "--quiet",
        "--soft-fail",
    ]

    if frameworks:
        cmd += ["--framework", frameworks]
    if skip_check:
        cmd += ["--skip-check", skip_check]
    if check:
        cmd += ["--check", check]

    return cmd


def main():
    agent_config = get_common_parameters()

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        cmd = build_command(out_dir)

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)

        sarif_files = list(out_dir.rglob("*.sarif"))
        if not sarif_files:
            print("Checkov produced no SARIF report", file=sys.stderr)
            sys.exit(proc.returncode or 1)

        raw = sarif_files[0].read_text()

    plugin = SarifPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
