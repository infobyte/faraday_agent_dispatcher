#!/usr/bin/env python3
import os
import sys
import tempfile
import subprocess
from pathlib import Path

from faraday_plugins.plugins.repo.sarif.plugin import SarifPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters


def build_command(output_path: Path):
    target = os.environ.get("EXECUTOR_CONFIG_TFSEC_TARGET")
    if not target:
        print("TFSEC_TARGET is required", file=sys.stderr)
        sys.exit(1)

    minimum_severity = os.environ.get("EXECUTOR_CONFIG_TFSEC_MIN_SEVERITY")
    exclude_checks = os.environ.get("EXECUTOR_CONFIG_TFSEC_EXCLUDE")

    cmd = [
        "tfsec", target,
        "--format", "sarif",
        "--out", str(output_path),
        "--soft-fail",
    ]

    if minimum_severity:
        cmd += ["--minimum-severity", minimum_severity]
    if exclude_checks:
        cmd += ["--exclude", exclude_checks]

    return cmd


def main():
    agent_config = get_common_parameters()

    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "tfsec.sarif"
        cmd = build_command(output_path)

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)

        if not output_path.exists():
            print("tfsec produced no SARIF report", file=sys.stderr)
            sys.exit(proc.returncode or 1)

        raw = output_path.read_text()

    plugin = SarifPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
