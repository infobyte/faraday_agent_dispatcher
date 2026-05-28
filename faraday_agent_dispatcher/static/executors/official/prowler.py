#!/usr/bin/env python3
import os
import sys
import tempfile
import subprocess
from pathlib import Path

from faraday_plugins.plugins.repo.prowler.plugin import ProwlerPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters

VALID_PROVIDERS = {"aws", "azure", "gcp", "kubernetes"}


def build_command(output_dir: Path):
    provider = os.environ.get("EXECUTOR_CONFIG_PROWLER_PROVIDER", "aws")
    if provider not in VALID_PROVIDERS:
        print(f"Invalid PROWLER_PROVIDER: {provider}", file=sys.stderr)
        sys.exit(1)

    checks = os.environ.get("EXECUTOR_CONFIG_PROWLER_CHECKS")
    severity = os.environ.get("EXECUTOR_CONFIG_PROWLER_SEVERITY")
    services = os.environ.get("EXECUTOR_CONFIG_PROWLER_SERVICES")
    regions = os.environ.get("EXECUTOR_CONFIG_PROWLER_REGIONS")

    cmd = [
        "prowler", provider,
        "--output-formats", "json",
        "--output-directory", str(output_dir),
        "--output-filename", "prowler",
    ]

    if checks:
        cmd += ["--checks", checks]
    if severity:
        cmd += ["--severity", severity]
    if services:
        cmd += ["--services", services]
    if regions and provider == "aws":
        cmd += ["--region", regions]

    return cmd


def find_json_report(output_dir: Path) -> Path:
    matches = list(output_dir.glob("prowler*.json"))
    if not matches:
        return None
    matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0]


def main():
    agent_config = get_common_parameters()

    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        cmd = build_command(output_dir)

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if proc.stderr:
            print(proc.stderr, file=sys.stderr)

        report = find_json_report(output_dir)
        if not report:
            print("Prowler produced no JSON report", file=sys.stderr)
            sys.exit(proc.returncode or 1)

        raw = report.read_text()

    plugin = ProwlerPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
