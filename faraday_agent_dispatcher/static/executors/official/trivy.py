#!/usr/bin/env python3
import os
import sys
import subprocess

from faraday_plugins.plugins.repo.trivy_json.plugin import TrivyJsonPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters

VALID_SCAN_TYPES = {"fs", "image", "repo", "config", "k8s"}


def build_command():
    scan_type = os.environ.get("EXECUTOR_CONFIG_TRIVY_SCAN_TYPE", "fs")
    if scan_type not in VALID_SCAN_TYPES:
        print(f"Invalid TRIVY_SCAN_TYPE: {scan_type}", file=sys.stderr)
        sys.exit(1)

    target = os.environ.get("EXECUTOR_CONFIG_TRIVY_TARGET")
    if not target:
        print("TRIVY_TARGET is required", file=sys.stderr)
        sys.exit(1)

    severity = os.environ.get("EXECUTOR_CONFIG_TRIVY_SEVERITY")
    skip_dirs = os.environ.get("EXECUTOR_CONFIG_TRIVY_SKIP_DIRS")
    ignore_unfixed = os.environ.get("EXECUTOR_CONFIG_TRIVY_IGNORE_UNFIXED")
    scanners = os.environ.get("EXECUTOR_CONFIG_TRIVY_SCANNERS", "vuln,secret,misconfig")

    cmd = ["trivy", scan_type, "--format", "json", "--quiet"]

    if scanners and scan_type in {"fs", "image", "repo"}:
        cmd += ["--scanners", scanners]

    if severity:
        cmd += ["--severity", severity]

    if skip_dirs:
        cmd += ["--skip-dirs", skip_dirs]

    if ignore_unfixed and ignore_unfixed.lower() == "true":
        cmd.append("--ignore-unfixed")

    cmd.append(target)
    return cmd


def main():
    agent_config = get_common_parameters()
    cmd = build_command()

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if not result.stdout.strip():
        print("Trivy produced no output", file=sys.stderr)
        sys.exit(result.returncode or 1)

    plugin = TrivyJsonPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(result.stdout)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
