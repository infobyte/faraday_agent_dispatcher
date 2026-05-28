#!/usr/bin/env python3
import os
import sys
import tempfile
import subprocess
from pathlib import Path

from faraday_plugins.plugins.repo.kubescape.plugin import KubescapePlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters

VALID_SCAN_TARGETS = {"cluster", "framework", "control"}


def build_command(output_path: Path):
    scan_target = os.environ.get("EXECUTOR_CONFIG_KUBESCAPE_SCAN_TARGET", "cluster")
    if scan_target not in VALID_SCAN_TARGETS:
        print(f"Invalid KUBESCAPE_SCAN_TARGET: {scan_target}", file=sys.stderr)
        sys.exit(1)

    framework = os.environ.get("EXECUTOR_CONFIG_KUBESCAPE_FRAMEWORK", "nsa")
    kubeconfig = os.environ.get("EXECUTOR_CONFIG_KUBESCAPE_KUBECONFIG")
    manifest_path = os.environ.get("EXECUTOR_CONFIG_KUBESCAPE_MANIFEST_PATH")

    cmd = ["kubescape", "scan"]

    if scan_target == "framework":
        cmd += ["framework", framework]
    elif scan_target == "control":
        control = os.environ.get("EXECUTOR_CONFIG_KUBESCAPE_CONTROL_ID")
        if not control:
            print("KUBESCAPE_CONTROL_ID required when scan target is 'control'", file=sys.stderr)
            sys.exit(1)
        cmd += ["control", control]

    if manifest_path:
        cmd.append(manifest_path)

    cmd += ["--format", "json", "--output", str(output_path)]

    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]

    return cmd


def main():
    agent_config = get_common_parameters()

    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "kubescape.json"
        cmd = build_command(output_path)

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if proc.stderr:
            print(proc.stderr, file=sys.stderr)

        if not output_path.exists():
            print("Kubescape produced no output file", file=sys.stderr)
            sys.exit(proc.returncode or 1)

        raw = output_path.read_text()

    plugin = KubescapePlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
