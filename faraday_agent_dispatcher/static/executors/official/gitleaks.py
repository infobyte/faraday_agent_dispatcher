#!/usr/bin/env python3
import os
import sys
import tempfile
import subprocess
from pathlib import Path

from faraday_plugins.plugins.repo.gitleaks.plugin import GitleaksPlugin

from faraday_agent_dispatcher.utils import arg_helpers
from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters
from faraday_agent_dispatcher.utils.source_target import resolve_source_path

VALID_MODES = {"dir", "git", "stdin"}


def build_command(output_path: Path):
    target = resolve_source_path("GITLEAKS")

    mode = arg_helpers.single("EXECUTOR_CONFIG_GITLEAKS_MODE", "dir")
    if mode not in VALID_MODES:
        print(f"Invalid GITLEAKS_MODE: {mode}", file=sys.stderr)
        sys.exit(1)

    config = os.environ.get("EXECUTOR_CONFIG_GITLEAKS_CONFIG")
    redact = os.environ.get("EXECUTOR_CONFIG_GITLEAKS_REDACT")

    cmd = [
        "gitleaks",
        mode,
        "--report-format",
        "json",
        "--report-path",
        str(output_path),
        "--no-banner",
    ]

    if config:
        cmd += ["--config", config]
    if redact and redact.lower() == "true":
        cmd.append("--redact")

    cmd.append(target)
    return cmd


def main():
    agent_config = get_common_parameters()

    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "gitleaks.json"
        cmd = build_command(output_path)

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if proc.stderr:
            print(proc.stderr, file=sys.stderr)

        if not output_path.exists():
            print("Gitleaks produced no output file", file=sys.stderr)
            sys.exit(proc.returncode if proc.returncode not in (0, 1) else 0)

        raw = output_path.read_text()

    if not raw.strip():
        raw = "[]"

    plugin = GitleaksPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(raw)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
