#!/usr/bin/env python3
import os
import sys
import subprocess

from faraday_plugins.plugins.repo.snyk.plugin import SnykPlugin

from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters
from faraday_agent_dispatcher.utils.source_target import resolve_source_path

VALID_MODES = {"test", "container", "iac", "code"}


def build_command():
    target = resolve_source_path("SNYK")

    mode = os.environ.get("EXECUTOR_CONFIG_SNYK_MODE", "test")
    if mode not in VALID_MODES:
        print(f"Invalid SNYK_MODE: {mode}", file=sys.stderr)
        sys.exit(1)

    severity_threshold = os.environ.get("EXECUTOR_CONFIG_SNYK_SEVERITY_THRESHOLD")
    org = os.environ.get("EXECUTOR_CONFIG_SNYK_ORG")
    file_arg = os.environ.get("EXECUTOR_CONFIG_SNYK_FILE")
    all_projects = os.environ.get("EXECUTOR_CONFIG_SNYK_ALL_PROJECTS")

    if mode == "test":
        cmd = ["snyk", "test", "--json"]
    elif mode == "container":
        cmd = ["snyk", "container", "test", "--json"]
    elif mode == "iac":
        cmd = ["snyk", "iac", "test", "--json"]
    else:
        cmd = ["snyk", "code", "test", "--json"]

    if severity_threshold:
        cmd += [f"--severity-threshold={severity_threshold}"]
    if org:
        cmd += [f"--org={org}"]
    if file_arg:
        cmd += [f"--file={file_arg}"]
    if all_projects and all_projects.lower() == "true":
        cmd.append("--all-projects")

    cmd.append(target)
    return cmd


def main():
    agent_config = get_common_parameters()
    cmd = build_command()

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if not result.stdout.strip():
        print("Snyk produced no output", file=sys.stderr)
        sys.exit(result.returncode if result.returncode not in (0, 1) else 1)

    plugin = SnykPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(result.stdout)
    print(plugin.get_json())


if __name__ == "__main__":
    main()
