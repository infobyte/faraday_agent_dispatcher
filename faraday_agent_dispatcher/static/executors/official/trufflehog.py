#!/usr/bin/env python3
import os
import sys
import json
import socket
import subprocess
import time
from datetime import datetime, timezone

from faraday_agent_dispatcher.utils.source_target import resolve_source_path


def faraday_command(params: str, started: float) -> dict:
    return {
        "tool": "TruffleHog",
        "command": "TruffleHog",
        "params": params,
        "user": os.environ.get("USER", ""),
        "hostname": socket.gethostname(),
        "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
        "duration": int((time.time() - started) * 1000),
        "import_source": "report",
    }


def build_command():
    mode = os.environ.get("EXECUTOR_CONFIG_TRUFFLEHOG_MODE", "filesystem")
    target = resolve_source_path("TRUFFLEHOG")

    only_verified = os.environ.get("EXECUTOR_CONFIG_TRUFFLEHOG_ONLY_VERIFIED")
    no_update = os.environ.get("EXECUTOR_CONFIG_TRUFFLEHOG_NO_UPDATE", "true")

    cmd = ["trufflehog", mode, target, "--json"]
    if no_update and no_update.lower() == "true":
        cmd.append("--no-update")
    if only_verified and only_verified.lower() == "true":
        cmd.append("--only-verified")

    return cmd, target


def to_vuln(item: dict) -> dict:
    detector = item.get("DetectorName") or item.get("DetectorType") or "Secret"
    raw = item.get("Raw") or ""
    redacted = raw[:6] + "..." if raw else ""
    verified = bool(item.get("Verified"))
    metadata = (item.get("SourceMetadata") or {}).get("Data") or {}
    location = next(iter(metadata.values()), {}) if metadata else {}
    return {
        "name": f"{detector} secret{' (verified)' if verified else ''}",
        "desc": (
            f"TruffleHog detected a `{detector}` secret.\n"
            f"Verified: {verified}\n"
            f"Sample: {redacted}\n"
            f"Location: {json.dumps(location)[:300]}"
        ),
        "severity": "high" if verified else "med",
        "type": "Vulnerability",
        "external_id": f"trufflehog-{detector}",
        "data": json.dumps(location),
        "refs": [],
    }


def main():
    started = time.time()
    cmd, target = build_command()

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    by_file = {}
    for f in findings:
        metadata = (f.get("SourceMetadata") or {}).get("Data") or {}
        loc = next(iter(metadata.values()), {}) if metadata else {}
        file_path = loc.get("file") or loc.get("repository") or target
        by_file.setdefault(file_path, []).append(f)

    hosts = []
    for file_path, items in by_file.items():
        hosts.append(
            {
                "ip": file_path,
                "hostnames": [],
                "description": "TruffleHog secret findings",
                "vulnerabilities": [to_vuln(i) for i in items],
            }
        )

    print(json.dumps({"hosts": hosts, "command": faraday_command(target, started)}))


if __name__ == "__main__":
    main()
