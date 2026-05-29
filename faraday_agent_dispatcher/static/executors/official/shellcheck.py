#!/usr/bin/env python3
import os
import sys
import json
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from faraday_agent_dispatcher.utils.source_target import resolve_source_path

SEVERITY_MAP = {
    "error": "high",
    "warning": "med",
    "info": "info",
    "style": "info",
}


def discover_targets(root: Path):
    if root.is_file():
        return [root]
    return [p for p in root.rglob("*") if p.is_file() and (p.suffix in {".sh", ".bash"} or _has_shebang(p))]


def _has_shebang(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(2)
        return head == b"#!"
    except OSError:
        return False


def to_vuln(item: dict) -> dict:
    level = (item.get("level") or "warning").lower()
    code = item.get("code")
    return {
        "name": item.get("message", f"ShellCheck SC{code}")[:80],
        "desc": (
            f"{item.get('message', '')}\n\n"
            f"Code: SC{code}\n"
            f"Range: line {item.get('line')} col {item.get('column')} "
            f"-> line {item.get('endLine')} col {item.get('endColumn')}"
        ),
        "severity": SEVERITY_MAP.get(level, "info"),
        "type": "Vulnerability",
        "external_id": f"SC{code}" if code else "shellcheck",
        "data": json.dumps(item.get("fix") or {}),
        "refs": [{"type": "other", "name": f"https://www.shellcheck.net/wiki/SC{code}"}] if code else [],
    }


def faraday_command(tool: str, params: str, started_at: float) -> dict:
    return {
        "tool": tool,
        "command": tool,
        "params": params,
        "user": os.environ.get("USER", ""),
        "hostname": socket.gethostname(),
        "start_date": datetime.fromtimestamp(started_at, tz=timezone.utc).isoformat(),
        "duration": int((time.time() - started_at) * 1000),
        "import_source": "report",
    }


def main():
    started = time.time()
    target = resolve_source_path("SHELLCHECK")

    severity = os.environ.get("EXECUTOR_CONFIG_SHELLCHECK_SEVERITY")
    extra_shells = os.environ.get("EXECUTOR_CONFIG_SHELLCHECK_SHELL")

    targets = discover_targets(Path(target))
    if not targets:
        print(f"No shell scripts found under {target}", file=sys.stderr)
        print(json.dumps({"hosts": [], "command": faraday_command("ShellCheck", target, started)}))
        return

    cmd = ["shellcheck", "-f", "json"]
    if severity:
        cmd += ["-S", severity]
    if extra_shells:
        cmd += ["-s", extra_shells]
    cmd += [str(p) for p in targets]

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)

    if not proc.stdout.strip():
        print(json.dumps({"hosts": [], "command": faraday_command("ShellCheck", target, started)}))
        return

    items = json.loads(proc.stdout)

    by_file = {}
    for item in items:
        by_file.setdefault(item["file"], []).append(item)

    hosts = []
    for file_path, items in by_file.items():
        hosts.append(
            {
                "ip": file_path,
                "hostnames": [Path(file_path).name],
                "description": "ShellCheck findings",
                "vulnerabilities": [to_vuln(i) for i in items],
            }
        )

    print(json.dumps({"hosts": hosts, "command": faraday_command("ShellCheck", target, started)}))


if __name__ == "__main__":
    main()
