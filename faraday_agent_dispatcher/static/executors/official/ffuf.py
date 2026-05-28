#!/usr/bin/env python3
import os
import sys
import json
import socket
import tempfile
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

SEVERITY_MAP = {
    "info": "info",
    "low": "low",
    "medium": "med",
    "med": "med",
    "high": "high",
}


def build_command(output_path: Path):
    target = os.environ.get("EXECUTOR_CONFIG_FFUF_TARGET")
    wordlist = os.environ.get("EXECUTOR_CONFIG_FFUF_WORDLIST")
    if not target or not wordlist:
        print("FFUF_TARGET and FFUF_WORDLIST are required", file=sys.stderr)
        sys.exit(1)
    if "FUZZ" not in target:
        print("FFUF_TARGET must contain the FUZZ keyword", file=sys.stderr)
        sys.exit(1)

    threads = os.environ.get("EXECUTOR_CONFIG_FFUF_THREADS", "40")
    match_codes = os.environ.get("EXECUTOR_CONFIG_FFUF_MATCH_CODES", "200,204,301,302,307,401,403")
    filter_size = os.environ.get("EXECUTOR_CONFIG_FFUF_FILTER_SIZE")
    extensions = os.environ.get("EXECUTOR_CONFIG_FFUF_EXTENSIONS")

    cmd = [
        "ffuf",
        "-u", target,
        "-w", wordlist,
        "-t", str(threads),
        "-mc", match_codes,
        "-of", "json",
        "-o", str(output_path),
        "-s",
    ]

    if filter_size:
        cmd += ["-fs", filter_size]

    if extensions:
        cmd += ["-e", extensions]

    return cmd


def normalize_severity(value: str) -> str:
    return SEVERITY_MAP.get((value or "info").lower(), "info")


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


def build_report(ffuf_output: dict, started: float) -> dict:
    severity = normalize_severity(os.environ.get("EXECUTOR_CONFIG_FFUF_SEVERITY", "info"))
    target = os.environ.get("EXECUTOR_CONFIG_FFUF_TARGET", "")
    parsed = urlparse(target.replace("FUZZ", ""))
    host_ip = parsed.hostname or "unknown"
    hostnames = [parsed.hostname] if parsed.hostname else []

    vulnerabilities = []
    for result in ffuf_output.get("results", []):
        path = result.get("url", "")
        status = result.get("status")
        vulnerabilities.append({
            "name": f"Discovered path: {path}",
            "desc": (
                f"ffuf discovered the resource `{path}`.\n\n"
                f"Status: {status}\n"
                f"Length: {result.get('length')}\n"
                f"Words: {result.get('words')}\n"
                f"Lines: {result.get('lines')}\n"
                f"Content-Type: {result.get('content-type', 'unknown')}"
            ),
            "severity": severity,
            "type": "Vulnerability",
            "data": json.dumps(result.get("input", {})),
            "external_id": f"FFUF-{status}-{path}",
            "refs": [{"type": "other", "name": path}],
        })

    return {
        "hosts": [{
            "ip": host_ip,
            "hostnames": hostnames,
            "description": "ffuf web content discovery",
            "vulnerabilities": vulnerabilities,
        }],
        "command": faraday_command("ffuf", target, started),
    }


def main():
    started = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "ffuf.json"
        cmd = build_command(output_path)

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if proc.stderr:
            print(proc.stderr, file=sys.stderr)

        if not output_path.exists():
            print("ffuf produced no output file", file=sys.stderr)
            sys.exit(proc.returncode or 1)

        with output_path.open() as f:
            ffuf_output = json.load(f)

    print(json.dumps(build_report(ffuf_output, started)))


if __name__ == "__main__":
    main()
