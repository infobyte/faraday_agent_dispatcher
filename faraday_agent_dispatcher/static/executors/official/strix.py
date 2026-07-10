#!/usr/bin/env python
"""Strix.ai — autonomous AI-pentester CLI wrapper.

Runs the strix-agent CLI against a target (URL / repo / local path) and
emits Faraday bulk-create JSON to stdout. Unlike the vendor's cloud
dashboard (which uses WorkOS SSO), the CLI is fully offline once
installed and drives an internal LLM sandbox.

Runtime prerequisites baked into the dispatcher image:
  - `strix` binary on PATH (installed via `pipx install strix-agent`)
  - Docker socket mounted read-write into the container (strix launches
    a nested Docker sandbox to isolate the AI agent)
  - An LLM API key (STRIX_LLM chooses the provider, LLM_API_KEY carries
    the token — e.g. STRIX_LLM=openai/gpt-5.4 + OPENAI-shaped key)

Env / args:
  STRIX_TARGET         (mandatory) — URL, repo URL, or local path
  STRIX_LLM            (mandatory) — LLM identifier per Strix docs
                                     (e.g. openai/gpt-5.4, anthropic/claude-opus-4-6)
  STRIX_LLM_API_KEY    (mandatory) — API key for the chosen provider
  STRIX_SCAN_MODE      (optional)  — quick | standard | deep (default quick;
                                     the executor caps to quick to keep LLM
                                     spend predictable — override to deep
                                     for a full audit)
  STRIX_MAX_BUDGET_USD (optional)  — hard cap on LLM spend (default 5)
  STRIX_INSTRUCTION    (optional)  — free-text guidance for the agent
                                     (credentials, focus areas)
  STRIX_TIMEOUT_SEC    (optional)  — subprocess timeout in seconds (default 1800)
  STRIX_MIN_SEVERITY   (optional)  — default 'medium'
  STRIX_RUNS_DIR       (optional)  — where strix writes strix_runs/ (default /tmp)

Exit-code contract from strix:
  0 = no vulns found       (emit hosts=[] host-inventory)
  1 = execution error      (surface as fatal; nothing emitted)
  2 = vulnerabilities found (parse strix_runs/<run>/ and emit them)
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

VALID_MODES = ("quick", "standard", "deep")
VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

STRIX_SEVERITY_TO_FARADAY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "note": "info",
}


def log(msg):
    print(msg, file=sys.stderr)


def _cfg(name, default=""):
    return os.environ.get(f"EXECUTOR_CONFIG_{name}") or os.environ.get(name) or default


def _safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _validate_min_severity(value):
    if not value:
        return "medium"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"STRIX_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return text


def _severity(strix_value, default="medium"):
    text = str(strix_value or "").strip().lower()
    return STRIX_SEVERITY_TO_FARADAY.get(text, default)


def _run_strix(target, llm, api_key, scan_mode, max_budget, instruction, runs_dir, timeout):
    """Invoke the strix CLI. Returns (exit_code, run_dir | None)."""
    strix_bin = shutil.which("strix")
    if not strix_bin:
        log("strix binary not found on PATH. Install via `pipx install strix-agent` in the image.")
        sys.exit(1)
    cmd = [
        strix_bin,
        "-n",
        "--target",
        target,
        "--scan-mode",
        scan_mode,
    ]
    if max_budget:
        cmd.extend(["--max-budget-usd", str(max_budget)])
    if instruction:
        cmd.extend(["--instruction", instruction])
    env = dict(os.environ)
    env["STRIX_LLM"] = llm
    env["LLM_API_KEY"] = api_key
    env["HOME"] = runs_dir  # strix writes to $HOME/strix_runs/ by default
    pathlib.Path(runs_dir).mkdir(parents=True, exist_ok=True)
    log(f"Strix: exec {' '.join(cmd)} (runs_dir={runs_dir}, timeout={timeout}s)")
    try:
        proc = subprocess.run(cmd, env=env, cwd=runs_dir, timeout=timeout, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        log(f"Strix: subprocess timed out after {timeout}s")
        return 124, None
    except FileNotFoundError as exc:
        log(f"Strix: cannot exec {strix_bin}: {exc}")
        return 1, None
    if proc.stdout:
        log(f"Strix stdout tail:\n{proc.stdout[-2000:]}")
    if proc.stderr:
        log(f"Strix stderr tail:\n{proc.stderr[-2000:]}")
    # Newest strix_runs/<run>/ directory is the one we just produced.
    runs_root = pathlib.Path(runs_dir) / "strix_runs"
    if not runs_root.exists():
        return proc.returncode, None
    run_dirs = sorted(
        (p for p in runs_root.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    latest = run_dirs[0] if run_dirs else None
    return proc.returncode, latest


def _parse_run_dir(run_dir):
    """Read a strix_runs/<name>/ directory and yield (title, severity, desc,
    refs, external_id) for each finding.

    Strix's on-disk layout isn't fully documented at write time. This parser
    walks the directory for common shapes:
      - <run>/findings.json (a list)
      - <run>/results/*.json (per-finding files)
      - <run>/report.md      (markdown fallback if no JSON present)
    """
    if run_dir is None or not run_dir.exists():
        return
    seen = set()
    # (a) findings.json at the run root
    for candidate in [run_dir / "findings.json", run_dir / "results.json", run_dir / "report.json"]:
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                log(f"Strix: failed to parse {candidate}: {exc}")
                continue
            rows = data.get("findings") if isinstance(data, dict) else data
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                fid = str(row.get("id") or row.get("finding_id") or "")
                if fid in seen:
                    continue
                seen.add(fid)
                yield row
    # (b) per-finding files under results/
    results_dir = run_dir / "results"
    if results_dir.exists() and results_dir.is_dir():
        for p in sorted(results_dir.glob("*.json")):
            try:
                row = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(row, dict):
                continue
            fid = str(row.get("id") or p.stem)
            if fid in seen:
                continue
            seen.add(fid)
            yield row


def _make_vuln(name, desc, severity, refs, external_id, tags=None):
    return {
        "name": name,
        "desc": desc,
        "severity": severity,
        "type": "Vulnerability",
        "refs": refs,
        "data": "",
        "external_id": external_id,
        "tool": "strix",
        "tags": tags or [],
    }


def _host_from_target(target):
    """Turn --target into an (ip, hostname) pair for Faraday grouping."""
    m = re.match(r"^https?://([^/]+)", target)
    if m:
        return "0.0.0.0", m.group(1)
    if target.startswith("git+") or "github.com" in target or "gitlab.com" in target:
        return "0.0.0.0", target
    # local path -> use basename
    return "0.0.0.0", os.path.basename(target.rstrip("/")) or target


def main():
    target = _cfg("STRIX_TARGET")
    llm = _cfg("STRIX_LLM")
    api_key = _cfg("STRIX_LLM_API_KEY") or _cfg("LLM_API_KEY")
    if not target:
        log("STRIX_TARGET is required.")
        sys.exit(1)
    if not llm or not api_key:
        log("STRIX_LLM and STRIX_LLM_API_KEY are required (e.g. openai/gpt-5.4 + your OpenAI key).")
        sys.exit(1)

    scan_mode = _cfg("STRIX_SCAN_MODE", "quick")
    if scan_mode not in VALID_MODES:
        log(f"Invalid STRIX_SCAN_MODE '{scan_mode}'. Use one of: {VALID_MODES}")
        sys.exit(1)
    max_budget = _safe_float(_cfg("STRIX_MAX_BUDGET_USD"), 5.0)
    instruction = _cfg("STRIX_INSTRUCTION")
    timeout = _safe_int(_cfg("STRIX_TIMEOUT_SEC"), 1800)
    runs_dir = _cfg("STRIX_RUNS_DIR", "/tmp")
    min_severity = _validate_min_severity(_cfg("STRIX_MIN_SEVERITY"))

    start_ts = time.time()
    exit_code, run_dir = _run_strix(target, llm, api_key, scan_mode, max_budget, instruction, runs_dir, timeout)
    duration_s = round(time.time() - start_ts, 1)
    log(f"Strix: exit={exit_code} run_dir={run_dir} duration={duration_s}s")

    if exit_code == 1:
        log("Strix: execution error; nothing to emit.")
        sys.exit(1)

    ip, hostname = _host_from_target(target)
    host = {
        "ip": ip,
        "description": f"Strix.ai scan target ({scan_mode})",
        "hostnames": [hostname],
        "vulnerabilities": [],
    }

    floor = SEVERITY_ORDER[min_severity]
    kept = 0
    for row in _parse_run_dir(run_dir):
        severity = _severity(row.get("severity") or row.get("risk"))
        if SEVERITY_ORDER[severity] < floor:
            continue
        fid = str(row.get("id") or row.get("finding_id") or "")
        title = row.get("title") or row.get("name") or f"Strix finding {fid}"
        desc_parts = []
        if row.get("description"):
            desc_parts.append(row["description"])
        if row.get("proof_of_concept") or row.get("poc") or row.get("reproduction"):
            desc_parts.append("PoC: " + str(row.get("proof_of_concept") or row.get("poc") or row.get("reproduction")))
        if row.get("remediation") or row.get("mitigation"):
            desc_parts.append("Remediation: " + str(row.get("remediation") or row.get("mitigation")))
        refs = []
        for cve in row.get("cves") or ([row["cve"]] if row.get("cve") else []):
            if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                refs.append({"name": cve.upper(), "type": "other"})
        for cwe in row.get("cwes") or []:
            refs.append({"name": f"CWE-{cwe}", "type": "other"})
        host["vulnerabilities"].append(
            _make_vuln(
                name=f"[AGENT] {title}",
                desc="\n".join(desc_parts) or "Strix.ai finding (no description).",
                severity=severity,
                refs=refs,
                external_id=f"strix:finding:{fid}" if fid else "",
                tags=["agent:strix", f"agent:strix:scan-mode:{scan_mode}"],
            )
        )
        kept += 1
    # Also emit a summary vuln so an empty scan still lands one asset record
    # in Faraday (proves the scan ran and cost $).
    host["vulnerabilities"].append(
        _make_vuln(
            name=f"[AGENT] Strix.ai scan summary ({scan_mode})",
            desc=(
                f"Target: {target}\n"
                f"Scan mode: {scan_mode}\n"
                f"Findings kept above floor '{min_severity}': {kept}\n"
                f"Duration: {duration_s}s\n"
                f"Exit code: {exit_code}"
            ),
            severity="info",
            refs=[],
            external_id=f"strix:scan:{int(start_ts)}",
            tags=["agent:strix:scan"],
        )
    )

    log(f"Strix: emitting 1 host ({hostname}) with {len(host['vulnerabilities'])} vulns.")
    print(json.dumps({"hosts": [host]}))


if __name__ == "__main__":
    main()
