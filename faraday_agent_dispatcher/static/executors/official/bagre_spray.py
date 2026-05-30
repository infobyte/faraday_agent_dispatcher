#!/usr/bin/env python3 -u
"""Bagre Password Spray Executor — Faraday agent for credential validation + password spray.

Pipeline:
  1. Query the configured source (IntelX by default) for compromised
     credentials matching the target domain (same source layer as
     bagre_executor.py).
  2. Discover hosts/services from the Faraday workspace via the REST API.
  3. Cross-product credentials with workspace services and run protocol
     validators (SSH, HTTP Basic, FTP, SMB, SMTP, IMAP, POP3) under a
     rate-limited password-spray policy.
  4. Report each successful authentication as a Faraday vulnerability via
     bulk_create JSON on stdout.

Environment variables:
  Source + Faraday: see bagre_executor.py / bagre.config / faraday_credentials.

  Password-spray policy (all optional):
    BAGRE_PASSWORD_SPRAY_MAX_ATTEMPTS_PER_USER  default 3
    BAGRE_PASSWORD_SPRAY_DELAY_MS               default 1000
    BAGRE_PASSWORD_SPRAY_TIMEOUT_S              default 5
    BAGRE_PASSWORD_SPRAY_MAX_TOTAL_ATTEMPTS     default 1000
    BAGRE_PASSWORD_SPRAY_CONCURRENCY            default 5
    BAGRE_PASSWORD_SPRAY_EXCLUDE_USERS          comma-separated lockout-protected
                                                list, default: admin,administrator,root
    BAGRE_PASSWORD_SPRAY_DRY_RUN                "true" to log jobs without
                                                attempting
    BAGRE_PASSWORD_SPRAY_PROTOCOLS              comma-separated filter
                                                (default: all supported)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import List, Optional, Dict, Any

from bagre.config import load_config
from bagre.sources import get_source
from bagre.sources.intelx_source import _decompose_url, host_in_scope, reconstruct_host
from bagre.faraday_credentials import FaradayConfig
from bagre.faraday_workspace import FaradayWorkspaceClient
from bagre.credential_validator import SUPPORTED_PROTOCOLS
from bagre.password_spray_engine import (
    PasswordSprayPolicy,
    PasswordSprayAttempt,
    build_jobs,
    build_endpoint_jobs,
    discover_login_endpoints,
    run_password_spray,
)

DEFAULT_EXCLUDED = "admin,administrator,root"
LOG_PREFIX = "[BAGRE-PASSWORD-SPRAY]"
TOOL_NAME = "bagre-password-spray"
SCRIPT_NAME = "bagre_password_spray_executor.py"


def log(message: str) -> None:
    """All logs go to stderr — stdout is reserved for the bulk_create JSON."""
    print(message, file=sys.stderr, flush=True)


def env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if not val:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    val = os.environ.get(name)
    if not val:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def env_csv(name: str, default: str) -> List[str]:
    raw = os.environ.get(name, default)
    return [v.strip() for v in raw.split(",") if v.strip()]


def get_param_from_env(param_name: str) -> Optional[str]:
    """Faraday dispatcher passes args as EXECUTOR_CONFIG_<PARAM>."""
    for var in (
        f"EXECUTOR_CONFIG_{param_name.upper()}",
        param_name.upper(),
        param_name.lower(),
        param_name,
    ):
        value = os.environ.get(var)
        if value:
            return value
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bagre Password Spray — validate compromised credentials and password-spray them"
    )
    parser.add_argument(
        "--target_domain",
        "--target-domain",
        dest="target_domain",
        required=False,
        default=None,
        help="Target domain to fetch credentials for (e.g., payway)",
    )
    parser.add_argument(
        "--target_subdomain",
        "--target-subdomain",
        dest="target_subdomain",
        required=False,
        default=None,
        help="Subdomain pattern (LIKE wildcards)",
    )
    parser.add_argument(
        "--protocols",
        required=False,
        default=None,
        help=f"Comma-separated protocols to spray. Supported: {','.join(SUPPORTED_PROTOCOLS)}",
    )
    parser.add_argument(
        "--limit",
        type=int,
        required=False,
        default=None,
        help="Max credentials to fetch from the configured source",
    )
    parser.add_argument(
        "--config-file",
        required=False,
        default=None,
        help="Path to bagre.ini",
    )
    return parser.parse_args()


def build_policy() -> PasswordSprayPolicy:
    excluded = set(env_csv("BAGRE_PASSWORD_SPRAY_EXCLUDE_USERS", DEFAULT_EXCLUDED))
    return PasswordSprayPolicy(
        max_attempts_per_user=env_int("BAGRE_PASSWORD_SPRAY_MAX_ATTEMPTS_PER_USER", 3),
        delay_ms=env_int("BAGRE_PASSWORD_SPRAY_DELAY_MS", 1000),
        timeout_s=env_float("BAGRE_PASSWORD_SPRAY_TIMEOUT_S", 5.0),
        max_total_attempts=env_int("BAGRE_PASSWORD_SPRAY_MAX_TOTAL_ATTEMPTS", 1000),
        concurrency=env_int("BAGRE_PASSWORD_SPRAY_CONCURRENCY", 5),
        excluded_users=excluded,
        dry_run=env_bool("BAGRE_PASSWORD_SPRAY_DRY_RUN", False),
    )


def output_json(data: dict) -> None:
    sys.stdout.write(json.dumps(data) + "\n")
    sys.stdout.flush()


def empty_output(command_str: str, duration: float, note: str = "") -> Dict[str, Any]:
    return {
        "hosts": [],
        "command": {
            "tool": TOOL_NAME,
            "command": command_str,
            "duration": duration,
            **({"note": note} if note else {}),
        },
    }


def attempt_to_vuln(
    attempt: PasswordSprayAttempt,
    target_domain: Optional[str],
    run_context: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a Faraday vulnerability dict from a successful password-spray attempt.

    ``run_context`` carries the spray-run-level metadata that should be
    visible on every HIT vuln (so each one is interpretable on its own):
    spray target, run timestamp, counts, success rate, run duration, and
    the discovered canonical login endpoint for this host.
    """
    date_str = datetime.now().strftime("%Y%m%d")
    search_id = target_domain or "password-spray"
    external_id = (
        f"BAGRE-PASSWORD-SPRAY-{search_id}-{attempt.protocol}-"
        f"{attempt.host}-{attempt.port}-{attempt.username}-{date_str}"
    )

    spray_target = run_context.get("spray_target") or target_domain or "(none)"
    started_at = run_context.get("started_at_iso") or ""
    duration_s = float(run_context.get("duration_s") or 0.0)
    total_attempts = int(run_context.get("total_attempts") or 0)
    total_successes = int(run_context.get("total_successes") or 0)
    credentials_in_scope = int(run_context.get("credentials_in_scope") or 0)
    credentials_skipped_scope = int(run_context.get("credentials_skipped_scope") or 0)
    success_rate = (100.0 * total_successes / total_attempts) if total_attempts else 0.0
    discovered_url = (run_context.get("discovered_endpoints") or {}).get(attempt.host)

    desc = (
        "A compromised credential from Bagre threat intelligence successfully "
        "authenticated against an asset in this workspace.\n\n"
        "### Validated credential\n"
        f"- **Username:** {attempt.username}\n"
        f"- **Password preview:** {attempt.password_preview}\n"
        f"- **Protocol:** {attempt.protocol}\n"
        f"- **Host:** {attempt.host}\n"
        f"- **Port:** {attempt.port}\n"
        f"- **Service:** {attempt.service_name or attempt.protocol}\n"
        f"- **Validator detail:** {attempt.detail}\n"
    )
    if discovered_url:
        desc += f"- **Login endpoint used:** {discovered_url}\n"

    desc += (
        "\n### Spray run context\n"
        f"- **Target scope:** {spray_target}\n"
        f"- **Run started:** {started_at} UTC\n"
        f"- **Run duration:** {duration_s:.1f} s\n"
        f"- **Credentials in scope:** {credentials_in_scope}"
    )
    if credentials_skipped_scope:
        desc += f" ({credentials_skipped_scope} skipped as out-of-scope)"
    desc += (
        f"\n- **Attempts dispatched:** {total_attempts}\n"
        f"- **Successful authentications:** {total_successes}\n"
        f"- **Success rate:** {success_rate:.2f}%\n"
    )

    data_lines = [
        f"protocol={attempt.protocol}",
        f"host={attempt.host}",
        f"port={attempt.port}",
        f"username={attempt.username}",
        f"password_preview={attempt.password_preview}",
        f"detail={attempt.detail}",
        f"spray_target={spray_target}",
        f"run_started_at={started_at}",
        f"run_duration_s={duration_s:.1f}",
        f"credentials_in_scope={credentials_in_scope}",
        f"credentials_skipped_scope={credentials_skipped_scope}",
        f"attempts={total_attempts}",
        f"successes={total_successes}",
        f"success_rate_pct={success_rate:.2f}",
    ]
    if discovered_url:
        data_lines.append(f"login_endpoint={discovered_url}")

    return {
        "name": f"Validated Compromised Credential — {attempt.protocol.upper()} on {attempt.host}",
        "desc": desc,
        "severity": "critical",
        "type": "Vulnerability",
        "data": "\n".join(data_lines) + "\n",
        "external_id": external_id,
        "refs": [{"name": f"{attempt.protocol}://{attempt.host}:{attempt.port}"}],
    }


def attempts_to_bulk_create(
    successes: List[PasswordSprayAttempt],
    target_domain: Optional[str],
    command_str: str,
    duration: float,
    summary: Dict[str, Any],
    run_context: Dict[str, Any],
) -> Dict[str, Any]:
    """Group successful attempts by host into Faraday bulk_create JSON."""
    hosts_by_ip: Dict[str, Dict[str, Any]] = {}
    for attempt in successes:
        host_key = attempt.host
        if host_key not in hosts_by_ip:
            hosts_by_ip[host_key] = {
                "ip": host_key,
                "description": "Asset with validated compromised credential (Bagre Password Spray)",
                "hostnames": [host_key],
                "vulnerabilities": [],
            }
        hosts_by_ip[host_key]["vulnerabilities"].append(attempt_to_vuln(attempt, target_domain, run_context))

    return {
        "hosts": list(hosts_by_ip.values()),
        "command": {
            "tool": TOOL_NAME,
            "command": command_str,
            "duration": duration,
            "params": summary,
        },
    }


def main() -> int:
    start = time.time()
    started_at_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    try:
        args = parse_args()
    except SystemExit:
        output_json(empty_output(SCRIPT_NAME, 0.0))
        return 0

    target_domain = args.target_domain or get_param_from_env("target_domain")
    target_subdomain = args.target_subdomain or get_param_from_env("target_subdomain")
    protocols_arg = args.protocols or get_param_from_env("protocols")
    limit_str = get_param_from_env("limit")
    limit_from_env = int(limit_str) if (limit_str and limit_str.isdigit()) else None

    if not target_domain:
        log(f"{LOG_PREFIX} no target_domain provided; nothing to do")
        output_json(empty_output(SCRIPT_NAME, time.time() - start, "no target_domain"))
        return 0

    try:
        config = load_config(args.config_file)
    except ValueError as e:
        log(f"{LOG_PREFIX} ERROR config error: {e}")
        output_json(empty_output(SCRIPT_NAME, time.time() - start, "bad config"))
        return 0

    # The spray must NOT inherit the scan's "unlimited" (limit=0) setting:
    # pulling tens of thousands of credentials makes the run take ~1 hour and
    # then cross-products them against every target. Use a dedicated cap.
    #   precedence: explicit --limit arg > limit env > BAGRE_PASSWORD_SPRAY_MAX_CREDENTIALS
    spray_cap = env_int("BAGRE_PASSWORD_SPRAY_MAX_CREDENTIALS", 500)
    if args.limit is not None and args.limit > 0:
        limit = args.limit
    elif limit_from_env is not None and limit_from_env > 0:
        limit = limit_from_env
    else:
        limit = spray_cap
    log(f"{LOG_PREFIX} credential fetch capped at {limit} (BAGRE_PASSWORD_SPRAY_MAX_CREDENTIALS)")

    faraday_cfg = FaradayConfig.from_env()
    if not faraday_cfg.is_configured():
        log(f"{LOG_PREFIX} ERROR Faraday config incomplete; cannot discover workspace assets")
        output_json(empty_output(SCRIPT_NAME, time.time() - start, "faraday config missing"))
        return 0

    # Authenticate to the Faraday workspace up front — needed both for the
    # workspace credential source and for target discovery.
    api = FaradayWorkspaceClient(faraday_cfg)
    if not api.authenticate():
        log(f"{LOG_PREFIX} ERROR Faraday authentication failed")
        output_json(empty_output(SCRIPT_NAME, time.time() - start, "faraday auth failed"))
        return 0

    # Credential source for the spray:
    #   * workspace (DEFAULT) — validate the credentials the scan already
    #     imported into this workspace. No upstream re-query, no IntelX
    #     file-read quota burn, and it sprays exactly what's been triaged.
    #   * intelx / clickhouse — re-query the upstream source.
    cred_source = (os.environ.get("BAGRE_PASSWORD_SPRAY_SOURCE") or "workspace").strip().lower()
    credentials: List[Dict[str, Any]] = []
    skipped_scope = 0
    if cred_source == "workspace":
        log(f"{LOG_PREFIX} reading credentials from workspace '{faraday_cfg.workspace}'")
        ws_creds = api.get_workspace_credentials()
        target_scope = (target_domain or "").strip(".").lower()
        for c in ws_creds:
            u, p, ep = c.get("username", ""), c.get("password", ""), c.get("endpoint", "")
            if not u or not p:
                continue
            row: Dict[str, Any] = {"user": u, "password": p}
            row.update(_decompose_url(ep))
            # Scope filter: when a target_domain is given, only spray creds
            # whose endpoint host is that host or a sub-host of it. A
            # subdomain search (canales.movistar.com.ar) stays scoped to that
            # subdomain instead of spraying the whole registered domain.
            if target_scope:
                row_host = reconstruct_host(row)
                if not host_in_scope(row_host, target_scope):
                    skipped_scope += 1
                    continue
            credentials.append(row)
            if limit and len(credentials) >= limit:
                break
        if target_scope:
            log(
                f"{LOG_PREFIX} scope='{target_scope}': kept {len(credentials)} creds, "
                f"skipped {skipped_scope} out-of-scope"
            )
    else:
        log(f"{LOG_PREFIX} querying source='{cred_source}' for credentials " f"of '{target_domain}' (limit={limit})")
        try:
            source = get_source(config, source_name=cred_source)
            with source.connection():
                credentials = source.query_credentials(
                    target_domain=target_domain,
                    target_subdomain=target_subdomain,
                    limit=limit,
                )
        except Exception as e:
            log(f"{LOG_PREFIX} ERROR source query failed: {e}")
            output_json(empty_output(SCRIPT_NAME, time.time() - start, "source error"))
            return 0

    log(f"{LOG_PREFIX} retrieved {len(credentials)} credential rows")
    if not credentials:
        output_json(empty_output(SCRIPT_NAME, time.time() - start, "no credentials"))
        return 0

    protocols_filter: Optional[List[str]] = None
    if protocols_arg:
        protocols_filter = [p.strip().lower() for p in protocols_arg.split(",") if p.strip()]
        unsupported = [p for p in protocols_filter if p not in SUPPORTED_PROTOCOLS]
        if unsupported:
            log(f"{LOG_PREFIX} WARN ignoring unsupported protocols: {unsupported}")
            protocols_filter = [p for p in protocols_filter if p in SUPPORTED_PROTOCOLS]
        if not protocols_filter:
            log(f"{LOG_PREFIX} ERROR no supported protocols left after filter")
            output_json(empty_output(SCRIPT_NAME, time.time() - start, "no supported protocols"))
            return 0

    log(f"{LOG_PREFIX} discovering targets in workspace '{faraday_cfg.workspace}'")
    targets = api.discover_targets(protocols_filter=protocols_filter)
    log(f"{LOG_PREFIX} discovered {len(targets)} targetable services in workspace")

    policy = build_policy()
    log(
        f"{LOG_PREFIX} policy: max_per_user={policy.max_attempts_per_user}, "
        f"delay_ms={policy.delay_ms}, timeout_s={policy.timeout_s}, "
        f"max_total={policy.max_total_attempts}, concurrency={policy.concurrency}, "
        f"dry_run={policy.dry_run}, excluded={sorted(policy.normalize_excluded())}"
    )

    # Target selection:
    #   * If the workspace has scanned services AND we're not forced into
    #     endpoint mode → cross-product creds × workspace services (SSH/FTP/…).
    #   * Otherwise → validate each credential against its OWN leaked endpoint
    #     URL (1:1), using the http-form / https-form validator for web logins.
    #     This is the common case for IntelX web creds where the workspace has
    #     no port-scan services yet.
    use_endpoints = env_bool("BAGRE_PASSWORD_SPRAY_USE_ENDPOINTS", False) or not targets
    if use_endpoints:
        form_login = env_bool("BAGRE_PASSWORD_SPRAY_FORM_LOGIN", True)
        log(
            f"{LOG_PREFIX} endpoint mode: validating each credential against its "
            f"own leaked URL (form_login={form_login}; reason="
            f"{'forced' if env_bool('BAGRE_PASSWORD_SPRAY_USE_ENDPOINTS', False) else 'no workspace services'})"
        )
        jobs = build_endpoint_jobs(credentials=credentials, policy=policy, log=log, form_login=form_login)
    else:
        jobs = build_jobs(credentials=credentials, targets=targets, policy=policy, log=log)
        log(f"{LOG_PREFIX} built {len(jobs)} password-spray jobs after policy filtering")

    if not jobs:
        output_json(empty_output(SCRIPT_NAME, time.time() - start, "no jobs after policy"))
        return 0

    # Discover the canonical login URL per host once and route every job
    # for that host through it. Without this step ~44% of attempts never
    # find a login form (leaked URLs are http:// + deep paths that 404).
    discovered_endpoints: Dict[str, Any] = {}
    if use_endpoints:
        discovered_endpoints = discover_login_endpoints(jobs=jobs, timeout_s=policy.timeout_s, log=log) or {}

    attempts = run_password_spray(jobs=jobs, policy=policy, log=log)
    successes = [a for a in attempts if a.success]
    log(
        f"{LOG_PREFIX} complete: {len(attempts)} attempts, "
        f"{len(successes)} successful, "
        f"{len(attempts) - len(successes)} failed/skipped"
    )

    duration = time.time() - start
    cmd_str = (
        f"{SCRIPT_NAME} --target_domain {target_domain}"
        + (f" --target_subdomain {target_subdomain}" if target_subdomain else "")
        + (f" --protocols {','.join(protocols_filter)}" if protocols_filter else "")
        + f" --limit {limit}"
    )
    summary = {
        "credentials_fetched": len(credentials),
        "targets_discovered": len(targets),
        "jobs": len(jobs),
        "attempts": len(attempts),
        "successes": len(successes),
        "policy": {
            "max_attempts_per_user": policy.max_attempts_per_user,
            "delay_ms": policy.delay_ms,
            "timeout_s": policy.timeout_s,
            "max_total_attempts": policy.max_total_attempts,
            "concurrency": policy.concurrency,
            "dry_run": policy.dry_run,
            "excluded_users": sorted(policy.normalize_excluded()),
        },
    }

    run_context = {
        "spray_target": target_domain or "",
        "started_at_iso": started_at_iso,
        "duration_s": duration,
        "total_attempts": len(attempts),
        "total_successes": len(successes),
        "credentials_in_scope": len(credentials),
        "credentials_skipped_scope": skipped_scope,
        "discovered_endpoints": discovered_endpoints,
    }
    output_json(attempts_to_bulk_create(successes, target_domain, cmd_str, duration, summary, run_context))
    return 0


if __name__ == "__main__":
    sys.exit(main())
