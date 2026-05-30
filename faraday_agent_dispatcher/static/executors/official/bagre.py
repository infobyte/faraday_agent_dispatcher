#!/usr/bin/env python3 -u
"""Bagre Executor - Faraday Agent for threat intelligence credential lookup.

This executor queries the Bagre ClickHouse database for compromised credentials
and outputs results in Faraday's Bulk Create JSON format.

Usage:
    bagre_executor.py --target-domain DOMAIN [--target-subdomain PATTERN] [--limit N]

Environment Variables:
    CLICKHOUSE_HOST     - ClickHouse server hostname (default: localhost)
    CLICKHOUSE_PORT     - ClickHouse server port (default: 9000)
    CLICKHOUSE_DATABASE - Database name (default: credentials_db)
    CLICKHOUSE_USER     - Username (required)
    CLICKHOUSE_PASSWORD - Password (required)
    BAGRE_QUERY_LIMIT   - Maximum results (default: 100)

    # For credential import (optional):
    FARADAY_URL         - Faraday server URL (e.g., https://faraday.example.com)
    FARADAY_USER        - Faraday username
    FARADAY_PASSWORD    - Faraday password
    FARADAY_WORKSPACE   - Faraday workspace name
    BAGRE_IMPORT_CREDS  - Set to "true" to enable credential import via Faraday API

Output:
    Single-line JSON to stdout in Faraday Bulk Create format.
"""

import argparse
import json
import os
import sys
import time
from typing import Optional, List, Dict, Any

from bagre.config import load_config
from bagre.sources import get_source
from bagre.formatter import format_faraday_output
from bagre.faraday_credentials import FaradayConfig, import_credentials_and_link

# Global flag to control logging (disabled by default for dispatcher compatibility)
ENABLE_LOGGING = os.environ.get("BAGRE_ENABLE_LOGGING", "").lower() in ("1", "true", "yes")


def log_error(message: str) -> None:
    """Log error message to stderr (only if logging enabled)."""
    if ENABLE_LOGGING:
        print(f"[ERROR] {message}", file=sys.stderr, flush=True)


def log_info(message: str) -> None:
    """Log info message to stderr (only if logging enabled)."""
    if ENABLE_LOGGING:
        print(f"[INFO] {message}", file=sys.stderr, flush=True)


def should_import_credentials() -> bool:
    """Check if credential import is enabled."""
    return os.environ.get("BAGRE_IMPORT_CREDS", "").lower() in ("1", "true", "yes")


def direct_publish_to_faraday(
    bulk_payload: Dict[str, Any],
    faraday_config: "FaradayConfig",
) -> bool:
    """POST bulk_create to Faraday directly from the executor.

    Used when BAGRE_IMPORT_CREDS=true so the executor can (a) create the
    vulnerability synchronously, then (b) create+link credentials to it,
    all before exiting. The dispatcher's auto-post after exit becomes a
    no-op because we emit an empty hosts payload.

    Returns True on success, False otherwise.
    """
    from datetime import datetime, timezone
    from bagre.faraday_credentials import FaradayAPIClient

    api = FaradayAPIClient(faraday_config)
    if not api.authenticate():
        print("[BAGRE ERROR] direct-publish: Faraday auth failed", file=sys.stderr, flush=True)
        return False

    # Build the command dict with required fields. Faraday's BulkCommandSchema
    # requires start_date (and accepts end_date); the dispatcher's own
    # bulk_create code path injects these automatically, but we are bypassing
    # the dispatcher here so we have to provide them ourselves.
    src_command = bulk_payload.get("command", {}) or {}
    duration_s = float(src_command.get("duration") or 0.0)
    end_dt = datetime.now(timezone.utc)
    start_dt = datetime.fromtimestamp(end_dt.timestamp() - duration_s, tz=timezone.utc)
    command = {
        "tool": src_command.get("tool", "bagre"),
        "command": src_command.get("command", "bagre_executor.py"),
        "duration": duration_s,
        "start_date": start_dt.isoformat(),
        "end_date": end_dt.isoformat(),
        "import_source": "agent",
    }

    # Strip credentials from the payload — we will create them separately,
    # with vulnerability_ids set, so they show up *inside* the vulnerability.
    payload = {
        "hosts": bulk_payload.get("hosts", []),
        "command": command,
    }
    try:
        r = api.session.post(
            f"{api.base_url}/_api/v3/ws/{api.config.workspace}/bulk_create",
            json=payload,
            timeout=30,
        )
    except Exception as e:
        print(f"[BAGRE ERROR] direct-publish: bulk_create exception: {e}", file=sys.stderr, flush=True)
        return False

    if r.status_code not in (200, 201):
        body = (r.text or "")[:300]
        print(
            f"[BAGRE ERROR] direct-publish: bulk_create HTTP {r.status_code}: {body}",
            file=sys.stderr,
            flush=True,
        )
        return False

    print(
        f"[BAGRE] direct-publish: bulk_create OK ({len(payload['hosts'])} hosts)",
        file=sys.stderr,
        flush=True,
    )
    return True


def import_credentials_to_faraday(credentials: List[Dict[str, Any]], external_id_pattern: str) -> None:
    """Import credentials to Faraday using faraday-cli.

    This runs after bulk_create has created the hosts/vulns.
    Credentials are linked to the vulnerabilities that were created (matched by external_id).

    Args:
        credentials: List of credential dictionaries from ClickHouse.
        external_id_pattern: Pattern to match vulnerabilities by external_id (default: "BAGRE-").
    """
    creds_count = len(credentials) if credentials else 0
    pat_len = len(external_id_pattern) if external_id_pattern else 0
    print(
        f"[BAGRE] import_credentials_to_faraday called with {creds_count} credentials, "
        f"external_id_pattern='{external_id_pattern}' (length: {pat_len})",
        file=sys.stderr,
        flush=True,
    )

    if not credentials:
        print("[BAGRE] No credentials to import", file=sys.stderr, flush=True)
        return

    faraday_config = FaradayConfig.from_env()

    if not faraday_config.is_configured():
        print(
            "[BAGRE ERROR] Faraday credential import not configured "
            "(missing FARADAY_URL, FARADAY_USER, FARADAY_PASSWORD, or FARADAY_WORKSPACE)",
            file=sys.stderr,
            flush=True,
        )
        print(
            f"[BAGRE DEBUG] FARADAY_URL={os.environ.get('FARADAY_URL', 'NOT SET')}, "
            f"FARADAY_USER={os.environ.get('FARADAY_USER', 'NOT SET')}, "
            f"FARADAY_WORKSPACE={os.environ.get('FARADAY_WORKSPACE', 'NOT SET')}",
            file=sys.stderr,
            flush=True,
        )
        return

    print(
        f"[BAGRE] Importing {len(credentials)} credentials to Faraday workspace: {faraday_config.workspace}",
        file=sys.stderr,
        flush=True,
    )
    print(
        f"[BAGRE] Will link credentials to vulnerabilities matching external_id pattern: {external_id_pattern}",
        file=sys.stderr,
        flush=True,
    )

    # Use API directly (faraday-cli doesn't support credential import)
    success, message, cred_ids = import_credentials_and_link(
        credentials=credentials, faraday_config=faraday_config, external_id_pattern=external_id_pattern
    )

    if success:
        log_info(f"Credential import successful: {message}")
        # Also print to stderr so it's visible even without logging enabled
        print(f"[BAGRE] Credential import: {message}", file=sys.stderr, flush=True)
    else:
        log_error(f"Credential import failed: {message}")
        print(f"[BAGRE ERROR] Credential import failed: {message}", file=sys.stderr, flush=True)


def get_param_from_env(param_name: str) -> Optional[str]:
    """Get parameter from environment variables.

    Faraday dispatcher passes params as EXECUTOR_CONFIG_<PARAM_NAME>
    """
    variants = [
        f"EXECUTOR_CONFIG_{param_name.upper()}",
        param_name.upper(),
        param_name.lower(),
        param_name,
    ]
    for var in variants:
        value = os.environ.get(var)
        if value:
            return value
    return None


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Bagre Threat Intelligence - Query compromised credentials")
    parser.add_argument(
        "--target_domain",
        "--target-domain",
        dest="target_domain",
        required=False,
        default=None,
        help="Target domain to search for compromised credentials (e.g., payway)",
    )
    parser.add_argument(
        "--target_subdomain",
        "--target-subdomain",
        dest="target_subdomain",
        required=False,
        default=None,
        help="Subdomain pattern to filter (supports LIKE wildcards, e.g., %%jenkins%%)",
    )
    parser.add_argument(
        "--mail_domain",
        "--mail-domain",
        dest="mail_domain",
        required=False,
        default=None,
        help="Mail domain to filter by (exact match, e.g., gmail)",
    )
    parser.add_argument(
        "--uri_path",
        "--uri-path",
        dest="uri_path",
        required=False,
        default=None,
        help="URI path pattern to filter (supports LIKE wildcards, e.g., %%login%%)",
    )
    parser.add_argument(
        "--limit", type=int, required=False, default=None, help="Maximum number of results (default: 100)"
    )
    parser.add_argument("--config-file", required=False, default=None, help="Path to configuration file")
    return parser.parse_args()


def build_command_string(
    target_domain: Optional[str],
    target_subdomain: Optional[str],
    mail_domain: Optional[str],
    uri_path: Optional[str],
    limit: Optional[int],
) -> str:
    """Build the command string for Faraday output."""
    cmd = "bagre_executor.py"
    if target_domain:
        cmd += f" --target_domain {target_domain}"
    if target_subdomain:
        cmd += f" --target_subdomain {target_subdomain}"
    if mail_domain:
        cmd += f" --mail_domain {mail_domain}"
    if uri_path:
        cmd += f" --uri_path {uri_path}"
    if limit:
        cmd += f" --limit {limit}"
    return cmd


def output_json(data: dict) -> None:
    """Output JSON to stdout and flush immediately."""
    sys.stdout.write(json.dumps(data) + "\n")
    sys.stdout.flush()


def main() -> int:
    """Main entry point for the Bagre executor."""
    start_time = time.time()

    try:
        # Parse arguments
        try:
            args = parse_args()
        except SystemExit:
            output_json({"hosts": [], "command": {"tool": "bagre", "command": "bagre_executor.py", "duration": 0}})
            return 0

        # Get parameters from args or environment
        target_domain = args.target_domain or get_param_from_env("target_domain")
        target_subdomain = args.target_subdomain or get_param_from_env("target_subdomain")
        mail_domain = args.mail_domain or get_param_from_env("mail_domain")
        uri_path = args.uri_path or get_param_from_env("uri_path")
        limit_str = get_param_from_env("limit")
        limit_from_env = int(limit_str) if limit_str else None

        # Validate that at least one search parameter is provided
        if not any([target_domain, mail_domain, uri_path]):
            output_json({"hosts": [], "command": {"tool": "bagre", "command": "bagre_executor.py", "duration": 0}})
            return 0

        # Load configuration
        try:
            config = load_config(args.config_file)
        except ValueError as exc:
            print(
                f"[BAGRE FATAL] config validation failed: {exc}",
                file=sys.stderr,
                flush=True,
            )
            output_json({"hosts": [], "command": {"tool": "bagre", "command": "bagre_executor.py", "duration": 0}})
            return 0

        # Determine query limit.
        #   limit > 0  : cap the number of credential rows returned to that many
        #   limit <= 0 : NO LIMIT — return every credential found across all
        #                downloaded files. Combine with INTELX_MAX_FILES=0 to
        #                also lift the download cap and pull everything for a
        #                domain.
        if args.limit is not None:
            limit = args.limit
        elif limit_from_env is not None:
            limit = limit_from_env
        else:
            limit = config.bagre.query_limit
        limit = None if (limit is not None and limit <= 0) else limit

        # Query the configured credential source (default: intelx; can be
        # overridden with BAGRE_SOURCE=clickhouse).
        try:
            source = get_source(config)
        except (ValueError, RuntimeError):
            output_json({"hosts": [], "command": {"tool": "bagre", "command": "bagre_executor.py", "duration": 0}})
            return 0

        try:
            with source.connection():
                credentials = source.query_credentials(
                    target_domain=target_domain,
                    target_subdomain=target_subdomain,
                    mail_domain=mail_domain,
                    uri_path=uri_path,
                    limit=limit,
                )
        except Exception as exc:
            import traceback

            print(
                f"[BAGRE FATAL] source.query_credentials raised " f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
            output_json({"hosts": [], "command": {"tool": "bagre", "command": "bagre_executor.py", "duration": 0}})
            return 0

        # Calculate duration
        duration = time.time() - start_time

        # Format output
        command_str = build_command_string(target_domain, target_subdomain, mail_domain, uri_path, limit)
        # Include credentials in bulk_create when BAGRE_IMPORT_CREDS=true
        include_creds_in_bulk = should_import_credentials()
        output = format_faraday_output(
            credentials=credentials,
            target_domain=target_domain,
            target_subdomain=target_subdomain,
            mail_domain=mail_domain,
            uri_path=uri_path,
            command=command_str,
            duration=duration,
            include_credentials=include_creds_in_bulk,
        )

        # Extract external_id for credential linking (remove it from output before sending)
        external_id = output.pop("_external_id", None)
        if not external_id and output.get("hosts"):
            # Fallback: extract from first vulnerability if not in output
            first_host = output["hosts"][0] if output["hosts"] else {}
            first_vuln = first_host.get("vulnerabilities", [{}])[0] if first_host.get("vulnerabilities") else {}
            external_id = first_vuln.get("external_id", "BAGRE-")

        import_enabled = should_import_credentials()
        faraday_cfg = FaradayConfig.from_env() if import_enabled else None

        # 1) Always let the dispatcher post the bulk_create — that path has
        #    the execution_id Faraday's API expects. The dispatcher streams
        #    stdout line-by-line, so the POST happens DURING this executor's
        #    lifetime, not after exit.
        output_json(output)

        # 2) If credential linking is enabled, run the linker immediately.
        #    The linker has its own 3-attempt retry with 5s waits to handle
        #    the case where the dispatcher's POST hasn't landed yet, so no
        #    extra leading sleep is needed.
        if import_enabled and faraday_cfg and faraday_cfg.is_configured() and credentials:
            print(
                f"[BAGRE] BAGRE_IMPORT_CREDS=true; linking {len(credentials)} "
                f"credentials to vulnerability external_id={external_id}",
                file=sys.stderr,
                flush=True,
            )
            import_credentials_to_faraday(credentials, external_id_pattern=external_id)
        elif import_enabled:
            print(
                "[BAGRE WARN] BAGRE_IMPORT_CREDS=true but Faraday config is incomplete; "
                "credentials will not be linked to the vulnerability",
                file=sys.stderr,
                flush=True,
            )
        else:
            print(
                "[BAGRE] Credential import disabled (BAGRE_IMPORT_CREDS not set to true)",
                file=sys.stderr,
                flush=True,
            )
        return 0

    except Exception as exc:
        # Log the traceback so the dispatcher captures it in stderr — silent
        # exception swallowing was hiding real bugs (e.g., the ekoparty.org
        # run that produced empty hosts with no diagnostic in the log).
        import traceback

        print(
            f"[BAGRE FATAL] main() raised {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        output_json({"hosts": [], "command": {"tool": "bagre", "command": "bagre_executor.py", "duration": 0}})
        return 0


if __name__ == "__main__":
    sys.exit(main())
