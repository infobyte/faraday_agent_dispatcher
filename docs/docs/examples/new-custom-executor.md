# Writing a Custom Executor

This guide walks you through creating a custom executor for Faraday Agent Dispatcher. An executor is any script or program that outputs Faraday-compatible JSON to stdout.

## The Executor Contract

Every executor must follow these rules:

1. **Print JSON data to stdout** — each line must be a valid JSON object conforming to the `bulk_create` schema
2. **Use stderr for logging** — any non-JSON output to stdout will cause a dispatcher error
3. **Exit with code 0 on success** — non-zero exit codes indicate failure
4. **Read configuration from environment variables** — the dispatcher injects these before execution
5. **Be idempotent when possible** — executors may be triggered multiple times

## Environment Variables

The dispatcher provides configuration to executors through three categories of environment variables:

| Prefix | Source | Typical Use |
|--------|--------|-------------|
| `EXECUTOR_CONFIG_*` | Run-time parameters from Faraday UI/API | Scan targets, options |
| `AGENT_CONFIG_*` | Common agent settings | `AGENT_CONFIG_IGNORE_INFO`, `AGENT_CONFIG_RESOLVE_HOSTNAME`, `AGENT_CONFIG_VULN_TAG` |
| No prefix | Persistent credentials in `varenvs` | API keys, tokens, passwords |

## Example: Python Executor

This minimal executor creates a host with a vulnerability:

```python
#!/usr/bin/env python3
"""
Minimal Faraday executor example.
Prints bulk_create-compatible JSON to stdout.
"""
import json
import sys

def main():
    # Use stderr for logging — stdout is reserved for JSON data
    print("Starting scan...", file=sys.stderr)

    # Build the host data with a vulnerability
    host = {
        "ip": "192.168.1.1",
        "description": "Test host",
        "hostnames": ["example.local"],
        "vulnerabilities": [
            {
                "name": "Example Vulnerability",
                "desc": "This is a test vulnerability found by the custom executor",
                "severity": "medium",
                "type": "Vulnerability",
                "refs": ["CVE-2024-0001"],
            }
        ],
        "services": [
            {
                "name": "http",
                "port": 80,
                "protocol": "tcp",
                "vulnerabilities": [
                    {
                        "name": "Web Vulnerability",
                        "severity": "low",
                        "type": "VulnerabilityWeb",
                        "method": "GET",
                        "website": "http://example.local",
                        "path": "/admin",
                        "status_code": 200,
                    }
                ],
            }
        ],
        "credentials": [
            {
                "name": "Default credentials",
                "username": "admin",
                "password": "admin",
            }
        ],
    }

    # Each print to stdout must be a single-line JSON object
    data = {"hosts": [host]}
    print(json.dumps(data))

    print("Scan complete.", file=sys.stderr)


if __name__ == "__main__":
    main()
```

## Example: Bash Executor

Executors can be written in any language. Here is a Bash example:

```bash
#!/bin/bash
# Minimal Faraday executor in Bash

echo "Starting scan..." >&2

# Read parameters from environment variables
TARGET="${EXECUTOR_CONFIG_TARGET:-192.168.1.1}"

# Output must be single-line JSON to stdout
cat <<ENDJSON
{"hosts": [{"ip": "$TARGET", "description": "Scanned host", "vulnerabilities": [{"name": "Open Port", "desc": "Port 22 is open", "severity": "info", "type": "Vulnerability"}]}]}
ENDJSON

echo "Scan complete." >&2
```

## bulk_create JSON Schema

Each line printed to stdout must conform to the Faraday `bulk_create` endpoint schema:

```json
{
  "hosts": [
    {
      "ip": "192.168.1.1",
      "description": "Host description",
      "hostnames": ["host.example.com"],
      "mac": "00:11:22:33:44:55",
      "os": "Linux",
      "vulnerabilities": [
        {
          "name": "Vulnerability Name",
          "desc": "Detailed description",
          "severity": "critical|high|medium|low|info|unclassified",
          "type": "Vulnerability",
          "refs": ["CVE-XXXX-YYYY", "https://example.com/advisory"],
          "resolution": "How to fix",
          "data": "Raw output data",
          "impact": {
            "accountability": true,
            "availability": false
          }
        }
      ],
      "services": [
        {
          "name": "http",
          "port": 80,
          "protocol": "tcp",
          "status": "open",
          "version": "Apache 2.4",
          "vulnerabilities": [
            {
              "name": "Web Vulnerability",
              "severity": "high",
              "type": "VulnerabilityWeb",
              "method": "POST",
              "website": "https://example.com",
              "path": "/login",
              "parameter_name": "username",
              "status_code": 200,
              "request": "POST /login HTTP/1.1...",
              "response": "HTTP/1.1 200 OK..."
            }
          ]
        }
      ],
      "credentials": [
        {
          "name": "Credential name",
          "username": "admin",
          "password": "secret"
        }
      ]
    }
  ],
  "command": {
    "tool": "my-custom-tool",
    "command": "custom-executor",
    "duration": 120
  }
}
```

### Severity Values

| Value | Description |
|-------|-------------|
| `critical` | Critical severity |
| `high` | High severity |
| `medium` | Medium severity |
| `low` | Low severity |
| `info` | Informational |
| `unclassified` | Unclassified severity |

### Vulnerability Types

| Type | Description |
|------|-------------|
| `Vulnerability` | Standard infrastructure vulnerability |
| `VulnerabilityWeb` | Web application vulnerability (requires `method`, `website`, `path`) |

## Registering Your Executor

### Using the Config Wizard

Run `faraday-dispatcher config-wizard` and select "Add a custom executor" to interactively configure:

1. Executor name
2. Command to run (e.g., `python3 /path/to/my_executor.py`)
3. Maximum JSON payload size
4. Environment variables (persistent credentials)
5. Parameters (run-time arguments)

### Manual YAML Configuration

Add your executor to the dispatcher YAML configuration:

```yaml
executors:
  my_custom_scanner:
    cmd: python3 /opt/executors/my_executor.py
    max_size: 65536
    varenvs:
      API_KEY: your-api-key
      API_SECRET: your-api-secret
    params:
      TARGET:
        type: string
        mandatory: true
      SCAN_DEPTH:
        type: integer
        mandatory: false
```

!!! note "Official vs. Custom Executors"
    Official executors use `repo_executor` (the executor name from the built-in library). Custom executors use `cmd` (the full command to run). Do not mix both in the same executor definition.

## Debugging Your Executor

The simplest way to debug is to run the executor directly outside the dispatcher:

```bash
# Set environment variables manually
export EXECUTOR_CONFIG_TARGET="192.168.1.1"
export MY_API_KEY="test-key"

# Run the executor and inspect JSON output
python3 my_executor.py

# Validate the JSON output
python3 my_executor.py | python3 -m json.tool
```

Since the executor just prints JSON to stdout, you can see all the data it would send to Faraday without actually sending it.

## Using a Faraday Plugin

If you are integrating with a tool that already has a [Faraday plugin](https://github.com/infobyte/faraday_plugins), you can leverage it to parse the tool's native output format:

```python
#!/usr/bin/env python3
import subprocess
import sys
from faraday_plugins.plugins.repo.nmap.plugin import NmapPlugin
from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters

def main():
    agent_config = get_common_parameters()

    # Run the scan tool
    result = subprocess.run(
        ["nmap", "-oX", "-", "192.168.1.0/24"],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        print(f"Scan failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Parse with the Faraday plugin
    plugin = NmapPlugin(**agent_config.to_plugin_kwargs())
    plugin.parseOutputString(result.stdout)
    print(plugin.get_json())

if __name__ == "__main__":
    main()
```

The `get_common_parameters()` function from `faraday_agent_dispatcher.utils.agent_configuration` reads the common `AGENT_CONFIG_*` environment variables and returns a configuration object. Call `.to_plugin_kwargs()` to convert it into keyword arguments for the plugin constructor.

## Tips

- **One JSON object per line** — each `print(json.dumps(data))` call should produce exactly one line
- **Incremental output** — for long-running scans, you can print multiple JSON objects (one per line) as results become available
- **Error handling** — print errors to stderr and exit with a non-zero code to signal failure to the dispatcher
- **Timeouts** — the dispatcher does not impose execution timeouts by default; implement your own if needed
- **Large results** — if your output exceeds `max_size`, increase it in the executor configuration
