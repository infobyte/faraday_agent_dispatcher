# Tenable.io Executor

The Tenable.io executor integrates with [Tenable.io](https://www.tenable.com/) to create, launch, and import vulnerability scan results into Faraday.

## How It Works

1. Authenticates with the Tenable.io API using access and secret keys
2. Creates a new scan, relaunches an existing scan, or downloads results from a completed scan
3. Polls scan status until completion (configurable interval)
4. Exports the scan report in Nessus format
5. Parses the report using `NessusPlugin` and sends findings to Faraday via `bulk_create`

## Configuration

### Environment Variables

These are persistent credentials stored in the `varenvs` section. They are **not** prefixed with `EXECUTOR_CONFIG_`.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TENABLE_ACCESS_KEY` | Yes | — | Tenable.io API access key |
| `TENABLE_SECRET_KEY` | Yes | — | Tenable.io API secret key |
| `TENABLE_PULL_INTERVAL` | No | `30` | Polling interval in seconds between status checks |

### Parameters

These are passed at run time and are prefixed with `EXECUTOR_CONFIG_` internally.

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `SCAN_NAME` | No | `faraday-scan` | Name for the scan in Tenable.io |
| `SCAN_ID` | No | — | ID of an existing scan to relaunch or download |
| `RELAUNCH_SCAN` | No | `false` | Set to `true` to relaunch an existing scan (requires `SCAN_ID`). If `false` with `SCAN_ID`, downloads the latest results without relaunching |
| `SCAN_TARGETS` | Conditional | — | JSON array of target IPs/hostnames (required for user-defined templates) |
| `TEMPLATE_NAME` | No | `agent_basic` | Tenable scan template name |
| `USE_USER_DEFINED_TEMPLATE` | No | `false` | Set to `true` to use a user-defined (custom policy) template |
| `AGENT_GROUP_NAME` | Conditional | — | Agent group name for agent-based scans (required for built-in templates) |

## YAML Configuration Example

```yaml
executors:
  tenableio:
    repo_executor: tenableio
    max_size: 65536
    varenvs:
      TENABLE_ACCESS_KEY: your-access-key
      TENABLE_SECRET_KEY: your-secret-key
      TENABLE_PULL_INTERVAL: "60"
    params:
      SCAN_NAME: weekly-vuln-scan
```

## Usage Scenarios

### Download Results from an Existing Scan

Provide `SCAN_ID` with `RELAUNCH_SCAN` set to `false` (default). The executor downloads the latest report without triggering a new scan.

```yaml
params:
  SCAN_ID: "42"
  RELAUNCH_SCAN: "false"
```

### Relaunch an Existing Scan

Provide `SCAN_ID` with `RELAUNCH_SCAN` set to `true`. The executor relaunches the scan and waits for completion.

```yaml
params:
  SCAN_ID: "42"
  RELAUNCH_SCAN: "true"
```

### Create a New Scan with a Built-in Template

Provide `SCAN_NAME`, `TEMPLATE_NAME`, and `AGENT_GROUP_NAME`. The executor creates a new agent-based scan.

```yaml
params:
  SCAN_NAME: my-network-scan
  TEMPLATE_NAME: agent_basic
  AGENT_GROUP_NAME: my-agent-group
```

### Create a New Scan with a User-Defined Template

Set `USE_USER_DEFINED_TEMPLATE` to `true` and provide `SCAN_TARGETS` as a JSON array, plus `TEMPLATE_NAME` matching a custom policy name.

```yaml
params:
  SCAN_NAME: custom-scan
  USE_USER_DEFINED_TEMPLATE: "true"
  TEMPLATE_NAME: My Custom Policy
  SCAN_TARGETS: '["192.168.1.0/24", "10.0.0.1"]'
```

## Supported Built-in Templates

The executor supports the following Tenable.io scan templates:

| Category | Templates |
|----------|-----------|
| General | `asv`, `discovery`, `basic`, `advanced`, `custom`, `offline` |
| Web Application | `webapp` |
| Compliance | `compliance`, `pci`, `scap` |
| Agent-based | `agent_basic`, `agent_advanced`, `agent_compliance`, `agent_scap`, `agent_malware`, `agent_custom`, `agent_inventory_collection`, `agent_log4shell` |
| Cloud | `cloud_audit` |
| Malware | `malware`, `mdm` |
| Threat-specific | `wannacry`, `intelamt`, `ghost`, `spectre_meltdown`, `zerologon`, `solorigate`, `hafnium`, `printnightmare`, `log4shell`, `log4shell_dc`, `log4shell_vulnerable_ecosystem` |
| Assessment | `patch_audit`, `active_directory`, `active_directory_identity`, `ripple-treck`, `eoy22`, `cisa_alert_aa22011a`, `contileaks`, `ransomware_ecosystem_2022` |

## Generating API Keys

1. Log in to [Tenable.io](https://cloud.tenable.com/)
2. Navigate to **My Account → API Keys**
3. Generate an access key and secret key pair
4. Store these in the executor's `varenvs` configuration

## Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| "access_key and secret_key were not provided" | Missing API credentials | Set `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY` |
| "Scan id not found" | Invalid scan ID | Check dispatcher logs for available scan IDs |
| "The provided template name does not exist" | Invalid template | Use one of the supported template names listed above, or set `USE_USER_DEFINED_TEMPLATE` to `true` for custom policies |
| "The provided agent group does not exist" | Invalid agent group | Verify the agent group name in your Tenable.io console |
| "Scan completed but did not return any results" | Empty scan results | Verify targets are reachable and scan template is appropriate |
| Scanner ends with non-completed status | Scan failed | Check Tenable.io console for scan error details |
