# QualysGuard Executor

The QualysGuard executor integrates with [Qualys VMDR](https://www.qualys.com/) to launch vulnerability scans and import results into Faraday.

## How It Works

1. Authenticates with the Qualys API using HTTP Basic Auth
2. Checks if the target IP exists in your Qualys asset inventory; creates it if not found
3. Launches a vulnerability scan using the specified option profile
4. Polls the scan status until completion (configurable interval)
5. Downloads the scan report and parses it using `QualysguardPlugin`
6. Sends findings to Faraday via `bulk_create`

## Configuration

### Environment Variables

These are persistent credentials stored in the `varenvs` section. They are **not** prefixed with `EXECUTOR_CONFIG_`.

| Variable | Required | Description |
|----------|----------|-------------|
| `QUALYS_USERNAME` | Yes | Qualys web login username |
| `QUALYS_PASSWORD` | Yes | Qualys web login password |

### Parameters

These are passed at run time and are prefixed with `EXECUTOR_CONFIG_` internally.

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `TARGET_IP` | Yes | — | IP address of the host to scan. The executor will create it in Qualys if not already registered |
| `OPTION_PROFILE` | Yes | — | Scan option profile ID (numeric) or name. Must already exist in Qualys |
| `PULL_INTERVAL` | No | `180` | Polling interval in seconds — how often the executor checks if the scan has finished |

!!! note "Option Profile"
    The `OPTION_PROFILE` parameter accepts either a numeric profile ID or a profile name string. If the profile is not found, the executor will display available profiles in the dispatcher logs to help you select the correct one.

## YAML Configuration Example

```yaml
executors:
  qualys:
    repo_executor: qualys
    max_size: 65536
    varenvs:
      QUALYS_USERNAME: your-qualys-username
      QUALYS_PASSWORD: your-qualys-password
    params:
      TARGET_IP: 192.168.1.100
      OPTION_PROFILE: "12345"
```

## Finding Your Option Profile ID

### Create a Scan Profile

In the Qualys VMDR section, navigate to:

**Scans → Option Profiles → New → Option Profile**

Complete the profile configuration as needed for your scanning requirements.

### Find the Profile ID

1. In the Option Profiles list, click on the profile title
2. Select **Info** from the dropdown menu
3. The profile ID is the first field displayed in the details panel

!!! tip
    You can use either the numeric ID or the profile name. Using the numeric ID is more reliable since names may not be unique.

## API Base URL

The executor connects to: `https://qualysguard.qg4.apps.qualys.com`

If your Qualys instance uses a different platform URL, you will need to modify the executor source code.

## Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Param TARGET_IP no passed" | Missing target IP | Provide the `TARGET_IP` parameter |
| "Param OPTION_PROFILE no passed" | Missing profile | Provide the `OPTION_PROFILE` parameter |
| Profile not found (error 1905) | Invalid profile ID/name | Check dispatcher logs for available profiles and use a valid one |
| Scan ends with non-Finished status | Scan error or timeout | Check Qualys console for scan details; increase `PULL_INTERVAL` if needed |
