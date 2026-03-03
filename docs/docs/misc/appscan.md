# HCL AppScan Executor

The AppScan executor integrates with [HCL AppScan on Cloud](https://cloud.appscan.com) to create, launch, and import DAST and SAST scan results into Faraday.

## How It Works

1. Authenticates with the AppScan API using your API key credentials
2. Creates a new scan **or** relaunches an existing scan
3. Waits for the scan execution to complete
4. Generates an XML security report from the scan results
5. Parses the report using the `AppScanPlugin` and sends findings to Faraday via `bulk_create`

## Configuration

### Environment Variables

These are persistent credentials stored in the `varenvs` section of your dispatcher configuration. They are **not** prefixed with `EXECUTOR_CONFIG_`.

| Variable | Required | Description |
|----------|----------|-------------|
| `HCL_KEY_ID` | Yes | API key ID for AppScan authentication |
| `HCL_KEY_SECRET` | Yes | API key secret for AppScan authentication |
| `HCL_APP_ID` | Yes | Application ID in AppScan to associate scans with |

### Parameters

These are passed at run time (from the Faraday UI or API) and are prefixed with `EXECUTOR_CONFIG_` internally.

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `HCL_SCAN_TYPE` | Yes | — | Scan type: `DAST` or `SAST` |
| `HCL_SCAN_TARGET` | Conditional | — | Target URL (DAST) or file ID (SAST). Required when creating a new scan |
| `HCL_SCAN_ID` | Conditional | — | Existing scan ID to relaunch. If provided, the executor runs this scan instead of creating a new one |
| `HCL_SCAN_NAME` | No | `<timestamp>-faraday-agent` | Custom name for the scan |

!!! note "Scan ID vs. Scan Target"
    You must provide **either** `HCL_SCAN_ID` (to relaunch an existing scan) **or** `HCL_SCAN_TARGET` (to create a new scan). If neither is provided, the executor will exit with an error.

## YAML Configuration Example

```yaml
executors:
  appscan:
    repo_executor: appscan
    max_size: 65536
    varenvs:
      HCL_KEY_ID: your-api-key-id
      HCL_KEY_SECRET: your-api-key-secret
      HCL_APP_ID: your-application-id
    params:
      HCL_SCAN_TYPE: DAST
```

## Usage Scenarios

### Create and Run a New DAST Scan

Set `HCL_SCAN_TYPE` to `DAST` and provide `HCL_SCAN_TARGET` with the URL of the target application. The target must already be registered in AppScan.

### Create and Run a New SAST Scan

Set `HCL_SCAN_TYPE` to `SAST` and provide `HCL_SCAN_TARGET` with the file ID of the application to analyze.

### Relaunch an Existing Scan

Provide `HCL_SCAN_ID` with the ID of a previously created scan. The executor will trigger a new execution of that scan and download the results.

## Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Key id, key secret or app_id missing" | Missing environment variables | Verify `HCL_KEY_ID`, `HCL_KEY_SECRET`, and `HCL_APP_ID` are set |
| "Invalid SCAN TYPE" | Wrong scan type value | Use exactly `DAST` or `SAST` (case-insensitive, converted to uppercase) |
| "Target not specified" | Neither target nor scan ID provided | Set `HCL_SCAN_TARGET` or `HCL_SCAN_ID` |
| HTTP 403 error | Insufficient permissions | Check that your API key has scan execution permissions for the application |
