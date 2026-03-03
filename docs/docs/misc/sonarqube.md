# SonarQube Executor

The SonarQube executor connects to a [SonarQube](https://www.sonarqube.org/) server to download and import security-related issues (and optionally security hotspots) into Faraday.

## How It Works

1. Authenticates with SonarQube using a project or user token (token-based auth with empty password)
2. Queries the `/api/issues/search` endpoint for issues with **SECURITY** impact only
3. Paginates through all results (500 items per page)
4. Optionally fetches security hotspots via `/api/hotspots/search` and `/api/hotspots/show`
5. Parses all findings using `SonarQubeAPIPlugin` and sends them to Faraday via `bulk_create`

!!! info "Security Focus"
    The executor only imports issues with **SECURITY** software quality impact. Maintainability and reliability issues are excluded.

## Configuration

### Environment Variables

These are persistent settings stored in the `varenvs` section. They are **not** prefixed with `EXECUTOR_CONFIG_`.

| Variable | Required | Description |
|----------|----------|-------------|
| `SONAR_URL` | Yes | Full URL of your SonarQube server (e.g., `http://localhost:9000`) |

### Parameters

These are passed at run time and are prefixed with `EXECUTOR_CONFIG_` internally.

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `TOKEN` | Yes | — | SonarQube API token for authentication |
| `COMPONENT_KEY` | No | — | Project or component key to limit the export to a specific project. If omitted, all security issues across all projects are imported |
| `GET_HOTSPOT` | No | `false` | Set to `true` to also fetch security hotspots in addition to regular issues |

## YAML Configuration Example

```yaml
executors:
  sonarqube:
    repo_executor: sonarqube
    max_size: 65536
    varenvs:
      SONAR_URL: http://localhost:9000
    params:
      TOKEN: your-sonarqube-token
      COMPONENT_KEY: my-project-key
      GET_HOTSPOT: "true"
```

## Generating a SonarQube Token

1. Click your profile picture in SonarQube, then go to **My Account**
2. Navigate to the **Security** tab
3. Enter a name for the new token
4. Select the token type:
    - **User Token** — access to all projects your user can see
    - **Project Analysis Token** — scoped to a specific project (verify the correct project is selected)
5. Click **Generate** — the token will be displayed once

!!! warning
    Copy the token immediately after generation. SonarQube will not show it again.

## API Details

| Setting | Value |
|---------|-------|
| Page size | 500 items per page |
| Issue filter | `impactSoftwareQualities=SECURITY` |
| Hotspot filter | `status=TO_REVIEW` (only unreviewed hotspots) |
| Auth method | HTTP Basic (token as username, empty password) |

## Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Environment variable not found" | Missing `SONAR_URL` or `TOKEN` | Ensure both are set in your configuration |
| No results imported | No security issues exist | Check SonarQube directly for security-impact issues |
| Hotspots not imported | `GET_HOTSPOT` not enabled | Set `GET_HOTSPOT` parameter to `true` |
| Network errors | SonarQube unreachable | Verify `SONAR_URL` is correct and the server is accessible from the dispatcher host |
| Invalid JSON responses | API compatibility issue | Ensure your SonarQube version supports the `/api/issues/search` and `/api/hotspots/search` endpoints |
