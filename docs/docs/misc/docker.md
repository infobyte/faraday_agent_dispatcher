# Docker Deployment

**Dispatcher version:** 3.9.1 | **Image:** `faradaysec/faraday_agent_dispatcher`

Deploy the Faraday Agent Dispatcher in a Docker container for isolated, reproducible agent environments with pre-installed security tools.

---

## Quick Start

```shell
# 1. Pull the image
docker pull faradaysec/faraday_agent_dispatcher

# 2. Create your configuration file (see Configuration section below)

# 3. Run with registration token (first time only)
docker run \
  -v /path/to/dispatcher.yaml:/root/.faraday/config/dispatcher.yaml \
  faradaysec/faraday_agent_dispatcher \
  --token=<REGISTRATION_TOKEN>
```

!!! warning
    You only need the `--token` flag the first time you run an agent. After registration, the agent token is saved to the config file and used automatically on subsequent runs.

---

## Docker Image Architecture

The official Docker image is built in two stages:

1. **Tools base image** (`plugins-docker/Dockerfile`) — Based on **Kali Linux Rolling**, includes pre-installed security tools (see [Pre-installed Tools](#pre-installed-tools))
2. **Dispatcher image** (`publish/Dockerfile`) — Installs the dispatcher Python package on top of the tools image:
    - Creates a Python virtual environment at `/opt/dispatcher_venv`
    - Installs `faraday_agent_dispatcher` and all dependencies
    - Sets entrypoint: `faraday-dispatcher run`

---

## Configuration

Create a `dispatcher.yaml` file to mount into the container. The file is mounted at `/root/.faraday/config/dispatcher.yaml`.

### HTTP configuration

For Faraday servers running without SSL:

```yaml
server:
  host: faraday-server.local
  ssl: false
  ssl_cert: ''
  ssl_ignore: false
  api_port: 5985
  websocket_port: 5985

agent:
  agent_name: docker-agent
  description: "Docker-based scanner agent"
  executors:
    nmap_scan:
      repo_executor: nmap.py
      repo_name: nmap
      max_size: 65536
      varenvs: {}
      params: {}
```

### HTTPS configuration (behind NGINX)

For production deployments with SSL termination:

```yaml
server:
  host: faraday.example.com
  ssl: true
  ssl_cert: ''
  ssl_ignore: false
  api_port: 443
  websocket_port: 443

agent:
  agent_name: docker-agent-prod
  description: "Production scanner agent"
  executors:
    nessus_scan:
      repo_executor: nessus.py
      repo_name: nessus
      max_size: 65536
      varenvs:
        NESSUS_USERNAME: "nessus_user"
        NESSUS_PASSWORD: "nessus_pass"
        NESSUS_URL: "https://nessus.internal:8834"
      params: {}
```

### Full configuration example

A complete configuration with multiple executors:

```yaml
server:
  host: faraday.example.com
  ssl: true
  ssl_cert: ''
  ssl_ignore: false
  api_port: 443
  websocket_port: 443

agent:
  agent_name: full-scanner
  description: "Multi-tool scanning agent"
  executors:
    nmap_scan:
      repo_executor: nmap.py
      repo_name: nmap
      max_size: 65536
      varenvs: {}
      params: {}
    nessus_scan:
      repo_executor: nessus.py
      repo_name: nessus
      max_size: 65536
      varenvs:
        NESSUS_USERNAME: "admin"
        NESSUS_PASSWORD: "secret"
        NESSUS_URL: "https://nessus.internal:8834"
      params: {}
    nuclei_scan:
      repo_executor: nuclei.py
      repo_name: nuclei
      max_size: 65536
      varenvs: {}
      params: {}
    nikto_scan:
      repo_executor: nikto2.py
      repo_name: nikto2
      max_size: 65536
      varenvs: {}
      params: {}
    wpscan_scan:
      repo_executor: wpscan.py
      repo_name: wpscan
      max_size: 65536
      varenvs: {}
      params: {}
```

---

## Running the Container

### First run (registration)

On the first run, pass the registration token obtained from **Administration > Agents** in the Faraday UI:

```shell
docker run \
  -v /absolute/path/to/dispatcher.yaml:/root/.faraday/config/dispatcher.yaml \
  faradaysec/faraday_agent_dispatcher \
  --token=<REGISTRATION_TOKEN>
```

After successful registration, the agent token is written back to the config file. Since the config file is mounted from the host, the token persists across container restarts.

### Subsequent runs

```shell
docker run \
  -v /absolute/path/to/dispatcher.yaml:/root/.faraday/config/dispatcher.yaml \
  faradaysec/faraday_agent_dispatcher
```

### With report import support

If you need to import report files (e.g., for the `report_processor` executor), mount a reports directory:

```shell
docker run \
  -v /absolute/path/to/dispatcher.yaml:/root/.faraday/config/dispatcher.yaml \
  -v /absolute/path/to/reports/:/root/reports/ \
  faradaysec/faraday_agent_dispatcher \
  --token=<REGISTRATION_TOKEN>
```

Then specify the report path as an executor parameter when triggering a scan.

### With custom SSL certificate

Mount a CA certificate for self-signed or internal certificate authorities:

```shell
docker run \
  -v /absolute/path/to/dispatcher.yaml:/root/.faraday/config/dispatcher.yaml \
  -v /absolute/path/to/ca-cert.pem:/root/.faraday/certs/ca-cert.pem:ro \
  faradaysec/faraday_agent_dispatcher
```

Update the config to reference the mounted certificate:

```yaml
server:
  ssl: true
  ssl_cert: '/root/.faraday/certs/ca-cert.pem'
```

### Background (detached) mode

For persistent deployments:

```shell
docker run -d \
  --name faraday-agent \
  --restart unless-stopped \
  -v /absolute/path/to/dispatcher.yaml:/root/.faraday/config/dispatcher.yaml \
  faradaysec/faraday_agent_dispatcher
```

---

## Pre-installed Tools

The Docker image includes these security tools pre-installed and ready to use:

| Tool | Source | Executor |
|------|--------|----------|
| Nmap | Kali package | `nmap.py` |
| Nmap vulners NSE | Kali package | (used by nmap executor) |
| Nikto | Kali package | `nikto2.py` |
| CrackMapExec | Kali package | `crackmapexec.py` |
| Nuclei | Built from source (v3, Go) | `nuclei.py` |
| WPScan | Ruby gem | `wpscan.py` |
| Arachni | v1.6.1.3 | `arachni.py` |
| OpenVAS | Kali package | `gvm_openvas.py`, `openvas_legacy.py` |
| Chromium | Kali package | (used by web scanning tools) |

**Tools NOT included** in the image (they run as external services, accessed via API):

- **Nessus** — requires a Nessus server URL
- **Burp Suite** — requires Burp Enterprise/Pro server
- **ZAP** — requires a ZAP server instance
- **Tenable.io / Tenable.sc** — cloud API access
- **Qualys** — cloud API access
- **SonarQube** — requires a SonarQube server
- **Shodan** — cloud API access

---

## Docker Compose

Example `docker-compose.yaml` for deploying the agent alongside Faraday:

```yaml
version: '3.8'

services:
  faraday-agent:
    image: faradaysec/faraday_agent_dispatcher
    container_name: faraday-agent
    restart: unless-stopped
    volumes:
      - ./dispatcher.yaml:/root/.faraday/config/dispatcher.yaml
      - ./reports:/root/reports
    # First run only — remove after registration:
    # command: ["--token", "<REGISTRATION_TOKEN>"]
    networks:
      - faraday-net

networks:
  faraday-net:
    external: true
```

Register the agent for the first time:

```shell
docker compose run --rm faraday-agent --token=<REGISTRATION_TOKEN>
```

Then start normally:

```shell
docker compose up -d
```

---

## Custom Docker Images

To build a custom image with additional tools:

```dockerfile
FROM faradaysec/faraday_agent_dispatcher:latest

# Install additional tools
RUN apt-get update && apt-get install -y \
    your-custom-tool \
    && rm -rf /var/lib/apt/lists/*

# Copy custom executor scripts
COPY my_executor.py /opt/custom_executors/

# The entrypoint is inherited: faraday-dispatcher run
```

Build and run:

```shell
docker build -t my-faraday-agent .
docker run -v /path/to/config.yaml:/root/.faraday/config/dispatcher.yaml \
  my-faraday-agent --token=<TOKEN>
```

---

## Volume Mounts Reference

| Container Path | Purpose | Required |
|----------------|---------|----------|
| `/root/.faraday/config/dispatcher.yaml` | Dispatcher configuration file | Yes |
| `/root/reports/` | Report files for `report_processor` executor | No |
| `/root/.faraday/certs/` | Custom SSL certificates | No |
| `/root/.faraday/logs/` | Dispatcher log files (persist for debugging) | No |

---

## Troubleshooting

### Container exits immediately

Check the container logs:

```shell
docker logs faraday-agent
```

Common causes:

- Config file not mounted or invalid YAML syntax
- Server unreachable (check host/port from within the container network)
- Invalid or expired agent token — re-register with `--token`

### Network connectivity issues

If the container cannot reach the Faraday server:

```shell
# Test connectivity from within the container
docker run --rm -it faradaysec/faraday_agent_dispatcher bash
curl -k https://faraday.example.com:443/_api/config
```

For Docker-to-Docker communication, ensure both containers are on the same Docker network.

### SSL certificate issues

```shell
# Verify the cert is accessible inside the container
docker run --rm \
  -v /path/to/ca-cert.pem:/root/.faraday/certs/ca-cert.pem:ro \
  faradaysec/faraday_agent_dispatcher \
  bash -c "openssl x509 -in /root/.faraday/certs/ca-cert.pem -noout -text"
```

### Tool not found errors

If an executor fails because a tool isn't installed:

1. Check if the tool is in the [pre-installed tools](#pre-installed-tools) list
2. For API-based tools (Nessus, Burp, etc.), the tool itself doesn't need to be installed — only network access to the tool's API is needed
3. Build a [custom Docker image](#custom-docker-images) with the missing tool

[dockerhub]: https://hub.docker.com/u/faradaysec
[getting-started]: ../getting-started.md
