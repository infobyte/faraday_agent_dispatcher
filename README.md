# Faraday Agent Dispatcher

[![PyPI version](https://img.shields.io/pypi/v/faraday-agent-dispatcher.svg)](https://pypi.org/project/faraday-agent-dispatcher/)
[![License](https://img.shields.io/github/license/infobyte/faraday_agent_dispatcher.svg)](https://github.com/infobyte/faraday_agent_dispatcher/blob/master/LICENSE)

Faraday Agent Dispatcher helps you develop and run integrations with [Faraday](https://github.com/infobyte/faraday/) written in any language. It acts as a bridge between your security scanning tools and the Faraday platform, automatically collecting scan results and importing them into your workspace.

**Current version: 3.9.1**

## Features

- **27 official executors** — ready-to-use integrations for popular security tools (Nmap, Nessus, Nuclei, Burp Suite, and more)
- **Custom executor support** — write your own executors in any language (Python, Bash, or anything that prints JSON to stdout)
- **Interactive configuration wizard** — guided setup for server connection, agent registration, and executor configuration
- **YAML configuration** — human-readable config format (INI format supported as legacy)
- **Docker support** — pre-built Docker image with common security tools installed
- **Multiple dispatcher instances** — run separate configurations for different sets of executors
- **WebSocket communication** — real-time bidirectional communication with Faraday Server via Socket.IO
- **Async architecture** — concurrent executor management with asyncio

## Installation

### pip (recommended)

```bash
pip3 install faraday_agent_dispatcher
```

### From source (development)

```bash
git clone https://github.com/infobyte/faraday_agent_dispatcher.git
cd faraday_agent_dispatcher
pip install -e .
```

### Docker

```bash
docker pull faradaysec/faraday_agent_dispatcher:latest
```

See the [Docker documentation](https://docs.agents.faradaysec.com/misc/docker/) for detailed container setup.

## Quick Start

### 1. Run the Configuration Wizard

```bash
faraday-dispatcher config-wizard
```

The wizard will guide you through:
- Faraday Server connection (host, port, SSL)
- Agent registration token (found at `http://<faraday-server>:5985/#/admin/agents`)
- Executor selection and configuration

### 2. Start the Dispatcher

```bash
faraday-dispatcher run
```

The default configuration file is saved to `~/.faraday/config/dispatcher.yaml`. To use a custom path:

```bash
faraday-dispatcher run --config-file /path/to/config.yaml
```

### 3. Run an Executor

Once the dispatcher is connected, trigger executors from:
- **Faraday Web UI** — navigate to your workspace, select the agent, and click "Run"
- **Faraday API** — `POST /v3/ws/<workspace>/agents/<agent_id>/run/`

## Official Executors

| Category | Executors |
|----------|-----------|
| Network Scanning | [Nmap](https://nmap.org), [Sublist3r](https://github.com/aboul3la/Sublist3r), [Shodan](https://www.shodan.io/) |
| Vulnerability Scanning | [Nessus](https://www.nessus.org), [Tenable.io](https://www.tenable.com/), [Tenable.sc](https://www.tenable.com/), [OpenVAS/GVM](https://www.openvas.org/), [OpenVAS Legacy](https://www.openvas.org/), [InsightVM](https://www.rapid7.com/products/insightvm/), [Qualys](https://www.qualys.com/), [Nuclei](https://github.com/projectdiscovery/nuclei) |
| Web Application | [Burp Suite](https://www.portswigger.net/burp), [Arachni](https://www.arachni-scanner.com/), [ZAP](https://www.zaproxy.org/), [W3af](http://w3af.org/), [WPScan](https://wpscan.org/), [WPScan Legacy](https://wpscan.org/), [Nikto](https://cirt.net/Nikto2), [HCL AppScan](https://cloud.appscan.com) |
| Code Analysis | [SonarQube](https://www.sonarqube.org/), [CodeQL](https://codeql.github.com/), [Dependabot](https://github.com/dependabot), [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning) |
| Enterprise | [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), [Cisco CyberVision](https://www.cisco.com/c/en/us/products/security/cyber-vision/index.html), [Microsoft Defender](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint) |
| Utilities | Report Processor (import local reports with [Faraday Plugins](https://github.com/infobyte/faraday_plugins)) |

## Custom Executors

An executor is a script that prints **single-line JSON** data to stdout in the [Faraday bulk_create format](https://api.faradaysec.com/). Use stderr for logging and debugging output.

### Minimal Python Example

```python
#!/usr/bin/env python3
import json, sys

print("Starting scan...", file=sys.stderr)
data = {
    "hosts": [{
        "ip": "192.168.1.1",
        "description": "Test host",
        "vulnerabilities": [{
            "name": "Example Vuln",
            "desc": "Found by custom executor",
            "severity": "medium",
            "type": "Vulnerability",
        }]
    }]
}
print(json.dumps(data))
```

### Configuring a Custom Executor

Add your executor with the `faraday-dispatcher config-wizard` or directly in the YAML configuration:

```yaml
executors:
  my_scanner:
    cmd: python3 /path/to/my_executor.py
    max_size: 65536
    varenvs:
      API_KEY: your-api-key
    params:
      TARGET:
        type: string
        mandatory: true
```

See the [custom executor guide](https://docs.agents.faradaysec.com/examples/new-custom-executor/) for detailed instructions.

## Running Multiple Dispatchers

To run multiple dispatcher instances, each with its own executors, create separate configuration files:

```bash
faraday-dispatcher run --config-file ~/.faraday/config/dispatcher-1.yaml
faraday-dispatcher run --config-file ~/.faraday/config/dispatcher-2.yaml
```

## Requirements

- Python 3.8+
- [Faraday](https://github.com/infobyte/faraday/) Server (v4.0+)
- [faraday-plugins](https://github.com/infobyte/faraday_plugins) (>=1.26.0)
- [faraday-agent-parameters-types](https://pypi.org/project/faraday-agent-parameters-types/) (>=1.9.0)

## Documentation

Full documentation is available at **[docs.agents.faradaysec.com](https://docs.agents.faradaysec.com)**.

- [Getting Started](https://docs.agents.faradaysec.com/getting-started/)
- [Architecture](https://docs.agents.faradaysec.com/technical/arch/)
- [Executor Development](https://docs.agents.faradaysec.com/technical/agents/)
- [Docker Deployment](https://docs.agents.faradaysec.com/misc/docker/)
- [Executor Guides](https://docs.agents.faradaysec.com/misc/) (AppScan, Qualys, SonarQube, Tenable.io)

## API Reference

The Faraday REST API is documented at **[api.faradaysec.com](https://api.faradaysec.com/)**.

## Links

- [Faraday Platform](https://github.com/infobyte/faraday/)
- [Faraday Plugins](https://github.com/infobyte/faraday_plugins)
- [Faraday CLI](https://github.com/infobyte/faraday-cli)
- [PyPI Package](https://pypi.org/project/faraday-agent-dispatcher/)

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
