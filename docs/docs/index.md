# Faraday Agent Dispatcher

**Version:** 3.9.1 | **Python:** 3.10+ | **Faraday Server:** 5.x

The Faraday Agent Dispatcher connects your security tools to [Faraday](https://github.com/infobyte/faraday) for automated, non-interactive vulnerability scanning. It eliminates the need to manually run tools and import reports — instead, agents run as persistent background processes that execute on demand and stream results directly into your workspace.

---

## How It Works

1. The dispatcher connects to the Faraday server via Socket.IO
2. It advertises its configured **executors** (security tool wrappers)
3. You trigger scans from the Faraday UI, the scheduler, or the API
4. The dispatcher launches the requested executor as a subprocess
5. Results are sent to the Faraday `bulk_create` endpoint automatically

Each agent can host **multiple executors**. An executor is a script (any language) that wraps a specific tool and outputs Faraday-compatible JSON to stdout.

---

## Official Executors

The dispatcher ships with **27 built-in executors** covering popular security tools:

| Category | Executors |
|----------|-----------|
| **Network scanning** | Nmap, Shodan |
| **Vulnerability scanning** | Nessus, Qualys, Tenable.io, Tenable.sc, InsightVM, OpenVAS (GVM), OpenVAS (legacy) |
| **Web application** | Burp Suite, ZAP, Arachni, Nikto, W3AF, WPScan, Nuclei |
| **Code analysis** | SonarQube, CodeQL, Dependabot |
| **Enterprise** | IBM AppScan, Cisco CyberVision, Microsoft Defender |
| **Utilities** | CrackMapExec, Sublist3r, Report Processor |

You can also write **custom executors** in any programming language.

---

## Quick Start

```shell
# Install
pip install faraday_agent_dispatcher

# Configure
faraday-dispatcher config-wizard

# Register and run (first time — get a token from Faraday admin panel)
faraday-dispatcher run --token=YOUR_TOKEN

# Subsequent runs (token is stored in config)
faraday-dispatcher run
```

For full instructions, see the [Getting Started Guide](getting-started.md).

---

## Documentation

| Page | Description |
|------|-------------|
| [Getting Started](getting-started.md) | Installation, configuration, registration, and first run |
| [Architecture](technical/arch.md) | Component diagram and communication protocol |
| [Agents & Executors](technical/agents.md) | Executor model, environment variables, parameters, and custom development |
| [Docker Deployment](misc/docker.md) | Docker image, docker-compose, and pre-installed tools |
| [Custom Executor Example](examples/new-custom-executor.md) | Step-by-step guide to writing your own executor |

---

## Docker

A pre-built Docker image is available with common security tools already installed:

```shell
docker pull faradaysec/faraday_agent_dispatcher
```

See the [Docker guide](misc/docker.md) for details.

---

## Links

- [Faraday Server](https://github.com/infobyte/faraday)
- [Faraday Plugins](https://github.com/infobyte/faraday_plugins)
- [Report an Issue](https://github.com/infobyte/faraday_agent_dispatcher/issues)
- [Faraday Documentation](https://docs.faradaysec.com)
