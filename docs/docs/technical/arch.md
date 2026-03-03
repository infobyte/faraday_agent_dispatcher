# Architecture

**Dispatcher version:** 3.9.1 | **Faraday Server:** 5.x

Faraday is a web application — the [server][server] is built with Python using Flask. You can automate tool usage with Faraday [agents][agents], which run as persistent background processes and execute security tools on demand.

---

## Overview

```
+------------------+       Socket.IO       +-------------------+
|                  | <-------------------> |                   |
|  Faraday Server  |    REST API (HTTPS)   | Agent Dispatcher  |
|  (Flask + Redis) | <-------------------> | (Python asyncio)  |
|                  |                       |                   |
+------------------+                       +--------+----------+
       |                                           |
       | bulk_create API                           | subprocess
       |                                           | (stdin/stdout/stderr)
       v                                           v
+------------------+                       +-------------------+
|   PostgreSQL     |                       |   Executor        |
|   (results)      |                       |   (nmap, nuclei,  |
+------------------+                       |    burp, etc.)    |
                                           +-------------------+
```

The system has three main components:

1. **Faraday Server** — The central platform, accessed via web browser or the [Faraday CLI][cli]. Both communicate with the server through its [REST API][api].
2. **Agent Dispatcher** — A middleware process that connects to the server, receives run commands, spawns executor subprocesses, and submits results.
3. **Executors** — Scripts that wrap specific security tools. They can be in any language and interact with any external service.

---

## Faraday Server

The server exposes a REST API for data operations and a Socket.IO namespace (`/dispatcher`) for real-time agent communication. Key server-side modules:

| Module | Purpose |
|--------|---------|
| `api/modules/agent.py` | Agent CRUD, token management, run endpoint |
| `api/modules/agent_execution.py` | Execution history tracking |
| `api/modules/agent_auth_token.py` | Registration token generation |
| `api/modules/agents_schedule.py` | Cron-based scheduler for automated runs |
| WebSocket server (Socket.IO) | `/dispatcher` namespace for real-time commands |

Other main server components include the Report Processor (for file-based report imports) and the WebSocket server (which also pushes notifications to the web UI).

---

## Agent Dispatcher

The dispatcher is a **single-process, async** Python application built on [asyncio][asyncio]. It:

1. Connects to the Faraday server via Socket.IO on the `/dispatcher` namespace
2. Announces its available executors with a `join_agent` event
3. Waits for `run` commands from the server (triggered by the UI, scheduler, or API)
4. Spawns executor scripts as subprocesses using `asyncio.create_subprocess_shell`
5. Reads stdout (JSON data) and stderr (logs) concurrently via async coroutines
6. POSTs each JSON result to the Faraday `bulk_create` endpoint
7. Reports execution status back via Socket.IO `run_status` events

### Core modules

| Module | File | Purpose |
|--------|------|---------|
| **Dispatcher** | `dispatcher_io.py` | Core class: registration, Socket.IO connection, executor management |
| **DispatcherNamespace** | `dispatcher_io.py` | Socket.IO event handler (`on_connect`, `on_run`, `on_disconnect`) |
| **Executor** | `executor.py` | Executor model: config validation, command resolution, dependency checks |
| **StdOutLineProcessor** | `executor_helper.py` | Reads executor stdout, parses JSON, POSTs to `bulk_create` |
| **StdErrLineProcessor** | `executor_helper.py` | Reads executor stderr, logs to dispatcher output |
| **Config** | `config.py` | YAML/INI configuration loading and validation |
| **CLI** | `cli/main.py` | Click-based CLI entry point (`run`, `config-wizard`) |
| **Wizard** | `cli/wizard.py` | Interactive configuration wizard |

---

## Communication Protocol

The dispatcher uses two communication channels to interact with the Faraday server:

### REST API

General data operations — registration, connectivity checks, and result submission. The dispatcher always initiates these requests.

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/_api/config` | GET | None | Connectivity / health check |
| `/_api/v3/agents` | POST | Registration token | Register new agent, returns agent token |
| `/_api/v3/agent_websocket_token` | POST | Agent token | Obtain Socket.IO authentication token |
| `/_api/v3/ws/{workspace}/bulk_create` | POST | Agent token | Submit scan results (hosts, services, vulns) |

**Authentication headers:**

- Registration: `Authorization: Token <registration_token>`
- Agent operations: `Authorization: agent <agent_token>`

!!! info "REST API Documentation"
    For full API details, see the [API documentation][api].

### Socket.IO Events (`/dispatcher` namespace)

Real-time command channel. The dispatcher connects to the `/dispatcher` Socket.IO namespace using `python-socketio`.

**Agent → Server events:**

| Event | Payload | When |
|-------|---------|------|
| `join_agent` | `{action: "JOIN_AGENT", token, executors: [{executor_name, args, category, tool}]}` | On connect — announces available executors |
| `run_status` | `{action: "RUN_STATUS", execution_ids, executor_name, running, successful, message}` | During/after executor execution |

**Server → Agent events:**

| Event | Payload | When |
|-------|---------|------|
| `run` | `{action: "RUN", execution_ids, workspaces, executor, args, plugin_args}` | Triggered by UI, scheduler, or API |

Key points:

- The agent always initiates the connection. The server cannot push-start an agent that isn't connected.
- The server sends `run` commands to tell the agent which executor to run, with what parameters and target workspaces.
- The agent responds with `run_status` to report whether the executor started, succeeded, or failed.

---

## Agent Registration Flow

```
Agent Dispatcher                              Faraday Server
      |                                              |
      |--- GET /_api/config ----------------------->|  (1) Connection check
      |<-- 200 OK ----------------------------------|
      |                                              |
      |--- POST /_api/v3/agents ------------------->|  (2) Register agent
      |   {token, name, description}                 |      (one-time, with reg token)
      |<-- 200 {token: "<agent_token>"} ------------|
      |                                              |
      |   [agent_token saved to config YAML]         |
      |                                              |
      |--- POST /_api/v3/agent_websocket_token ----->|  (3) Get WS auth token
      |   Authorization: agent <agent_token>         |
      |<-- 200 {token: "<ws_token>"} ---------------|
      |                                              |
      |=== Socket.IO connect /dispatcher ==========>|  (4) Establish connection
      |                                              |
      |--- emit("join_agent") --------------------->|  (5) Announce executors
      |   {action: "JOIN_AGENT",                     |
      |    token: ws_token,                          |
      |    executors: [...]}                         |
      |                                              |
      |   [Agent shows ONLINE in UI]                 |
```

**Error handling during registration:**

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| 401 | Invalid registration token | Re-generate token in admin panel |
| 402 | License expired or invalid | Check Faraday license |
| 404 | Server unreachable or wrong URL | Verify host/port/SSL settings |

---

## Executor Execution Flow

```
Faraday Server                  Dispatcher                      Executor Process
      |                              |                                |
      |--- emit("run") ------------>|                                |
      |   {executor, args,           |                                |
      |    workspaces,               |                                |
      |    execution_ids,            |                                |
      |    plugin_args}              |                                |
      |                              |                                |
      |                              |-- Validate parameters -------->|
      |                              |   (type check, mandatory)      |
      |                              |                                |
      |                              |-- Check dependencies --------->|
      |                              |   (verify tool installed)      |
      |                              |                                |
      |<-- emit("run_status") ------|                                |
      |   {running: true}            |                                |
      |                              |-- create_subprocess_shell ---->|
      |                              |   (with env vars set)          |
      |                              |                                |
      |                              |       +------ stdout -------->|
      |                              |       |   (JSON lines)        |
      |                              |       +------ stderr -------->|
      |                              |       |   (log messages)      |
      |                              |                                |
      |<-- POST bulk_create --------|<-- read stdout (per line) -----|
      |   (for each workspace)       |   parse JSON, add metadata    |
      |                              |                                |
      |                              |<-- read stderr (per line) -----|
      |                              |   log to dispatcher output     |
      |                              |                                |
      |                              |<-- process exits (rc=0) ------|
      |                              |                                |
      |<-- POST bulk_create --------|  (final: empty hosts + duration)|
      |   (command closure)          |                                |
      |                              |                                |
      |<-- emit("run_status") ------|                                |
      |   {successful: true}         |                                |
```

---

## Async Architecture

The dispatcher uses Python `asyncio` with a single event loop. Running coroutines:

1. **Socket.IO client** — Maintains the persistent connection to the server, dispatches events to the `DispatcherNamespace` handler
2. **`on_run` handler** — Triggered per `run` command; validates parameters, spawns executor, manages subprocess lifecycle
3. **StdOutLineProcessor** — Per-executor coroutine reading stdout line by line
4. **StdErrLineProcessor** — Per-executor coroutine reading stderr line by line

Multiple executors can run concurrently — each `run` command spawns a new set of stdout/stderr reader coroutines.

### Graceful shutdown

On SIGINT or SIGTERM:

1. The dispatcher sends a `LEAVE_AGENT` message via Socket.IO
2. All running executor tasks are cancelled
3. The Socket.IO connection is closed
4. The process exits

[server]: https://github.com/infobyte/faraday
[agents]: https://github.com/infobyte/faraday_agent_dispatcher
[cli]: https://github.com/infobyte/faraday-cli
[api]: https://api.faradaysec.com
[asyncio]: https://docs.python.org/3/library/asyncio.html
