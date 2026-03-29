# Faraday Agent Dispatcher

## Stack
Python 3.8+, asyncio, aiohttp, websockets, Click, PyYAML.

## Project Structure
- `faraday_agent_dispatcher/dispatcher.py` — Main Dispatcher class (async)
- `faraday_agent_dispatcher/dispatcher_io.py` — Async WebSocket handler
- `faraday_agent_dispatcher/executor.py` — Command executor
- `faraday_agent_dispatcher/executor_helper.py` — StdOutLineProcessor, StdErrLineProcessor
- `faraday_agent_dispatcher/config.py` — YAML/INI config management
- `faraday_agent_dispatcher/cli/main.py` — Click CLI entry point
- `faraday_agent_dispatcher/utils/` — Utility modules (logging, text, metadata)
- `tests/unittests/` — pytest + pytest-asyncio tests

## Async Patterns
The codebase uses `async def` extensively:
```python
class Dispatcher:
    async def register(self):
        ...
    async def connect(self):
        ...
    async def run_once(self):
        ...
```

## Config
- Primary format: YAML (`~/.faraday/config/dispatcher.yaml`)
- INI fallback with migration to YAML
- Sections for executor params and environment variables

## Testing
- Run: `pytest tests/`
- Uses pytest-asyncio (0.18.3) for async tests
- Fixtures in `tests/utils/testing_faraday_server.py`
- Config tests use `@pytest.mark.parametrize`

## Code Style
- black (line length 119) + flake8 (max 120)
- Pre-commit hooks configured

## Git Conventions
- Base branch: `dev`
- Branch naming: `tkt_{iid}_{slug}`
- Stage with `git add -u` (never `git add -A`)

## CHANGELOG (REQUIRED for every change)
Create `CHANGELOG/current/{iid}.md` (single line):
```
[FIX] Description of change. #{iid}
```
Types: `[FIX]` bug fix, `[ADD]` new feature, `[MOD]` modification, `[DEL]` removal.
Always include the CHANGELOG file in your commit.

## Common Pitfalls
- Always create the CHANGELOG entry — MRs without it will be rejected
- Use async/await throughout — the dispatcher is fully asynchronous
- Executor configs are validated via control_dict and ParamsSchema
- Test async functions with pytest-asyncio markers
