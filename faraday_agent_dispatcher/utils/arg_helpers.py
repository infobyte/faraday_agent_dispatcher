"""Helpers for reading EXECUTOR_CONFIG_* env vars whose manifest type is "list".

When a manifest field is declared as `"type": "list"`, the Faraday UI sends a
JSON-encoded array as the env var value (e.g. `'["high","critical"]'`). The
dispatcher's create_process forwards it via `str(args[k])` unchanged when the
value already is a string. These helpers normalise that wire format back into
either a single value (first element) or a CSV string suitable for CLI flags
that already accept comma-separated values.
"""

from __future__ import annotations

import json
import os
from typing import Optional


def _load(name: str) -> Optional[list]:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return None
    stripped = raw.strip()
    if stripped.startswith("["):
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            return [raw]
        if isinstance(value, list):
            return [str(v) for v in value if v is not None and v != ""]
        return [str(value)]
    return [raw]


def single(name: str, default: Optional[str] = None) -> Optional[str]:
    items = _load(name)
    if not items:
        return default
    return items[0]


def csv(name: str, default: Optional[str] = None) -> Optional[str]:
    items = _load(name)
    if not items:
        return default
    return ",".join(items)


def items(name: str) -> list:
    return _load(name) or []
