import importlib
import os
import re
from pathlib import Path


def test_imports():
    folder = Path(__file__).parent.parent.parent / 'faraday_agent_dispatcher' / "static" / "executors" / "official"
    modules = [
        f"{Path(module).stem}"
        for module in os.listdir(folder)
        if re.match(r".*\.py", module) is not None]
    error_message = ""
    for module in modules:
        try:
            importlib.import_module(f"faraday_agent_dispatcher.static.executors.official.{module}")
        except ImportError as e:
            error_message = f"{error_message}Can't import {module}\n"

    assert len(error_message) == 0, error_message
