import importlib
import os
import re
from pathlib import Path

from faraday_agent_dispatcher.utils.metadata_utils import (
    executor_folder,
    executor_metadata,
    full_check_metadata,
)


def test_imports():
    folder = executor_folder()
    modules = [f"{Path(module).stem}" for module in os.listdir(folder) if re.match(r".*\.py", module) is not None]
    error_message = ""
    for module in modules:
        try:
            importlib.import_module(f"faraday_agent_dispatcher.static.executors.official.{module}")
        except ImportError:
            error_message = f"{error_message}Can't import {module}\n"

    assert len(error_message) == 0, error_message


def test_no_path_varenv_in_manifests():
    folder = executor_folder()
    modules = [f"{Path(module).stem}" for module in os.listdir(folder) if re.match(r".*\.py", module) is not None]

    error_message = ""
    for module in modules:
        try:
            metadata = executor_metadata(module)
            if not full_check_metadata(metadata):
                error_message = f"{error_message}Not all manifest keys in " f"manifest for {module}\n"
            if "environment_variables" in metadata:
                if "PATH" in metadata["environment_variables"]:
                    error_message = f"{error_message}Overriding PATH " f"environment variable in {module}\n"

        except FileNotFoundError:
            error_message = f"{error_message}Can't found manifest file for " f"{module}\n"

    assert len(error_message) == 0, error_message
