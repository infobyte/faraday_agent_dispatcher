import asyncio
import json
import os
from pathlib import Path
from typing import Union

import faraday_agent_dispatcher.logger as logging
from faraday_agent_parameters_types.utils import get_manifests
from faraday_agent_dispatcher import __version__ as current_version

logger = logging.get_logger()

# Manifests for executors bundled with the dispatcher but not released in the
# faraday_agent_parameters_types package (the offensive-check executors). They
# ship with the package so tests, runtime metadata lookups and the deployment
# generator resolve them without a separate parameters-types release.
LOCAL_MANIFESTS_DIR = Path(__file__).parent.parent / "static" / "manifests"


def local_manifests() -> dict:
    manifests = {}
    if LOCAL_MANIFESTS_DIR.is_dir():
        for path in LOCAL_MANIFESTS_DIR.glob("*.json"):
            try:
                data = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                logger.error(f"Could not load bundled manifest {path}: {exc}")
                continue
            manifests[data["name"]] = data
    return manifests


def all_manifests() -> dict:
    """Released parameters-types manifests merged with bundled local ones."""
    merged = dict(get_manifests(current_version))
    for name, data in local_manifests().items():
        merged.setdefault(name, data)
    return merged


MANDATORY_METADATA_KEYS = [
    "cmd",
    "check_cmds",
    "arguments",
    "environment_variables",
]
INFO_METADATA_KEYS = [
    "category",
    "name",
    "title",
    "website",
    "description",
    "image",
]


# Path can be treated as str
def executor_folder() -> Union[Path, str]:
    folder = Path(__file__).parent.parent / "static" / "executors"
    if "WIZARD_DEV" in os.environ:
        return folder / "dev"
    else:
        return folder / "official"


def executor_metadata(executor_name: str) -> dict:
    metadata = get_manifests(current_version).get(executor_name)
    if metadata is None:
        metadata = local_manifests().get(executor_name)
    return metadata


def check_metadata(metadata) -> bool:
    return all(k in metadata for k in MANDATORY_METADATA_KEYS)


def full_check_metadata(metadata) -> bool:
    return all(k in metadata for k in INFO_METADATA_KEYS) and check_metadata(metadata)


async def check_commands(metadata: dict) -> bool:
    async def run_check_command(cmd: str) -> int:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        while True:
            stdout, stderr = await proc.communicate()
            if len(stdout) > 0:
                logger.debug(f"Dependency check {cmd} prints: {stdout.decode()}")
            if len(stderr) > 0:
                logger.error(f"Dependency check {cmd} prints to " f"error: {stderr.decode()}")
            if len(stdout) == 0 and len(stderr) == 0:
                break

        return proc.returncode

    for check_cmd in metadata["check_cmds"]:
        response = await run_check_command(check_cmd)
        if response != 0:
            return False

    logger.info("Dependency check ended. Ready to go")
    return True
    # Async check if needed
    # check_coros = [run_check_command(cmd) for cmd in metadata["check_cmds"]]
    # responses = await asyncio.gather(*check_coros)
    # return all(response == 0 for response in responses)
