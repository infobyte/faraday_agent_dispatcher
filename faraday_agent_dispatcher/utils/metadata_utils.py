import asyncio
import json
import os
from pathlib import Path
import faraday_agent_dispatcher.logger as logging

logger = logging.get_logger()


def executor_folder():

    folder = Path(__file__).parent.parent / 'static' / 'executors'
    if "WIZARD_DEV" in os.environ:
        return folder / "dev"
    else:
        return folder / "official"


def executor_metadata(executor_filename):
    chosen = Path(executor_filename)
    chosen_metadata_path = executor_folder() / f"{chosen.stem}_manifest.json"
    chosen_path = executor_folder() / chosen
    with open(chosen_metadata_path) as metadata_file:
        data = metadata_file.read()
        metadata = json.loads(data)
    return metadata


async def check_commands(metadata):
    async def run_check_command(cmd):
        proc = await asyncio.create_subprocess_shell(cmd,
                                                     stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE
                                                     )
        while True:
            stdout, stderr = await proc.communicate()
            if len(stdout) > 0:
                logger.debug(f"Dependency check prints: {stdout}")
            if len(stderr) > 0:
                logger.debug(f"Dependency check error: {stderr}")
            if len(stdout) == 0 and len(stderr) == 0:
                break

        return proc.returncode

    check_coros = [run_check_command(cmd) for cmd in metadata["check_cmds"]]
    responses = await asyncio.gather(*check_coros)
    return all(response == 0 for response in responses)
