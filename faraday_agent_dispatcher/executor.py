import re

from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher.utils.metadata_utils import (
    executor_metadata,
    executor_folder,
    check_commands,
)
from faraday_agent_dispatcher.utils.control_values_utils import (
    control_int,
    control_str,
    ParamsSchema,
)
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_dispatcher.logger import get_logger

logger = get_logger()


class Executor:
    __control_dict = {
        "cmd": control_str(True),
        "repo_executor": control_str(True),
        "max_size": control_int(True),
    }

    def __init__(self, name: str, config):
        name = name.strip()
        self.control_config(name, config)
        self.name = name
        self.repo_executor = config.get("repo_executor")
        if self.repo_executor:
            self.repo_name = re.search(r"(^[a-zA-Z0-9_-]+)(?:\..*)*$", self.repo_executor).group(1)
            metadata = executor_metadata(self.repo_name)
            repo_path = executor_folder() / self.repo_executor
            self.cmd = metadata["cmd"].format(EXECUTOR_FILE_PATH=repo_path)
        else:
            self.cmd = config.get("cmd")

        self.max_size = int(config.get("max_size", 64 * 1024))
        self.params = dict(config[Sections.EXECUTOR_PARAMS]) if Sections.EXECUTOR_PARAMS in config else {}
        self.varenvs = dict(config[Sections.EXECUTOR_VARENVS]) if Sections.EXECUTOR_VARENVS in config else {}

    def control_config(self, name, config):
        if " " in name:
            raise ValueError("Executor names can't contains space character, passed name:" f"{name}")

        for option in self.__control_dict:
            value = config[option] if option in config else None
            self.__control_dict[option](option, value)
        if Sections.EXECUTOR_PARAMS in config:
            value = config.get(Sections.EXECUTOR_PARAMS)
            errors = ParamsSchema().validate({"params": value})
            if errors:
                raise ValueError(errors)

    async def check_cmds(self):
        if self.repo_executor is None:
            return True
        repo_name = re.search(r"(^[a-zA-Z0-9_-]+)(?:\..*)*$", self.repo_executor).group(1)
        metadata = executor_metadata(repo_name)
        if not await check_commands(metadata):
            logger.info(
                f"{Bcolors.WARNING}Invalid bash dependency for " f"{Bcolors.BOLD}{self.repo_name}{Bcolors.ENDC}"
            )
            return False
        else:
            return True
