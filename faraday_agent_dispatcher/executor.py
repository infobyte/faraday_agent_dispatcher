import os
from pathlib import Path
import json

from faraday_agent_dispatcher.cli.utils.model_load import executor_metadata, executor_folder
from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher.utils.control_values_utils import (
    control_int,
    control_str,
    control_bool
)


def get_repo_path(repo_name):

    EXECUTOR_FOLDER = Path(__file__).parent.parent / 'static' / 'executors'
    if "WIZARD_DEV" in os.environ:
        folder = EXECUTOR_FOLDER / "dev"
    else:
        folder = EXECUTOR_FOLDER / "official"
    chosen = Path(repo_name)
    chosen_metadata_path = folder / f"{chosen.stem}_manifest.json"
    chosen_path = EXECUTOR_FOLDER / chosen
    with open(chosen_metadata_path) as metadata_file:
        data = metadata_file.read()
        metadata = json.loads(data)
    return metadata["cmd"].format(EXECUTOR_FILE_PATH=chosen_path)



class Executor:
    __control_dict = {
        Sections.EXECUTOR_DATA: {
           "cmd": control_str(True),
           "repo_executor": control_str(True),
           "max_size": control_int(True)
        }
    }

    def __init__(self, name: str, config):
        name = name.strip()
        self.control_config(name, config)
        self.name = name
        executor_section = Sections.EXECUTOR_DATA.format(name)
        params_section = Sections.EXECUTOR_PARAMS.format(name)
        varenvs_section = Sections.EXECUTOR_VARENVS.format(name)
        repo_name = config[executor_section].get("repo_executor", None)
        if repo_name:
            metadata = executor_metadata(repo_name)
            repo_path = executor_folder() / repo_name
            self.cmd = metadata['cmd'].format(EXECUTOR_FILE_PATH=repo_path)
        else:
            self.cmd = config[executor_section].get("cmd")

        self.max_size = int(config[executor_section].get("max_size", 64 * 1024))
        self.params = dict(config[params_section]) if params_section in config else {}
        self.params = {key: value.lower() in ["t", "true"] for key, value in self.params.items()}
        self.varenvs = dict(config[varenvs_section]) if varenvs_section in config else {}

    def control_config(self, name, config):
        if " " in name:
            raise ValueError(f"Executor names can't contains space character, passed name: {name}")
        if Sections.EXECUTOR_DATA.format(name) not in config:
            raise ValueError(f"{name} is an executor name but there is no proper section")

        for section in self.__control_dict:
            for option in self.__control_dict[section]:
                value = config.get(section.format(name), option) if option in config[section.format(name)] else None
                self.__control_dict[section][option](option, value)
        params_section = Sections.EXECUTOR_PARAMS.format(name)
        if params_section in config:
            for option in config[params_section]:
                value = config.get(params_section, option)
                control_bool(option, value)