# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import configparser
from typing import Dict

import yaml

from faraday_agent_dispatcher.utils.control_values_utils import (
    control_int,
    control_str,
    control_host,
    control_agent_token,
    control_bool,
    control_executors,
)
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_parameters_types.utils import get_manifests
from faraday_agent_dispatcher import __version__ as current_version
import os
import logging
from pathlib import Path
from shutil import copy
from functools import lru_cache

try:
    FARADAY_PATH = Path(os.environ["FARADAY_HOME"]).expanduser()
except KeyError:
    FARADAY_PATH = Path("~").expanduser() / ".faraday"


LOGS_PATH = FARADAY_PATH / "logs"
CONFIG_PATH = FARADAY_PATH / "config"


if not FARADAY_PATH.exists():
    print(f"{Bcolors.WARNING}The configuration folder" f" does not exist, creating" f" it{Bcolors.ENDC}")
    FARADAY_PATH.mkdir()
if not LOGS_PATH.exists():
    LOGS_PATH.mkdir()
if not CONFIG_PATH.exists():
    CONFIG_PATH.mkdir()

CONFIG_FILENAME = CONFIG_PATH / "dispatcher.yaml"

EXAMPLE_CONFIG_FILENAME = Path(__file__).parent / "example_config.yaml"

OLD_CONFIG_FILENAME = CONFIG_PATH / "dispatcher.ini"

USE_RFC = False

LOGGING_LEVEL = logging.DEBUG

DEFAULT_EXECUTOR_VERIFY_NAME = "unnamed_executor"

instance = {}


def reset_config(filepath: Path):
    if filepath.is_dir():
        filename = filepath / "dispatcher.yaml"
    else:
        filename = filepath
        filepath = filepath.parent
    if not filename.is_file():
        if (filepath / "dispatcher.ini").is_file():
            filename = update_config_from_ini_to_yaml((filepath / "dispatcher.ini"))
        else:
            copy(EXAMPLE_CONFIG_FILENAME, filename)
    elif filename.suffix == ".ini":
        filename = update_config_from_ini_to_yaml(filename)

    try:
        with filename.open() as yaml_file:
            if not yaml_file:
                raise ValueError(
                    f"Unable to read config " f"file located at {filename}",
                    False,
                )
            instance.clear()
            instance.update(update_config(yaml.safe_load(yaml_file)))
    except EnvironmentError:
        raise EnvironmentError("Error opening the config file")


def check_filepath(filepath: str = None):
    if filepath is None:
        raise ValueError("Filepath needed to save")
    if filepath == EXAMPLE_CONFIG_FILENAME:
        raise ValueError("Can't override sample config")


def save_config(filepath=None):
    check_filepath(filepath)
    if filepath.is_dir():
        filepath = filepath / "dispatcher.yaml"
    elif filepath.suffix != ".yaml":
        filepath = filepath.with_suffix(".yaml")
    with filepath.open("w") as configfile:
        yaml.dump(instance, configfile)


def update_config_from_ini_to_yaml(filepath: Path):
    """
    This methods tries to adapt old .ini versions, if its not possible,
    warns about it and exits with a proper error code
    """

    old_instance = configparser.ConfigParser()

    try:
        if not old_instance.read(filepath):
            raise ValueError(f"Unable to read config file located" f" at {filepath}", False)
    except configparser.DuplicateSectionError:
        raise ValueError(f"The config in {filepath} contains " f"duplicated sections", True)

    if OldSections.AGENT not in old_instance:
        if OldSections.EXECUTOR in old_instance:
            agent_name = old_instance.get(OldSections.EXECUTOR, "agent_name")
            executor_name = DEFAULT_EXECUTOR_VERIFY_NAME
            old_instance.add_section(OldSections.EXECUTOR_DATA.format(executor_name))
            old_instance.add_section(OldSections.EXECUTOR_VARENVS.format(executor_name))
            old_instance.add_section(OldSections.EXECUTOR_PARAMS.format(executor_name))
            old_instance.add_section(OldSections.AGENT)
            old_instance.set(OldSections.AGENT, "agent_name", agent_name)
            old_instance.set(OldSections.AGENT, "executors", executor_name)
            cmd = old_instance.get(OldSections.EXECUTOR, "cmd")
            old_instance.set(OldSections.EXECUTOR_DATA.format(executor_name), "cmd", cmd)
            old_instance.remove_section(OldSections.EXECUTOR)
    else:
        data = []

        if "executors" in old_instance[OldSections.AGENT]:
            executor_list = old_instance.get(OldSections.AGENT, "executors").split(",")
            if "" in executor_list:
                executor_list.remove("")
            for executor_name in executor_list:
                executor_name = executor_name.strip()
                if OldSections.EXECUTOR_DATA.format(executor_name) not in old_instance.sections():
                    data.append(f"{OldSections.EXECUTOR_DATA.format(executor_name)}" f" section does not exist")
        else:
            data.append(f"executors option not in {OldSections.AGENT} section")

        if len(data) > 0:
            raise ValueError("\n".join(data))

    if OldSections.TOKENS in old_instance:
        if "registration" in old_instance.options(OldSections.TOKENS):
            old_instance.remove_option(OldSections.TOKENS, "registration")
        if not old_instance.options(OldSections.TOKENS):
            old_instance.remove_section(OldSections.TOKENS)

    if OldSections.SERVER not in old_instance:
        raise ValueError("Server section missing in config file")

    if "workspace" in old_instance[OldSections.SERVER]:
        workspace_loaded_value = old_instance.get(section=OldSections.SERVER, option="workspace")
        workspaces_value = workspace_loaded_value

        if "workspaces" in old_instance[OldSections.SERVER]:
            print(
                f"{Bcolors.WARNING}Both section {Bcolors.BOLD}workspace "
                f"{Bcolors.ENDC}{Bcolors.WARNING}and "
                f"{Bcolors.BOLD}workspaces{Bcolors.ENDC}"
                f"{Bcolors.WARNING} found. Merging them"
            )
            logging.warning("Both section workspace and workspaces " "found. Merging them")
            workspaces_loaded_value = old_instance.get(section=OldSections.SERVER, option="workspaces")
            if len(workspaces_value) >= 0:
                workspaces_value = f"{workspaces_value}," f"{workspaces_loaded_value}"
        old_instance.set(
            section=OldSections.SERVER,
            option="workspaces",
            value=workspaces_value,
        )
        old_instance.remove_option(OldSections.SERVER, "workspace")

        if "ssl" not in old_instance[OldSections.SERVER]:
            old_instance.set(OldSections.SERVER, "ssl", "True")
        if "ssl_cert" not in old_instance[OldSections.SERVER]:
            old_instance.set(OldSections.SERVER, "ssl_cert", "")

    # TO YAML

    yaml_config = {}
    executors = {}

    # Agent & Executors

    if OldSections.AGENT in old_instance:
        if "executors" in old_instance[OldSections.AGENT]:
            executor_list = old_instance.get(OldSections.AGENT, "executors").split(",")
            if "" in executor_list:
                executor_list.remove("")
            for executor_name in executor_list:
                executor_name = executor_name.strip()

                executors[executor_name] = {}

                # Data
                for key, value in old_instance[OldSections.EXECUTOR_DATA.format(executor_name)].items():
                    executors[executor_name][key] = value

                if "max_size" not in executors[executor_name]:
                    executors[executor_name]["max_size"] = "65536"

                # Varenvs
                executors[executor_name]["varenvs"] = {}
                if OldSections.EXECUTOR_VARENVS.format(executor_name) in old_instance:
                    for key, value in old_instance[OldSections.EXECUTOR_VARENVS.format(executor_name)].items():
                        executors[executor_name]["varenvs"][key] = value

                # Params
                executors[executor_name]["params"] = {}
                if OldSections.EXECUTOR_PARAMS.format(executor_name) in old_instance:
                    for key, value in old_instance[OldSections.EXECUTOR_PARAMS.format(executor_name)].items():
                        executors[executor_name]["params"][key] = {
                            "mandatory": value.lower() in ["true", "t"],
                            "type": "string",
                            "base": "string",
                        }

        else:
            data.append(f"executors option not in {OldSections.AGENT} section")

        yaml_config[Sections.AGENT] = {
            "agent_name": old_instance.get(OldSections.AGENT, "agent_name"),
            Sections.EXECUTORS: executors,
        }

    # Tokens
    if OldSections.TOKENS in old_instance:
        yaml_config[Sections.TOKENS] = {}
        for key, value in old_instance[OldSections.TOKENS].items():
            yaml_config[Sections.TOKENS][key] = value

    # Server
    yaml_config[Sections.SERVER] = {}
    if OldSections.SERVER in old_instance:
        for key, value in old_instance[OldSections.SERVER].items():
            yaml_config[Sections.SERVER][key] = value

    if "workspaces" in yaml_config[Sections.SERVER] and isinstance(yaml_config[Sections.SERVER]["workspaces"], str):
        str_list = yaml_config[Sections.SERVER]["workspaces"].split(",")
        if "" in str_list:
            str_list.remove("")
        yaml_config[Sections.SERVER]["workspaces"] = str_list

    instance.update(yaml_config)
    # control_config()
    save_file = filepath.with_suffix(".yaml")
    save_config(save_file)
    return save_file


def update_config(config: Dict):
    """
    This methods tries to adapt old .yaml versions
    """
    # From 2.1.0 to 2.1.3
    if Sections.SERVER in config:
        if "ssl_ignore" not in config[Sections.SERVER]:
            config[Sections.SERVER]["ssl_ignore"] = False
        if "api_port" in config[Sections.SERVER] and isinstance(config[Sections.SERVER]["api_port"], str):
            config[Sections.SERVER]["api_port"] = int(config[Sections.SERVER]["api_port"])
        if "websocket_port" in config[Sections.SERVER] and isinstance(config[Sections.SERVER]["websocket_port"], str):
            config[Sections.SERVER]["websocket_port"] = int(config[Sections.SERVER]["websocket_port"])
        if isinstance(config[Sections.SERVER]["ssl"], str):
            config[Sections.SERVER]["ssl"] = config[Sections.SERVER]["ssl"] == "True"
    if Sections.AGENT in config and Sections.EXECUTORS in config[Sections.AGENT]:
        for executor in config[Sections.AGENT]["executors"]:
            if (
                isinstance(config[Sections.AGENT]["executors"], dict)
                and "repo_executor" in config[Sections.AGENT]["executors"][executor]
                and "repo_name" not in config[Sections.AGENT]["executors"][executor]
            ):
                new_repo_name = get_repo_exec().get(
                    config[Sections.AGENT]["executors"][executor]["repo_executor"],
                    "",
                )
                config[Sections.AGENT]["executors"][executor]["repo_name"] = new_repo_name
                if len(new_repo_name) == 0:
                    logging.warning(
                        f"{Bcolors.WARNING}We tried to update the executor "
                        f"{executor} but faild. Its recommended "
                        f"to delete and add it by faraday-dispatcher"
                        f" config-wizard{Bcolors.ENDC}"
                    )

    return config


class Sections:
    TOKENS = "tokens"
    SERVER = "server"
    AGENT = "agent"
    EXECUTORS = "executors"
    EXECUTOR_VARENVS = "varenvs"
    EXECUTOR_PARAMS = "params"
    EXECUTOR_DATA = "{}"


class OldSections(Sections):
    EXECUTOR = "executor"
    EXECUTOR_VARENVS = "{}_varenvs"
    EXECUTOR_PARAMS = "{}_params"


__control_dict = {
    Sections.SERVER: {
        "host": control_host,
        "ssl": control_bool,
        "ssl_ignore": control_bool,
        "ssl_cert": control_str(nullable=True),
        "api_port": control_int(),
        "websocket_port": control_int(),
    },
    Sections.TOKENS: {
        "agent": control_agent_token,
    },
    Sections.AGENT: {
        "agent_name": control_str(),
        "executors": control_executors,
    },
}


def control_config():
    for section in __control_dict:
        for option in __control_dict[section]:
            if section not in instance:
                if section == Sections.TOKENS:
                    continue
                raise ValueError(f"{section} section missing in config file")
            else:
                if option not in instance[section] and section != Sections.TOKENS:
                    raise ValueError(f"{option} option missing in {section} section of " f"the config file")
            value = instance[section][option] if option in instance[section] else None
            __control_dict[section][option](option, value)


@lru_cache(maxsize=None)
def get_repo_exec() -> dict:
    """
    Return the a dict of manifests with keys being repo_executor
    and values the name of the manifest
    """
    executer_names = {}
    metadata = get_manifests(current_version)
    for key, value in metadata.items():
        executer_names[value.get("repo_executor")] = key
    return executer_names
