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
from faraday_agent_dispatcher.utils.control_values_utils import (
    control_int,
    control_str,
    control_host,
    control_registration_token,
    control_agent_token,
    control_list,
    control_bool
)
from faraday_agent_dispatcher.utils.text_utils import Bcolors

import os
import logging
import configparser
from pathlib import Path
from configparser import DuplicateSectionError

try:
    FARADAY_PATH = Path(os.environ['FARADAY_HOME']).expanduser()
except KeyError:
    FARADAY_PATH = Path('~').expanduser() / '.faraday'


LOGS_PATH = FARADAY_PATH / 'logs'
CONFIG_PATH = FARADAY_PATH / 'config'


if not FARADAY_PATH.exists():
    print(f"{Bcolors.WARNING}The configuration folder does not exists, creating it{Bcolors.ENDC}")
    FARADAY_PATH.mkdir()
if not LOGS_PATH.exists():
    LOGS_PATH.mkdir()
if not CONFIG_PATH.exists():
    CONFIG_PATH.mkdir()

CONFIG_FILENAME = CONFIG_PATH / 'dispatcher.ini'

EXAMPLE_CONFIG_FILENAME = Path(__file__).parent / 'example_config.ini'

USE_RFC = False

LOGGING_LEVEL = logging.DEBUG

DEFAULT_EXECUTOR_VERIFY_NAME = "unnamed_executor"

instance = configparser.ConfigParser()


def reset_config(filepath: Path):
    instance.clear()
    if filepath.is_dir():
        filepath = filepath / "dispatcher.ini"
    try:
        if not instance.read(filepath):
            raise ValueError(f'Unable to read config file located at {filepath}', False)
    except DuplicateSectionError as e:
        raise ValueError(f'The config in {filepath} contains duplicated sections', True)


def check_filepath(filepath: str = None):
    if filepath is None:
        raise ValueError("Filepath needed to save")
    if filepath == EXAMPLE_CONFIG_FILENAME:
        raise ValueError("Can't override sample config")


def save_config(filepath=None):
    check_filepath(filepath)
    if filepath.is_dir():
        filepath = filepath / "dispatcher.ini"
    with open(filepath, 'w') as configfile:
        instance.write(configfile)


def verify():
    # This methods tries to adapt old versions, if its not possible, warns about it and exits with a proper error code
    should_be_empty = False
    if Sections.AGENT not in instance:
        if OldSections.EXECUTOR in instance:
            agent_name = instance.get(OldSections.EXECUTOR, "agent_name")
            executor_name = DEFAULT_EXECUTOR_VERIFY_NAME
            instance.add_section(Sections.EXECUTOR_DATA.format(executor_name))
            instance.add_section(Sections.EXECUTOR_VARENVS.format(executor_name))
            instance.add_section(Sections.EXECUTOR_PARAMS.format(executor_name))
            instance.add_section(Sections.AGENT)
            instance.set(Sections.AGENT, "agent_name", agent_name)
            instance.set(Sections.AGENT, "executors", executor_name)
            cmd = instance.get(OldSections.EXECUTOR, "cmd")
            instance.set(Sections.EXECUTOR_DATA.format(executor_name), "cmd", cmd)
            instance.remove_section(OldSections.EXECUTOR)
        else:
            should_be_empty = True
    else:
        data = []

        if 'executors' in instance[Sections.AGENT]:
            executor_list = instance.get(Sections.AGENT, 'executors').split(',')
            if '' in executor_list:
                executor_list.remove('')
            for executor_name in executor_list:
                if Sections.EXECUTOR_DATA.format(executor_name) not in instance.sections():
                    data.append(f"{Sections.EXECUTOR_DATA.format(executor_name)} section does not exists")
        else:
            data.append(f'executors option not in {Sections.AGENT} section')

        if len(data) > 0:
            raise ValueError('\n'.join(data))

    if should_be_empty:
        assert len(instance.sections()) == 0
    else:
        if 'ssl' not in instance[Sections.SERVER]:
            instance.set(Sections.SERVER, "ssl", "True")
        if 'ssl_cert' not in instance[Sections.SERVER]:
            instance.set(Sections.SERVER, "ssl_cert", "")
        control_config()


class OldSections:
    EXECUTOR = "executor"


class Sections:
    TOKENS = "tokens"
    SERVER = "server"
    AGENT = "agent"
    EXECUTOR_VARENVS = "{}_varenvs"
    EXECUTOR_PARAMS = "{}_params"
    EXECUTOR_DATA = "{}"


__control_dict = {
        Sections.SERVER: {
            "host": control_host,
            "ssl": control_bool,
            "ssl_cert": control_str(nullable=True),
            "api_port": control_int(),
            "websocket_port": control_int(),
            "workspace": control_str(),
        },
        Sections.TOKENS: {
            "registration": control_registration_token,
            "agent": control_agent_token
        },
        Sections.AGENT: {
            "agent_name": control_str(),
            "executors": control_list(can_repeat=False)
        },
    }


def control_config():
    for section in __control_dict:
        for option in __control_dict[section]:
            if section not in instance:
                err = f"Section {section} is an mandatory section in the config"
                raise ValueError(err)
            value = instance.get(section, option) if option in instance[section] else None
            __control_dict[section][option](option, value)
