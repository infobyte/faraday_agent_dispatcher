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

import os
import logging
import configparser
from pathlib import Path

try:
    FARADAY_PATH = Path(os.environ['FARADAY_HOME'])
except KeyError:
    FARADAY_PATH = Path('~').expanduser() / '.faraday'


LOGS_PATH = FARADAY_PATH / 'logs'
CONFIG_PATH = FARADAY_PATH / 'config'
CONFIG_FILENAME = CONFIG_PATH / 'dispatcher.ini'

EXAMPLE_CONFIG_FILENAME = Path(__file__).parent / 'example_config.ini'

USE_RFC = False

LOGGING_LEVEL = logging.DEBUG

instance = configparser.ConfigParser()


def reset_config(filepath):
    instance.clear()
    if not instance.read(filepath):
        raise ValueError(f'Unable to read config file located at {filepath}')


def check_filepath(filepath: str = None):
    if filepath is None:
        raise ValueError("Filepath needs to save")
    if filepath == EXAMPLE_CONFIG_FILENAME:
        raise ValueError("Can't override sample config")


def save_config(filepath=None):
    check_filepath(filepath)
    with open(filepath, 'w') as configfile:
        instance.write(configfile)


class Sections:
    TOKENS = "tokens"
    SERVER = "server"
    AGENT = "agent"
    EXECUTOR_VARENVS = "{}_varenvs"
    EXECUTOR_PARAMS = "{}_params"
    EXECUTOR_DATA = "{}"
