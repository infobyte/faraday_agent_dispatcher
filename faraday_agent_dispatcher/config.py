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

import logging

import configparser

import aiofiles

CONST_FARADAY_HOME_PATH = "."
CONST_FARADAY_LOGS_PATH = "logs"
CONST_CONFIG = f"{CONST_FARADAY_HOME_PATH}/static/config.ini"

USE_RFC = False

LOGGING_LEVEL = logging.ERROR

instance = configparser.ConfigParser()
instance.read(CONST_CONFIG)


async def async_save_config(filename=CONST_CONFIG):
    async with aiofiles.open(filename, 'w') as configfile:
        await instance.write(configfile)


def save_config(filename=CONST_CONFIG):
    with open(filename, 'w') as configfile:
        instance.write(configfile)


TOKENS_SECTION = "tokens"
SERVER_SECTION = "server"
EXECUTOR_SECTION = "executor"