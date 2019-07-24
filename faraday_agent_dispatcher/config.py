import configparser

import logging

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
