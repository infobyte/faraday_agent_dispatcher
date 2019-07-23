import configparser

import logging

CONST_FARADAY_HOME_PATH = "."
CONST_FARADAY_LOGS_PATH = "logs"

USE_RFC = False

LOGGING_LEVEL = logging.ERROR


class Configuration:

    def __init__(self):
        self.values = configparser.ConfigParser()
        self.values.read(self.path())
        asas = 4

    def path(self):
        return f"{CONST_FARADAY_HOME_PATH}/static/config.ini"

    def get(self, field):
        return self.values["VALUES"][field]

    def set(self, field, value):
        self.values["VALUES"][field] = value
        with open(self.path(), 'w') as configfile:
            self.values.write(configfile)

    def get_all(self):
        return self.values["VALUES"]


instance = Configuration()