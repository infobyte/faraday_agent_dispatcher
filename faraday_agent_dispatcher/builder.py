# -*- coding: utf-8 -*-
from faraday_agent_dispatcher.dispatcher import Dispatcher

import requests
from urllib.parse import urljoin


class DispatcherBuilder:

    def __init__(self):
        self.config_map_function = {
            "faraday_url": self.faraday_url,
            "access_token": self.access_token
        }
        self.__faraday_url = None
        self.__access_token = None

    def config(self, config_dict):
        for key in config_dict.keys():
            if key in self.config_map_function.keys():
                self.config_map_function[key](config_dict[key])
            else:
                # TO LOGGER
                print("Key " + key + "not supported")
        return self

    def faraday_url(self, url):
        self.__faraday_url = url
        return self

    def access_token(self, access_token):
        self.__access_token = access_token
        return self

    def build(self):
        # Control fields

        # Ask for Agent token
        a = urljoin(self.__faraday_url, "_api/v2/agents/")

        r = requests.post(url=urljoin(self.__faraday_url, "_api/v2/agents/"), data={"token": self.__access_token})

        # Instantiate Dispatcher

        return Dispatcher()

