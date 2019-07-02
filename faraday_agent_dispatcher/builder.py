# -*- coding: utf-8 -*-
from faraday_agent_dispatcher.dispatcher import Dispatcher


class DispatcherBuilder:

    def __init__(self):
        self.__faraday_url = None
        self.__access_token = None

    def config(self, config_dict):
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

        # Instantiate Dispatcher

        return Dispatcher()

