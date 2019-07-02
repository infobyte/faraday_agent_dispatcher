# -*- coding: utf-8 -*-
from faraday_agent_dispatcher.dispatcher import Dispatcher

class DispatcherBuilder:

    def __init__(self):
        self.__faraday_url = None

    def faraday_url(self, url):
        self.__faraday_url = url
        return self

    def build(self):
        # Control fields and Instantiate Dispatcher
        return Dispatcher()

