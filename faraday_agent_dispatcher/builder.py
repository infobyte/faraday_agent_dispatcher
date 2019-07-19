# -*- coding: utf-8 -*-
from faraday_agent_dispatcher.dispatcher import Dispatcher

import requests
from urllib.parse import urljoin


class DispatcherBuilder:

    def __init__(self):
        self.config_map_function = {
            "faraday_url": self.faraday_url,
            "faraday_port": self.faraday_port,
            "workspace": self.faraday_workspace,
            "registration_token": self.registration_token,
            "executor_filename": self.executor_filename
        }
        self.__faraday_url = "localhost"
        self.__faraday_port = "5985"
        self.__workspace = None
        self.__registration_token = None
        self.__executor_filename = None

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

    def faraday_port(self, port):
        self.__faraday_port = port
        return self

    def faraday_workspace(self, workspace):
        self.__workspace = workspace
        return self

    def registration_token(self, registration_token):
        self.__registration_token = registration_token
        return self

    def executor_filename(self,executor_filename):
        self.__executor_filename = executor_filename
        return self

    def __full_url(self):
        return self.__faraday_url + ":" + str(self.__faraday_port)

    def build(self):
        # Control fields

        # Ask for Agent token -- ws in url means workspace
        token_registration_url = urljoin(self.__full_url(), "_api/v2/ws/"+ self.__workspace +"/agent_registration/")

        token_response = requests.post(token_registration_url, json={'token': self.__registration_token, 'name': "TEST"})

        # Instantiate Dispatcher

        return Dispatcher(self.__full_url(),
                          self.__workspace,
                          token_response.json()['token'],
                          self.__executor_filename,
                          self.__registration_token)

