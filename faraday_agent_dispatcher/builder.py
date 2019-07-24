# -*- coding: utf-8 -*-

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

from faraday_agent_dispatcher.dispatcher import Dispatcher

import requests
from urllib.parse import urljoin


class DispatcherBuilder:

    def __init__(self):
        self.config_map_function = {
            "faraday_host": self.faraday_host,
            "api_port": self.api_port,
            "websocket_port": self.websocket_port,
            "workspace": self.faraday_workspace,
            "registration_token": self.registration_token,
            "executor_filename": self.executor_filename
        }
        self.__faraday_host = "localhost"
        self.__api_port = "5985"
        self.__websocket_port = "9000"
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

    def faraday_host(self, host):
        self.__faraday_host = host
        return self

    def api_port(self, port):
        self.__api_port = port
        return self

    def websocket_port(self, port):
        self.__websocket_port = port
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

    def __full_url(self, secure = False):
        prefix = "https://" if secure else "http://"
        return f"{prefix}{self.__faraday_host}:{self.__api_port}"

    def build(self):
        # Control fields

        # Ask for Agent token -- ws in url means workspace
        token_registration_url = urljoin(self.__full_url(), "_api/v2/ws/"+ self.__workspace +"/agent_registration/")

        token_response = requests.post(token_registration_url, json={'token': self.__registration_token, 'name': "TEST"})

        # Instantiate Dispatcher

        a =5
        # return Dispatcher(self.__faraday_host,
        #                   self.__workspace,
        #                   token_response.json()['token'],
        #                   self.__executor_filename,
        #                   self.__api_port,
        #                   self.__websocket_port)

