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

import requests
from urllib.parse import urljoin

import json

from aiohttp import ClientSession
import asyncio
import websockets
import aiofiles

import os

from faraday_agent_dispatcher.executor_helper import FIFOLineProcessor, StdErrLineProcessor, StdOutLineProcessor
import faraday_agent_dispatcher.logger as logging

from faraday_agent_dispatcher.config import instance as config, \
    EXECUTOR_SECTION, SERVER_SECTION, TOKENS_SECTION, save_config

logger = logging.get_logger()

LOG = False


class Dispatcher:

    def __init__(self):
        self.__host = config.get(SERVER_SECTION, "host")
        self.__api_port = config.get(SERVER_SECTION, "api_port")
        self.__websocket_port = config.get(SERVER_SECTION, "websocket_port")
        self.__workspace = config.get(SERVER_SECTION, "workspace")
        self.__agent_token = config[TOKENS_SECTION].get("agent", None)
        self.__executor_cmd = config.get(EXECUTOR_SECTION, "cmd")
        self.__session = ClientSession()
        self.__websocket_token = None
        self.__websocket = None

    def __get_url(self, port):
        return f"{self.__host}:{port}"

    def __api_url(self, secure=False):
        prefix = "https://" if secure else "http://"
        return f"{prefix}{self.__get_url(self.__api_port)}"

    def __websocket_url(self, secure=False):
        prefix = "wss://" if secure else "ws://"
        return f"{prefix}{self.__get_url(self.__websocket_port)}"

    async def reset_websocket_token(self):
        # I'm built so I ask for websocket token
        headers = {"Authorization": f"Agent {self.__agent_token}"}
        d = f'{self.__api_url()}/_api/v2/agent_websocket_token/'
        websocket_token_response = await self.__session.post(
            f'{self.__api_url()}/_api/v2/agent_websocket_token/',
            headers=headers)

        websocket_token_json = await websocket_token_response.json()  # TODO ERRORS
        self.__websocket_token = websocket_token_json["token"]

    async def connect(self):

        # REFACTORING
        if self.__agent_token is None:
            registration_token = self.__agent_token = config.get(TOKENS_SECTION, "registration")
            if registration_token is None:
                # TODO RAISE CORRECT
                raise RuntimeError
            token_registration_url = f"{self.__api_url()}/_api/v2/ws/{self.__workspace}/agent_registration/"
            token_response = await self.__session.post(token_registration_url,
                                                       json={'token': registration_token, 'name': "TEST"})
            # todo control token is jsonable
            token = await token_response.json()
            self.__agent_token = token["token"]
            config.set(TOKENS_SECTION, "agent", self.__agent_token)
            save_config()

        # I'm built so I can connect
        if self.__websocket_token is None:
            await self.reset_websocket_token()

        async with websockets.connect(self.__websocket_url()) as websocket:
            await websocket.send(json.dumps({
                'action': 'JOIN_AGENT',
                'workspace': self.__workspace,
                'token': self.__websocket_token,
            }))

            self.__websocket = websocket

            await self.run_await()  # This line can we called from outside (in main)

    async def disconnect(self):
        await self.__session.close()
        await self.__websocket.close()

    # V2
    async def run_await(self):
        # Next line must be uncommented, when faraday (and dispatcher) maintains the keep alive
        data = await self.__websocket.recv()
        # TODO Control data
        fifo_name = Dispatcher.rnd_fifo_name()
        Dispatcher.create_fifo(fifo_name)
        process = await self.create_process(fifo_name)
        async with aiofiles.open(fifo_name, "r") as fifo_file:
            tasks = [StdOutLineProcessor(process).process_f(),
                     StdErrLineProcessor(process).process_f(),
                     FIFOLineProcessor(fifo_file, self.__session).process_f(),
                     self.run_await()]

            await asyncio.gather(*tasks)
            await process.communicate()

    @staticmethod
    def create_fifo(fifo_name):
        if os.path.exists(fifo_name):
            os.remove(fifo_name)
        os.mkfifo(fifo_name)

    @staticmethod
    def rnd_fifo_name():
        import string
        from random import choice
        chars = string.ascii_letters + string.digits
        name = "".join(choice(chars) for _ in range(10))
        return f"/tmp/{name}"

    async def create_process(self, fifo_name):
        new_env = os.environ.copy()
        new_env["FIFO_NAME"] = fifo_name
        process = await asyncio.create_subprocess_shell(
            self.__executor_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=new_env
        )
        return process

    async def send(self):
        # Any time can be called by IPC

        # Send by API and Agent Token the info
        url = urljoin(self.__api_url(), "_api/v2/ws/"+ self.__workspace +"/hosts/")

        pass

