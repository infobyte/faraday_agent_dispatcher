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

import json

import asyncio
import websockets
from aiohttp.client_exceptions import ClientResponseError

from faraday_agent_dispatcher.config import reset_config
from faraday_agent_dispatcher.executor_helper import StdErrLineProcessor, StdOutLineProcessor
from faraday_agent_dispatcher.utils.url_utils import api_url, websocket_url
from faraday_agent_dispatcher.utils.control_values_utils import (
    control_int,
    control_str,
    control_host,
    control_registration_token,
    control_agent_token
)
import faraday_agent_dispatcher.logger as logging

from faraday_agent_dispatcher.config import instance as config, \
    EXECUTOR_SECTION, SERVER_SECTION, TOKENS_SECTION, save_config

logger = logging.get_logger()


class Dispatcher:

    __control_dict = {
        SERVER_SECTION: {
            "host": control_host,
            "api_port": control_int,
            "websocket_port": control_int,
            "workspace": control_str
        },
        TOKENS_SECTION: {
            "registration": control_registration_token,
            "agent": control_agent_token
        },
        EXECUTOR_SECTION: {
            "cmd": control_str,
            "agent_name": control_str
        }
    }

    def __init__(self, session, config_path=None):
        reset_config(filepath=config_path)
        self.control_config()
        self.config_path = config_path
        self.host = config.get(SERVER_SECTION, "host")
        self.api_port = config.get(SERVER_SECTION, "api_port")
        self.websocket_port = config.get(SERVER_SECTION, "websocket_port")
        self.workspace = config.get(SERVER_SECTION, "workspace")
        self.agent_token = config[TOKENS_SECTION].get("agent", None)
        self.executor_cmd = config.get(EXECUTOR_SECTION, "cmd")
        self.agent_name = config.get(EXECUTOR_SECTION, "agent_name")
        self.session = session
        self.websocket = None
        self.websocket_token = None

    async def reset_websocket_token(self):
        # I'm built so I ask for websocket token
        headers = {"Authorization": f"Agent {self.agent_token}"}
        websocket_token_response = await self.session.post(
            api_url(self.host, self.api_port, postfix='/_api/v2/agent_websocket_token/'),
            headers=headers)

        websocket_token_json = await websocket_token_response.json()
        return websocket_token_json["token"]

    async def register(self):

        if self.agent_token is None:
            registration_token = self.agent_token = config.get(TOKENS_SECTION, "registration")
            assert registration_token is not None, "The registration token is mandatory"
            token_registration_url = api_url(self.host,
                                             self.api_port,
                                             postfix=f"/_api/v2/ws/{self.workspace}/agent_registration/")
            logger.info(f"token_registration_url: {token_registration_url}")
            try:
                token_response = await self.session.post(token_registration_url,
                                                         json={'token': registration_token, 'name': self.agent_name})
                assert token_response.status == 201
                token = await token_response.json()
                self.agent_token = token["token"]
                config.set(TOKENS_SECTION, "agent", self.agent_token)
                save_config(self.config_path)
            except ClientResponseError as e:
                if e.status == 404:
                    logger.info(f'404 HTTP ERROR received: Workspace "{self.workspace}" not found')
                    return
                else:
                    logger.info(f"Unexpected error: {e}")
                    raise e

        self.websocket_token = await self.reset_websocket_token()

    async def connect(self):

        if not self.websocket_token:
            return

        async with websockets.connect(websocket_url(self.host, self.websocket_port)) as websocket:
            await websocket.send(json.dumps({
                'action': 'JOIN_AGENT',
                'workspace': self.workspace,
                'token': self.websocket_token,
            }))

            logger.info("Connection to Faraday server succeeded")
            self.websocket = websocket

            await self.run_await()  # This line can we called from outside (in main)

    async def run_await(self):
        while True:
            # Next line must be uncommented, when faraday (and dispatcher) maintains the keep alive
            data = await self.websocket.recv()
            asyncio.create_task(self.run_once(data))

    async def run_once(self, data:str= None):
        # TODO Control data
        logger.info('Running executor with data: %s', data)
        data_dict = json.loads(data)
        if "action" in data_dict:
            if data_dict["action"] == "RUN":
                process = await self.create_process()
                tasks = [StdOutLineProcessor(process, self.session).process_f(),
                         StdErrLineProcessor(process).process_f(),
                         ]

                await asyncio.gather(*tasks)
                await process.communicate()
                assert process.returncode is not None
                if process.returncode == 0:
                    logger.info("Executor finished successfully")
                else:
                    logger.warning(
                        f"Executor finished with exit code {process.returncode}")
            else:
                logger.info("Action unrecognized")

        else:
            logger.info("Data not contains action to do")

    async def create_process(self):
        process = await asyncio.create_subprocess_shell(
            self.executor_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=int(config[EXECUTOR_SECTION].get("max_size", 64 * 1024))
            # If the config is not set, use async.io default
        )
        return process

    def control_config(self):
        for section in self.__control_dict:
            for option in self.__control_dict[section]:
                value = config.get(section, option) if option in config[section] else None
                self.__control_dict[section][option](option, value)
