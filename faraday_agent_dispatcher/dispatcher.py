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

from faraday_agent_dispatcher.config import instance as config, Sections, save_config

logger = logging.get_logger()
logging.setup_logging()


class Dispatcher:

    __control_dict = {
        Sections.SERVER: {
            "host": control_host,
            "api_port": control_int,
            "websocket_port": control_int,
            "workspace": control_str
        },
        Sections.TOKENS: {
            "registration": control_registration_token,
            "agent": control_agent_token
        },
        Sections.EXECUTOR: {
            "cmd": control_str,
            "agent_name": control_str
        },

    }

    def __init__(self, session, config_path=None):
        reset_config(filepath=config_path)
        self.control_config()
        self.config_path = config_path
        self.host = config.get(Sections.SERVER, "host")
        self.api_port = config.get(Sections.SERVER, "api_port")
        self.websocket_port = config.get(Sections.SERVER, "websocket_port")
        self.workspace = config.get(Sections.SERVER, "workspace")
        self.agent_token = config[Sections.TOKENS].get("agent", None)
        self.executor_cmd = config.get(Sections.EXECUTOR, "cmd")
        self.agent_name = config.get(Sections.EXECUTOR, "agent_name")
        self.session = session
        self.websocket = None
        self.websocket_token = None

    async def reset_websocket_token(self):
        # I'm built so I ask for websocket token
        headers = {"Authorization": f"Agent {self.agent_token}"}
        logger.info(f"headers:{headers}")
        websocket_token_response = await self.session.post(
            api_url(self.host, self.api_port, postfix='/_api/v2/agent_websocket_token/'),
            headers=headers)

        websocket_token_json = await websocket_token_response.json()
        return websocket_token_json["token"]

    async def register(self):

        if self.agent_token is None:
            registration_token = self.agent_token = config.get(Sections.TOKENS, "registration")
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
                config.set(Sections.TOKENS, "agent", self.agent_token)
                save_config(self.config_path)
            except ClientResponseError as e:
                if e.status == 404:
                    logger.info(f"404 HTTP ERROR received: Workspace not found")
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
        logger.info('Parsing data: %s', data)
        data_dict = json.loads(data)
        if "action" in data_dict:
            if data_dict["action"] == "RUN":
                params = config.options(Sections.PARAMS).copy()
                passed_params = data_dict['args']
                [params.remove(param) for param in config.defaults()]
                # mandatoy_params_not_passed = [
                #    not any([
                #        param in passed_param  # The param is not there
                #        for param in params                                                     # For all parameters
                #    ])
                #    for passed_param in passed_params  # For all parameter passed
                #]
                #assert not any(mandatoy_params_not_passed)

                all_accepted = all(
                    [
                     any([
                        param in passed_param           # Control any available param
                        for param in params             # was passed
                        ])
                     for passed_param in passed_params  # For all passed params
                    ])
                if not all_accepted:
                    logger.error("Unexpected argument passed")
                mandatory_full = all(
                    [
                     config.get(Sections.PARAMS, param) != "True"  # All params is not mandatory
                     or any([
                        param in passed_param for passed_param in passed_params  # Or was passed
                        ])
                     for param in params
                    ]
                )
                if not mandatory_full:
                    logger.error("Mandatory argument not passed")

                if mandatory_full and all_accepted:
                    logger.info('Running executor')
                    process = await self.create_process(data_dict["args"])
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

    async def create_process(self, args):
        if args is None:
            cmd = self.executor_cmd
        elif isinstance(args, str):
            logger.warning("Args from data received is a string")
            cmd = self.executor_cmd + " --" + args
        elif isinstance(args, list):
            cmd = " --".join([self.executor_cmd] + args)
        else:
            logger.error("Args from data received has a not supported type")
            raise ValueError("Args from data received has a not supported type")
        import os
        env = os.environ.copy()
        for varenv in config.options(Sections.VARENVS):
            if varenv not in config.defaults():
                env[varenv.upper()] = config.get(Sections.VARENVS,varenv)
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
        )
        return process

    def control_config(self):
        for section in self.__control_dict:
            for option in self.__control_dict[section]:
                value = config.get(section, option) if option in config[section] else None
                self.__control_dict[section][option](option, value)
