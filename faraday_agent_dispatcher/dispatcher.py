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

import os
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
    control_agent_token,
    control_list
)
import faraday_agent_dispatcher.logger as logging

from faraday_agent_dispatcher.config import instance as config, Sections, save_config
from faraday_agent_dispatcher.executor import Executor

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
        Sections.AGENT: {
            "agent_name": control_str,
            "executors": control_list
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
        self.agent_name = config.get(Sections.AGENT, "agent_name")
        self.session = session
        self.websocket = None
        self.websocket_token = None
        self.executors = {
            executor_name:
                Executor(executor_name, config) for executor_name in config[Sections.AGENT].get("executors", []).split(",")
        }

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
                    logger.info(f'404 HTTP ERROR received: Workspace "{self.workspace}" not found')
                    return
                else:
                    logger.info(f"Unexpected error: {e}")
                    raise e

        self.websocket_token = await self.reset_websocket_token()

    async def connect(self, out_func=None):

        if not self.websocket_token:
            return

        connected_data = json.dumps({
                    'action': 'JOIN_AGENT',
                    'workspace': self.workspace,
                    'token': self.websocket_token,
                })

        if out_func is None:

            async with websockets.connect(websocket_url(self.host, self.websocket_port)) as websocket:
                await websocket.send(connected_data)

                logger.info("Connection to Faraday server succeeded")
                self.websocket = websocket

                await self.run_await()  # This line can we called from outside (in main)
        else:
            await out_func(connected_data)

    async def run_await(self):
        while True:
            # Next line must be uncommented, when faraday (and dispatcher) maintains the keep alive
            data = await self.websocket.recv()
            asyncio.create_task(self.run_once(data))

    async def run_once(self, data:str= None, out_f=None):
        out_f = out_f if out_f is not None else self.websocket.send
        logger.info('Parsing data: %s', data)
        data_dict = json.loads(data)
        if "action" in data_dict:
            if data_dict["action"] == "RUN":
                params = config.options(Sections.PARAMS).copy()
                passed_params = data_dict['args'] if 'args' in data_dict else {}
                [params.remove(param) for param in config.defaults()]

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
                    await out_f(
                        json.dumps({
                            "action": "RUN_STATUS",
                            "running": False,
                            "message": f"Unexpected argument(s) passed to {self.agent_name} agent"
                        })
                    )
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
                    await out_f(
                        json.dumps({
                            "action": "RUN_STATUS",
                            "running": False,
                            "message": f"Mandatory argument(s) not passed to {self.agent_name} agent"
                        })
                    )

                if mandatory_full and all_accepted:
                    running_msg = f"Running executor from {self.agent_name} agent"
                    logger.info('Running executor')

                    process = await self.create_process(passed_params)
                    tasks = [StdOutLineProcessor(process, self.session).process_f(),
                             StdErrLineProcessor(process).process_f(),
                             ]
                    await out_f(
                        json.dumps({
                            "action": "RUN_STATUS",
                            "running": True,
                            "message": running_msg
                        })
                    )
                    await asyncio.gather(*tasks)
                    await process.communicate()
                    assert process.returncode is not None
                    if process.returncode == 0:
                        logger.info("Executor finished successfully")
                        await out_f(
                            json.dumps({
                                "action": "RUN_STATUS",
                                "successful": True,
                                "message": "Executor finished successfully"
                            }))
                    else:
                        logger.warning(
                            f"Executor finished with exit code {process.returncode}")
                        await out_f(
                            json.dumps({
                                "action": "RUN_STATUS",
                                "successful": False,
                                "message": "Executor failed"
                            }))
            else:
                logger.info("Unrecognized action")
                await out_f(json.dumps({f"{data_dict['action']}_RESPONSE": "Error: Unrecognized action"}))
        else:
            logger.info("Data not contains action to do")
            await out_f(json.dumps({"error": "'action' key is mandatory in this websocket connection"}))

    async def create_process(self, args):
        env = os.environ.copy()
        if isinstance(args, dict):
            for k in args:
                env[k.upper()] = str(args[k])
        else:
            logger.error("Args from data received has a not supported type")
            raise ValueError("Args from data received has a not supported type")
        for varenv in config.options(Sections.VARENVS):
            if varenv not in config.defaults():
                env[varenv.upper()] = config.get(Sections.VARENVS,varenv)
        process = await asyncio.create_subprocess_shell(
            self.executor_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            limit=int(config[Sections.EXECUTOR].get("max_size", 64 * 1024))
            # If the config is not set, use async.io default
        )
        return process

    def control_config(self):
        for section in self.__control_dict:
            for option in self.__control_dict[section]:
                value = config.get(section, option) if option in config[section] else None
                self.__control_dict[section][option](option, value)
