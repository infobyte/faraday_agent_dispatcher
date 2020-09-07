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
import ssl
import json

import asyncio
from pathlib import Path
from asyncio import Task
from typing import List, Dict

import websockets
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from aiohttp import ClientTimeout
from aiohttp.client_exceptions import (
    ClientResponseError,
    ClientConnectorError,
    ClientConnectorCertificateError,
    ClientConnectorSSLError
)

from faraday_agent_dispatcher.config import reset_config
from faraday_agent_dispatcher.executor_helper import (
    StdErrLineProcessor,
    StdOutLineProcessor,
)
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_dispatcher.utils.url_utils import api_url, websocket_url
import faraday_agent_dispatcher.logger as logging

from faraday_agent_dispatcher.config import (
    instance as config,
    Sections,
    save_config,
    control_config,
    verify
)
from faraday_agent_dispatcher.executor import Executor

logger = logging.get_logger()
logging.setup_logging()


def _parse_list(list_str: str) -> List[str]:
    str_list = list_str.split(",")
    if "" in str_list:
        str_list.remove("")
    return str_list


class Dispatcher:

    class TaskLabels:
        CONNECTION_CHECK = "Connection check"
        EXECUTOR = "EXECUTOR"

    def __init__(self, session, config_path=None):
        reset_config(filepath=config_path)
        try:
            verify()
            control_config()
        except ValueError as e:
            logger.error(e)
            raise e
        self.config_path = config_path
        self.host = config.get(Sections.SERVER, "host")
        self.api_port = config.get(Sections.SERVER, "api_port")
        self.websocket_port = config.get(Sections.SERVER, "websocket_port")
        self.agent_token = config[Sections.TOKENS].get("agent", None)
        self.agent_name = config.get(Sections.AGENT, "agent_name")
        self.session = session
        self.websocket = None
        self.websocket_token = None
        self.workspaces = _parse_list(
            config.get(Sections.SERVER, "workspaces")
        )

        self.executors = {
            executor_name:
                Executor(executor_name, config)
                for executor_name in _parse_list(
                    config[Sections.AGENT].get("executors", "")
                )
        }
        self.ws_ssl_enabled = self.api_ssl_enabled = \
            config[Sections.SERVER].get("ssl", "False").lower() \
            in ["t", "true"]
        ssl_cert_path = config[Sections.SERVER].get("ssl_cert", None)
        if not Path(ssl_cert_path).exists():
            raise ValueError(
                f"SSL cert does not exist in path {ssl_cert_path}"
            )
        self.api_kwargs: Dict[str, object] = {
            "ssl": ssl.create_default_context(cafile=ssl_cert_path) if
            "HTTPS_PROXY" not in os.environ else False
        } \
            if self.api_ssl_enabled and ssl_cert_path \
            else {}
        if "HTTPS_PROXY" in os.environ:
            logger.info("HTTPS_PROXY is set; will not do SSL verify")
            ws_ssl_context = ssl.create_default_context()
            ws_ssl_context.check_hostname = False
            ws_ssl_context.verify_mode = ssl.CERT_NONE
        else:
            ws_ssl_context = ssl.create_default_context(cafile=ssl_cert_path)
        self.ws_kwargs = {
            "ssl": ws_ssl_context
        } \
            if self.ws_ssl_enabled \
            else {}
        self.execution_id = None
        self.executor_tasks: Dict[str, List[Task]] = {
            Dispatcher.TaskLabels.EXECUTOR: [],
            Dispatcher.TaskLabels.CONNECTION_CHECK: [],
        }
        self.sigterm_received = False

    async def reset_websocket_token(self):
        # I'm built so I ask for websocket token
        headers = {"Authorization": f"Agent {self.agent_token}"}
        websocket_token_response = await self.session.post(
            api_url(
                self.host,
                self.api_port,
                postfix='/_api/v2/agent_websocket_token/',
                secure=self.api_ssl_enabled
            ),
            headers=headers,
            **self.api_kwargs
        )

        websocket_token_json = await websocket_token_response.json()
        return websocket_token_json["token"]

    async def register(self):
        if not await self.check_connection():
            exit(1)

        if self.agent_token is None:
            registration_token = self.agent_token = \
                config.get(Sections.TOKENS, "registration")
            assert registration_token is not None, \
                "The registration token is mandatory"
            token_registration_url = api_url(
                self.host,
                self.api_port,
                postfix="/_api/v2/agent_registration/",
                secure=self.api_ssl_enabled
            )
            logger.info(f"token_registration_url: {token_registration_url}")
            try:
                token_response = await self.session.post(
                    token_registration_url,
                    json={
                        'token': registration_token,
                        'name': self.agent_name,
                        'workspaces': self.workspaces,
                    },
                    **self.api_kwargs
                )
                token = await token_response.json()
                self.agent_token = token["token"]
                config.set(Sections.TOKENS, "agent", self.agent_token)
                save_config(self.config_path)
            except ClientResponseError as e:
                if e.status == 404:
                    logger.error(
                        "404 HTTP ERROR received: Can't connect to the server"
                    )
                elif e.status == 401:
                    logger.error(
                        "Invalid registration token, please reset and retry. "
                        "If the error persist, you should try to edit the "
                        "registration token with the wizard command "
                        "`faraday-dispatcher config-wizard`"
                    )
                else:
                    logger.info(f"Unexpected error: {e}")
                logger.debug(msg="Exception raised", exc_info=e)
                exit(1)
            except ClientConnectorError as e:
                logger.debug(msg="Connection con error failed", exc_info=e)
                logger.error("Can connect to server")

        try:
            self.websocket_token = await self.reset_websocket_token()
            logger.info("Registered successfully")
        except ClientResponseError as e:
            error_msg = "Invalid agent token, please reset and retry. If " \
                        "the error persist, you should remove the agent " \
                        "token with the wizard command `faraday-dispatcher " \
                        "config-wizard`"
            logger.error(error_msg)
            self.agent_token = None
            logger.debug(msg="Exception raised", exc_info=e)
            exit(1)

    async def connect(self, out_func=None):

        if not self.websocket_token and not out_func:
            return

        connected_data = json.dumps({
                    'action': 'JOIN_AGENT',
                    'workspaces': self.workspaces,
                    'token': self.websocket_token,
                    'executors': [
                        {
                            "executor_name": executor.name,
                            "args": executor.params
                        }
                        for executor in self.executors.values()
                    ]
                })

        if out_func is None:

            async with websockets.connect(
                    websocket_url(
                        self.host,
                        self.websocket_port,
                        postfix='/websockets',
                        secure=self.ws_ssl_enabled
                    ),
                    **self.ws_kwargs) as websocket:
                await websocket.send(connected_data)

                logger.info("Connection to Faraday server succeeded")
                self.websocket = websocket

                # This line can we called from outside (in main)
                await self.run_await()
        else:
            await out_func(connected_data)

    async def run_await(self):
        while True:
            try:
                data = await self.websocket.recv()
                executor_task = asyncio.create_task(self.run_once(data))
                self.executor_tasks[Dispatcher.TaskLabels.EXECUTOR].append(
                    executor_task
                )
            except ConnectionClosedError:
                logger.info("The connection unexpectedly")
                break
            except ConnectionClosedOK as e:
                if e.reason:
                    logger.info(f"The server ended connection: {e.reason}")
                break

    async def run_once(self, data: str = None, out_func=None):
        out_func = out_func if out_func is not None else self.websocket.send
        logger.info('Parsing data: %s', data)
        data_dict = json.loads(data)
        if "action" not in data_dict:
            logger.info("Data not contains action to do")
            await out_func(
                json.dumps(
                    {
                        "error":
                            "'action' key is mandatory in this websocket "
                            "connection"
                    }
                )
            )
            return

        # `RUN` is the ONLY SUPPORTED COMMAND FOR NOW
        if data_dict["action"] not in ["RUN"]:
            logger.info("Unrecognized action")
            await out_func(
                json.dumps(
                    {
                        f"{data_dict['action']}_RESPONSE":
                            "Error: Unrecognized action"
                    }
                )
            )
            return

        if "execution_id" not in data_dict:
            logger.info("Data not contains execution id")
            await out_func(
                json.dumps(
                    {
                        "error":
                            "'execution_id' key is mandatory in this "
                            "websocket connection"
                    }
                )
            )
            return
        self.execution_id = data_dict["execution_id"]

        if "workspace" not in data_dict:
            logger.info("Data not contains workspace name")
            await out_func(
                json.dumps(
                    {
                        "error":
                            "'workspace' key is mandatory in this "
                            "websocket connection"
                    }
                )
            )
            return
        workspace_selected = data_dict["workspace"]

        if data_dict["action"] == "RUN":
            if "executor" not in data_dict:
                logger.error("No executor selected")
                await out_func(
                    json.dumps({
                        "action": "RUN_STATUS",
                        "execution_id": self.execution_id,
                        "running": False,
                        "message": "No executor selected to "
                                   f"{self.agent_name} agent"
                    })
                )
                return

            if workspace_selected not in self.workspaces:
                logger.error("Invalid workspace passed")
                await out_func(
                    json.dumps(
                        {
                            "action": f"{data_dict['action']}_STATUS",
                            "execution_id": self.execution_id,
                            "running": False,
                            "message": "Invalid workspace passed to "
                                       f"{self.agent_name} agent"
                        }
                    )
                )
                return

            if data_dict["executor"] not in self.executors:
                logger.error("The selected executor not exists")
                await out_func(
                    json.dumps({
                        "action": "RUN_STATUS",
                        "execution_id": self.execution_id,
                        "executor_name": data_dict['executor'],
                        "running": False,
                        "message": "The selected executor "
                                   f"{data_dict['executor']} not exists in "
                                   f"{self.agent_name} agent"
                    })
                )
                return

            executor = self.executors[data_dict["executor"]]

            params = list(executor.params.keys()).copy()
            passed_params = data_dict['args'] if 'args' in data_dict else {}
            [params.remove(param) for param in config.defaults()]

            all_accepted = all(
                [
                    any([
                        param in passed_param     # Control any available param
                        for param in params             # was passed
                        ])
                    for passed_param in passed_params   # For all passed params
                ])
            if not all_accepted:
                logger.error(
                    f"Unexpected argument passed to {executor.name} executor"
                )
                await out_func(
                    json.dumps({
                        "action": "RUN_STATUS",
                        "execution_id": self.execution_id,
                        "executor_name": executor.name,
                        "running": False,
                        "message": "Unexpected argument(s) passed to "
                                   f"{executor.name} executor from "
                                   f"{self.agent_name} agent"
                    })
                )
            mandatory_full = all(
                [
                    not executor.params[param]  # All params is not mandatory
                    or any([
                        param in passed_param
                        for passed_param in passed_params  # Or was passed
                        ])
                    for param in params
                ]
            )
            if not mandatory_full:
                logger.error(
                    "Mandatory argument not passed to {executor.name} executor"
                )
                await out_func(
                    json.dumps({
                        "action": "RUN_STATUS",
                        "execution_id": self.execution_id,
                        "executor_name": executor.name,
                        "running": False,
                        "message": f"Mandatory argument(s) not passed to "
                                   f"{executor.name} executor from "
                                   f"{self.agent_name} agent"
                    })
                )

            if mandatory_full and all_accepted:
                if not await executor.check_cmds():
                    # The function logs why cant run
                    return
                running_msg = f"Running {executor.name} executor from " \
                              f"{self.agent_name} agent"
                logger.info("Running {} executor".format(executor.name))

                process = await self.create_process(executor, passed_params)
                tasks = [
                    StdOutLineProcessor(
                        process,
                        self.session,
                        self.execution_id,
                        workspace_selected,
                        self.api_ssl_enabled,
                        self.api_kwargs
                    ).process_f(),
                    StdErrLineProcessor(process).process_f(),
                ]
                await out_func(
                    json.dumps({
                        "action": "RUN_STATUS",
                        "execution_id": self.execution_id,
                        "executor_name": executor.name,
                        "running": True,
                        "message": running_msg
                    })
                )
                await asyncio.gather(*tasks)
                await process.communicate()
                assert process.returncode is not None
                if process.returncode == 0:
                    logger.info(
                        f"Executor {executor.name} finished successfully"
                    )
                    await out_func(
                        json.dumps({
                            "action": "RUN_STATUS",
                            "execution_id": self.execution_id,
                            "executor_name": executor.name,
                            "successful": True,
                            "message": f"Executor {executor.name} from "
                                       f"{self.agent_name} finished "
                                       "successfully"
                        }))
                else:
                    logger.warning(
                        f"Executor {executor.name} finished with exit code"
                        f" {process.returncode}"
                    )
                    await out_func(
                        json.dumps({
                            "action": "RUN_STATUS",
                            "execution_id": self.execution_id,
                            "executor_name": executor.name,
                            "successful": False,
                            "message": f"Executor {executor.name} "
                                       f"from {self.agent_name} failed"
                        }))

    @staticmethod
    async def create_process(executor: Executor, args):
        env = os.environ.copy()
        if isinstance(args, dict):
            for k in args:
                env[f"EXECUTOR_CONFIG_{k.upper()}"] = str(args[k])
        else:
            logger.error("Args from data received has a not supported type")
            raise ValueError(
                "Args from data received has a not supported type"
            )
        for varenv, value in executor.varenvs.items():
            env[f"{varenv.upper()}"] = value
        process = await asyncio.create_subprocess_shell(
            executor.cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            limit=executor.max_size
            # If the config is not set, use async.io default
        )
        return process

    async def close(self, signal):
        self.sigterm_received = True
        if self.websocket and self.websocket.open:
            await self.websocket.send(
                json.dumps({
                    "action": "LEAVE_AGENT",
                    "token": self.websocket_token,
                    "reason": f"{signal} received",
                })
            )
            for task in self.executor_tasks[Dispatcher.TaskLabels.EXECUTOR]:
                task.cancel()
            await self.websocket.close(code=1000, reason=f"{signal} received")
        for task in \
                self.executor_tasks[Dispatcher.TaskLabels.CONNECTION_CHECK]:
            task.cancel()
        await asyncio.sleep(0.25)

    async def check_connection(self):
        server_url = api_url(
            self.host,
            self.api_port,
            secure=self.api_ssl_enabled
        )
        logger.debug(f"Validating server connection with {server_url}")
        try:
            kwargs = self.api_kwargs.copy()
            if 'DISPATCHER_TEST' in os.environ and \
                    os.environ['DISPATCHER_TEST'] == "True":
                kwargs["timeout"] = ClientTimeout(total=1)
            # > The below code allows this get to be canceled,
            # > But breaks only ours Gitlab CI tests (local OK)
            # check_connection_task = asyncio.create_task(
            #    self.session.get(server_url, **kwargs)
            # )
            # self.executor_tasks[Dispatcher.TaskLabels.CONNECTION_CHECK].\
            #    append(check_connection_task)
            # await check_connection_task
            await self.session.get(server_url, **kwargs)

        except (
                ClientConnectorCertificateError,
                ClientConnectorSSLError
        ) as e:
            logger.debug("Invalid SSL Certificate", exc_info=e)
            print(f"{Bcolors.FAIL}Invalid SSL Certificate, use "
                  "`faraday-dispatcher config-wizard` and check the "
                  "certificate configuration")
            return False
        except ClientConnectorError as e:
            logger.error("Can not connect to Faraday server")
            logger.debug("Connect failed traceback", exc_info=e)
            return False
        except asyncio.TimeoutError as e:
            logger.error("Faraday server timed-out. "
                         "TIP: Check ssl configuration")
            logger.debug("Timeout error. Check ssl", exc_info=e)
            return False
        except asyncio.CancelledError:
            logger.info("User sent close signal")
            return False
        return True
