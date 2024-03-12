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

import aiohttp
import socketio
import asyncio
from datetime import datetime
from pathlib import Path
from asyncio import Task
from typing import List, Dict
import sys
import websockets
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from aiohttp import ClientTimeout
from aiohttp.client_exceptions import (
    ClientResponseError,
    ClientConnectorError,
    ClientConnectorCertificateError,
    ClientConnectorSSLError,
)
import click
from faraday_agent_dispatcher.config import reset_config
from faraday_agent_dispatcher.executor_helper import (
    StdErrLineProcessor,
    StdOutLineProcessor,
)
from faraday_agent_dispatcher.utils.control_values_utils import (
    control_registration_token,
)
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_dispatcher.utils.url_utils import api_url, websocket_url
import faraday_agent_dispatcher.logger as logging
from faraday_agent_dispatcher import config
from faraday_agent_dispatcher.config import (
    Sections,
    save_config,
    control_config,
)
from faraday_agent_dispatcher.utils.metadata_utils import (
    executor_metadata,
    check_metadata,
)
from faraday_agent_dispatcher.cli.utils.model_load import set_repo_params
from faraday_agent_dispatcher.executor import Executor
from faraday_agent_parameters_types.utils import type_validate

logger = logging.get_logger()
logging.setup_logging()


class Dispatcher:
    class TaskLabels:
        CONNECTION_CHECK = "Connection check"
        EXECUTOR = "EXECUTOR"

    def __init__(self, session, config_path=None, *args, **kwargs):
        reset_config(filepath=config_path)
        self.update_executors()
        try:
            control_config()
        except ValueError as e:
            logger.error(e)
            raise e
        self.config_path = config_path
        self.host = config.instance[Sections.SERVER]["host"]
        self.api_port = config.instance[Sections.SERVER]["api_port"]
        self.websocket_port = config.instance[Sections.SERVER]["websocket_port"]
        self.agent_token = (
            config.instance[Sections.TOKENS].get("agent") if Sections.TOKENS in config.instance else None
        )
        self.agent_name = config.instance[Sections.AGENT]["agent_name"]
        self.session = session
        self.websocket = None
        self.websocket_token = None
        self.executors = {
            executor_name: Executor(executor_name, executor_data)
            for executor_name, executor_data in config.instance[Sections.AGENT].get("executors", {}).items()
        }
        self.ws_ssl_enabled = self.api_ssl_enabled = config.instance[Sections.SERVER].get("ssl", False)
        self.sio = socketio.AsyncClient()
        ssl_cert_path = config.instance[Sections.SERVER].get("ssl_cert", None)
        ssl_ignore = config.instance[Sections.SERVER].get("ssl_ignore", False)
        if not Path(ssl_cert_path).exists():
            raise ValueError(f"SSL cert does not exist in path {ssl_cert_path}")
        if self.api_ssl_enabled:
            logger.info("api_ssl is enabled")
            if ssl_cert_path:
                ssl_cert_context = ssl.create_default_context(cafile=ssl_cert_path)
                self.api_kwargs = {"ssl": ssl_cert_context}
                self.ws_kwargs = {"ssl": ssl_cert_context}
                connector = aiohttp.TCPConnector(ssl=ssl_cert_context)
                http_session = aiohttp.ClientSession(connector=connector)
                self.sio = socketio.AsyncClient(http_session=http_session)
            else:
                if ssl_ignore or "HTTPS_PROXY" in os.environ:
                    logger.info(f"ssl_ignore config is {ssl_ignore}")
                    if "HTTPS_PROXY" in os.environ:
                        logger.info("HTTPS_PROXY variable found in environment")
                    ignore_ssl_context = ssl.create_default_context()
                    ignore_ssl_context.check_hostname = False
                    ignore_ssl_context.verify_mode = ssl.CERT_NONE
                    self.api_kwargs = {"ssl": ignore_ssl_context}
                    self.ws_kwargs = {"ssl": ignore_ssl_context}
                    connector = aiohttp.TCPConnector(ssl=ignore_ssl_context)
                    http_session = aiohttp.ClientSession(connector=connector)
                    self.sio = socketio.AsyncClient(http_session=http_session)
                else:
                    self.api_kwargs: Dict[str, object] = {}
                    self.ws_kwargs: Dict[str, object] = {}
        else:
            self.api_kwargs: Dict[str, object] = {}
            self.ws_kwargs: Dict[str, object] = {}
        self.execution_ids = None
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
                postfix="/_api/v3/agent_websocket_token",
                secure=self.api_ssl_enabled,
            ),
            headers=headers,
            **self.api_kwargs,
        )

        websocket_token_json = await websocket_token_response.json()
        return websocket_token_json["token"]

    async def register(self, registration_token=None):
        if not await self.check_connection():
            exit(1)

        if self.agent_token is None:
            try:
                control_registration_token("token", registration_token)
            except ValueError as ex:
                print(f"{Bcolors.FAIL}{ex.args[0]}")
                logger.error(ex.args[0])
                exit(1)

            token_registration_url = api_url(
                self.host,
                self.api_port,
                postfix="/_api/v3/agents",
                secure=self.api_ssl_enabled,
            )
            logger.info(f"token_registration_url: {token_registration_url}")
            try:
                token_response = await self.session.post(
                    token_registration_url,
                    json={
                        "token": registration_token,
                        "name": self.agent_name,
                    },
                    **self.api_kwargs,
                )
                token = await token_response.json()
                self.agent_token = token["token"]
                if Sections.TOKENS not in config.instance:
                    config.instance[Sections.TOKENS] = {}
                config.instance[Sections.TOKENS]["agent"] = self.agent_token
                save_config(self.config_path)
            except ClientResponseError as e:
                if e.status == 404:
                    logger.error("404 HTTP ERROR received: Can't connect to the server")
                elif e.status == 401:
                    logger.error(
                        "Invalid registration token, please reset and retry. "
                        "If the error persist, you should try to edit the "
                        "registration token with the wizard command "
                        "`faraday-dispatcher config-wizard`\nHint: "
                        "If the faraday version is not the expected this"
                        "could fail, check "
                        "https://github.com/infobyte/faraday_agent_dispatcher"
                        "/blob/master/RELEASE.md"
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
            if e.status == 402:
                error_msg = "Unauthorized. Is your license expired or invalid?"
            else:
                error_msg = (
                    "Invalid agent token, please reset and retry. If "
                    "the error persist, you should remove the agent "
                    "token with the wizard command `faraday-dispatcher "
                    "config-wizard`"
                )
            logger.error(error_msg)
            self.agent_token = None
            logger.debug(msg="Exception raised", exc_info=e)
            exit(1)

    async def connect(self):
        if not self.websocket_token:
            return

        connected_data = json.dumps(
            {
                "action": "JOIN_AGENT",
                "token": self.websocket_token,
                "executors": [
                    {"executor_name": executor.name, "args": executor.params} for executor in self.executors.values()
                ],
            }
        )
        async with websockets.connect(
            websocket_url(
                self.host,
                self.websocket_port,
                postfix="/websockets",
                secure=self.ws_ssl_enabled,
            ),
            **self.ws_kwargs,
        ) as websocket:
            await websocket.send(connected_data)

            logger.info("Connection to Faraday server succeeded")
            self.websocket = websocket

            # This line can we called from outside (in main)
            await self.run_await()

    async def run_await(self):
        while True:
            try:
                data = await self.websocket.recv()
                executor_task = asyncio.create_task(self.run_once(data))
                self.executor_tasks[Dispatcher.TaskLabels.EXECUTOR].append(executor_task)
            except ConnectionClosedError:
                logger.info("The connection unexpectedly")
                break
            except ConnectionClosedOK as e:
                if e.reason:
                    logger.info(f"The server ended connection: {e.reason}")
                break

    async def run_once(self, data: str = None):
        try:
            logger.info(f"Parsing data: {data}")
            data_dict = json.loads(data)
            if "action" not in data_dict:
                logger.info("Data not contains action to do")
                await self.websocket.send(
                    json.dumps({"error": "'action' key is mandatory" " in this websocket connection"})
                )
                return

            # `RUN` is the ONLY SUPPORTED COMMAND FOR NOW
            if data_dict["action"] not in ["RUN"]:
                logger.info("Unrecognized action")
                await self.websocket.send(
                    json.dumps({f"{data_dict['action']}_RESPONSE": "Error: " "Unrecognized " "action"})
                )
                return

            if "execution_ids" not in data_dict:
                logger.info("Data not contains execution id")
                await self.websocket.send(
                    json.dumps({"error": "'execution_ids' key is mandatory" " in this " "websocket connection"})
                )
                return
            self.execution_ids = data_dict["execution_ids"]
            if "workspaces" not in data_dict:
                logger.info("Data not contains workspaces list")
                await self.websocket.send(
                    json.dumps({"error": "'workspaces' key is mandatory in this " "websocket connection"})
                )
                return
            workspaces_selected = data_dict["workspaces"]

            if data_dict["action"] == "RUN":
                if "executor" not in data_dict:
                    logger.error("No executor selected")
                    await self.websocket.send(
                        json.dumps(
                            {
                                "action": "RUN_STATUS",
                                "execution_ids": self.execution_ids,
                                "running": False,
                                "message": "No executor selected to " f"{self.agent_name} agent",
                            }
                        )
                    )
                    return

                if data_dict["executor"] not in self.executors:
                    logger.error("The selected executor not exists")
                    await self.websocket.send(
                        json.dumps(
                            {
                                "action": "RUN_STATUS",
                                "execution_ids": self.execution_ids,
                                "executor_name": data_dict["executor"],
                                "running": False,
                                "message": "The selected executor "
                                f"{data_dict['executor']} not exists in "
                                f"{self.agent_name} agent",
                            }
                        )
                    )
                    return

                executor = self.executors[data_dict["executor"]]

                params = list(executor.params.keys()).copy()
                passed_params = data_dict["args"] if "args" in data_dict else {}

                all_accepted = all(
                    [
                        any([param in passed_param for param in params])  # Control any available param  # was passed
                        for passed_param in passed_params
                        # For all passed params
                    ]
                )
                if not all_accepted:
                    logger.error(f"Unexpected argument passed to {executor.name}" f" executor")
                    await self.websocket.send(
                        json.dumps(
                            {
                                "action": "RUN_STATUS",
                                "execution_ids": self.execution_ids,
                                "executor_name": executor.name,
                                "running": False,
                                "message": "Unexpected argument(s) passed to "
                                f"{executor.name} executor from "
                                f"{self.agent_name} agent",
                            }
                        )
                    )
                mandatory_full = all(
                    [
                        not executor.params[param]["mandatory"]  # All params is not mandatory
                        or any([param in passed_param for passed_param in passed_params])  # Or was passed
                        for param in params
                    ]
                )
                if not mandatory_full:
                    logger.error(f"Mandatory argument not passed " f"to {executor.name} executor")
                    await self.websocket.send(
                        json.dumps(
                            {
                                "action": "RUN_STATUS",
                                "execution_ids": self.execution_ids,
                                "executor_name": executor.name,
                                "running": False,
                                "message": f"Mandatory argument(s) "
                                f"not passed to "
                                f"{executor.name} executor from "
                                f"{self.agent_name} agent",
                            }
                        )
                    )

                # VALIDATE
                errors = dict()
                for param in passed_params:
                    param_errors = type_validate(executor.params[param]["type"], passed_params[param])
                    if param_errors:
                        errors[param] = ",".join(param_errors["data"])
                        logger.error(
                            f'Validation error on parameter "{param}", of type'
                            f' "{executor.params[param]["type"]}":'
                            f" {errors[param]}"
                        )

                if errors:
                    error_msg = "Validation error:"
                    for param in errors:
                        error_msg += (
                            f"\n{param} = {passed_params[param]} " f"did not validate correctly: {errors[param]}"
                        )
                    logger.error(error_msg)
                    await self.websocket.send(
                        json.dumps(
                            {
                                "action": "RUN_STATUS",
                                "execution_ids": self.execution_ids,
                                "executor_name": executor.name,
                                "running": False,
                                "message": error_msg,
                            }
                        )
                    )
                    return

                if mandatory_full and all_accepted:
                    if not await executor.check_cmds():
                        # The function logs why cant run
                        return
                    running_msg = f"Running {executor.name} executor from " f"{self.agent_name} agent"
                    logger.info(f"Running {executor.name} executor")

                    #                TODO move all checks to another function
                    plugin_args = data_dict.get("plugin_args", {})
                    process = await self.create_process(executor, passed_params, plugin_args)
                    start_date = datetime.utcnow()
                    command_json = {
                        "tool": self.agent_name,
                        "command": executor.name,
                        "user": "",
                        "hostname": "",
                        "params": ", ".join([f"{key}={value}" for (key, value) in passed_params.items()]),
                        "import_source": "agent",
                        "start_date": start_date.isoformat(),
                    }
                    tasks = [
                        StdOutLineProcessor(
                            process,
                            self.session,
                            self.execution_ids,
                            workspaces_selected,
                            self.api_ssl_enabled,
                            self.api_kwargs,
                            command_json,
                            start_date,
                        ).process_f(),
                        StdErrLineProcessor(process).process_f(),
                    ]
                    await self.websocket.send(
                        json.dumps(
                            {
                                "action": "RUN_STATUS",
                                "execution_ids": self.execution_ids,
                                "executor_name": executor.name,
                                "running": True,
                                "message": running_msg,
                            }
                        )
                    )
                    await asyncio.gather(*tasks)
                    await process.communicate()
                    assert process.returncode is not None
                    if process.returncode == 0:
                        logger.info(f"Executor {executor.name} finished successfully")
                        await self.websocket.send(
                            json.dumps(
                                {
                                    "action": "RUN_STATUS",
                                    "execution_ids": self.execution_ids,
                                    "executor_name": executor.name,
                                    "successful": True,
                                    "message": f"Executor "
                                    f"{executor.name} from "
                                    f"{self.agent_name} finished "
                                    "successfully",
                                }
                            )
                        )
                    else:
                        logger.warning(f"Executor {executor.name} finished with exit code" f" {process.returncode}")
                        await self.websocket.send(
                            json.dumps(
                                {
                                    "action": "RUN_STATUS",
                                    "execution_ids": self.execution_ids,
                                    "executor_name": executor.name,
                                    "successful": False,
                                    "message": f"Executor {executor.name} " f"from {self.agent_name} failed",
                                }
                            )
                        )
        except Exception as e:
            logger.error(f"Exception occurred {e}")
            await self.websocket.send(
                json.dumps(
                    {
                        "action": "RUN_STATUS",
                        "execution_ids": self.execution_ids,
                        "executor_name": executor.name,
                        "successful": False,
                        "message": f"Executor {executor.name} " f"from {self.agent_name} failed",
                    }
                )
            )

    @staticmethod
    async def create_process(executor: Executor, args: dict, plugin_args: dict):
        env = os.environ.copy()
        # Executor Variables
        if isinstance(args, dict):
            for k in args:
                env[f"EXECUTOR_CONFIG_{k.upper()}"] = str(args[k])
        else:
            logger.error("Args from data received has a not supported type")
            raise ValueError("Args from data received has a not supported type")
        # Plugins Variables
        for pa in plugin_args:
            if isinstance(plugin_args.get(pa), list):
                env[f"AGENT_CONFIG_{pa.upper()}"] = ",".join(plugin_args.get(pa))
            elif plugin_args.get(pa):
                env[f"AGENT_CONFIG_{pa.upper()}"] = str(plugin_args.get(pa))
        # Executor Defaults
        for varenv, value in executor.varenvs.items():
            env[f"{varenv.upper()}"] = value
        command = executor.cmd
        if command.endswith(".py") and executor.repo_executor:
            command = f"{sys.executable} {command}"
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            limit=executor.max_size,
            # If the config is not set, use async.io default
        )
        return process

    async def close(self, signal):
        self.sigterm_received = True
        if self.websocket and self.websocket.open:
            await self.websocket.send(
                json.dumps(
                    {
                        "action": "LEAVE_AGENT",
                        "token": self.websocket_token,
                        "reason": f"{signal} received",
                    }
                )
            )
            for task in self.executor_tasks[Dispatcher.TaskLabels.EXECUTOR]:
                task.cancel()
            await self.websocket.close(code=1000, reason=f"{signal} received")
        for task in self.executor_tasks[Dispatcher.TaskLabels.CONNECTION_CHECK]:
            task.cancel()
        await asyncio.sleep(0.25)

    async def check_connection(self):
        server_url = api_url(
            self.host,
            self.api_port,
            postfix="/_api/v3/info",
            secure=self.api_ssl_enabled,
        )
        logger.debug(f"Validating server connection with {server_url}")
        try:
            kwargs = self.api_kwargs.copy()
            if "DISPATCHER_TEST" in os.environ and os.environ["DISPATCHER_TEST"] == "True":
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

        except (ClientConnectorCertificateError, ClientConnectorSSLError) as e:
            logger.debug("Invalid SSL Certificate", exc_info=e)
            print(
                f"{Bcolors.FAIL}Invalid SSL Certificate, use "
                "`faraday-dispatcher config-wizard` and check the "
                "certificate configuration"
            )
            return False
        except ClientConnectorError as e:
            logger.error("Can not connect to Faraday server")
            logger.debug("Connect failed traceback", exc_info=e)
            return False
        except asyncio.TimeoutError as e:
            logger.error("Faraday server timed-out. " "TIP: Check ssl configuration")
            logger.debug("Timeout error. Check ssl", exc_info=e)
            return False
        except asyncio.CancelledError:
            logger.info("User sent close signal")
            return False
        return True

    @staticmethod
    def update_executors():
        executors = config.instance.get(Sections.AGENT, {}).get("executors")
        if isinstance(executors, dict):
            for executor_name, executor_data in executors.items():
                repo_name = executor_data.get("repo_name")
                metadata = executor_metadata(repo_name)
                if metadata:
                    if not check_metadata(metadata):
                        click.secho(
                            f"Invalid manifest for: {executor_name}",
                            fg="yellow",
                        )
                    set_repo_params(executor_name, metadata)
                    for env_varb in metadata.get("environment_variables"):
                        if env_varb not in executor_data.get("varenvs"):
                            logger.warning(
                                f"{Bcolors.WARNING}The enviroment variable"
                                f" {env_varb} of executor {repo_name}"
                                f" is not defined in config file."
                                f"{Bcolors.ENDC}"
                            )


class DispatcherNamespace(socketio.AsyncClientNamespace):
    def __init__(self, dispatcher=None, namespace=""):
        self.dispatcher = dispatcher
        super().__init__(namespace=namespace)

    async def on_connect(self):
        connected_data = {
            "action": "JOIN_AGENT",
            "token": self.dispatcher.websocket_token,
            "executors": [
                {"executor_name": executor.name, "args": executor.params}
                for executor in self.dispatcher.executors.values()
            ],
        }
        await self.emit("join_agent", connected_data)

    async def on_disconnect(self, *args, **kwargs):
        await self.disconnect()

    async def on_run(self, data):
        workspaces_selected = data["workspaces"]
        self.dispatcher.execution_ids = data["execution_ids"]
        if "executor" not in data:
            logger.error("No executor selected")
            # await self.websocket.send(
            #     json.dumps(
            #         {
            #             "action": "RUN_STATUS",
            #             "execution_ids": self.execution_ids,
            #             "running": False,
            #             "message": "No executor selected to " f"{self.agent_name} agent",
            #         }
            #     )
            # )
            return
        if data["executor"] not in self.dispatcher.executors:
            logger.error("The selected executor not exists")
            await self.websocket.send(
                json.dumps(
                    {
                        "action": "RUN_STATUS",
                        "execution_ids": self.dispatcher.execution_ids,
                        "executor_name": data["executor"],
                        "running": False,
                        "message": "The selected executor "
                        f"{data['executor']} not exists in "
                        f"{self.dispatcher.agent_name} agent",
                    }
                )
            )
            return

        executor = self.dispatcher.executors[data["executor"]]

        params = list(executor.params.keys()).copy()
        passed_params = data["args"] if "args" in data else {}

        all_accepted = all(
            [
                any([param in passed_param for param in params])  # Control any available param  # was passed
                for passed_param in passed_params
                # For all passed params
            ]
        )
        if not all_accepted:
            logger.error(f"Unexpected argument passed to {executor.name}" f" executor")
            await self.dispatcher.websocket.send(
                json.dumps(
                    {
                        "action": "RUN_STATUS",
                        "execution_ids": self.dispatcher.execution_ids,
                        "executor_name": executor.name,
                        "running": False,
                        "message": "Unexpected argument(s) passed to "
                        f"{executor.name} executor from "
                        f"{self.dispatcher.agent_name} agent",
                    }
                )
            )
        mandatory_full = all(
            [
                not executor.params[param]["mandatory"]  # All params is not mandatory
                or any([param in passed_param for passed_param in passed_params])  # Or was passed
                for param in params
            ]
        )
        if not mandatory_full:
            logger.error(f"Mandatory argument not passed " f"to {executor.name} executor")
            await self.dispatcher.websocket.send(
                json.dumps(
                    {
                        "action": "RUN_STATUS",
                        "execution_ids": self.dispatcher.execution_ids,
                        "executor_name": executor.name,
                        "running": False,
                        "message": f"Mandatory argument(s) "
                        f"not passed to "
                        f"{executor.name} executor from "
                        f"{self.dispatcher.agent_name} agent",
                    }
                )
            )

        # VALIDATE
        errors = dict()
        for param in passed_params:
            param_errors = type_validate(executor.params[param]["type"], passed_params[param])
            if param_errors:
                errors[param] = ",".join(param_errors["data"])
                logger.error(
                    f'Validation error on parameter "{param}", of type'
                    f' "{executor.params[param]["type"]}":'
                    f" {errors[param]}"
                )

        if errors:
            error_msg = "Validation error:"
            for param in errors:
                error_msg += f"\n{param} = {passed_params[param]} " f"did not validate correctly: {errors[param]}"
            logger.error(error_msg)
            await self.dispatcher.websocket.send(
                json.dumps(
                    {
                        "action": "RUN_STATUS",
                        "execution_ids": self.dispatcher.execution_ids,
                        "executor_name": executor.name,
                        "running": False,
                        "message": error_msg,
                    }
                )
            )
            return

        if mandatory_full and all_accepted:
            if not await executor.check_cmds():
                # The function logs why cant run
                return
            logger.info(f"Running {executor.name} executor")

            plugin_args = data.get("plugin_args", {})
            process = await self.dispatcher.create_process(executor, passed_params, plugin_args)
            start_date = datetime.utcnow()
            command_json = {
                "tool": self.dispatcher.agent_name,
                "command": executor.name,
                "user": "",
                "hostname": "",
                "params": ", ".join([f"{key}={value}" for (key, value) in passed_params.items()]),
                "import_source": "agent",
                "start_date": start_date.isoformat(),
            }
            tasks = [
                StdOutLineProcessor(
                    process,
                    self.dispatcher.session,
                    self.dispatcher.execution_ids,
                    workspaces_selected,
                    self.dispatcher.api_ssl_enabled,
                    self.dispatcher.api_kwargs,
                    command_json,
                    start_date,
                ).process_f(),
                StdErrLineProcessor(process).process_f(),
            ]
            await asyncio.gather(*tasks)
            await process.communicate()
            assert process.returncode is not None
            if process.returncode == 0:
                logger.info(f"Executor {executor.name} finished successfully")
                status_message = json.dumps(
                    {
                        "action": "RUN_STATUS",
                        "execution_ids": self.dispatcher.execution_ids,
                        "executor_name": executor.name,
                        "successful": True,
                        "message": f"Executor "
                        f"{executor.name} from "
                        f"{self.dispatcher.agent_name} finished "
                        "successfully",
                    }
                )
                await self.emit("run_status", status_message)
                return
            else:
                logger.warning(f"Executor {executor.name} finished with exit code" f" {process.returncode}")
