#!/usr/bin/env python
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

"""Tests for `faraday_agent_dispatcher` package."""

import os
from copy import deepcopy
from pathlib import Path
import random

import pytest
import sys

from itsdangerous import TimestampSigner

from faraday_agent_dispatcher.dispatcher import Dispatcher
from faraday_agent_dispatcher.config import (
    instance as configuration,
    Sections,
)
from tests.unittests.config.agent_dispatcher import (
    generate_basic_built_config,
    generate_executor_options,
    generate_register_options,
)
from tests.utils.testing_faraday_server import (  # noqa: F401
    FaradayTestConfig,
    test_config,
    tmp_custom_config,
    tmp_default_config,
    test_logger_handler,
    test_logger_folder,
)
from faraday_agent_dispatcher.config import reset_config, save_config


@pytest.mark.parametrize(
    "config_changes_dict",
    generate_basic_built_config(),
    ids=lambda elem: elem["id_str"],
)
def test_basic_built(tmp_custom_config, config_changes_dict):  # noqa F811
    reset_config(tmp_custom_config.config_file_path)
    config_path = tmp_custom_config.config_file_path.with_suffix(".yaml")
    for section in config_changes_dict["replace"]:
        for option in config_changes_dict["replace"][section]:
            if section == "executor":
                if "ex1" not in configuration[Sections.AGENT][Sections.EXECUTORS]:
                    configuration[Sections.AGENT][Sections.EXECUTORS]["ex1"] = {}
                configuration[Sections.AGENT][Sections.EXECUTORS]["ex1"][option] = config_changes_dict["replace"][
                    section
                ][option]
                continue
            elif section not in configuration:
                configuration[section] = {}
            configuration[section][option] = config_changes_dict["replace"][section][option]
    for section in config_changes_dict["remove"]:
        if "section" in config_changes_dict["remove"][section]:
            if section in configuration:
                configuration.pop(section)
        else:
            for option in config_changes_dict["remove"][section]:
                if (
                    section == "executor"
                    and "ex1" in configuration[Sections.AGENT][Sections.EXECUTORS]
                    and option in configuration[Sections.AGENT][Sections.EXECUTORS]["ex1"]
                ):
                    configuration[Sections.AGENT][Sections.EXECUTORS]["ex1"].pop(option)
                elif section in configuration and option in configuration[section]:
                    configuration[section].pop(option)
    save_config(config_path)
    if "expected_exception" in config_changes_dict:
        with pytest.raises(config_changes_dict["expected_exception"]):
            Dispatcher(None, config_path)
    else:
        Dispatcher(None, config_path)


@pytest.mark.parametrize("register_options", generate_register_options(), ids=lambda elem: elem["id_str"])
@pytest.mark.asyncio
async def test_start_and_register(
    register_options,
    test_config: FaradayTestConfig,  # noqa F811
    tmp_default_config,  # noqa F811
    test_logger_handler,  # noqa F811
):
    os.environ["DISPATCHER_TEST"] = "True"
    if "use_ssl" in register_options:
        if (register_options["use_ssl"] and not test_config.is_ssl) or (
            not register_options["use_ssl"] and test_config.is_ssl
        ):
            pytest.skip(
                f"This test should be skipped: server_ssl:{test_config.is_ssl}"
                f" and config_use_ssl:f {register_options['use_ssl']}"
            )

    client = test_config.client

    if test_config.base_route:
        configuration[Sections.SERVER]["base_route"] = test_config.base_route

    # Config
    configuration[Sections.SERVER]["ssl"] = str(test_config.is_ssl)
    if test_config.is_ssl:
        configuration[Sections.SERVER]["ssl_cert"] = str(test_config.ssl_cert_path / "ok.crt")
        configuration[Sections.SERVER]["host"] = "localhost"
    else:
        configuration[Sections.SERVER]["host"] = client.host

    configuration[Sections.SERVER]["api_port"] = str(client.port)
    configuration[Sections.SERVER]["workspaces"] = test_config.workspaces
    if "ex1" not in configuration[Sections.AGENT][Sections.EXECUTORS]:
        configuration[Sections.AGENT][Sections.EXECUTORS]["ex1"] = {
            "max_size": "65536",
            "params": {},
            "varenvs": {},
        }
    configuration[Sections.AGENT][Sections.EXECUTORS]["ex1"]["cmd"] = "exit 1"

    for section in register_options["replace_data"]:
        for option in register_options["replace_data"][section]:
            if section not in configuration:
                configuration[section] = {}
            configuration[section][option] = register_options["replace_data"][section][option]

    tmp_default_config.save()

    # Init and register it
    dispatcher = Dispatcher(client.session, tmp_default_config.config_file_path)

    if "expected_exception" not in register_options:
        await dispatcher.register(test_config.registration_token)
        # Control tokens
        assert dispatcher.agent_token == test_config.agent_token

        signer = TimestampSigner(test_config.app_config["SECRET_KEY"], salt="websocket_agent")
        agent_id = int(signer.unsign(dispatcher.websocket_token).decode("utf-8"))
        assert test_config.agent_id == agent_id
    else:
        if "bad_registration_token" in register_options:
            if register_options["bad_registration_token"] is None:
                token = None
            elif register_options["bad_registration_token"] == "incorrect":
                token = f"{((int(test_config.registration_token) + 1) % 1000000):06}"
            elif register_options["bad_registration_token"] == "bad format":
                token = "qewqwe"
            else:  # == "bad"
                token = test_config.registration_token[0:3]
        else:
            token = test_config.registration_token
        with pytest.raises(register_options["expected_exception"]):
            await dispatcher.register(token)

    history = test_logger_handler.history

    logs_ok, failed_logs = await check_logs(history, register_options["logs"])

    if "optional_logs" in register_options and not logs_ok:
        logs_ok, new_failed_logs = await check_logs(history, register_options["optional_logs"])
        failed_logs = {"logs": failed_logs, "optional_logs": new_failed_logs}

    assert logs_ok, failed_logs


async def check_logs(history, logs):
    logs_ok = True
    failed_logs = []
    for log in logs:
        min_count = 1 if "min_count" not in log else log["min_count"]
        max_count = sys.maxsize if "max_count" not in log else log["max_count"]
        log_ok = (
            max_count
            >= len(
                list(
                    filter(
                        lambda x: (log["msg"] in x.message) and (x.levelname == log["levelname"]),
                        history,
                    )
                )
            )
            >= min_count
        )

        if not log_ok:
            failed_logs.append(log)

        logs_ok &= log_ok
    return logs_ok, failed_logs


# TODO: FROM HERE NOT CHECKED YET
@pytest.mark.parametrize("executor_options", generate_executor_options(), ids=lambda elem: elem["id_str"])
@pytest.mark.asyncio
async def test_run_once(
    test_config: FaradayTestConfig,  # noqa F811
    tmp_default_config,  # noqa F811
    test_logger_handler,  # noqa F811
    test_logger_folder,  # noqa F811
    executor_options,
):
    # Config
    if "workspaces" in executor_options:
        test_config.workspaces = executor_options["workspaces"]
    workspaces = test_config.workspaces

    if test_config.base_route:
        configuration[Sections.SERVER]["base_route"] = test_config.base_route

    configuration[Sections.SERVER]["api_port"] = str(test_config.client.port)
    configuration[Sections.SERVER]["websocket_port"] = str(test_config.client.port)
    configuration[Sections.SERVER]["workspaces"] = workspaces
    if Sections.TOKENS not in configuration:
        configuration[Sections.TOKENS] = {}
    configuration[Sections.TOKENS]["agent"] = test_config.agent_token
    configuration[Sections.SERVER]["ssl"] = str(test_config.is_ssl)
    if test_config.is_ssl:
        configuration[Sections.SERVER]["ssl_cert"] = str(test_config.ssl_cert_path / "ok.crt")
        configuration[Sections.SERVER]["host"] = "localhost"
    else:
        configuration[Sections.SERVER]["host"] = test_config.client.host
    path_to_basic_executor = Path(__file__).parent.parent / "data" / "basic_executor.py"
    executor_names = ["ex1"] + ([] if "extra" not in executor_options else executor_options["extra"])

    test_config.executors = []
    for ex in executor_names:
        from faraday_agent_parameters_types.data_types import DATA_TYPE

        false_params = {
            "count": DATA_TYPE["integer"],
            "spare": DATA_TYPE["boolean"],
            "spaced_before": DATA_TYPE["boolean"],
            "spaced_middle": DATA_TYPE["boolean"],
            "err": DATA_TYPE["boolean"],
            "fails": DATA_TYPE["boolean"],
        }
        configuration[Sections.AGENT][Sections.EXECUTORS][ex] = {
            "cmd": f"python {path_to_basic_executor}",
            "params": {},
            "varenvs": {},
        }
        for param in false_params:
            configuration[Sections.AGENT][Sections.EXECUTORS][ex][Sections.EXECUTOR_PARAMS][param] = {
                "mandatory": False,
                "type": false_params[param].type.class_name,
                "base": false_params[param].type.base,
            }

        configuration[Sections.AGENT][Sections.EXECUTORS][ex][Sections.EXECUTOR_PARAMS]["out"] = {
            "mandatory": True,
            "type": DATA_TYPE["string"].type.class_name,
            "base": DATA_TYPE["string"].type.base,
        }

        if "varenvs" in executor_options:
            for varenv in executor_options["varenvs"]:
                configuration[Sections.AGENT][Sections.EXECUTORS][ex][Sections.EXECUTOR_VARENVS][
                    varenv
                ] = executor_options["varenvs"][varenv]

        max_size = str(64 * 1024) if "max_size" not in executor_options else executor_options["max_size"]
        configuration[Sections.AGENT][Sections.EXECUTORS][ex]["max_size"] = max_size
        executor_metadata = {
            "executor_name": ex,
            "args": {
                param: value
                for param, value in configuration[Sections.AGENT][Sections.EXECUTORS][ex][
                    Sections.EXECUTOR_PARAMS
                ].items()
            },
        }
        executor_metadata["args"]["out"] = {"mandatory": True, "type": "string", "base": "string"}
        test_config.executors.append(executor_metadata)

    tmp_default_config.save()

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session, tmp_default_config.config_file_path)
    selected_workspace = random.choice(workspaces)
    print(selected_workspace)

    ws_responses = deepcopy(executor_options["ws_responses"])
    run_data = deepcopy(executor_options["data"])
    if "workspace" in run_data:
        run_data["workspace"] = run_data["workspace"].format(selected_workspace)
    test_config.ws_data = {"run_data": run_data, "ws_responses": ws_responses}

    await dispatcher.register(test_config.registration_token)
    await dispatcher.connect()

    history = test_logger_handler.history
    assert len(test_config.ws_data["ws_responses"]) == 0
    for log in executor_options["logs"]:
        min_count = 1 if "min_count" not in log else log["min_count"]
        max_count = sys.maxsize if "max_count" not in log else log["max_count"]
        assert (
            max_count
            >= len(
                list(
                    filter(
                        lambda x: x.levelname == log["levelname"] and log["msg"] in x.message,
                        history,
                    )
                )
            )
            >= min_count
        ), log["msg"]
