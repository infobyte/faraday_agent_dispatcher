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
    get_merge_executors
)
from tests.utils.testing_faraday_server import (  # noqa: F401
    FaradayTestConfig,
    test_config,
    tmp_custom_config,
    tmp_default_config,
    test_logger_handler,
    test_logger_folder,
)
from tests.utils.text_utils import fuzzy_string


@pytest.mark.parametrize('config_changes_dict',
                         generate_basic_built_config(),
                         ids=lambda elem: elem["id_str"])
def test_basic_built(tmp_custom_config, config_changes_dict):  # noqa F811
    for section in config_changes_dict["replace"]:
        for option in config_changes_dict["replace"][section]:
            if section not in configuration:
                configuration.add_section(section)
            configuration.set(
                section,
                option,
                config_changes_dict["replace"][section][option]
            )
    for section in config_changes_dict["remove"]:
        if "section" in config_changes_dict["remove"][section]:
            configuration.remove_section(section)
        else:
            for option in config_changes_dict["remove"][section]:
                configuration.remove_option(section, option)
    tmp_custom_config.save()
    if "expected_exception" in config_changes_dict:
        if "duplicate_exception" in config_changes_dict \
                and config_changes_dict["duplicate_exception"]:
            with open(tmp_custom_config.config_file_path, "r") as file:
                content = file.read()
            with open(tmp_custom_config.config_file_path, "w") as file:
                file.write(content)
                file.write(content)
        with pytest.raises(config_changes_dict["expected_exception"]):
            Dispatcher(None, tmp_custom_config.config_file_path)
    else:
        Dispatcher(None, tmp_custom_config.config_file_path)


@pytest.mark.parametrize('register_options',
                         generate_register_options(),
                         ids=lambda elem: elem["id_str"])
@pytest.mark.asyncio
async def test_start_and_register(register_options,
                                  test_config: FaradayTestConfig,  # noqa F811
                                  tmp_default_config,  # noqa F811
                                  test_logger_handler):  # noqa F811
    os.environ['DISPATCHER_TEST'] = "True"
    if "use_ssl" in register_options:
        if (register_options["use_ssl"] and not test_config.is_ssl) or \
                (not register_options["use_ssl"] and test_config.is_ssl):
            pytest.skip(
                f"This test should be skipped: server_ssl:{test_config.is_ssl}"
                f" and config_use_ssl:f {register_options['use_ssl']}"
            )

    client = test_config.client

    if test_config.base_route:
        configuration.set(Sections.SERVER,
                          "base_route",
                          test_config.base_route)

    # Config
    configuration.set(Sections.SERVER, "ssl", str(test_config.is_ssl))
    if test_config.is_ssl:
        configuration.set(Sections.SERVER,
                          "ssl_cert",
                          str(test_config.ssl_cert_path / "ok.crt")
                          )
        configuration.set(Sections.SERVER, "host", "localhost")
    else:
        configuration.set(Sections.SERVER, "host", client.host)

    configuration.set(Sections.SERVER, "api_port", str(client.port))
    configuration.set(Sections.SERVER, "workspaces",
                      test_config.workspaces_str()
                      )
    configuration.set(
        Sections.TOKENS,
        "registration",
        test_config.registration_token
    )
    configuration.set(Sections.EXECUTOR_DATA.format("ex1"), "cmd", 'exit 1')

    for section in register_options["replace_data"]:
        for option in register_options["replace_data"][section]:
            if section not in configuration:
                configuration.add_section(section)
            configuration.set(
                section,
                option,
                register_options["replace_data"][section][option]
            )

    tmp_default_config.save()

    # Init and register it
    dispatcher = Dispatcher(
        client.session,
        tmp_default_config.config_file_path
    )

    if "expected_exception" not in register_options:
        await dispatcher.register()
        # Control tokens
        assert dispatcher.agent_token == test_config.agent_token

        signer = TimestampSigner(
            test_config.app_config['SECRET_KEY'],
            salt="websocket_agent"
        )
        agent_id = int(
            signer.unsign(dispatcher.websocket_token).decode('utf-8')
        )
        assert test_config.agent_id == agent_id
    else:
        with pytest.raises(register_options["expected_exception"]):
            await dispatcher.register()

    history = test_logger_handler.history

    logs_ok, failed_logs = await check_logs(history, register_options["logs"])

    if "optional_logs" in register_options and not logs_ok:
        logs_ok, new_failed_logs = await check_logs(
            history,
            register_options["optional_logs"]
        )
        failed_logs = {"logs": failed_logs, "optional_logs": new_failed_logs}

    assert logs_ok, failed_logs


async def check_logs(history, logs):
    logs_ok = True
    failed_logs = []
    for log in logs:
        min_count = 1 if "min_count" not in log else log["min_count"]
        max_count = sys.maxsize if "max_count" not in log else log["max_count"]
        log_ok = \
            max_count >= \
            len(
                list(
                    filter(
                        lambda x: (log["msg"] in x.message) and
                                  (x.levelname == log["levelname"]),
                        history
                    )
                )
            ) >= min_count

        if not log_ok:
            failed_logs.append(log)

        logs_ok &= log_ok
    return logs_ok, failed_logs


# TODO: FROM HERE NOT CHECKED YET
@pytest.mark.parametrize('executor_options',
                         generate_executor_options(),
                         ids=lambda elem: elem["id_str"])
@pytest.mark.asyncio
async def test_run_once(test_config: FaradayTestConfig, # noqa F811
                        tmp_default_config, # noqa F811
                        test_logger_handler, # noqa F811
                        test_logger_folder, # noqa F811
                        executor_options):
    # Config
    if "workspaces" in executor_options:
        test_config.workspaces = executor_options["workspaces"].split(",")
    workspaces = test_config.workspaces
    workspaces_str = test_config.workspaces_str()

    if test_config.base_route:
        configuration.set(Sections.SERVER,
                          "base_route",
                          test_config.base_route)

    configuration.set(Sections.SERVER, "api_port",
                      str(test_config.client.port))
    configuration.set(Sections.SERVER, "websocket_port",
                      str(test_config.client.port))
    configuration.set(Sections.SERVER, "workspaces", workspaces_str)
    configuration.set(Sections.TOKENS, "registration",
                      test_config.registration_token)
    configuration.set(Sections.TOKENS, "agent", test_config.agent_token)
    configuration.set(Sections.SERVER, "ssl", str(test_config.is_ssl))
    if test_config.is_ssl:
        configuration.set(Sections.SERVER,
                          "ssl_cert",
                          str(test_config.ssl_cert_path / "ok.crt")
                          )
        configuration.set(Sections.SERVER, "host", "localhost")
    else:
        configuration.set(Sections.SERVER, "host", test_config.client.host)
    path_to_basic_executor = (
            Path(__file__).parent.parent /
            'data' / 'basic_executor.py'
    )
    executor_names = ["ex1"] + (
        [] if "extra" not in executor_options else executor_options["extra"])
    configuration.set(Sections.AGENT, "executors", ",".join(executor_names))
    test_config.executors = []
    for executor_name in executor_names:
        executor_section = Sections.EXECUTOR_DATA.format(executor_name)
        params_section = Sections.EXECUTOR_PARAMS.format(executor_name)
        varenvs_section = Sections.EXECUTOR_VARENVS.format(executor_name)
        for section in [executor_section, params_section, varenvs_section]:
            if section not in configuration:
                configuration.add_section(section)

        configuration.set(executor_section, "cmd",
                          "python {}".format(path_to_basic_executor))
        false_params = ["count", "spare", "spaced_before", "spaced_middle",
                        "err", "fails"]
        [configuration.set(params_section, param, "False") for param in
         false_params]
        configuration.set(params_section, "out", "True")
        if "varenvs" in executor_options:
            for varenv in executor_options["varenvs"]:
                configuration.set(varenvs_section, varenv,
                                  executor_options["varenvs"][varenv])

        max_size = str(64 * 1024) if "max_size" not in executor_options else \
            executor_options["max_size"]
        configuration.set(executor_section, "max_size", max_size)
        executor_metadata = {
                "executor_name": executor_name,
                "args": {
                    param: False for param in false_params
                }
            }
        executor_metadata["args"]["out"] = True
        test_config.executors.append(
            executor_metadata
        )

    tmp_default_config.save()

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session,
                            tmp_default_config.config_file_path)
    selected_workspace = random.choice(workspaces)
    print(selected_workspace)

    ws_responses = deepcopy(executor_options["ws_responses"])
    run_data = deepcopy(executor_options["data"])
    if 'workspace' in run_data:
        run_data['workspace'] = \
            run_data['workspace'].format(selected_workspace)
    test_config.ws_data = {
        "run_data": run_data,
        "ws_responses": ws_responses
    }

    await dispatcher.register()
    await dispatcher.connect()

    history = test_logger_handler.history
    assert len(test_config.ws_data["ws_responses"]) == 0
    for log in executor_options["logs"]:
        min_count = 1 if "min_count" not in log else log["min_count"]
        max_count = sys.maxsize if "max_count" not in log else log["max_count"]
        assert max_count >= \
               len(
                   list(
                       filter(
                           lambda x: x.levelname == log["levelname"] and log[
                               "msg"] in x.message, history))) >= \
               min_count, log["msg"]


# This test merging "workspace" & "workspaces" in config to "workspaces"
@pytest.mark.asyncio
async def test_merge_config(test_config: FaradayTestConfig, # noqa F811
                            tmp_default_config, # noqa F811
                            test_logger_handler, # noqa F811
                            test_logger_folder): # noqa F811
    configuration.set(Sections.SERVER, "api_port",
                      str(test_config.client.port))
    configuration.set(Sections.SERVER, "websocket_port",
                      str(test_config.client.port))
    if test_config.base_route:
        configuration.set(Sections.SERVER,
                          "base_route",
                          test_config.base_route)
    configuration.set(Sections.SERVER, "ssl", str(test_config.is_ssl))
    if test_config.is_ssl:
        configuration.set(Sections.SERVER,
                          "ssl_cert",
                          str(test_config.ssl_cert_path / "ok.crt")
                          )
        configuration.set(Sections.SERVER, "host", "localhost")
    else:
        configuration.set(Sections.SERVER, "host", test_config.client.host)
    configuration.set(Sections.SERVER,
                      "workspaces",
                      test_config.workspaces_str()
                      )
    random_workspace_name = fuzzy_string(15)
    configuration.set(Sections.SERVER,
                      "workspace",
                      random_workspace_name
                      )

    test_config.workspaces = [random_workspace_name] + test_config.workspaces
    configuration.set(Sections.TOKENS, "registration",
                      test_config.registration_token)
    configuration.set(Sections.TOKENS, "agent", test_config.agent_token)
    path_to_basic_executor = (
            Path(__file__).parent.parent /
            'data' / 'basic_executor.py'
    )
    configuration.set(Sections.AGENT, "executors", "ex1,ex2,ex3,ex4")

    for executor_name in ["ex1", "ex3", "ex4"]:
        executor_section = Sections.EXECUTOR_DATA.format(executor_name)
        params_section = Sections.EXECUTOR_PARAMS.format(executor_name)
        for section in [executor_section, params_section]:
            if section not in configuration:
                configuration.add_section(section)
        configuration.set(executor_section, "cmd",
                          "python {}".format(path_to_basic_executor))

    configuration.set(Sections.EXECUTOR_PARAMS.format("ex1"), "param1", "True")
    configuration.set(Sections.EXECUTOR_PARAMS.format("ex1"), "param2",
                      "False")
    configuration.set(Sections.EXECUTOR_PARAMS.format("ex3"), "param3",
                      "False")
    configuration.set(Sections.EXECUTOR_PARAMS.format("ex3"), "param4",
                      "False")
    tmp_default_config.save()
    dispatcher = Dispatcher(test_config.client.session,
                            tmp_default_config.config_file_path)

    test_config.ws_data["run_data"] = {"agent_id": 1}
    test_config.ws_data["ws_responses"] = [{
        "error": "'action' key is mandatory in this websocket connection"
    }]
    test_config.executors = get_merge_executors()

    await dispatcher.register()
    await dispatcher.connect()

    assert len(test_config.ws_data["ws_responses"]) == 0
