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

"""Tests for `faraday_dummy_agent` package."""

import json
import os
import pytest
import sys

from pathlib import Path
from itsdangerous import TimestampSigner

from faraday_agent_dispatcher.dispatcher import Dispatcher
from faraday_agent_dispatcher.config import (
    reset_config,
    save_config,
    instance as configuration,
    Sections
)

from tests.utils.text_utils import fuzzy_string
from tests.utils.testing_faraday_server import FaradayTestConfig, test_config, tmp_custom_config, tmp_default_config, \
    test_logger_handler, test_logger_folder


@pytest.mark.parametrize('config_changes_dict',
                         [{"remove": {Sections.SERVER: ["host"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {Sections.SERVER: ["api_port"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.SERVER: {"api_port": "Not a port number"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.SERVER: {"api_port": "6000"}}},  # None error as parse int
                          {"remove": {Sections.SERVER: ["websocket_port"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.SERVER: {"websocket_port": "Not a port number"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.SERVER: {"websocket_port": "9001"}}},  # None error as parse int
                          {"remove": {Sections.SERVER: ["workspace"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {Sections.TOKENS: ["registration"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.TOKENS: {"registration": "invalid_token"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.TOKENS: {"registration": "   46aasdje446aasdje446aa"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.TOKENS: {"registration": "QWE46aasdje446aasdje446aa"}}},
                          {"remove": {},
                           "replace": {Sections.TOKENS: {"agent": "invalid_token"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.TOKENS: {
                               "agent": "   46aasdje446aasdje446aa46aasdje446aasdje446aa46aasdje446aasdje"
                           }},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {Sections.TOKENS: {
                               "agent": "QWE46aasdje446aasdje446aaQWE46aasdje446aasdje446aaQWE46aasdje446"}}},
                          {"remove": {Sections.EXECUTOR: ["cmd"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {Sections.EXECUTOR: ["agent_name"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {}}
                          ])
def test_basic_built(tmp_custom_config, config_changes_dict):
    for section in config_changes_dict["replace"]:
        for option in config_changes_dict["replace"][section]:
            configuration.set(section, option, config_changes_dict["replace"][section][option])
    for section in config_changes_dict["remove"]:
        for option in config_changes_dict["remove"][section]:
            configuration.remove_option(section, option)
    tmp_custom_config.save()
    if "expected_exception" in config_changes_dict:
        with pytest.raises(config_changes_dict["expected_exception"]):
            Dispatcher(None, tmp_custom_config.config_file_path)
    else:
        Dispatcher(None, tmp_custom_config.config_file_path)


async def test_start_and_register(test_config: FaradayTestConfig, tmp_default_config):
    # Config
    configuration.set(Sections.SERVER, "api_port", str(test_config.client.port))
    configuration.set(Sections.SERVER, "host", test_config.client.host)
    configuration.set(Sections.SERVER, "workspace", test_config.workspace)
    configuration.set(Sections.TOKENS, "registration", test_config.registration_token)
    configuration.set(Sections.EXECUTOR, "cmd", 'exit 1')
    tmp_default_config.save()

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session, tmp_default_config.config_file_path)
    await dispatcher.register()

    # Control tokens
    assert dispatcher.agent_token == test_config.agent_token

    signer = TimestampSigner(test_config.app_config['SECRET_KEY'], salt="websocket_agent")
    agent_id = int(signer.unsign(dispatcher.websocket_token).decode('utf-8'))
    assert test_config.agent_id == agent_id


async def test_start_with_bad_config(test_config: FaradayTestConfig, tmp_default_config):
    # Config
    configuration.set(Sections.SERVER, "api_port", str(test_config.client.port))
    configuration.set(Sections.SERVER, "host", test_config.client.host)
    configuration.set(Sections.SERVER, "workspace", test_config.workspace)
    configuration.set(Sections.TOKENS, "registration", "NotOk" * 5)
    configuration.set(Sections.EXECUTOR, "cmd", 'exit 1')
    tmp_default_config.save()

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session, tmp_default_config.config_file_path)

    with pytest.raises(AssertionError):
        await dispatcher.register()


@pytest.mark.parametrize('executor_options',
                         [
                             {  # 0
                                 "data": {"agent_id": 1},
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Data not contains action to do"},
                                 ],
                                 "ws_responses": [
                                     {"error": "'action' key is mandatory in this websocket connection"}
                                 ]
                             },
                             {  # 1
                                 "data": {"action": "CUT", "agent_id": 1},
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Unrecognized action"},
                                 ],
                                 "ws_responses": [
                                     {"CUT_RESPONSE": "Error: Unrecognized action"}
                                 ]
                             },
                             {  # 2
                                 "data": {"action": "RUN", "agent_id": 1, "args": {"out": "json"}},
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 2
                                 "data": {"action": "RUN", "agent_id": 1, "executor": "ex1", "args": {"out": "json"}},
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 3
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1",
                                     "args": {"out": "json", "count": "5"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR", "msg": "JSON Parsing error: Extra data"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 4
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1",
                                     "args": {"out": "json", "count": "5", "spare": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create", "min_count": 5},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 5
                                 "data": {
                                     "action": "RUN",
                                     "agent_id": 1,
                                     "executor": "ex1",
                                     "args": {"out": "json", "spaced_before": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 6
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1",
                                     "args": {"out": "json", "spaced_middle": "T", "count": "5", "spare": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create", "max_count": 1},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 7
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1", "args": {"out": "bad_json"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR",
                                      "msg": "Invalid data supplied by the executor to the bulk create endpoint. "
                                             "Server responded: "},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 8
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1", "args": {"out": "str"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR", "msg": "JSON Parsing error: Expecting value"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 9
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1",
                                     "args": {"out": "none", "err": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "DEBUG", "msg": "Print by stderr"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 10
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1",
                                     "args": {"out": "none", "fails": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "WARNING", "msg": "Executor finished with exit code 1"},
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": False,
                                         "message": "Executor failed"
                                     }
                                 ]
                             },
                             {  # 11
                                 "data": {
                                     "action": "RUN",
                                     "agent_id": 1,
                                     "executor": "ex1",
                                     "args": {"out": "none", "err": "T", "fails": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "DEBUG", "msg": "Print by stderr"},
                                     {"levelname": "WARNING", "msg": "Executor finished with exit code 1"},
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": False,
                                         "message": "Executor failed"
                                     }
                                 ]
                             },
                             {  # 12
                                 "data": {
                                     "action": "RUN",
                                     "agent_id": 1,
                                     "executor": "ex1",
                                     "args": {"out": "json"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "varenvs": {"DO_NOTHING": "True"},
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 13
                                 "data": {
                                     "action": "RUN",
                                     "agent_id": 1,
                                     "executor": "ex1",
                                     "args": {"err": "T", "fails": "T"},
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "ERROR", "msg": "Mandatory argument not passed"},
                                 ],
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": False,
                                         "message": "Mandatory argument(s) not passed to unnamed_agent agent"
                                     }
                                 ]
                             },
                             {  # 14
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1",
                                     "args": {"out": "json", "WTF": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "INFO", "msg": "Executor finished successfully", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "ERROR", "msg": "Unexpected argument passed"},
                                 ],
                                 "ws_responses": [
                                     {"action": "RUN_STATUS",
                                      "running": False,
                                      "message": "Unexpected argument(s) passed to unnamed_agent agent"}
                                 ]
                             },
                             {  # 15
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1", "args": {"out": "json"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR",
                                      "msg": "Invalid data supplied by the executor to the bulk create endpoint. "
                                             "Server responded: "},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "workspace": "error500",
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 16
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "ex1", "args": {"out": "json"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR",
                                      "msg": "Invalid data supplied by the executor to the bulk create endpoint. "
                                             "Server responded: "},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "workspace": "error429",
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 17
                                 "data": {"action": "RUN", "agent_id": 1, "executor": "ex1", "args": {"out": "json"}},
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR", "msg": "ValueError raised processing stdout, try with "
                                                                   "bigger limiting size in config"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "max_size": "1",
                                 "ws_responses": [
                                     {
                                         "action": "RUN_STATUS",
                                         "running": True,
                                         "message": "Running executor from unnamed_agent agent"
                                     }, {
                                         "action": "RUN_STATUS",
                                         "successful": True,
                                         "message": "Executor finished successfully"
                                     }
                                 ]
                             },
                             {  # 18
                                 "data": {
                                     "action": "RUN", "agent_id": 1,
                                     "args": {"out": "json", "WTF": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "INFO", "msg": "Executor finished successfully", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "ERROR", "msg": "Unexpected argument passed"},
                                 ],
                                 "ws_responses": [
                                     {"action": "RUN_STATUS",
                                      "running": False,
                                      "message": "No executor selected"}
                                 ]
                             },
                             {  # 19
                                 "data": {
                                     "action": "RUN", "agent_id": 1, "executor": "NOT_4N_CORRECT_EXECUTOR",
                                     "args": {"out": "json", "WTF": "T"}
                                 },
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "INFO", "msg": "Executor finished successfully", "max_count": 0,
                                      "min_count": 0},
                                     {"levelname": "ERROR", "msg": "Unexpected argument passed"},
                                 ],
                                 "ws_responses": [
                                     {"action": "RUN_STATUS",
                                      "running": False,
                                      "message": "The selected executor not exists"}
                                 ]
                             },
                         ])
async def test_run_once(test_config: FaradayTestConfig, tmp_default_config, test_logger_handler,
                        test_logger_folder, executor_options):
    # Config
    workspace = test_config.workspace if "workspace" not in executor_options else executor_options["workspace"]
    configuration.set(Sections.SERVER, "api_port", str(test_config.client.port))
    configuration.set(Sections.SERVER, "host", test_config.client.host)
    configuration.set(Sections.SERVER, "workspace", workspace)
    configuration.set(Sections.TOKENS, "registration", test_config.registration_token)
    configuration.set(Sections.TOKENS, "agent", test_config.agent_token)
    path_to_basic_executor = (
            Path(__file__).parent.parent /
            'data' / 'basic_executor.py'
    )
    configuration.set(Sections.EXECUTOR, "cmd", "python {}".format(path_to_basic_executor))
    configuration.set(Sections.PARAMS, "out", "True")
    [configuration.set(Sections.PARAMS, param, "False") for param in [
            "count", "spare", "spaced_before", "spaced_middle", "err", "fails"]]
    if "varenvs" in executor_options:
        for varenv in executor_options["varenvs"]:
            configuration.set(Sections.VARENVS, varenv, executor_options["varenvs"][varenv])

    max_size = str(64 * 1024) if "max_size" not in executor_options else executor_options["max_size"]
    configuration.set(Sections.EXECUTOR, "max_size", max_size)

    tmp_default_config.save()

    async def ws_messages_checker(msg):
        msg_ = json.loads(msg)
        assert msg_ in executor_options["ws_responses"]
        executor_options["ws_responses"].remove(msg_)

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session, tmp_default_config.config_file_path)
    await dispatcher.run_once(json.dumps(executor_options["data"]), ws_messages_checker)
    history = test_logger_handler.history
    assert len(executor_options["ws_responses"]) == 0
    for l in executor_options["logs"]:
        min_count = 1 if "min_count" not in l else l["min_count"]
        max_count = sys.maxsize if "max_count" not in l else l["max_count"]
        assert max_count >= \
            len(list(filter(lambda x: x.levelname == l["levelname"] and l["msg"] in x.message, history))) >= \
            min_count, l["msg"]


async def test_connect():
    pass  # TODO
