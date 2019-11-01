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
    SERVER_SECTION,
    TOKENS_SECTION,
    EXECUTOR_SECTION
)

from tests.utils.text_utils import fuzzy_string
from tests.utils.testing_faraday_server import FaradayTestConfig, test_config, tmp_custom_config, tmp_default_config, \
    test_logger_handler


@pytest.mark.parametrize('config_changes_dict',
                         [{"remove": {SERVER_SECTION: ["host"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {SERVER_SECTION: ["api_port"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {SERVER_SECTION: {"api_port": "Not a port number"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {SERVER_SECTION: {"api_port": "6000"}}},  # None error as parse int
                          {"remove": {SERVER_SECTION: ["websocket_port"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {SERVER_SECTION: {"websocket_port": "Not a port number"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {SERVER_SECTION: {"websocket_port": "9001"}}},  # None error as parse int
                          {"remove": {SERVER_SECTION: ["workspace"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {TOKENS_SECTION: ["registration"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {TOKENS_SECTION: {"registration": "invalid_token"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {TOKENS_SECTION: {"registration": "   46aasdje446aasdje446aa"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {TOKENS_SECTION: {"registration": "QWE46aasdje446aasdje446aa"}}},
                          {"remove": {},
                           "replace": {TOKENS_SECTION: {"agent": "invalid_token"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {TOKENS_SECTION: {
                               "agent": "   46aasdje446aasdje446aa46aasdje446aasdje446aa46aasdje446aasdje"
                           }},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {TOKENS_SECTION: {
                               "agent": "QWE46aasdje446aasdje446aaQWE46aasdje446aasdje446aaQWE46aasdje446"}}},
                          {"remove": {EXECUTOR_SECTION: ["cmd"]},
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": {EXECUTOR_SECTION: ["agent_name"]},
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
    configuration.set(SERVER_SECTION, "api_port", str(test_config.client.port))
    configuration.set(SERVER_SECTION, "host", test_config.client.host)
    configuration.set(SERVER_SECTION, "workspace", test_config.workspace)
    configuration.set(TOKENS_SECTION, "registration", test_config.registration_token)
    configuration.set(EXECUTOR_SECTION, "cmd", 'exit 1')
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
    configuration.set(SERVER_SECTION, "api_port", str(test_config.client.port))
    configuration.set(SERVER_SECTION, "host", test_config.client.host)
    configuration.set(SERVER_SECTION, "workspace", test_config.workspace)
    configuration.set(TOKENS_SECTION, "registration", "NotOk" * 5)
    configuration.set(EXECUTOR_SECTION, "cmd", 'exit 1')
    tmp_default_config.save()

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session, tmp_default_config.config_file_path)

    with pytest.raises(AssertionError):
        await dispatcher.register()


@pytest.mark.skip
def test_websocket(test_config: FaradayTestConfig, tmp_config):
    text = fuzzy_string(15)
    file = f"/tmp/{fuzzy_string(8)}.txt"
    configuration.set(SERVER_SECTION, "api_port", str(test_config.client.port))
    configuration.set(SERVER_SECTION, "workspace", test_config.workspace)
    configuration.set(SERVER_SECTION, "websocket_port", str(test_config.websocket_port))
    configuration.set(SERVER_SECTION, "host", test_config.client.host)
    configuration.set(EXECUTOR_SECTION, "cmd", f"echo {text} > {file}")
    tmp_config.save()

    dispatcher = Dispatcher(test_config.client.session, tmp_config.config_file_path)
    dispatcher.connect()
    test_config.run_agent_to_websocket()  ## HERE SEND BY WS THE RUN COMMAND

    with open(file, 'rt') as f:
        assert text in f.readline()


@pytest.mark.parametrize('executor_options',
                         [
                             {
                                 "data": {"agent_id": 1},
                                 "args": [],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Data not contains action to do"},
                                 ]
                             },
                             {
                                 "data": {"action": "CUT", "agent_id": 1},
                                 "args": [],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Action unrecognized"},
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out json"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out json", "count 5"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR", "msg": "JSON Parsing error: Extra data"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out json", "count 5", "spare"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create", "min_count": 5},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out json", "spaced_before"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out json", "spaced_middle", "count 5", "spare"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "INFO", "msg": "Data sent to bulk create", "max_count": 1},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out bad_json"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR",
                                      "msg": "Invalid data supplied by the executor to the bulk create endpoint. Server responded: "},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out str"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR", "msg": "JSON Parsing error: Expecting value"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["err"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "DEBUG", "msg": "Print by stderr"},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["fails"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "WARNING", "msg": "Executor finished with exit code 1"},
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["err", "fails"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "DEBUG", "msg": "Print by stderr"},
                                     {"levelname": "WARNING", "msg": "Executor finished with exit code 1"},
                                 ]
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out json"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR",
                                      "msg": "Invalid data supplied by the executor to the bulk create endpoint. Server responded: "},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "workspace": "error500"
                             },
                             {
                                 "data": {"action": "RUN", "agent_id": 1},
                                 "args": ["out json"],
                                 "logs": [
                                     {"levelname": "INFO", "msg": "Running executor"},
                                     {"levelname": "ERROR",
                                      "msg": "Invalid data supplied by the executor to the bulk create endpoint. Server responded: "},
                                     {"levelname": "INFO", "msg": "Executor finished successfully"}
                                 ],
                                 "workspace": "error429"
                             },
                         ])
async def test_run_once(test_config: FaradayTestConfig, tmp_default_config, test_logger_handler, executor_options):
    # Config
    workspace = test_config.workspace if "workspace" not in executor_options else executor_options["workspace"]
    configuration.set(SERVER_SECTION, "api_port", str(test_config.client.port))
    configuration.set(SERVER_SECTION, "host", test_config.client.host)
    configuration.set(SERVER_SECTION, "workspace", workspace)
    configuration.set(TOKENS_SECTION, "registration", test_config.registration_token)
    configuration.set(TOKENS_SECTION, "agent", test_config.agent_token)
    path_to_basic_executor = (
        Path(__file__).parent.parent /
        'data' / 'basic_executor.py'
    )
    args = ' --'.join([''] + executor_options['args'])
    configuration.set(EXECUTOR_SECTION, "cmd", f"python {path_to_basic_executor} {args}")
    tmp_default_config.save()

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session, tmp_default_config.config_file_path)
    await dispatcher.run_once(json.dumps(executor_options["data"]))
    history = test_logger_handler.history
    for l in executor_options["logs"]:
        min_count = 1 if "min_count" not in l else l["min_count"]
        max_count = sys.maxsize if "max_count" not in l else l["max_count"]
        assert max_count >= \
            len(list(filter(lambda x: x.levelname == l["levelname"] and l["msg"] in x.message, history))) >= \
            min_count
