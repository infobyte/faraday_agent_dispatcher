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

import os
import pytest

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
from tests.utils.testing_faraday_server import FaradayTestConfig, test_config

@pytest.mark.parametrize('config_changes_dict',
                         [{"remove": {SERVER_SECTION: ["host"]},
                           "replace": {}},  # None error as default value
                          {"remove": {SERVER_SECTION: ["api_port"]},
                           "replace": {}},  # None error as default value
                          {"remove": {},
                           "replace": {SERVER_SECTION: {"api_port": "Not a port number"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {SERVER_SECTION: {"api_port": "6000"}}},  # None error as parse int
                          {"remove": {SERVER_SECTION: ["websocket_port"]},
                           "replace": {}},
                          {"remove": {},
                           "replace": {SERVER_SECTION: {"websocket_port": "Not a port number"}},
                           "expected_exception": ValueError},
                          {"remove": {},
                           "replace": {SERVER_SECTION: {"websocket_port": "9001"}}},   # None error as parse int
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
def test_basic_built(config_changes_dict):
    reset_config()
    for section in config_changes_dict["replace"]:
        for option in config_changes_dict["replace"][section]:
            configuration.set(section, option, config_changes_dict["replace"][section][option])
    for section in config_changes_dict["remove"]:
        for option in config_changes_dict["remove"][section]:
            configuration.remove_option(section, option)
    config_file_path = f"/tmp/{fuzzy_string(10)}.ini"
    save_config(config_file_path)
    if "expected_exception" in config_changes_dict:
        with pytest.raises(config_changes_dict["expected_exception"]):
            Dispatcher(None, config_file_path)
    else:
        Dispatcher(None, config_file_path)


async def test_start_and_register(test_config: FaradayTestConfig):
    # Config
    reset_config()
    configuration.set(SERVER_SECTION, "api_port", str(test_config.client.port))
    configuration.set(SERVER_SECTION, "host", test_config.client.host)
    configuration.set(SERVER_SECTION, "workspace", test_config.workspace)
    configuration.set(TOKENS_SECTION, "registration", test_config.registration_token)
    config_file_path = f"/tmp/{fuzzy_string(10)}.ini"
    save_config(config_file_path)

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session, config_file_path)
    await dispatcher.register()

    # Control tokens
    assert dispatcher.agent_token == test_config.agent_token

    signer = TimestampSigner(test_config.app_config['SECRET_KEY'], salt="websocket_agent")
    agent_id = int(signer.unsign(dispatcher.websocket_token).decode('utf-8'))
    assert test_config.agent_id == agent_id

    os.remove(config_file_path)


@pytest.mark.skip
def test_websocket(test_config: FaradayTestConfig):
    text = fuzzy_string(15)
    file = f"/tmp/{fuzzy_string(8)}.txt"
    configuration.set(SERVER_SECTION, "api_port", str(test_config.client.port))
    configuration.set(SERVER_SECTION, "workspace", test_config.workspace)
    configuration.set(SERVER_SECTION, "websocket_port", str(test_config.websocket_port))
    configuration.set(SERVER_SECTION, "host", test_config.client.host)
    configuration.set(EXECUTOR_SECTION, "cmd", f"echo {text} > {file}")
    config_file_path = f"/tmp/{fuzzy_string(10)}.ini"
    save_config(config_file_path)

    dispatcher = Dispatcher(test_config.client.session, config_file_path)
    dispatcher.connect()
    test_config.run_agent_to_websocket() ## HERE SEND BY WS THE RUN COMMAND

    with open(file, 'rt') as f:
        assert text in f.readline()


@pytest.mark.parametrize('options',
                         [["out json"],
                          ["out bad_json"],
                          ["out str"],
                          ["err"],
                          ["fails"],
                          ["err", "fails"],
                          ])
async def test_run_once(test_config: FaradayTestConfig, options):
    # Config
    reset_config()
    configuration.set(SERVER_SECTION, "api_port", str(test_config.client.port))
    configuration.set(SERVER_SECTION, "host", test_config.client.host)
    configuration.set(SERVER_SECTION, "workspace", test_config.workspace)
    configuration.set(TOKENS_SECTION, "registration", test_config.registration_token)
    configuration.set(TOKENS_SECTION, "agent", test_config.agent_token)
    configuration.set(EXECUTOR_SECTION, "cmd", " --".join(["python ../data/basic_executor.py"] + options))
    print(" --".join(["python ../data/basic_executor.py"] + options))
    # TODO TEST CLOSE ON FIRST /n
    config_file_path = f"/tmp/{fuzzy_string(10)}.ini"
    save_config(config_file_path)

    # Init and register it
    dispatcher = Dispatcher(test_config.client.session, config_file_path)
    await dispatcher.run_once()

    os.remove(config_file_path)