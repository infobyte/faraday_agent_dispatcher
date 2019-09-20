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

import pytest

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
    reset_config(use_default=True)
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


def test_register():
    pass


def test_connect():
    pass


def test_run_once():
    pass