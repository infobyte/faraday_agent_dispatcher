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

from click.testing import CliRunner

from faraday_agent_dispatcher import cli
from faraday_agent_dispatcher.dispatcher import Dispatcher


def correct_config_dict():
    return {
        "faraday_host": "localhost",
        "api_port": "5968",
        "websocket_port": "9000",
        "workspace": "faraday_workspace",
        "registration_token": "valid_registration_token",
        "executor_filename": "test_executor"
    }


host_data = {
    "ip": "127.0.0.1",
    "description": "test",
    "hostnames": ["test.com", "test2.org"]
}

service_data = {
    "name": "http",
    "port": 80,
    "protocol": "tcp",
}

vuln_data = {
    'name': 'sql injection',
    'desc': 'test',
    'severity': 'high',
    'type': 'Vulnerability',
    'impact': {
        'accountability': True,
        'availability': False,
    },
    'refs': ['CVE-1234']
}

full_data = {
    "hosts": [host_data],
    "services": [service_data],
    "vulns": [vuln_data]
}

expected_history = ["Connected to websocket", "Received run request by websocket", "Running executor", "Sending " + str(full_data)]


class ToBeDefinedError(Exception):
    pass


@pytest.mark.parametrize('config',
                         [{"remove": ["faraday_host"],
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": ["api_port"],
                           "replace": {}},
                          {"remove": [],
                           "replace": {"api_port": "Not a port number"},
                           "expected_exception": ValueError},
                          {"remove": [],
                           "replace": {"api_port": "5897"},
                           "expected_exception": ToBeDefinedError},
                          # One must try to connect to another faraday and succeed, the other fails
                          {"remove": [],
                           "replace": {"api_port": "5900"},
                           "expected_exception": ToBeDefinedError},
                          {"remove": ["websocket_port"],
                           "replace": {}},
                          {"remove": [],
                           "replace": {"websocket_port": "Not a port number"},
                           "expected_exception": ValueError},
                          {"remove": [],
                           "replace": {"websocket_port": "9001"},
                           "expected_exception": ToBeDefinedError},
                          # One must try to connect to another faraday and succeed, the other fails
                          {"remove": [],
                           "replace": {"websocket_port": "9002"},
                           "expected_exception": ToBeDefinedError},
                          {"remove": ["workspace"],
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": [],
                           "replace": {"workspace": "9002"},
                           "expected_exception": ToBeDefinedError},  # Try to connect and fails
                          {"remove": ["registration_token"],
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": [],
                           "replace": {"registration_token": "invalid_token"},
                           "expected_exception": SyntaxError},
                          {"remove": ["executor_filename"],
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": [],
                           "replace": {}}
                          ])
@pytest.mark.parametrize('use_dict', [True, False])
def test_basic_built(config, use_dict):
    # Here fails except all needed parameters are set
    config_dict = correct_config_dict()
    for key in config["replace"].keys():
        config_dict[key] = config["replace"][key]
    for key in config["remove"]:
        del config_dict[key]
    d_builder = None
    if use_dict:
        d_builder.config(config_dict)
    else:
        if "faraday_host" in config_dict:
            d_builder.faraday_host(config_dict["faraday_host"])
        if "api_port" in config_dict:
            d_builder.api_port(config_dict["api_port"])
        if "websocket_port" in config_dict:
            d_builder.websocket_port(config_dict["websocket_port"])
        if "workspace" in config_dict:
            d_builder.faraday_workspace(config_dict["workspace"])
        if "registration_token" in config_dict:
            d_builder.registration_token(config_dict["registration_token"])
        if "executor_filename" in config_dict:
            d_builder.executor_filename(config_dict["executor_filename"])
    if "expected_exception" in config:
        with pytest.raises(config["expected_exception"]):
            d_builder.build()
    else:
        assert isinstance(d_builder.build(), Dispatcher)
        assert os.getenv("AGENT_API_TOKEN") == "valid_api_token"
        assert os.getenv("AGENT_WS_TOKEN") == "valid_ws_token"
