#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `faraday_dummy_agent` package."""

import os
import pytest

from click.testing import CliRunner

from faraday_agent_dispatcher import cli
from faraday_agent_dispatcher.dispatcher import Dispatcher
from faraday_agent_dispatcher.builder import DispatcherBuilder


def correct_config_dict():
    return {
        "faraday_url": "localhost",
        "registration_token": "valid_registration_token"
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


@pytest.mark.parametrize('config',
                         [{"remove": ["faraday_url"],
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": ["registration_token"],
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": [],
                           "replace": {"registration_token": "invalid_token"},
                           "expected_exception": SyntaxError},
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
    d_builder = DispatcherBuilder()
    if use_dict:
        d_builder.config(config_dict)
    else:
        if "faraday_url" in config_dict:
            d_builder.faraday_url(config_dict["faraday_url"])
        if "registration_token" in config_dict:
            d_builder.registration_token(config_dict["registration_token"])
    if "expected_exception" in config:
        with pytest.raises(config["expected_exception"]):
            d_builder.build()
    else:
        assert isinstance(d_builder.build(), Dispatcher)
        assert os.getenv("FARADAY_URL") == config_dict["faraday_url"]
        assert os.getenv("AGENT_API_TOKEN") == "valid_api_token"
        assert os.getenv("AGENT_WS_TOKEN") == "valid_ws_token"


def test_executor_connection():
    # Create basic executor and test function
    dispatcher = DispatcherBuilder().config(correct_config_dict()).build()
    dispatcher.run()
    assert dispatcher.get_output() == "I'm a testing executor"
    assert dispatcher.get_faraday_info() == full_data


def test_ws_connection():
    # Create local dispatcher with localhost WS
    # localhost WS send
    dispatcher = DispatcherBuilder().config(correct_config_dict()).build()
    dispatcher.connect()
    # mock: ok + run
    assert dispatcher.history() == expected_history
