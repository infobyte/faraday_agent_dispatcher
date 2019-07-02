#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `faraday_dummy_agent` package."""

import pytest

from click.testing import CliRunner

from faraday_agent_dispatcher import cli
from faraday_agent_dispatcher.dispatcher import Dispatcher
from faraday_agent_dispatcher.builder import DispatcherBuilder


def correct_config_dict():
    return {
        "faraday_url": "localhost",
        "access_token": "valid_token"
    }

@pytest.mark.parametrize('config',
                         [{"remove": ["faraday_url"],
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": ["access_token"],
                           "replace": {},
                           "expected_exception": ValueError},
                          {"remove": [],
                           "replace": {"access_token": "invalid_token"},
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
        if "access_token" in config_dict:
            d_builder.access_token(config_dict["access_token"])
    if "expected_exception" in config:
        with pytest.raises(config["expected_exception"]):
            d_builder.build()
    else:
        assert isinstance(d_builder.build(), Dispatcher)


def test_ws_connection():
    dispatcher = DispatcherBuilder()\
        .config(correct_config_dict())\
        .build()
    dispatcher.connect()
    dispatcher.run()
    dispatcher.send()
    # Create local dispatcher with localhost WS
    # localhost WS send
    pass


def test_executor_connection():
    # Create basic executor and test function
    pass


def test_command_line_interface():
    """Test the CLI."""
    return
    runner = CliRunner()
    result = runner.invoke(cli.main)
    assert result.exit_code == 0
    assert 'faraday_agent_dispatcher.cli.main' in result.output
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0
    assert '--help  Show this message and exit.' in help_result.output
