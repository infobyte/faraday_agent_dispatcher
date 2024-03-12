from pathlib import Path
from typing import Dict

import pytest
from click.testing import CliRunner
import os

from faraday_agent_dispatcher import config as config_mod
from faraday_agent_dispatcher.cli.main import config_wizard
from faraday_agent_dispatcher.config import Sections
from tests.unittests.config.wizard import (
    generate_inputs,
    generate_no_ssl_ini_configs,
    generate_ssl_ini_configs,
    generate_error_ini_configs,
    parse_inputs,
    old_version_path,
)
from tests.unittests.wizard_input import DispatcherInput


inputs = generate_inputs()
no_ssl_ini_configs = generate_no_ssl_ini_configs()
ssl_ini_configs = generate_ssl_ini_configs()
all_ini_configs = no_ssl_ini_configs + ssl_ini_configs
error_ini_configs = generate_error_ini_configs()


@pytest.mark.parametrize("testing_inputs", inputs, ids=lambda elem: elem["id_str"])
@pytest.mark.parametrize("ini_config", all_ini_configs, ids=lambda elem: elem["id_str"])
def test_new_config(testing_inputs: Dict[(str, object)], ini_config):
    runner = CliRunner()

    content = None
    content_path = ini_config["dir"]

    if content_path != "":
        with open(content_path, "r") as content_file:
            content = content_file.read()

    with runner.isolated_filesystem() as file_system:
        if content:
            path = Path(file_system) / "dispatcher.ini"
            with path.open(mode="w") as content_file:
                content_file.write(content)
        else:
            path = Path(file_system)
        """
        The in_data variable will be consumed for the cli command, but in order
        to avoid unexpected inputs with no data (and a infinite wait),
        a \0\n block of input is added at the end of the input. Furthermore the
         \0 is added as a possible choice of the ones and should exit with
        error.
        """
        in_data = "Q\nN\n" if ini_config["id_str"] == "no_ini" else ""
        in_data += parse_inputs(testing_inputs) + "\0\n" * 1000
        env = os.environ
        env["DEBUG_INPUT_MODE"] = "True"

        result = runner.invoke(config_wizard, args=["-c", path], input=in_data, env=env)
        assert result.exit_code == testing_inputs["exit_code"], result.exception
        if "exception" in testing_inputs:
            assert str(result.exception) == str(testing_inputs["exception"])
            assert testing_inputs["exception"].__class__ == result.exception.__class__
        else:
            # Control '\0' is not passed in the output, as the input is echoed
            assert "\0\n" not in result.output
        if "expected_outputs" in testing_inputs:
            for expected_output in testing_inputs["expected_outputs"]:
                assert expected_output in result.output

        expected_executors_set = set.union(ini_config["old_executors"], testing_inputs["after_executors"])

        if path.suffix == ".ini":
            path = path.with_suffix(".yaml")
        config_mod.reset_config(path)
        executor_config_set = set(config_mod.instance[Sections.AGENT].get("executors"))
        assert executor_config_set == expected_executors_set

        assert f"Section: {Sections.TOKENS}" not in result.output


@pytest.mark.parametrize("delete_token", [True, False])
def test_with_agent_token(delete_token):
    runner = CliRunner()

    content_path = old_version_path() / "1.2_with_agent_token.ini"

    with open(content_path, "r") as content_file:
        content = content_file.read()

    with runner.isolated_filesystem() as file_system:
        path = Path(file_system) / "dispatcher.ini"
        with path.open(mode="w") as content_file:
            content_file.write(content)
        env = os.environ
        env["DEBUG_INPUT_MODE"] = "True"
        input_str = DispatcherInput(
            ssl="false",
            delete_agent_token=delete_token,
        ).input_str()
        input_str = f"A\n{input_str}Q\n"
        escape_string = "\0\n" * 1000
        result = runner.invoke(
            config_wizard,
            args=["-c", path],
            input=f"{input_str}{escape_string}",
            env=env,
        )
        assert result.exit_code == 0, result.exception
        assert f"Section: {Sections.TOKENS}" in result.output

        path = path.with_suffix(".yaml")
        config_mod.reset_config(path)
        if delete_token:
            assert "agent" not in config_mod.instance[Sections.TOKENS]
        else:
            assert "agent" in config_mod.instance[Sections.TOKENS]


def test_begin_and_quit():
    runner = CliRunner()

    with runner.isolated_filesystem() as file_system:
        path = Path(file_system) / "dispatcher.yaml"
        input_str = "Q\nY\n"
        escape_string = "\0\n" * 1000
        env = os.environ
        env["DEBUG_INPUT_MODE"] = "True"

        result = runner.invoke(
            config_wizard,
            args=["-c", path],
            input=f"{input_str}{escape_string}",
            env=env,
        )

        assert result.exit_code == 0, result.exception
        assert len(config_mod.instance) == 2
        assert "\0\n" not in result.output
