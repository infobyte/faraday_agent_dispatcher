import pytest
from click.testing import CliRunner
from typing import List, Dict
import os
from pathlib import Path

from faraday_agent_dispatcher.cli.main import config_wizard
from tests.utils.text_utils import fuzzy_string


class ExecutorConfig:
    def __init__(self, name=None, cmd=None, max_size=None, varenvs: Dict[(str, str)] = None,
                 params: Dict[(str, bool)] = None):
        self.name = name or ""
        self.cmd = cmd or ""
        self.max_size = max_size or ""
        self.varenvs = varenvs or {}
        self.params = params or {}

    def config_str(self):
        config = \
            f"{self.name}\n" \
            f"{self.cmd}\n" \
            f"{self.max_size}\n"
        for key in self.varenvs:
            config = f"{config}A\n{key}\n{self.varenvs[key]}\n"
        config = f"{config}Q\n"
        for key in self.params:
            config = f"{config}A\n{key}\n{'y' if self.params[key] else 'n'}\n"
        config = f"{config}Q\n"
        return config


class RepeatedExecutorConfig(ExecutorConfig):

    def __init__(self, name=None, repeated_name=None, cmd=None, max_size=None, varenvs: Dict[(str, str)] = None,
                 params: Dict[(str, bool)] = None):
        super().__init__(repeated_name, cmd, max_size, varenvs, params)
        self.correct_name = name or fuzzy_string(8)

    def config_str(self):
        config = super().config_str().split("\n")
        config.insert(1, self.correct_name)
        return '\n'.join(config)


class DispatcherConfig:
    def __init__(self, host=None, api_port=None, ws_port=None, workspace=None, agent_name=None,
                 registration_token=None, empty=False):
        self.server_config = {
            "host": host or "",
            "api_port": api_port or "",
            "ws_port": ws_port or "",
            "workspace": workspace or "",
        }
        self.agent = agent_name or ""
        self.registration_token = registration_token or ""
        self.empty = empty

    def config_str(self):
        config = f"{self.server_config['host']}\n" \
                 f"{self.server_config['api_port']}\n" \
                 f"{self.server_config['ws_port']}\n" \
                 f"{self.server_config['workspace']}\n" \
                 f"{self.registration_token}\n" \
                 f"{self.agent}\n"
        return config

# Order will be:
    # * Agent/Executor (?)
    # * Agent
    #   * Host
    #   * API port
    #   * WS port
    #   * Workspace
    #   * Agent name
    #   * Registration token (if set, remove agent token)
    # * Executors
    # AMD (?)
    #   * MD -> Which one?
    #   * Main config:
    #     * Executor name
    #     * Executor command
    #     * Max size
    #   * VARENVS AMD (?)
    #   * Params AMD (?)


def generate_configs():
    return [
        # All default
        {
            "config": DispatcherConfig(),
            "exit_code": 0
        },
        # Executors config
        {
            "config": DispatcherConfig(),
            "executors_config": {
                "add": [
                    ExecutorConfig(name="ex1", cmd="cmd 1", params={"add_param1": True, "add_param2": False}),
                    ExecutorConfig(name="ex2", cmd="cmd 2", varenvs={"add_varenv1": "AVarEnv"}),
                    ExecutorConfig(name="ex3", cmd="cmd 3", params={"add_param1": True, "add_param2": False},
                                   varenvs={"add_varenv1": "AVarEnv"}),
                ]
            },
            "exit_code": 0
        },
        # Bad Executors config
        {
            "config": DispatcherConfig(),
            "executors_config": {
                "add": [
                    ExecutorConfig(name="ex1", cmd="cmd 1", params={"add_param1": True, "add_param2": False}),
                    ExecutorConfig(name="ex2", cmd="cmd 2", varenvs={"add_varenv1": "AVarEnv"}),
                    ExecutorConfig(name="ex3", cmd="cmd 3", params={"add_param1": True, "add_param2": False},
                                   varenvs={"add_varenv1": "AVarEnv"}),
                    RepeatedExecutorConfig(repeated_name="ex1", cmd="cmd 4",
                                           params={"add_param3": True, "add_param4": False},
                                           varenvs={"add_varenv2": "AVarEnv"}),
                ]
            },
            "exit_code": 0
        },
        # Executors config
        {
            "config": DispatcherConfig(),
            "executors_config": {
                "add": [
                    ExecutorConfig(name="ex1", cmd="cmd 1", params={"add_param1": True, "add_param2": False}),
                    ExecutorConfig(name="ex2", cmd="cmd 2", varenvs={"add_varenv": "AVarEnv"}),
                    ExecutorConfig(name="ex3", cmd="cmd 3", params={"add_param1": True, "add_param2": False},
                                   varenvs={"add_varenv": "AVarEnv"}),
                ],
                "mod": [
                    ExecutorConfig(name="ex1", cmd="exit 1", params={"mod_param1": True, "add_param1": False}),
                    ExecutorConfig(name="ex2", cmd="", varenvs={"mod_varenv1": "AVarEnv"}),
                    ExecutorConfig(name="ex3", cmd="", params={"mod_param1": True, "mod_param2": False},
                                   varenvs={"mod_varenv1": "AVarEnv"}),
                ]
            },
            "exit_code": 0
        },
        # Dispatcher config
        {
            "config": DispatcherConfig(host="127.0.0.1", api_port="13123", ws_port="1234", workspace="aworkspace",
                                       agent_name="agent", registration_token="1234567890123456789012345"),
            "exit_code": 0
        },
        # Bad token config
        {
            "config": DispatcherConfig(host="127.0.0.1", api_port="13123", ws_port="1234", workspace="aworkspace",
                                       agent_name="agent", registration_token="12345678901234567890"),
            "exit_code": 1,
            "exception": ValueError("registration must be 25 character length")
        },
    ]


def ls_old_inis():
    files = []
    path = Path(__file__).parent.parent / 'data' / 'old_version_inis'
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            files.append(path / file)
    return files


configs = generate_configs()
inis_files = [""] + ls_old_inis()


def parse_config(config: Dict):
    output = ""
    if "config" in config:
        dispatcher_config: DispatcherConfig = config['config']
        output = f"A\n{dispatcher_config.config_str()}"
    if "executors_config" in config:
        executors_config = config["executors_config"]
        output = f"{output}E\n"
        if "add" in executors_config:
            for executor_conf in executors_config["add"]:
                output = f"{output}A\n{executor_conf.config_str()}"
        if "mod" in executors_config:
            for executor_conf in executors_config["mod"]:
                output = f"{output}M\n{executor_conf.config_str()}"
        if "del" in executors_config:
            for executor_conf in executors_config["del"]:
                output = f"{output}D\n{executor_conf.name}\n"
        output = f"{output}Q\n"
    output = f"{output}Q\n"
    return output


@pytest.mark.parametrize(
    "testing_configs",
    configs
)
@pytest.mark.parametrize(
    "ini_filepath",
    inis_files
)
def test_new_config(testing_configs: Dict[(str, object)], ini_filepath):
    runner = CliRunner()

    content = None

    if ini_filepath != "":
        with open(ini_filepath, 'r') as content_file:
            content = content_file.read()

    with runner.isolated_filesystem() as file_system:

        if content:
            path = Path(file_system) / "dispatcher.ini"
            with path.open(mode="w") as content_file:
                content_file.write(content)
        else:
            path = Path(file_system)
        in_data = parse_config(testing_configs) + "\0\n" * 1000  # HORRIBLE FIX
        env = os.environ
        env["DEFAULT_VALUE_NONE"] = "True"
        result = runner.invoke(config_wizard, args=["-c", path], input=in_data, env=env)
        assert result.exit_code == testing_configs["exit_code"], result.exception
        if "exception" in testing_configs:
            assert str(result.exception) == str(testing_configs["exception"])
            assert result.exception.__class__ == testing_configs["exception"].__class__
