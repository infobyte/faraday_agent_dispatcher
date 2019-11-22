import pytest
from click.testing import CliRunner
from typing import List, Dict

from faraday_agent_dispatcher.cli import config_wizard


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
            f"{self.max_size}\n" \
            f"{len(self.varenvs)}\n"
        for key in self.varenvs:
            config = f"{config}{key}\n{self.varenvs[key]}\n"
        config = f"{config}" \
                 f"{len(self.params)}\n"
        for key in self.params:
            config = f"{config}{key}\n{str(self.params[key])}\n"
        return config


class DispatcherConfig:
    def __init__(self, host=None, api_port=None, ws_port=None, workspace=None, agent_name=None,
                 registration_token=None, executors=None):
        self.server_config = {
            "host": host or "",
            "api_port": api_port or "",
            "ws_port": ws_port or "",
            "workspace": workspace or "",
        }
        self.agent = agent_name or ""
        self.registration_token = registration_token or ""
        self.executors: List[ExecutorConfig] = executors or []

    def config_str(self):
        config = f"{self.server_config['host']}\n" \
                 f"{self.server_config['api_port']}\n" \
                 f"{self.server_config['ws_port']}\n" \
                 f"{self.server_config['workspace']}\n" \
                 f"{self.server_config['ws_port']}\n" \
                 f"{self.agent}\n" \
                 f"{self.registration_token}\n" \
                 f"{len(self.executors)}\n"
        for executor in self.executors:
            config = f"{config}{executor.config_str()}\n"
        return config
# Order will be:
    # * Host
    # * API port
    # * WS port
    # * Workspace
    # * Agent name
    # * Registration token (if set, remove agent token)
    # * Executors How many?:
    #   * Main config:
    #     * Executor name
    #     * Executor command
    #     * Max size
    #   * VARENVS
    #   * Params


def generate_configs():
    return []


configs = generate_configs()


@pytest.mark.parametrize(
    "testing_configs",
    configs
)
def test_new_config(testing_configs: Dict[(str, object)]):
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(config_wizard, input=testing_configs["config"].config_str())
        assert result.exit_code == testing_configs["exit_code"]
        assert result.output == testing_configs["output"]


if __name__ == '__main__':
    d = DispatcherConfig()
    dd = DispatcherConfig(executors=[ExecutorConfig("qwe","qweqe",params={"qeqwe": True, "asdasda": False}),
                                     ExecutorConfig(name="qwsde",cmd="qwdfeqe",varenvs={"asdasda": "False"})])
    print (dd.config_str())
    #print ("QWE")
    #print(dd.config_str())