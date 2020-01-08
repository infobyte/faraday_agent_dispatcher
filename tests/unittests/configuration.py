from typing import List
from enum import Enum

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


class ADMType(Enum):
    ADD = 1
    MODIFY = 2
    DELETE = 3


class VarEnvConfig:

    def __init__(self, name: str, value: str, adm_type: ADMType):
        self.name = name
        self.value = value
        self.adm_type = adm_type

    def config_str(self):
        prefix = self.adm_type.name[0]
        if prefix == "D":
            return f"{prefix}\n{self.name}\n"
        return f"{prefix}\n{self.name}\n{self.value}\n"


class ParamConfig(VarEnvConfig):

    def __init__(self, name: str, value: bool, adm_type: ADMType):
        super().__init__(name, 'Y' if value else 'N', adm_type)


class ExecutorConfig:
    def __init__(self, name=None, error_name=None, cmd=None, max_size=None, varenvs: List[VarEnvConfig] = None,
                 params: List[ParamConfig] = None, new_name: str = "", adm_type: ADMType = None):
        self.name = name or ""
        self.error_name = error_name
        self.cmd = cmd or ""
        self.max_size = max_size or ""
        self.varenvs = varenvs or {}
        self.params = params or {}
        self.adm_type = adm_type
        self.new_name = new_name

    def config_str(self):
        prefix = self.adm_type.name[0]
        config = f"{prefix}\n"
        if self.error_name:
            config = f"{config}{self.error_name}\n{prefix}\n"

        if self.adm_type == ADMType.DELETE:
            return f"{config}{self.name}\n"

        config = f"{config}" \
                 f"{self.name}\n"
        if self.adm_type == ADMType.MODIFY:
            config = f"{config}{self.new_name}\n"
        config = f"{config}" \
            f"{self.cmd}\n" \
            f"{self.max_size}\n"
        for varenv_config in self.varenvs:
            config = f"{config}{varenv_config.config_str()}\n"
        config = f"{config}Q\n"
        for param_config in self.params:
            config = f"{config}{param_config.config_str()}\n"
        config = f"{config}Q\n"
        return config


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
