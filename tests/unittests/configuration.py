from typing import Dict

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


class VarEnvConfig:

    def __init__(self, name: str, value: str, adm_type: str):
        self.name = name
        self.value = value
        self.adm_type = adm_type

    def config_str(self):
        prefix = self.adm_type.upper()[0]
        if prefix == "D":
            return f"{prefix}\n{self.name}\n"
        return f"{prefix}\n{self.name}\n{self.value}\n"


class ParamConfig(VarEnvConfig):

    def __init__(self, name: str, value: bool, adm_type: str):
        super().__init__(name, 'y' if value else 'n', adm_type)


class ExecutorConfig:
    def __init__(self, name=None, error_name=None, cmd=None, max_size=None, varenvs: Dict[(str, VarEnvConfig)] = None,
                 params: Dict[(str, ParamConfig)] = None, adm_type: str = None):
        self.name = name or ""
        self.error_name = error_name
        self.cmd = cmd or ""
        self.max_size = max_size or ""
        self.varenvs = varenvs or {}
        self.params = params or {}
        self.adm_type = adm_type

    def config_str(self):
        prefix = self.adm_type.upper()[0]
        if prefix == "D":
            return f"{prefix}\n{self.name}\n"
        config = f"{prefix}\n"
        if self.error_name:
            config = f"{config}{self.error_name}\n{prefix}\n"
        config = f"{config}" \
            f"{self.name}\n" \
            f"{self.cmd}\n" \
            f"{self.max_size}\n"
        for key in self.varenvs:
            config = f"{config}{self.varenvs[key].config_str()}\n"
        config = f"{config}Q\n"
        for key in self.params:
            config = f"{config}{self.params[key].config_str()}\n"
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
