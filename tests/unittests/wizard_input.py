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
#   * Main input:
#     * Executor name
#     * Executor command
#     * Max size
#   * VARENVS AMD (?)
#   * Params AMD (?)


class ADMType(Enum):
    ADD = 1
    MODIFY = 2
    DELETE = 3


class VarEnvInput:

    def __init__(self, name: str, value: str, adm_type: ADMType, error_name=None, new_name=None):
        self.name = name
        self.value = value
        self.adm_type = adm_type
        self.error_name = error_name
        self.new_name = new_name

    def input_str(self):
        prefix = self.adm_type.name[0]
        cli_input = f"{prefix}\n"
        if self.error_name:
            cli_input = f"{cli_input}{self.error_name}\n{prefix}\n"

        if self.adm_type == ADMType.DELETE:
            return f"{cli_input}{self.name}\n"

        cli_input = f"{cli_input}" \
                    f"{self.name}\n"
        if self.adm_type == ADMType.MODIFY:
            cli_input = f"{cli_input}{self.new_name}\n"
        return f"{cli_input}{self.value}\n"


class ParamInput(VarEnvInput):

    def __init__(self, name: str, value: bool, adm_type: ADMType):
        super().__init__(name, 'Y' if value else 'N', adm_type)


class ExecutorInput:
    def __init__(self, name=None, error_name=None, cmd=None, max_size=None, varenvs: List[VarEnvInput] = None,
                 params: List[ParamInput] = None, new_name: str = "", adm_type: ADMType = None):
        self.name = name or ""
        self.error_name = error_name
        self.cmd = cmd or ""
        self.max_size = max_size or ""
        self.varenvs = varenvs or {}
        self.params = params or {}
        self.adm_type = adm_type
        self.new_name = new_name

    def input_str(self):
        prefix = self.adm_type.name[0]
        cli_input = f"{prefix}\n"
        if self.error_name:
            cli_input = f"{cli_input}{self.error_name}\n{prefix}\n"

        if self.adm_type == ADMType.DELETE:
            return f"{cli_input}{self.name}\n"

        cli_input = f"{cli_input}" \
                    f"{self.name}\n"
        if self.adm_type == ADMType.MODIFY:
            cli_input = f"{cli_input}{self.new_name}\n"
        cli_input = f"{cli_input}" \
            f"{self.cmd}\n" \
            f"{self.max_size}\n"
        for varenv_input in self.varenvs:
            cli_input = f"{cli_input}{varenv_input.input_str()}"
        cli_input = f"{cli_input}Q\n"
        for param_input in self.params:
            cli_input = f"{cli_input}{param_input.input_str()}"
        cli_input = f"{cli_input}Q\n"
        return cli_input


class DispatcherInput:
    def __init__(self, host=None, api_port=None, ws_port=None, workspace=None, agent_name=None,
                 registration_token=None, empty=False):
        self.server_input = {
            "host": host or "",
            "api_port": api_port or "",
            "ws_port": ws_port or "",
            "workspace": workspace or "",
        }
        self.agent = agent_name or ""
        self.registration_token = registration_token or ""
        self.empty = empty

    def input_str(self):
        input_str = f"{self.server_input['host']}\n" \
                 f"{self.server_input['api_port']}\n" \
                 f"{self.server_input['ws_port']}\n" \
                 f"{self.server_input['workspace']}\n"

        if isinstance(self.registration_token, str):
            self.registration_token = [self.registration_token]
        for token in self.registration_token:
            input_str = f"{input_str}{token}\n"

        return f"{input_str}" \
               f"{self.registration_token}\n" \
               f"{self.agent}\n"
