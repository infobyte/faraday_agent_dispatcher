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


class Input:
    def input_str(self):
        return ""


class VarEnvInput(Input):
    def __init__(self, name: str, value: str, adm_type: ADMType, error_name=None, new_name=None):
        if adm_type == ADMType.ADD and value == "":
            raise ValueError('IF ADMTYPE = ADD, VALUE CAN NOT BE ""')
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

        cli_input = f"{cli_input}" f"{self.name}\n"
        if self.adm_type == ADMType.MODIFY:
            cli_input = f"{cli_input}{self.new_name or self.name}\n"
        return f"{cli_input}{self.value}\n"


class ParamInput(Input):
    def __init__(self, name: str, mandatory: bool, type: str, adm_type: ADMType, error_type=None, new_name=None):
        self.name = name
        self.mandatory = mandatory
        self.type = type
        self.adm_type = adm_type
        self.error_name = error_type
        self.new_name = new_name

    def input_str(self):
        prefix = self.adm_type.name[0]
        cli_input = f"{prefix}\n"
        if self.error_name:
            cli_input = f"{cli_input}{self.error_name}\n{prefix}\n"

        if self.adm_type == ADMType.DELETE:
            return f"{cli_input}{self.name}\n"

        cli_input = f"{cli_input}" f"{self.name}\n"
        if self.adm_type == ADMType.MODIFY:
            cli_input = f"{cli_input}{self.new_name or self.name}\n"
        mand = "y" if self.mandatory else "n"
        return f"{cli_input}{mand}\n{self.type}\n\n"


class ExecutorInput:
    def __init__(
        self,
        name=None,
        error_name=None,
        cmd=None,
        max_size=None,
        varenvs: List[VarEnvInput] = None,
        params: List[ParamInput] = None,
        new_name: str = "",
        new_error_name=None,
        adm_type: ADMType = None,
    ):
        self.name = name or ""
        self.error_name = error_name
        self.cmd = cmd or ""
        self.max_size = max_size or ""
        self.varenvs = varenvs or {}
        self.params = params or {}
        self.adm_type = adm_type
        self.new_name = new_name
        self.new_error_name = new_error_name

    def input_str(self):
        prefix = self.adm_type.name[0]
        cli_input = f"{prefix}\n"

        if self.error_name:
            cli_input = f"{cli_input}{self.error_name}\n{prefix}\n"

        if self.adm_type == ADMType.DELETE:
            return f"{cli_input}{self.name}\n"

        cli_input = f"{cli_input}" f"{self.name}\n"

        if self.adm_type == ADMType.ADD:
            cli_input = f"{cli_input}Y\n"

        if self.adm_type == ADMType.MODIFY:
            if self.new_error_name:
                cli_input = f"{cli_input}{self.new_error_name}\n"
            cli_input = f"{cli_input}{self.new_name or self.name}\n"
        cli_input = f"{cli_input}" f"{self.cmd}\n" f"{self.max_size}\n"
        for varenv_input in self.varenvs:
            cli_input = f"{cli_input}{varenv_input.input_str()}"
        cli_input = f"{cli_input}Q\n"
        for param_input in self.params:
            cli_input = f"{cli_input}{param_input.input_str()}"
        cli_input = f"{cli_input}Q\n"
        return cli_input


class RepoVarEnvInput(Input):
    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value

    def input_str(self):
        return f"{self.value}\n"


class RepoExecutorInput:
    def __init__(
        self,
        base=None,
        name=None,
        error_name=None,
        max_size=None,
        force_quit=False,
        varenvs: List[RepoVarEnvInput] = None,
        new_name: str = "",
        adm_type: ADMType = None,
    ):
        self.name = name or ""
        self.error_name = error_name
        self.base = base or ""
        self.max_size = max_size or ""
        self.force_quit = force_quit
        self.varenvs = varenvs or {}
        self.adm_type = adm_type
        self.new_name = new_name

    def input_str(self):
        prefix = self.adm_type.name[0]
        cli_input = f"{prefix}\n"

        if self.error_name:
            cli_input = f"{cli_input}{self.error_name}\n{prefix}\n"

        if self.adm_type == ADMType.DELETE:
            return f"{cli_input}{self.name}\n"

        cli_input = f"{cli_input}" f"{self.name}\n"

        if self.force_quit:
            if self.adm_type == ADMType.ADD:
                cli_input = f"{cli_input}N\nQ\nY\nQ\nY\n"
        else:
            if self.adm_type == ADMType.ADD:
                cli_input = f"{cli_input}N\n{self.base}\n"

            if self.adm_type == ADMType.MODIFY:
                cli_input = f"{cli_input}{self.new_name or self.name}\n"
            cli_input = f"{cli_input}" f"{self.max_size}\n"
            for varenv_input in self.varenvs:
                cli_input = f"{cli_input}{varenv_input.input_str()}"

        cli_input = f"{cli_input}Q\n"
        cli_input = f"{cli_input}Q\n"
        return cli_input


class DispatcherInput:
    def __init__(
        self,
        host=None,
        api_port=None,
        ws_port=None,
        workspaces=None,
        ssl=None,
        ssl_ignore=None,
        agent_name=None,
        delete_agent_token: bool = None,
        empty=False,
    ):
        self.ssl = ssl is None or (isinstance(ssl, bool) and ssl) or ssl.lower() != "false"
        self.ssl_ignore = (
            ssl_ignore is None or (isinstance(ssl_ignore, bool) and ssl_ignore) or ssl_ignore.lower() != "false"
        )
        self.server_input = {
            "ssl": "Y" if self.ssl else "N",
            "ssl_ignore": "Y" if self.ssl and self.ssl_ignore else "N",
            "host": host or "localhost",
            "api_port": api_port or "13123",
            "ws_port": ws_port or "1234",
        }
        self.workspaces = workspaces
        self.agent = agent_name or ""
        self.delete_agent_token = delete_agent_token
        self.empty = empty

    def input_str(self):
        if self.ssl:
            input_str = (
                f"{self.server_input['host']}\n" f"{self.server_input['ssl']}\n" f"{self.server_input['api_port']}\n"
            )
            input_str = f"{input_str}{self.server_input['ssl_ignore']}\n"
            input_str = f"{input_str}{self.process_input_workspaces()}\n"
        else:
            input_str = (
                f"{self.server_input['host']}\n"
                f"{self.server_input['ssl']}\n"
                f"{self.server_input['api_port']}\n"
                f"{self.server_input['ws_port']}\n"
                f"{self.process_input_workspaces()}\n"
            )

        if self.delete_agent_token is not None:
            input_str = f"{input_str}{'Y' if self.delete_agent_token else 'N'}\n"

        return f"{input_str}{self.agent}\n"

    def process_input_workspaces(self):
        cli_input = ""
        for workspace_input in self.workspaces:
            cli_input = f"{cli_input}{workspace_input.input_str()}\n"
        return f"{cli_input}Q\n"


class WorkspaceInput(Input):
    def __init__(self, name: str, adm_type: ADMType, error_name=None):
        self.name = name
        self.adm_type = adm_type
        self.error_name = error_name

    def input_str(self):
        prefix = self.adm_type.name[0]
        cli_input = f"{prefix}\n"
        if self.adm_type == ADMType.MODIFY:
            return cli_input

        if self.error_name:
            cli_input = f"{cli_input}{self.error_name}\n{prefix}\n"

        return f"{cli_input}{self.name}\n"
