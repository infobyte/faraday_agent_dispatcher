from pathlib import Path
from typing import List, Dict

from faraday_agent_dispatcher import config as config_mod
from tests.unittests.wizard_input import (
    DispatcherInput,
    ExecutorInput,
    ParamInput,
    ADMType,
    VarEnvInput,
    RepoExecutorInput,
    RepoVarEnvInput,
    WorkspaceInput,
)

DATA_FOLDER = Path(__file__).parent.parent.parent / "data"


def old_version_path():
    return DATA_FOLDER / "old_version_inis"


def generate_inputs():
    return [
        {
            "id_str": "All default",
            "dispatcher_input": DispatcherInput(
                ssl="false", workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)]
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "All default with ssl false",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Dispatcher input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                host="127.0.0.1",
                api_port="13123",
                ws_port="1234",
                agent_name="agent",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Dispatcher input only host",
            "dispatcher_input": DispatcherInput(
                host="127.0.0.1",
                ssl="false",
                agent_name="agent",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Dispatcher input host and port",
            "dispatcher_input": DispatcherInput(
                host="127.0.0.1:8080",
                ssl="false",
                agent_name="agent",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Dispatcher input scheme url",
            "dispatcher_input": DispatcherInput(
                host="http://127.0.0.1:8080",
                ssl="false",
                agent_name="agent",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Dispatcher input host base_route",
            "dispatcher_input": DispatcherInput(
                host="127.0.0.1/faraday",
                ssl="false",
                agent_name="agent",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Bad token input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                host="127.0.0.1",
                api_port="13123",
                ws_port="1234",
                agent_name="agent",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "exit_code": 0,
            "expected_output": ["registration must be 25 character length"],
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="cmd 2",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex3",
                    cmd="cmd 3",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1", "ex2", "ex3"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Bad Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="cmd 2",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex3",
                    cmd="cmd 3",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    error_name="ex1",
                    cmd="cmd 4",
                    name="ex4",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1", "ex2", "ex3", "ex4"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Mod Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="cmd 2",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex3",
                    cmd="cmd 3",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex1",
                    error_name="QWE",
                    cmd="exit 1",
                    params=[
                        ParamInput(name="mod_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param1", mandatory=False, type="string", adm_type=ADMType.MODIFY),
                    ],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="",
                    varenvs=[VarEnvInput(name="mod_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(
                    name="ex3",
                    new_name="eX3",
                    cmd="",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.MODIFY)],
                    adm_type=ADMType.MODIFY,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1", "ex2", "eX3"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Del Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="cmd 2",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex3",
                    cmd="cmd 3",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex1",
                    error_name="QWE",
                    cmd="exit 1",
                    params=[ParamInput(name="add_param1", mandatory=False, type="string", adm_type=ADMType.DELETE)],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(name="ex2", cmd="", adm_type=ADMType.DELETE),
                ExecutorInput(
                    name="ex3",
                    cmd="",
                    varenvs=[
                        VarEnvInput(
                            error_name="aadd_varenv1",
                            name="add_varenv1",
                            new_name="add_varenv1moded",
                            value="",
                            adm_type=ADMType.MODIFY,
                        ),
                        VarEnvInput(name="add_varenv1moded", value="", adm_type=ADMType.DELETE),
                    ],
                    adm_type=ADMType.MODIFY,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1", "ex3"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Repo Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false", workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)]
            ),
            "executors_input": [
                RepoExecutorInput(
                    name="ex1",
                    base="4",
                    varenvs=[
                        RepoVarEnvInput(name="NESSUS_USERNAME", value="asd"),
                        RepoVarEnvInput(name="NESSUS_PASSWORD", value="asdsad"),
                        RepoVarEnvInput(name="NESSUS_URL", value="asdasd"),
                    ],
                    adm_type=ADMType.ADD,
                ),
                RepoExecutorInput(
                    name="ex1",
                    varenvs=[
                        RepoVarEnvInput(name="NESSUS_USERNAME", value="asd"),
                        RepoVarEnvInput(name="NESSUS_PASSWORD", value="asdsad"),
                        RepoVarEnvInput(name="NESSUS_URL", value="asdasd"),
                    ],
                    adm_type=ADMType.MODIFY,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Add multiple executors and delete one",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[
                    WorkspaceInput(name="aworkspace1", adm_type=ADMType.ADD),
                    WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD),
                    WorkspaceInput(name="aworkspace1", adm_type=ADMType.DELETE),
                ],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Add an executor and delete and add one",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[
                    WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD),
                    WorkspaceInput(name="aworkspace", adm_type=ADMType.DELETE),
                    WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD),
                ],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Delete an non-existent executor (Test modify do " "nothing)",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[
                    WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD),
                    WorkspaceInput(name="not_exist", adm_type=ADMType.DELETE),
                    WorkspaceInput(name="not_exist", adm_type=ADMType.MODIFY),
                ],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Try add an existent executor",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[
                    WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD),
                    WorkspaceInput(name="second", adm_type=ADMType.ADD, error_name="aworkspace"),
                ],
            ),
            "exit_code": 0,
            "after_executors": set(),
            "after_workspaces": {"aworkspace", "second"},
        },
        {
            "id_str": "Basic Name with comma Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    error_name="ex,1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Mod Name with comma Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="cmd 2",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex3",
                    cmd="cmd 3",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex1",
                    error_name="QWE",
                    cmd="exit 1",
                    params=[
                        ParamInput(name="mod_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param1", mandatory=False, type="string", adm_type=ADMType.MODIFY),
                    ],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="",
                    varenvs=[VarEnvInput(name="mod_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(
                    name="ex3",
                    new_error_name="eX,3",
                    new_name="eX3",
                    cmd="",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.MODIFY)],
                    adm_type=ADMType.MODIFY,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1", "ex2", "eX3"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Name with backslash Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    error_name="ex\\1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Mod Name with backslash Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="cmd 2",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex3",
                    cmd="cmd 3",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex1",
                    error_name="QWE",
                    cmd="exit 1",
                    params=[
                        ParamInput(name="mod_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param1", mandatory=False, type="string", adm_type=ADMType.MODIFY),
                    ],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="",
                    varenvs=[VarEnvInput(name="mod_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(
                    name="ex3",
                    new_error_name="eX\\3",
                    new_name="eX3",
                    cmd="",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.MODIFY)],
                    adm_type=ADMType.MODIFY,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1", "ex2", "eX3"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Name with slash Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    error_name="ex/1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Basic Mod Name with slash Executors input",
            "dispatcher_input": DispatcherInput(
                ssl="false",
                workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)],
            ),
            "executors_input": [
                ExecutorInput(
                    name="ex1",
                    cmd="cmd 1",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="cmd 2",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex3",
                    cmd="cmd 3",
                    params=[
                        ParamInput(name="add_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param2", mandatory=False, type="string", adm_type=ADMType.ADD),
                    ],
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.ADD,
                ),
                ExecutorInput(
                    name="ex1",
                    error_name="QWE",
                    cmd="exit 1",
                    params=[
                        ParamInput(name="mod_param1", mandatory=True, type="string", adm_type=ADMType.ADD),
                        ParamInput(name="add_param1", mandatory=False, type="string", adm_type=ADMType.MODIFY),
                    ],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(
                    name="ex2",
                    cmd="",
                    varenvs=[VarEnvInput(name="mod_varenv1", value="AVarEnv", adm_type=ADMType.ADD)],
                    adm_type=ADMType.MODIFY,
                ),
                ExecutorInput(
                    name="ex3",
                    new_error_name="eX/3",
                    new_name="eX3",
                    cmd="",
                    varenvs=[VarEnvInput(name="add_varenv1", value="AVarEnv", adm_type=ADMType.MODIFY)],
                    adm_type=ADMType.MODIFY,
                ),
            ],
            "exit_code": 0,
            "after_executors": {"ex1", "ex2", "eX3"},
            "after_workspaces": {"aworkspace"},
        },
        {
            "id_str": "Force Quit Executor",
            "dispatcher_input": DispatcherInput(
                ssl="false", workspaces=[WorkspaceInput(name="aworkspace", adm_type=ADMType.ADD)]
            ),
            "executors_input": [
                RepoExecutorInput(
                    name="ex1",
                    force_quit=True,
                    adm_type=ADMType.ADD,
                ),
            ],
            "exit_code": 0,
            "after_executors": {},
            "after_workspaces": {"aworkspace"},
        },
    ]


def generate_no_ssl_ini_configs():
    return [
        {
            "id_str": "no .ini",
            "dir": "",
            "old_executors": set(),
            "old_workspaces": set(),
        },
        {
            "id_str": "0.1.ini",
            "dir": old_version_path() / "0.1.ini",
            "old_executors": {config_mod.DEFAULT_EXECUTOR_VERIFY_NAME},
            "old_workspaces": {"workspace"},
        },
        {
            "id_str": "1.0.ini",
            "dir": old_version_path() / "1.0.ini",
            "old_executors": {"test", "test2"},
            "old_workspaces": {"workspace"},
        },
    ]


def generate_ssl_ini_configs():
    return [
        {
            "id_str": "1.2.ini",
            "dir": old_version_path() / "1.2.ini",
            "old_executors": {"test", "test2", "test3"},
            "old_workspaces": {"workspace"},
        },
        {
            "id_str": "1.5.ini",
            "dir": old_version_path() / "1.5.ini",
            "old_executors": {"test", "test2", "test3"},
            "old_workspaces": {"workspace"},
        },
    ]


def generate_error_ini_configs():
    return [
        {
            "id_str": "1.0.ini missing a executor section",
            "dir": old_version_path() / "1.0_error0.ini",
            "exception_message": "notAConfiguredExecutor section does not " "exists",
        },
        {
            "id_str": "1.0.ini missing executor option",
            "dir": old_version_path() / "1.0_error1.ini",
            "exception_message": "executors option not in agent section",
        },
    ]


def parse_inputs(testing_inputs: Dict):
    result_input = ""
    if "dispatcher_input" in testing_inputs:
        dispatcher_input: DispatcherInput = testing_inputs["dispatcher_input"]
        result_input = f"A\n{dispatcher_input.input_str()}"
    if "executors_input" in testing_inputs:
        executors_input: List[ExecutorInput] = testing_inputs["executors_input"]
        result_input = f"{result_input}E\n"
        for executor_input in executors_input:
            result_input = f"{result_input}{executor_input.input_str()}"
        result_input = f"{result_input}Q\n"
    result_input = f"{result_input}Q\n"
    return result_input
