from pathlib import Path

from faraday_agent_dispatcher.config import Sections


def generate_basic_built_config():
    return [
        {
            "id_str": "Error: No host",
            "remove": {Sections.SERVER: ["host"]},
            "replace": {},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: No API port",
            "remove": {Sections.SERVER: ["api_port"]},
            "replace": {},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: API port not number",
            "remove": {},
            "replace": {Sections.SERVER: {"api_port": "Not a port number"}},
            "expected_exception": ValueError,
        },
        {
            "id_str": "OK: API port number",
            "remove": {},
            "replace": {Sections.SERVER: {"api_port": "6000"}},
        },  # None error as parse int
        {
            "id_str": "Error: No WS port not number",
            "remove": {Sections.SERVER: ["websocket_port"]},
            "replace": {},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: WS port not number",
            "remove": {},
            "replace": {Sections.SERVER: {"websocket_port": "Not a port number"}},
            "expected_exception": ValueError,
        },
        {
            "id_str": "OK: WS port number",
            "remove": {},
            "replace": {Sections.SERVER: {"websocket_port": "9001"}},
        },  # None error as parse int
        {
            "id_str": "Error: No workspaces",
            "remove": {Sections.SERVER: ["workspaces"]},
            "replace": {},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: agent token length",
            "remove": {},
            "replace": {Sections.TOKENS: {"agent": "invalid_token"}},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: agent token length (after strip)",
            "remove": {},
            "replace": {
                Sections.TOKENS: {"agent": "   46aasdje446aasdje446aa46aasdje446aasdje446aa46aasdje446aasdje"}
            },
            "expected_exception": ValueError,
        },
        {
            "id_str": "OK: agent token",
            "remove": {},
            "replace": {
                Sections.TOKENS: {"agent": "QWE46aasdje446aasdje446aaQWE46aasdje446aasdje446aaQWE46aasdje446"}
            },
        },
        {
            "id_str": "OK: executor without cmd",
            "remove": {Sections.EXECUTOR_DATA.format("ex1"): ["cmd"]},
            "replace": {},
        },
        {
            "id_str": "Error: executor max_size port not number",
            "remove": {},
            "replace": {Sections.EXECUTOR_DATA.format("ex1"): {"max_size": "ASDASD"}},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: executor param not bool (str)",
            "remove": {},
            "replace": {Sections.EXECUTOR_PARAMS.format("ex1"): {"param1": "ASDASD"}},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: executor param not bool (number)",
            "remove": {},
            "replace": {Sections.EXECUTOR_PARAMS.format("ex1"): {"param1": "5"}},
            "expected_exception": ValueError,
        },
        {
            "id_str": "OK: executor param is bool",
            "remove": {},
            "replace": {Sections.EXECUTOR_PARAMS.format("ex1"): {"param1": "True"}},
        },
        {
            "id_str": "Error: No agent_name",
            "remove": {Sections.AGENT: ["agent_name"]},
            "replace": {},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: executor repeated",
            "remove": {},
            "replace": {Sections.AGENT: {"executors": "ex1,ex1"}},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: No agent section",
            "remove": {Sections.AGENT: ["section"]},
            "replace": {},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: No server section",
            "remove": {Sections.SERVER: ["section"]},
            "replace": {},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: Duplicated section",
            "remove": {},
            "replace": {},
            "duplicate_exception": True,
            "expected_exception": ValueError,
        },
        {
            "id_str": "OK: different executors (mid-split)",
            "remove": {},
            "replace": {Sections.AGENT: {"executors": "ex1, ex2"}},
        },
        {
            "id_str": "OK: different executors (end-split)",
            "remove": {},
            "replace": {Sections.AGENT: {"executors": "ex1,ex2 "}},
        },
        {
            "id_str": "OK: different executors (begin-split)",
            "remove": {},
            "replace": {Sections.AGENT: {"executors": " ex1,ex2"}},
        },
        {
            "id_str": "OK: different executors (mid-split)",
            "remove": {},
            "replace": {Sections.AGENT: {"executors": " ex1, ex2 , ex3"}},
        },
        {
            "id_str": "Error: different executors (spaced name)",
            "remove": {},
            "replace": {Sections.AGENT: {"executors": "ex1,ex 1"}},
            "expected_exception": ValueError,
        },
        {
            "id_str": "Error: Executor not configured",
            "remove": {},
            "replace": {Sections.AGENT: {"executors": "ex1,ex8"}},
            "expected_exception": ValueError,
        },
        {"id_str": "OK: All default", "remove": {}, "replace": {}},
        {
            "id_str": "Error: ssl crt do not exists",
            "remove": {},
            "replace": {Sections.SERVER: {"ssl": "True", "ssl_cert": "/tmp/sarasa.pub"}},
            "expected_exception": ValueError,
        },
    ]


def generate_register_options():
    return [
        {
            "id_str": "Bad registration token",
            "bad_registration_token": "Bad",
            "replace_data": {},
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "token must be 6 character length",
                },
            ],
            "expected_exception": SystemExit,
        },
        {
            "id_str": "Bad format registration token",
            "bad_registration_token": "bad format",
            "replace_data": {},
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "token must be a number",
                },
            ],
            "expected_exception": SystemExit,
        },
        {
            "id_str": "Incorrect registration token",
            "bad_registration_token": "incorrect",
            "replace_data": {},
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "Invalid registration token, please reset and retry. "
                    "If the error persist, you should try to edit the "
                    "registration token with the wizard command "
                    "`faraday-dispatcher config-wizard`",
                },
            ],
            "expected_exception": SystemExit,
        },
        {
            "id_str": "No registration token",
            "bad_registration_token": None,
            "replace_data": {},
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "No connected before, provide a token. For more help see `faraday-dispatcher run --help`",
                },
            ],
            "expected_exception": SystemExit,
        },
        {
            "id_str": "Bad agent token",
            "replace_data": {
                Sections.TOKENS: {"agent": "QWE46aasdje446aasdje446aaQWE46aasdje446aasdje446aaQWE46aasdje446"}
            },
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "Invalid agent token, please reset and retry. "
                    "If the error persist, you should remove the "
                    "agent token with the wizard command "
                    "`faraday-dispatcher config-wizard`",
                },
            ],
            "expected_exception": SystemExit,
        },
        {
            "id_str": "OK",
            "replace_data": {},
            "logs": [
                {"levelname": "INFO", "msg": "Registered successfully"},
            ],
        },
        {
            "id_str": "Non-existent host",
            "replace_data": {Sections.SERVER: {"host": "cizfyteurbsc06aolxe0qtzsr2mftvy7bwvvd47e.com"}},
            "logs": [
                {"levelname": "ERROR", "msg": "Can not connect to Faraday server"},
            ],
            "expected_exception": SystemExit,
        },
        # 5 SSL to port with http
        {
            "id_str": "Trying SSL over HTTP",
            "replace_data": {
                Sections.SERVER: {
                    "ssl": "True",
                }
            },
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "Faraday server timed-out. TIP: Check ssl configuration",
                },
                {"levelname": "DEBUG", "msg": "Timeout error. Check ssl"},
            ],
            "optional_logs": [
                {"levelname": "DEBUG", "msg": "Invalid SSL Certificate"},
            ],
            "use_ssl": False,
            "expected_exception": SystemExit,
        },
        {
            "id_str": "Wrong SSL crt",
            "replace_data": {
                Sections.SERVER: {
                    "ssl": "True",
                    "ssl_cert": str(Path(__file__).parent.parent.parent / "data" / "wrong.crt"),
                }
            },
            "logs": [
                {"levelname": "DEBUG", "msg": "Invalid SSL Certificate"},
            ],
            "optional_logs": [
                {"levelname": "ERROR", "msg": "Can not connect to Faraday server"},
            ],
            "use_ssl": True,
            "expected_exception": SystemExit,
        },
        {
            "id_str": "Bad host within SSL cert",
            "replace_data": {
                Sections.SERVER: {
                    "host": "127.0.0.1",
                    "ssl": "True",
                    "ssl_cert": str(Path(__file__).parent.parent.parent / "data" / "ok.crt"),
                }
            },
            "logs": [
                {"levelname": "DEBUG", "msg": "Invalid SSL Certificate"},
            ],
            "use_ssl": True,
            "expected_exception": SystemExit,
        },
    ]


def generate_executor_options():
    return [
        {
            "id_str": "No action in ws",
            "data": {"agent_id": 1},
            "logs": [
                {"levelname": "INFO", "msg": "Data not contains action to do"},
            ],
            "ws_responses": [{"error": "'action' key is mandatory in this websocket connection"}],
        },
        {
            "id_str": "Bad action in ws",
            "data": {"action": "CUT", "agent_id": 1},
            "logs": [
                {"levelname": "INFO", "msg": "Unrecognized action"},
            ],
            "ws_responses": [{"CUT_RESPONSE": "Error: Unrecognized action"}],
        },
        {
            "id_str": "No execution id in ws",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Data not contains execution id"},
            ],
            "ws_responses": [{"error": "'execution_id' key is mandatory in this websocket connection"}],
        },
        {
            "id_str": "OK",
            "data": {
                "action": "RUN",
                "execution_id": 1,
                "agent_id": 1,
                "executor": "ex1",
                "workspace": "{}",
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {"levelname": "INFO", "msg": "Data sent to bulk create"},
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "OK, but extra data log (N json in 1 line)",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "execution_id": 1,
                "workspace": "{}",
                "args": {"out": "json", "count": "5"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {"levelname": "ERROR", "msg": "JSON Parsing error: Extra data"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "OK (N json in N lines)",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "execution_id": 1,
                "workspace": "{}",
                "args": {"out": "json", "count": "5", "spare": "T"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 5,
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "OK (\n before the data)",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "execution_id": 1,
                "workspace": "{}",
                "executor": "ex1",
                "args": {"out": "json", "spaced_before": "T"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "OK, just 1 (1 json + 2\n + N-1 in N-1 line)",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "execution_id": 1,
                "workspace": "{}",
                "args": {
                    "out": "json",
                    "spaced_middle": "T",
                    "count": "5",
                    "spare": "T",
                },
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 1,
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "Error in data sent to the server",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "execution_id": 1,
                "workspace": "{}",
                "executor": "ex1",
                "args": {"out": "bad_json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {
                    "levelname": "ERROR",
                    "msg": "Invalid data supplied by the executor to the bulk create endpoint. Server responded: ",
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "Send str, not JSON",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "execution_id": 1,
                "executor": "ex1",
                "args": {"out": "str"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {"levelname": "ERROR", "msg": "JSON Parsing error: Expecting value"},
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "Bad parameter and error log",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "execution_id": 1,
                "workspace": "{}",
                "args": {"out": "none", "err": "T"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {"levelname": "DEBUG", "msg": "Print by stderr"},
                {"levelname": "DEBUG", "msg": "unexpected value in out parameter"},
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "Bad parameter and failing executor",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "workspace": "{}",
                "execution_id": 1,
                "args": {"out": "none", "fails": "T"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {
                    "levelname": "WARNING",
                    "msg": "Executor ex1 finished with exit code 1",
                },
                {"levelname": "DEBUG", "msg": "unexpected value in out parameter"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": False,
                    "message": "Executor ex1 from unnamed_agent failed",
                },
            ],
        },
        {
            "id_str": "Bad parameter, error log and failed executor",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "none", "err": "T", "fails": "T"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {"levelname": "DEBUG", "msg": "Print by stderr"},
                {"levelname": "DEBUG", "msg": "unexpected value in out parameter"},
                {
                    "levelname": "WARNING",
                    "msg": "Executor ex1 finished with exit code 1",
                },
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": False,
                    "message": "Executor ex1 from unnamed_agent failed",
                },
            ],
        },
        {
            "id_str": "Var env effect",  # TODO check the print to STDERR
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 0,
                    "min_count": 0,
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "varenvs": {"DO_NOTHING": "True"},
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "Missing mandatory argument",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "execution_id": 1,
                "executor": "ex1",
                "args": {"err": "T", "fails": "T"},
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0,
                },
                {"levelname": "ERROR", "msg": "Mandatory argument not passed"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": False,
                    "message": "Mandatory argument(s) not passed to ex1 executor from unnamed_agent agent",
                }
            ],
        },
        {
            "id_str": "Extra parameter",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "workspace": "{}",
                "execution_id": 1,
                "args": {"out": "json", "WTF": "T"},
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0,
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 0,
                    "min_count": 0,
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully",
                    "max_count": 0,
                    "min_count": 0,
                },
                {"levelname": "ERROR", "msg": "Unexpected argument passed"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": False,
                    "message": "Unexpected argument(s) passed to ex1 executor from unnamed_agent agent",
                }
            ],
        },
        {
            "id_str": "Server response: 500",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "execution_id": 1,
                "executor": "ex1",
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "ERROR",
                    "msg": "Invalid data supplied by the executor to the bulk create endpoint. Server responded: ",
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "workspaces": "error500",
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "Server response: 429",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "execution_id": 1,
                "workspace": "{}",
                "executor": "ex1",
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "ERROR",
                    "msg": "Invalid data supplied by the executor to the bulk create endpoint. Server responded: ",
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "workspaces": "error429",
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "Bad configuration over data size",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "execution_id": 1,
                "executor": "ex1",
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {
                    "levelname": "ERROR",
                    "msg": "ValueError raised processing stdout, try with bigger limiting size in config",
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "max_size": "1",
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
        {
            "id_str": "No executor selected",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "execution_id": 1,
                "args": {"out": "json"},
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0,
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 0,
                    "min_count": 0,
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully",
                    "max_count": 0,
                    "min_count": 0,
                },
                {"levelname": "ERROR", "msg": "No executor selected"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "execution_id": 1,
                    "running": False,
                    "message": "No executor selected to unnamed_agent agent",
                }
            ],
        },
        {
            "id_str": "Bad executor name",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "execution_id": 1,
                "executor": "NOT_4N_CORRECT_EXECUTOR",
                "args": {"out": "json"},
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0,
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 0,
                    "min_count": 0,
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully",
                    "max_count": 0,
                    "min_count": 0,
                },
                {"levelname": "ERROR", "msg": "The selected executor not exists"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "NOT_4N_CORRECT_EXECUTOR",
                    "execution_id": 1,
                    "running": False,
                    "message": "The selected executor NOT_4N_CORRECT_EXECUTOR not exists in unnamed_agent agent",
                }
            ],
        },
        {
            "id_str": "OK, running other executor",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "workspace": "{}",
                "execution_id": 1,
                "executor": "add_ex1",
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running add_ex1 executor"},
                {"levelname": "INFO", "msg": "Data sent to bulk create"},
                {"levelname": "INFO", "msg": "Executor add_ex1 finished successfully"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "add_ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running add_ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "add_ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor add_ex1 from unnamed_agent finished successfully",
                },
            ],
            "extra": ["add_ex1"],
        },
        {
            "id_str": "Not workspace selected",
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "execution_id": 1,
                "executor": "ex1",
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Data not contains workspace name"},
            ],
            "ws_responses": [{"error": "'workspace' key is mandatory in this websocket connection"}],
        },
        {
            "id_str": "JUST in WS wrong workspace",
            "data": {
                "action": "RUN",
                "execution_id": 1,
                "agent_id": 1,
                "executor": "ex1",
                "workspace": "asd{}",
                "args": {"out": "json"},
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0,
                },
                {"levelname": "ERROR", "msg": "Invalid workspace passed"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "execution_id": 1,
                    "running": False,
                    "message": "Invalid workspace passed to unnamed_agent agent",
                }
            ],
        },
        {
            "id_str": "Post to other workspace",
            "data": {
                "action": "RUN",
                "execution_id": 1,
                "agent_id": 1,
                "executor": "ex1",
                "workspace": "{}",
                "args": {"out": "json"},
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0,
                },
                {
                    "levelname": "ERROR",
                    "msg": "Invalid data supplied by the executor to the bulk create endpoint. Server responded: ",
                },
                {"levelname": "INFO", "msg": "Executor ex1 finished successfully"},
            ],
            "workspaces": "other_workspace",
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent",
                },
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished successfully",
                },
            ],
        },
    ]


def get_merge_executors():
    return [
        {"executor_name": "ex1", "args": {"param1": True, "param2": False}},
        {"executor_name": "ex2", "args": {"port_list": True, "target": True}},
        {"executor_name": "ex3", "args": {"param3": False, "param4": False}},
        {"executor_name": "ex4", "args": {}},
    ]
