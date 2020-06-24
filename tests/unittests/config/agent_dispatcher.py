from pathlib import Path

from faraday_agent_dispatcher.config import Sections


def generate_basic_built_config():
    return [
               {
                   "remove": {Sections.SERVER: ["host"]},
                   "replace": {},
                   "expected_exception": ValueError},
               {
                   "remove": {Sections.SERVER: ["api_port"]},
                   "replace": {},
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.SERVER: {
                           "api_port": "Not a port number"
                       }
                   },
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.SERVER: {
                           "api_port": "6000"}
                   }
               },  # None error as parse int
               {
                   "remove": {
                       Sections.SERVER: ["websocket_port"]
                   },
                   "replace": {},
                   "expected_exception": ValueError},
               {
                   "remove": {},
                   "replace": {
                       Sections.SERVER: {
                           "websocket_port": "Not a port number"
                       }
                   },
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.SERVER: {
                           "websocket_port": "9001"
                       }
                   }
               },  # None error as parse int
               {
                   "remove": {Sections.SERVER: ["workspace"]},
                   "replace": {},
                   "expected_exception": ValueError
               },
               {
                   "remove": {Sections.TOKENS: ["registration"]},
                   "replace": {},
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.TOKENS: {
                           "registration": "invalid_token"
                       }
                   },
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.TOKENS: {
                           "registration": "   46aasdje446aasdje"
                                           "446aa"
                       }
                   },
                   "expected_exception": ValueError},
               {
                   "remove": {},
                   "replace": {
                       Sections.TOKENS: {
                           "registration": "QWE46aasdje446aasdje"
                                           "446aa"
                       }
                   }
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.TOKENS: {
                           "agent": "invalid_token"
                       }
                   },
                   "expected_exception": ValueError},
               {
                   "remove": {},
                   "replace": {
                       Sections.TOKENS: {
                           "agent": "   46aasdje446aasdje"
                                    "446aa46aasdje446aasd"
                                    "je446aa46aasdje446aa"
                                    "sdje"
                       }
                   },
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.TOKENS: {
                           "agent": "QWE46aasdje446aasdje"
                                    "446aaQWE46aasdje446a"
                                    "asdje446aaQWE46aasdj"
                                    "e446"
                       }
                   }
               },
               {
                   "remove": {
                       Sections.EXECUTOR_DATA.format("ex1"):
                           ["cmd"]
                   },
                   "replace": {}
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.EXECUTOR_DATA.format("ex1"):
                           {"max_size": "ASDASD"}
                   },
                   "expected_exception": ValueError},
               {
                   "remove": {},
                   "replace": {
                       Sections.EXECUTOR_PARAMS.format("ex1"):
                           {"param1": "ASDASD"}
                   },
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.EXECUTOR_PARAMS.format("ex1"):
                           {"param1": "5"}
                   },
                   "expected_exception": ValueError},
               {
                   "remove": {},
                   "replace": {
                       Sections.EXECUTOR_PARAMS.format("ex1"):
                           {"param1": "True"}
                   }
               },
               {
                   "remove": {Sections.AGENT: ["agent_name"]},
                   "replace": {},
                   "expected_exception": ValueError},
               {
                   "remove": {},
                   "replace": {
                       Sections.AGENT: {"executors": "ex1,ex1"}
                   },
                   "expected_exception": ValueError
               },
               {
                   "remove": {Sections.AGENT: ["section"]},
                   "replace": {},
                   "expected_exception": ValueError
               },
               {
                   "remove": {Sections.TOKENS: ["section"]},
                   "replace": {},
                   "expected_exception": ValueError
               },
               {
                   "remove": {Sections.SERVER: ["section"]},
                   "replace": {},
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {},
                   "duplicate_exception": True,
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.AGENT:
                           {"executors": "ex1, ex2"}
                   },
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.AGENT: {"executors": "ex1,ex2 "}
                   },
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.AGENT: {"executors": " ex1,ex2"}
                   },
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.AGENT: {
                           "executors": " ex1, ex2 , ex3"
                       }
                   },
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.AGENT:
                           {"executors": "ex1,ex 1"}
                   },
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {
                       Sections.AGENT: {
                           "executors": "ex1,ex8"
                       }
                   },
                   "expected_exception": ValueError
               },
               {
                   "remove": {},
                   "replace": {}
               },
               # X SSL cert is not an existent file
               {
                   "remove": {},
                   "replace": {
                       Sections.SERVER: {
                           "ssl": "True",
                           "ssl_cert": "/tmp/sarasa.pub"
                       }
                   },
                   "expected_exception": ValueError
               },
           ]


def generate_register_options():
    return [
        # 0
        {
            "replace_data": {Sections.TOKENS: {"registration": "NotOk" * 5}},
            "logs": [
                {"levelname": "ERROR",
                 "msg":
                     "Invalid registration token, please reset and retry. "
                     "If the error persist, you should try to edit the "
                     "registration token with the wizard command "
                     "`faraday-dispatcher config-wizard`"
                 },
            ],
            "use_ssl_server": False,
            "expected_exception": SystemExit
        },
        # 1
        {
            "replace_data": {
                Sections.TOKENS: {
                    "agent":
                        "QWE46aasdje446aasdje446aaQWE46aasdje446aasdje446aa"
                        "QWE46aasdje446"
                }
            },
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "Invalid agent token, please reset and retry. "
                           "If the error persist, you should remove the "
                           "agent token with the wizard command "
                           "`faraday-dispatcher config-wizard`"
                },
            ],
            "use_ssl_server": False,
            "expected_exception": SystemExit
        },
        # 2
        {
            "replace_data": {},
            "logs": [
                {"levelname": "INFO", "msg": "Registered successfully"},
            ],
            "use_ssl_server": False,
        },
        # 3 OK SSL
        {
            "replace_data": {
                Sections.SERVER: {
                    "host": "localhost",
                    "ssl": "True",
                    "ssl_cert": str(
                        Path(__file__).parent.parent.parent / 'data' / 'ok.crt'
                    )
                }
            },
            "logs": [
                {"levelname": "INFO", "msg": "Registered successfully"},
            ],
            "use_ssl_server": True,
        },
        # 4 Cannot conect
        {
            "replace_data": {
                Sections.SERVER: {
                    "host": "cizfyteurbsc06aolxe0qtzsr2mftvy7bwvvd47e.com"
                }
            },
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "Can not connect to Faraday server"
                },
            ],
            "use_ssl_server": False,
            "expected_exception": SystemExit
        },
        # 5 SSL to port with http
        {
            "replace_data": {
                Sections.SERVER: {
                    "ssl": "True",
                }
            },
            "logs": [
                {
                    "levelname": "ERROR",
                    "msg": "Faraday server timed-out. "
                           "TIP: Check ssl configuration"
                },
                {
                    "levelname": "DEBUG",
                    "msg": "Timeout error. Check ssl"
                },
            ],
            "optional_logs": [
                {"levelname": "DEBUG", "msg": "Invalid SSL Certificate"},
            ],
            "use_ssl_server": False,
            "expected_exception": SystemExit
        },
        # 6 Invalid SSL
        {
            "replace_data": {
                Sections.SERVER: {
                    "host": "localhost",
                    "ssl": "True",
                    "ssl_cert": str(
                        Path(__file__).parent.parent.parent
                        / 'data'
                        / 'wrong.crt'
                    )
                }
            },
            "logs": [
                {"levelname": "DEBUG", "msg": "Invalid SSL Certificate"},
            ],
            "use_ssl_server": True,
            "expected_exception": SystemExit
        },
        # 7 Correct SSL but to 127.0.0.1, not to localhost
        {
            "replace_data": {
                Sections.SERVER: {
                    "ssl": "True",
                    "ssl_cert": str(
                        Path(__file__).parent.parent.parent
                        / 'data'
                        / 'ok.crt'
                    )
                }
            },
            "logs": [
                {"levelname": "DEBUG", "msg": "Invalid SSL Certificate"},
            ],
            "use_ssl_server": True,
            "expected_exception": SystemExit
        }
    ]


def generate_executor_options():
    return [
        {  # 0
            "data": {"agent_id": 1},
            "logs": [
                {"levelname": "INFO", "msg": "Data not contains action to do"},
            ],
            "ws_responses": [
                {
                    "error": "'action' key is mandatory in this websocket "
                             "connection"
                }
            ]
        },
        {  # 1
            "data": {"action": "CUT", "agent_id": 1},
            "logs": [
                {"levelname": "INFO", "msg": "Unrecognized action"},
            ],
            "ws_responses": [
                {"CUT_RESPONSE": "Error: Unrecognized action"}
            ]
        },
        {  # 2
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "args": {"out": "json"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Data not contains execution id"},
            ],
            "ws_responses": [
                {
                    "error": "'execution_id' key is mandatory in this "
                             "websocket connection"
                }
            ]
        },
        {  # 3
            "data": {"action": "RUN",
                     "execution_id": 1,
                     "agent_id": 1,
                     "executor": "ex1",
                     "args": {"out": "json"}},
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {"levelname": "INFO", "msg": "Data sent to bulk create"},
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 4
            "data": {
                "action": "RUN", "agent_id": 1, "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "json", "count": "5"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "ERROR",
                    "msg": "JSON Parsing error: Extra data"
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 5
            "data": {
                "action": "RUN", "agent_id": 1, "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "json", "count": "5", "spare": "T"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 5
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 6
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "execution_id": 1,
                "executor": "ex1",
                "args": {"out": "json", "spaced_before": "T"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 7
            "data": {
                "action": "RUN", "agent_id": 1, "executor": "ex1",
                "execution_id": 1,
                "args": {
                    "out": "json",
                    "spaced_middle": "T",
                    "count": "5",
                    "spare": "T"
                }
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 1
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 8
            "data": {
                "action": "RUN", "agent_id": 1,
                "execution_id": 1,
                "executor": "ex1", "args": {"out": "bad_json"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0
                },
                {
                    "levelname": "ERROR",
                    "msg": "Invalid data supplied by the executor to the bulk"
                           " create endpoint. Server responded: "},
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 9
            "data": {
                "action": "RUN", "agent_id": 1,
                "execution_id": 1,
                "executor": "ex1", "args": {"out": "str"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0
                },
                {
                    "levelname": "ERROR",
                    "msg": "JSON Parsing error: Expecting value"
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 10
            "data": {
                "action": "RUN", "agent_id": 1, "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "none", "err": "T"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0
                },
                {"levelname": "DEBUG", "msg": "Print by stderr"},
                {
                    "levelname": "DEBUG",
                    "msg": "unexpected value in out parameter"
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 11
            "data": {
                "action": "RUN", "agent_id": 1, "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "none", "fails": "T"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0
                },
                {
                    "levelname": "WARNING",
                    "msg": "Executor ex1 finished with exit code 1"
                },
                {
                    "levelname": "DEBUG",
                    "msg": "unexpected value in out parameter"
                },
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": False,
                    "message": "Executor ex1 from unnamed_agent failed"
                }
            ]
        },
        {  # 12
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "none", "err": "T", "fails": "T"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0
                },
                {"levelname": "DEBUG", "msg": "Print by stderr"},
                {
                    "levelname": "DEBUG",
                    "msg": "unexpected value in out parameter"
                },
                {
                    "levelname": "WARNING",
                    "msg": "Executor ex1 finished with exit code 1"
                },
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": False,
                    "message": "Executor ex1 from unnamed_agent failed"
                }
            ]
        },
        {  # 13
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "json"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "varenvs": {"DO_NOTHING": "True"},
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 14
            "data": {
                "action": "RUN",
                "agent_id": 1,
                "execution_id": 1,
                "executor": "ex1",
                "args": {"err": "T", "fails": "T"},
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0},
                {"levelname": "ERROR", "msg": "Mandatory argument not passed"},
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": False,
                    "message": "Mandatory argument(s) not passed to ex1 "
                               "executor from unnamed_agent agent"
                }
            ]
        },
        {  # 15
            "data": {
                "action": "RUN", "agent_id": 1, "executor": "ex1",
                "execution_id": 1,
                "args": {"out": "json", "WTF": "T"}
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 0,
                    "min_count": 0},
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "ERROR",
                    "msg": "Unexpected argument passed"
                },
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": False,
                    "message": "Unexpected argument(s) passed to ex1 executor "
                               "from unnamed_agent agent"
                }
            ]
        },
        {  # 16
            "data": {
                "action": "RUN", "agent_id": 1,
                "execution_id": 1,
                "executor": "ex1", "args": {"out": "json"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "ERROR",
                    "msg": "Invalid data supplied by the executor to the bulk "
                           "create endpoint. Server responded: "
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0},
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "workspace": "error500",
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 17
            "data": {
                "action": "RUN", "agent_id": 1,
                "execution_id": 1,
                "executor": "ex1", "args": {"out": "json"}
            },
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "ERROR",
                    "msg": "Invalid data supplied by the executor to the "
                           "bulk create endpoint. Server responded: "},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0},
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "workspace": "error429",
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 18
            "data": {"action": "RUN", "agent_id": 1,
                     "execution_id": 1,
                     "executor": "ex1", "args": {"out": "json"}},
            "logs": [
                {"levelname": "INFO", "msg": "Running ex1 executor"},
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "min_count": 0,
                    "max_count": 0
                },
                {
                    "levelname": "ERROR",
                    "msg": "ValueError raised processing stdout, try with "
                           "bigger limiting size in config"},
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully"
                }
            ],
            "max_size": "1",
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running ex1 executor from unnamed_agent agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor ex1 from unnamed_agent finished "
                               "successfully"
                }
            ]
        },
        {  # 19
            "data": {
                "action": "RUN", "agent_id": 1,
                "execution_id": 1,
                "args": {"out": "json"}
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "ERROR",
                    "msg": "No executor selected"
                },
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "execution_id": 1,
                    "running": False,
                    "message": "No executor selected to unnamed_agent agent"
                }
            ]
        },
        {  # 20
            "data": {
                "action": "RUN", "agent_id": 1,
                "execution_id": 1,
                "executor": "NOT_4N_CORRECT_EXECUTOR",
                "args": {"out": "json"}
            },
            "logs": [
                {
                    "levelname": "INFO",
                    "msg": "Running ex1 executor",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "INFO",
                    "msg": "Data sent to bulk create",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "INFO",
                    "msg": "Executor ex1 finished successfully",
                    "max_count": 0,
                    "min_count": 0
                },
                {
                    "levelname": "ERROR",
                    "msg": "The selected executor not exists"
                },
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "NOT_4N_CORRECT_EXECUTOR",
                    "execution_id": 1,
                    "running": False,
                    "message": "The selected executor NOT_4N_CORRECT_EXECUTOR "
                               "not exists in unnamed_agent agent"}
            ]
        },
        {  # 21
            "data": {"action": "RUN", "agent_id": 1,
                     "execution_id": 1,
                     "executor": "add_ex1", "args": {"out": "json"}},
            "logs": [
                {"levelname": "INFO", "msg": "Running add_ex1 executor"},
                {"levelname": "INFO", "msg": "Data sent to bulk create"},
                {
                    "levelname": "INFO",
                    "msg": "Executor add_ex1 finished successfully"
                }
            ],
            "ws_responses": [
                {
                    "action": "RUN_STATUS",
                    "executor_name": "add_ex1",
                    "execution_id": 1,
                    "running": True,
                    "message": "Running add_ex1 executor from unnamed_agent "
                               "agent"
                }, {
                    "action": "RUN_STATUS",
                    "executor_name": "add_ex1",
                    "execution_id": 1,
                    "successful": True,
                    "message": "Executor add_ex1 from unnamed_agent finished "
                               "successfully"
                }
            ],
            "extra": ["add_ex1"]
        },
    ]


def connect_ws_responses(workspace):
    return [{
        'action': 'JOIN_AGENT',
        'workspace': workspace,
        'token': None,
        'executors': [
            {
                "executor_name": "ex1",
                "args": {
                    "param1": True,
                    "param2": False
                }
            },
            {
                "executor_name": "ex2",
                "args": {
                    "port_list": True,
                    "target": True
                }
            },
            {
                "executor_name": "ex3",
                "args": {
                    "param3": False,
                    "param4": False
                }
            },
            {
                "executor_name": "ex4",
                "args": {}
            }
        ]
    }]
