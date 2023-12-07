import tempfile

from faraday_agent_dispatcher.config import (
    instance as config,
    reset_config,
    Sections,
    save_config,
    EXAMPLE_CONFIG_FILENAME,
)

from faraday_agent_dispatcher.utils.url_utils import api_url

from tests.data.basic_executor import host_data, vuln_data
from tests.utils.text_utils import fuzzy_string
import os
from pathlib import Path
from requests import Session
import subprocess
import time

reset_config(EXAMPLE_CONFIG_FILENAME)
HOST = config[Sections.SERVER].get("host")
API_PORT = config[Sections.SERVER].get("api_port")
WS_PORT = config[Sections.SERVER].get("websocket_port")
# TODO FIX WHEN FARADAY ACCEPTS CAPITAL FIRST LETTER
WORKSPACE = fuzzy_string(6).lower()
AGENT_NAME = fuzzy_string(6)
EXECUTOR_NAME = fuzzy_string(6)
SSL = "false"

USER = os.getenv("FARADAY_USER")
EMAIL = os.getenv("FARADAY_EMAIL")
PASS = os.getenv("FARADAY_PASSWORD")

LOGGER_DIR = Path("./logs")

agent_ok_status_keys_set = {
    "create_date",
    "creator",
    "id",
    "name",
    "is_online",
    "active",
    "status",
    "update_date",
    "executors",
    "last_run",
}

agent_ok_status_dict = {
    "creator": None,
    "name": AGENT_NAME,
    "is_online": True,
    "active": True,
    "status": "online",
}


def test_execute_agent():
    session = Session()
    # Initial set up
    res = session.post(
        api_url(HOST, API_PORT, postfix="/_api/login"),
        json={"email": USER, "password": PASS},
    )
    assert res.status_code == 200, res.text
    res = session.get(api_url(HOST, API_PORT, postfix="/_api/v3/agents"))
    count = len(res.json())
    # session_res = session.get(api_url(HOST, API_PORT,
    # postfix="/_api/session"))
    res = session.post(
        api_url(HOST, API_PORT, postfix="/_api/v3/ws"),
        json={"name": WORKSPACE},
    )
    assert res.status_code == 201, res.text
    res = session.get(api_url(HOST, API_PORT, postfix="/_api/v3/agent_token"))
    assert res.status_code == 200, res.text
    token = res.json()["token"]

    # Config set up
    if Sections.TOKENS in config:
        config.pop(Sections.TOKENS)
    config[Sections.SERVER]["ssl"] = SSL
    config[Sections.AGENT]["agent_name"] = AGENT_NAME
    config[Sections.AGENT]["executors"][EXECUTOR_NAME] = {}
    path_to_basic_executor = Path(__file__).parent.parent.parent / "data" / "basic_executor.py"
    executor_section = config[Sections.AGENT]["executors"][EXECUTOR_NAME]
    executor_section["params"] = {
        "out": {"mandatory": True, "base": "string", "type": "string"},
        "count": {"mandatory": False, "base": "string", "type": "string"},
        "space": {"mandatory": False, "base": "string", "type": "string"},
        "spaced_before": {
            "mandatory": False,
            "base": "string",
            "type": "string",
        },
        "spaced_middle": {
            "mandatory": False,
            "base": "string",
            "type": "string",
        },
        "err": {"mandatory": False, "base": "string", "type": "string"},
        "fails": {"mandatory": False, "base": "string", "type": "string"},
    }
    executor_section["varenvs"] = {}
    executor_section["max_size"] = 65536
    executor_section["cmd"] = f"python {path_to_basic_executor}"

    with tempfile.TemporaryDirectory() as tempdirfile:
        config_pathfile = Path(tempdirfile)
        save_config(config_pathfile)

        # Init dispatcher!
        command = [
            "faraday-dispatcher",
            "run",
            f"--config-file={config_pathfile}",
            f"--logdir={LOGGER_DIR}",
            f"--token={token}",
            "--debug",
        ]
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)  # If fails check time

        # Checking dispatcher connection
        res = session.get(api_url(HOST, API_PORT, postfix="/_api/v3/agents"))
        assert res.status_code == 200, res.text
        res_data = res.json()
        assert len(res_data) == count + 1, p.communicate(timeout=0.1)
        agent = res_data[-1]
        agent_id = agent["id"]
        if agent_ok_status_keys_set != set(agent.keys()):
            print("Keys set from agent endpoint differ from expected ones, " "checking if its a superset")
            print(f"agent_ok_status_keys_set= {agent_ok_status_keys_set}")
            print(f"agent.keys() = {agent.keys()}")
            assert agent_ok_status_keys_set.issubset(set(agent.keys()))
        for key in agent_ok_status_dict:
            assert agent[key] == agent_ok_status_dict[key], [
                agent,
                agent_ok_status_dict,
            ]

        # Run executor!
        res = session.post(
            api_url(
                HOST,
                API_PORT,
                postfix=f'/_api/v3/agents/{agent["id"]}/run',
            ),
            json={
                # "csrf_token": session_res.json()["csrf_token"],
                "executor_data": {
                    "agent_id": agent_id,
                    "executor": EXECUTOR_NAME,
                    "args": {"out": "json"},
                },
                "workspaces_names": [WORKSPACE],
            },
        )
        assert res.status_code == 200, res.text
        command_id = res.json()["commands_id"][0]

        # Command ID should be in progress!
        res = session.get(
            api_url(
                HOST,
                API_PORT,
                postfix=f"/_api/v3/ws/{WORKSPACE}/commands/{command_id}",
            ),
        )
        assert res.status_code == 200, res.text
        command_check_response = res.json()
        assert command_check_response["import_source"] == "agent"
        assert command_check_response["duration"] == "In progress"

        time.sleep(3)  # If fails check time

        # Command ID should not be in progress!
        res = session.get(
            api_url(
                HOST,
                API_PORT,
                postfix=f"/_api/v3/ws/{WORKSPACE}/commands/{command_id}",
            ),
        )
        assert res.status_code == 200, res.text
        command_check_response = res.json()
        assert command_check_response["duration"] != "In progress"

        # Test results
        res = session.get(api_url(HOST, API_PORT, postfix=f"/_api/v3/ws/{WORKSPACE}/hosts"))
        host_dict = res.json()
        assert host_dict["count"] == 1, (res.text, host_dict)
        host = host_dict["rows"][0]["value"]
        for key in host_data:
            if key == "hostnames":
                assert set(host[key]) == set(host_data[key])
            else:
                assert host[key] == host_data[key]
        assert host["vulns"] == 1

        res = session.get(api_url(HOST, API_PORT, postfix=f"/_api/v3/ws/{WORKSPACE}/vulns"))
        vuln_dict = res.json()
        assert vuln_dict["count"] == 1
        vuln = vuln_dict["vulnerabilities"][0]["value"]
        for key in vuln_data:
            if key == "impact":
                for k_key in vuln["impact"]:
                    if k_key in vuln_data["impact"]:
                        assert vuln["impact"][k_key] == vuln_data["impact"][k_key]
                    else:
                        assert not vuln["impact"][k_key]
            else:
                assert vuln[key] == vuln_data[key]
        assert vuln["target"] == host_data["ip"]
