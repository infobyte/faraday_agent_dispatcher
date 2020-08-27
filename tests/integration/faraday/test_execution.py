import tempfile

from faraday_agent_dispatcher.config import (
    instance as config,
    reset_config,
    Sections,
    save_config,
    EXAMPLE_CONFIG_FILENAME
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
HOST = config.get(Sections.SERVER, "host")
API_PORT = config.get(Sections.SERVER, "api_port")
WS_PORT = config.get(Sections.SERVER, "websocket_port")
# TODO FIX WHEN FARADAY ACCEPTS CAPITAL FIRST LETTER
WORKSPACE = fuzzy_string(6).lower()
AGENT_NAME = fuzzy_string(6)
EXECUTOR_NAME = fuzzy_string(6)
SSL = "false"

USER = os.getenv("FARADAY_USER")
EMAIL = os.getenv("FARADAY_EMAIL")
PASS = os.getenv("FARADAY_PASSWORD")

LOGGER_DIR = Path("./logs")

agent_ok_status_keys_set = {'create_date',
                            'creator',
                            'id',
                            'name',
                            'token',
                            'is_online',
                            'active',
                            'status',
                            'update_date'}

agent_ok_status_dict = {
    'creator': None,
    'name': AGENT_NAME,
    'is_online': True,
    'active': True,
    'status': 'online'
}


def test_execute_agent():
    session = Session()
    # Initial set up
    res = session.post(
        api_url(HOST, API_PORT, postfix='/_api/login'),
        json={'email': USER, 'password': PASS}
    )
    assert res.status_code == 200, res.text
    session_res = session.get(api_url(HOST, API_PORT, postfix='/_api/session'))
    res = session.post(
        api_url(HOST, API_PORT, postfix='/_api/v2/ws/'),
        json={'name': WORKSPACE}
    )
    assert res.status_code == 201, res.text
    res = session.get(api_url(HOST, API_PORT, postfix='/_api/v2/agent_token/'))
    assert res.status_code == 200, res.text
    token = res.json()['token']

    # Config set up
    config.set(Sections.TOKENS, "registration", token)
    config.remove_option(Sections.TOKENS, "agent")
    config.set(Sections.SERVER, "workspaces", WORKSPACE)
    config.set(Sections.SERVER, "ssl", SSL)
    config.set(Sections.AGENT, "agent_name", AGENT_NAME)
    config.set(Sections.AGENT, "executors", EXECUTOR_NAME)
    path_to_basic_executor = (
        Path(__file__).parent.parent.parent /
        'data' / 'basic_executor.py'
    )
    executor_section = Sections.EXECUTOR_DATA.format(EXECUTOR_NAME)
    params_section = Sections.EXECUTOR_PARAMS.format(EXECUTOR_NAME)
    for section in [executor_section, params_section]:
        if section not in config:
            config.add_section(section)

    config.set(
        Sections.EXECUTOR_DATA.format(EXECUTOR_NAME),
        "cmd",
        f"python {path_to_basic_executor}"
    )

    config.set(params_section, "out", "True")
    [config.set(params_section, param, "False") for param in [
        "count", "spare", "spaced_before", "spaced_middle", "err", "fails"]]

    with tempfile.TemporaryDirectory() as tempdirfile:
        config_pathfile = Path(tempdirfile)
        save_config(config_pathfile)

        # Init dispatcher!
        command = [
            'faraday-dispatcher',
            'run',
            f'--config-file={config_pathfile}',
            f'--logdir={LOGGER_DIR}'
        ]
        p = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(2)  # If fails check time

        # Checking dispatcher connection
        res = session.get(
            api_url(HOST, API_PORT, postfix=f'/_api/v2/ws/{WORKSPACE}/agents/')
        )
        assert res.status_code == 200, res.text
        res_data = res.json()
        assert len(res_data) == 1, p.communicate(timeout=0.1)
        agent = res_data[0]
        agent_id = agent["id"]
        if agent_ok_status_keys_set != set(agent.keys()):
            print(
                "Keys set from agent endpoint differ from expected ones, "
                "checking if its a superset"
            )
            assert agent_ok_status_keys_set.issubset(set(agent.keys()))
        for key in agent_ok_status_dict:
            assert agent[key] == agent_ok_status_dict[key], \
                [agent, agent_ok_status_dict]

        # Run executor!
        res = session.post(api_url(
            HOST,
            API_PORT,
            postfix=f'/_api/v2/ws/{WORKSPACE}/agents/{agent["id"]}/run/'),
            json={
                'csrf_token': session_res.json()['csrf_token'],
                'executorData': {
                    "agent_id": agent_id,
                    "executor": EXECUTOR_NAME,
                    "args": {"out": "json"}
                }
            })
        assert res.status_code == 200, res.text
        time.sleep(2)  # If fails check time

        # Test results
        res = session.get(
            api_url(
                HOST,
                API_PORT,
                postfix=f'/_api/v2/ws/{WORKSPACE}/hosts'
            )
        )
        host_dict = res.json()
        assert host_dict["total_rows"] == 1, (res.text, host_dict)
        host = host_dict["rows"][0]["value"]
        for key in host_data:
            if key == "hostnames":
                assert set(host[key]) == set(host_data[key])
            else:
                assert host[key] == host_data[key]
        assert host["vulns"] == 1

        res = session.get(
            api_url(HOST, API_PORT, postfix=f'/_api/v2/ws/{WORKSPACE}/vulns')
        )
        vuln_dict = res.json()
        assert vuln_dict["count"] == 1
        vuln = vuln_dict["vulnerabilities"][0]["value"]
        for key in vuln_data:
            if key == 'impact':
                for k_key in vuln['impact']:
                    if k_key in vuln_data['impact']:
                        assert vuln['impact'][k_key] == \
                               vuln_data['impact'][k_key]
                    else:
                        assert not vuln['impact'][k_key]
            else:
                assert vuln[key] == vuln_data[key]
        assert vuln["target"] == host_data['ip']
