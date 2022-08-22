import json
import os
from pathlib import Path
import subprocess

import pytest


# Executors not tested:
# * burp: it's an API
# * crackmapexec: it's for insecure AD, unavailable at CI test timing
# * nessus: it's an API
# * openvas: it's an API + to be fixed
# * report_procesor: it just uses faraday_plugin
# * w3af: py2
# * wpscan: actually uses docker
# * zap: it's an API


executors_to_test = [
    {
        "name": "arachni",
        "script": "arachni.py",
        "varenvs": {
            "ARACHNI_PATH": "/usr/local/src/arachni/bin",
            "EXECUTOR_CONFIG_NAME_URL": "www.scanme.org",
        },
    },
    {
        "name": "nikto2",
        "script": "nikto2.py",
        "varenvs": {"EXECUTOR_CONFIG_TARGET_URL": "http://www.scanme.org"},
    },
    {
        "name": "nmap",
        "script": "nmap.py",
        "varenvs": {"EXECUTOR_CONFIG_TARGET": "www.scanme.org"},
    },
    {
        "name": "complex_nmap",
        "script": "nmap.py",
        "varenvs": {
            "EXECUTOR_CONFIG_TARGET": "www.scanme.org",
            "EXECUTOR_CONFIG_PORT_LIST": "1-100",
            "EXECUTOR_CONFIG_OPTION_SC": "True",
            "EXECUTOR_CONFIG_OPTION_SV": "True",
            "EXECUTOR_CONFIG_OPTION_PN": "True",
        },
    },
    {
        "name": "sublist3r",
        "cmd": "bash",
        "script": "sublist3r.sh",
        "varenvs": {"EXECUTOR_CONFIG_DOMAIN": "hack.me"},
    },
    {
        "name": "nuclei",
        "script": "nuclei.py",
        "varenvs": {
            "NUCLEI_TEMPLATES": "/usr/local/src/nuclei" "/v2/cmd/nuclei/nuclei-templates",
            "EXECUTOR_CONFIG_NUCLEI_TARGET": "www.scanme.org",
        },
    },
    {
        "name": "nuclei_multi",
        "script": "nuclei.py",
        "varenvs": {
            "NUCLEI_TEMPLATES": "/usr/local/src/nuclei" "/v2/cmd/nuclei/nuclei-templates",
            "EXECUTOR_CONFIG_NUCLEI_TARGET": "www.scanme.org," "https://grafana.faradaysec.com",
        },
    },
    {
        "name": "nuclei_exclude",
        "script": "nuclei.py",
        "varenvs": {
            "NUCLEI_TEMPLATES": "/usr/local/src/nuclei/v2/cmd/nuclei" "/nuclei-templates",
            "EXECUTOR_CONFIG_NUCLEI_TARGET": "www.scanme.org",
            "NUCLEI_EXCLUDE": "files/",
        },
    },
]

executors_path = Path(__file__).parent.parent.parent / "faraday_agent_dispatcher" / "static" / "executors" / "official"


def sort_dict_multilevel(value):
    if isinstance(value, dict):
        value = dict(sorted(value.items()))
        for k in value.keys():
            value[k] = sort_dict_multilevel(value[k])
    if isinstance(value, list):
        if len(value) > 0 and not isinstance(value[0], (list, dict)):
            value = sorted(value)
        else:
            value = [sort_dict_multilevel(v) for v in value]
    return value


@pytest.mark.parametrize("executor_data", executors_to_test, ids=lambda i: i["name"])
def test_executors(executor_data):
    script = executor_data["script"]
    env = os.environ.copy()
    for key in executor_data["varenvs"]:
        env[key] = str(executor_data["varenvs"][key])
    cmd = "python3" if "cmd" not in executor_data else executor_data["cmd"]
    process = subprocess.run(
        [cmd, str(executors_path / f"{script}")],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    responses_list = [json.loads(json_elem) for json_elem in process.stdout.decode().split("\n") if len(json_elem) > 0]
    for response in responses_list:
        assert "hosts" in response, response
    responses_list = [sort_dict_multilevel(response["hosts"]) for response in responses_list]
    assert len(responses_list) > 0
