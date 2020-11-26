import json
import os
from pathlib import Path
import subprocess

import pytest

executors_to_test = [
    {"name": "nmap", "varenvs": {"EXECUTOR_CONFIG_PORT_LIST": "1-10000", "EXECUTOR_CONFIG_TARGET": "www.scanme.org"}}
]
executors_path = Path(__file__).parent.parent.parent / "faraday_agent_dispatcher" / "static" / "executors" / "official"


@pytest.mark.parametrize("executor_data", executors_to_test, ids=lambda i: i["name"])
def test_executors(executor_data, data_regression):
    name = executor_data["name"]
    env = os.environ.copy()
    for key in executor_data["varenvs"]:
        env[key] = str(executor_data["varenvs"][key])
    process = subprocess.run(
        ["python3", str(executors_path / f"{name}.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    response = json.loads(process.stdout.decode())
    data_regression.check(response["hosts"])
