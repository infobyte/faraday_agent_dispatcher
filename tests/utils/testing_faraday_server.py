import json
import os
import shutil
import ssl
from typing import Dict

import pytest
import random
import pathlib
from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.test_utils import TestClient, TestServer
from itsdangerous import TimestampSigner
import logging
from logging import StreamHandler
from faraday_agent_dispatcher.logger import get_logger, reset_logger
from queue import Queue
from pathlib import Path

from faraday_agent_dispatcher.config import (
    EXAMPLE_CONFIG_FILENAME,
    save_config,
    reset_config,
)

from tests.data.basic_executor import host_data, vuln_data
from tests.utils.text_utils import fuzzy_string


class FaradayTestConfig:
    def __init__(self, is_ssl: bool = False, has_base_route: bool = False):
        self.workspaces = [fuzzy_string(8) for _ in range(0, random.randint(2, 6))]
        self.registration_token = f"{random.randint(0, 999999):06}"
        self.agent_token = fuzzy_string(64)
        self.agent_id = random.randint(1, 1000)
        self.websocket_port = random.randint(1025, 65535)
        self.is_ssl = is_ssl
        self.ssl_cert_path = Path(__file__).parent.parent / "data"
        self.client = None
        self.base_route = f"{fuzzy_string(24)}" if has_base_route else None
        self.app_config = {
            "SECURITY_TOKEN_AUTHENTICATION_HEADER": "Authorization",
            "SECRET_KEY": "SECRET_KEY",
        }
        self.changes_queue = Queue()
        self.ws_data = {}

    def run_agent_to_websocket(self):
        self.changes_queue.put(
            {
                "agent_id": self.agent_id,
                "action": "RUN",
            }
        )

    async def generate_client(self):
        self.client = await self.aiohttp_faraday_client()

    async def aiohttp_faraday_client(self):
        app = web.Application()
        app.router.add_get(self.wrap_route("/_api/v3/info"), get_info(self))
        app.router.add_post(
            self.wrap_route("/_api/v3/agent_registration"),
            get_agent_registration(self),
        )
        app.router.add_post(
            self.wrap_route("/_api/v3/agent_websocket_token"),
            get_agent_websocket_token(self),
        )
        for workspace in self.workspaces:
            app.router.add_post(
                self.wrap_route(f"/_api/v3/ws/{workspace}/bulk_create"),
                get_bulk_create(self),
            )
        app.router.add_post(self.wrap_route("/_api/v3/ws/error500/bulk_create"), get_bulk_create(self))
        app.router.add_post(self.wrap_route("/_api/v3/ws/error429/bulk_create"), get_bulk_create(self))
        app.router.add_get(self.wrap_route("/websockets"), get_ws_handler(self))

        server = TestServer(app)
        server_params = {}
        if self.is_ssl:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.ssl_cert_path / "ok.crt", self.ssl_cert_path / "ok.key")
            server_params["ssl"] = ssl_context
        await server.start_server(**server_params)
        client = TestClient(server, raise_for_status=True)
        return client

    def wrap_route(self, route: str):
        if self.base_route is None:
            return f"{route}"
        return f"/{self.base_route}{route}"


def get_agent_registration(test_config: FaradayTestConfig):
    async def agent_registration(request: Request):
        data = await request.text()
        data = json.loads(data)
        if "token" not in data or data["token"] != test_config.registration_token:
            return web.HTTPUnauthorized()
        if "workspaces" not in data:
            return web.HTTPBadRequest()
        response_dict = {
            "name": data["name"],
            "token": test_config.agent_token,
            "id": test_config.agent_id,
        }
        return web.HTTPCreated(text=json.dumps(response_dict), headers={"content-type": "application/json"})

    return agent_registration


def verify_token(test_config, request):
    if test_config.app_config["SECURITY_TOKEN_AUTHENTICATION_HEADER"] not in request.headers:
        return web.HTTPUnauthorized()
    header = request.headers[test_config.app_config["SECURITY_TOKEN_AUTHENTICATION_HEADER"]]
    try:
        (auth_type, token) = header.split(None, 1)
    except ValueError:
        return web.HTTPUnauthorized()
    auth_type = auth_type.lower()
    if auth_type != "agent":
        return web.HTTPUnauthorized()
    if token != test_config.agent_token:
        return web.HTTPForbidden()


def get_agent_websocket_token(test_config: FaradayTestConfig):
    async def agent_websocket_token(request: web.Request):
        error = verify_token(test_config, request)
        if error:
            return error

        # ######### Sing and send
        signer = TimestampSigner(test_config.app_config["SECRET_KEY"], salt="websocket_agent")
        assert test_config.agent_id is not None
        test_config.ws_token = signer.sign(str(test_config.agent_id)).decode()
        response_dict = {"token": test_config.ws_token}
        return web.Response(text=json.dumps(response_dict), headers={"content-type": "application/json"})

    return agent_websocket_token


def get_info(_: FaradayTestConfig):
    async def info(_):
        response_dict = {"Faraday Server": "Running", "Version": "3.14.2"}
        return web.Response(text=json.dumps(response_dict), headers={"content-type": "application/json"})

    return info


def get_bulk_create(test_config: FaradayTestConfig):
    async def bulk_create(request):
        error = verify_token(test_config, request)
        if error:
            return error

        if "error500" in request.url.path:
            return web.HTTPInternalServerError()
        if "error429" in request.url.path:
            return web.HTTPTooManyRequests()

        if all(workspace not in request.url.path for workspace in test_config.workspaces):
            return web.HTTPNotFound()
        _host_data = host_data.copy()
        _host_data["vulnerabilities"] = [vuln_data.copy()]
        data = json.loads((await request.read()).decode())
        if "execution_id" not in data:
            return web.HTTPBadRequest()
        if "ip" not in data["hosts"][0]:
            return web.HTTPBadRequest()
        assert _host_data == data["hosts"][0]
        return web.HTTPCreated()

    return bulk_create


def order_dict(bare_dict: Dict) -> Dict:
    return {k: order_dict(v) if isinstance(v, dict) else v for k, v in sorted(bare_dict.items())}


def get_ws_handler(test_config: FaradayTestConfig):
    async def websocket_handler(request):

        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            msg_ = json.loads(msg.data)
            if "action" in msg_ and msg_["action"] == "JOIN_AGENT":
                assert test_config.workspaces == msg_["workspaces"]
                assert test_config.ws_token == msg_["token"]
                assert sorted(
                    [order_dict(elem) for elem in test_config.executors], key=lambda elem: elem["executor_name"]
                ) == sorted([order_dict(elem) for elem in msg_["executors"]], key=lambda elem: elem["executor_name"])

                await ws.send_json(test_config.ws_data["run_data"])
            else:
                assert msg_ in test_config.ws_data["ws_responses"]
                test_config.ws_data["ws_responses"].remove(msg_)
                if len(test_config.ws_data["ws_responses"]) == 0:
                    await ws.close()
                    break

        return ws

    return websocket_handler


test_config_params = [
    {"is_ssl": is_ssl, "has_base_route": has_base_route}
    for is_ssl in [False, True]
    for has_base_route in [False, True]
]


@pytest.fixture(
    params=test_config_params,
    ids=lambda elem: f"SSL: {elem['is_ssl']}, BaseRoute: " f"{elem['has_base_route']}",
)
async def test_config(request):
    config = FaradayTestConfig(**request.param)
    await config.generate_client()
    yield config
    await config.client.close()


class TmpConfig:
    config_file_path = Path(f"/tmp/{fuzzy_string(10)}.yaml")

    def save(self):
        save_config(self.config_file_path)


@pytest.fixture
def tmp_default_config():
    config = TmpConfig()
    shutil.copyfile(EXAMPLE_CONFIG_FILENAME, config.config_file_path)
    reset_config(config.config_file_path)
    yield config
    os.remove(config.config_file_path)


@pytest.fixture
def tmp_custom_config():
    config = TmpConfig()
    ini_path = pathlib.Path(__file__).parent.parent / "data" / "test_config.ini"
    shutil.copyfile(ini_path, config.config_file_path.with_suffix(".ini"))
    reset_config(config.config_file_path)
    yield config
    os.remove(config.config_file_path)


class TestLoggerHandler(StreamHandler):
    def __init__(self):
        super().__init__()
        self.history = []
        self.name = "TEST_HANDLER"

    def emit(self, record):
        self.history.append(record)


@pytest.fixture(scope="session")
def test_logger_folder():
    reset_logger("./logs")


@pytest.fixture()
def test_logger_handler():
    logger_handler = TestLoggerHandler()
    logger = get_logger()
    logger_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s {%(threadName)s} "
        "[%(filename)s:%(lineno)s - %(funcName)s()]  %(message)s"
    )
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)
    yield logger_handler
    logger.removeHandler(logger_handler)
