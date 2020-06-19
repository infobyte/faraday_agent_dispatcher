import json
import os
import shutil
import ssl

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
    def __init__(self):
        self.workspace = fuzzy_string(8)
        self.registration_token = fuzzy_string(25)
        self.agent_token = fuzzy_string(64)
        self.agent_id = random.randint(1, 1000)
        self.websocket_port = random.randint(1025, 65535)
        self.client = None
        self.ssl_client = None
        self.app_config = {
            "SECURITY_TOKEN_AUTHENTICATION_HEADER": 'Authorization',
            "SECRET_KEY": 'SECRET_KEY',
        }
        self.changes_queue = Queue()

    def run_agent_to_websocket(self):
        self.changes_queue.put({
            'agent_id': self.agent_id,
            'action': 'RUN',
        })

    async def generate_client(self):
        self.client, self.ssl_client = await aiohttp_faraday_client(self)


def get_agent_registration(test_config: FaradayTestConfig):
    async def agent_registration(request: Request):
        data = await request.text()
        data = json.loads(data)
        if 'token' not in data or data['token'] != test_config.registration_token:
            return web.HTTPUnauthorized()
        response_dict = {"name": data["name"],
                         "token": test_config.agent_token,
                         "id": test_config.agent_id}
        return web.HTTPCreated(text=json.dumps(response_dict), headers={'content-type': 'application/json'})
    return agent_registration


def verify_token(test_config, request):
    if test_config.app_config['SECURITY_TOKEN_AUTHENTICATION_HEADER'] not in request.headers:
        return web.HTTPUnauthorized()
    header = request.headers[test_config.app_config['SECURITY_TOKEN_AUTHENTICATION_HEADER']]
    try:
        (auth_type, token) = header.split(None, 1)
    except ValueError:
        return web.HTTPUnauthorized()
    auth_type = auth_type.lower()
    if auth_type != 'agent':
        return web.HTTPUnauthorized()
    if token != test_config.agent_token:
        return web.HTTPForbidden()


def get_agent_websocket_token(test_config: FaradayTestConfig):
    async def agent_websocket_token(request: web.Request):
        error = verify_token(test_config, request)
        if error:
            return error

        ########## Sing and send
        signer = TimestampSigner(test_config.app_config['SECRET_KEY'], salt="websocket_agent")
        assert test_config.agent_id is not None
        token = signer.sign(str(test_config.agent_id))
        response_dict = {"token": token.decode()}
        return web.Response(text=json.dumps(response_dict), headers={'content-type': 'application/json'})
    return agent_websocket_token


def get_base(test_config: FaradayTestConfig):
    async def base(request):
        return web.HTTPOk()
    return base


def get_bulk_create(test_config: FaradayTestConfig):
    async def bulk_create(request):
        error = verify_token(test_config, request)
        if error:
            return error

        if "error500" in request.url.path:
            return web.HTTPInternalServerError()
        if "error429" in request.url.path:
            return web.HTTPTooManyRequests()

        if test_config.workspace not in request.url.path:
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


@pytest.fixture
async def test_config():
    config = FaradayTestConfig()
    await config.generate_client()
    yield config
    await config.client.close()
    await config.ssl_client.close()


class TmpConfig:
    config_file_path = Path(f"/tmp/{fuzzy_string(10)}.ini")

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
def tmp_custom_config(config=None):
    config = TmpConfig()
    ini_path = (
        pathlib.Path(__file__).parent.parent /
        'data' / 'test_config.ini'
    )
    shutil.copyfile(ini_path, config.config_file_path)
    reset_config(config.config_file_path)
    yield config
    os.remove(config.config_file_path)


async def aiohttp_faraday_client(test_config: FaradayTestConfig):
    app = web.Application()
    app.router.add_get("/", get_base(test_config))
    app.router.add_post(f"/_api/v2/ws/{test_config.workspace}/agent_registration/",
                        get_agent_registration(test_config))
    app.router.add_post('/_api/v2/agent_websocket_token/', get_agent_websocket_token(test_config))
    app.router.add_post(f"/_api/v2/ws/{test_config.workspace}/bulk_create/", get_bulk_create(test_config))
    app.router.add_post(f"/_api/v2/ws/error500/bulk_create/", get_bulk_create(test_config))
    app.router.add_post(f"/_api/v2/ws/error429/bulk_create/", get_bulk_create(test_config))
    server = TestServer(app)
    await server.start_server()
    ssl_cert_path = Path(__file__).parent.parent / 'data'
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(ssl_cert_path / 'ok.crt', ssl_cert_path / 'ok.key')
    ssl_server = TestServer(app)
    await ssl_server.start_server(ssl=ssl_context)
    client = TestClient(server, raise_for_status=True)
    ssl_client = TestClient(ssl_server, raise_for_status=True)
    return client, ssl_client


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
        '%(asctime)s - %(name)s - %(levelname)s {%(threadName)s} [%(filename)s:%(lineno)s - %(funcName)s()]  %(message)s')
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)
    yield logger_handler
    logger.removeHandler(logger_handler)
