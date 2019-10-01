import json
import pytest
import random
from aiohttp import web
from aiohttp.web_request import Request
from itsdangerous import TimestampSigner
from queue import Queue

from tests.utils.websocket_server import start_websockets_faraday_server


class FaradayTestConfig:
    def __init__(self):
        from .text_utils import fuzzy_string
        self.workspace = fuzzy_string(8)
        self.registration_token = fuzzy_string(25)
        self.agent_token = fuzzy_string(64)
        self.agent_id = random.randint(1, 1000)
        self.websocket_port = random.randint(1025, 65535)
        self.client = None
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

    async def generate_client(self, aiohttp_client, aiohttp_server):
        self.client = await aiohttp_faraday_client(aiohttp_client, aiohttp_server, self)
        start_websockets_faraday_server(self)


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


def get_agent_websocket_token(test_config: FaradayTestConfig):
    async def agent_websocket_token(request: web.Request):
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

        ########## Sing and send
        signer = TimestampSigner(test_config.app_config['SECRET_KEY'], salt="websocket_agent")
        assert test_config.agent_id is not None
        token = signer.sign(str(test_config.agent_id))
        response_dict = {"token": token.decode()}
        return web.Response(text=json.dumps(response_dict), headers={'content-type': 'application/json'})
    return agent_websocket_token


def get_bulk_create(test_config: FaradayTestConfig):
    async def bulk_create(request):
        # TODO check
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

        if not test_config.workspace in request.url.path:
            web.HTTPNotFound()
        from tests.data.basic_executor import host_data, vuln_data
        _host_data = host_data.copy()
        _host_data["vulnerabilities"] = [vuln_data.copy()]
        data = json.loads((await request.read()).decode())
        assert _host_data == data["hosts"][0]
        return web.HTTPCreated()

    return bulk_create


@pytest.fixture
async def test_config(aiohttp_client, aiohttp_server, loop):
    config = FaradayTestConfig()
    await config.generate_client(aiohttp_client, aiohttp_server)
    return config


async def aiohttp_faraday_client(aiohttp_client, aiohttp_server, test_config: FaradayTestConfig):
    app = web.Application()
    app.router.add_post(f"/_api/v2/ws/{test_config.workspace}/agent_registration/",
                        get_agent_registration(test_config))
    app.router.add_post('/_api/v2/agent_websocket_token/', get_agent_websocket_token(test_config))
    app.router.add_post(f"/_api/v2/ws/{test_config.workspace}/bulk_create/", get_bulk_create(test_config))
    server = await aiohttp_server(app)
    client = await aiohttp_client(server)
    return client
