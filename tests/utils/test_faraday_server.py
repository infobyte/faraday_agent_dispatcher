import pytest
from aiohttp import web

@pytest.fixture
def aiohttp_faraday_client(loop,aiohttp_client):
    app = web.Application()
    app.router.add_get()