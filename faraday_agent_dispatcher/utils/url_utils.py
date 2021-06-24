from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher import config


def __get_url(host: str, port: int, base_route: str = None):
    if base_route is None:
        base_route = config.instance[Sections.SERVER].get("base_route", None)
    if base_route is None:
        return f"{host}:{port}"
    else:
        return f"{host}:{port}/{base_route}"


def api_url(host, port, postfix: str = "/", secure=False):
    prefix = "https://" if secure else "http://"
    return f"{prefix}{__get_url(host,port)}{postfix}"


def websocket_url(host, port, postfix: str = "/", secure=False):
    prefix = "wss://" if secure else "ws://"
    return f"{prefix}{__get_url(host,port)}{postfix}"
