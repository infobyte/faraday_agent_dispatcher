
def __get_url(host, port):
    return f"{host}:{port}"


def api_url(host, port, postfix: str = "", secure=False):
    prefix = "https://" if secure else "http://"
    return f"{prefix}{__get_url(host,port)}{postfix}"


def websocket_url(host, port, postfix: str = "", secure=False):
    prefix = "wss://" if secure else "ws://"
    return f"{prefix}{__get_url(host,port)}{postfix}"
