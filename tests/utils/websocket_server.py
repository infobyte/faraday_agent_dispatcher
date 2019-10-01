# Sin estas dos primeras lineas rompe, pero pregunta por asyncio, invertigar
import txaio
txaio.use_twisted()

from autobahn.websocket.protocol import WebSocketProtocol
from twisted.internet import reactor
from http import cookies
import json
from queue import Empty

from autobahn.twisted.websocket import (
    WebSocketServerFactory,
    WebSocketServerProtocol,
    listenWS
)
from itsdangerous import BadData, TimestampSigner

# test_config: FaradayTestConfig (NOT hint typing because of circular dependencies)
def decode_agent_websocket_token(token, test_config):
    signer = TimestampSigner(test_config.app_config['SECRET_KEY'],
                             salt="websocket_agent")
    try:
        agent_id = signer.unsign(token, max_age=60).decode('utf-8')
    except BadData as e:
        raise ValueError("Invalid Token")
    if not agent_id == test_config.agent_id:
        raise ValueError("Invalid Agent id")
    return agent_id

# test_config: FaradayTestConfig (NOT hint typing because of circular dependencies)
def start_websockets_faraday_server(test_config):
    connected_agents = {}

    class BroadcastServerProtocol(WebSocketServerProtocol):

        def onConnect(self, request):
            protocol, headers = None, {}
            # see if there already is a cookie set ..
            if 'cookie' in request.headers:
                try:
                    cookie = cookies.SimpleCookie()
                    cookie.load(str(request.headers['cookie']))
                except cookies.CookieError:
                    pass
            return (protocol, headers)

        def onMessage(self, payload, is_binary):
            """
                We only support JOIN and LEAVE workspace messages.
                When authentication is implemented we need to verify
                that the user can join the selected workspace.
                When authentication is implemented we need to reply
                the client if the join failed.
            """
            if not is_binary:
                message = json.loads(payload)
                if message['action'] == 'JOIN_AGENT':
                    if 'token' not in message:
                        # logger.warn("Invalid agent join message")
                        self.state = WebSocketProtocol.STATE_CLOSING
                        self.sendClose()
                        return False
                    try:
                        agent_id = decode_agent_websocket_token(message['token'], test_config)
                    except ValueError:
                        # logger.warn('Invalid agent token!')
                        self.state = WebSocketProtocol.STATE_CLOSING
                        self.sendClose()
                        return False
                    # factory will now send broadcast messages to the agent
                    return self.factory.join_agent(self, agent_id)
                if message['action'] == 'LEAVE_AGENT':
                    (agent_id,) = [
                        k
                        for (k, v) in connected_agents.items()
                        if v == self
                    ]
                    assert agent_id == test_config.agent_id
                    self.factory.leave_agent(self, agent_id)
                    self.state = WebSocketProtocol.STATE_CLOSING
                    self.sendClose()
                    return False

        def connectionLost(self, reason):
            WebSocketServerProtocol.connectionLost(self, reason)
            self.factory.unregister(self)
            self.factory.unregister_agent(self)

        def sendServerStatus(self, redirectUrl=None, redirectAfter=0):
            self.sendHtml('This is a websocket port.')

    class WorkspaceServerFactory(WebSocketServerFactory):
        """
            This factory uses the changes_queue to broadcast
            message via websockets.

            Any message put on that queue will be sent to clients.

            Clients subscribe to workspace channels.
            This factory will broadcast message to clients subscribed
            on workspace.

            The message in the queue must contain the workspace.
        """
        protocol = BroadcastServerProtocol

        def __init__(self, url):
            WebSocketServerFactory.__init__(self, url)
            # this dict has a key for each channel
            # values are list of clients.
            self.tick()

        def tick(self):
            """
                Uses changes_queue to broadcast messages to clients.
                broadcast method knowns each client workspace.
            """
            try:
                msg = test_config.changes_queue.get_nowait()
                self.broadcast(json.dumps(msg))
            except Empty:
                pass
            reactor.callLater(0.5, self.tick)

        def join_agent(self, agent_connection, agent_id):
            # logger.info("Agent {} joined!".format(agent.id))
            connected_agents[agent_id] = agent_connection
            return True

        def leave_agent(self, agent_connection, agent_id):
            # logger.info("Agent {} leaved".format(agent.id))
            connected_agents.pop(agent_id)
            return True

        def unregister_agent(self, protocol):
            for (key, value) in connected_agents.items():
                if value == protocol:
                    del connected_agents[key]

        def broadcast(self, msg):
            if isinstance(msg, str):
                msg = msg.encode('utf-8')
            # logger.debug("broadcasting prepared message '{}' ..".format(msg))
            prepared_msg = json.loads(self.prepareMessage(msg).payload)

            if b'agent_id' in msg:
                agent_id = prepared_msg['agent_id']
                try:
                    agent_connection = connected_agents[agent_id]
                except KeyError:
                    # The agent is offline
                    return
                reactor.callFromThread(agent_connection.sendPreparedMessage, self.prepareMessage(msg))
                # logger.debug("prepared message sent to agent id: {}".format(agent_id))

    from faraday_agent_dispatcher.utils.url_utils import websocket_url
    factory = WorkspaceServerFactory(url=websocket_url(host=test_config.client.host, port=test_config.websocket_port))
    factory.protocol = BroadcastServerProtocol
    test_config.websocket_server = factory
    listenWS(factory, interface=test_config.client.host)