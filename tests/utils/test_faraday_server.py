import pytest
from aiohttp import web
from aiohttp.web_request import Request
from urllib.parse import parse_qs
import json


def get_agent_registration(registration_token, agent_token):
    async def agent_registration(request: Request):
        data = await request.text()
        data = json.loads(data)
        if 'token' not in data or data['token'] != registration_token:
            return web.HTTPUnauthorized()
        response_dict = {"name": data["name"],
                         "token": agent_token,
                         "id": 1}
        return web.HTTPCreated(text=json.dumps(response_dict), headers={'content-type': 'application/json'})
    return agent_registration


async def agent_websocket_token(request: web.Request):
    if app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER'] not in request.headers:
        return web.HTTPUnauthorized()
    header = request.headers[app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER']]
    try:
        (auth_type, token) = header.split(None, 1)
    except ValueError:
        return web.HTTPUnauthorized()
    auth_type = auth_type.lower()
    if auth_type != 'agent':
        return web.HTTPUnauthorized()
    if token != "correctToken":
        return web.HTTPForbidden()

    ########## THEN
    signer = TimestampSigner(app.config['SECRET_KEY'], salt="websocket_agent")
    assert agent.id is not None
    token = signer.sign(str(agent.id))
    return web.Response(data={"token": token})


async def bulk_create(request):
    try:
        validate_csrf(flask.request.form.get('csrf_token'))
    except wtforms.ValidationError:
        flask.abort(403)

    def parse_hosts(list_string):
        items = re.findall(r"([.a-zA-Z0-9_-]+)", list_string)
        return items

    def parse_tags(list_string):
        items = re.findall(r"([.a-zA-Z0-9_-]+)", list_string)
        return items

    workspace = self._get_workspace(workspace_name)

    logger.info("Create hosts from CSV")
    if 'file' not in flask.request.files:
        abort(400, "Missing File in request")
    hosts_file = flask.request.files['file']
    stream = StringIO(hosts_file.stream.read().decode("utf-8"), newline=None)
    FILE_HEADERS = {'description', 'hostnames', 'ip', 'os', 'tags'}
    try:
        hosts_reader = csv.DictReader(stream)
        if set(hosts_reader.fieldnames) != FILE_HEADERS:
            logger.error("Missing Required headers in CSV (%s)", FILE_HEADERS)
            abort(400, "Missing Required headers in CSV (%s)" % FILE_HEADERS)
        hosts_created_count = 0
        hosts_with_errors_count = 0
        for host_dict in hosts_reader:
            try:
                hostnames = parse_hosts(host_dict.pop('hostnames'))
                tags = parse_tags(host_dict.pop('tags'))
                other_fields = {'owned': False, 'mac': u'00:00:00:00:00:00', 'default_gateway_ip': u'None'}
                host_dict.update(other_fields)
                host = super(HostsView, self)._perform_create(host_dict, workspace_name)
                host.workspace = workspace
                for name in hostnames:
                    get_or_create(db.session, Hostname, name=name, host=host, workspace=host.workspace)
                for tag in tags:
                    host.tags.add(tag)
                db.session.commit()
            except Exception as e:
                logger.error("Error creating host (%s)", e)
                hosts_with_errors_count += 1
            else:
                logger.debug("Host Created (%s)", host_dict)
                hosts_created_count += 1
        return make_response(jsonify(hosts_created=hosts_created_count, hosts_with_errors=hosts_with_errors_count), 200)
    except Exception as e:
        logger.error("Error parsing hosts CSV (%s)", e)
        abort(400, "Error parsing hosts CSV (%s)" % e)


@pytest.fixture
async def config(aiohttp_client, aiohttp_server, loop):
    config = FaradayConfig()
    await config.generate_client(aiohttp_client, aiohttp_server)
    return config


async def h_cli(aiohttp_client, aiohttp_server, workspace, registration_token, agent_token):
    app = web.Application()
    app.router.add_post(f"/_api/v2/ws/{workspace}/agent_registration/", get_agent_registration(registration_token, agent_token))
    app.router.add_post('/_api/v2/agent_websocket_token/', agent_websocket_token)  # headers = headers)
    app.router.add_post(f"/_api/v2/ws/{workspace}/bulk_create/", bulk_create)
    server = await aiohttp_server(app)#, port=5600)
    client = await aiohttp_client(server)
    return client


class FaradayConfig:
    def __init__(self):
        from .text_utils import fuzzy_string
        self.workspace = fuzzy_string(8)
        self.registration_token = fuzzy_string(25)
        self.agent_token = fuzzy_string(64)
        self.client = None

    async def generate_client(self, aiohttp_client, aiohttp_server):
        self.client = await h_cli(aiohttp_client, aiohttp_server, self.workspace, self.registration_token,
                                  self.agent_token)
