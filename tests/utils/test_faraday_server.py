import pytest
from aiohttp import web


async def agent_registration(request):
    token = 0 #request.pop('token')
    if True or token != "theToken":
        web.HTTPUnauthorized()
    return web.HTTPCreated(text="TODO") #TODO 201 Correct data


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
async def h_cli(aiohttp_client, aiohttp_server, loop):
    app = web.Application()
    app.router.add_post("/_api/v2/ws/workspace/agent_registration/", agent_registration)
    app.router.add_post('/_api/v2/agent_websocket_token/', agent_websocket_token)  # headers = headers)
    app.router.add_post("/_api/v2/ws/workspace/bulk_create/", bulk_create)
    server = await aiohttp_server(app)#, port=5600)
    client = await aiohttp_client(server)
    return client
