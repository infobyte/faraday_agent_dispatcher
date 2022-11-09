#!/usr/bin/env python
import os
import sys
import datetime
import time
import xml.etree.ElementTree as ET
from faraday_plugins.plugins.repo.openvas.plugin import OpenvasPlugin
from gvm.connections import UnixSocketConnection, SSHConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform


def main():
    ignore_info = os.getenv("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
    hostname_resolution = os.getenv("AGENT_CONFIG_RESOLVE_HOSTNAME", "True").lower() == "true"
    vuln_tag = os.getenv("AGENT_CONFIG_VULN_TAG", None)
    if vuln_tag:
        vuln_tag = vuln_tag.split(",")
    service_tag = os.getenv("AGENT_CONFIG_SERVICE_TAG", None)
    if service_tag:
        service_tag = service_tag.split(",")
    host_tag = os.getenv("AGENT_CONFIG_HOSTNAME_TAG", None)
    if host_tag:
        host_tag = host_tag.split(",")
    user = os.environ.get("GVM_USER")
    passw = os.environ.get("GVM_PASSW")
    userssh = os.environ.get("EXECUTOR_CONFIG_SSH_USER")
    passwssh = os.environ.get("EXECUTOR_CONFIG_SSH_PASSW")
    host = os.environ.get("HOST")
    port = os.environ.get("PORT")
    socket = os.environ.get("EXECUTOR_CONFIG_SOCKET_PATH")
    tls_certfile = os.environ.get("EXECUTOR_CONFIG_TLS_CERTFILE_PATH")
    tls_cafile = os.environ.get("EXECUTOR_CONFIG_TLS_CAFILE_PATH")
    tls_keyfile = os.environ.get("EXECUTOR_CONFIG_TLS_KEYFILE_PATH")
    tls_passw = os.environ.get("EXECUTOR_CONFIG_TLS_PKEY_PASSW")
    connection_type = os.environ.get("EXECUTOR_CONFIG_CONNECTION_TYPE").lower()
    scan_url = os.environ.get("EXECUTOR_CONFIG_SCAN_TARGET")
    # Defaults to: Full and Fast
    scan_id = os.environ.get("EXECUTOR_CONFIG_SCAN_ID") or "daba56c8-73ec-11df-a475-002264764cea"
    # Defaults to: All IANA assigned TCP
    port_list = os.environ.get("EXECUTOR_CONFIG_PORT_LIST_ID") or "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

    # RAW XML FORMAT
    xml_format = "a994b278-1f62-11e1-96ac-406186ea4fc5"

    # OPENVAS SCANNER
    scanner = "08b69003-5fc2-4037-a479-93b440211c73"

    if not user or not passw or not host or not port:
        print(
            "Data config ['User', 'Passw', 'Host', 'Port']" " GVM_OpenVas not provided",
            file=sys.stderr,
        )
        sys.exit()

    if not scan_url:
        print("Scan Url not provided", file=sys.stderr)
        sys.exit()

    valid_connections = ("socket", "ssh", "tls")
    if connection_type not in valid_connections:
        print(
            "Not a valid connection_type, Choose between socket-ssh-tls",
            file=sys.stderr,
        )
        sys.exit()

    if connection_type == "socket":
        # Default Socket according to official docs
        socket = "/var/run/gvmd.sock" if not socket else socket
    elif connection_type == "ssh":
        if not userssh or not passwssh:
            print("SSH username or password not provided", file=sys.stderr)
            sys.exit()

    # CONNECTION
    transform = EtreeCheckCommandTransform()

    # USER NEEDS PERMISSION ON THE SOCKET
    if connection_type == "socket":
        connection = UnixSocketConnection(path=socket)
    elif connection_type == "ssh":
        connection = SSHConnection(hostname=host, port=port, username=userssh, password=passwssh)
    elif connection_type == "tls":
        connection = TLSConnection(
            hostname=host,
            port=port,
            certfile=tls_certfile,
            cafile=tls_cafile,
            keyfile=tls_keyfile,
            password=tls_passw,
        )

    # Create Target
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(user, passw)
        name = f"Suspect Host {scan_url} {str(datetime.datetime.now())}"

        response = gmp.create_target(name=name, hosts=[scan_url], port_list_id=port_list)

    target_id = response.get("id")

    # Create Task
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(user, passw)
        name = f"Scan Suspect Host {scan_url} {str(datetime.datetime.now())}"
        response = gmp.create_task(
            name=name,
            config_id=scan_id,
            target_id=target_id,
            scanner_id=scanner,
        )

    task_id = response.get("id")

    # Start Task
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(user, passw)

        response = gmp.start_task(task_id)

    report_id = response[0].text

    # Check task status function
    def get_task(_task_id):
        with Gmp(connection=connection, transform=transform) as _gmp:
            _gmp.authenticate(user, passw)

            _response = _gmp.get_task(_task_id)
            status = _response[1].find("status").text

            return True if status == "Done" else False

    scan_done = False

    # Loop to see if scan is done
    while not scan_done:
        scan_done = get_task(task_id)
        time.sleep(5)

    # Get report
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(user, passw)
        try:
            report = gmp.get_report(
                report_id=report_id,
                report_format_id=xml_format,
                filter="apply_overrides=0 levels=hml rows=-1 min_qod=70 "
                "first=1 sort-reverse=severity "
                "notes=0 overrides=0",
                details=True,
            )
        except TypeError:
            report = gmp.get_report(
                report_id=report_id,
                report_format_id=xml_format,
                filter_string="apply_overrides=0 levels=hml rows=-1 min_qod=70 "
                "first=1 sort-reverse=severity "
                "notes=0 overrides=0",
                details=True,
            )

    # Parse report and send to Faraday
    plugin = OpenvasPlugin(
        ignore_info=ignore_info,
        hostname_resolution=hostname_resolution,
        host_tag=host_tag,
        service_tag=service_tag,
        vuln_tag=vuln_tag,
    )
    plugin.parseOutputString(ET.tostring(report[0], encoding="unicode"))
    print(plugin.get_json())


if __name__ == "__main__":
    main()
