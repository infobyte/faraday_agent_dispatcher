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
    user = os.environ.get("USER_GVM")
    passw = os.environ.get("PASSW_GVM")
    userssh = os.environ.get("USER_SSH")
    passwssh = os.environ.get("PASSW_SSH")
    host = os.environ.get("HOST")
    port = os.environ.get("PORT")
    connection_type = os.environ.get("CONNECTION_TYPE")
    scan_url = os.environ.get("EXECUTOR_CONFIG_SCAN_URL")
    scan_id = os.environ.get("EXECUTOR_CONFIG_SCAN_ID")
    port_list = os.environ.get("EXECUTOR_CONFIG_PORT_LIST_ID")
    socket = os.environ.get("SOCKET_PATH")

    # RAW XML FORMAT
    xml_format = "a994b278-1f62-11e1-96ac-406186ea4fc5"

    # OPENVAS SCANNER
    scanner = "08b69003-5fc2-4037-a479-93b440211c73"


    if not user or not passw or not connection_type:
        print(
            "Data config ['User', 'Passw', 'Connection_type'] GVM_OpenVas not " "provided",
            file=sys.stderr,
        )
        sys.exit()

    if not scan_url:
        print("Scan Url not provided", file=sys.stderr)
        sys.exit()

    valid_connections = ["socket", "ssh", "tls"]
    if connection_type not in valid_connections:
        print("Not a valid connection_type, Choose between socket-ssh-tls", file=sys.stderr)
        sys.exit()

    if not scan_id:
        # Scan_ID Full and fast
        scan_id = "daba56c8-73ec-11df-a475-002264764cea"

    if not port_list:
        # Port List: All IANA assigned TCP
        port_list = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

    if not socket and connection_type == "socket":
        socket = '/var/run/gvmd.sock'

    # CONNECTION
    transform = EtreeCheckCommandTransform()
    if connection_type == "socket":
        connection = UnixSocketConnection(path=socket)
    elif connection_type == "ssh":
        connection = SSHConnection(hostname=host, port=port, username=userssh, password=passwssh)
    elif connection_type == "tls":
        connection = TLSConnection(hostname=host, port=port)

    # Create Target
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(user, passw)
        name = "Suspect Host {} {}".format(scan_url, str(datetime.datetime.now()))

        response = gmp.create_target(
            name=name, hosts=[scan_url], port_list_id=port_list
        )

    target_id = response.get("id")

    # Create Task
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(user, passw)
        name = "Scan Suspect Host {}".format(scan_url)
        response = gmp.create_task(
            name=name,
            config_id=scan_id,
            target_id=target_id,
            scanner_id=scanner
        )

    task_id = response.get('id')

    # Start Task
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(user, passw)

        response = gmp.start_task(task_id)

    report_id = response[0].text

    def getTask(task_id):
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(user, passw)

            response = gmp.get_task(task_id)
            status = response[1].find("status").text

            return True if status == "Done" else False


    scan_done = False

    while scan_done == False:
        scan_done = getTask(task_id)
        time.sleep(5)

    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(user, passw)

        report = gmp.get_report(report_id=report_id, report_format_id=xml_format, filter="apply_overrides=0 levels=hml rows=-1 min_qod=70 first=1 sort-reverse=severity notes=0 overrides=0", details=True)

    plugin = OpenvasPlugin()
    plugin.parseOutputString(ET.tostring(report[0], encoding="unicode"))
    print(plugin.get_json())


if __name__ == "__main__":
    main()
