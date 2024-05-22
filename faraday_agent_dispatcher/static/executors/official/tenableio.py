import os
import sys
import time
import re
import json

from tenable.io import TenableIO
from faraday_plugins.plugins.repo.nessus.plugin import NessusPlugin


HTTP_REGEX = re.compile("^(http|https)://")
TEMPLATE_NAMES = [
    "asv",
    "discovery",
    "wannacry",
    "intelamt",
    "basic",
    "patch_audit",
    "webapp",
    "malware",
    "mobile",
    "mdm",
    "compliance",
    "pci",
    "offline",
    "cloud_audit",
    "scap",
    "custom",
    "ghost",
    "spectre_meltdown",
    "advanced",
    "agent_advanced",
    "agent_basic",
    "agent_compliance",
    "agent_scap",
    "agent_malware",
    "agent_custom",
    "ripple-treck",
    "zerologon",
    "solorigate",
    "hafnium",
    "printnightmare",
    "active_directory",
    "log4shell",
    "log4shell_dc",
    "agent_log4shell",
    "log4shell_vulnerable_ecosystem",
    "eoy22",
    "agent_inventory_collection",
    "cisa_alert_aa22011a",
    "contileaks",
    "ransomware_ecosystem_2022",
    "active_directory_identity",
]


def log(msg):
    print(msg, file=sys.stderr)


def search_policy_id_by_template_name(tio, template_name):
    policies = tio.policies.list()
    for policy in policies:
        if policy["name"] == template_name:
            return policy["id"]
    return None


def get_agent_group_uuid_by_agent_group_name(tio, agent_group_name):
    agent_groups = tio.agent_groups.list()
    for agent_group in agent_groups:
        if agent_group["name"] == agent_group_name:
            return agent_group["uuid"]
    return None


def search_scan_id(tio, TENABLE_SCAN_ID):
    scans = tio.scans.list()
    scans_id = ""
    for scan in scans:
        scans_id += f"{scan['id']} {scan['name']}\n"
        if str(scan["id"]) == str(TENABLE_SCAN_ID):
            log(
                f"Scan found: {scan['name']}",
            )
            break
    else:
        log(
            f"Scan id {TENABLE_SCAN_ID} not found, the current scans available are: {scans_id}",
        )
        exit(1)
    return scan


def parse_targets(tenable_scan_targets):
    """
    Given a string of ips separated by ',' it takes out the http or https
    and retrieves only the domain name or ip address"""
    parsed_targets = []
    for ip in tenable_scan_targets:
        if HTTP_REGEX.match(ip):
            target = re.sub(HTTP_REGEX, "", ip).strip()
        else:
            target = ip.strip()
        parsed_targets.append(target)
    return parsed_targets


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
    TENABLE_SCAN_NAME = os.getenv("EXECUTOR_CONFIG_SCAN_NAME", "faraday-scan")
    TENABLE_SCAN_ID = os.getenv("EXECUTOR_CONFIG_SCAN_ID")
    TENABLE_RELAUNCH_SCAN = os.getenv("EXECUTOR_CONFIG_RELAUNCH_SCAN", "False").lower() == "true"
    TENABLE_SCAN_TARGETS = os.getenv("EXECUTOR_CONFIG_SCAN_TARGETS")  # solo para user-defined template
    TENABLE_TEMPLATE_NAME = os.getenv("EXECUTOR_CONFIG_TEMPLATE_NAME", "agent_basic")
    TENABLE_PULL_INTERVAL = os.getenv("TENABLE_PULL_INTERVAL", 30)
    TENABLE_ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
    TENABLE_SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")
    TENABLE_IS_USER_DEFINED = os.getenv("EXECUTOR_CONFIG_USE_USER_DEFINED_TEMPLATE", "False").lower() == "true"
    TENABLE_AGENT_GROUP_NAME = os.getenv("EXECUTOR_CONFIG_AGENT_GROUP_NAME")

    if not (TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY):
        log("TenableIo access_key and secret_key were not provided")
        exit(1)
    tio = TenableIO(TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY)
    if TENABLE_SCAN_ID and not TENABLE_RELAUNCH_SCAN:
        scan = search_scan_id(tio, TENABLE_SCAN_ID)
        report = tio.scans.export(scan["id"])
        plugin = NessusPlugin(
            ignore_info=ignore_info,
            hostname_resolution=hostname_resolution,
            host_tag=host_tag,
            service_tag=service_tag,
            vuln_tag=vuln_tag,
        )
        plugin.parseOutputString(report.read())
        print(plugin.get_json())
        return
    if TENABLE_SCAN_ID:
        scan = search_scan_id(tio, TENABLE_SCAN_ID)
    elif TENABLE_IS_USER_DEFINED and TENABLE_SCAN_NAME and TENABLE_SCAN_TARGETS and TENABLE_TEMPLATE_NAME:
        policy_id = search_policy_id_by_template_name(
            tio, TENABLE_TEMPLATE_NAME
        )  # User defined template policy id is searched by template_name
        if not policy_id:
            log("The provided template name does not exist.")  # policy_id refers to a user_defined_template
            exit(1)
        targets = json.loads(TENABLE_SCAN_TARGETS)
        parsed_targets = parse_targets(targets)
        log(f"The targets are {parsed_targets}")
        scan = tio.scans.create(name=TENABLE_SCAN_NAME, targets=parsed_targets, policy_id=policy_id)
    else:
        if TENABLE_TEMPLATE_NAME not in TEMPLATE_NAMES:
            log("The provided template name does not exist.")
            exit(1)
        agent_group_uuid = get_agent_group_uuid_by_agent_group_name(tio, TENABLE_AGENT_GROUP_NAME)
        if not agent_group_uuid:
            log("The provided agent group does not exist.")
            exit(1)
        scan = tio.scans.create(
            name=TENABLE_SCAN_NAME,
            template=TENABLE_TEMPLATE_NAME,
            agent_group_id=[agent_group_uuid],  # Must be a list, otherwise returns 500
        )
    tio.scans.launch(scan["id"])
    status = "pending"
    while status[-2:] != "ed":
        time.sleep(int(TENABLE_PULL_INTERVAL))
        status = tio.scans.status(scan["id"])
    if status != "completed":
        log(f"Scanner ended with status {status}")
        exit(1)
    report = tio.scans.export(
        scan["id"]
    )  # Valid report is assumed. If report isn't valid, executor will crash but dispatcher won't.
    plugin = NessusPlugin(
        ignore_info=ignore_info,
        hostname_resolution=hostname_resolution,
        host_tag=host_tag,
        service_tag=service_tag,
        vuln_tag=vuln_tag,
    )
    plugin.parseOutputString(report.read())
    print(plugin.get_json())


if __name__ == "__main__":
    main()
