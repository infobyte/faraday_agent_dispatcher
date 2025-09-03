#!/usr/bin/env python
import os
import sys
import json
import time
from datetime import datetime

from requests import Session
from requests_ratelimiter import LimiterAdapter

SECONDS_AFTER_TOO_MANY_REQUESTS = 30

session = Session()
adapter = LimiterAdapter(per_minute=40)
session.mount("http://", adapter)
session.mount("https://", adapter)


def log(msg="", end="\n"):
    print(msg, file=sys.stderr, flush=True, end=end)


def dt_ms_patch(date_str):
    """
    This patch fixes an issue where datetime cannot process milliseconds
    with more than 6 decimal places, which raises an exception.
    Also removes anything beyond the milliseconds
    """
    patch = (date_str[:-1][: date_str.index(".") + 7]) if "." in date_str else date_str[:-1]
    return datetime.strptime(patch, "%Y-%m-%dT%H:%M:%S.%f")


def severity_patch(severity):
    if severity not in ["critical", "high", "medium", "low", "info", "unclassified"]:
        return "unclassified"
    return severity


def description_maker(machine):
    ips = ""
    for ip in machine["ipAddresses"]:
        if ip["type"] in ["SoftwareLoopback", "Tunnel"]:
            continue
        if len(ip["ipAddress"]) < 7 or ip["ipAddress"] in ["127.0.0.1"]:
            continue
        # converts '7CDB98C877F1' into '7C:DB:98:C8:77:F1' for better readability
        mac = (
            (":".join(ip["macAddress"][i : i + 2] for i in range(0, len(ip["macAddress"]), 2)))  # noqa: E203
            if ip["macAddress"] is not None
            else "N/A"
        )

        ips += f"  IP: {ip['ipAddress']}\n  MAC: {mac}\n\n"

    last_seen = dt_ms_patch(machine["lastSeen"]).strftime("%d/%m/%Y at %H:%M:%S UTC")
    first_seen = dt_ms_patch(machine["firstSeen"]).strftime("%d/%m/%Y at %H:%M:%S UTC")

    desc = f"## Operating System\n{machine['osPlatform']} "
    desc += f"{machine['osArchitecture'] if machine['osArchitecture'] is not None else ''} "
    desc += f"{machine['version'] if machine['version'] not in [None, 'Other'] else ''} "
    desc += f"{'(build ' + str(machine['osBuild']) + ')' if machine['osBuild'] not in [None, 'Other'] else ''}\n\n"
    desc += f"## Device Timestamps\nFirst Seen: {first_seen}\n  Last Seen: {last_seen}\n\n"
    desc += f"## Known IP's & associated MAC address\n{ips}"
    return desc


def token_gen(tenant_id, client_id, client_secret):
    app_id_url = "https://api.securitycenter.microsoft.com"
    app_auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    r_body = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "resource": app_id_url,
    }
    resp = session.post(app_auth_url, data=r_body).json()
    if "error" in resp.keys():
        log(f"Error at token generation: {resp['error']}")
        log(resp["error_description"])
        exit(1)
    access_token = resp["access_token"]
    log("Token generated successfully")
    return access_token


def get_machines(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = session.get("https://api.security.microsoft.com/api/machines", headers=headers).json()
    if "error" in resp.keys():
        log(f"Error at retrieving machines: {resp['error']['code']}")
        log(resp["error"]["message"])
        exit(1)
    return resp["value"]


def get_machine_vulns(token, machine_id):
    headers = {"Authorization": f"Bearer {token}"}
    resp = session.get(
        f"https://api.security.microsoft.com/api/machines/{machine_id}/vulnerabilities", headers=headers
    ).json()
    if "error" in resp.keys():
        log(f"Error at retrieving machine vulns: {resp['error']['code']}")
        log(resp["error"]["message"])
        # In case limiter is not suffice. We'll try a second time after SECONDS_AFTER_TOO_MANY_REQUESTS seconds.
        if resp["error"]["code"] == "TooManyRequests":
            log(f"Waiting for {SECONDS_AFTER_TOO_MANY_REQUESTS} seconds")
            time.sleep(SECONDS_AFTER_TOO_MANY_REQUESTS)
            resp = session.get(
                f"https://api.security.microsoft.com/api/machines/{machine_id}/vulnerabilities", headers=headers
            ).json()
            if "error" in resp.keys():
                log(f"Second error at retrieving machine vulns: {resp['error']['code']}. Exiting...")
                exit(1)
        else:
            exit(1)
    return resp["value"]


def generate_report(token, vuln_tags, host_tags, days_old):
    hosts = []
    log("Fetching machines...", "\r")
    machines = get_machines(token)
    log(f"Retrieved {len(machines)} machines")
    log("Filtering assets ...")
    matched_machines = []
    for machine in machines:
        # check if machine is younger than threshold, measured in days (1 day = 86400 secs)
        if dt_ms_patch(machine["lastSeen"]).timestamp() >= (datetime.now().timestamp() - (days_old * 86400)):
            matched_machines.append(machine)
    log(f"{len(matched_machines)} machines matched time filter")
    avr_time = []
    for machine in matched_machines:
        _start = time.time()
        host = {
            "ip": machine["id"],
            "os": machine["osPlatform"],
            "hostnames": [machine["computerDnsName"] if machine["computerDnsName"] is not None else "N/A"],
            "mac": "",
            "tags": [tag for tag in machine["machineTags"]] + host_tags,
            "description": description_maker(machine),
        }
        vuln_list = []
        for vuln in get_machine_vulns(token, machine["id"]):
            vuln_list.append(
                {
                    "name": vuln["name"],
                    "desc": vuln["description"],
                    "severity": severity_patch(vuln["severity"].lower()),
                    "external_id": vuln["id"],
                    "type": "Vulnerability",
                    "status": "open",
                    "cve": [vuln["id"]],
                    "cvss3": {"base_score": str(vuln["cvssV3"]), "vector_string": vuln["cvssVector"]},
                    "tags": vuln["tags"] + vuln_tags,
                    "confirmed": vuln["exploitVerified"],
                    "refs": [{"name": url, "type": "other"} for url in vuln["exploitUris"]],
                    "resolution": f"https://security.microsoft.com/vulnerabilities/vulnerability/{vuln['id']}"
                    + "/recommendation",
                    "cwe": [],
                }
            )
        host["vulnerabilities"] = vuln_list
        hosts.append(host)
        avr_time.append(time.time() - _start)
        log(
            f"Processing assets: {len(hosts)} / {len(matched_machines)} ({len(hosts)*100/len(matched_machines):.2f}%)"
            + f" ETA: {((len(matched_machines)-len(hosts))*(sum(avr_time)/len(avr_time)))/60:.2f} min"
        )
    print(json.dumps({"hosts": hosts}))


def main():
    params_tenant_id = os.getenv("TENANT_ID")
    params_client_id = os.getenv("CLIENT_ID")
    params_client_secret = os.getenv("CLIENT_SECRET")
    params_days_old = os.getenv("EXECUTOR_CONFIG_DAYS_OLD")
    params_days_old = (
        int(params_days_old) if params_days_old.isnumeric() else log("DAYS_OLD Variable must be an integer") or exit()
    )

    params_vuln_tags = os.getenv("AGENT_CONFIG_VULN_TAG")
    params_vuln_tags = (params_vuln_tags.split(",") if params_vuln_tags != "" else []) if params_vuln_tags else []

    params_host_tags = os.getenv("AGENT_CONFIG_HOSTNAME_TAG")
    params_host_tags = (params_host_tags.split(",") if params_host_tags != "" else []) if params_host_tags else []

    token = token_gen(params_tenant_id, params_client_id, params_client_secret)
    generate_report(
        token, params_vuln_tags, params_host_tags, int(params_days_old) if int(params_days_old) >= 1 else 1
    )


if __name__ == "__main__":
    main()
