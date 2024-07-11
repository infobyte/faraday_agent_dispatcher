#!/usr/bin/env python
import os
import sys
import json
import time
import datetime
import requests
from urllib3.exceptions import InsecureRequestWarning
from faraday_agent_dispatcher.utils.severity_utils import severity_from_score

API_BASE = "/api/3.0"


def log(msg, end="\n"):
    print(msg, file=sys.stderr, flush=True, end=end)


def parse_date(date_str):
    try:
        return datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").timestamp()
    except ValueError:
        return ""


def cybervision_report_composer(url, token, preset_list, asset_tags, vuln_tags):
    req_headers = {"accept": "application/json", "x-token-id": token}
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    presets_queue = []
    presets_id = {}

    # STAGE 1 - get preset list
    req_url = f"{url}{API_BASE}/presets"
    try:
        resp = requests.get(req_url, headers=req_headers, timeout=20, verify=False).json()
    except TimeoutError:
        log("Can't reach Cyber Vision: connection timed out")
        sys.exit(1)
    if "error" in resp:
        log(f"API Error: {resp['error']}")
        sys.exit(1)
    for req_preset in preset_list:
        for preset in resp:
            if preset["label"] == req_preset:
                presets_id[preset["label"]] = preset["id"]
                presets_queue.append(preset["id"])
    presets_id_inv = {v: k for k, v in presets_id.items()}

    # STAGE 2 - get all vulns per preset
    presets_vuln_collection = {}
    step_c = 1
    step_s = 100

    for _id in presets_queue:  # post to update to latest computed data
        req_refresh_url = f"{url}{API_BASE}/presets/{_id}/refreshData"
        try:
            resp = requests.post(req_refresh_url, headers=req_headers, timeout=20, verify=False)
        except TimeoutError:
            log("Can't reach Cyber Vision: connection timed out")
            sys.exit(1)

    for _id in presets_queue:
        serv_c = 0
        while True:  # wait until data is ready
            req_test_url = f"{url}{API_BASE}/presets/{_id}/visualisations/vulnerability-list?page=1&size=5"
            try:
                resp = requests.get(req_test_url, headers=req_headers, timeout=20, verify=False)
                if "Service unavailable" in resp.content.decode("UTF-8"):
                    if serv_c == 0:
                        log(f"Preset {presets_id_inv[_id]} data is not ready, waiting...")
                    serv_c += 1
                else:
                    log(f"Preset {presets_id_inv[_id]} data is ready!")
                    serv_c = 0
                    break
                if serv_c >= 60:
                    break
            except TimeoutError:
                log("Can't reach Cyber Vision: connection timed out")
                sys.exit(1)
            time.sleep(1)

        if serv_c >= 60:
            log(f"Error: Preset {presets_id_inv[_id]} took many time to refresh data")
            continue

        step_c = 1
        presets_vuln_collection[_id] = []
        while True:  # paged data fetch
            req_url = f"{url}{API_BASE}/presets/{_id}/visualisations/vulnerability-list?page={step_c}&size={step_s}"
            try:
                resp = requests.get(req_url, headers=req_headers, timeout=20, verify=False)
                resp = resp.json()
            except TimeoutError:
                log("Can't reach Cyber Vision: connection timed out")
                sys.exit(1)
            except ValueError as ve:
                log(f"{str(ve)} at preset {presets_id_inv[_id]}")
                break
            if "error" in resp:
                log(f"API Error: {resp['error']}")
                break
            if len(resp) < 1:
                break
            presets_vuln_collection[_id].append(resp)
            step_c += 1

    # STAGE 3 - processing vulns
    hosts = {}
    for pres_data in presets_id.items():
        if not pres_data[1] in presets_vuln_collection.keys():
            log(f"Error: No vulnerabilities loaded for {pres_data[0]} ({pres_data[1]})")
            continue
        for vuln_pack in presets_vuln_collection[pres_data[1]]:
            for vuln in vuln_pack:
                if not vuln["device"]["label"] in hosts:
                    hosts[vuln["device"]["label"]] = {
                        "ip": vuln["device"]["label"],
                        "description": f"Device ID {vuln['device']['id']}",
                        "mac": "" if not vuln["device"]["mac"] else vuln["device"]["mac"],
                        "vulnerabilities": [],
                        "tags": [pres_data[0]] + asset_tags,
                    }
                if not vuln["title"] in [x["name"] for x in hosts[vuln["device"]["label"]]["vulnerabilities"]]:
                    try:
                        vuln["cvss"] = float(vuln["cvss"])
                    except ValueError:
                        vuln["cvss"] = -1.0
                    hosts[vuln["device"]["label"]]["vulnerabilities"].append(
                        {
                            "name": vuln["title"],
                            "desc": vuln["summary"],
                            "severity": severity_from_score(vuln["cvss"], 10.0),
                            "refs": [{"name": ref["link"], "type": "other"} for ref in vuln["links"]],
                            "external_id": vuln["id"],
                            "type": "Vulnerability",
                            "resolution": vuln["solution"],
                            "data": vuln["fullDescription"],
                            "status": "open",
                            "cve": [x["cve"] for i, x in enumerate(vuln_pack) if x["title"] == vuln["title"]],
                            "run_date": parse_date(vuln["publishTime"]),
                            "tags": vuln_tags,
                            "cwe": [],
                        }
                    )
    data = {"hosts": [x[1] for x in hosts.items()]}
    print(json.dumps(data))


def main():
    params_cybervision_token = os.getenv("CYBERVISION_TOKEN")
    params_cybervision_url = os.getenv("CYBERVISION_HTTPS_URL")
    params_cybervision_presets_env = os.getenv("EXECUTOR_CONFIG_CYBERVISION_PRESETS")

    params_cybervision_presets = []
    if params_cybervision_presets_env:
        params_cybervision_presets = json.loads(params_cybervision_presets_env)

    if not params_cybervision_url.startswith("https://"):
        log("Cyber Vision URL must be HTTPS")
        sys.exit(1)

    params_vulnerability_tags = os.getenv("AGENT_CONFIG_VULN_TAG") or []
    if params_vulnerability_tags:
        params_vulnerability_tags = params_vulnerability_tags.split(",")
    params_asset_tags = os.getenv("AGENT_CONFIG_HOSTNAME_TAG") or []
    if params_asset_tags:
        params_asset_tags = params_asset_tags.split(",")

    cybervision_report_composer(
        params_cybervision_url,
        params_cybervision_token,
        params_cybervision_presets,
        params_asset_tags,
        params_vulnerability_tags,
    )


if __name__ == "__main__":
    main()
