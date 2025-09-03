#!/usr/bin/env python
import os
import sys
import json
import datetime

from urllib3.exceptions import InsecureRequestWarning

import requests

from faraday_agent_dispatcher.utils.severity_utils import severity_from_score
from faraday_agent_dispatcher.utils.logging import log

API_BASE = "/api/3.0"
MY_PRESET_LABEL = "My preset"


def parse_date(date_str):
    try:
        return datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").timestamp()
    except ValueError:
        return ""


def cybervision_report_composer(
    url,
    token,
    preset_list,
    asset_tags,
    vuln_tags,
    presets_containing=None,
    only_my_presets=True,
    only_preset_refresh=False,
):
    req_headers = {"accept": "application/json", "x-token-id": token}
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    presets_queue = []
    presets_id = {}

    log(f"My Presets: {only_my_presets}")
    log(f"Presets list: {preset_list}")
    log(f"Refresh Presets: {only_preset_refresh}")
    log(f"Presets Containing: {presets_containing}")

    # STAGE 1 - get preset list
    req_url = f"{url}{API_BASE}/presets"
    try:
        log("Getting presets...")
        resp = requests.get(req_url, headers=req_headers, timeout=20, verify=False).json()
    except TimeoutError:
        log("Can't reach Cyber Vision: connection timed out")
        sys.exit(1)
    if "error" in resp:
        log(f"API Error: {resp['error']}")
        sys.exit(1)
    if not preset_list:
        log("No specific presets selected.")
        for preset in resp:
            preset_label = preset.get("label")
            preset_id = preset.get("id")
            if only_my_presets:
                category = preset.get("category")
                if not category:
                    log(f"No category found for preset {preset_label}")
                    continue
                category_label = category.get("label")
                if not category_label:
                    log(f"No category found for preset {preset_label}")
                    continue
                if category_label == MY_PRESET_LABEL:
                    if presets_containing:
                        if presets_containing in preset_label:
                            log(f"Preset {preset_label} contains {presets_containing}")
                            presets_id[preset_label] = preset_id
                            presets_queue.append(preset_id)
                    else:
                        presets_id[preset_label] = preset_id
                        presets_queue.append(preset_id)
            else:
                if presets_containing:
                    if presets_containing in preset_label:
                        log(f"Preset {preset_label} contains {presets_containing}")
                        presets_id[preset_label] = preset_id
                        presets_queue.append(preset_id)
                else:
                    presets_id[preset_label] = preset_id
                    presets_queue.append(preset_id)
    else:
        log("Presets list selected")
        for req_preset in preset_list:
            for preset in resp:
                preset_label = preset.get("label")
                preset_id = preset.get("id")
                if preset_label == req_preset:
                    presets_id[preset_label] = preset_id
                    presets_queue.append(preset_id)

    log(f"Added {len(presets_queue)} presets to process.")
    presets_id_inv = {v: k for k, v in presets_id.items()}

    # Refresh STAGE. If set it will exit after finishing the refresh.
    if only_preset_refresh:
        log("Refreshing presets...")
        for _id in presets_queue:  # post to update to latest computed data
            req_refresh_url = f"{url}{API_BASE}/presets/{_id}/refreshData"
            try:
                log(f"Refreshing preset {_id}")
                resp = requests.post(req_refresh_url, headers=req_headers, timeout=20, verify=False)
            except TimeoutError:
                log("Can't reach Cyber Vision: connection timed out")
                sys.exit(1)
        sys.exit(1)

    # STAGE 2 - get all vulns per preset
    presets_vuln_collection = {}
    for _id in presets_queue:
        log(f"Trying to get data for preset {presets_id_inv[_id]}...")
        step_c = 1
        step_s = 100
        presets_vuln_collection[_id] = []
        while True:  # paged data fetch
            req_url = f"{url}{API_BASE}/presets/{_id}/visualisations/vulnerability-list?page={step_c}&size={step_s}"
            try:
                resp = requests.get(req_url, headers=req_headers, timeout=20, verify=False)
                if "Service unavailable" in resp.content.decode("UTF-8"):
                    log(f"Preset {presets_id_inv[_id]} data is not ready, skipping...")
                    break
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
                log(vuln)
                title = vuln.get("title", "")  # TODO: Que pasa si es vacío el titulo?
                device = vuln.get("device")
                if not device:
                    log(f"Error: No device for {vuln} ({title})")
                    continue
                device_label = device.get("label")
                device_id = device.get("id")
                if device_label not in hosts:
                    hosts[device_label] = {
                        "ip": device_label,
                        "description": f"Device ID {device_id}",
                        "mac": device.get("mac", ""),
                        "vulnerabilities": [],
                        "tags": [pres_data[0]] + asset_tags,
                    }
                if title not in [x["name"] for x in hosts[device_label]["vulnerabilities"]]:

                    try:
                        cvss_base_score = float(vuln.get("CVSS", -1.0))
                    except ValueError:
                        cvss_base_score = -1.0

                    hosts[device_label]["vulnerabilities"].append(
                        {
                            "name": title,
                            "desc": vuln.get("summary"),
                            "severity": severity_from_score(cvss_base_score, 10.0),
                            "refs": [{"name": ref.get("link", ""), "type": "other"} for ref in vuln.get("links", [])],
                            "external_id": "",
                            "type": "Vulnerability",
                            "resolution": vuln.get("solution"),
                            "data": vuln.get("fullDescription"),
                            "status": "open",
                            "cve": [x.get("cve") for i, x in enumerate(vuln_pack) if x.get("title") == title],
                            "run_date": parse_date(vuln.get("publishTime")),
                            "tags": vuln_tags,
                            "cwe": [],
                        }
                    )

    data = {"hosts": [x[1] for x in hosts.items()]}
    print(json.dumps(data))


def main():
    params_cybervision_token = os.getenv("CYBERVISION_TOKEN")
    params_cybervision_url = os.getenv("CYBERVISION_HTTPS_URL")

    fetch_specific_presets = os.getenv("EXECUTOR_CONFIG_SPECIFIC_PRESETS")
    fetch_presets_containing = os.getenv("EXECUTOR_CONFIG_PRESETS_CONTAINING", None)
    fetch_my_presets = bool(os.getenv("EXECUTOR_CONFIG_MY_PRESETS", False))
    only_refresh_presets = bool(os.getenv("EXECUTOR_CONFIG_REFRESH_PRESETS", False))

    params_fetch_specific_presets_list = []
    if fetch_specific_presets:
        params_fetch_specific_presets_list = json.loads(fetch_specific_presets)

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
        params_fetch_specific_presets_list,
        params_asset_tags,
        params_vulnerability_tags,
        only_my_presets=fetch_my_presets,
        presets_containing=fetch_presets_containing,
        only_preset_refresh=only_refresh_presets,
    )


if __name__ == "__main__":
    main()
