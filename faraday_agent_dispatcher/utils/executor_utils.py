

def get_plugins_args(my_envs):
    ignore_info = my_envs.get("AGENT_CONFIG_IGNORE_INFO", "False").lower() == "true"
    hostname_resolution = my_envs.get("AGENT_CONFIG_RESOLVE_HOSTNAME", "True").lower() == "true"
    vuln_tag = my_envs.get("AGENT_CONFIG_VULN_TAG", None)
    if vuln_tag:
        vuln_tag = vuln_tag.split(",")
    service_tag = my_envs.get("AGENT_CONFIG_SERVICE_TAG", None)
    if service_tag:
        service_tag = service_tag.split(",")
    host_tag = my_envs.get("AGENT_CONFIG_HOSTNAME_TAG", None)
    if host_tag:
        host_tag = host_tag.split(",")
    return {
        "ignore_info": ignore_info,
        "hostname_resolution": hostname_resolution,
        "vuln_tag": vuln_tag,
        "service_tag": service_tag,
        "host_tag": host_tag,
    }