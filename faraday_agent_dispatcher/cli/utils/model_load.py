import click
from urllib.parse import urlparse

from faraday_agent_dispatcher import config
from faraday_agent_dispatcher.cli.utils.general_inputs import (
    confirm_prompt,
    choose_adm,
)
from faraday_agent_dispatcher.cli.utils.general_prompts import (
    get_new_name,
)
from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_parameters_types.data_types import DATA_TYPE


def append_keys(agent_dict, section):
    agent_dict[section]["api_port"] = {
        "default_value": lambda _ssl: "443" if _ssl else "5985",
        "type": click.IntRange(min=1, max=65535),
    }
    agent_dict[section]["websocket_port"] = {
        "default_value": lambda _ssl: "443" if _ssl else "9000",
        "type": click.IntRange(min=1, max=65535),
    }
    return agent_dict


def url_setting(url):
    url_info = {"url_name": None, "url_path": None, "check_ssl": False, "api_port": None, "websocket_port": None}
    url_host = urlparse(url)

    if not url_host.scheme:
        url = f"http://{url}"
        url_host = urlparse(url)
        url_info["check_ssl"] = None

    url_info["url_name"] = url_host.netloc
    url_info["url_path"] = url_host.path[1:]

    match_port = url_info["url_name"].find(":")
    if match_port >= 0:
        url_info["url_name"] = url_info["url_name"][:match_port]

    if url_info["check_ssl"] is not None:
        if url_host.scheme == "http":
            if url_host.port:
                url_info["api_port"] = url_host.port
                url_info["websocket_port"] = url_host.port
            else:
                url_info["api_port"] = 5985
                url_info["websocket_port"] = 9000
            url_info["check_ssl"] = False
        elif url_host.scheme == "https":
            if url_host.port:
                url_info["api_port"] = url_host.port
                url_info["websocket_port"] = url_host.port
            else:
                url_info["api_port"] = 443
                url_info["websocket_port"] = 443
            url_info["check_ssl"] = True

    return url_info


def ask_value(agent_dict, opt, section, ssl, control_opt=None):
    info_url = {}

    if agent_dict[section][opt]["type"] == click.BOOL:
        def_value = config.instance[section].get(opt, None)
        if def_value is None:
            def_value = agent_dict[section][opt]["default_value"](ssl)
    else:
        def_value = config.instance[section].get(opt, None) or agent_dict[section][opt]["default_value"](ssl)

    value = None
    while value is None:
        if agent_dict[section][opt]["type"] == click.BOOL:
            value = confirm_prompt(f"{opt}", default=def_value)
        else:
            value = click.prompt(f"{opt}", default=def_value, type=agent_dict[section][opt]["type"])
        if opt == "host":
            info_url = url_setting(value)
            value = info_url["url_name"]

        if value == "":
            click.secho("Trying to save with empty value", fg="yellow")
        try:
            if control_opt is None:
                config.__control_dict[section][opt](opt, value)
            else:
                config.__control_dict[section][control_opt](opt, value)
        except ValueError as e:
            click.secho(f"{e}", fg="red")
            value = None
    return value, info_url


def process_agent():
    agent_dict = {
        Sections.SERVER: {
            "host": {
                "default_value": lambda _: "127.0.0.1",
                "type": click.STRING,
            },
            "ssl": {
                "default_value": lambda _: True,
                "type": click.BOOL,
            },
            "ssl_ignore": {
                "default_value": lambda _: False,
                "type": click.BOOL,
            },
            "workspaces": {
                "default_value": lambda _: "workspace",
                "type": click.STRING,
            },
        },
        Sections.TOKENS: {
            "agent": {},
        },
        Sections.AGENT: {
            "agent_name": {
                "default_value": lambda _: "agent",
                "type": click.STRING,
            }
        },
    }

    ssl = True

    for section in agent_dict:
        if Sections.TOKENS == section and (section not in config.instance or "agent" not in config.instance[section]):
            continue
        print(f"{Bcolors.OKBLUE}Section: {section}{Bcolors.ENDC}")
        for opt in agent_dict[section]:
            if section not in config.instance:
                config.instance[section] = dict()
            if section == Sections.TOKENS and opt == "agent":
                if "agent" in config.instance[section] and confirm_prompt("Delete agent token?", default=None):
                    config.instance[section].pop(opt)
            elif opt == "workspaces":
                process_workspaces()
            else:
                if opt == "host":
                    value, url_json = ask_value(agent_dict, opt, section, ssl)
                    if url_json["url_path"]:
                        config.instance[section]["base_route"] = str(url_json["url_path"])
                elif opt == "ssl":
                    old_ssl_value = config.instance[section].get("ssl", None)
                    if url_json["check_ssl"] is None:
                        value, _ = ask_value(agent_dict, opt, section, ssl)
                        ssl = value
                    else:
                        ssl = str(url_json["check_ssl"]).lower() == "true"
                        value = ssl

                    if old_ssl_value != value:
                        config.instance[section].pop("api_port", None)
                        config.instance[section].pop("websocket_port", None)

                    if url_json["api_port"] is None:
                        agent_dict = append_keys(agent_dict, Sections.SERVER)
                        for type_ports in ["api_port", "websocket_port"]:
                            value_port, _ = ask_value(agent_dict, type_ports, section, ssl, type_ports)
                            config.instance[section][type_ports] = value_port
                            agent_dict[Sections.SERVER].pop(type_ports, None)

                    else:
                        config.instance[section]["api_port"] = url_json["api_port"]
                        config.instance[section]["websocket_port"] = url_json["websocket_port"]
                elif opt == "ssl_ignore" and not ssl:
                    continue
                else:
                    value, _ = ask_value(agent_dict, opt, section, ssl)
                config.instance[section][opt] = value


def process_workspaces() -> None:
    end = False
    section = Sections.SERVER

    workspaces = config.instance[Sections.SERVER].get("workspaces", [])

    while not end:
        print(f"The current workspaces{Bcolors.ENDC} are:" f" {Bcolors.OKGREEN}{workspaces}{Bcolors.ENDC}")
        value = choose_adm("workspace", ignore=["M"])
        if value == "A":
            workspace_name = click.prompt("Workspace name")
            if workspace_name in workspaces:
                print(f"{Bcolors.WARNING}The workspace {workspace_name} already " f"exists{Bcolors.ENDC}")
            else:
                workspaces.append(workspace_name)
        elif value == "D":
            workspace_name = click.prompt("workspace name")
            if workspace_name not in workspaces:
                print(f"{Bcolors.WARNING}There is no {workspace_name}" f"workspace{Bcolors.ENDC}")
            else:
                workspaces.remove(workspace_name)
        else:
            end = True

    config.instance[section]["workspaces"] = workspaces


def process_var_envs(executor_name):
    end = False
    if "varenvs" not in config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name]:
        config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name]["varenvs"] = {}
    section = config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name].get("varenvs")

    while not end:
        print(
            f"The current {Bcolors.BOLD}{Bcolors.OKBLUE}{executor_name}"
            f" executor's environment variables{Bcolors.ENDC} are:"
            f" {Bcolors.OKGREEN}{list(section.keys())}"
            f"{Bcolors.ENDC}"
        )
        value = choose_adm("environment variable")
        if value == "A":
            env_var = click.prompt("Environment variable name").lower()
            if env_var in section:
                print(f"{Bcolors.WARNING}The environment variable {env_var} " f"already exists{Bcolors.ENDC}")
            else:
                value = click.prompt("Environment variable value")
                section[env_var] = value
        elif value == "M":
            env_var = click.prompt("Environment variable name").lower()
            if env_var not in section:
                print(f"{Bcolors.WARNING}There is no {env_var} environment " f"variable{Bcolors.ENDC}")
            else:
                def_value, env_var = get_new_name(env_var, section, "environment variable")
                value = click.prompt("Environment variable value", default=def_value)
                section[env_var] = value
        elif value == "D":
            env_var = click.prompt("Environment variable name").lower()
            if env_var not in section:
                print(f"{Bcolors.WARNING}There is no {env_var}" f"environment variable{Bcolors.ENDC}")
            else:
                section.pop(env_var)
        else:
            end = True


def process_params(executor_name):
    end = False
    if "params" not in config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name]:
        config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name]["params"] = {}
    section = config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name].get("params")

    while not end:
        print(
            f"The current {Bcolors.BOLD}{Bcolors.OKBLUE}{executor_name}"
            f" executor's arguments{Bcolors.ENDC} are: "
            f"{Bcolors.OKGREEN}{list(section.keys())}"
            f"{Bcolors.ENDC}"
        )
        value = choose_adm("argument")
        if value == "A":
            param = click.prompt("Argument name").lower()
            if param in section:
                print(f"{Bcolors.WARNING}The argument {param} already exists" f"{Bcolors.ENDC}")
            else:
                mandatory = confirm_prompt("Is mandatory?")
                input_type = click.prompt("Type?", type=click.Choice(DATA_TYPE.keys()))
                input_base_type = DATA_TYPE[input_type].type().base
                section[param] = {"mandatory": mandatory, "type": input_type, "base": input_base_type}
        elif value == "M":
            param = click.prompt("Argument name").lower()
            if param not in section:
                print(f"{Bcolors.WARNING}There is no {param} argument" f"{Bcolors.ENDC}")
            else:
                def_value, param = get_new_name(param, section, "argument")
                mandatory = confirm_prompt("Is mandatory?", default=def_value["mandatory"])
                input_type = click.prompt("Type?", type=click.Choice(DATA_TYPE.keys()), default=def_value["type"])
                input_base_type = DATA_TYPE[input_type].type().base
                section[param] = {"mandatory": mandatory, "type": input_type, "base": input_base_type}
        elif value == "D":
            param = click.prompt("Argument name").lower()
            if param not in section:
                print(f"{Bcolors.WARNING}There is no {param} argument" f"{Bcolors.ENDC}")
            else:
                section.pop(param)
        else:
            end = True


def process_repo_var_envs(executor_name, metadata: dict):
    env_vars = metadata["environment_variables"]
    if "varenvs" not in config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name]:
        config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name]["varenvs"] = {}
    section = config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name].get("varenvs")

    for env_var in env_vars:
        def_value = section.get(env_var, None)
        value = click.prompt(f"Environment variable {env_var} value", default=def_value)
        section[env_var] = value


def set_repo_params(executor_name, metadata: dict):
    params: dict = metadata["arguments"]
    if "params" not in config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name]:
        config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name]["params"] = {}
    section = config.instance[Sections.AGENT][Sections.EXECUTORS][executor_name].get("params")

    for param, value in params.items():
        section[param] = value
