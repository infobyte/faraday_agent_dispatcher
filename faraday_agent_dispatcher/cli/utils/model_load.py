import click
from pathlib import Path

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


def ask_value(agent_dict, opt, section, ssl, control_opt=None):
    def_value = config.instance[section].get(opt, None) or \
                agent_dict[section][opt]["default_value"](ssl)
    value = None
    while value is None:
        value = click.prompt(
            f"{opt}",
            default=def_value,
            type=agent_dict[section][opt]["type"]
        )
        if value == "":
            print(
                f"{Bcolors.WARNING}Trying to save with empty value"
                f"{Bcolors.ENDC}"
            )
        try:
            if control_opt is None:
                config.__control_dict[section][opt](opt, value)
            else:
                config.__control_dict[section][control_opt](opt, value)
        except ValueError as e:
            print(f"{Bcolors.FAIL}{e}{Bcolors.ENDC}")
            value = None
    return value


def process_agent():
    agent_dict = {
        Sections.SERVER: {
            "host": {
                "default_value": lambda _: "127.0.0.1",
                "type": click.STRING,
            },
            "ssl": {
                "default_value": lambda _: "True",
                "type": click.BOOL,
            },
            "ssl_port": {
                "default_value": lambda _: "443",
                "type": click.IntRange(min=1, max=65535),
            },
            "ssl_cert": {
                "default_value": lambda _: "",
                "type": click.Path(allow_dash=False, dir_okay=False),
            },
            "api_port":  {
                "default_value": lambda _ssl: "443" if _ssl else "5985",
                "type": click.IntRange(min=1, max=65535),
            },
            "websocket_port":   {
                "default_value": lambda _ssl: "443" if _ssl else "9000",
                "type": click.IntRange(min=1, max=65535),
            },
            "workspaces": {
                "default_value": lambda _: "workspace",
                "type": click.STRING,
            }
        },
        Sections.TOKENS: {
            "registration": {
                "default_value": lambda _: "ACorrectTokenIs25CharLen",
                "type": click.STRING,
            },
            "agent": {}
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
        print(f"{Bcolors.OKBLUE}Section: {section}{Bcolors.ENDC}")
        for opt in agent_dict[section]:
            if section not in config.instance:
                config.instance.add_section(section)
            if section == Sections.TOKENS and opt == "agent":
                if "agent" in config.instance.options(section) \
                        and confirm_prompt("Delete agent token?"):
                    config.instance.remove_option(section, opt)
            elif section == Sections.SERVER and opt.__contains__("port"):
                if opt == "ssl_port":
                    if ssl:
                        value = ask_value(
                            agent_dict,
                            opt,
                            section,
                            ssl,
                            'api_port'
                        )
                        config.instance.set(
                            section,
                            'api_port',
                            str(value)
                        )
                        config.instance.set(
                            section,
                            'websocket_port',
                            str(value)
                        )
                    else:
                        continue
                else:
                    if not ssl:
                        value = ask_value(agent_dict, opt, section, ssl)
                        config.instance.set(section, opt, str(value))
                    else:
                        continue
            elif opt == "ssl_cert":
                if ssl:

                    if confirm_prompt("Default SSL behavior?"):
                        path = ""
                    else:
                        path = None
                        while path is None:
                            value = ask_value(agent_dict, opt, section, ssl)
                            if value != "" and Path(value).exists():
                                path = value
                    config.instance.set(section, opt, str(path))
            elif opt == "workspaces":
                process_workspaces()
            else:
                value = ask_value(agent_dict, opt, section, ssl)
                if opt == "ssl":
                    ssl = str(value).lower() == "true"
                config.instance.set(section, opt, str(value))


def process_workspaces() -> None:
    end = False
    section = Sections.SERVER

    workspaces = config.instance[Sections.SERVER].get("workspaces", "")
    workspaces = workspaces.split(",")
    if "" in workspaces:
        workspaces.remove("")

    while not end:
        print(
            f"The actual workspaces{Bcolors.ENDC} are:"
            f" {Bcolors.OKGREEN}{workspaces}{Bcolors.ENDC}"
        )
        value = choose_adm("workspace", ignore=["M"])
        if value == "A":
            workspace_name = click.prompt("Workspace name")
            if workspace_name in workspaces:
                print(
                    f"{Bcolors.WARNING}The workspace {workspace_name} already "
                    f"exists{Bcolors.ENDC}"
                )
            else:
                workspaces.append(workspace_name)
        elif value == "D":
            workspace_name = click.prompt("workspace name")
            if workspace_name not in workspaces:
                print(
                    f"{Bcolors.WARNING}There is no {workspace_name}"
                    f"workspace{Bcolors.ENDC}"
                )
            else:
                workspaces.remove(workspace_name)
        else:
            end = True

    config.instance.set(section, "workspaces", ",".join(workspaces))


def process_var_envs(executor_name):
    end = False
    section = Sections.EXECUTOR_VARENVS.format(executor_name)

    while not end:
        print(
            f"The actual {Bcolors.BOLD}{Bcolors.OKBLUE}{executor_name}"
            f" executor's environment variables{Bcolors.ENDC} are:"
            f" {Bcolors.OKGREEN}{config.instance.options(section)}"
            f"{Bcolors.ENDC}"
        )
        value = choose_adm("environment variable")
        if value == "A":
            env_var = click.prompt("Environment variable name").lower()
            if env_var in config.instance.options(section):
                print(
                    f"{Bcolors.WARNING}The environment variable {env_var} "
                    f"already exists{Bcolors.ENDC}"
                )
            else:
                value = click.prompt("Environment variable value")
                config.instance.set(section, env_var, value)
        elif value == "M":
            env_var = click.prompt("Environment variable name").lower()
            if env_var not in config.instance.options(section):
                print(
                    f"{Bcolors.WARNING}There is no {env_var} environment "
                    f"variable{Bcolors.ENDC}"
                )
            else:
                def_value, env_var = get_new_name(
                    env_var,
                    section,
                    "environment variable"
                )
                value = click.prompt(
                    "Environment variable value",
                    default=def_value
                )
                config.instance.set(section, env_var, value)
        elif value == "D":
            env_var = click.prompt("Environment variable name").lower()
            if env_var not in config.instance.options(section):
                print(
                    f"{Bcolors.WARNING}There is no {env_var}"
                    f"environment variable{Bcolors.ENDC}"
                )
            else:
                config.instance.remove_option(section, env_var)
        else:
            end = True


def process_params(executor_name):
    end = False
    section = Sections.EXECUTOR_PARAMS.format(executor_name)

    while not end:
        print(
            f"The actual {Bcolors.BOLD}{Bcolors.OKBLUE}{executor_name}"
            f" executor's arguments{Bcolors.ENDC} are: "
            f"{Bcolors.OKGREEN}{config.instance.options(section)}"
            f"{Bcolors.ENDC}"
        )
        value = choose_adm("argument")
        if value == "A":
            param = click.prompt("Argument name").lower()
            if param in config.instance.options(section):
                print(
                    f"{Bcolors.WARNING}The argument {param} already exists"
                    f"{Bcolors.ENDC}"
                )
            else:
                value = confirm_prompt("Is mandatory?")
                config.instance.set(section, param, f"{value}")
        elif value == "M":
            param = click.prompt("Argument name").lower()
            if param not in config.instance.options(section):
                print(
                    f"{Bcolors.WARNING}There is no {param} argument"
                    f"{Bcolors.ENDC}"
                )
            else:
                def_value, param = get_new_name(param, section, "argument")
                value = confirm_prompt("Is mandatory?", default=def_value)
                config.instance.set(section, param, f"{value}")
        elif value == "D":
            param = click.prompt("Argument name").lower()
            if param not in config.instance.options(section):
                print(
                    f"{Bcolors.WARNING}There is no {param} argument"
                    f"{Bcolors.ENDC}"
                )
            else:
                config.instance.remove_option(section, param)
        else:
            end = True


def process_repo_var_envs(executor_name, metadata: dict):
    section = Sections.EXECUTOR_VARENVS.format(executor_name)
    env_vars = metadata["environment_variables"]

    for env_var in env_vars:
        def_value = config.instance[section].get(env_var, None)
        value = click.prompt(
            f"Environment variable {env_var} value",
            default=def_value
        )
        config.instance.set(section, env_var, value)


def set_repo_params(executor_name, metadata: dict):
    section = Sections.EXECUTOR_PARAMS.format(executor_name)
    params: dict = metadata["arguments"]
    for param, value in params.items():
        config.instance.set(section, param, f"{value}")
