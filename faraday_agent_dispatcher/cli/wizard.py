import os
import sys

import click
from pathlib import Path

from faraday_agent_dispatcher import config
from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher.utils.text_utils import Bcolors


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
                "type": click.Path(allow_dash=False),
            },
            "api_port":  {
                "default_value": lambda _ssl: "443" if _ssl else "5985",
                "type": click.IntRange(min=1, max=65535),
            },
            "websocket_port":   {
                "default_value": lambda _ssl: "443" if _ssl else "9000",
                "type": click.IntRange(min=1, max=65535),
            },
            "workspace": {
                "default_value": lambda _: "workspace",
                "type": click.STRING,
            }
        },
        Sections.TOKENS: {
            "registration": {
                "default_value": lambda _: "ACorrectTokenHas25CharLen",
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
                        value = ask_value(agent_dict, opt, section, ssl, 'api_port')
                        config.instance.set(section, 'api_port', str(value))
                        config.instance.set(section, 'websocket_port', str(value))
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
                    value = ask_value(agent_dict, opt, section, ssl)
                    config.instance.set(section, opt, str(value))
            else:
                value = ask_value(agent_dict, opt, section, ssl)
                if opt == "ssl":
                    ssl = value == "True"
                config.instance.set(section, opt, str(value))


def ask_value(agent_dict, opt, section, ssl, control_opt=None):
    def_value = config.instance[section].get(opt, None) or agent_dict[section][opt]["default_value"](ssl)
    value = None
    while value is None:
        value = click.prompt(f"{opt}", default=def_value, type=agent_dict[section][opt]["type"])
        if value == "":
            print(f"{Bcolors.WARNING}Trying to save with empty value{Bcolors.ENDC}")
        try:
            if control_opt is None:
                config.__control_dict[section][opt](opt, value)
            else:
                config.__control_dict[section][control_opt](opt, value)
        except ValueError as e:
            print(f"{Bcolors.FAIL}{e}{Bcolors.ENDC}")
            value = None
    return value


def get_default_value_and_choices(default_value, choices):
    if "DEBUG_INPUT_MODE" in os.environ:
        default_value = None
        choices = choices + ["\0"]
    return default_value, choices


def confirm_prompt(text: str, default:bool = None):
    if default is not None:
        default = "Y" if default else "N"
    return click.prompt(text=text, type=click.Choice(["Y", "N"], case_sensitive=False), default=default).upper() == 'Y'


def process_choice_errors(value):
    if "DEBUG_INPUT_MODE" in os.environ and value in ["\0"]:
        raise click.exceptions.Abort()


def choose_adm(subject):
    def_value, choices = get_default_value_and_choices("Q", ["A", "M", "D", "Q"])
    value = click.prompt(f"Do you want to [A]dd, [M]odify or [D]elete an {subject}? Do you want to [Q]uit?",
                         type=click.Choice(choices=choices, case_sensitive=False),
                         default=def_value).upper()
    process_choice_errors(value)
    return value


def process_var_envs(executor_name):
    end = False
    section = Sections.EXECUTOR_VARENVS.format(executor_name)

    while not end:
        print(f"The actual {Bcolors.BOLD}{Bcolors.OKBLUE}{executor_name} executor's environment variables{Bcolors.ENDC}"
              f" are: {Bcolors.OKGREEN}{config.instance.options(section)}{Bcolors.ENDC}")
        value = choose_adm("environment variable")
        if value == "A":
            env_var = click.prompt("Environment variable name").lower()
            if env_var in config.instance.options(section):
                print(f"{Bcolors.WARNING}The environment variable {env_var} already exists{Bcolors.ENDC}")
            else:
                value = click.prompt("Environment variable value")
                config.instance.set(section, env_var, value)
        elif value == "M":
            env_var = click.prompt("Environment variable name").lower()
            if env_var not in config.instance.options(section):
                print(f"{Bcolors.WARNING}There is no {env_var} environment variable{Bcolors.ENDC}")
            else:
                def_value, env_var = get_new_name(env_var, section, "environment variable")
                value = click.prompt("Environment variable value", default=def_value)
                config.instance.set(section, env_var, value)
        elif value == "D":
            env_var = click.prompt("Environment variable name").lower()
            if env_var not in config.instance.options(section):
                print(f"{Bcolors.WARNING}There is no {env_var} environment variable{Bcolors.ENDC}")
            else:
                config.instance.remove_option(section, env_var)
        else:
            end = True


def get_new_name(name: str, section: str, named_type: str):
    new_name = None
    while new_name is None:
        new_name = click.prompt("New name", default=name)
        if new_name in config.instance.options(section) and name != new_name:
            print(f"{Bcolors.WARNING}The {named_type} {new_name} already exists{Bcolors.ENDC}")
            new_name = None
    def_value = config.instance.get(section, name)
    if name != new_name:
        config.instance.remove_option(section, name)
        name = new_name
    return def_value, name


def process_params(executor_name):
    end = False
    section = Sections.EXECUTOR_PARAMS.format(executor_name)

    while not end:
        print(f"The actual {Bcolors.BOLD}{Bcolors.OKBLUE}{executor_name} executor's arguments{Bcolors.ENDC} are: "
              f"{Bcolors.OKGREEN}{config.instance.options(section)}{Bcolors.ENDC}")
        value = choose_adm("argument")
        if value == "A":
            param = click.prompt("Argument name").lower()
            if param in config.instance.options(section):
                print(f"{Bcolors.WARNING}The argument {param} already exists{Bcolors.ENDC}")
            else:
                value = confirm_prompt("Is mandatory?")
                config.instance.set(section, param, f"{value}")
        elif value == "M":
            param = click.prompt("Argument name").lower()
            if param not in config.instance.options(section):
                print(f"{Bcolors.WARNING}There is no {param} argument{Bcolors.ENDC}")
            else:
                def_value, param = get_new_name(param, section, "argument")
                value = confirm_prompt("Is mandatory?", default=def_value)
                config.instance.set(section, param, f"{value}")
        elif value == "D":
            param = click.prompt("Argument name").lower()
            if param not in config.instance.options(section):
                print(f"{Bcolors.WARNING}There is no {param} argument{Bcolors.ENDC}")
            else:
                config.instance.remove_option(section, param)
        else:
            end = True


class Wizard:

    MAX_BUFF_SIZE = 1024

    def __init__(self, config_filepath: Path):
        self.config_filepath = config_filepath

        try:
            config.reset_config(config_filepath)
        except ValueError as e:
            if e.args[1] or config_filepath.is_file():
                raise e  # the filepath is either a file, or a folder containing a file, which can't be processed
        try:
            config.verify()
        except ValueError as e:
            print(f"{Bcolors.FAIL}{e}{Bcolors.ENDC}")
            sys.exit(1)
        self.executors_list = []
        self.load_executors()

    def run(self):
        end = False

        def_value, choices = get_default_value_and_choices("Q", ["A", "E", "Q"])

        while not end:
            value = click.prompt("Do you want to edit the [A]gent or the [E]xecutors? Do you want to [Q]uit?",
                                 type=click.Choice(choices=choices, case_sensitive=False),
                                 default=def_value)
            if value.upper() == "A":
                process_agent()
            elif value.upper() == "E":
                self.process_executors()
            else:
                process_choice_errors(value)
                try:
                    if Sections.AGENT in config.instance.sections():
                        self.save_executors()
                        config.control_config()
                        end = True
                    else:
                        print(f"{Bcolors.FAIL}Add agent configuration{Bcolors.ENDC}")

                except ValueError as e:
                    print(f"{Bcolors.FAIL}{e}{Bcolors.ENDC}")

        config.save_config(self.config_filepath)

    def load_executors(self):
        if Sections.AGENT in config.instance:
            executors = config.instance[Sections.AGENT].get("executors", "")
            self.executors_list = executors.split(",")
            if "" in self.executors_list:
                self.executors_list.remove("")

    def save_executors(self):
        config.instance.set(Sections.AGENT, "executors", ",".join(self.executors_list))

    def process_executors(self):
        end = False

        while not end:
            print(f"The actual configured {Bcolors.OKBLUE}{Bcolors.BOLD}executors{Bcolors.ENDC} are: {Bcolors.OKGREEN}"
                  f"{self.executors_list}{Bcolors.ENDC}")
            value = choose_adm("executor")
            if value.upper() == "A":
                self.new_executor()
            elif value.upper() == "M":
                self.edit_executor()
            elif value.upper() == "D":
                self.delete_executor()
            else:
                end = True

    def new_executor(self):
        name = click.prompt("Name")
        if name in self.executors_list:
            print(f"{Bcolors.WARNING}The executor {name} already exists{Bcolors.ENDC}")
            return
        self.executors_list.append(name)
        cmd = click.prompt("Command to execute", default="exit 1")
        max_buff_size = click.prompt("Max data sent to server",
                                     type=click.IntRange(min=Wizard.MAX_BUFF_SIZE), default=65536)
        for section in Wizard.EXECUTOR_SECTIONS:
            formatted_section = section.format(name)
            config.instance.add_section(formatted_section)
        config.instance.set(Sections.EXECUTOR_DATA.format(name), "cmd", cmd)
        config.instance.set(Sections.EXECUTOR_DATA.format(name), "max_size", f"{max_buff_size}")
        process_var_envs(name)
        process_params(name)

    EXECUTOR_SECTIONS = [Sections.EXECUTOR_DATA, Sections.EXECUTOR_PARAMS, Sections.EXECUTOR_VARENVS]

    def edit_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_list:
            print(f"{Bcolors.WARNING}There is no {name} executor{Bcolors.ENDC}")
            return
        new_name = None
        while new_name is None:
            new_name = click.prompt("New name", default=name)
            if new_name in self.executors_list and name != new_name:
                print(f"{Bcolors.WARNING}The executor {name} already exists{Bcolors.ENDC}")
                new_name = None
        if new_name != name:
            for unformatted_section in Wizard.EXECUTOR_SECTIONS:
                section = unformatted_section.format(new_name)
                config.instance.add_section(section)
                for item in config.instance.items(unformatted_section.format(name)):
                    config.instance.set(section, item[0], item[1])
                config.instance.remove_section(unformatted_section.format(name))
            self.executors_list.remove(name)
            self.executors_list.append(new_name)
            name = new_name
        section = Sections.EXECUTOR_DATA.format(name)
        cmd = click.prompt("Command to execute",
                           default=config.instance.get(section, "cmd"))
        max_buff_size = click.prompt("Max data sent to server", type=click.IntRange(min=Wizard.MAX_BUFF_SIZE),
                                     default=config.instance.get(section, "max_size"))
        config.instance.set(section, "cmd", cmd)
        config.instance.set(section, "max_size", f"{max_buff_size}")
        process_var_envs(name)
        process_params(name)

    def delete_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_list:
            print(f"{Bcolors.WARNING}There is no {name} executor{Bcolors.ENDC}")
            return
        for section in Wizard.EXECUTOR_SECTIONS:
            config.instance.remove_section(section.format(name))
        self.executors_list.remove(name)
