import os

import click
from pathlib import Path

from faraday_agent_dispatcher import config
from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher.utils.text_utils import Bcolors


def process_agent():
    agent_dict = {
        Sections.SERVER: {
            "host": "127.0.0.1", "api_port": 6000, "websocket_port": 6006, "workspace": "works"
        },
        Sections.TOKENS: {
            "registration": "ACorrectTokenHas25CharLen"
                 },
        Sections.AGENT: {
            "agent_name": "agent"
        },
    }

    for section in agent_dict:
        print(f"{Bcolors.OKBLUE}Section: {section}{Bcolors.ENDC}")
        for opt in agent_dict[section]:
            if section not in config.instance:
                config.instance.add_section(section)
            def_value = config.instance[section].get(opt, None) or agent_dict[section][opt]
            value = click.prompt(f"{opt}", default=def_value)
            if value == "":
                print(f"{Bcolors.WARNING}TODO WARNING{Bcolors.ENDC}")
            config.__control_dict[section][opt](opt, value)

            config.instance.set(section, opt, str(value))


def get_default_value_and_choices(default_value, choices):
    if "DEFAULT_VALUE_NONE" in os.environ:
        default_value = None
        choices = choices + ["Q", "\0"]
    return default_value, choices


def confirm_prompt(text: str, default=None):
    return click.prompt(text=text, type=click.Choice(["Y", "N"]), default=default) == 'Y'


def process_choice_errors(value):
    if "DEFAULT_VALUE_NONE" in os.environ and value in ["\0"]:
        raise click.exceptions.Abort()


def choose_adm(subject):
    def_value, choices = get_default_value_and_choices("", ["A", "M", "D"])
    value = click.prompt(f"Do you want to add, modify or delete an {subject}?",
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
                def_value = config.instance.get(section, env_var)
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
                old_value = config.instance.get(section, param)
                value = confirm_prompt("Is mandatory?", default=old_value)
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

    def __init__(self, config_filepath: Path):
        self.config_filepath = config_filepath

        try:
            config.reset_config(config_filepath)
        except ValueError as e:
            if e.args[1] or config_filepath.is_file():
                raise e  # the filepath is either a file, or a folder containing a file, which can't be processed
        config.verify()
        self.executors_list = []
        self.load_executors()

    def run(self):
        end = False

        def_value, choices = get_default_value_and_choices("", ["A", "E"])

        while not end:
            value = click.prompt("Do you want to edit the agent or the executors?",
                                 type=click.Choice(choices=choices, case_sensitive=False),
                                 default=def_value)
            if value.upper() == "A":
                process_agent()
            elif value.upper() == "E":
                self.process_executors()
            else:
                process_choice_errors(value)
                end = True
        self.save_executors()
        config.save_config(self.config_filepath)

    def load_executors(self):
        if Sections.AGENT in config.instance:
            executors = config.instance[Sections.AGENT].get("executors", "")
            self.executors_list = executors.split(",")

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
        max_buff_size = click.prompt("Max data sent to server", type=int, default=65536)
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
            print(f"{Bcolors.WARNING}There is no {name} argument{Bcolors.ENDC}")
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
            name = new_name
        section = Sections.EXECUTOR_DATA.format(name)
        cmd = click.prompt("Command to execute",
                           default=config.instance.get(section, "cmd"))
        max_buff_size = click.prompt("Max data sent to server", type=int,
                                     default=config.instance.get(section, "max_size"))
        config.instance.set(section, "cmd", cmd)
        config.instance.set(section, "max_size", f"{max_buff_size}")
        process_var_envs(name)
        process_params(name)

    def delete_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_list:
            print(f"{Bcolors.WARNING}There is no {name} argument{Bcolors.ENDC}")
            return
        for section in Wizard.EXECUTOR_SECTIONS:
            config.instance.remove_section(section.format(name))
        self.executors_list.remove(name)
