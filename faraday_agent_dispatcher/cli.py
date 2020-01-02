# -*- coding: utf-8 -*-

# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Console script for faraday_agent_dispatcher."""
import os
import sys

import click
import asyncio
import traceback

from aiohttp import ClientSession

from faraday_agent_dispatcher.dispatcher import Dispatcher
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_dispatcher import config
from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher.utils.text_utils import Bcolors
import faraday_agent_dispatcher.logger as logging
from pathlib import Path

logger = logging.get_logger()


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


def process_config_file(config_filepath: Path):
    if config_filepath is None and not os.path.exists(config.CONFIG_FILENAME):
        logger.info("Config file doesn't exist. Run the command `faraday-dispatcher config-wizard` to create one")
        exit(1)
    config_filepath = config_filepath or Path(config.CONFIG_FILENAME)
    config_filepath = Path(config_filepath)
    config.reset_config(config_filepath)


async def main(config_file):

    process_config_file(config_file)

    async with ClientSession(raise_for_status=True) as session:
        try:
            dispatcher = Dispatcher(session, config_file)
        except ValueError as ex:
            print(f'{Bcolors.FAIL}Error configuring dispatcher: '
                  f'{Bcolors.BOLD}{str(ex)}{Bcolors.ENDC}')
            print(f'Try checking your config file located at {Bcolors.BOLD}'
                  f'{config.CONFIG_FILENAME}{Bcolors.ENDC}')
            return 1
        await dispatcher.register()
        await dispatcher.connect()

    return 0


@click.command(help="faraday-dispatcher run")
@click.option("-c", "--config-file", default=None, help="Path to config ini file")
@click.option("--logdir", default="~", help="Path to logger directory")
def run(config_file, logdir):
    logging.reset_logger(logdir)
    logger = logging.get_logger()
    try:
        exit_code = asyncio.run(main(config_file))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logger.error(traceback.format_exception(exc_type, exc_value, exc_traceback))
        raise
    sys.exit(exit_code)


class Wizard:

    def __init__(self, config_filepath):
        self.config_filepath = config_filepath
        config.reset_config(config_filepath)
        config.verify()
        self.executors_list = []

    def run(self):
        end = False

        def_value, choices = self.get_default_value_and_choices("", ["A", "E"])

        while not end:
            value = click.prompt("Do you want to edit the agent or the executors?",
                                 type=click.Choice(choices=choices, case_sensitive=False),
                                 default=def_value)
            if value.upper() == "A":
                self.process_agent()
            elif value.upper() == "E":
                self.process_executors()
            else:
                self.process_choice_errors(value)
                end = True
        config.save_config(self.config_filepath)

    def choose_adm(self, subject):
        def_value, choices = self.get_default_value_and_choices("", ["A", "M", "D"])
        value = click.prompt(f"Do you want to add, modify or delete an {subject}?",
                             type=click.Choice(choices=choices, case_sensitive=False),
                             default=def_value).upper()
        self.process_choice_errors(value)
        return value

    def process_agent(self):
        agent_dict = {
            Sections.SERVER: [
                "host", "api_port", "websocket_port", "workspace"
            ],
            Sections.TOKENS: [
                "registration"
            ],
            Sections.AGENT: [
                "agent_name"
            ],
        }

        for section in agent_dict:
            print(f"{Bcolors.OKBLUE}Section: {section}{Bcolors.ENDC}")
            for opt in agent_dict[section]:
                def_value = config.instance[section].get(opt, "")
                value = click.prompt(f"{opt}", default=f"{def_value}")
                if value == "":
                    print(f"{Bcolors.WARNING}TODO WARNING{Bcolors.ENDC}")

                config.instance.set(section, opt, value)

    def executors(self):
        executors = config.instance[Sections.AGENT].get("executors", "")
        self.executors_list = executors.split(",")

    def save_executors(self):
        config.instance.set(Sections.AGENT,"executors",",".join(self.executors_list))

    def process_executors(self):
        end = False

        while not end:
            print(f"The actual configured {Bcolors.OKBLUE}{Bcolors.BOLD}executors{Bcolors.ENDC} are: {Bcolors.OKGREEN}{self.executors_list}{Bcolors.ENDC}")
            value = self.choose_adm("executor")
            if value.upper() == "A":
                self.new_executor()
            elif value.upper() == "M":
                self.edit_executor()
            elif value.upper() == "D":
                self.delete_executor()
            else:
                end = True

    def process_var_envs(self, executor_name):
        end = False
        section = Sections.EXECUTOR_VARENVS.format(executor_name)

        while not end:
            print(f"The actual {Bcolors.BOLD}{Bcolors.OKBLUE}{executor_name} executor's environment variables{Bcolors.ENDC} are: "
                  f"{Bcolors.OKGREEN}{config.instance.options(section)}{Bcolors.ENDC}")
            value = self.choose_adm("environment variable")
            if value == "A":
                envvar = click.prompt("Environment variable name").lower()
                if envvar in config.instance.options(section):
                    print(f"{Bcolors.WARNING}TODO WARN{Bcolors.ENDC}")
                else:
                    value = click.prompt("Environment variable value")
                    config.instance.set(section, envvar, value)
            elif value == "M":
                envvar = click.prompt("Environment variable name").lower()
                if envvar not in config.instance.options(section):
                    print(f"{Bcolors.WARNING}TODO WARN{Bcolors.ENDC}")
                else:
                    def_value = config.instance.get(section, envvar)
                    value = click.prompt("Environment variable value", default=def_value)
                    config.instance.set(section, envvar, value)
            elif value == "D":
                envvar = click.prompt("Environment variable name").lower()
                if envvar not in config.instance.options(section):
                    print(f"{Bcolors.WARNING}TODO WARN{Bcolors.ENDC}")
                else:
                    config.instance.remove_option(section, envvar)
            else:
                end = True

    def process_params(self, executor_name):
        end = False
        section = Sections.EXECUTOR_PARAMS.format(executor_name)

        while not end:
            print(f"The actual {Bcolors.BOLD}{Bcolors.OKBLUE}{executor_name} executor's arguments{Bcolors.ENDC} are: "
                  f"{Bcolors.OKGREEN}{config.instance.options(section)}{Bcolors.ENDC}")
            value = self.choose_adm("argument")
            if value == "A":
                param = click.prompt("Argument name").lower()
                if param in config.instance.options(section):
                    print(f"{Bcolors.WARNING}TODO WARN{Bcolors.ENDC}")
                else:
                    value = click.confirm("Is mandatory?")
                    config.instance.set(section, param, f"{value}")
            elif value == "M":
                param = click.prompt("Argument name").lower()
                if param not in config.instance.options(section):
                    print(f"{Bcolors.WARNING}TODO WARN{Bcolors.ENDC}")
                else:
                    value = click.confirm("Is mandatory?")
                    config.instance.set(section, param, f"{value}")
            elif value == "D":
                param = click.prompt("Argument name").lower()
                if param not in config.instance.options(section):
                    print(f"{Bcolors.WARNING}TODO WARN{Bcolors.ENDC}")
                else:
                    config.instance.remove_option(section, param)
            else:
                end = True

    def new_executor(self):
        name = None
        while name is None:
            name = click.prompt("Name")
            if name in self.executors_list:
                name = None
        self.executors_list.append(name)
        max_buff_size = click.prompt("Max data sent to server", type=int, default=65536)
        cmd = click.prompt("Command to execute")
        for section in Wizard.EXECUTOR_SECTIONS:
            formatted_section = section.format(name)
            config.instance.add_section(formatted_section)
        config.instance.set(Sections.EXECUTOR_DATA.format(name), "cmd", cmd)
        config.instance.set(Sections.EXECUTOR_DATA.format(name), "max_size", f"{max_buff_size}")
        self.process_var_envs(name)
        self.process_params(name)

    EXECUTOR_SECTIONS = [Sections.EXECUTOR_DATA, Sections.EXECUTOR_PARAMS, Sections.EXECUTOR_VARENVS]

    def edit_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_list:
            return
        new_name = None
        while new_name is None:
            new_name = click.prompt("New name", default=name)
            if new_name in self.executors_list and name != new_name:
                print(f"{Bcolors.WARNING}REPEATED{Bcolors.ENDC}")
                new_name = None
        if new_name != name:
            for unformated_section in Wizard.EXECUTOR_SECTIONS:
                section = unformated_section.format(new_name)
                config.instance.add_section(section)
                for item in config.instance.items(unformated_section.format(name)):
                    config.instance.set(section, item[0], item[1])
                config.instance.remove_section(unformated_section.format(name))
            name = new_name
        section = Sections.EXECUTOR_DATA.format(name)
        max_buff_size = click.prompt("Max data sent to server", type=int,
                                     default=config.instance.get(section, "max_size"))
        cmd = click.prompt("Command to execute",
                           default=config.instance.get(section, "cmd"))
        config.instance.set(section, "cmd", cmd)
        config.instance.set(section, "max_size", f"{max_buff_size}")
        self.process_var_envs(name)
        self.process_params(name)

    def delete_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_list:
            return
        for section in Wizard.EXECUTOR_SECTIONS:
            config.instance.remove_section(section.format(name))
        self.executors_list.remove(name)

    def get_default_value_and_choices(self, default_value, choices):
        if "DEFAULT_VALUE_NONE" in os.environ:
            default_value = None
            choices = choices + ["Q", "\0"]
        return default_value, choices

    @staticmethod
    def process_choice_errors(value):
        if "" in os.environ and value in ["\0"]:
            raise click.exceptions.Abort()


@click.command(help="faraday-dispatcher config_wizard")
@click.option("-c", "--config-filepath", default=None, help="Path to config ini file")
def config_wizard(config_filepath):

    Wizard(config_filepath or Path(config.CONFIG_FILENAME)).run()

cli.add_command(config_wizard)
cli.add_command(run)

if __name__ == '__main__':

    cli()
