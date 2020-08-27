import os
import re
import sys
from typing import Optional

import click
from pathlib import Path

from faraday_agent_dispatcher import config
from faraday_agent_dispatcher.cli.utils.exceptions import WizardCanceledOption
from faraday_agent_dispatcher.cli.utils.model_load import (
    process_agent,
    process_var_envs,
    process_params,
    process_repo_var_envs,
    set_repo_params,
)
from faraday_agent_dispatcher.utils.metadata_utils import (
    executor_folder,
    executor_metadata,
    check_commands,
    check_metadata
)
from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_dispatcher.cli.utils.general_inputs import (
    choose_adm,
    confirm_prompt,
    get_default_value_and_choices,
    process_choice_errors, choice_paged_option
)
import faraday_agent_dispatcher.logger as logging

logger = logging.get_logger()

DEFAULT_PAGE_SIZE = 5


class Wizard:

    MAX_BUFF_SIZE = 1024
    PAGE_SIZE = DEFAULT_PAGE_SIZE
    EXECUTOR_SECTIONS = [
        Sections.EXECUTOR_DATA,
        Sections.EXECUTOR_PARAMS,
        Sections.EXECUTOR_VARENVS
    ]

    def __init__(self, config_filepath: Path):
        self.config_filepath = config_filepath

        try:
            config.reset_config(config_filepath)
        except ValueError as e:
            if e.args[1] or config_filepath.is_file():
                # the filepath is either a file, or a folder containing a file,
                # which can't be processed
                raise e
        try:
            config.verify()
        except ValueError as e:
            print(f"{Bcolors.FAIL}{e}{Bcolors.ENDC}")
            sys.exit(1)
        self.executors_list = []
        self.load_executors()

    async def run(self):
        end = False

        def_value, choices = get_default_value_and_choices("Q",
                                                           ["A", "E", "Q"]
                                                           )

        while not end:
            value = click.prompt(
                "Do you want to edit the [A]gent or the [E]xecutors? Do you "
                "want to [Q]uit?",
                type=click.Choice(choices=choices, case_sensitive=False),
                default=def_value
            )
            if value.upper() == "A":
                process_agent()
            elif value.upper() == "E":
                await self.process_executors()
            else:
                process_choice_errors(value)
                try:
                    if Sections.AGENT in config.instance.sections():
                        self.save_executors()
                        config.control_config()
                        end = True
                    else:
                        print(f"{Bcolors.FAIL}Add agent configuration"
                              f"{Bcolors.ENDC}")

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
        config.instance.set(
            Sections.AGENT,
            "executors",
            ",".join(self.executors_list)
        )

    async def process_executors(self):
        end = False

        while not end:
            print(f"The actual configured {Bcolors.OKBLUE}{Bcolors.BOLD}"
                  f"executors{Bcolors.ENDC} are: {Bcolors.OKGREEN}"
                  f"{self.executors_list}{Bcolors.ENDC}")
            value = choose_adm("executor")
            if value.upper() == "A":
                await self.new_executor()
            elif value.upper() == "M":
                self.edit_executor()
            elif value.upper() == "D":
                self.delete_executor()
            else:
                end = True

    def check_executors_name(self, show_text: str, default=None):
        name = click.prompt(show_text, default=default)
        if name in self.executors_list and name != default:
            print(
                f"{Bcolors.WARNING}The executor {name} already exists"
                f"{Bcolors.ENDC}"
            )
            return
        if ',' in name:
            print(
                f"{Bcolors.WARNING}"
                f"The executor cannot contain \',\' in its name"
                f"{Bcolors.ENDC}"
            )
            return
        return name

    async def new_executor(self):
        name = self.check_executors_name("Name")
        if name:
            self.executors_list.append(name)
            custom_executor = confirm_prompt(
                "Is a custom executor?",
                default=False
            )
            if custom_executor:
                self.new_custom_executor(name)
            else:
                await self.new_repo_executor(name)

    async def get_base_repo(self) -> dict:
        executors = [
            f"{executor}"
            for executor in os.listdir(executor_folder())
            if re.match("(.*_manifest.json|__pycache__)", executor) is None
        ]

        async def control_base_repo(chosen_option: str) -> Optional[dict]:
            metadata = executor_metadata(chosen_option)
            try:
                if not check_metadata(metadata):
                    print(
                        f"{Bcolors.WARNING}Invalid manifest for "
                        f"{Bcolors.BOLD}{chosen_option}{Bcolors.ENDC}"
                    )
                else:
                    if not await check_commands(metadata):
                        print(
                            f"{Bcolors.WARNING}Invalid bash dependency for"
                            f" {Bcolors.BOLD}{chosen_option}{Bcolors.ENDC}"
                            f"")
                    else:
                        metadata["name"] = chosen_option
                        return metadata
            except FileNotFoundError:
                print(
                    f"{Bcolors.WARNING}Not existent manifest for "
                    f"{Bcolors.BOLD}{chosen_option}{Bcolors.ENDC}"
                )
            return None

        return await choice_paged_option(executors,
                                         self.PAGE_SIZE,
                                         control_base_repo)

    async def new_repo_executor(self, name):
        try:
            metadata = await self.get_base_repo()
            Wizard.set_generic_data(name, repo_executor_name=metadata["name"])
            process_repo_var_envs(name, metadata)
            set_repo_params(name, metadata)
        except WizardCanceledOption:
            print(
                f"{Bcolors.BOLD}New repository executor not added"
                f"{Bcolors.ENDC}"
            )

    @staticmethod
    def set_generic_data(name, cmd=None, repo_executor_name: str = None):
        max_buff_size = \
            click.prompt("Max data sent to server",
                         type=click.IntRange(min=Wizard.MAX_BUFF_SIZE),
                         default=65536)
        for section in Wizard.EXECUTOR_SECTIONS:
            formatted_section = section.format(name)
            config.instance.add_section(formatted_section)
        config.instance.set(
            Sections.EXECUTOR_DATA.format(name),
            "max_size",
            f"{max_buff_size}"
        )
        if repo_executor_name:
            config.instance.set(
                Sections.EXECUTOR_DATA.format(name),
                "repo_executor",
                f"{repo_executor_name}"
            )
        else:
            config.instance.set(
                Sections.EXECUTOR_DATA.format(name),
                "cmd",
                cmd
            )

    def new_custom_executor(self, name):
        cmd = click.prompt("Command to execute", default="exit 1")
        Wizard.set_generic_data(name, cmd=cmd)
        process_var_envs(name)
        process_params(name)

    def edit_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_list:
            print(
                f"{Bcolors.WARNING}There is no {name} executor{Bcolors.ENDC}"
            )
            return
        new_name = None
        while new_name is None:
            new_name = self.check_executors_name("New name", default=name)
        if new_name != name:
            for unformatted_section in Wizard.EXECUTOR_SECTIONS:
                section = unformatted_section.format(new_name)
                old_section = unformatted_section.format(name)
                config.instance.add_section(section)
                for item in config.instance.items(old_section):
                    config.instance.set(section, item[0], item[1])
                config.instance.remove_section(old_section)
            self.executors_list.remove(name)
            self.executors_list.append(new_name)
            name = new_name
        section = Sections.EXECUTOR_DATA.format(name)
        repo_name = config.instance[section].get("repo_executor", None)
        if repo_name:
            max_buff_size = click.prompt(
                "Max data sent to server",
                type=click.IntRange(min=Wizard.MAX_BUFF_SIZE),
                default=config.instance.get(section, "max_size")
            )
            config.instance.set(section, "max_size", f"{max_buff_size}")
            metadata = executor_metadata(repo_name)
            process_repo_var_envs(name, metadata)
        else:
            cmd = click.prompt("Command to execute",
                               default=config.instance.get(section, "cmd"))
            max_buff_size = click.prompt(
                "Max data sent to server",
                type=click.IntRange(min=Wizard.MAX_BUFF_SIZE),
                default=config.instance.get(section, "max_size")
            )
            config.instance.set(section, "cmd", cmd)
            config.instance.set(section, "max_size", f"{max_buff_size}")
            process_var_envs(name)
            process_params(name)

    def delete_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_list:
            print(
                f"{Bcolors.WARNING}There is no {name} executor{Bcolors.ENDC}"
            )
            return
        for section in Wizard.EXECUTOR_SECTIONS:
            config.instance.remove_section(section.format(name))
        self.executors_list.remove(name)
