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
    check_metadata,
)
from faraday_agent_dispatcher.config import Sections
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_dispatcher.cli.utils.general_inputs import (
    choose_adm,
    confirm_prompt,
    get_default_value_and_choices,
    process_choice_errors,
    choice_paged_option,
)
import faraday_agent_dispatcher.logger as logging

logger = logging.get_logger()

DEFAULT_PAGE_SIZE = 10


class Wizard:

    MAX_BUFF_SIZE = 65536
    PAGE_SIZE = DEFAULT_PAGE_SIZE
    EXECUTOR_SECTIONS = [
        Sections.EXECUTOR_DATA,
        Sections.EXECUTOR_PARAMS,
        Sections.EXECUTOR_VARENVS,
    ]
    SPECIAL_CHARACTER = [",", "/", "\\", ";", "_"]

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
        save_file = True
        def_value, choices = get_default_value_and_choices("Q", ["A", "E", "Q"])

        while not end:
            value = click.prompt(
                "Do you want to edit the [A]gent or the [E]xecutors? Do you " "want to [Q]uit?",
                type=click.Choice(choices=choices, case_sensitive=False),
                default=def_value,
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
                        if confirm_prompt(
                            f"{Bcolors.WARNING}File configuration not save. Are you sure?" f"{Bcolors.ENDC}"
                        ):
                            print(f"{Bcolors.WARNING}File configuration not created" f"{Bcolors.ENDC}")
                            end = True
                            save_file = False
                        else:
                            end = False

                except ValueError as e:
                    print(f"{Bcolors.FAIL}{e}{Bcolors.ENDC}")

        if save_file:
            config.save_config(self.config_filepath)

    def load_executors(self):
        if Sections.AGENT in config.instance:
            executors = config.instance[Sections.AGENT].get("executors", "")
            self.executors_list = executors.split(",")
            if "" in self.executors_list:
                self.executors_list.remove("")

    def save_executors(self):
        config.instance.set(Sections.AGENT, "executors", ",".join(self.executors_list))

    async def process_executors(self):
        end = False

        while not end:
            list_executors = self.get_name_executors()
            print(
                f"The actual configured {Bcolors.OKBLUE}{Bcolors.BOLD}"
                f"executors{Bcolors.ENDC} are: {Bcolors.OKGREEN}"
                f"{list_executors}{Bcolors.ENDC}"
            )
            value = choose_adm("executor")
            if value.upper() == "A":
                await self.new_executor()
            elif value.upper() == "M":
                self.edit_executor()
            elif value.upper() == "D":
                self.delete_executor()
            else:
                end = True

    def get_name_executors(self):
        executors_list_only_name = []
        for name_executor in self.executors_list:
            position_end = name_executor.rfind("_")
            position_end = position_end + 1
            executors_list_only_name.append(name_executor[position_end:])
        return executors_list_only_name

    def check_executors_name(self, show_text: str, default=None):
        name = click.prompt(show_text)
        executors_list_only_name = self.get_name_executors()
        if name in executors_list_only_name and name != default:
            print(f"{Bcolors.WARNING}The executor {name} already exists" f"{Bcolors.ENDC}")
            return
        for character in Wizard.SPECIAL_CHARACTER:
            if character in name:
                print(f"{Bcolors.WARNING}" f"The executor cannot contain {character} in its name" f"{Bcolors.ENDC}")
                return
        return name

    def change_name(self, name, executor="custom"):
        new_name = f"{executor}_{name}"
        for nro in range(len(self.executors_list)):
            if self.executors_list[nro] == name:
                self.executors_list[nro] = new_name

        return new_name

    async def new_executor(self):
        name = self.check_executors_name("Name")
        if name:
            self.executors_list.append(name)
            custom_executor = confirm_prompt("Is a custom executor?", default=False)
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
                    print(f"{Bcolors.WARNING}Invalid manifest for " f"{Bcolors.BOLD}{chosen_option}{Bcolors.ENDC}")
                else:
                    if not await check_commands(metadata):
                        print(
                            f"{Bcolors.WARNING}Invalid bash dependency for"
                            f" {Bcolors.BOLD}{chosen_option}{Bcolors.ENDC}"
                            f""
                        )
                    else:
                        metadata["name"] = chosen_option
                        return metadata
            except FileNotFoundError:
                print(f"{Bcolors.WARNING}Not existent manifest for " f"{Bcolors.BOLD}{chosen_option}{Bcolors.ENDC}")
            return None

        return await choice_paged_option(executors, self.PAGE_SIZE, control_base_repo)

    async def new_repo_executor(self, name):
        try:
            metadata = await self.get_base_repo()
            name_executor = metadata["name"].rsplit(".")
            new_name = self.change_name(name=name, executor=name_executor[0])
            Wizard.set_generic_data(new_name, repo_executor_name=metadata["name"])
            process_repo_var_envs(new_name, metadata)
            set_repo_params(new_name, metadata)
            print(f"{Bcolors.OKGREEN}New repository executor added" f"{Bcolors.ENDC}")
        except WizardCanceledOption:
            self.executors_list.pop()
            print(f"{Bcolors.BOLD}New repository executor not added" f"{Bcolors.ENDC}")

    @staticmethod
    def set_generic_data(name, cmd=None, repo_executor_name: str = None):
        for section in Wizard.EXECUTOR_SECTIONS:
            formatted_section = section.format(name)
            config.instance.add_section(formatted_section)
        config.instance.set(Sections.EXECUTOR_DATA.format(name), "max_size", f"{Wizard.MAX_BUFF_SIZE}")
        if repo_executor_name:
            config.instance.set(
                Sections.EXECUTOR_DATA.format(name),
                "repo_executor",
                f"{repo_executor_name}",
            )
        else:
            config.instance.set(Sections.EXECUTOR_DATA.format(name), "cmd", cmd)

    def new_custom_executor(self, name):
        cmd = click.prompt("Command to execute", default="exit 1")
        new_name = self.change_name(name=name)
        Wizard.set_generic_data(new_name, cmd=cmd)
        process_var_envs(new_name)
        process_params(new_name)

    def edit_executor(self):
        name = click.prompt("Name")
        executors_list_only_name = self.get_name_executors()
        if name not in executors_list_only_name:
            print(f"{Bcolors.WARNING}There is no {name} executor{Bcolors.ENDC}")
            return
        new_name = None
        index = executors_list_only_name.index(name)
        while new_name is None:
            new_name = self.check_executors_name(f"New name [{name}]", default=name)
        if new_name != name:
            nro_end = self.executors_list[index].find("_")
            new_name = f"{self.executors_list[index][:nro_end]}_{new_name}"
            for unformatted_section in Wizard.EXECUTOR_SECTIONS:
                section = unformatted_section.format(new_name)
                old_section = unformatted_section.format(self.executors_list[index])
                config.instance.add_section(section)
                for item in config.instance.items(old_section):
                    config.instance.set(section, item[0], item[1])
                config.instance.remove_section(old_section)

            self.executors_list.remove(self.executors_list[index])
            self.executors_list.append(new_name)
        section = Sections.EXECUTOR_DATA.format(self.executors_list[index])
        repo_name = config.instance[section].get("repo_executor", None)
        if repo_name:
            metadata = executor_metadata(repo_name)
            process_repo_var_envs(self.executors_list[index], metadata)
        else:
            cmd = click.prompt("Command to execute", default=config.instance.get(section, "cmd"))
            config.instance.set(section, "cmd", cmd)
            process_var_envs(self.executors_list[index])
            process_params(self.executors_list[index])
        print(f"{Bcolors.OKGREEN}Update repository executor finish" f"{Bcolors.ENDC}")

    def delete_executor(self):
        name = click.prompt("Name")
        executors_list_only_name = self.get_name_executors()
        if name not in executors_list_only_name:
            print(f"{Bcolors.WARNING}There is no {name} executor{Bcolors.ENDC}")
            return
        index = executors_list_only_name.index(name)
        name_delete = self.executors_list[index]
        for section in Wizard.EXECUTOR_SECTIONS:
            config.instance.remove_section(section.format(name_delete))
        self.executors_list.remove(name_delete)
