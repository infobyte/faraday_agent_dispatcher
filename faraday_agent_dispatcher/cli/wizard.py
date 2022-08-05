import os
import re
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
    SPECIAL_CHARACTER = [",", "/", "\\"]

    def __init__(self, config_filepath: Path):
        self.config_filepath = config_filepath

        try:
            config.reset_config(config_filepath)
        except ValueError as e:
            if e.args[1] or config_filepath.is_file():
                # the filepath is either a file, or a folder containing a file,
                # which can't be processed
                raise e
        config.control_config()
        self.executors_dict = {}
        self.load_executors()

    async def run(self):
        end = False
        ignore_changes = False
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
                    if Sections.AGENT in config.instance:
                        click.echo(self.status_report(sections=config.instance))
                        config.control_config()
                        end = True
                    else:
                        if confirm_prompt(
                            click.style(
                                "File configuration not saved. Are you sure?",
                                fg="yellow",
                            )
                        ):
                            click.echo(self.status_report(sections=config.instance.sections()))
                            end = True
                            ignore_changes = True
                        else:
                            end = False

                except ValueError as e:
                    click.secho(f"{e}", fg="red")
        if not ignore_changes:
            config.save_config(self.config_filepath)

    def load_executors(self):
        if Sections.AGENT in config.instance:
            self.executors_dict = config.instance[Sections.AGENT].get("executors", {})

    async def process_executors(self):
        end = False

        while not end:
            print(
                f"The current configured {Bcolors.OKBLUE}{Bcolors.BOLD}"
                f"executors{Bcolors.ENDC} are: {Bcolors.OKGREEN}"
                f"{list(self.executors_dict.keys())}{Bcolors.ENDC}"
            )
            value = choose_adm("executor")
            if value.upper() == "A":
                await self.new_executor()
            elif value.upper() == "M":
                self.edit_executor()
            elif value.upper() == "D":
                self.delete_executor()
            else:
                quit_executor_msg = click.style("There are no executors loaded. Are you sure?", fg="yellow")
                return confirm_prompt(quit_executor_msg, default=False) if not self.executors_dict else True

    def check_executors_name(self, show_text: str, default=None):
        name = click.prompt(show_text, default=default)
        if name in self.executors_dict and name != default:
            click.secho(f"The executor {name} already exists", fg="yellow")
            return
        for character in Wizard.SPECIAL_CHARACTER:
            if character in name:
                click.secho(
                    f"The executor cannot contain {character} in its name",
                    fg="yellow",
                )
                return
        return name

    async def new_executor(self):
        name = self.check_executors_name("Name")
        if name:
            self.executors_dict[name] = {}
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

        executors_names = list(
            map(
                lambda x: re.search(r"(^[a-zA-Z0-9_-]+)(?:\..*)*$", x).group(1),
                executors,
            )
        )

        async def control_base_repo(chosen_option: str) -> Optional[dict]:
            metadata = executor_metadata(chosen_option)
            try:
                if not check_metadata(metadata):
                    click.secho(f"Invalid manifest for: {chosen_option}", fg="yellow")
                else:
                    if not await check_commands(metadata):
                        print(
                            f"{Bcolors.WARNING}Invalid bash dependency for"
                            f" {Bcolors.BOLD}{chosen_option}{Bcolors.ENDC}"
                            f""
                        )
                    else:
                        return metadata
            except FileNotFoundError:
                click.secho(f"Not existent manifest for: {chosen_option}", fg="yellow")
            return None

        return await choice_paged_option(executors_names, self.PAGE_SIZE, control_base_repo)

    async def new_repo_executor(self, name):
        try:
            metadata = await self.get_base_repo()
            Wizard.set_generic_data(name, metadata=metadata)
            process_repo_var_envs(name, metadata)
            set_repo_params(name, metadata)
            click.secho("New repository executor added", fg="green")
        except WizardCanceledOption:
            self.executors_dict.pop(name)
            click.secho("New repository executor not added", fg="yellow")

    @staticmethod
    def set_generic_data(name, cmd=None, metadata: dict = {}):
        executor = config.instance[Sections.AGENT][Sections.EXECUTORS][name]
        repo_executor_name = metadata.get("repo_executor")
        executor["max_size"] = Wizard.MAX_BUFF_SIZE
        if repo_executor_name:
            executor["repo_executor"] = repo_executor_name
            executor["repo_name"] = metadata.get("name")
        else:
            executor["cmd"] = cmd

    def new_custom_executor(self, name):
        cmd = click.prompt("Command to execute", default="exit 1")
        Wizard.set_generic_data(name, cmd=cmd)
        process_var_envs(name)
        process_params(name)

    def edit_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_dict:
            click.secho(f"There is no {name} executor", fg="yellow")
            return
        new_name = None
        while new_name is None:
            new_name = self.check_executors_name("New name", default=name)
        if new_name != name:
            value = self.executors_dict[name]
            self.executors_dict.pop(name)
            self.executors_dict[new_name] = value
            name = new_name
        section = Sections.EXECUTOR_DATA.format(name)
        repo_executor = self.executors_dict[section].get("repo_executor")
        if repo_executor:
            repo_name = re.search(r"(^[a-zA-Z0-9_-]+)(?:\..*)*$", repo_executor).group(1)
            metadata = executor_metadata(repo_name)
            process_repo_var_envs(name, metadata)
        else:
            cmd = click.prompt(
                "Command to execute",
                default=self.executors_dict[section]["cmd"],
            )
            self.executors_dict[section]["cmd"] = cmd
            process_var_envs(name)
            process_params(name)
        click.secho("Update repository executor finish", fg="green")

    def delete_executor(self):
        name = click.prompt("Name")
        if name not in self.executors_dict:
            click.secho(f"There is no {name} executor", fg="yellow")
            return
        self.executors_dict.pop(name)

    def status_report(self, sections):
        min_sections = [Sections.SERVER, Sections.AGENT]
        check = all(item in sections for item in min_sections)
        if check:
            msj = click.style("File configuration OK.", fg="green")
        else:
            msj = click.style(
                "File configuration not complete. Missing section.",
                fg="yellow",
            )
        if Sections.TOKENS not in sections:
            msj += (
                f"\n{Bcolors.WARNING}Token not found, "
                f'remember to run "faraday-dispatcher '
                f'run --token {{TOKEN}}"{Bcolors.ENDC}'
            )
        return msj
