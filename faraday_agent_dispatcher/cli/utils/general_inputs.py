import math
import os

import click

from faraday_agent_dispatcher.cli.utils.exceptions import WizardCanceledOption
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from typing import List, Callable, Optional, Awaitable, TypeVar

T = TypeVar('T')


def get_default_value_and_choices(default_value, choices):
    if "DEBUG_INPUT_MODE" in os.environ:
        default_value = None
        choices = choices + ["\0"]
    return default_value, choices


def confirm_prompt(text: str, default: bool = None):
    if default is not None:
        default = "Y" if default else "N"
    return click.prompt(
        text=text,
        type=click.Choice(["Y", "N"], case_sensitive=False),
        default=default
    ).upper() == 'Y'


def process_choice_errors(value):
    if "DEBUG_INPUT_MODE" in os.environ and value in ["\0"]:
        raise click.exceptions.Abort()


def choose_adm(subject: str, ignore: List[str] = None) -> str:
    ignore = ignore if ignore is not None else []
    values = [value for value in ["A", "M", "D", "Q"] if value not in ignore]
    def_value, choices = get_default_value_and_choices("Q", values)
    value = click.prompt(
        f"Do you want to [A]dd, [M]odify or [D]elete an {subject}? Do you "
        f"want to [Q]uit?",
        type=click.Choice(choices=choices, case_sensitive=False),
        default=def_value
    ).upper()
    process_choice_errors(value)
    return value


async def choice_paged_option(
        options: List, page_size: int,
        control_option: Callable[
            [str],
            Awaitable[Optional[T]]]) -> T:
    metadata: T = None
    page = 0
    max_page = int(math.ceil(len(options) / page_size))
    while metadata is None:
        print("The executors are:")
        paged_executors = options[
                          page * page_size:
                          min((page + 1) * page_size, len(options))
                          ]
        for i, name in enumerate(paged_executors):
            print(f"{Bcolors.OKGREEN}{i + 1}: {name}{Bcolors.ENDC}")
        if page > 0:
            print(f"{Bcolors.OKBLUE}-: Previous page{Bcolors.ENDC}")
        if page < max_page - 1:
            print(f"{Bcolors.OKBLUE}+: Next page{Bcolors.ENDC}")
        print(f"{Bcolors.OKBLUE}Q: Don't choose{Bcolors.ENDC}")
        chosen = click.prompt("Choose one")
        if chosen not in [
            str(i)
            for i in range(1, len(paged_executors) + 1)
        ]:
            if chosen == '+' and page < max_page - 1:
                page += 1
            elif chosen == '-' and page > 0:
                page -= 1
            elif chosen == "Q":
                raise WizardCanceledOption(
                    "Repository executor selection canceled"
                )
            else:
                print(
                    f"{Bcolors.WARNING}Invalid option "
                    f"{Bcolors.BOLD}{chosen}{Bcolors.ENDC}"
                )
        else:
            chosen = paged_executors[int(chosen) - 1]
            metadata: T = await control_option(chosen)

    return metadata
