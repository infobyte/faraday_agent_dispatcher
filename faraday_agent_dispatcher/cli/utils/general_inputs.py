import os

import click


def get_default_value_and_choices(default_value, choices):
    if "DEBUG_INPUT_MODE" in os.environ:
        default_value = None
        choices = choices + ["\0"]
    return default_value, choices


def confirm_prompt(text: str, default: bool = None):
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
