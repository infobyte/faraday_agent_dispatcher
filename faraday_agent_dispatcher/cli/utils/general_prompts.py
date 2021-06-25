import click

from faraday_agent_dispatcher.utils.text_utils import Bcolors


def get_new_name(name: str, section: dict, named_type: str):
    new_name = None
    while new_name is None:
        new_name = click.prompt("New name", default=name)
        if new_name in section and name != new_name:
            print(f"{Bcolors.WARNING}The {named_type} {new_name} already exists" f"{Bcolors.ENDC}")
            new_name = None
    def_value = section[name]
    if name != new_name:
        section.pop(name)
        name = new_name
    return def_value, name
