import click

from faraday_agent_dispatcher import config
from faraday_agent_dispatcher.utils.text_utils import Bcolors


def get_new_name(name: str, section: str, named_type: str):
    new_name = None
    while new_name is None:
        new_name = click.prompt("New name", default=name)
        if new_name in config.instance.options(section) and name != new_name:
            print(
                f"{Bcolors.WARNING}The {named_type} {new_name} already exists"
                f"{Bcolors.ENDC}"
            )
            new_name = None
    def_value = config.instance.get(section, name)
    if name != new_name:
        config.instance.remove_option(section, name)
        name = new_name
    return def_value, name
