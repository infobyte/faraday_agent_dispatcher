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
import shutil

import click
import asyncio
import traceback

from aiohttp import ClientSession

from faraday_agent_dispatcher.dispatcher import Dispatcher
from faraday_agent_dispatcher.utils.text_utils import Bcolors
from faraday_agent_dispatcher import config
import faraday_agent_dispatcher.logger as logging
from pathlib import Path

logger = logging.get_logger()


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


def process_config_file(config_filepath: Path, verify: bool = True):
    if config_filepath is None and not os.path.exists(config.CONFIG_FILENAME):
        logger.info("Config file doesn't exist. Run the command `faraday-dispatcher config-wizard` to create one")
        exit(1)
    config_filepath = config_filepath or Path(config.CONFIG_FILENAME)
    config.reset_config(config_filepath)
    if verify:
        config.verify()


async def main(config_file):

    config_file = Path(config_file)

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


def process_agent():
    pass


def process_executors():
    pass


def get_default_value_and_choices(default_value, choices):
    if "DEFAULT_VALUE_NONE" in os.environ:
        default_value = None
        choices = choices + ["Q"]
    return default_value, choices

@click.command(help="faraday-dispatcher config_wizard")
@click.option("-c", "--config-filepath", default=None, help="Path to config ini file")
def config_wizard(config_filepath):

    process_config_file(config_filepath, verify=False)

    end = False

    def_value, choices = get_default_value_and_choices("", ["A", "E"])

    while not end:
        value = click.prompt("What you want to edit?",
                             type=click.Choice(choices=choices, case_sensitive=False),
                             default=def_value)
        if value.upper() == "A":
            process_agent()
        elif value.upper() == "E":
            process_executors()
        else:
            # TODO CHECK BEFORE
            end = True


cli.add_command(config_wizard)
cli.add_command(run)

if __name__ == '__main__':

    cli()
