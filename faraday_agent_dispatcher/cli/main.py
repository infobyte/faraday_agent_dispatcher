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

from faraday_agent_dispatcher.cli.wizard import Wizard
from faraday_agent_dispatcher.dispatcher import Dispatcher
from faraday_agent_dispatcher import config, __version__
from faraday_agent_dispatcher.utils.text_utils import Bcolors
import faraday_agent_dispatcher.logger as logging
from pathlib import Path

logger = logging.get_logger()


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, '-v', '--version')
def cli():
    pass


def process_config_file(config_filepath: Path):
    if config_filepath is None and not os.path.exists(config.CONFIG_FILENAME):
        logger.info("Config file doesn't exist. Run the command `faraday-dispatcher config-wizard` to create one")
        exit(1)
    config_filepath = config_filepath or Path(config.CONFIG_FILENAME)
    config_filepath = Path(config_filepath)
    config.reset_config(config_filepath)
    return config_filepath


async def main(config_file):

    config_file = process_config_file(config_file)

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
@click.option("--log-level", default="info", help="Log level set = [notset|debug|info|warning|error|critical]")
@click.option("--debug", is_flag=True, default=False, help="Set debug logging, overrides --log-level option")
def run(config_file, logdir, log_level, debug):
    logging.reset_logger(logdir)
    if debug:
        logging_level = logging.get_level("debug")
    else:
        logging_level = logging.get_level(log_level)
    logging.set_logging_level(logging_level)
    logger = logging.get_logger()
    try:
        exit_code = asyncio.run(main(config_file))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.debug("Error running the dispatcher", exc_info=e)
        raise
    sys.exit(exit_code)


@click.command(help="faraday-dispatcher config_wizard")
@click.option("-c", "--config-filepath", default=None, help="Path to config ini file")
def config_wizard(config_filepath):
    config_filepath = config_filepath or config.CONFIG_FILENAME

    Wizard(Path(config_filepath)).run()


cli.add_command(config_wizard)
cli.add_command(run)

if __name__ == '__main__':

    cli()
