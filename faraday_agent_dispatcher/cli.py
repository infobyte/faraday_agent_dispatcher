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

"""Console script for faraday_dummy_agent."""
import sys
import click
import asyncio
import traceback

from aiohttp import ClientSession

from faraday_agent_dispatcher.dispatcher import Dispatcher
import faraday_agent_dispatcher.logger as logging


async def main(config_file):

    # Parse args

    async with ClientSession(raise_for_status=True) as session:
        dispatcher = Dispatcher(session, config_file)
        await dispatcher.register()
        await dispatcher.connect()

    return 0


@click.command("dispatcher")
@click.option("--config-file", default=None,help="Path to config ini file")
@click.option("--logs-folder", default="~", help="Path to logger folder")
def main_sync(config_file, logs_folder):
    logging.reset_logger(logs_folder)
    logger = logging.get_logger()
    try:
        r = asyncio.run(main(config_file))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logger.error(traceback.format_exception(exc_type, exc_value, exc_traceback))
        sys.exit(1)  # pragma: no cover


if __name__ == "__main__":
    main_sync(None)
