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

from faraday_agent_dispatcher.dispatcher import Dispatcher
from faraday_agent_dispatcher.builder import DispatcherBuilder
from faraday_agent_dispatcher.config import instance as config
from aiohttp import ClientSession

async def main():
    dispatcher_builder = DispatcherBuilder()
    # Open config

    #dispatcher_builder.config(config)
    #dispatcher_builder.registration_token(config["tokens"]["registration"])
    #dispatcher_builder.faraday_workspace("w1")
    #dispatcher = dispatcher_builder.build()

    # Parse args

    async with ClientSession(raise_for_status=True) as session:
        dispatcher = Dispatcher(session)
        await dispatcher.connect()

    return 0


def main_sync():
    try:
        r = asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
    sys.exit(r)  # pragma: no cover


if __name__ == "__main__":
    main_sync()
