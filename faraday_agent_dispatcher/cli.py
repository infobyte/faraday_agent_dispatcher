# -*- coding: utf-8 -*-

"""Console script for faraday_dummy_agent."""
import sys
import click
import asyncio

from faraday_agent_dispatcher.builder import DispatcherBuilder

default_config = {
        "faraday_host": "localhost",
        "registration_token": u'QTlA75R1RNG33utzdlgpOcrJo',
        "workspace": "w1",
        #"executor_filename": "./samples/scratchpy.sh",
        "executor_filename": "python ./samples/scratch2.py"
    }


async def dispatch():
    dispatcher_builder = DispatcherBuilder()
    # Open config

    dispatcher_builder.config(default_config)

    # Parse args

    dispatcher = dispatcher_builder.build()

    await dispatcher.connect()

    # await dispatcher.run()

    print("WARN DISPATCHER ENDED")
    await dispatcher.disconnect()

    return 0


async def main(args=None):
    res = await asyncio.gather(dispatch())
    return res

if __name__ == "__main__":
    r = asyncio.run(main())
    print(5)
    sys.exit(r)  # pragma: no cover
