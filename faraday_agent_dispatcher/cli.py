# -*- coding: utf-8 -*-

"""Console script for faraday_dummy_agent."""
import sys
import click

from faraday_agent_dispatcher.builder import DispatcherBuilder

default_config = {
        "faraday_url": "http://localhost",
        "faraday_port": "5985",
        "registration_token": u'da84edfd-5caa-4215-b496-02e24dd5b581',
        "workspace": "w1",
        "executor_filename": "./samples/scratchpy.sh"
    }


@click.command()
def main(args=None):
    """Console script for faraday_dummy_agent."""
    dispatcher_builder = DispatcherBuilder()
    # Open config

    dispatcher_builder.config(default_config)

    # Parse args

    dispatcher = dispatcher_builder.build()

    # TODO dispatcher.connect()

    dispatcher.run()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
