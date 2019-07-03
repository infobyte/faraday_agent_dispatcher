# -*- coding: utf-8 -*-

"""Console script for faraday_dummy_agent."""
import sys
import click

from faraday_agent_dispatcher.builder import DispatcherBuilder

default_config = {
        "faraday_url": "http://localhost:5985",
        "access_token": "da84edfd-5caa-4215-b496-02e24dd5b581"
    }


@click.command()
def main(args=None):
    """Console script for faraday_dummy_agent."""
    dispatcher_builder = DispatcherBuilder()
    # Open config

    dispatcher_builder.config(default_config)

    # Parse args

    dispatcher = dispatcher_builder.build()

    dispatcher.connect()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
