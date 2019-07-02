# -*- coding: utf-8 -*-

"""Console script for faraday_dummy_agent."""
import sys
import click

from faraday_agent_dispatcher.builder import DispatcherBuilder


@click.command()
def main(args=None):
    """Console script for faraday_dummy_agent."""
    dispatcher_builder = DispatcherBuilder()
    # Open config

    # Parse args

    ### EXAMPLE
    dispatcher_builder.faraday_url("")

    dispatcher = dispatcher_builder.build()

    dispatcher.connect()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
