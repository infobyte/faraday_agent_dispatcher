# -*- coding: utf-8 -*-

"""Console script for faraday_dummy_agent."""
import sys
import click

from faraday_agent_dispatcher.dispatcher import run

@click.command()
def main(args=None):
    """Console script for faraday_dummy_agent."""
    click.echo("Replace this message by putting your code into "
               "faraday_dummy_agent.cli.main")
    click.echo("See click documentation at http://click.pocoo.org/")

    run()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
