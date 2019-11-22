from click.testing import CliRunner
from faraday_agent_dispatcher.cli import register


def test_basic():
    runner = CliRunner()
    result = runner.invoke(register, ["-c=asd"])
    assert result.exit_code == 0

