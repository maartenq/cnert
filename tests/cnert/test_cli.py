# tests/cnert/test_cli.py

from cnert import __version__
from cnert.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def test_cli_without_args_options():
    result = runner.invoke(app)
    assert result.exit_code == 0
    assert "42" in result.stdout


def test_cli_with_option_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout == f"{__version__}\n"
