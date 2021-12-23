# tests/cnert/test_cli.py
# vim: ai et ts=4 sw=4 sts=4 ft=python fileencoding=utf-8

from typer.testing import CliRunner

from cnert import __version__
from cnert.cli import app

runner = CliRunner()


def test_cli_without_args_options():
    result = runner.invoke(app)
    assert result.exit_code == 0
    assert "42" in result.stdout


def test_cli_with_option_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout == f"{__version__}\n"
