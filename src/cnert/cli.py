# cnert/cli.py
# vim: ai et ts=4 sw=4 sts=4 ft=python fileencoding=utf-8

from typing import Optional

import typer

from . import __version__

app = typer.Typer()


def version_callback(value: bool):
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.command()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback
    ),
):
    typer.echo("42")
