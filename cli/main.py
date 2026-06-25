#!/usr/bin/env python3
"""CLI for Open AI Grid Auth Service."""

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import __version__
from src.server import run_server

console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


@click.group()
def cli():
    """Open AI Grid Auth Service"""


@cli.command()
@click.option("--config", "-c", default="config/default_config.yaml", help="Config file path")
@click.option("--port", "-p", default=8800, type=int, help="Port to listen on")
def start(config, port):
    """Start the authentication service."""
    console.print(f"[bold green]Open AI Grid Auth Service v{__version__}[/bold green]")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        runner, site = loop.run_until_complete(run_server(config, port))
        console.print(f"\n[bold blue]Auth Service running:[/bold blue]")
        console.print(f"  http://localhost:{port}/auth/register")
        console.print(f"  http://localhost:{port}/auth/login")
        console.print(f"  http://localhost:{port}/auth/leaderboard")
        console.print(f"\n[dim]Press Ctrl+C to stop[/dim]\n")
        loop.run_forever()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Shutting down...[/bold yellow]")
        loop.run_until_complete(site.stop())
        loop.run_until_complete(runner.cleanup())
    except Exception as exc:
        console.print(f"[bold red]Error: {exc}[/bold red]")
        sys.exit(1)


@cli.command()
def version():
    """Show version."""
    console.print(f"[bold cyan]Open AI Grid Auth Service[/bold cyan] v{__version__}")


if __name__ == "__main__":
    cli()
