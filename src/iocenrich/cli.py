"""Typer CLI entrypoint."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Windows terminals default to cp1252, which can't print emoji/unicode. Force
# UTF-8 so reports render everywhere.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from . import detector
from .engine import Engine
from .models import IOCType, Report, Verdict
from .providers.abuseipdb import AbuseIPDBProvider
from .providers.urlhaus import URLhausProvider
from .providers.virustotal import VirusTotalProvider

app = typer.Typer(help="IOC enrichment & triage CLI")
console = Console()

_VERDICT_STYLE = {
    Verdict.CLEAN: "bold green",
    Verdict.SUSPICIOUS: "bold yellow",
    Verdict.MALICIOUS: "bold red",
    Verdict.UNKNOWN: "dim",
}


def _build_providers() -> list:
    """Assemble the active providers.

    Providers whose API key is missing are still included — they return a clear
    'key not set' result instead of silently disappearing, so the user knows
    what they're missing.
    """
    return [URLhausProvider(), VirusTotalProvider(), AbuseIPDBProvider()]


def _render_table(report: Report) -> None:
    ioc = report.ioc
    style = _VERDICT_STYLE.get(report.verdict, "white")
    console.print(
        f"\n[bold]{ioc.value}[/bold]  ([cyan]{ioc.type.value}[/cyan])  ->  "
        f"[{style}]{report.verdict.value.upper()}[/{style}]  "
        f"(score {report.score:.2f})"
    )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Provider")
    table.add_column("Score")
    table.add_column("Detail")
    for r in report.results:
        if r.success:
            score = "-" if r.score is None else f"{r.score:.2f}"
            table.add_row(r.provider, score, r.summary or "-")
        else:
            table.add_row(r.provider, "err", f"[red]{r.error}[/red]")
    console.print(table)


@app.command()
def main(
    ioc: str = typer.Argument(..., help="IP, domain, URL, or file hash to enrich"),
    output: str = typer.Option("table", help="Output format: table | json | markdown"),
    save: str = typer.Option(None, "--save", help="Write the report to this file path"),
) -> None:
    """Enrich a single IOC."""
    load_dotenv()

    indicator = detector.detect(ioc)
    if indicator.type == IOCType.UNKNOWN:
        console.print(f"[red]Could not recognize '{ioc}' as an IP, domain, URL, or hash.[/red]")
        raise typer.Exit(code=1)

    engine = Engine(_build_providers())
    report = engine.enrich(indicator)

    from .report import json_report, markdown_report

    if output == "json":
        text = json_report.render(report)
        console.print_json(text)
    elif output == "markdown":
        text = markdown_report.render(report)
        console.print(text)
    else:
        text = None
        _render_table(report)

    if save:
        # For the table format there's no file body, so default to JSON on save.
        body = text if text is not None else json_report.render(report)
        Path(save).write_text(body, encoding="utf-8")
        console.print(f"[green]Saved report to[/green] {save}")


if __name__ == "__main__":
    app()
