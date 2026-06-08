"""CLI entrypoint for the red-teaming harness."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

app = typer.Typer(help="Automated red-teaming harness for LLM safety evaluation.")
console = Console()


@app.command()
def run(
    model: str = typer.Option("claude-haiku-4-5-20251001", help="Target model to red-team."),
    attacks_dir: Path = typer.Option(Path("attacks"), help="Directory containing YAML attack templates."),
    categories: Optional[str] = typer.Option(None, help="Comma-separated categories to run (e.g. jailbreak,prompt_injection)."),
    severity: Optional[str] = typer.Option(None, help="Filter by severity: low, medium, high."),
    output: Optional[Path] = typer.Option(None, help="Save JSON report to this path."),
) -> None:
    """Run red-team probes against a target model and generate a risk report."""
    from .loader import load_all_templates
    from .runner import RedTeamRunner
    from .reporter import build_report, render_console, save_json

    category_list = [c.strip() for c in categories.split(",")] if categories else None

    templates = load_all_templates(attacks_dir, categories=category_list, severity=severity)
    if not templates:
        console.print("[yellow]No attack templates found matching filters.[/yellow]")
        raise typer.Exit(0)

    console.print(f"[cyan]Loaded {len(templates)} attack templates. Running probes against [bold]{model}[/bold]…[/cyan]\n")

    runner = RedTeamRunner(target_model=model)
    results = runner.run_all(templates)

    report = build_report(results, target_model=model)
    render_console(report)

    if output:
        save_json(report, output)


if __name__ == "__main__":
    app()
