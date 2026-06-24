"""``llm-guard`` command-line interface.

Subcommands
-----------
- ``scan-input`` / ``scan-output``: scan a single string and print the verdict.
- ``redteam``: fire the bundled payload corpus at the mock provider and print a
  resistance report (rich table by default, ``--json`` or ``--sarif``).
- ``owasp``: print the OWASP LLM Top 10 coverage table.
"""

from __future__ import annotations

import json
import sys

import typer
from rich.console import Console
from rich.table import Table

from llm_guard.models import ScanResult, Verdict
from llm_guard.owasp import ALL_CATEGORIES
from llm_guard.providers import MockProvider
from llm_guard.redteam import RedTeamReport, run_redteam, to_sarif

app = typer.Typer(
    add_completion=False,
    help="Security scanner + runtime firewall for LLM applications (OWASP LLM Top 10).",
)
console = Console()
err_console = Console(stderr=True)

_VERDICT_STYLE = {
    Verdict.ALLOW: "bold green",
    Verdict.FLAG: "bold yellow",
    Verdict.BLOCK: "bold red",
}


def _print_scan_result(text: str, result: ScanResult, surface: str) -> None:
    style = _VERDICT_STYLE[result.verdict]
    console.print(
        f"[bold]{surface}[/bold] verdict: "
        f"[{style}]{result.verdict.value.upper()}[/{style}] "
        f"(risk {result.risk_score:.2f})"
    )
    if result.is_clean:
        console.print("  [green]No detections.[/green]")
        return
    table = Table(show_header=True, header_style="bold magenta", box=None)
    table.add_column("Rule")
    table.add_column("OWASP")
    table.add_column("Severity")
    table.add_column("Score", justify="right")
    table.add_column("Detail")
    for det in result.detections:
        table.add_row(
            det.rule_id,
            det.category.label,
            det.severity.value,
            f"{det.score:.2f}",
            det.description,
        )
    console.print(table)


@app.command("scan-input")
def scan_input_cmd(
    text: str = typer.Argument(..., help="User input text to scan."),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Scan a single user-input string for injection / jailbreak attempts."""
    from llm_guard.scanner import scan_input as _scan

    result = _scan(text)
    if json_out:
        console.print_json(result.model_dump_json())
    else:
        _print_scan_result(text, result, "Input")
    raise typer.Exit(code=1 if result.is_blocked else 0)


@app.command("scan-output")
def scan_output_cmd(
    text: str = typer.Argument(..., help="Model output text to scan."),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Scan a single model-output string for sensitive-data leakage."""
    from llm_guard.scanner import scan_output as _scan

    result = _scan(text)
    if json_out:
        console.print_json(result.model_dump_json())
    else:
        _print_scan_result(text, result, "Output")
    raise typer.Exit(code=1 if result.is_blocked else 0)


def _resistance_style(fraction: float) -> str:
    if fraction >= 0.85:
        return "bold green"
    if fraction >= 0.6:
        return "bold yellow"
    return "bold red"


def _print_redteam_table(report: RedTeamReport) -> None:
    overall = report.resistance_score
    style = _resistance_style(overall)
    console.print(f"\n[bold]AI Red-Team Report[/bold] — target: [cyan]{report.target_name}[/cyan]")
    console.print(
        f"Overall resistance: [{style}]{overall:.0%}[/{style}] "
        f"({report.resisted}/{report.total} payloads resisted)\n"
    )

    cat_table = Table(title="By OWASP LLM category", header_style="bold magenta")
    cat_table.add_column("Category")
    cat_table.add_column("Resisted", justify="right")
    cat_table.add_column("Resistance", justify="right")
    from llm_guard.owasp import title_for

    for cs in report.category_scores:
        cstyle = _resistance_style(cs.resistance)
        cat_table.add_row(
            f"{cs.category} {title_for(cs.category)}",
            f"{cs.resisted}/{cs.total}",
            f"[{cstyle}]{cs.resistance:.0%}[/{cstyle}]",
        )
    console.print(cat_table)

    detail = Table(title="Per-payload results", header_style="bold magenta")
    detail.add_column("ID")
    detail.add_column("Technique")
    detail.add_column("Result")
    detail.add_column("Detail")
    for r in report.results:
        mark = "[green]RESISTED[/green]" if r.resisted else "[red]VULNERABLE[/red]"
        detail.add_row(r.payload.id, r.payload.technique, mark, r.detail)
    console.print(detail)


@app.command("redteam")
def redteam_cmd(
    json_out: bool = typer.Option(False, "--json", help="Emit a JSON report."),
    sarif_out: bool = typer.Option(False, "--sarif", help="Emit a SARIF 2.1.0 report."),
    vulnerable: bool = typer.Option(
        False,
        "--vulnerable",
        help="Target an intentionally unguarded mock model (for contrast).",
    ),
    fail_under: float | None = typer.Option(
        None,
        "--fail-under",
        help="Exit non-zero if overall resistance is below this fraction (0-1).",
    ),
) -> None:
    """Run the red-team battery against the mock provider and report resistance."""
    target = MockProvider(vulnerable=vulnerable)
    report = run_redteam(target)

    if json_out:
        console.print_json(json.dumps(report.to_dict()))
    elif sarif_out:
        console.print_json(json.dumps(to_sarif(report)))
    else:
        _print_redteam_table(report)

    if fail_under is not None and report.resistance_score < fail_under:
        err_console.print(
            f"[red]Resistance {report.resistance_score:.0%} below threshold {fail_under:.0%}[/red]"
        )
        raise typer.Exit(code=1)


@app.command("owasp")
def owasp_cmd() -> None:
    """Print the OWASP LLM Top 10 (2025) coverage table."""
    table = Table(title="OWASP Top 10 for LLM Applications (2025)", header_style="bold magenta")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Covered", justify="center")
    for entry in ALL_CATEGORIES:
        mark = "[green]yes[/green]" if entry.addressed else "[dim]—[/dim]"
        table.add_row(entry.id, entry.title, mark)
    console.print(table)


def main() -> None:
    """Entry point used by the ``llm-guard`` console script."""
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        err_console.print("[yellow]Interrupted.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
