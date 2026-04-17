"""Typer CLI for GhostAudit."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ghostaudit._version import __version__
from ghostaudit.checks import ALL_CHECKS
from ghostaudit.config import ALL_CHECK_CATEGORIES, ScanConfig
from ghostaudit.report import generate_html_report, generate_json_report, print_console_report
from ghostaudit.scanner import run_scan

app = typer.Typer(
    name="ghostaudit",
    help="Kubernetes Security Auditor - scan clusters for misconfigurations.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
err_console = Console(stderr=True)


def version_callback(value: bool) -> None:
    if value:
        console.print(f"ghostaudit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", "-v", help="Show version and exit.", callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """GhostAudit - Kubernetes Security Auditor CLI."""


@app.command()
def scan(
    kubeconfig: str | None = typer.Option(
        None, "--kubeconfig", "-k",
        help="Path to kubeconfig file. Defaults to ~/.kube/config or in-cluster config.",
    ),
    namespace: str | None = typer.Option(
        None, "--namespace", "-n",
        help="Scan a specific namespace only. Default: all namespaces.",
    ),
    output: str | None = typer.Option(
        None, "--output", "-o",
        help="Output file path. Format detected from extension (.html, .json).",
    ),
    checks_filter: str | None = typer.Option(
        None, "--checks", "-c",
        help=f"Comma-separated check categories to run. Options: {', '.join(ALL_CHECK_CATEGORIES)}",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", help="Enable verbose output.",
    ),
) -> None:
    """Run a security scan against a Kubernetes cluster."""
    check_list = ALL_CHECK_CATEGORIES
    if checks_filter:
        check_list = [c.strip() for c in checks_filter.split(",")]

    try:
        config = ScanConfig(
            kubeconfig=kubeconfig,
            namespace=namespace,
            output=output,
            checks=check_list,
            verbose=verbose,
        )
    except ValueError as e:
        err_console.print(f"[bold red]Configuration error:[/] {e}")
        raise typer.Exit(code=1)

    err_console.print(f"[bold blue]GhostAudit[/] v{__version__}")
    err_console.print()

    report = run_scan(config)

    # Always print console report to stderr
    print_console_report(report, console=console)

    # Write file output if requested
    if output:
        output_path = Path(output)
        ext = output_path.suffix.lower()

        if ext == ".html":
            generate_html_report(report, output_path=str(output_path))
            err_console.print(f"\n[bold green]HTML report written to:[/] {output_path}")
        elif ext == ".json":
            generate_json_report(report, output_path=str(output_path))
            err_console.print(f"\n[bold green]JSON report written to:[/] {output_path}")
        else:
            # Default: JSON
            generate_json_report(report, output_path=str(output_path))
            err_console.print(f"\n[bold green]Report written to:[/] {output_path}")

    # Exit with non-zero if critical findings
    critical_count = report.summary.get("CRITICAL", 0)
    high_count = report.summary.get("HIGH", 0)
    if critical_count > 0 or high_count > 0:
        raise typer.Exit(code=2)


@app.command(name="checks")
def list_checks() -> None:
    """List all available security checks with descriptions."""
    table = Table(
        title="GhostAudit Security Checks",
        show_header=True,
        header_style="bold blue",
    )
    table.add_column("ID", style="bold", min_width=10)
    table.add_column("Category", min_width=10)
    table.add_column("Title", min_width=20)
    table.add_column("Description")

    for category_name in ALL_CHECK_CATEGORIES:
        check_cls = ALL_CHECKS.get(category_name)
        if check_cls is None:
            continue
        for info in check_cls.list_checks():
            table.add_row(
                info.check_id,
                info.category.upper(),
                info.title,
                info.description,
            )

    console.print(table)
