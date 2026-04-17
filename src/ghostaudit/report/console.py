"""Rich console report output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ghostaudit.models import ScanReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[!!!]",
    Severity.HIGH: "[!!]",
    Severity.MEDIUM: "[!]",
    Severity.LOW: "[~]",
    Severity.INFO: "[i]",
}


def print_console_report(report: ScanReport, console: Console | None = None) -> None:
    """Print a formatted security report to the console."""
    if console is None:
        console = Console()

    # Header
    score = report.score
    if score >= 80:
        score_color = "green"
    elif score >= 60:
        score_color = "yellow"
    elif score >= 40:
        score_color = "red"
    else:
        score_color = "bold red"

    header = Text()
    header.append("GhostAudit Security Report\n", style="bold white")
    header.append(f"Cluster: {report.cluster_name}\n", style="dim")
    header.append(f"Time: {report.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n", style="dim")
    header.append(f"Namespaces: {', '.join(report.namespaces_scanned) or 'all'}\n", style="dim")
    header.append(f"Checks: {', '.join(report.checks_run)}\n", style="dim")
    header.append("\nSecurity Score: ", style="bold")
    header.append(f"{score}/100", style=f"bold {score_color}")

    console.print(Panel(header, border_style="blue", title="[bold blue]GhostAudit[/]"))

    # Summary table
    summary = report.summary
    summary_table = Table(title="Findings Summary", show_header=True)
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    for sev in Severity:
        count = summary.get(sev.value, 0)
        color = SEVERITY_COLORS[sev]
        summary_table.add_row(
            Text(sev.value, style=color),
            Text(str(count), style=color if count > 0 else "dim"),
        )
    summary_table.add_row(
        Text("TOTAL", style="bold"),
        Text(str(summary["TOTAL"]), style="bold"),
    )
    console.print(summary_table)
    console.print()

    # Findings
    if not report.findings:
        console.print("[bold green]No security findings! Your cluster looks good.[/]")
        return

    for finding in report.findings:
        color = SEVERITY_COLORS[finding.severity]
        icon = SEVERITY_ICONS[finding.severity]

        title = Text()
        title.append(f"{icon} ", style=color)
        title.append(f"[{finding.check_id}] ", style="bold")
        title.append(finding.title, style=f"bold {color}")

        detail = Text()
        detail.append("Resource: ", style="bold")
        detail.append(f"{finding.resource_kind}/{finding.resource_name}")
        if finding.namespace and finding.namespace != "<cluster>":
            detail.append(f" (ns: {finding.namespace})")
        detail.append("\n\n")
        detail.append(finding.description)
        detail.append("\n\n")
        detail.append("Remediation: ", style="bold green")
        detail.append(finding.remediation)

        console.print(Panel(
            detail,
            title=title,
            border_style=color.replace("bold ", ""),
            padding=(0, 1),
        ))

    # Errors
    if report.errors:
        console.print()
        for error in report.errors:
            console.print(f"[bold red]Error:[/] {error}")
