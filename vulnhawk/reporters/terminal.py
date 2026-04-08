"""Beautiful terminal output using Rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnhawk.models import ScanResult, Severity


def render(result: ScanResult, console: Console | None = None) -> None:
    """Render scan results to the terminal."""
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]VulnHawk Security Scan[/bold]\n"
            f"Target: [cyan]{result.target}[/cyan]\n"
            f"Backend: [dim]{result.llm_backend}[/dim]  |  "
            f"Files: [dim]{result.files_scanned}[/dim]  |  "
            f"Chunks: [dim]{result.chunks_analyzed}[/dim]  |  "
            f"Duration: [dim]{result.scan_duration:.1f}s[/dim]",
            border_style="blue",
        )
    )

    if not result.findings:
        console.print("\n[bold green]No vulnerabilities found.[/bold green]\n")
        return

    # Summary table
    summary = Table(title="Summary", show_header=True, border_style="dim")
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", justify="right")

    severity_counts = {}
    for finding in result.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            summary.add_row(
                Text(sev.value.upper(), style=sev.color),
                str(count),
            )

    console.print(summary)
    console.print()

    # Individual findings
    for i, finding in enumerate(result.findings, 1):
        sev = finding.severity
        confidence_bar = _confidence_bar(finding.confidence)

        header = f"[{sev.color}]{sev.emoji} {sev.value.upper()}[/{sev.color}]  {finding.title}"
        if finding.cwe_id:
            header += f"  [dim]({finding.cwe_id})[/dim]"

        panel_content = []

        # Location
        panel_content.append(
            f"[bold]Location:[/bold] {finding.file_path}:{finding.start_line}-{finding.end_line}"
        )
        panel_content.append(f"[bold]Confidence:[/bold] {confidence_bar} {finding.confidence:.0%}")

        if finding.category:
            panel_content.append(f"[bold]Category:[/bold] {finding.category}")

        # Description
        panel_content.append(f"\n[bold]Description:[/bold]\n{finding.description}")

        # Code snippet
        if finding.code_snippet:
            snippet = finding.code_snippet[:500]
            panel_content.append(f"\n[bold]Vulnerable Code:[/bold]\n```\n{snippet}\n```")

        # Fix suggestion
        if finding.fix_suggestion:
            panel_content.append(
                f"\n[bold green]Fix:[/bold green]\n{finding.fix_suggestion}"
            )

        console.print(
            Panel(
                "\n".join(panel_content),
                title=header,
                border_style=sev.color,
                subtitle=f"Finding {i}/{len(result.findings)}",
            )
        )
        console.print()

    # Footer
    total = len(result.findings)
    critical = severity_counts.get(Severity.CRITICAL, 0)
    high = severity_counts.get(Severity.HIGH, 0)

    if critical > 0 or high > 0:
        console.print(
            f"[bold red]Found {total} vulnerabilities "
            f"({critical} critical, {high} high)[/bold red]\n"
        )
    else:
        console.print(
            f"[bold yellow]Found {total} vulnerabilities[/bold yellow]\n"
        )


def _confidence_bar(confidence: float) -> str:
    """Render a confidence bar."""
    filled = int(confidence * 10)
    empty = 10 - filled
    return f"[green]{'|' * filled}[/green][dim]{'|' * empty}[/dim]"
