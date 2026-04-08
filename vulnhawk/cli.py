"""VulnHawk CLI - AI-powered code security scanner."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console

from vulnhawk import __version__
from vulnhawk.models import ScanMode, Severity

console = Console()


def _get_llm(backend: str, model: str | None):
    """Initialize the requested LLM backend."""
    if backend == "claude":
        from vulnhawk.llm.claude import ClaudeLLM
        llm = ClaudeLLM(model=model or "claude-sonnet-4-20250514")
    elif backend == "openai":
        from vulnhawk.llm.openai_backend import OpenAILLM
        llm = OpenAILLM(model=model or "gpt-4o")
    elif backend == "ollama":
        from vulnhawk.llm.ollama import OllamaLLM
        llm = OllamaLLM(model=model or "llama3.1")
    else:
        console.print(f"[red]Unknown backend: {backend}[/red]")
        sys.exit(1)

    if not llm.is_configured():
        if backend == "claude":
            console.print("[red]ANTHROPIC_API_KEY not set.[/red]")
            console.print("Set it: export ANTHROPIC_API_KEY=sk-ant-...")
        elif backend == "openai":
            console.print("[red]OPENAI_API_KEY not set.[/red]")
            console.print("Set it: export OPENAI_API_KEY=sk-...")
        elif backend == "ollama":
            console.print("[red]Ollama not running.[/red]")
            console.print("Start it: ollama serve")
        sys.exit(1)

    return llm


@click.group()
@click.version_option(version=__version__, prog_name="vulnhawk")
def main():
    """VulnHawk - AI-powered code security scanner.

    Find vulnerabilities that Semgrep and CodeQL miss.
    """
    pass


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--backend", "-b",
    type=click.Choice(["claude", "openai", "ollama"]),
    default="claude",
    help="LLM backend to use",
)
@click.option("--model", "-m", default=None, help="Specific model name (overrides backend default)")
@click.option(
    "--mode",
    type=click.Choice(["full", "auth", "injection", "secrets", "config", "crypto"]),
    default="full",
    help="Scan focus area",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="low",
    help="Minimum severity to report",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["terminal", "json", "sarif", "markdown"]),
    default="terminal",
    help="Output format",
)
@click.option("--output-file", "-f", type=click.Path(), default=None, help="Write output to file")
@click.option("--no-progress", is_flag=True, help="Disable progress bar")
def scan(target, backend, model, mode, severity, output, output_file, no_progress):
    """Scan a codebase or file for security vulnerabilities.

    TARGET can be a file or directory path.

    Examples:

        vulnhawk scan ./src

        vulnhawk scan ./src --mode auth --severity high

        vulnhawk scan ./api -b ollama -m llama3.1

        vulnhawk scan . -o sarif -f results.sarif
    """
    from vulnhawk.scanner.engine import scan as run_scan

    target_path = Path(target).resolve()
    llm = _get_llm(backend, model)
    scan_mode = ScanMode(mode)
    min_severity = Severity(severity)

    # Banner
    if output == "terminal":
        console.print(f"\n[bold blue]VulnHawk v{__version__}[/bold blue]")
        console.print("[dim]AI-powered code security scanner[/dim]")
        console.print(f"[dim]Backend: {backend} | Mode: {mode} | Min severity: {severity}[/dim]\n")

    result = asyncio.run(
        run_scan(
            target=target_path,
            llm=llm,
            mode=scan_mode,
            min_severity=min_severity,
            show_progress=output == "terminal" and not no_progress,
        )
    )

    # Render output
    if output == "terminal":
        from vulnhawk.reporters.terminal import render
        render(result, console)
    elif output == "json":
        from vulnhawk.reporters.json_reporter import render
        rendered = render(result)
        if output_file:
            Path(output_file).write_text(rendered)
            console.print(f"[green]Results written to {output_file}[/green]")
        else:
            click.echo(rendered)
    elif output == "sarif":
        from vulnhawk.reporters.sarif import render
        rendered = render(result)
        if output_file:
            Path(output_file).write_text(rendered)
            console.print(f"[green]SARIF results written to {output_file}[/green]")
        else:
            click.echo(rendered)
    elif output == "markdown":
        from vulnhawk.reporters.markdown import render
        rendered = render(result)
        if output_file:
            Path(output_file).write_text(rendered)
            console.print(f"[green]Report written to {output_file}[/green]")
        else:
            click.echo(rendered)

    # Exit code: non-zero if critical/high findings
    if result.critical_count > 0 or result.high_count > 0:
        sys.exit(1)


@main.command()
@click.argument("target", type=click.Path(exists=True))
def info(target):
    """Show what VulnHawk would scan (without running analysis).

    Useful for checking file discovery and chunk counts before a scan.
    """
    from vulnhawk.scanner.chunker import chunk_codebase, chunk_file

    target_path = Path(target).resolve()

    if target_path.is_file():
        chunks = chunk_file(target_path)
        files = [target_path]
    else:
        chunks, files = chunk_codebase(target_path)

    console.print("\n[bold]VulnHawk Scan Preview[/bold]")
    console.print(f"Target: [cyan]{target_path}[/cyan]")
    console.print(f"Files: [green]{len(files)}[/green]")
    console.print(f"Chunks: [green]{len(chunks)}[/green]")

    # Language breakdown
    lang_counts: dict[str, int] = {}
    for chunk in chunks:
        lang_counts[chunk.language.value] = lang_counts.get(chunk.language.value, 0) + 1

    console.print("\n[bold]Languages:[/bold]")
    for lang, count in sorted(lang_counts.items(), key=lambda x: -x[1]):
        console.print(f"  {lang}: {count} chunks")

    # Chunk types
    type_counts: dict[str, int] = {}
    for chunk in chunks:
        type_counts[chunk.chunk_type] = type_counts.get(chunk.chunk_type, 0) + 1

    console.print("\n[bold]Chunk Types:[/bold]")
    for ctype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        console.print(f"  {ctype}: {count}")

    console.print()


if __name__ == "__main__":
    main()
