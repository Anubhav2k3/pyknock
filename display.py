"""
pyknock/display.py
──────────────────
Terminal UI layer — all Rich rendering lives here.
"""

from __future__ import annotations
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.rule import Rule
from rich.syntax import Syntax
from rich import box
from rich.columns import Columns
from rich.align import Align

console = Console()

BANNER = r"""
[bold red]
 ██████╗ ██╗   ██╗██╗  ██╗███╗   ██╗ ██████╗  ██████╗██╗  ██╗
 ██╔══██╗╚██╗ ██╔╝██║ ██╔╝████╗  ██║██╔═══██╗██╔════╝██║ ██╔╝
 ██████╔╝ ╚████╔╝ █████╔╝ ██╔██╗ ██║██║   ██║██║     █████╔╝ 
 ██╔═══╝   ╚██╔╝  ██╔═██╗ ██║╚██╗██║██║   ██║██║     ██╔═██╗ 
 ██║        ██║   ██║  ██╗██║ ╚████║╚██████╔╝╚██████╗██║  ██╗
 ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
[/bold red]"""

TAGLINE = "[dim white]  ⚡ Autonomous AI Pentesting Agent  |  github.com/anubhav2k3/pyknock  |  v1.0.0[/dim white]"


def print_banner() -> None:
    console.print(BANNER)
    console.print(Align.center(TAGLINE))
    console.print()


def print_rule(title: str, style: str = "bold red") -> None:
    console.print(Rule(f" {title} ", style=style))


def print_phase(phase: str, description: str) -> None:
    console.print()
    console.print(Panel(
        f"[bold white]{description}[/bold white]",
        title=f"[bold red]◈ PHASE: {phase.upper()}[/bold red]",
        border_style="red",
        padding=(0, 2),
    ))


def print_tool_start(tool: str, cmd: str) -> None:
    console.print(f"  [bold yellow]▶[/bold yellow] [cyan]{tool}[/cyan]  [dim]{cmd}[/dim]")


def print_tool_output(output: str, max_lines: int = 30) -> None:
    lines = output.strip().splitlines()
    if not lines:
        return
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"[dim]... (+{len(lines) - max_lines} more lines)[/dim]"]
    for line in lines:
        console.print(f"    [dim white]{line}[/dim white]")


def print_tool_done(tool: str, elapsed: float, findings: int = 0) -> None:
    badge = f"[green]{findings} finding(s)[/green]" if findings else "[dim]no new findings[/dim]"
    console.print(
        f"  [bold green]✔[/bold green] [cyan]{tool}[/cyan]  "
        f"[dim]{elapsed:.1f}s[/dim]  {badge}"
    )


def print_ai_thinking(text: str) -> None:
    console.print()
    console.print(Panel(
        Text(text, style="italic white"),
        title="[bold magenta]🤖 AI ANALYSIS[/bold magenta]",
        border_style="magenta",
        padding=(0, 2),
    ))


def print_ai_decision(decision: str, next_tools: list[str]) -> None:
    tools_str = "  ".join(f"[bold cyan]{t}[/bold cyan]" for t in next_tools) or "[dim]none[/dim]"
    console.print(Panel(
        f"[white]{decision}[/white]\n\n[bold]Next tools:[/bold]  {tools_str}",
        title="[bold blue]📡 DECISION[/bold blue]",
        border_style="blue",
        padding=(0, 2),
    ))


def print_finding(severity: str, title: str, detail: str) -> None:
    colours = {
        "CRITICAL": ("red", "💀"),
        "HIGH":     ("bright_red", "🔴"),
        "MEDIUM":   ("yellow", "🟡"),
        "LOW":      ("green", "🟢"),
        "INFO":     ("cyan", "ℹ️ "),
    }
    colour, icon = colours.get(severity.upper(), ("white", "•"))
    console.print(
        f"  {icon}  [{colour}][{severity}][/{colour}]  [bold white]{title}[/bold white]"
    )
    if detail:
        console.print(f"       [dim]{detail[:160]}[/dim]")


def print_findings_table(findings: list[dict]) -> None:
    if not findings:
        console.print("[dim]  No findings recorded.[/dim]")
        return
    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="red",
        show_header=True,
        header_style="bold red",
        padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=38)
    table.add_column("Detail", width=52)

    sev_colours = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                   "LOW": "green", "INFO": "cyan"}

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        colour = sev_colours.get(sev.upper(), "white")
        table.add_row(
            str(i),
            f"[{colour}]{sev}[/{colour}]",
            f.get("title", ""),
            f.get("detail", "")[:80],
        )
    console.print(table)


def print_summary_stats(stats: dict) -> None:
    items = []
    for label, val, colour in [
        ("Target",    stats.get("target", "?"),  "white"),
        ("Duration",  stats.get("duration", "?"), "cyan"),
        ("Tools Run", str(stats.get("tools_run", 0)), "yellow"),
        ("Findings",  str(stats.get("total_findings", 0)), "red"),
        ("Iterations",str(stats.get("iterations", 0)), "magenta"),
    ]:
        items.append(Panel(f"[{colour}]{val}[/{colour}]", title=f"[dim]{label}[/dim]",
                           border_style="dim", padding=(0, 2)))
    console.print(Columns(items, equal=True, expand=True))


def spinner_context(label: str):
    """Return a Live spinner context manager."""
    return Live(
        Spinner("dots2", text=Text(f" {label}", style="dim white")),
        console=console,
        refresh_per_second=10,
        transient=True,
    )


def print_error(msg: str) -> None:
    console.print(f"[bold red]  ✖  ERROR:[/bold red] [white]{msg}[/white]")


def print_warn(msg: str) -> None:
    console.print(f"[bold yellow]  ⚠  WARN:[/bold yellow] [white]{msg}[/white]")


def print_info(msg: str) -> None:
    console.print(f"  [bold cyan]ℹ[/bold cyan]  [white]{msg}[/white]")


def print_done(report_path: str) -> None:
    console.print()
    console.print(Panel(
        f"[bold green]Scan complete![/bold green]\n\n"
        f"[white]Report saved to:[/white] [bold cyan]{report_path}[/bold cyan]",
        title="[bold green]✅  PYKNOCK DONE[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))
