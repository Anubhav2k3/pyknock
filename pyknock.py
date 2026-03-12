#!/usr/bin/env python3
"""
pyknock.py
──────────
PyKnock — Autonomous AI Pentesting Agent
Powered by Claude (Anthropic)

Usage:
  python pyknock.py -t <target> -k <api_key> [options]
  python pyknock.py -t scanme.nmap.org -k $ANTHROPIC_API_KEY
  python pyknock.py -t 93.184.216.34 -k $ANTHROPIC_API_KEY --max-iter 8

Options:
  -t, --target        Target hostname or IP (required)
  -k, --api-key       Anthropic API key (or set ANTHROPIC_API_KEY env var)
  -o, --output        Output directory for reports (default: ./reports)
  --max-iter          Max AI decision cycles (default: 12)
  --version           Show version
  -h, --help          Show this help

⚠  LEGAL NOTICE: Only scan targets you own or have explicit written permission to test.
"""

from __future__ import annotations
import argparse
import os
import sys
import socket
import time
from pathlib import Path

# ── Import our own modules ──────────────────────────────────
# Add the directory containing this script to path
sys.path.insert(0, str(Path(__file__).parent))

import display
import agent as agent_module
import report as report_module


VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pyknock",
        description="PyKnock — Autonomous AI Pentesting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
        add_help=False,
    )
    parser.add_argument("-t", "--target",   required=False, help="Target hostname or IP")
    parser.add_argument("-k", "--api-key",  default=None,  help="Anthropic API key")
    parser.add_argument("-o", "--output",   default="reports", help="Report output dir")
    parser.add_argument("--max-iter",       type=int, default=12, help="Max AI cycles")
    parser.add_argument("--version",        action="store_true", help="Show version")
    parser.add_argument("-h", "--help",     action="store_true", help="Show help")
    return parser.parse_args(argv)


# ─────────────────────────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────────────────────────

def _validate_target(target: str) -> str:
    """Resolve and validate target. Returns cleaned target string."""
    target = target.strip().rstrip("/")
    # Remove scheme if given
    for scheme in ("http://", "https://", "ftp://"):
        if target.startswith(scheme):
            target = target[len(scheme):]
    # Attempt DNS resolution as a sanity check
    try:
        ip = socket.gethostbyname(target)
        display.print_info(f"Resolved {target} → {ip}")
    except socket.gaierror:
        display.print_warn(f"Could not resolve {target!r} — continuing anyway")
    return target


def _get_api_key(args: argparse.Namespace) -> str:
    key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        display.print_error(
            "No Anthropic API key provided.\n"
            "  Set via -k/--api-key flag or ANTHROPIC_API_KEY environment variable.\n"
            "  Get a key at: https://console.anthropic.com/"
        )
        sys.exit(1)
    return key.strip()


# ─────────────────────────────────────────────────────────────
# Consent / legal prompt
# ─────────────────────────────────────────────────────────────

def _legal_consent(target: str) -> None:
    display.console.print(
        "\n[bold yellow]⚠  LEGAL NOTICE[/bold yellow]\n"
        "[white]Only scan targets you OWN or have EXPLICIT WRITTEN PERMISSION to test.\n"
        f"Target: [bold cyan]{target}[/bold cyan][/white]\n"
    )
    try:
        ans = input("  Do you have authorisation to scan this target? [y/N] ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)
    if ans not in ("y", "yes"):
        display.print_warn("Authorisation not confirmed. Exiting.")
        sys.exit(0)
    print()


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # ── Version / help ─────────────────────────────────────
    if args.version:
        print(f"PyKnock v{VERSION}")
        return 0

    display.print_banner()

    if args.help or not args.target:
        display.console.print(__doc__)
        return 0

    # ── Setup ──────────────────────────────────────────────
    api_key = _get_api_key(args)
    target  = _validate_target(args.target)
    output_dir = args.output
    max_iter   = max(1, min(args.max_iter, 20))

    _legal_consent(target)

    display.print_info(f"Target      : [bold cyan]{target}[/bold cyan]")
    display.print_info(f"Output dir  : [dim]{output_dir}[/dim]")
    display.print_info(f"Max AI cycles: {max_iter}")
    display.print_info(f"API model   : claude-sonnet-4-20250514")
    display.console.print()

    start = time.time()

    # ── Run agent ──────────────────────────────────────────
    try:
        state = agent_module.run_agent(
            target=target,
            api_key=api_key,
            max_iterations=max_iter,
        )
    except KeyboardInterrupt:
        display.print_warn("Scan interrupted by user.")
        state = agent_module.AgentState(target=target)
        state.start_time = start

    # ── Print findings summary ─────────────────────────────
    display.print_rule("FINDINGS SUMMARY")
    display.print_findings_table([
        {"severity": f.severity, "title": f.title, "detail": f.detail}
        for f in state.findings
    ])

    # ── Stats ──────────────────────────────────────────────
    elapsed = time.time() - start
    display.print_rule("SCAN STATISTICS")
    display.print_summary_stats({
        "target":         target,
        "duration":       f"{int(elapsed // 60)}m {int(elapsed % 60)}s",
        "tools_run":      len(state.tools_run),
        "total_findings": len(state.findings),
        "iterations":     state.iterations,
    })

    # ── Save reports ───────────────────────────────────────
    display.print_rule("SAVING REPORTS")
    try:
        md_path, json_path = report_module.save_reports(state, output_dir)
        display.print_info(f"Markdown report : [bold cyan]{md_path}[/bold cyan]")
        display.print_info(f"JSON report     : [bold cyan]{json_path}[/bold cyan]")
        display.print_done(md_path)
    except Exception as e:
        display.print_error(f"Could not save reports: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
