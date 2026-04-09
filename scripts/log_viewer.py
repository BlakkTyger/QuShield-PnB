#!/usr/bin/env python3
"""
QuShield-PnB Log Viewer — reads structured JSONL logs with filtering and formatting.

Usage:
    python scripts/log_viewer.py --service crypto_inspector --last 20
    python scripts/log_viewer.py --level ERROR --since "2026-04-09T10:00"
    python scripts/log_viewer.py --follow --service orchestrator
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

LEVEL_COLORS = {
    "DEBUG": "dim",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold red",
}


def find_log_dir() -> Path:
    """Find the project logs directory."""
    from app.config import settings
    return settings.log_dir_abs


def read_log_entries(
    service: str = None,
    level: str = None,
    function: str = None,
    scan_id: str = None,
    last_n: int = None,
    since: str = None,
) -> list[dict]:
    """Read and filter log entries from JSONL files."""
    log_dir = find_log_dir()
    entries = []

    if not log_dir.exists():
        console.print(f"[red]Log directory not found: {log_dir}[/red]")
        return []

    # Collect log files
    if service:
        service_dirs = [log_dir / service]
    else:
        service_dirs = [d for d in log_dir.iterdir() if d.is_dir()]

    for sdir in service_dirs:
        if not sdir.exists():
            continue
        for log_file in sorted(sdir.glob("*.jsonl")):
            try:
                with open(log_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            entries.append(entry)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue

    # Apply filters
    if level:
        entries = [e for e in entries if e.get("level", "").upper() == level.upper()]
    if function:
        entries = [e for e in entries if function.lower() in e.get("function", "").lower()]
    if scan_id:
        entries = [e for e in entries if e.get("scan_id") == scan_id]
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            entries = [
                e for e in entries
                if datetime.fromisoformat(e.get("timestamp", "2000-01-01")) >= since_dt
            ]
        except ValueError:
            console.print(f"[yellow]Invalid --since datetime: {since}[/yellow]")

    # Limit
    if last_n:
        entries = entries[-last_n:]

    return entries


def display_entries(entries: list[dict]):
    """Display log entries as a formatted Rich table."""
    if not entries:
        console.print("[dim]No log entries found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold cyan", box=None, pad_edge=False)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Level", width=8)
    table.add_column("Service", style="cyan", width=18)
    table.add_column("Function", style="dim", width=25)
    table.add_column("Message", no_wrap=False)

    for entry in entries:
        ts = entry.get("timestamp", "")[:19]
        level = entry.get("level", "?")
        service = entry.get("service", "?")
        func = entry.get("function", "?")[:25]
        msg = entry.get("message", "")

        level_style = LEVEL_COLORS.get(level, "")
        level_text = Text(level, style=level_style)

        # Add extra fields to message
        extras = {k: v for k, v in entry.items()
                  if k not in ("timestamp", "level", "service", "function", "message", "asctime", "taskName")}
        if extras:
            extra_str = " | " + " ".join(f"{k}={v}" for k, v in list(extras.items())[:3])
            msg += extra_str

        table.add_row(ts, level_text, service, func, msg[:120])

    console.print(table)
    console.print(f"\n[dim]{len(entries)} entries displayed[/dim]")


def follow_mode(service: str = None):
    """Tail -f style log watching."""
    console.print("[bold cyan]Following logs... (Ctrl+C to stop)[/bold cyan]\n")
    seen = set()
    while True:
        entries = read_log_entries(service=service)
        for entry in entries:
            key = f"{entry.get('timestamp')}_{entry.get('message', '')[:50]}"
            if key not in seen:
                seen.add(key)
                display_entries([entry])
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="QuShield-PnB Log Viewer")
    parser.add_argument("--service", "-s", help="Filter by service name")
    parser.add_argument("--level", "-l", help="Filter by log level (DEBUG/INFO/WARNING/ERROR)")
    parser.add_argument("--function", "-f", help="Filter by function name (substring match)")
    parser.add_argument("--scan-id", help="Filter by scan ID")
    parser.add_argument("--last", "-n", type=int, default=50, help="Show last N entries (default: 50)")
    parser.add_argument("--since", help="Show entries since datetime (ISO format)")
    parser.add_argument("--follow", action="store_true", help="Follow mode (like tail -f)")
    args = parser.parse_args()

    if args.follow:
        try:
            follow_mode(service=args.service)
        except KeyboardInterrupt:
            console.print("\n[dim]Stopped following.[/dim]")
    else:
        entries = read_log_entries(
            service=args.service,
            level=args.level,
            function=args.function,
            scan_id=args.scan_id,
            last_n=args.last,
            since=args.since,
        )
        display_entries(entries)


if __name__ == "__main__":
    main()
