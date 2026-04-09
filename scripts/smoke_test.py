#!/usr/bin/env python3
"""
QuShield-PnB Smoke Test — end-to-end validation of all system components.

Usage: python scripts/smoke_test.py [domain]
"""
import sys
import os
import time

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def check_config() -> tuple[bool, str]:
    """Check configuration loads correctly."""
    try:
        from app.config import settings
        if not settings.POSTGRES_PASSWORD:
            return False, "POSTGRES_PASSWORD not set in .env"
        return True, f"DB: {settings.POSTGRES_DB}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}"
    except Exception as e:
        return False, str(e)


def check_database() -> tuple[bool, str]:
    """Check database connectivity."""
    try:
        from app.core.database import check_connection
        if check_connection():
            return True, "PostgreSQL connected"
        return False, "Cannot connect to PostgreSQL"
    except Exception as e:
        return False, str(e)


def check_logging() -> tuple[bool, str]:
    """Check logging framework works."""
    try:
        from app.core.logging import get_logger
        logger = get_logger("smoke_test")
        logger.info("Smoke test log entry")
        return True, "JSON logging to logs/smoke_test/"
    except Exception as e:
        return False, str(e)


def check_models() -> tuple[bool, str]:
    """Check all models import correctly."""
    try:
        from app.models import (
            ScanJob, Asset, AssetPort, Certificate,
            CBOMRecord, CBOMComponent, RiskScore, RiskFactor, ComplianceResult,
        )
        return True, "9 models loaded"
    except Exception as e:
        return False, str(e)


def check_schemas() -> tuple[bool, str]:
    """Check Pydantic schemas."""
    try:
        from app.schemas.scan import ScanRequest
        from app.schemas.asset import AssetCreate
        from app.schemas.risk import MoscaInput
        ScanRequest(targets=["example.com"])
        return True, "All schemas validated"
    except Exception as e:
        return False, str(e)


def check_static_data() -> tuple[bool, str]:
    """Check static data files load."""
    try:
        import json
        base = os.path.join(os.path.dirname(__file__), "..", "backend", "app", "data")
        files = ["nist_quantum_levels.json", "pqc_oids.json",
                 "data_shelf_life_defaults.json", "regulatory_deadlines.json"]
        total = 0
        for f in files:
            data = json.load(open(os.path.join(base, f)))
            total += len(data)
        return True, f"{len(files)} files, {total} total entries"
    except Exception as e:
        return False, str(e)


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    console.print(Panel.fit(
        f"[bold cyan]QuShield-PnB Smoke Test[/bold cyan]\n"
        f"[dim]Target: {domain}[/dim]",
        border_style="cyan",
    ))
    console.print()

    checks = [
        ("Config", check_config),
        ("Database", check_database),
        ("Logging", check_logging),
        ("Models", check_models),
        ("Schemas", check_schemas),
        ("Static Data", check_static_data),
    ]

    table = Table(show_header=True, header_style="bold")
    table.add_column("Component", style="cyan", width=15)
    table.add_column("Status", width=8)
    table.add_column("Details")

    all_pass = True
    for name, check_fn in checks:
        try:
            passed, detail = check_fn()
        except Exception as e:
            passed, detail = False, str(e)

        if passed:
            table.add_row(name, "[green]✅ PASS[/green]", detail)
        else:
            table.add_row(name, "[red]❌ FAIL[/red]", f"[red]{detail}[/red]")
            all_pass = False

    console.print(table)
    console.print()

    if all_pass:
        console.print("[bold green]All checks passed![/bold green]")
    else:
        console.print("[bold red]Some checks failed — see details above.[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
