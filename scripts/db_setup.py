#!/usr/bin/env python3
"""
Database setup script — creates the QuShield database and all tables.
Run from project root: python scripts/db_setup.py
"""
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from rich.console import Console
from rich.table import Table

console = Console()


def main():
    console.print("\n[bold cyan]QuShield-PnB Database Setup[/bold cyan]\n")

    # Step 1: Check connection
    console.print("[dim]Connecting to PostgreSQL...[/dim]")
    try:
        from app.config import settings
        from app.core.database import engine, check_connection, Base
        from app.models import (
            ScanJob, Asset, AssetPort, Certificate,
            CBOMRecord, CBOMComponent, RiskScore, RiskFactor, ComplianceResult,
        )

        if not check_connection():
            console.print("[red]✗ Cannot connect to PostgreSQL[/red]")
            console.print(f"  Connection URL: {settings.database_url}")
            console.print("  Make sure PostgreSQL is running and the database exists.")
            console.print("  On Manjaro: sudo systemctl start postgresql")
            sys.exit(1)

        console.print("[green]✓ Connected to PostgreSQL[/green]")
        console.print(f"  Database: {settings.POSTGRES_DB}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}")

    except Exception as e:
        console.print(f"[red]✗ Connection failed: {e}[/red]")
        sys.exit(1)

    # Step 2: Create all tables
    console.print("\n[dim]Creating tables...[/dim]")
    try:
        Base.metadata.create_all(bind=engine)
        tables = list(Base.metadata.tables.keys())
        console.print(f"[green]✓ Created {len(tables)} tables[/green]")

        table = Table(title="Database Tables")
        table.add_column("Table Name", style="cyan")
        table.add_column("Columns", style="dim")
        for name, tbl in Base.metadata.tables.items():
            cols = ", ".join(c.name for c in tbl.columns)
            table.add_row(name, cols)
        console.print(table)

    except Exception as e:
        console.print(f"[red]✗ Table creation failed: {e}[/red]")
        sys.exit(1)

    console.print("\n[bold green]Database setup complete![/bold green]\n")


if __name__ == "__main__":
    main()
