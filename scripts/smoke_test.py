import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.core.database import SessionLocal
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.risk import RiskScore
from app.services.orchestrator import ScanOrchestrator

def build_cli_table(assets, db):
    table = Table(title="Asset Discovery & Cryptographic Inventory", show_header=True, header_style="bold magenta")
    table.add_column("Asset / Subdomain", style="dim", width=25)
    table.add_column("IP Address", width=15)
    table.add_column("Encryption Algo", width=18)
    table.add_column("TLS Ver", justify="center", width=8)
    table.add_column("Key Len", justify="center", width=8)
    table.add_column("Validity", justify="center", width=12)
    table.add_column("Q. Status", justify="center", width=10)
    table.add_column("Risk Score", justify="center", width=8)

    for asset in assets:
        cert = db.query(Certificate).filter(Certificate.asset_id == asset.id).first()
        risk = db.query(RiskScore).filter(RiskScore.asset_id == asset.id).first()

        encryption = "N/A"
        tls_ver = "N/A"
        key_len = "N/A"
        valid_date = "N/A"
        q_status = "N/A"
        risk_str = "N/A"

        if cert:
            encryption = f"{cert.key_type}-{cert.signature_algorithm}" if cert.key_type and cert.signature_algorithm else "Unknown"
            tls_ver = "Live"  # Ideally derived from CBOM/infrastructure
            key_len = str(cert.key_length) if cert.key_length else "-"
            valid_date = str(cert.valid_to.date()) if cert.valid_to else "-"
            # Fallback mappings for Q-Status
            if "ML-KEM" in encryption.upper() or "ML-DSA" in encryption.upper():
                q_status = "[bold green]Safe[/bold green]"
            else:
                q_status = "[bold red]Vuln[/bold red]"

        if risk:
            score = risk.quantum_risk_score
            if score > 750:
                risk_str = f"[bold red]{score}[/bold red]"
            elif score > 500:
                risk_str = f"[bold yellow]{score}[/bold yellow]"
            else:
                risk_str = f"[bold green]{score}[/bold green]"

        table.add_row(
            asset.hostname,
            asset.ip_v4 or "-",
            encryption,
            tls_ver,
            key_len,
            valid_date,
            q_status,
            risk_str
        )

    return table

def run_smoke_test(domain: str):
    console = Console()
    console.print(Panel.fit(f"[bold blue]QuShield-PnB Smoke Test Report[/bold blue]\nTarget: {domain}"))

    orch = ScanOrchestrator()
    try:
        console.print(f"[yellow]Triggering orchestrator execution against {domain}...[/yellow]")
        scan_id = orch.start_scan([domain])
        summary = orch.run_scan(scan_id)

        console.print(f"\n[bold green]Scan Completed in {summary['duration_seconds']}s[/bold green]")
        console.print(f"Phases Processed: {summary['phases_completed']}")
        console.print(f"Assets Discovered: {summary['assets_discovered']}")
        console.print(f"Crypto Scans Completed: {summary['crypto_scans']}")

        db = SessionLocal()
        assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
        table = build_cli_table(assets, db)
        console.print(table)
        db.close()

    except Exception as e:
        console.print(f"[bold red]Smoke test failed:[/bold red] {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python smoke_test.py <domain>")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    run_smoke_test(target_domain)
