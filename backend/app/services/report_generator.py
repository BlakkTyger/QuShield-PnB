"""
AI Report Generator — Builds Executive and Technical HTML/PDF reports using WeasyPrint
and Jinja2 templates, featuring AI-generated narrative summaries.
"""
import os
import logging
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader

try:
    from weasyprint import HTML
except ImportError:
    HTML = None

from sqlalchemy.orm import Session
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.risk import RiskScore
from app.models.auth import User
from app.services.ai_service import get_ai_provider

logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, db: Session, user: User):
        self.db = db
        self.user = user
        self.ai = get_ai_provider(user)
        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))

    def _generate_ai_narrative(self, stats: dict, high_risks: list) -> str:
        """Prompts the LLM to generate an Executive Summary based on scan stats."""
        system_prompt = "You are a CIO-level Quantum Security Advisor. Provide a brief, 3-paragraph executive narrative summarizing the scan results and prioritizing action. Use professional board-room language."
        
        prompt = f"""
Scan Statistics:
Total Assets: {stats['total']}
Critical/High Risks: {stats['high_count']}
Average Readiness (0-10): {stats['avg_readiness']}

Significant High Risk Assets:
"""
        for r in high_risks[:10]: # Limit context length
            prompt += f"- {r['hostname']} ({r['asset_type']}): {r['weakness']}\n"
            
        try:
            return self.ai.generate(prompt=prompt, system=system_prompt, temperature=0.3)
        except Exception as e:
            logger.error(f"Failed to generate narrative: {e}")
            return "AI Narrative generation temporarily unavailable."

    def generate_executive_report(self, scan_id: str) -> bytes:
        """Generates an Executive PDF report via Jinja + WeasyPrint."""
        scan_job = self.db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan_job or scan_job.user_id != self.user.id:
            raise ValueError("Scan not found or unauthorized")

        assets = self.db.query(Asset).filter(Asset.scan_id == scan_id).all()
        risks = self.db.query(RiskScore).filter(RiskScore.scan_id == scan_id).all()

        total_assets = len(assets)
        high_risks = []
        
        asset_map = {str(a.id): a for a in assets}
        
        sum_readiness = 0
        for r in risks:
            # Compute a 0-10 readiness from 0-1000 risk score (inverted: lower risk = higher readiness)
            readiness = max(0, 10 - (r.quantum_risk_score or 0) / 100)
            sum_readiness += readiness
            if r.risk_classification in ("quantum_critical", "quantum_vulnerable"):
                asset = asset_map.get(str(r.asset_id))
                if asset:
                    high_risks.append({
                        "hostname": asset.hostname,
                        "ip_address": asset.ip_v4 or "N/A",
                        "asset_type": asset.asset_type,
                        "risk_score": r.quantum_risk_score,
                        "classification": (r.risk_classification or "unknown").upper(),
                        "weakness": f"Quantum risk score {r.quantum_risk_score}/1000 — classical crypto vulnerable to CRQC"
                    })

        avg_readiness = round(sum_readiness / len(risks), 1) if risks else 0.0

        stats = {
            "total": total_assets,
            "high_count": len(high_risks),
            "avg_readiness": avg_readiness
        }

        # Generate LLM Narrative Narrative
        ai_narrative = self._generate_ai_narrative(stats, high_risks)

        # Render HTML Template
        template = self.jinja_env.get_template("executive.html")
        html_content = template.render(
            scan_id=scan_id,
            generation_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            total_assets=total_assets,
            high_risks_count=len(high_risks),
            avg_readiness=avg_readiness,
            ai_narrative=ai_narrative,
            critical_assets=high_risks
        )

        # Convert to PDF
        if HTML:
            pdf_bytes = HTML(string=html_content).write_pdf()
            return pdf_bytes
        else:
            logger.warning("WeasyPrint missing, returning raw HTML instead.")
            return html_content.encode('utf-8')
