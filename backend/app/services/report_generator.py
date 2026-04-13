"""Report generation service with per-report templates and datasets."""
import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader

try:
    from weasyprint import HTML
except ImportError:
    HTML = None

from sqlalchemy.orm import Session
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.risk import RiskScore
from app.models.compliance import ComplianceResult
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.auth import User
from app.services.ai_service import get_ai_provider

logger = logging.getLogger(__name__)


class ReportGenerator:
    TEMPLATE_BY_TYPE = {
        "executive": "executive.html",
        "cbom_audit": "cbom_audit.html",
        "rbi_submission": "rbi_submission.html",
        "migration_progress": "migration_progress.html",
        "full_scan": "full_scan.html",
    }

    def __init__(self, db: Session, user: User):
        self.db = db
        self.user = user
        self.ai = get_ai_provider(user)
        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))

    def generate_report(self, scan_id: str, report_type: str, format: str = "pdf", password: str = None) -> bytes:
        if report_type not in self.TEMPLATE_BY_TYPE:
            raise ValueError("Unsupported report type")

        scan_job = self.db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan_job or scan_job.user_id != self.user.id:
            raise ValueError("Scan not found or unauthorized")

        dataset = self._build_dataset(scan_job)
        if report_type == "executive" or report_type == "full_scan":
            dataset["ai_narrative"] = self._generate_ai_narrative(dataset["stats"], dataset["critical_assets"])

        if format == "json":
            import json
            return json.dumps(dataset, default=str).encode("utf-8")
        elif format == "csv":
            import io
            import csv
            output = io.StringIO()
            assets = dataset.get("assets", [])
            if assets:
                writer = csv.DictWriter(output, fieldnames=assets[0].keys())
                writer.writeheader()
                for a in assets:
                    writer.writerow(a)
            else:
                output.write("No assets found in dataset.")
            return output.getvalue().encode("utf-8")

        template = self.jinja_env.get_template(self.TEMPLATE_BY_TYPE[report_type])
        html_content = template.render(**dataset)
        pdf_bytes = self._to_pdf_or_html(html_content)
        
        if format == "pdf" and password:
            try:
                from PyPDF2 import PdfReader, PdfWriter
                import io
                reader = PdfReader(io.BytesIO(pdf_bytes))
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                writer.encrypt(user_password=password, owner_password=password, use_128bit=True)
                pwd_output = io.BytesIO()
                writer.write(pwd_output)
                return pwd_output.getvalue()
            except ImportError:
                logger.error("PyPDF2 not installed. Proceeding without encryption.")
                
        return pdf_bytes

    def _to_pdf_or_html(self, html_content: str) -> bytes:
        if HTML:
            return HTML(string=html_content).write_pdf()
        logger.warning("WeasyPrint missing, returning raw HTML instead.")
        return html_content.encode("utf-8")

    def _build_dataset(self, scan_job: ScanJob) -> Dict[str, Any]:
        scan_id = str(scan_job.id)
        assets = self.db.query(Asset).filter(Asset.scan_id == scan_job.id).all()
        risks = self.db.query(RiskScore).filter(RiskScore.scan_id == scan_job.id).all()
        compliance = self.db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_job.id).all()
        cbom_records = self.db.query(CBOMRecord).filter(CBOMRecord.scan_id == scan_job.id).all()

        asset_by_id = {str(asset.id): asset for asset in assets}
        risk_by_asset = {str(r.asset_id): r for r in risks}
        compliance_by_asset = {str(c.asset_id): c for c in compliance}
        cbom_by_asset = {str(c.asset_id): c for c in cbom_records}

        critical_assets: List[Dict[str, Any]] = []
        scored_assets: List[Dict[str, Any]] = []
        risk_counts: Dict[str, int] = {}
        sum_readiness = 0.0

        for risk in risks:
            risk_class = risk.risk_classification or "unknown"
            risk_counts[risk_class] = risk_counts.get(risk_class, 0) + 1
            readiness = max(0, 10 - (risk.quantum_risk_score or 0) / 100)
            sum_readiness += readiness
            if risk_class in ("quantum_critical", "quantum_vulnerable"):
                asset = asset_by_id.get(str(risk.asset_id))
                if asset:
                    critical_assets.append(
                        {
                            "hostname": asset.hostname,
                            "ip_address": asset.ip_v4 or "N/A",
                            "asset_type": asset.asset_type or "unknown",
                            "risk_score": risk.quantum_risk_score or 0,
                            "classification": risk_class.replace("quantum_", "").upper(),
                            "weakness": f"Quantum risk score {risk.quantum_risk_score or 0}/1000",
                        }
                    )

        for asset in assets:
            asset_id = str(asset.id)
            risk = risk_by_asset.get(asset_id)
            comp = compliance_by_asset.get(asset_id)
            cbom = cbom_by_asset.get(asset_id)
            scored_assets.append(
                {
                    "hostname": asset.hostname,
                    "asset_type": asset.asset_type or "unknown",
                    "ip_address": asset.ip_v4 or "N/A",
                    "risk_score": risk.quantum_risk_score if risk else 0,
                    "risk_classification": (risk.risk_classification or "unknown").replace("quantum_", ""),
                    "hndl_exposed": bool(risk.hndl_exposed) if risk else False,
                    "crypto_agility_score": comp.crypto_agility_score if comp else 0,
                    "rbi_compliant": bool(comp.rbi_compliant) if comp else False,
                    "tls_13_enforced": bool(comp.tls_13_enforced) if comp else False,
                    "cbom_components": cbom.total_components if cbom else 0,
                    "cbom_ready_pct": round(cbom.quantum_ready_pct or 0, 1) if cbom else 0.0,
                }
            )

        avg_readiness = round(sum_readiness / len(risks), 1) if risks else 0.0
        avg_compliance_pct = round(
            (sum((c.compliance_pct or 0) for c in compliance) / len(compliance)) if compliance else 0.0, 1
        )
        avg_crypto_agility = round(
            (sum((c.crypto_agility_score or 0) for c in compliance) / len(compliance)) if compliance else 0.0, 1
        )

        cbom_components = (
            self.db.query(CBOMComponent).filter(CBOMComponent.scan_id == scan_job.id).all()
        )
        algorithm_distribution: Dict[str, int] = {}
        vulnerable_components = 0
        for component in cbom_components:
            name = component.name or "Unknown"
            algorithm_distribution[name] = algorithm_distribution.get(name, 0) + 1
            if component.is_quantum_vulnerable:
                vulnerable_components += 1

        top_algorithms = sorted(
            [{"name": name, "count": count} for name, count in algorithm_distribution.items()],
            key=lambda row: row["count"],
            reverse=True,
        )[:20]

        stats = {
            "total": len(assets),
            "high_count": len(critical_assets),
            "avg_readiness": avg_readiness,
            "avg_compliance_pct": avg_compliance_pct,
            "avg_crypto_agility": avg_crypto_agility,
            "total_cbom_components": len(cbom_components),
            "vulnerable_cbom_components": vulnerable_components,
            "rbi_compliant_assets": sum(1 for c in compliance if c.rbi_compliant),
            "tls_13_assets": sum(1 for c in compliance if c.tls_13_enforced),
            "hybrid_assets": sum(1 for c in compliance if c.hybrid_mode_active),
        }

        return {
            "scan_id": scan_id,
            "scan_type": scan_job.scan_type,
            "scan_status": scan_job.status,
            "targets": scan_job.targets or [],
            "generation_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "completed_at": scan_job.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan_job.completed_at else "N/A",
            "stats": stats,
            "risk_counts": risk_counts,
            "critical_assets": sorted(critical_assets, key=lambda row: row["risk_score"], reverse=True),
            "assets": sorted(scored_assets, key=lambda row: row["risk_score"], reverse=True),
            "top_algorithms": top_algorithms,
        }

    def _generate_ai_narrative(self, stats: Dict[str, Any], high_risks: List[Dict[str, Any]]) -> str:
        system_prompt = (
            "You are a CIO-level Quantum Security Advisor. "
            "Provide a concise 3-paragraph narrative and prioritize action items."
        )
        prompt = (
            f"Total Assets: {stats['total']}\n"
            f"Critical/High Risks: {stats['high_count']}\n"
            f"Average Readiness (0-10): {stats['avg_readiness']}\n"
            f"Compliance %: {stats['avg_compliance_pct']}\n\n"
            "Top high-risk assets:\n"
        )
        for row in high_risks[:10]:
            prompt += f"- {row['hostname']} ({row['asset_type']}): {row['weakness']}\n"
        try:
            return self.ai.generate(prompt=prompt, system=system_prompt, temperature=0.3)
        except Exception as exc:
            logger.error("Failed to generate narrative: %s", exc)
            return (
                "Automated narrative generation is unavailable. "
                "Prioritize critical/vulnerable assets and accelerate migration to PQC-ready controls."
            )
