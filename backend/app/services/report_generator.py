"""
Report Generation Service — Produces dense, AI-enriched, chart-embedded PDF/HTML reports.

Supports 6 report types, each with:
- Per-section AI narrative (structured prompts, deterministic)
- Embedded Matplotlib chart images (base64 PNG)
- Saved to filesystem with GeneratedReport DB record
- Summaries embedded into ChromaDB for AI assistant access
"""
import io
import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from jinja2 import Environment, FileSystemLoader

try:
    from weasyprint import HTML
except ImportError:
    HTML = None

from sqlalchemy.orm import Session
from app.config import settings
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.risk import RiskScore, RiskFactor
from app.models.compliance import ComplianceResult
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.certificate import Certificate
from app.models.generated_report import GeneratedReport
from app.models.auth import User
from app.services.ai_service import get_ai_provider, AIConfigurationError

logger = logging.getLogger(__name__)


REPORT_LABELS = {
    "executive": "Quantum Risk Executive Summary",
    "full_scan": "Full Infrastructure Scan Report",
    "rbi_submission": "RBI Crypto Governance Report",
    "cbom_audit": "CBOM Audit Package",
    "migration_progress": "PQC Migration Progress Report",
    "pqc_migration_plan": "PQC Migration Plan",
}

TEMPLATE_BY_TYPE = {
    "executive": "executive.html",
    "cbom_audit": "cbom_audit.html",
    "rbi_submission": "rbi_submission.html",
    "migration_progress": "migration_progress.html",
    "full_scan": "full_scan.html",
    "pqc_migration_plan": "pqc_migration_plan.html",
}


class ReportGenerator:

    def __init__(self, db: Session, user: User):
        self.db = db
        self.user = user
        try:
            self.ai = get_ai_provider(user)
        except AIConfigurationError as e:
            logger.warning(f"AI provider unavailable: {e}")
            self.ai = None
        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))

    # ──────────────────────────────────────────────────────────────────────────
    # Public entry points
    # ──────────────────────────────────────────────────────────────────────────

    def generate_report(self, scan_id: str, report_type: str,
                        format: str = "pdf", password: str = None) -> bytes:
        if report_type not in TEMPLATE_BY_TYPE:
            raise ValueError(f"Unsupported report type '{report_type}'")

        scan_job = self.db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan_job or str(scan_job.user_id) != str(self.user.id):
            raise ValueError("Scan not found or unauthorized")

        dataset = self._build_dataset(scan_job)

        try:
            from app.services.chart_generator import ChartGenerator
            cg = ChartGenerator(self.db, scan_job)
            dataset["charts"] = cg.generate_all()
        except Exception as e:
            logger.warning(f"Chart generation failed: {e}")
            dataset["charts"] = {}

        dataset["ai"] = self._generate_ai_sections(report_type, dataset)

        if format == "json":
            import json
            safe = {k: v for k, v in dataset.items() if k != "charts"}
            return json.dumps(safe, default=str).encode("utf-8")

        if format == "csv":
            import csv
            output = io.StringIO()
            assets = dataset.get("assets", [])
            if assets:
                writer = csv.DictWriter(output, fieldnames=assets[0].keys())
                writer.writeheader()
                writer.writerows(assets)
            else:
                output.write("No assets found.")
            return output.getvalue().encode("utf-8")

        template = self.jinja_env.get_template(TEMPLATE_BY_TYPE[report_type])
        html_content = template.render(**dataset)
        output_bytes = self._to_pdf_or_html(html_content, format)

        if format == "pdf" and password:
            output_bytes = self._encrypt_pdf(output_bytes, password)

        self._save_report(scan_job, report_type, format, output_bytes, dataset)
        return output_bytes

    def get_chart_data(self, scan_id: str) -> Dict[str, Any]:
        scan_job = self.db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan_job or str(scan_job.user_id) != str(self.user.id):
            raise ValueError("Scan not found or unauthorized")
        dataset = self._build_dataset(scan_job)
        return {
            "risk_counts": dataset["risk_counts"],
            "top_algorithms": dataset["top_algorithms"],
            "stats": dataset["stats"],
            "assets": dataset["assets"][:50],
        }

    # ──────────────────────────────────────────────────────────────────────────
    # PDF / HTML output
    # ──────────────────────────────────────────────────────────────────────────

    def _to_pdf_or_html(self, html_content: str, fmt: str = "pdf") -> bytes:
        if fmt == "html":
            return html_content.encode("utf-8")
        if HTML:
            return HTML(string=html_content).write_pdf()
        logger.warning("WeasyPrint missing — returning raw HTML.")
        return html_content.encode("utf-8")

    def _encrypt_pdf(self, pdf_bytes: bytes, password: str) -> bytes:
        try:
            from PyPDF2 import PdfReader, PdfWriter
            reader = PdfReader(io.BytesIO(pdf_bytes))
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.encrypt(user_password=password, owner_password=password, use_128bit=True)
            out = io.BytesIO()
            writer.write(out)
            return out.getvalue()
        except ImportError:
            logger.warning("PyPDF2 not installed — skipping encryption.")
            return pdf_bytes

    # ──────────────────────────────────────────────────────────────────────────
    # Dataset builder
    # ──────────────────────────────────────────────────────────────────────────

    def _build_dataset(self, scan_job: ScanJob) -> Dict[str, Any]:
        sid = scan_job.id
        assets = self.db.query(Asset).filter(Asset.scan_id == sid).all()
        risks = self.db.query(RiskScore).filter(RiskScore.scan_id == sid).all()
        compliance = self.db.query(ComplianceResult).filter(ComplianceResult.scan_id == sid).all()
        cbom_records = self.db.query(CBOMRecord).filter(CBOMRecord.scan_id == sid).all()
        cbom_components = self.db.query(CBOMComponent).filter(CBOMComponent.scan_id == sid).all()
        certs = self.db.query(Certificate).filter(Certificate.scan_id == sid).all()

        asset_by_id = {str(a.id): a for a in assets}
        risk_by_asset = {str(r.asset_id): r for r in risks}
        compliance_by_asset = {str(c.asset_id): c for c in compliance}
        cbom_by_asset = {str(c.asset_id): c for c in cbom_records}

        critical_assets, scored_assets = [], []
        risk_counts: Dict[str, int] = {}
        sum_readiness = 0.0

        for risk in risks:
            rc = risk.risk_classification or "unknown"
            risk_counts[rc] = risk_counts.get(rc, 0) + 1
            sum_readiness += max(0, 10 - (risk.quantum_risk_score or 0) / 100)
            if rc in ("quantum_critical", "quantum_vulnerable"):
                asset = asset_by_id.get(str(risk.asset_id))
                if asset:
                    # Collect risk factors for detail
                    factors = self.db.query(RiskFactor).filter(RiskFactor.risk_score_id == risk.id).all()
                    factor_list = [f"{f.factor_name}: {f.factor_score:.0f}" for f in factors]
                    critical_assets.append({
                        "hostname": asset.hostname,
                        "ip_address": asset.ip_v4 or "N/A",
                        "asset_type": asset.asset_type or "unknown",
                        "tls_version": asset.tls_version or "N/A",
                        "risk_score": risk.quantum_risk_score or 0,
                        "classification": rc.replace("quantum_", "").upper(),
                        "hndl_exposed": bool(risk.hndl_exposed),
                        "tnfl_risk": bool(risk.tnfl_risk),
                        "mosca_x": round(risk.mosca_x or 0, 1),
                        "mosca_y": round(risk.mosca_y or 0, 1),
                        "weakness": "; ".join(factor_list) if factor_list else f"Risk score {risk.quantum_risk_score or 0}/1000",
                        "hosting_provider": asset.hosting_provider or "N/A",
                        "is_third_party": bool(asset.is_third_party),
                        "third_party_vendor": asset.third_party_vendor or "",
                    })

        for asset in assets:
            aid = str(asset.id)
            risk = risk_by_asset.get(aid)
            comp = compliance_by_asset.get(aid)
            cbom = cbom_by_asset.get(aid)
            scored_assets.append({
                "hostname": asset.hostname,
                "asset_type": asset.asset_type or "unknown",
                "ip_address": asset.ip_v4 or "N/A",
                "tls_version": asset.tls_version or "N/A",
                "risk_score": risk.quantum_risk_score if risk else 0,
                "risk_classification": (risk.risk_classification or "unknown").replace("quantum_", ""),
                "hndl_exposed": bool(risk.hndl_exposed) if risk else False,
                "tnfl_risk": bool(risk.tnfl_risk) if risk else False,
                "crypto_agility_score": comp.crypto_agility_score if comp else 0,
                "rbi_compliant": bool(comp.rbi_compliant) if comp else False,
                "sebi_compliant": bool(comp.sebi_compliant) if comp else False,
                "pci_compliant": bool(comp.pci_compliant) if comp else False,
                "tls_13_enforced": bool(comp.tls_13_enforced) if comp else False,
                "fips_203_deployed": bool(comp.fips_203_deployed) if comp else False,
                "fips_204_deployed": bool(comp.fips_204_deployed) if comp else False,
                "hybrid_mode": bool(comp.hybrid_mode_active) if comp else False,
                "cbom_components": cbom.total_components if cbom else 0,
                "cbom_ready_pct": round(cbom.quantum_ready_pct or 0, 1) if cbom else 0.0,
                "is_third_party": bool(asset.is_third_party),
                "third_party_vendor": asset.third_party_vendor or "",
                "hosting_provider": asset.hosting_provider or "",
            })

        # Algorithm distribution from CBOM
        algo_dist: Dict[str, Dict] = {}
        vulnerable_components = 0
        for comp_item in cbom_components:
            name = comp_item.name or "Unknown"
            if name not in algo_dist:
                algo_dist[name] = {"count": 0, "vulnerable": bool(comp_item.is_quantum_vulnerable),
                                   "nist_level": comp_item.nist_quantum_level,
                                   "component_type": comp_item.component_type or ""}
            algo_dist[name]["count"] += 1
            if comp_item.is_quantum_vulnerable:
                vulnerable_components += 1

        top_algorithms = sorted(
            [{"name": k, **v} for k, v in algo_dist.items()],
            key=lambda r: r["count"], reverse=True
        )[:20]

        # Certificate summary
        cert_summary = []
        for cert in certs[:50]:
            cert_summary.append({
                "common_name": cert.common_name or "N/A",
                "issuer": cert.issuer or "N/A",
                "algorithm": cert.signature_algorithm or "N/A",
                "key_type": cert.key_type or "N/A",
                "key_length": cert.key_length or 0,
                "valid_to": cert.valid_to.strftime("%Y-%m-%d") if cert.valid_to else "N/A",
                "is_quantum_vulnerable": bool(cert.is_quantum_vulnerable),
                "tls_version": cert.tls_version or "N/A",
                "forward_secrecy": bool(cert.forward_secrecy),
            })

        # Third-party vendor summary
        third_party_assets = [a for a in scored_assets if a["is_third_party"]]
        vendor_risk: Dict[str, Dict] = {}
        for a in third_party_assets:
            vendor = a["third_party_vendor"] or a["hosting_provider"] or "Unknown"
            if vendor not in vendor_risk:
                vendor_risk[vendor] = {"count": 0, "risk_sum": 0, "hndl": 0}
            vendor_risk[vendor]["count"] += 1
            vendor_risk[vendor]["risk_sum"] += a["risk_score"]
            if a["hndl_exposed"]:
                vendor_risk[vendor]["hndl"] += 1
        vendor_summary = sorted([
            {"vendor": k, "assets": v["count"],
             "avg_risk": round(v["risk_sum"] / max(v["count"], 1)),
             "hndl_assets": v["hndl"]}
            for k, v in vendor_risk.items()
        ], key=lambda x: x["avg_risk"], reverse=True)

        # Summary stats
        n_risks = len(risks) or 1
        n_comp = len(compliance) or 1
        hndl_count = sum(1 for r in risks if r.hndl_exposed)
        stats = {
            "total": len(assets),
            "critical_count": sum(1 for r in risks if (r.risk_classification or "") == "quantum_critical"),
            "vulnerable_count": sum(1 for r in risks if (r.risk_classification or "") == "quantum_vulnerable"),
            "high_count": len(critical_assets),
            "hndl_count": hndl_count,
            "hndl_pct": round(hndl_count / n_risks * 100, 1),
            "avg_readiness": round(sum_readiness / n_risks, 1),
            "avg_compliance_pct": round(sum((c.compliance_pct or 0) for c in compliance) / n_comp, 1),
            "avg_crypto_agility": round(sum((c.crypto_agility_score or 0) for c in compliance) / n_comp, 1),
            "total_cbom_components": len(cbom_components),
            "vulnerable_cbom_components": vulnerable_components,
            "quantum_ready_pct": round((len(cbom_components) - vulnerable_components) / max(len(cbom_components), 1) * 100, 1),
            "rbi_compliant_assets": sum(1 for c in compliance if c.rbi_compliant),
            "sebi_compliant_assets": sum(1 for c in compliance if c.sebi_compliant),
            "pci_compliant_assets": sum(1 for c in compliance if c.pci_compliant),
            "tls_13_assets": sum(1 for c in compliance if c.tls_13_enforced),
            "hybrid_assets": sum(1 for c in compliance if c.hybrid_mode_active),
            "fips_203_assets": sum(1 for c in compliance if c.fips_203_deployed),
            "fips_204_assets": sum(1 for c in compliance if c.fips_204_deployed),
            "fips_205_assets": sum(1 for c in compliance if c.fips_205_deployed),
            "third_party_count": len(third_party_assets),
            "total_certs": len(certs),
            "vulnerable_certs": sum(1 for c in certs if c.is_quantum_vulnerable),
        }

        gen_date = datetime.now(timezone.utc)
        return {
            "report_title": "",  # filled per-type in AI sections
            "scan_id": str(sid),
            "scan_type": getattr(scan_job, "scan_type", "deep"),
            "scan_status": scan_job.status,
            "targets": scan_job.targets or [],
            "generation_date": gen_date.strftime("%Y-%m-%d %H:%M UTC"),
            "generation_date_long": gen_date.strftime("%B %d, %Y at %H:%M UTC"),
            "completed_at": scan_job.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan_job.completed_at else "N/A",
            "stats": stats,
            "risk_counts": risk_counts,
            "critical_assets": sorted(critical_assets, key=lambda r: r["risk_score"], reverse=True),
            "assets": sorted(scored_assets, key=lambda r: r["risk_score"], reverse=True),
            "top_algorithms": top_algorithms,
            "cert_summary": cert_summary,
            "vendor_summary": vendor_summary,
            "compliance_list": compliance,
            "charts": {},
            "ai": {},
        }

    # ──────────────────────────────────────────────────────────────────────────
    # AI section generation (deterministic structured prompts)
    # ──────────────────────────────────────────────────────────────────────────

    def _ai_generate(self, prompt: str, system: str, fallback: str = "") -> str:
        if not self.ai:
            return fallback or "AI generation unavailable — configure GROQ_API_KEY."
        try:
            return self.ai.generate(prompt=prompt, system=system, temperature=0.2)
        except Exception as e:
            logger.warning(f"AI section generation failed: {e}")
            return fallback or "Content generation temporarily unavailable."

    def _ctx(self, dataset: Dict[str, Any]) -> str:
        s = dataset["stats"]
        targets = ", ".join(dataset.get("targets", []))
        top_algo_str = ", ".join(a["name"] for a in dataset.get("top_algorithms", [])[:8])
        crits = dataset["critical_assets"][:5]
        crit_str = "\n".join(
            f"  - {a['hostname']} ({a['asset_type']}, score {a['risk_score']}/1000, HNDL={'YES' if a['hndl_exposed'] else 'NO'})"
            for a in crits
        )
        return (
            f"Organization targets: {targets}\n"
            f"Total assets scanned: {s['total']} | Critical: {s['critical_count']} | Vulnerable: {s['vulnerable_count']}\n"
            f"HNDL-exposed assets: {s['hndl_count']} ({s['hndl_pct']}%)\n"
            f"Avg quantum readiness: {s['avg_readiness']}/10 | Avg compliance: {s['avg_compliance_pct']}%\n"
            f"Avg crypto agility: {s['avg_crypto_agility']}/100\n"
            f"TLS 1.3 enforced: {s['tls_13_assets']}/{s['total']} assets\n"
            f"FIPS-203(ML-KEM): {s['fips_203_assets']} | FIPS-204(ML-DSA): {s['fips_204_assets']} | Hybrid mode: {s['hybrid_assets']}\n"
            f"RBI compliant: {s['rbi_compliant_assets']} | SEBI compliant: {s['sebi_compliant_assets']} | PCI: {s['pci_compliant_assets']}\n"
            f"CBOM: {s['total_cbom_components']} components, {s['vulnerable_cbom_components']} quantum-vulnerable ({s['quantum_ready_pct']}% ready)\n"
            f"Top algorithms in use: {top_algo_str}\n"
            f"Top 5 critical assets:\n{crit_str}\n"
            f"Third-party vendors: {s['third_party_count']} assets from external providers\n"
        )

    def _generate_ai_sections(self, report_type: str, dataset: Dict[str, Any]) -> Dict[str, str]:
        ctx = self._ctx(dataset)
        SYS = "You are a senior Quantum Security Architect and compliance expert for Indian banking infrastructure. Be precise, technical, and actionable. Use specific numbers from the data provided. Do not repeat the data — provide expert analysis, implications, and specific recommendations."

        if report_type == "executive":
            return {
                "board_summary": self._ai_generate(
                    f"DATA:\n{ctx}\n\nWrite a board-level executive summary (3 paragraphs) of the organization's quantum security posture. Cover: (1) overall quantum risk severity and urgency, (2) the most critical exposures and their business impact, (3) strategic priorities for the next 90 days. Use C-suite language — no jargon, but be specific with numbers.", SYS),
                "risk_posture": self._ai_generate(
                    f"DATA:\n{ctx}\n\nAnalyze the current quantum risk posture in depth. Explain: what the risk scores mean in practice, which assets are most exposed to 'Harvest Now Decrypt Later' attacks today, and how the Mosca inequality applies. Quantify the urgency.", SYS),
                "top_threats": self._ai_generate(
                    f"DATA:\n{ctx}\n\nIdentify and rank the top 5 quantum threats facing this organization right now. For each: name the threat, which assets are affected, what the attacker could do, and the regulatory consequence under RBI/SEBI frameworks.", SYS),
                "immediate_actions": self._ai_generate(
                    f"DATA:\n{ctx}\n\nProvide 7 specific, immediately actionable steps the CISO must take within the next 30 days to reduce quantum risk. Be precise — name specific algorithms to disable, specific systems to prioritize, and specific vendors to contact.", SYS),
                "roadmap_90d": self._ai_generate(
                    f"DATA:\n{ctx}\n\nCreate a detailed 90-day post-quantum migration quick-win roadmap. Organize by week-by-week milestones. Focus on highest-impact, lowest-complexity actions first.", SYS),
            }

        elif report_type == "full_scan":
            return {
                "infra_overview": self._ai_generate(
                    f"DATA:\n{ctx}\n\nProvide a comprehensive technical overview of the scanned infrastructure from a quantum cryptography perspective. Describe the asset landscape, diversity of cryptographic exposure, and overall attack surface.", SYS),
                "tls_findings": self._ai_generate(
                    f"DATA:\n{ctx}\n\nAnalyze all TLS-related findings in depth. Cover: TLS version distribution problems, cipher suite vulnerabilities, key exchange algorithm weaknesses, and which endpoints are highest priority for ML-KEM migration.", SYS),
                "cert_findings": self._ai_generate(
                    f"DATA:\n{ctx}\n\nAnalyze the certificate infrastructure findings. Cover: quantum-vulnerable signing algorithms in certificates, certificate expiry risks, CA chain weaknesses, and the PQC certificate migration path.", SYS),
                "shadow_assets": self._ai_generate(
                    f"DATA:\n{ctx}\n\nAnalyze any shadow assets, unknown hosts, or unmanaged infrastructure discovered. Discuss the quantum security implications of unmanaged assets in the attack surface.", SYS),
                "third_party_risk": self._ai_generate(
                    f"DATA:\n{ctx}\n\nAnalyze third-party and vendor quantum risk. For each major third-party provider identified, assess their PQC readiness, the data flows at risk, and recommended contractual/technical mitigations.", SYS),
                "technical_recommendations": self._ai_generate(
                    f"DATA:\n{ctx}\n\nProvide a prioritized technical remediation plan with specific steps for each vulnerability category. Include: exact algorithm replacements, library versions, configuration changes, and testing procedures.", SYS),
            }

        elif report_type == "rbi_submission":
            return {
                "compliance_status": self._ai_generate(
                    f"DATA:\n{ctx}\n\nProvide a formal compliance status narrative for RBI IT Framework 2023 submission. Cover each major requirement: CBOM inventory, quantum risk assessment, TLS standards, certificate management, and third-party risk. Use regulatory language appropriate for RBI submission.", SYS),
                "fips_gap_analysis": self._ai_generate(
                    f"DATA:\n{ctx}\n\nConduct a detailed gap analysis against FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) requirements. For each standard: current state, gap identified, remediation plan, and target completion date.", SYS),
                "npci_sebi_pci": self._ai_generate(
                    f"DATA:\n{ctx}\n\nAnalyze compliance status against NPCI UPI cryptographic requirements, SEBI CSCRF cybersecurity framework, and PCI DSS 4.0 cryptographic controls. Identify specific gaps and required actions.", SYS),
                "remediation_plan": self._ai_generate(
                    f"DATA:\n{ctx}\n\nPrepare a formal remediation plan suitable for RBI submission. Include: prioritized list of non-compliant controls, remediation actions, responsible parties, timelines, and success criteria for each item.", SYS),
                "attestation": self._ai_generate(
                    f"DATA:\n{ctx}\n\nDraft an attestation narrative for the Board Risk Committee confirming the quantum risk assessment has been completed per RBI IT Framework 2023 requirements, summarizing the key findings and management's commitment to remediation.", SYS),
            }

        elif report_type == "cbom_audit":
            return {
                "cbom_summary": self._ai_generate(
                    f"DATA:\n{ctx}\n\nWrite an executive summary of the Cryptographic Bill of Materials (CBOM) audit. Cover: total cryptographic inventory, distribution of algorithm types, proportion quantum-vulnerable vs quantum-safe, and the overall cryptographic hygiene assessment.", SYS),
                "algorithm_analysis": self._ai_generate(
                    f"DATA:\n{ctx}\n\nConduct a detailed analysis of the quantum-vulnerable algorithms discovered. For each major vulnerable algorithm found: explain why it is vulnerable to quantum attack, which assets use it, the attack timeline under Mosca's inequality, and the recommended PQC replacement.", SYS),
                "key_exchange_findings": self._ai_generate(
                    f"DATA:\n{ctx}\n\nAnalyze the key exchange findings specifically. Focus on: which key exchange mechanisms are in use (RSA, ECDH, DH, X25519), their quantum vulnerability, HNDL exposure risk, and migration path to ML-KEM-768 or hybrid X25519MLKEM768.", SYS),
                "migration_priority": self._ai_generate(
                    f"DATA:\n{ctx}\n\nProvide a prioritized algorithm migration order. List each algorithm that needs replacement, its migration complexity (1-5), estimated effort in person-days, and the specific NIST FIPS replacement. Order from highest-impact/lowest-effort to lowest-impact/highest-effort.", SYS),
            }

        elif report_type == "migration_progress":
            s = dataset["stats"]
            return {
                "progress_summary": self._ai_generate(
                    f"DATA:\n{ctx}\n\nSummarize the current state of PQC migration progress. Based on the data, estimate what phase of migration this organization is in (Inventory/Prioritize/Migrate/Verify per PQCC framework) and what percentage of work is complete.", SYS),
                "phase_status": self._ai_generate(
                    f"DATA:\n{ctx}\n\nFor each PQCC migration phase (1: Inventory, 2: Prioritize, 3: Migrate, 4: Verify), assess the current completion status with specific evidence from the scan data. Identify what is done, what is in progress, and what is not started.", SYS),
                "blockers": self._ai_generate(
                    f"DATA:\n{ctx}\n\nIdentify the top migration blockers. What is preventing faster PQC adoption in this infrastructure? Include: technical blockers (legacy systems, library limitations), vendor blockers, process blockers, and resource constraints. Be specific.", SYS),
                "acceleration": self._ai_generate(
                    f"DATA:\n{ctx}\n\nRecommend specific actions to accelerate PQC migration. What are the highest-leverage interventions that would move the most assets from vulnerable to protected in the shortest time? Include quick wins that can be done in < 2 weeks.", SYS),
            }

        elif report_type == "pqc_migration_plan":
            return {
                "executive_summary": self._ai_generate(
                    f"DATA:\n{ctx}\n\nWrite a comprehensive executive summary for a PQC Migration Plan. Cover: the quantum threat timeline relevant to this organization, the business case for urgent migration, the scope of work required, and expected outcomes after full migration.", SYS),
                "provider_analysis": self._ai_generate(
                    f"DATA:\n{ctx}\n\nAnalyze the PQC readiness of external providers and infrastructure dependencies identified in the scan. For each major external dependency (cloud providers, CDNs, payment gateways, core banking vendors, database providers), assess their PQC readiness and the risk they pose. Reference known vendor PQC roadmaps.", SYS),
                "phase_1_inventory": self._ai_generate(
                    f"DATA:\n{ctx}\n\nDesign Phase 1 (Inventory & Discovery) of the PQC migration plan. Based on the scan findings, identify: what additional inventory work remains, any blind spots in current CBOM coverage, and specific steps to achieve complete cryptographic visibility. Include timeline and resource estimates.", SYS),
                "phase_2_prioritize": self._ai_generate(
                    f"DATA:\n{ctx}\n\nDesign Phase 2 (Prioritize & Plan) of the migration. Apply Mosca's inequality to the specific assets found. Define migration cohorts (Cohort A: 0-12 months, B: 12-24 months, C: 24-36 months) and assign each major asset to a cohort with justification.", SYS),
                "phase_3_migrate": self._ai_generate(
                    f"DATA:\n{ctx}\n\nDesign Phase 3 (Migrate) with specific technical implementation steps for this infrastructure. Include: exact algorithm selections per use case (key exchange: ML-KEM-768, signatures: ML-DSA-65 or SLH-DSA), TLS migration sequence, PKI migration steps, and hybrid transition strategy. Give specific library version and configuration guidance.", SYS),
                "phase_4_verify": self._ai_generate(
                    f"DATA:\n{ctx}\n\nDesign Phase 4 (Verify & Monitor). Define: what 'done' looks like for PQC migration of this infrastructure, specific verification tests to run, monitoring alerts to configure, compliance validation procedures for RBI/SEBI submission, and the ongoing crypto-agility maintenance program.", SYS),
                "vendor_recommendations": self._ai_generate(
                    f"DATA:\n{ctx}\n\nProvide specific, actionable recommendations for each major vendor/provider identified. For each: exact steps to request PQC migration timeline, contractual language to add, technical configurations to apply now, and fallback options if vendor is too slow.", SYS),
            }

        return {}

    # ──────────────────────────────────────────────────────────────────────────
    # Persistence
    # ──────────────────────────────────────────────────────────────────────────

    def _save_report(self, scan_job: ScanJob, report_type: str,
                     fmt: str, content: bytes, dataset: Dict[str, Any]) -> Optional[GeneratedReport]:
        try:
            reports_dir = settings.reports_dir_abs / str(self.user.id)
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"{report_type}_{str(scan_job.id)[:8]}_{ts}.{fmt}"
            file_path = reports_dir / filename
            file_path.write_bytes(content)
            size_kb = len(content) // 1024

            label = REPORT_LABELS.get(report_type, report_type.replace("_", " ").title())
            targets_str = ", ".join(scan_job.targets or [])
            record = GeneratedReport(
                user_id=self.user.id,
                scan_id=scan_job.id,
                report_type=report_type,
                format=fmt,
                title=f"{label} — {targets_str}",
                file_path=str(file_path),
                file_size_kb=size_kb,
                targets=targets_str,
            )
            self.db.add(record)
            self.db.commit()
            self.db.refresh(record)

            # Embed report summary into ChromaDB for AI assistant access
            self._embed_report_summary(record, dataset)
            return record
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return None

    def _embed_report_summary(self, record: GeneratedReport, dataset: Dict[str, Any]) -> None:
        try:
            from app.services.vector_store import VectorStore
            vs = VectorStore(self.user)
            s = dataset["stats"]
            summary = (
                f"Report: {record.title} | Type: {record.report_type} | Generated: {record.generated_at}\n"
                f"Targets: {record.targets}\n"
                f"Total assets: {s['total']} | Critical: {s['critical_count']} | HNDL exposed: {s['hndl_count']}\n"
                f"Avg readiness: {s['avg_readiness']}/10 | Compliance: {s['avg_compliance_pct']}% | Crypto agility: {s['avg_crypto_agility']}/100\n"
                f"CBOM: {s['total_cbom_components']} components, {s['quantum_ready_pct']}% quantum-ready\n"
                f"RBI compliant: {s['rbi_compliant_assets']}/{s['total']} assets"
            )
            vs.embed_and_store(
                texts=[summary],
                metadatas=[{"source": f"report_{record.id}", "report_type": record.report_type,
                            "scan_id": str(record.scan_id), "source_type": "generated_report"}],
                ids=[f"report_{record.id}"],
            )
        except Exception as e:
            logger.warning(f"Failed to embed report summary: {e}")
