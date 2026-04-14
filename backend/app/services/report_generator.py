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

        # Monte Carlo CRQC simulation summary
        crqc_sim = {"p5": 2029, "p50": 2032, "p95": 2039, "mean": 2032.0}
        cert_race_summary = {"safe": 0, "natural_rotation": 0, "at_risk": 0}
        try:
            from app.services.monte_carlo import simulate_crqc_arrival
            mc_result = simulate_crqc_arrival(n_simulations=10000, seed=42)
            crqc_sim = {
                "p5": mc_result["percentiles"]["p5"],
                "p50": mc_result["percentiles"]["p50"],
                "p95": mc_result["percentiles"]["p95"],
                "mean": mc_result["statistics"]["mean"],
            }
        except Exception:
            pass
        try:
            from app.services.risk_engine import compute_cert_crqc_race
            race = compute_cert_crqc_race(str(sid), self.db)
            cert_race_summary = {
                "safe": race.get("safe", 0),
                "natural_rotation": race.get("natural_rotation", 0),
                "at_risk": race.get("at_risk", 0),
                "pct_at_risk": round(race.get("pct_at_risk", 0) * 100, 1),
            }
        except Exception:
            pass

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
            "crqc_sim": crqc_sim,
            "cert_race": cert_race_summary,
            "charts": {},
            "ai": {},
        }

    # ──────────────────────────────────────────────────────────────────────────
    # AI section generation (deterministic structured prompts)
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _md_to_html(text: str) -> str:
        """Convert basic markdown to HTML for report rendering."""
        import re
        # Bold
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        # Italic
        text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
        # H3
        text = re.sub(r'^### (.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
        # H2
        text = re.sub(r'^## (.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
        # H1
        text = re.sub(r'^# (.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
        # Numbered list items
        text = re.sub(r'^\d+\.\s+(.+)$', r'<li>\1</li>', text, flags=re.MULTILINE)
        # Bullet list items
        text = re.sub(r'^[-•]\s+(.+)$', r'<li>\1</li>', text, flags=re.MULTILINE)
        # Wrap consecutive <li> in <ul>
        text = re.sub(r'(<li>.*?</li>)(\n<li>.*?</li>)*', lambda m: '<ul>' + m.group(0) + '</ul>', text, flags=re.DOTALL)
        # Paragraphs — blank lines become <p> breaks
        paragraphs = re.split(r'\n{2,}', text.strip())
        result = []
        for p in paragraphs:
            p = p.strip()
            if not p:
                continue
            if p.startswith('<h') or p.startswith('<ul>'):
                result.append(p)
            else:
                result.append(f'<p>{p}</p>')
        return '\n'.join(result)

    def _ai_generate(self, prompt: str, system: str, fallback: str = "") -> str:
        import time
        if not self.ai:
            return fallback or "<p>AI generation unavailable — configure GROQ_API_KEY.</p>"
        try:
            raw = self.ai.generate(prompt=prompt, system=system, temperature=0.2)
            return self._md_to_html(raw)
        except Exception as e:
            logger.warning(f"AI section generation failed: {e}")
            if fallback:
                return fallback
            return f"<p><em>AI analysis unavailable: {str(e)[:120]}</em></p>"

    def _ai_generate_with_delay(self, prompt: str, system: str, fallback: str = "") -> str:
        """Same as _ai_generate but adds a small delay after to avoid burst rate limiting."""
        import time
        result = self._ai_generate(prompt, system, fallback)
        time.sleep(1)
        return result

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

    def _fallback(self, section: str, dataset: Dict[str, Any]) -> str:
        """Generate a data-driven fallback when AI is unavailable."""
        s = dataset["stats"]
        targets = ", ".join(dataset.get("targets", []))
        algos = ", ".join(a["name"] for a in dataset.get("top_algorithms", [])[:5])
        crits = dataset.get("critical_assets", [])[:3]
        crit_names = ", ".join(a["hostname"] for a in crits) if crits else "none identified"

        fb = {
            "board_summary": (
                f"<p>This quantum risk assessment covers <strong>{s['total']} assets</strong> across {targets}. "
                f"<strong>{s['critical_count']} assets are classified Quantum Critical</strong> and {s['vulnerable_count']} are Quantum Vulnerable, "
                f"representing an immediate exposure to harvest-now-decrypt-later (HNDL) attacks. "
                f"{s['hndl_count']} assets ({s['hndl_pct']}%) are actively HNDL-exposed today.</p>"
                f"<p>Quantum readiness stands at <strong>{s['avg_readiness']}/10</strong> with an average compliance score of {s['avg_compliance_pct']}%. "
                f"Only {s['tls_13_assets']} of {s['total']} assets enforce TLS 1.3. "
                f"FIPS 203 (ML-KEM) is deployed on {s['fips_203_assets']} assets and FIPS 204 (ML-DSA) on {s['fips_204_assets']} assets.</p>"
                f"<p>Immediate strategic priorities: (1) migrate {s['hndl_count']} HNDL-exposed assets to ML-KEM-768 within 90 days, "
                f"(2) enforce TLS 1.3 across all {s['total'] - s['tls_13_assets']} non-compliant assets, "
                f"(3) complete CBOM remediation for {s['vulnerable_cbom_components']} quantum-vulnerable cryptographic components.</p>"
            ),
            "risk_posture": (
                f"<p>The CBOM inventory contains <strong>{s['total_cbom_components']} cryptographic components</strong>, "
                f"of which <strong>{s['vulnerable_cbom_components']} ({100 - s['quantum_ready_pct']:.0f}%) are quantum-vulnerable</strong>. "
                f"The most prevalent vulnerable algorithms are: {algos}. "
                f"These are susceptible to Shor's algorithm on a sufficiently large quantum computer.</p>"
                f"<p>Under Mosca's inequality, with a CRQC estimated to arrive within 10–15 years and data sensitivity lifespans of 5–10 years, "
                f"migration must begin immediately for the {s['hndl_count']} HNDL-exposed assets. "
                f"Most at risk: {crit_names}.</p>"
                f"<p>Crypto agility average is <strong>{s['avg_crypto_agility']}/100</strong>. "
                f"Hybrid PQC (X25519MLKEM768) is active on {s['hybrid_assets']} assets, providing partial protection.</p>"
            ),
            "top_threats": (
                f"<ul>"
                f"<li><strong>HNDL Exposure:</strong> {s['hndl_count']} assets transmit encrypted data vulnerable to harvest-now-decrypt-later attacks today.</li>"
                f"<li><strong>Quantum-Vulnerable Key Exchange:</strong> RSA/ECDH key exchange on {s['total'] - s['fips_203_assets']} assets will be broken by a CRQC.</li>"
                f"<li><strong>Weak Certificate Signing:</strong> {s['vulnerable_certs']} of {s['total_certs']} certificates use quantum-vulnerable signature algorithms.</li>"
                f"<li><strong>TLS Downgrade Risk:</strong> {s['total'] - s['tls_13_assets']} assets do not enforce TLS 1.3, enabling legacy cipher exploitation.</li>"
                f"<li><strong>Third-Party Exposure:</strong> {s['third_party_count']} assets depend on third-party providers whose PQC readiness is unconfirmed.</li>"
                f"</ul>"
            ),
            "immediate_actions": (
                f"<ul>"
                f"<li>Prioritise migration of {s['hndl_count']} HNDL-exposed assets to ML-KEM-768 key exchange within 30 days.</li>"
                f"<li>Enforce TLS 1.3 minimum on all {s['total'] - s['tls_13_assets']} non-compliant assets — disable TLS 1.2 fallback.</li>"
                f"<li>Replace quantum-vulnerable algorithms ({algos}) with NIST FIPS 203/204/205 alternatives.</li>"
                f"<li>Issue PQC migration timeline requests to all {s['third_party_count']} third-party vendors.</li>"
                f"<li>Enable hybrid PQC (X25519MLKEM768) on all internet-facing endpoints immediately.</li>"
                f"<li>Renew {s['vulnerable_certs']} quantum-vulnerable certificates with ML-DSA-65 or hybrid certificates.</li>"
                f"<li>Engage RBI/SEBI reporting on current compliance gap — {s['total'] - s['rbi_compliant_assets']} assets non-compliant with RBI IT Framework 2023.</li>"
                f"</ul>"
            ),
            "roadmap_90d": (
                f"<p><strong>Weeks 1–2:</strong> Complete CBOM gap analysis, identify all {s['vulnerable_cbom_components']} vulnerable components, assign owners.</p>"
                f"<p><strong>Weeks 3–4:</strong> Enable TLS 1.3 enforcement on all {s['total'] - s['tls_13_assets']} non-compliant assets.</p>"
                f"<p><strong>Weeks 5–6:</strong> Deploy hybrid PQC (X25519MLKEM768) on all {s['hndl_count']} HNDL-exposed internet-facing assets.</p>"
                f"<p><strong>Weeks 7–8:</strong> Renew top {min(s['vulnerable_certs'], 20)} quantum-vulnerable certificates with PQC-hybrid certificates.</p>"
                f"<p><strong>Weeks 9–10:</strong> Vendor engagement — send PQC timeline requests, review responses, escalate laggards.</p>"
                f"<p><strong>Weeks 11–12:</strong> Validate all changes, update CBOM records, prepare RBI IT Framework 2023 compliance report.</p>"
            ),
            "infra_overview": (
                f"<p>The scan covered <strong>{s['total']} assets</strong> across {targets}. "
                f"Of these, {s['critical_count']} are Quantum Critical, {s['vulnerable_count']} are Quantum Vulnerable, "
                f"and {s['hndl_count']} are actively exposed to HNDL attacks.</p>"
                f"<p>The cryptographic landscape includes {s['total_cbom_components']} components, "
                f"with {s['quantum_ready_pct']}% quantum-ready. "
                f"TLS 1.3 is enforced on {s['tls_13_assets']}/{s['total']} assets. "
                f"Third-party infrastructure accounts for {s['third_party_count']} assets.</p>"
            ),
            "tls_findings": (
                f"<p>TLS 1.3 is enforced on <strong>{s['tls_13_assets']} of {s['total']} assets ({round(s['tls_13_assets']/(s['total'] or 1)*100,1)}%)</strong>. "
                f"The remaining {s['total'] - s['tls_13_assets']} assets use TLS 1.2 or older, which permits cipher suites with quantum-vulnerable key exchange (RSA, ECDHE).</p>"
                f"<p>Key exchange migration priority: all {s['hndl_count']} HNDL-exposed endpoints must transition to ML-KEM-768 or X25519MLKEM768 hybrid immediately. "
                f"Hybrid mode is already active on {s['hybrid_assets']} assets, which provides forward secrecy against quantum adversaries.</p>"
                f"<p><strong>Recommended actions:</strong> Disable TLS 1.2 on all public endpoints; configure TLS 1.3 with X25519MLKEM768 as the preferred key exchange group; "
                f"monitor for TLS negotiation fallbacks using your WAF or load balancer logs.</p>"
            ),
            "cert_findings": (
                f"<p>Of <strong>{s['total_certs']} certificates</strong> scanned, "
                f"<strong>{s['vulnerable_certs']} ({round(s['vulnerable_certs']/(s['total_certs'] or 1)*100,1)}%) use quantum-vulnerable signature algorithms</strong> "
                f"(RSA-2048/4096, ECDSA P-256/P-384). These certificates will be forgeable by a CRQC.</p>"
                f"<p>Certificate migration path: transition to hybrid certificates combining classical ECDSA P-256 with ML-DSA-65 (per IETF draft-ounsworth-pq-composite-sigs). "
                f"Begin with externally-visible certificates; internal PKI can follow in Phase 3.</p>"
                f"<p><strong>Priority certificates to replace:</strong> renew the {min(s['vulnerable_certs'], 10)} shortest-lived quantum-vulnerable certificates first, "
                f"as they will require renewal soonest and can adopt PQC signing at that time.</p>"
            ),
            "shadow_assets": (
                f"<p>The scan identified <strong>{s['total']} assets</strong> in scope. "
                f"Any assets not appearing in your internal CMDB represent shadow infrastructure — "
                f"unmanaged assets are particularly dangerous as they receive no cryptographic updates.</p>"
                f"<p>Cross-reference these {s['total']} discovered assets against your CMDB. "
                f"Any discrepancies should be investigated immediately — shadow assets often run outdated TLS stacks with no monitoring.</p>"
                f"<p><strong>Action:</strong> Implement continuous asset discovery (re-run QuShield scans weekly) to detect new assets before they accumulate cryptographic debt.</p>"
            ),
            "third_party_risk": (
                f"<p><strong>{s['third_party_count']} assets</strong> are hosted or managed by third-party providers. "
                f"These represent supply-chain quantum risk — even if your own infrastructure migrates, "
                f"data flowing through non-PQC-ready vendors remains harvestable.</p>"
                f"<p><strong>Recommended actions:</strong></p>"
                f"<ul>"
                f"<li>Request formal PQC migration timelines from all {s['third_party_count']} external providers within 30 days.</li>"
                f"<li>Add PQC migration obligations to vendor contracts at next renewal.</li>"
                f"<li>For vendors with no roadmap, evaluate alternatives or deploy application-layer encryption (PQC TLS wrapper) as interim mitigation.</li>"
                f"</ul>"
            ),
            "technical_recommendations": (
                f"<ul>"
                f"<li><strong>Key Exchange:</strong> Deploy ML-KEM-768 (FIPS 203) or X25519MLKEM768 hybrid on all TLS endpoints. "
                f"Priority: {s['hndl_count']} HNDL-exposed assets. Library: OpenSSL 3.5+, BoringSSL, or liboqs 0.10+.</li>"
                f"<li><strong>Signatures:</strong> Replace RSA/ECDSA with ML-DSA-65 (FIPS 204) for code signing, auth tokens, and certificates. "
                f"Use SLH-DSA (FIPS 205) for long-term document signing.</li>"
                f"<li><strong>TLS Configuration:</strong> Set minimum TLS 1.3, preferred cipher TLS_AES_256_GCM_SHA384, "
                f"key share X25519MLKEM768. Disable TLS_RSA_* suites immediately.</li>"
                f"<li><strong>Certificates:</strong> Renew {s['vulnerable_certs']} quantum-vulnerable certificates using composite PQC certificates "
                f"(classical + ML-DSA-65) from a PQC-capable CA (DigiCert, Entrust, or self-hosted via CFSSL with liboqs patch).</li>"
                f"<li><strong>CBOM:</strong> Update {s['vulnerable_cbom_components']} vulnerable component records after migration; "
                f"integrate CBOM generation into CI/CD pipeline using CycloneDX.</li>"
                f"</ul>"
            ),
            "compliance_status": (
                f"<p>As of this assessment, <strong>{s['rbi_compliant_assets']} of {s['total']} assets ({round(s['rbi_compliant_assets']/(s['total'] or 1)*100,1)}%) "
                f"are compliant with RBI IT Framework 2023</strong> cryptographic requirements. "
                f"SEBI CSCRF compliance stands at {s['sebi_compliant_assets']}/{s['total']} assets. "
                f"PCI DSS 4.0 (Req 4.2.1) compliance: {s['pci_compliant_assets']}/{s['total']} assets.</p>"
                f"<p>A full quantum risk assessment has been completed covering {s['total']} assets, "
                f"{s['total_cbom_components']} CBOM components, and {s['total_certs']} TLS certificates, "
                f"meeting RBI IT Framework 2023 Section 4.2 (Quantum Risk Assessment) requirements.</p>"
                f"<p>Key gaps: TLS 1.3 enforcement ({s['tls_13_assets']}/{s['total']} compliant), "
                f"FIPS 203 deployment ({s['fips_203_assets']}/{s['total']}), "
                f"FIPS 204 deployment ({s['fips_204_assets']}/{s['total']}). "
                f"Remediation timelines are provided in Section 6.</p>"
            ),
            "fips_gap_analysis": (
                f"<p><strong>FIPS 203 (ML-KEM):</strong> Deployed on {s['fips_203_assets']}/{s['total']} assets. "
                f"Gap: {s['total'] - s['fips_203_assets']} assets require ML-KEM-768 key exchange deployment. "
                f"Target completion: 12 months.</p>"
                f"<p><strong>FIPS 204 (ML-DSA):</strong> Deployed on {s['fips_204_assets']}/{s['total']} assets. "
                f"Gap: {s['total'] - s['fips_204_assets']} assets require ML-DSA-65 signature deployment. "
                f"Target completion: 18 months.</p>"
                f"<p><strong>FIPS 205 (SLH-DSA):</strong> Deployed on {s['fips_205_assets']}/{s['total']} assets. "
                f"Required for long-term document and code signing. Target completion: 24 months.</p>"
            ),
            "npci_sebi_pci": (
                f"<p><strong>NPCI UPI (mTLS):</strong> All UPI-connected endpoints must enforce mutual TLS with quantum-safe key exchange. "
                f"Current status: {s['hybrid_assets']} assets have hybrid PQC active.</p>"
                f"<p><strong>SEBI CSCRF:</strong> {s['sebi_compliant_assets']}/{s['total']} assets meet SEBI cybersecurity framework requirements. "
                f"Gap areas: cryptographic agility score averages {s['avg_crypto_agility']}/100 (target: 75+).</p>"
                f"<p><strong>PCI DSS 4.0 (Req 4.2.1):</strong> {s['pci_compliant_assets']}/{s['total']} assets compliant. "
                f"All cardholder data environments must enforce TLS 1.2+ (TLS 1.3 strongly recommended) and forward secrecy.</p>"
            ),
            "remediation_plan": (
                f"<ul>"
                f"<li><strong>P1 (0–90 days):</strong> Migrate {s['hndl_count']} HNDL-exposed assets to ML-KEM-768. Owner: CISO. Cost: medium.</li>"
                f"<li><strong>P1 (0–90 days):</strong> Enforce TLS 1.3 on {s['total'] - s['tls_13_assets']} non-compliant assets. Owner: Infrastructure team.</li>"
                f"<li><strong>P2 (90–180 days):</strong> Replace {s['vulnerable_certs']} quantum-vulnerable certificates. Owner: PKI team.</li>"
                f"<li><strong>P2 (90–180 days):</strong> Deploy ML-DSA-65 on authentication services. Owner: Application teams.</li>"
                f"<li><strong>P3 (180–365 days):</strong> Complete CBOM remediation for {s['vulnerable_cbom_components']} vulnerable components. Owner: Development leads.</li>"
                f"<li><strong>P3 (180–365 days):</strong> Third-party vendor PQC certification. Owner: Procurement + Legal.</li>"
                f"</ul>"
            ),
            "attestation": (
                f"<p>This report certifies that a comprehensive quantum cryptographic risk assessment has been completed "
                f"for {targets} in accordance with RBI IT Framework 2023, Section 4.2. "
                f"The assessment covered {s['total']} assets, {s['total_cbom_components']} CBOM components, and {s['total_certs']} TLS certificates.</p>"
                f"<p>Key findings have been communicated to the Board Risk Committee. "
                f"A formal remediation plan is in place targeting full compliance within 365 days. "
                f"Management commits to quarterly progress reviews and immediate escalation of any material quantum risk events.</p>"
            ),
            "cbom_summary": (
                f"<p>The CBOM audit identified <strong>{s['total_cbom_components']} cryptographic components</strong> across {s['total']} assets. "
                f"Of these, <strong>{s['vulnerable_cbom_components']} ({100 - s['quantum_ready_pct']:.0f}%) are quantum-vulnerable</strong> — "
                f"susceptible to Shor's algorithm attacks by a cryptographically-relevant quantum computer.</p>"
                f"<p>Quantum-ready components: {s['total_cbom_components'] - s['vulnerable_cbom_components']} ({s['quantum_ready_pct']}%). "
                f"The most prevalent algorithms requiring replacement are: {algos}.</p>"
                f"<p>Crypto agility score averages <strong>{s['avg_crypto_agility']}/100</strong>. "
                f"A score below 50 indicates hardcoded cryptography that will require significant refactoring to migrate.</p>"
            ),
            "algorithm_analysis": (
                f"<p>The following quantum-vulnerable algorithms were identified and require replacement:</p>"
                f"<ul>"
                f"<li><strong>RSA (all key sizes):</strong> Broken by Shor's algorithm in polynomial time. Replace with ML-KEM-768 (key encapsulation) or ML-DSA-65 (signatures).</li>"
                f"<li><strong>ECDH/ECDSA (P-256, P-384):</strong> Vulnerable to quantum attack. Replace with ML-KEM-768 or hybrid X25519MLKEM768.</li>"
                f"<li><strong>DH/DHE:</strong> All Diffie-Hellman variants are broken by quantum computers. Migrate to ML-KEM immediately.</li>"
                f"</ul>"
                f"<p>Total vulnerable components: {s['vulnerable_cbom_components']}. "
                f"Under Mosca's inequality with CRQC arrival in 10–15 years, migration must begin now for any data with &gt;5 year sensitivity.</p>"
            ),
            "key_exchange_findings": (
                f"<p>Key exchange mechanisms in use include classical algorithms (RSA, ECDH, DHE) which are fully broken by Shor's algorithm. "
                f"Hybrid PQC (X25519MLKEM768) is active on <strong>{s['hybrid_assets']} assets</strong>, providing quantum-safe forward secrecy for those connections.</p>"
                f"<p><strong>HNDL risk:</strong> {s['hndl_count']} assets are actively transmitting data under quantum-vulnerable key exchange. "
                f"Any encrypted traffic captured today can be decrypted when a CRQC becomes available.</p>"
                f"<p><strong>Migration path:</strong> Deploy ML-KEM-768 (FIPS 203) as the primary key encapsulation mechanism. "
                f"Use X25519MLKEM768 hybrid during transition to maintain backwards compatibility. "
                f"Target: zero non-hybrid connections on internet-facing assets within 90 days.</p>"
            ),
            "migration_priority": (
                f"<p>Algorithm replacement priority order (highest impact, lowest effort first):</p>"
                f"<ul>"
                f"<li><strong>1. TLS Key Exchange (RSA/ECDH → ML-KEM-768):</strong> Complexity 2/5. "
                f"Affects {s['total'] - s['fips_203_assets']} assets. Effort: 2–4 person-days per server. Replace immediately.</li>"
                f"<li><strong>2. Certificate Signatures (RSA/ECDSA → ML-DSA-65):</strong> Complexity 3/5. "
                f"Affects {s['vulnerable_certs']} certificates. Effort: 1 person-day per certificate renewal cycle.</li>"
                f"<li><strong>3. Application-Layer Signatures → ML-DSA-65/SLH-DSA:</strong> Complexity 4/5. "
                f"Affects internal signing workflows. Effort: 5–15 person-days per application.</li>"
                f"<li><strong>4. Symmetric Key Derivation (HKDF → post-quantum KDF):</strong> Complexity 2/5. Low urgency.</li>"
                f"<li><strong>5. Legacy Protocol Removal (DH, RSA-OAEP):</strong> Complexity 3/5. "
                f"Requires dependency analysis before removal.</li>"
                f"</ul>"
            ),
            "progress_summary": (
                f"<p>Current PQC migration status: <strong>{s['quantum_ready_pct']}% of CBOM components are quantum-ready</strong>. "
                f"ML-KEM (FIPS 203) is deployed on {s['fips_203_assets']}/{s['total']} assets. "
                f"ML-DSA (FIPS 204) is deployed on {s['fips_204_assets']}/{s['total']} assets. "
                f"Hybrid mode is active on {s['hybrid_assets']} assets.</p>"
                f"<p>Based on the PQCC framework, this organisation is currently in <strong>Phase 2 (Prioritize & Plan)</strong>, "
                f"with Phase 1 (Inventory) substantially complete ({s['total_cbom_components']} components catalogued) "
                f"and Phase 3 (Migrate) beginning on {s['fips_203_assets'] + s['fips_204_assets']} assets.</p>"
            ),
            "phase_status": (
                f"<ul>"
                f"<li><strong>Phase 1 — Inventory:</strong> Complete. {s['total']} assets, {s['total_cbom_components']} CBOM components catalogued.</li>"
                f"<li><strong>Phase 2 — Prioritize:</strong> In progress. {s['critical_count']} critical assets identified; Mosca analysis applied; cohort assignment in progress.</li>"
                f"<li><strong>Phase 3 — Migrate:</strong> Started. {s['fips_203_assets']} assets have ML-KEM; {s['hybrid_assets']} have hybrid PQC. "
                f"{s['total'] - s['fips_203_assets']} assets remain to migrate.</li>"
                f"<li><strong>Phase 4 — Verify:</strong> Not started. Verification framework and monitoring to be established after Phase 3 completes.</li>"
                f"</ul>"
            ),
            "blockers": (
                f"<ul>"
                f"<li><strong>Vendor dependency:</strong> {s['third_party_count']} assets depend on third-party providers with unconfirmed PQC timelines.</li>"
                f"<li><strong>Legacy TLS stacks:</strong> {s['total'] - s['tls_13_assets']} assets use pre-TLS-1.3 stacks that may not support ML-KEM without library upgrades.</li>"
                f"<li><strong>Certificate authority lag:</strong> Many internal CAs do not yet issue ML-DSA certificates, blocking hybrid certificate rollout.</li>"
                f"<li><strong>Application hardcoding:</strong> Low average crypto agility score ({s['avg_crypto_agility']}/100) indicates hardcoded algorithms in applications requiring code changes.</li>"
                f"</ul>"
            ),
            "acceleration": (
                f"<ul>"
                f"<li><strong>Quick win (1 week):</strong> Enable X25519MLKEM768 hybrid in nginx/HAProxy config — zero code changes required, immediate HNDL protection on {s['hndl_count']} endpoints.</li>"
                f"<li><strong>Quick win (2 weeks):</strong> Force TLS 1.3 minimum on all load balancers — eliminates TLS 1.2 fallback risk.</li>"
                f"<li><strong>Medium term:</strong> Upgrade OpenSSL to 3.5+ across all servers — enables ML-KEM natively without additional libraries.</li>"
                f"<li><strong>Process fix:</strong> Add CBOM generation to CI/CD pipeline — ensures all new deployments are scanned before go-live.</li>"
                f"</ul>"
            ),
            "executive_summary": (
                f"<p>This PQC Migration Plan covers <strong>{s['total']} assets</strong> across {targets}. "
                f"The quantum threat timeline (CRQC arrival estimated 2030–2035) combined with a data sensitivity lifespan of 5+ years "
                f"requires migration to begin immediately for {s['hndl_count']} HNDL-exposed assets.</p>"
                f"<p>Current state: {s['quantum_ready_pct']}% quantum-ready ({s['total_cbom_components'] - s['vulnerable_cbom_components']} of {s['total_cbom_components']} CBOM components). "
                f"Full migration is estimated at 24–36 months at the current pace. "
                f"This plan accelerates that to 18 months through phased cohort migration.</p>"
                f"<p>Expected outcomes: 100% ML-KEM-768 key exchange, 100% ML-DSA-65 certificate signatures, "
                f"full RBI IT Framework 2023 compliance, and elimination of all HNDL exposure.</p>"
            ),
            "provider_analysis": (
                f"<p><strong>{s['third_party_count']} assets</strong> are managed by third-party providers. "
                f"Each provider introduces supply-chain quantum risk — traffic through non-PQC providers is harvestable regardless of your own migration status.</p>"
                f"<p><strong>Recommended actions per provider:</strong></p>"
                f"<ul>"
                f"<li>AWS/Azure/GCP: All major clouds have ML-KEM support in preview — enable via TLS policy configuration.</li>"
                f"<li>CDN providers (Cloudflare, Akamai): Both support hybrid PQC TLS — enable X25519MLKEM768 in settings.</li>"
                f"<li>Payment gateways: Request formal PQC migration commitment with SLA. Escalate if no timeline provided within 30 days.</li>"
                f"<li>Core banking vendors: Engage vendors immediately — these have the longest migration cycles (12–24 months).</li>"
                f"</ul>"
            ),
            "phase_1_inventory": (
                f"<p><strong>Status:</strong> {s['total_cbom_components']} components catalogued across {s['total']} assets. "
                f"CBOM coverage is {'high' if s['total_cbom_components'] > s['total'] * 5 else 'partial'}.</p>"
                f"<p><strong>Remaining work:</strong> Integrate CBOM generation into CI/CD pipelines; extend scanning to internal microservices; "
                f"add {s['third_party_count']} third-party providers to inventory scope.</p>"
                f"<p><strong>Timeline:</strong> 4–6 weeks. <strong>Resources:</strong> 1 security engineer + automated scanning pipeline.</p>"
            ),
            "phase_2_prioritize": (
                f"<p>Applying Mosca's inequality (x=migration time, y=data shelf life, z=CRQC arrival):</p>"
                f"<ul>"
                f"<li><strong>Cohort A (0–12 months):</strong> {s['hndl_count']} HNDL-exposed + {s['critical_count']} critical assets. Immediate migration required.</li>"
                f"<li><strong>Cohort B (12–24 months):</strong> {s['vulnerable_count']} quantum-vulnerable assets. High sensitivity data.</li>"
                f"<li><strong>Cohort C (24–36 months):</strong> Remaining at-risk assets and internal services.</li>"
                f"<li><strong>Cohort D (Ongoing):</strong> {s['hybrid_assets']} hybrid-PQC assets — maintain and monitor.</li>"
                f"</ul>"
            ),
            "phase_3_migrate": (
                f"<p><strong>Key Exchange:</strong> Deploy ML-KEM-768 (FIPS 203) via OpenSSL 3.5+ or liboqs 0.10+. "
                f"Configure X25519MLKEM768 as preferred TLS key share group for hybrid transition.</p>"
                f"<p><strong>Signatures:</strong> Deploy ML-DSA-65 (FIPS 204) for authentication tokens, API signing, and new certificate issuance. "
                f"Use SLH-DSA-Shake-128s (FIPS 205) for long-term document signing.</p>"
                f"<p><strong>PKI:</strong> Stand up hybrid CA using CFSSL with liboqs patch or use DigiCert/Entrust PQC CA service. "
                f"Issue composite certificates (classical ECDSA P-256 + ML-DSA-65) for {s['vulnerable_certs']} vulnerable certificate renewals.</p>"
                f"<p><strong>TLS Config:</strong> nginx: <code>ssl_ecdh_curve X25519MLKEM768:X25519;</code> | "
                f"OpenSSL: <code>Groups = X25519MLKEM768:prime256v1</code></p>"
            ),
            "phase_4_verify": (
                f"<p><strong>Definition of Done:</strong> 100% of assets have ML-KEM-768 key exchange, "
                f"0 quantum-vulnerable certificates, all CBOM components NIST-level 3+, "
                f"full RBI IT Framework 2023 compliance.</p>"
                f"<p><strong>Verification tests:</strong> Run QuShield scan post-migration; verify TLS handshake uses ML-KEM key share; "
                f"validate certificate chain ML-DSA signatures; confirm CBOM shows 0 vulnerable components.</p>"
                f"<p><strong>Ongoing monitoring:</strong> Monthly QuShield scans; CBOM diff alerts on new deployments; "
                f"quarterly vendor PQC status review; annual RBI submission update.</p>"
            ),
            "vendor_recommendations": (
                f"<p>For each of the {s['third_party_count']} third-party providers identified:</p>"
                f"<ul>"
                f"<li><strong>Immediate:</strong> Send formal PQC migration timeline request with 30-day response SLA.</li>"
                f"<li><strong>Contractual:</strong> Add to next contract renewal: 'Vendor shall achieve FIPS 203/204 compliance by [date] or provide written migration plan.'</li>"
                f"<li><strong>Technical interim:</strong> Deploy application-layer PQC encryption (Kyber/ML-KEM wrapper) for data flows through non-PQC vendors.</li>"
                f"<li><strong>Fallback:</strong> Identify alternative PQC-ready vendors for each critical third-party dependency.</li>"
                f"</ul>"
            ),
        }
        return fb.get(section, f"<p>Data summary: {s['total']} assets scanned, {s['critical_count']} critical, {s['hndl_count']} HNDL-exposed.</p>")

    def _generate_ai_sections(self, report_type: str, dataset: Dict[str, Any]) -> Dict[str, str]:
        ctx = self._ctx(dataset)
        SYS = (
            "You are a senior Quantum Security Architect and compliance expert for Indian banking infrastructure. "
            "Be precise, technical, and actionable. Use specific numbers from the data provided. "
            "Do not repeat the data — provide expert analysis, implications, and specific recommendations. "
            "Format your response using markdown: use **bold** for key terms, ## for section headings, "
            "and - bullet points for lists. Write in clear paragraphs."
        )

        def ai(key: str, prompt: str) -> str:
            return self._ai_generate_with_delay(prompt, SYS, fallback=self._fallback(key, dataset))

        if report_type == "executive":
            return {
                "board_summary": ai("board_summary",
                    f"DATA:\n{ctx}\n\nWrite a board-level executive summary (3 paragraphs) of the organization's quantum security posture. Cover: (1) overall quantum risk severity and urgency, (2) the most critical exposures and their business impact, (3) strategic priorities for the next 90 days. Use C-suite language — no jargon, but be specific with numbers."),
                "risk_posture": ai("risk_posture",
                    f"DATA:\n{ctx}\n\nAnalyze the current quantum risk posture in depth. Explain: what the risk scores mean in practice, which assets are most exposed to Harvest Now Decrypt Later attacks today, and how the Mosca inequality applies. Quantify the urgency."),
                "top_threats": ai("top_threats",
                    f"DATA:\n{ctx}\n\nIdentify and rank the top 5 quantum threats facing this organization right now. For each: name the threat, which assets are affected, what the attacker could do, and the regulatory consequence under RBI/SEBI frameworks."),
                "immediate_actions": ai("immediate_actions",
                    f"DATA:\n{ctx}\n\nProvide 7 specific, immediately actionable steps the CISO must take within the next 30 days to reduce quantum risk. Be precise — name specific algorithms to disable, specific systems to prioritize, and specific vendors to contact."),
                "roadmap_90d": ai("roadmap_90d",
                    f"DATA:\n{ctx}\n\nCreate a detailed 90-day post-quantum migration quick-win roadmap. Organize by 2-week milestones. Focus on highest-impact, lowest-complexity actions first."),
            }

        elif report_type == "full_scan":
            return {
                "infra_overview": ai("infra_overview",
                    f"DATA:\n{ctx}\n\nProvide a comprehensive technical overview of the scanned infrastructure from a quantum cryptography perspective. Describe the asset landscape, diversity of cryptographic exposure, and overall attack surface."),
                "tls_findings": ai("tls_findings",
                    f"DATA:\n{ctx}\n\nAnalyze all TLS-related findings in depth. Cover: TLS version distribution problems, cipher suite vulnerabilities, key exchange algorithm weaknesses, and which endpoints are highest priority for ML-KEM migration."),
                "cert_findings": ai("cert_findings",
                    f"DATA:\n{ctx}\n\nAnalyze the certificate infrastructure findings. Cover: quantum-vulnerable signing algorithms in certificates, certificate expiry risks, CA chain weaknesses, and the PQC certificate migration path."),
                "shadow_assets": ai("shadow_assets",
                    f"DATA:\n{ctx}\n\nAnalyze any shadow assets, unknown hosts, or unmanaged infrastructure discovered. Discuss the quantum security implications of unmanaged assets in the attack surface."),
                "third_party_risk": ai("third_party_risk",
                    f"DATA:\n{ctx}\n\nAnalyze third-party and vendor quantum risk. For each major third-party provider identified, assess their PQC readiness, the data flows at risk, and recommended contractual/technical mitigations."),
                "technical_recommendations": ai("technical_recommendations",
                    f"DATA:\n{ctx}\n\nProvide a prioritized technical remediation plan with specific steps for each vulnerability category. Include: exact algorithm replacements, library versions, configuration changes, and testing procedures."),
            }

        elif report_type == "rbi_submission":
            return {
                "compliance_status": ai("compliance_status",
                    f"DATA:\n{ctx}\n\nProvide a formal compliance status narrative for RBI IT Framework 2023 submission. Cover each major requirement: CBOM inventory, quantum risk assessment, TLS standards, certificate management, and third-party risk."),
                "fips_gap_analysis": ai("fips_gap_analysis",
                    f"DATA:\n{ctx}\n\nConduct a detailed gap analysis against FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) requirements. For each standard: current state, gap identified, remediation plan, and target completion date."),
                "npci_sebi_pci": ai("npci_sebi_pci",
                    f"DATA:\n{ctx}\n\nAnalyze compliance status against NPCI UPI cryptographic requirements, SEBI CSCRF cybersecurity framework, and PCI DSS 4.0 cryptographic controls. Identify specific gaps and required actions."),
                "remediation_plan": ai("remediation_plan",
                    f"DATA:\n{ctx}\n\nPrepare a formal remediation plan suitable for RBI submission. Include: prioritized list of non-compliant controls, remediation actions, responsible parties, timelines, and success criteria for each item."),
                "attestation": ai("attestation",
                    f"DATA:\n{ctx}\n\nDraft an attestation narrative for the Board Risk Committee confirming the quantum risk assessment has been completed per RBI IT Framework 2023 requirements, summarizing the key findings and management's commitment to remediation."),
            }

        elif report_type == "cbom_audit":
            return {
                "cbom_summary": ai("cbom_summary",
                    f"DATA:\n{ctx}\n\nWrite an executive summary of the Cryptographic Bill of Materials (CBOM) audit. Cover: total cryptographic inventory, distribution of algorithm types, proportion quantum-vulnerable vs quantum-safe, and the overall cryptographic hygiene assessment."),
                "algorithm_analysis": ai("algorithm_analysis",
                    f"DATA:\n{ctx}\n\nConduct a detailed analysis of the quantum-vulnerable algorithms discovered. For each major vulnerable algorithm found: explain why it is vulnerable to quantum attack, which assets use it, the attack timeline under Mosca's inequality, and the recommended PQC replacement."),
                "key_exchange_findings": ai("key_exchange_findings",
                    f"DATA:\n{ctx}\n\nAnalyze the key exchange findings specifically. Focus on: which key exchange mechanisms are in use (RSA, ECDH, DH, X25519), their quantum vulnerability, HNDL exposure risk, and migration path to ML-KEM-768 or hybrid X25519MLKEM768."),
                "migration_priority": ai("migration_priority",
                    f"DATA:\n{ctx}\n\nProvide a prioritized algorithm migration order. List each algorithm that needs replacement, its migration complexity (1-5), estimated effort in person-days, and the specific NIST FIPS replacement. Order from highest-impact/lowest-effort to lowest-impact/highest-effort."),
            }

        elif report_type == "migration_progress":
            return {
                "progress_summary": ai("progress_summary",
                    f"DATA:\n{ctx}\n\nSummarize the current state of PQC migration progress. Based on the data, estimate what phase of migration this organization is in (Inventory/Prioritize/Migrate/Verify per PQCC framework) and what percentage of work is complete."),
                "phase_status": ai("phase_status",
                    f"DATA:\n{ctx}\n\nFor each PQCC migration phase (1: Inventory, 2: Prioritize, 3: Migrate, 4: Verify), assess the current completion status with specific evidence from the scan data. Identify what is done, what is in progress, and what is not started."),
                "blockers": ai("blockers",
                    f"DATA:\n{ctx}\n\nIdentify the top migration blockers. What is preventing faster PQC adoption in this infrastructure? Include: technical blockers (legacy systems, library limitations), vendor blockers, process blockers, and resource constraints. Be specific."),
                "acceleration": ai("acceleration",
                    f"DATA:\n{ctx}\n\nRecommend specific actions to accelerate PQC migration. What are the highest-leverage interventions that would move the most assets from vulnerable to protected in the shortest time? Include quick wins that can be done in under 2 weeks."),
            }

        elif report_type == "pqc_migration_plan":
            return {
                "executive_summary": ai("executive_summary",
                    f"DATA:\n{ctx}\n\nWrite a comprehensive executive summary for a PQC Migration Plan. Cover: the quantum threat timeline relevant to this organization, the business case for urgent migration, the scope of work required, and expected outcomes after full migration."),
                "provider_analysis": ai("provider_analysis",
                    f"DATA:\n{ctx}\n\nAnalyze the PQC readiness of external providers and infrastructure dependencies. For each major external dependency (cloud providers, CDNs, payment gateways, core banking vendors), assess their PQC readiness and the risk they pose."),
                "phase_1_inventory": ai("phase_1_inventory",
                    f"DATA:\n{ctx}\n\nDesign Phase 1 (Inventory and Discovery) of the PQC migration plan. Identify what additional inventory work remains, any CBOM coverage gaps, and specific steps to achieve complete cryptographic visibility. Include timeline and resource estimates."),
                "phase_2_prioritize": ai("phase_2_prioritize",
                    f"DATA:\n{ctx}\n\nDesign Phase 2 (Prioritize and Plan). Apply Mosca's inequality to the specific assets found. Define migration cohorts (Cohort A: 0-12 months, B: 12-24, C: 24-36) and assign each major asset group with justification."),
                "phase_3_migrate": ai("phase_3_migrate",
                    f"DATA:\n{ctx}\n\nDesign Phase 3 (Migrate) with specific technical implementation steps. Include: exact algorithm selections (ML-KEM-768, ML-DSA-65, SLH-DSA), TLS migration sequence, PKI migration steps, and hybrid transition strategy with library version and config guidance."),
                "phase_4_verify": ai("phase_4_verify",
                    f"DATA:\n{ctx}\n\nDesign Phase 4 (Verify and Monitor). Define what done looks like, specific verification tests, monitoring alerts, compliance validation procedures for RBI/SEBI, and the ongoing crypto-agility maintenance program."),
                "vendor_recommendations": ai("vendor_recommendations",
                    f"DATA:\n{ctx}\n\nProvide specific actionable recommendations for each major vendor/provider identified. For each: exact steps to request PQC migration timeline, contractual language to add, technical configurations to apply now, and fallback options."),
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
