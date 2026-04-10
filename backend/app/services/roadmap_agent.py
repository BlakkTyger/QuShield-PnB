"""
AI Migration Roadmap Generator — Evaluates Scan risks and CBOMs, then constructs
a customized, detailed post-quantum migration roadmap structured per PQCC.org guidelines.
"""
import json
import logging
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.risk import RiskScore
from app.models.auth import User
from app.services.ai_service import get_ai_provider

logger = logging.getLogger(__name__)

def generate_migration_roadmap(scan_id: str, db: Session, user: User) -> dict:
    """
    Coordinates extraction of risk/asset data, creates an LLM prompt based on
    NIST/PQCC guidelines, and generates a structured JSON roadmap.
    """
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job:
        raise ValueError(f"Scan {scan_id} not found")

    # Gather data context
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    risks = db.query(RiskScore).filter(RiskScore.scan_id == scan_id).all()
    
    asset_map = {str(a.id): a.hostname for a in assets}
    
    # Identify high risk items
    high_risks = [r for r in risks if r.risk_classification in ("quantum_critical", "quantum_vulnerable")]
    
    if not high_risks:
        return {
            "status": "success",
            "message": "No critical/high quantum risks found. Migration roadmap not required.",
            "phases": []
        }

    # Format risk context for LLM
    context_lines = []
    for r in high_risks:
        hostname = asset_map.get(str(r.asset_id), "Unknown Asset")
        context_lines.append(f"- {hostname}: Risk Score {r.quantum_risk_score}/1000, Classification: {r.risk_classification}")
    
    context_str = "\n".join(context_lines)

    system_prompt = """
You are a senior Quantum Security Migration architect for QuShield-PnB.
You adhere to the PQCC.org (Post-Quantum Cryptography Coalition) 4-phase roadmap:
1. Inventory
2. Prioritize
3. Migrate
4. Verify

Given the following critical infrastructure risks detected in a recent scan, 
generate a customized Post-Quantum Migration Roadmap in pure JSON format.
Your output MUST be a valid JSON object matching this schema:
{
  "executive_summary": "...",
  "estimated_timeline_months": 18,
  "phases": [
    {
      "phase_name": "Phase 1: Inventory & Discovery",
      "duration": "...",
      "key_actions": ["...", "..."],
      "relevant_assets": ["..."]
    },
    ... (do for all 4 phases)
  ]
}

DO NOT wrap the response in markdown blocks. Output pure JSON only.
"""
    prompt = f"Here are the high-risk assets detected in the scan:\n{context_str}\n\nGenerate the JSON roadmap."

    ai = get_ai_provider(user)
    
    try:
        response_text = ai.generate(prompt=prompt, system=system_prompt, temperature=0.2)
        
        # Clean potential markdown wrappers if LLM disobeyed
        response_text = response_text.replace("```json", "").replace("```", "").strip()
        
        roadmap_data = json.loads(response_text)
        
        # We could save this to the DB. For now, returning it to be handled by the router
        logger.info(f"Generated AI Roadmap for scan {scan_id}")
        return roadmap_data
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM roadmap output: {e}\nRaw: {response_text}")
        raise ValueError("Failed to generate a valid roadmap.")
    except Exception as e:
        logger.error(f"Roadmap generation failed: {e}")
        raise ValueError(f"AI Generation error: {e}")
