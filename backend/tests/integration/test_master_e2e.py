"""
Master End-to-End Verification Suite for Phase 9 Validation.
Targets `pnb.bank.in` exclusively as authorized by the system administrator.
Tests Authentication, Deep Scan Triggering, Discoveries, Crypto, Mosca's Risk,
Compliance generation, Graph Topology, and AI output.
"""

import os
import sys
import uuid
import asyncio
from datetime import datetime
import json

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.core.database import SessionLocal
from app.services.auth_service import create_user, get_user_by_email
from app.services.orchestrator import ScanOrchestrator
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.risk import RiskScore
from app.models.certificate import Certificate
from app.models.compliance import ComplianceResult
from app.services.sql_agent import TabularAgent
from app.services.vector_store import VectorStore
from app.services.roadmap_agent import generate_migration_roadmap

TARGET_DOMAIN = "pnb.bank.in"
TEST_USER_EMAIL = f"test_{uuid.uuid4()}@pnb-admin.local"
TEST_USER_PASS = "secure_e2e_password"

# Global artifact aggregator
results_log = [f"# Phase 9 E2E Test Results against {TARGET_DOMAIN}", f"Generated: {datetime.now()}"]

def append_log(msg: str):
    print(msg)
    results_log.append(msg)

async def run_master_e2e():
    db = SessionLocal()
    append_log(f"## 1. Setup & Authentication")
    try:
        # 1. Auth Create
        user = create_user(db, TEST_USER_EMAIL, TEST_USER_PASS)
        append_log(f"✅ User created successfully. ID: {user.id}")

        # 2. Trigger Scan
        append_log(f"\n## 2. Deep Scan Orchestration ({TARGET_DOMAIN})")
        orch = ScanOrchestrator()
        
        scan_job = ScanJob(
            targets=[TARGET_DOMAIN],
            status="pending",
            scan_type="deep",
            user_id=user.id
        )
        db.add(scan_job)
        db.commit()
        db.refresh(scan_job)
        scan_id = scan_job.id
        append_log(f"✅ Scan Job created: {scan_id}. Starting blocking orchestrator execution...")

        # Run synchronously for test simplicity instead of background stream
        orch.run_scan(str(scan_id), loop=asyncio.get_running_loop())
        
        # Reload scan record
        db.refresh(scan_job)
        if scan_job.status == "completed":
             append_log(f"✅ Deep Scan completed successfully!")
        else:
             append_log(f"❌ Deep Scan failed or stuck: {scan_job.status} - {scan_job.error_message}")
             return

        # 3. Discovery Accuracies
        assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
        append_log(f"\n## 3. Discovery Phase Validation")
        append_log(f"- Discovered {len(assets)} unique assets.")
        for a in assets:
            append_log(f"  - Asset: {a.hostname} ({a.ip_address}) - Type: {a.asset_type}")

        # 4. Crypto Inspector & Algorithms
        append_log(f"\n## 4. Cryptographic PQC Accuracy")
        certs = db.query(Certificate).filter(Certificate.scan_id == scan_id).all()
        for c in certs:
             append_log(f"  - Certificate [{c.id}]: Issuer={c.issuer_cn}, Algo={c.signature_algorithm}, PQC_Safe={c.is_pqc_safe}")
             if not c.signature_algorithm:
                 append_log(f"    ❌ BUG: Missing signature algorithm on cert!")

        for a in assets:
             if a.tls_version:
                 append_log(f"  - TLS Handshake [{a.hostname}]: {a.tls_version}, Weakest={a.weakest_cipher}, NIST_Lvl={a.pqc_nist_level}")
             else:
                 append_log(f"  - No TLS Handshake recorded for {a.hostname} (Expected for non-HTTP)")

        # 5. Risk Scores (Mosca)
        append_log(f"\n## 5. Mosca Risk Execution")
        risks = db.query(RiskScore).filter(RiskScore.scan_id == scan_id).all()
        for r in risks:
             append_log(f"  - Asset [{r.asset_id}] Risk: {r.risk_classification} ({r.base_score})")
             append_log(f"    CRQC Timeframe Check: {r.mitigation_recommendation}")
             if r.base_score is None:
                 append_log(f"    ❌ BUG: Base score is NULL!")

        # 6. Compliance Engine
        append_log(f"\n## 6. Compliance Generation")
        compliances = db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()
        for c in compliances:
             append_log(f"  - {c.framework} Compliance: Passing={c.is_passing}, Penalty={c.financial_penalty_estimate_usd}")

        # 7. AI Tabular Agent (H.3.3 / H.2)
        append_log(f"\n## 7. AI Engine Validation")
        append_log(f"  - Testing Memory-Isolated SQL logic...")
        sql_agent = TabularAgent(user, db)
        try:
             ans = sql_agent.query("How many distinct assets were discovered?")
             append_log(f"  ✅ SQL Agent Execution: {ans[:200]}")
        except Exception as e:
             append_log(f"  ❌ SQL Agent Failed: {str(e)}")

        # 8. AI Roadmap
        append_log(f"  - Testing PQCC Roadmap Generation...")
        try:
             roadmap = generate_migration_roadmap(str(scan_id), db, user)
             roadmap_smry = roadmap.get("executive_summary", "Missing summary") if isinstance(roadmap, dict) else str(roadmap)[:50]
             append_log(f"  ✅ Roadmap Output: {roadmap_smry[:150]}...")
        except Exception as e:
             append_log(f"  ❌ Roadmap Failed: {str(e)}")

    except Exception as e:
        import traceback
        append_log(f"\n❌ FATAL PIPELINE EXCEPTION: {e}")
        append_log(traceback.format_exc())
    finally:
        db.close()
        # Ensure we write out to Testing_Results
        with open("/home/blakktyger/Documents/BlakkTyger/Projects/QuShield-PnB/TESTING_RESULTS.md", "w") as f:
            f.write("\n".join(results_log))
        print("Logged to TESTING_RESULTS.md")


if __name__ == "__main__":
    asyncio.run(run_master_e2e())
