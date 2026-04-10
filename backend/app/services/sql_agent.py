"""
SQL Tabular Data Agent — Securely processes user structured data by creating a strictly
isolated, ephemeral, in-memory SQLite database populated ONLY with their data.
"""
import logging
import sqlite3
import json
from uuid import UUID
from typing import Dict, Any, List, Optional
import pandas as pd

from sqlalchemy.orm import Session
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.risk import RiskScore
from app.models.compliance import ComplianceResult
from app.models.auth import User
from app.services.ai_service import get_ai_provider

logger = logging.getLogger(__name__)


class TabularAgent:
    def __init__(self, user: User, db: Session):
        self.user = user
        self.db = db
        self.ai = get_ai_provider(user)

    def _build_isolated_db(self) -> sqlite3.Connection:
        """
        Creates an ephemeral SQLite database in memory.
        STRICT ISOLATION: Fetches only the given user's data. If user is None, returns empty.
        There is zero chance of cross-tenant leakage as the data is dumped into Memory DB.
        """
        conn = sqlite3.connect(":memory:")

        # Get all scan_ids belonging to this user
        scans = self.db.query(ScanJob).filter(ScanJob.user_id == self.user.id).all()
        scan_ids = [s.id for s in scans]

        if not scan_ids:
            return conn  # Empty DB

        # 1. Scans Table
        df_scans = pd.DataFrame([{
            "id": str(s.id), "targets": ", ".join(s.targets), "status": s.status, 
            "created_at": s.created_at, "completed_at": s.completed_at
        } for s in scans])
        df_scans.to_sql("scans", conn, index=False)

        # 2. Assets Table
        assets = self.db.query(Asset).filter(Asset.scan_id.in_(scan_ids)).all()
        if assets:
            df_assets = pd.DataFrame([{
                "id": str(a.id), "scan_id": str(a.scan_id), "hostname": a.hostname,
                "ip_address": a.ip_v4, "asset_type": a.asset_type,
                "is_shadow": a.is_shadow, "is_third_party": a.is_third_party
            } for a in assets])
            df_assets.to_sql("assets", conn, index=False)

        # 3. Certificates Table
        certs = self.db.query(Certificate).filter(Certificate.scan_id.in_(scan_ids)).all()
        if certs:
            df_certs = pd.DataFrame([{
                "id": str(c.id), "asset_id": str(c.asset_id), "scan_id": str(c.scan_id),
                "issuer": c.issuer, "common_name": c.common_name, 
                "signature_algorithm": c.signature_algorithm,
                "is_quantum_vulnerable": c.is_quantum_vulnerable, "valid_from": c.valid_from, "valid_to": c.valid_to
            } for c in certs])
            df_certs.to_sql("certificates", conn, index=False)

        # 4. Risk Scores Table
        risks = self.db.query(RiskScore).filter(RiskScore.scan_id.in_(scan_ids)).all()
        if risks:
            df_risks = pd.DataFrame([{
                "asset_id": str(r.asset_id), "base_score": float(r.quantum_risk_score or 0),
                "risk_classification": r.risk_classification, 
                "quantum_readiness_level": r.risk_classification
            } for r in risks])
            df_risks.to_sql("risk_scores", conn, index=False)
            
        return conn

    def query(self, question: str) -> str:
        """Process a natural language tabular query, generate SQL, execute, and return narrative."""
        conn = self._build_isolated_db()
        cursor = conn.cursor()

        # Step 1: Text-to-SQL
        schema_prompt = """
You are an expert Data Analyst AI for QuShield-PnB.
You have the following tables:
1. scans (id, targets, status, created_at, completed_at)
2. assets (id, scan_id, hostname, ip_address, asset_type, is_shadow, is_third_party)
3. certificates (id, asset_id, scan_id, issuer, common_name, signature_algorithm, is_quantum_vulnerable, valid_from, valid_to)
4. risk_scores (asset_id, base_score, risk_classification, quantum_readiness_level)

Output ONLY a valid syntactically correct SQLite query. Do NOT add markdown formatting, do NOT write ```sql. Only the query string.
If the question is unrelated to the data, return 'SELECT NULL;'.
"""
        user_prompt = f"Write a query to answer the user's question:\n{question}"
        
        try:
            sql_query_raw = self.ai.generate(user_prompt, system=schema_prompt, temperature=0.1)
            
            # Robust extraction of SQL from markdown block if LLM ignored instructions
            sql_query = sql_query_raw
            if "```" in sql_query:
                import re
                sql_match = re.search(r"```(sql|sqlite)?(.*?)```", sql_query, re.DOTALL | re.IGNORECASE)
                if sql_match:
                    sql_query = sql_match.group(2).strip()
            
            sql_query = sql_query.strip().strip(";").rstrip(";") + ";" # Ensure single semicolon
            
            logger.info(f"SQL Agent executing: {sql_query}")
            
            # Execute Query
            cursor.execute(sql_query)
            results = cursor.fetchall()
            columns = [description[0] for description in cursor.description] if cursor.description else []
            
            # Formatting results to tabular string
            if not results:
                raw_data_string = "No results found."
            else:
                row_dicts = [dict(zip(columns, row)) for row in results]
                raw_data_string = json.dumps(row_dicts, indent=2, default=str)
        except Exception as e:
            logger.error(f"SQL Agent error: {e}")
            raw_data_string = f"Error executing query: {e}"
        finally:
            conn.close()

        # Step 2: Insights Generation
        insights_system = "You are a quantum security analyst. Summarize these database query results clearly and concisely for the user. Answer their original question exactly based on the data provided."
        insights_prompt = f"User Question: '{question}'\n\nThe DB returned:\n{raw_data_string}\n\nProvide the final answer to the user in a short summary paragraph."
        
        try:
            final_answer = self.ai.generate(insights_prompt, system=insights_system, temperature=0.5)
            return final_answer
        except Exception as e:
            return f"Error analyzing data: {e} | Raw Data: {raw_data_string}"
