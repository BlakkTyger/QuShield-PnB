# Standalone Test for AI Migration Roadmap Generation
import os
import sys
import logging
from unittest.mock import MagicMock

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

from app.services.ai_service import get_ai_provider
from app.services.crypto_inspector import CryptoInspector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_roadmap_logic():
    print("\n--- Testing AI Migration Roadmap Logic ---")
    
    # Mock user
    user = MagicMock()
    user.deployment_mode = "cloud"
    user.ai_tier = "free"
    user.cloud_api_keys = {}
    
    ai = get_ai_provider(user)
    
    # Sample scan data context
    context = """
    Scan Results for pnb.bank.in:
    - 5 Assets found.
    - 3 Certificates found.
    - Vulnerabilities:
        - asset1.pnb.bank.in: RSA-2048 (Quantum Vulnerable)
        - asset2.pnb.bank.in: ECDSA-P256 (Quantum Vulnerable)
    - Compliance: Failing FIPS 203 (ML-KEM required).
    """
    
    system_prompt = "You are a PQC migration expert. Based on the scan data, generate a 4-phase migration roadmap."
    user_prompt = f"Data:\n{context}\n\nGenerate the roadmap."
    
    print("Generating roadmap via Groq...")
    roadmap = ai.generate(user_prompt, system=system_prompt)
    
    print(f"\n--- Generated Roadmap ---\n{roadmap}\n")
    
    if len(roadmap) > 100:
        print("✅ Roadmap generated successfully.")
    else:
        print("❌ Roadmap seems too short or failed.")

if __name__ == "__main__":
    test_roadmap_logic()
