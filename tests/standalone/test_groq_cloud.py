# Standalone Test for Groq Cloud Inference
import os
import sys
import logging

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

from app.services.ai_service import GroqProvider, get_ai_provider
from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_groq_direct():
    print("\n--- Testing Groq Direct Inference ---")
    api_key = settings.GROQ_API_KEY
    if not api_key:
        print("❌ Error: GROQ_API_KEY not found in settings.")
        return

    provider = GroqProvider(api_key=api_key)
    prompt = "Explain in one sentence what a Post-Quantum Cryptographic Bill of Materials (CBOM) is."
    
    print(f"Sending prompt to Groq...")
    response = provider.generate(prompt)
    print(f"Response: {response}")
    
    if "[AI Error]" in response:
        print("❌ Groq Inference Failed.")
    else:
        print("✅ Groq Inference Success!")

def test_factory_cloud():
    print("\n--- Testing AI Provider Factory (Cloud Default) ---")
    # Mock user with cloud mode
    from unittest.mock import MagicMock
    user = MagicMock()
    user.deployment_mode = "cloud"
    user.ai_tier = "free"
    user.cloud_api_keys = {}
    
    provider = get_ai_provider(user)
    print(f"Factory returned provider: {type(provider).__name__}")
    
    if isinstance(provider, GroqProvider):
        print("✅ Factory correctly returned GroqProvider for Cloud Free tier.")
    else:
        print(f"❌ Factory returned {type(provider).__name__} instead of GroqProvider.")

if __name__ == "__main__":
    test_groq_direct()
    test_factory_cloud()
