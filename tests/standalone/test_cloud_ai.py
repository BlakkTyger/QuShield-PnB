"""
Standalone Test for Cloud AI Pipeline (Groq + Jina).
Verifies that inference and embeddings work with configured keys.
"""
import sys
import os
import json
from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from app.services.ai_service import GroqProvider, get_ai_provider
from app.services.embedding_service import JinaEmbedder, get_embedding_provider
from app.config import settings

def test_groq_inference():
    print("\n--- Testing Groq Cloud Inference ---")
    key = os.getenv("GROQ_API_KEY") or settings.GROQ_API_KEY
    if not key:
        print("❌ Skip: GROQ_API_KEY not found.")
        return False
    
    provider = GroqProvider(api_key=key)
    prompt = "Explain quantum risk in one sentence."
    print(f"Prompt: {prompt}")
    
    try:
        response = provider.generate(prompt)
        print(f"Response: {response}")
        if response and "[AI Error]" not in response:
            print("✅ Groq Pass")
            return True
        else:
            print(f"❌ Groq Fail: {response}")
            return False
    except Exception as e:
        print(f"❌ Groq Error: {e}")
        return False

def test_jina_embeddings():
    print("\n--- Testing Jina Cloud Embeddings ---")
    key = os.getenv("JINA_API_KEY") or settings.JINA_API_KEY
    if not key:
        print("❌ Skip: JINA_API_KEY not found.")
        return False
    
    embedder = JinaEmbedder(api_key=key)
    texts = ["Quantum computing", "Symmetric encryption"]
    print(f"Input: {texts}")
    
    try:
        embeddings = embedder.embed(texts)
        if len(embeddings) == 2 and len(embeddings[0]) > 0:
            print(f"✅ Jina Pass (Vector Size: {len(embeddings[0])})")
            return True
        else:
            print(f"❌ Jina Fail: Unexpected output shape")
            return False
    except Exception as e:
        print(f"❌ Jina Error: {e}")
        return False

def test_factory_logic():
    print("\n--- Testing Provider Factory Logic ---")
    # Mock settings / user if needed, but here we just check if it returns Clout providers
    ai = get_ai_provider()
    emb = get_embedding_provider()
    
    print(f"Default AI Provider: {type(ai).__name__}")
    print(f"Default Embedding Provider: {type(emb).__name__}")
    
    # In Phase 10 cloud-first, we expect Groq and Jina if keys are present
    if "Groq" in type(ai).__name__ or "Jina" in type(emb).__name__:
         print("✅ Factory Pass")
         return True
    return False

if __name__ == "__main__":
    load_dotenv()
    print("QuShield-PnB Cloud AI Verification Tool")
    results = [
        test_groq_inference(),
        test_jina_embeddings(),
        test_factory_logic()
    ]
    
    if all(results):
        print("\n🏆 Cloud AI Integration: VERIFIED")
    else:
        print("\n⚠️ Cloud AI Integration: PARTIAL/FAILED")
