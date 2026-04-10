# Standalone Test for Groq RAG
import os
import sys
import logging
from unittest.mock import MagicMock

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

from app.services.vector_store import VectorStore
from app.services.ai_service import get_ai_provider
from app.models.auth import User

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_groq_rag():
    print("\n--- Testing Groq RAG logic ---")
    
    # Mock User
    user = User()
    user.id = "5178b42e-cfcd-4029-bd97-8999f7064587" # My test user
    user.deployment_mode = "cloud"
    user.ai_tier = "free"
    user.cloud_api_keys = {}
    
    # 1. Seed Vector Store
    print("Seeding Vector Store...")
    vs = VectorStore(user)
    texts = [
        "QuShield-PnB found that pnb.bank.in is vulnerable to quantum attacks due to RSA-2048 usage.",
        "The recommended mitigation for RSA-2048 is to upgrade to ML-KEM or a hybrid TLS group.",
        "Internal assets like 'db.pnb.bank.in' are currently secure as they use internal PQC tunnels."
    ]
    metadatas = [
        {"source": "scan_report_1"},
        {"source": "mitigation_guide"},
        {"source": "internal_audit"}
    ]
    ids = ["doc1", "doc2", "doc3"]
    
    success = vs.embed_and_store(texts, metadatas, ids)
    if not success:
        print("❌ Seeding failed. Check if Ollama (nomic-embed-text) is running or configured.")
        return

    # 2. Search
    query = "What should I do about RSA-2048 vulnerability?"
    print(f"Searching for: {query}")
    results = vs.search(query, n_results=2)
    
    context_texts = [r["content"] for r in results]
    context_str = "\n\n".join(context_texts)
    print(f"Context retrieved: {context_str}")
    
    # 3. Infer
    ai = get_ai_provider(user)
    system_prompt = f"Use the context below to answer.\nContext:\n{context_str}"
    
    print("Generating RAG answer via Groq...")
    answer = ai.generate(query, system=system_prompt)
    print(f"\n--- AI Answer ---\n{answer}\n")
    
    if "ML-KEM" in answer or "hybrid" in answer:
        print("✅ RAG logic verified with Groq.")
    else:
        print("❌ RAG answer didn't mention expected terms.")

if __name__ == "__main__":
    test_groq_rag()
