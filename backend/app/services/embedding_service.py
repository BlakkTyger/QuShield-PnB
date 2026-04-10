"""
Embedding Service — Unifies Local and Cloud embedding models.
"""
import abc
import os
import json
import logging
import requests
from typing import List, Optional

from app.models.auth import User

logger = logging.getLogger(__name__)


class EmbeddingProvider(abc.ABC):
    @abc.abstractmethod
    def embed(self, texts: List[str]) -> List[List[float]]:
        """Generate vector embeddings for a list of strings."""
        pass


class OllamaEmbedder(EmbeddingProvider):
    """Local, secure embeddings via Ollama running on localhost."""
    def __init__(self, model_override: str = None):
        self.model = model_override or "nomic-embed-text"
        self.base_url = "http://localhost:11434/api/embed"

    def embed(self, texts: List[str]) -> List[List[float]]:
        # Ollama /api/embed accepts an array of strings in the 'input' field.
        payload = {
            "model": self.model,
            "input": texts
        }
        try:
            response = requests.post(self.base_url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data.get("embeddings", [])
        except Exception as e:
            logger.error(f"Ollama embedding failed: {e}")
            # Return empty lists or raise? Better to raise or return empty to fall back.
            return [[] for _ in texts]


class OpenAIEmbedder(EmbeddingProvider):
    """Cloud embeddings via OpenAI."""
    def __init__(self, api_key: str, model_override: str = None):
        self.api_key = api_key
        self.model = model_override or "text-embedding-3-small"
        self.base_url = "https://api.openai.com/v1/embeddings"

    def embed(self, texts: List[str]) -> List[List[float]]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "input": texts
        }
        try:
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            # OpenAI returns a list of objects {"embedding": [...]}
            embeddings = [item["embedding"] for item in data.get("data", [])]
            return embeddings
        except Exception as e:
            logger.error(f"OpenAI embedding failed: {e}")
            return [[] for _ in texts]


def get_embedding_provider(user: Optional[User] = None) -> EmbeddingProvider:
    """
    Factory to return the appropriate LLM Embedder based on user tier and mode.
    """
    if not user:
        return OllamaEmbedder()

    mode = getattr(user, "deployment_mode", "secure")
    tier = getattr(user, "ai_tier", "free")
    keys = getattr(user, "cloud_api_keys", {}) or {}

    if mode == "secure":
        return OllamaEmbedder()

    if mode == "cloud":
        # Cloud users with Pro/Enterprise get OpenAI embeddings
        if tier in ("professional", "enterprise"):
            oai_key = keys.get("openai_key") or os.environ.get("OPENAI_API_KEY")
            if oai_key:
                model = "text-embedding-3-large" if tier == "enterprise" else "text-embedding-3-small"
                return OpenAIEmbedder(api_key=oai_key, model_override=model)
        
        # Free tier Cloud users, or fallback if Openai key is missing, uses Local fallback 
        # (Alternatively could use HuggingFace/Jina/Groq API if Groq supported native emb endpoint directly here). 
        # For simplicity and latency, nomic-embed-text locally is sufficient.
        return OllamaEmbedder()

    return OllamaEmbedder()
