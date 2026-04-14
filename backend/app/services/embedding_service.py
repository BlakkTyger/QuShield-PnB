"""
Embedding Service — Unifies Local and Cloud embedding models.
"""
import abc
import os
import json
import logging
import requests
from typing import List, Optional

from app.config import settings
from app.models.auth import User

logger = logging.getLogger(__name__)


class EmbeddingProvider(abc.ABC):
    @abc.abstractmethod
    def embed(self, texts: List[str]) -> List[List[float]]:
        """Generate vector embeddings for a list of strings."""
        pass


class OllamaEmbedder(EmbeddingProvider):
    """Local, secure embeddings via Ollama."""
    def __init__(self, model_override: str = None):
        self.model = model_override or "nomic-embed-text"
        self.base_url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/embed"

    def embed(self, texts: List[str]) -> List[List[float]]:
        # Ollama /api/embed accepts an array of strings in the 'input' field.
        payload = {
            "model": self.model,
            "input": texts
        }
        try:
            logger.info(f"Ollama Embedding: {self.base_url} [Model: {self.model}]")
            response = requests.post(self.base_url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data.get("embeddings", [])
        except Exception as e:
            logger.error(f"Ollama embedding failed: {e}")
            return [[] for _ in texts]


class OpenAIEmbedder(EmbeddingProvider):
    """Cloud embeddings via OpenAI."""
    def __init__(self, api_key: str, model_override: str = None):
        self.api_key = api_key
        self.model = model_override or "text-embedding-3-small"
        self.base_url = "https://api.openai.com/v1/embeddings"

    def embed(self, texts: List[str]) -> List[List[float]]:
        if not self.api_key:
            return [[] for _ in texts]

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "input": texts
        }
        try:
            logger.info(f"OpenAI Embedding [Model: {self.model}]")
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            # OpenAI returns a list of objects {"embedding": [...]}
            embeddings = [item["embedding"] for item in data.get("data", [])]
            return embeddings
        except Exception as e:
            logger.error(f"OpenAI embedding failed: {e}")
            return [[] for _ in texts]


class JinaEmbedder(EmbeddingProvider):
    """Cloud embeddings via Jina AI (BGE-M3 / Jina v3)."""
    def __init__(self, api_key: str, model_override: str = None):
        self.api_key = api_key
        self.model = model_override or "jina-embeddings-v3"
        self.base_url = "https://api.jina.ai/v1/embeddings"

    def embed(self, texts: List[str]) -> List[List[float]]:
        if not self.api_key:
            return [[] for _ in texts]

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "input": [{"text": t, "task": "retrieval.passage"} for t in texts],
        }
        try:
            logger.info(f"Jina Cloud Embedding [Model: {self.model}]")
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            # Jina returns a list of objects {"embedding": [...]}
            embeddings = [item["embedding"] for item in data.get("data", [])]
            return embeddings
        except Exception as e:
            logger.error(f"Jina embedding failed: {e}")
            return [[] for _ in texts]


def get_embedding_provider(user: Optional[User] = None) -> EmbeddingProvider:
    """
    Factory to return the appropriate LLM Embedder based on user tier and mode.
    Prioritizes Cloud providers (OpenAI, Jina) in Phase 10.
    """
    mode = "cloud"
    tier = "free"
    keys = {}

    if user:
        mode = getattr(user, "deployment_mode", "cloud")
        tier = getattr(user, "ai_tier", "free")
        keys = getattr(user, "cloud_api_keys", {}) or {}

    oai_key = keys.get("openai_key") or settings.OPENAI_API_KEY
    jina_key = keys.get("jina_key") or settings.JINA_API_KEY

    # 1. Cloud Mode Routing
    if mode == "cloud":
        # Professional/Enterprise users get OpenAI if key is present
        if tier in ("professional", "enterprise") and oai_key:
            model = "text-embedding-3-large" if tier == "enterprise" else "text-embedding-3-small"
            return OpenAIEmbedder(api_key=oai_key, model_override=model)
        
        # Fallback to Jina for Free tier or if OpenAI is missing
        if jina_key:
            return JinaEmbedder(api_key=jina_key)
            
        # Last resort: Try local Ollama if configured
        return OllamaEmbedder()

    # 2. Secure (Local) Mode Routing
    if mode == "secure":
        return OllamaEmbedder()

    # 3. Global Default
    return OllamaEmbedder()
