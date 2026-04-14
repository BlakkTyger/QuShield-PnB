"""
AI Generation Service — Unifies Local (Ollama) and Cloud (Groq/OpenAI) LLM providers.

Active tier: Cloud → Free (Groq llama-3.3-70b-versatile + Jina embeddings).
All other tiers are scaffolded but disabled (Coming Soon).
"""
import abc
import logging
import requests
from typing import Optional

from app.config import settings
from app.models.auth import User

logger = logging.getLogger(__name__)


class AIConfigurationError(Exception):
    """Raised when the AI provider cannot be initialised due to missing credentials."""
    pass


class AIProvider(abc.ABC):
    @abc.abstractmethod
    def generate(self, prompt: str, system: str = None, temperature: float = 0.7) -> str:
        """Generate text given a prompt and optional system instructions."""
        pass


class OllamaProvider(AIProvider):
    """Local, secure generation via Ollama (Local Mode — Coming Soon)."""
    def __init__(self, model_override: str = None):
        self.model = model_override or "llama3.1:8b"
        self.base_url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate"

    def generate(self, prompt: str, system: str = None, temperature: float = 0.7) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature}
        }
        if system:
            payload["system"] = system

        try:
            logger.info(f"Ollama Request: {self.base_url} [Model: {self.model}]")
            response = requests.post(self.base_url, json=payload, timeout=120)
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            raise RuntimeError(f"Local model generation failed: {e}") from e


class GroqProvider(AIProvider):
    """Cloud execution via Groq. Free tier: llama-3.3-70b-versatile."""
    # Best available free models on Groq as of 2025
    FREE_MODEL = "llama-3.3-70b-versatile"
    PRO_MODEL = "llama-3.3-70b-versatile"
    ENTERPRISE_MODEL = "llama-3.3-70b-versatile"

    def __init__(self, api_key: str, model_override: str = None):
        if not api_key:
            raise AIConfigurationError(
                "GROQ_API_KEY is not configured. Set it in your .env file to enable AI features. "
                "Get a free key at https://console.groq.com"
            )
        self.api_key = api_key
        self.model = model_override or self.FREE_MODEL
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    def generate(self, prompt: str, system: str = None, temperature: float = 0.7) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 8192,
        }

        try:
            logger.info(f"Groq Cloud Request [Model: {self.model}]")
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=120)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except requests.HTTPError as e:
            logger.error(f"Groq API HTTP error: {e.response.status_code} — {e.response.text}")
            raise RuntimeError(f"Groq API error ({e.response.status_code}): {e.response.text}") from e
        except Exception as e:
            logger.error(f"Groq API generation failed: {e}")
            raise RuntimeError(f"Cloud generation failed: {e}") from e


class OpenAIProvider(AIProvider):
    """Cloud execution via OpenAI (Professional / Enterprise — Coming Soon)."""
    def __init__(self, api_key: str, model_override: str = None):
        if not api_key:
            raise AIConfigurationError("OPENAI_API_KEY is not configured.")
        self.api_key = api_key
        self.model = model_override or "gpt-4o-mini"
        self.base_url = "https://api.openai.com/v1/chat/completions"

    def generate(self, prompt: str, system: str = None, temperature: float = 0.7) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 8192,
        }

        try:
            logger.info(f"OpenAI Cloud Request [Model: {self.model}]")
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=120)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except requests.HTTPError as e:
            logger.error(f"OpenAI HTTP error: {e.response.status_code}")
            raise RuntimeError(f"OpenAI API error: {e}") from e
        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            raise RuntimeError(f"OpenAI generation failed: {e}") from e


def get_ai_provider(user: Optional[User] = None) -> AIProvider:
    """
    Factory: returns the appropriate LLM provider for the user's mode+tier.

    Currently active: Cloud → Free (Groq llama-3.3-70b-versatile).
    Cloud Pro/Enterprise and all Local tiers are scaffolded but require
    additional configuration (Coming Soon in UI).
    """
    mode = "cloud"
    tier = "free"
    keys: dict = {}

    if user:
        mode = getattr(user, "deployment_mode", "cloud") or "cloud"
        tier = getattr(user, "ai_tier", "free") or "free"
        keys = getattr(user, "cloud_api_keys", {}) or {}

    groq_key = keys.get("groq_key") or settings.GROQ_API_KEY
    oai_key = keys.get("openai_key") or settings.OPENAI_API_KEY

    if mode == "cloud":
        if tier == "enterprise" and oai_key:
            return OpenAIProvider(api_key=oai_key, model_override="gpt-4o")
        if tier == "professional" and oai_key:
            return OpenAIProvider(api_key=oai_key, model_override="gpt-4o-mini")
        # Free tier (and any cloud tier without OpenAI key) → Groq
        return GroqProvider(api_key=groq_key, model_override=GroqProvider.FREE_MODEL)

    if mode == "secure":
        # Local mode — Ollama required
        tier_models = {
            "enterprise": "llama3.1:70b",
            "professional": "llama3.1:8b",
            "free": "llama3.1:8b",
        }
        return OllamaProvider(model_override=tier_models.get(tier, "llama3.1:8b"))

    # Hard fallback — should not reach here in normal operation
    raise AIConfigurationError(
        f"Unknown deployment mode '{mode}'. Set GROQ_API_KEY in .env to use Cloud mode."
    )
