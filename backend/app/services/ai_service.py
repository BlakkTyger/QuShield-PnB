"""
AI Generation Service — Unifies Local (Ollama) and Cloud (Groq/OpenAI) LLM providers.
"""
import abc
import os
import json
import logging
import requests
from typing import Optional

from app.models.auth import User

logger = logging.getLogger(__name__)


class AIProvider(abc.ABC):
    @abc.abstractmethod
    def generate(self, prompt: str, system: str = None, temperature: float = 0.7) -> str:
        """Generate text given a prompt and optional system instructions."""
        pass


class OllamaProvider(AIProvider):
    """Local, secure generation via Ollama running on localhost."""
    def __init__(self, model_override: str = None):
        # Default to a highly capable small model for local execution
        self.model = model_override or "qwen2.5:3b"
        self.base_url = "http://localhost:11434/api/generate"

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
            response = requests.post(self.base_url, json=payload, timeout=120)
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return f"[AI Error] Failed to generate response locally: {str(e)}"


class GroqProvider(AIProvider):
    """Cloud execution via Groq's blazing fast Llama 3 API."""
    def __init__(self, api_key: str, model_override: str = None):
        self.api_key = api_key
        self.model = model_override or "llama-3.1-8b-instant"
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
            "temperature": temperature
        }

        try:
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"Groq API generation failed: {e}")
            return f"[AI Error] Cloud generation failed: {str(e)}"


class OpenAIProvider(AIProvider):
    """Cloud execution via OpenAI (for Professional / Enterprise)."""
    def __init__(self, api_key: str, model_override: str = None):
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
            "temperature": temperature
        }

        try:
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            return f"[AI Error] Cloud generation failed: {str(e)}"


def get_ai_provider(user: Optional[User] = None) -> AIProvider:
    """
    Factory to return the appropriate LLM generator based on user tier and deployment mode.
    Fallbacks to secure local deployment mode if no user or no keys exist.
    """
    # 1. Fallback / Anonymous users -> Secure limits
    if not user:
        return OllamaProvider(model_override="qwen2.5:3b")

    mode = getattr(user, "deployment_mode", "secure")
    tier = getattr(user, "ai_tier", "free")
    keys = getattr(user, "cloud_api_keys", {}) or {}

    # 2. Secure (Local) Mode Routing
    if mode == "secure":
        if tier == "enterprise":
            return OllamaProvider("llama3.1:70b")
        elif tier == "professional":
            return OllamaProvider("llama3-8b")
        else:
            return OllamaProvider("qwen2.5:3b")

    # 3. Cloud Mode Routing
    if mode == "cloud":
        # Check for user-provided API keys in user.cloud_api_keys JSON blob
        if tier in ("professional", "enterprise"):
            oai_key = keys.get("openai_key") or os.environ.get("OPENAI_API_KEY")
            if oai_key:
                model = "gpt-4o" if tier == "enterprise" else "gpt-4o-mini"
                return OpenAIProvider(api_key=oai_key, model_override=model)
            
            # Fallback if no OpenAI key provided but asked for pro tier
            groq_key = keys.get("groq_key") or os.environ.get("GROQ_API_KEY")
            if groq_key:
                 return GroqProvider(api_key=groq_key, model_override="llama-3.1-70b-versatile" if tier == "enterprise" else "llama-3.1-8b-instant")
            
            # Global fallback
            return OllamaProvider()
            
        else:
            # Free cloud uses Groq due to generous free limits
            groq_key = keys.get("groq_key") or os.environ.get("GROQ_API_KEY")
            if groq_key:
                return GroqProvider(api_key=groq_key, model_override="llama-3.1-8b-instant")
            else:
                return OllamaProvider()

    # Defaults fallback
    return OllamaProvider()
