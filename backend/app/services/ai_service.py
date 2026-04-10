"""
AI Generation Service — Unifies Local (Ollama) and Cloud (Groq/OpenAI) LLM providers.
"""
import abc
import os
import json
import logging
import requests
from typing import Optional

from app.config import settings
from app.models.auth import User

logger = logging.getLogger(__name__)


class AIProvider(abc.ABC):
    @abc.abstractmethod
    def generate(self, prompt: str, system: str = None, temperature: float = 0.7) -> str:
        """Generate text given a prompt and optional system instructions."""
        pass


class OllamaProvider(AIProvider):
    """Local, secure generation via Ollama."""
    def __init__(self, model_override: str = None):
        # Default to a highly capable small model for local execution
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
            return f"[AI Error] Failed to generate response locally: {str(e)}"


class GroqProvider(AIProvider):
    """Cloud execution via Groq's blazing fast Llama 3 API."""
    def __init__(self, api_key: str, model_override: str = None):
        self.api_key = api_key
        self.model = model_override or "llama-3.1-8b-instant"
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    def generate(self, prompt: str, system: str = None, temperature: float = 0.7) -> str:
        if not self.api_key:
            return "[AI Error] Groq API key not configured."

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
            logger.info(f"Groq Cloud Request [Model: {self.model}]")
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
        if not self.api_key:
            return "[AI Error] OpenAI API key not configured."

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
            logger.info(f"OpenAI Cloud Request [Model: {self.model}]")
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            return f"[AI Error] Cloud generation failed: {str(e)}"


def get_ai_provider(user: Optional[User] = None) -> AIProvider:
    """
    Factory to return the appropriate LLM generator based on user tier and deployment mode.
    Defaults to Cloud Mode (Groq) if GROQ_API_KEY is present in settings or user profile.
    """
    # 1. Determine Mode & Tier
    mode = "cloud" # Default to cloud for Phase 10
    tier = "free"
    keys = {}

    if user:
        mode = getattr(user, "deployment_mode", "cloud")
        tier = getattr(user, "ai_tier", "free")
        keys = getattr(user, "cloud_api_keys", {}) or {}

    # 2. Key Collection (Priority: User Profile > Settings/Env)
    groq_key = keys.get("groq_key") or settings.GROQ_API_KEY
    oai_key = keys.get("openai_key") or settings.OPENAI_API_KEY

    # 3. Cloud Mode Routing (Priority)
    if mode == "cloud":
        # Professional/Enterprise check
        if tier in ("professional", "enterprise"):
            if oai_key:
                model = "gpt-4o" if tier == "enterprise" else "gpt-4o-mini"
                return OpenAIProvider(api_key=oai_key, model_override=model)
            if groq_key:
                model = "llama-3.1-70b-versatile" if tier == "enterprise" else "llama-3.1-8b-instant"
                return GroqProvider(api_key=groq_key, model_override=model)
            
        # Free Cloud uses Groq
        if groq_key:
            return GroqProvider(api_key=groq_key, model_override="llama-3.1-8b-instant")
        
        # Fallback to local if no cloud keys found although mode is cloud
        return OllamaProvider()

    # 4. Secure (Local) Mode Routing
    if mode == "secure":
        if tier == "enterprise":
            return OllamaProvider("llama3.1:70b")
        elif tier == "professional":
            return OllamaProvider("llama3.1:8b")
        else:
            # Free tier legacy fallback or qwen if preferred
            return OllamaProvider("llama3.1:8b")

    # 5. Global Default
    return OllamaProvider()
