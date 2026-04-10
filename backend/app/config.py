"""
QuShield-PnB Configuration System
Loads settings from .env file at project root using Pydantic Settings.
"""
import os
from pathlib import Path
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


# Project root is two levels up from this file (backend/app/config.py -> project root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- PostgreSQL ---
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "qushield"

    # JWT Config
    JWT_SECRET_KEY: str = "super_secret_jwt_key_for_dev_only"

    # Worker limits
    POSTGRES_USER: str = "qushield"
    POSTGRES_PASSWORD: str = "changeme_local_dev"

    # --- Application ---
    APP_ENV: str = "development"
    LOG_LEVEL: str = "DEBUG"
    LOG_DIR: str = "logs"
    DATA_DIR: str = "data"
    REPORTS_DIR: str = "data/reports"
    CBOM_DIR: str = "data/cbom"

    @property
    def log_dir_abs(self) -> Path:
        """Absolute path for log directory."""
        p = Path(self.LOG_DIR)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def data_dir_abs(self) -> Path:
        """Absolute path for data directory."""
        p = Path(self.DATA_DIR)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def cbom_dir_abs(self) -> Path:
        p = Path(self.CBOM_DIR)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def reports_dir_abs(self) -> Path:
        p = Path(self.REPORTS_DIR)
        return p if p.is_absolute() else PROJECT_ROOT / p

    # --- Discovery Engine API Keys (optional) ---
    SECURITYTRAILS_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""

    # --- NVD API Key (optional) ---
    NVD_API_KEY: str = ""

    # --- MaxMind GeoIP ---
    GEOIP_DB_PATH: str = str(PROJECT_ROOT / "data" / "geolite" / "GeoLite2-City.mmdb")

    # --- Ollama (Phase 9) ---
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    @property
    def database_url(self) -> str:
        """Synchronous PostgreSQL connection URL."""
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def async_database_url(self) -> str:
        """Async PostgreSQL connection URL (for asyncpg)."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()


# Convenience alias
settings = get_settings()
