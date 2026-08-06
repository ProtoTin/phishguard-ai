"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the PhishGuard API."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="PHISHGUARD_",
        extra="ignore",
    )

    app_name: str = "PhishGuard API"
    environment: Literal["development", "test", "production"] = "development"
    model_report_path: Path = Path("reports/model-evaluation.json")
    policy_path: Path = Path("config/detection-policy.json")
    max_request_bytes: int = 65_536


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()
