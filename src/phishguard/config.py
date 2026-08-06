"""Application configuration loaded from environment variables."""

from functools import lru_cache
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


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()
