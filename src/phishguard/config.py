"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
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
    max_request_bytes: int = Field(default=65_536, ge=1, le=1_048_576)
    analysis_timeout_seconds: float = Field(default=5.0, gt=0, le=30.0)
    analysis_rate_limit: int = Field(default=30, ge=1, le=10_000)
    analysis_rate_window_seconds: int = Field(default=60, ge=1, le=3_600)
    allowed_hosts: str = "localhost,127.0.0.1,test,testserver"

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, value: str) -> str:
        """Require at least one explicit, comma-separated HTTP host."""

        hosts = [host.strip() for host in value.split(",") if host.strip()]
        if not hosts:
            raise ValueError("allowed_hosts must contain at least one host")
        return ",".join(hosts)

    @property
    def allowed_host_list(self) -> list[str]:
        """Return normalized host entries for Starlette's host middleware."""

        return self.allowed_hosts.split(",")


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()
