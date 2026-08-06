"""Tests for application configuration."""

from pathlib import Path

import pytest

from phishguard.config import Settings


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PHISHGUARD_APP_NAME", raising=False)
    monkeypatch.delenv("PHISHGUARD_ENVIRONMENT", raising=False)
    settings = Settings()

    assert settings.app_name == "PhishGuard API"
    assert settings.environment == "development"
    assert settings.max_request_bytes == 65_536


def test_settings_reads_prefixed_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PHISHGUARD_ENVIRONMENT", "test")

    settings = Settings()

    assert settings.environment == "test"
