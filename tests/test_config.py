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
    assert settings.analysis_timeout_seconds == 5.0
    assert settings.analysis_rate_limit == 30
    assert settings.analysis_rate_window_seconds == 60
    assert settings.allowed_host_list == ["localhost", "127.0.0.1", "test", "testserver"]


def test_settings_reads_prefixed_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PHISHGUARD_ENVIRONMENT", "test")

    settings = Settings()

    assert settings.environment == "test"


def test_allowed_hosts_are_normalized(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PHISHGUARD_ALLOWED_HOSTS", " example.com, api.example.com ")

    settings = Settings()

    assert settings.allowed_hosts == "example.com,api.example.com"
    assert settings.allowed_host_list == ["example.com", "api.example.com"]


def test_allowed_hosts_cannot_be_empty(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PHISHGUARD_ALLOWED_HOSTS", " , ")

    with pytest.raises(ValueError, match="allowed_hosts"):
        Settings()
