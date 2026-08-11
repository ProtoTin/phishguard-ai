"""Tests for production server configuration."""

import pytest

from phishguard.server import get_port


def test_server_uses_local_default_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PORT", raising=False)

    assert get_port() == 8000


def test_server_uses_platform_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORT", "10000")

    assert get_port() == 10_000


@pytest.mark.parametrize("value", ["invalid", "0", "65536"])
def test_server_rejects_invalid_port(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PORT", value)

    with pytest.raises(ValueError, match="PORT"):
        get_port()
