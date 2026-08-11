"""Regression tests for the public deployment Blueprint."""

from pathlib import Path

import yaml  # type: ignore[import-untyped]


def test_render_blueprint_matches_production_container() -> None:
    """Keep the service hostname, port, and readiness check synchronized."""

    blueprint = yaml.safe_load(Path("render.yaml").read_text(encoding="utf-8"))
    service = blueprint["services"][0]
    environment = {entry["key"]: entry["value"] for entry in service["envVars"]}

    assert service["type"] == "web"
    assert service["runtime"] == "docker"
    assert service["plan"] == "free"
    assert service["healthCheckPath"] == "/ready"
    assert service["autoDeployTrigger"] == "checksPass"
    assert environment["PORT"] == "8000"
    assert environment["PHISHGUARD_ENVIRONMENT"] == "production"
    assert environment["PHISHGUARD_ALLOWED_HOSTS"] == (f"{service['name']}.onrender.com")
