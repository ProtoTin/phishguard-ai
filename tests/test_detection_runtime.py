"""Tests for verified and version-compatible runtime model loading."""

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import joblib
import numpy as np
import pytest
from numpy.typing import NDArray

from phishguard import __version__
from phishguard.detection.policy import POLICY_VERSION
from phishguard.detection.runtime import (
    DetectionEngine,
    DetectionProvider,
    DetectionUnavailableError,
)


class SerializableModel:
    """Minimal trusted artifact used to exercise digest-checked loading."""

    def predict_proba(self, texts: Sequence[str]) -> NDArray[np.float64]:
        positive = np.full(len(texts), 0.5, dtype=np.float64)
        return np.column_stack((1 - positive, positive))


def artifact(path: Path) -> dict[str, object]:
    joblib.dump(SerializableModel(), path)
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def runtime_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    base_email = artifact(tmp_path / "base-email.joblib")
    base_url = artifact(tmp_path / "base-url.joblib")
    calibrated_email = artifact(tmp_path / "calibrated-email.joblib")
    calibrated_url = artifact(tmp_path / "calibrated-url.joblib")
    model_report = tmp_path / "model-report.json"
    model_report.write_text(
        json.dumps(
            {
                "tasks": {
                    "email": {"artifact": base_email},
                    "url": {"artifact": base_url},
                }
            }
        )
    )
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "project_version": __version__,
                "policy_version": POLICY_VERSION,
                "models": {"email": calibrated_email, "url": calibrated_url},
            }
        )
    )
    return model_report, policy, tmp_path / "base-email.joblib"


def test_runtime_loads_verified_artifacts_and_provider_caches(tmp_path: Path) -> None:
    model_report, policy, _ = runtime_files(tmp_path)

    engine = DetectionEngine.from_files(model_report, policy)
    provider = DetectionProvider(model_report, policy)

    assert set(engine.base_models) == {"email", "url"}
    assert set(engine.calibrated_models) == {"email", "url"}
    assert provider.get() is provider.get()
    with pytest.raises(ValueError, match="Unsupported content type"):
        engine.analyze("attachment", "invoice.pdf")


def test_runtime_rejects_tampered_artifact(tmp_path: Path) -> None:
    model_report, policy, base_email_path = runtime_files(tmp_path)
    base_email_path.write_bytes(b"tampered")

    with pytest.raises(ValueError, match="digest mismatch"):
        DetectionEngine.from_files(model_report, policy)


def test_runtime_rejects_version_mismatch(tmp_path: Path) -> None:
    model_report, policy, _ = runtime_files(tmp_path)
    policy_data = json.loads(policy.read_text())
    policy_data["project_version"] = "0.0.0"
    policy.write_text(json.dumps(policy_data))

    with pytest.raises(ValueError, match="project version"):
        DetectionEngine.from_files(model_report, policy)


def test_provider_translates_missing_files(tmp_path: Path) -> None:
    provider = DetectionProvider(tmp_path / "missing.json", tmp_path / "policy.json")

    with pytest.raises(DetectionUnavailableError, match="unavailable"):
        provider.get()
