"""Verified runtime loading for the email and URL detectors."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from phishguard import __version__
from phishguard.detection.calibration import load_verified_model
from phishguard.detection.explanations import CalibratedModel, explain
from phishguard.detection.policy import POLICY_VERSION
from phishguard.modeling.baselines import BinaryProbabilisticModel


class Analyzer(Protocol):
    """Runtime interface used by the API and test doubles."""

    def analyze(self, content_type: str, text: str) -> dict[str, object]: ...


class DetectionUnavailableError(RuntimeError):
    """Raised when verified detector artifacts cannot be loaded."""


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"Expected {context} to be an object")
    return cast(Mapping[str, object], value)


def _artifact_model(metadata: object, context: str) -> BinaryProbabilisticModel:
    artifact = _mapping(metadata, context)
    path = artifact.get("path")
    digest = artifact.get("sha256")
    expected_bytes = artifact.get("bytes")
    if (
        not isinstance(path, str)
        or not isinstance(digest, str)
        or not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
    ):
        raise TypeError(f"Expected {context} to contain path, sha256, and bytes")
    artifact_path = Path(path)
    if artifact_path.stat().st_size != expected_bytes:
        raise ValueError(f"Artifact size mismatch for {artifact_path}")
    return load_verified_model(artifact_path, digest)


@dataclass(frozen=True)
class DetectionEngine:
    """In-memory verified models used for offline-only inference."""

    base_models: Mapping[str, BinaryProbabilisticModel]
    calibrated_models: Mapping[str, CalibratedModel]

    @classmethod
    def from_files(cls, model_report_path: Path, policy_path: Path) -> DetectionEngine:
        """Load version-compatible artifacts after verifying every digest."""

        model_report = _mapping(
            json.loads(model_report_path.read_text(encoding="utf-8")), "model report"
        )
        policy = _mapping(json.loads(policy_path.read_text(encoding="utf-8")), "policy")
        if model_report.get("project_version") != __version__:
            raise ValueError("Model report project version does not match the running service")
        if policy.get("project_version") != __version__:
            raise ValueError("Policy project version does not match the running service")
        if policy.get("policy_version") != POLICY_VERSION:
            raise ValueError("Policy version does not match the running service")

        model_tasks = _mapping(model_report.get("tasks"), "model report tasks")
        policy_models = _mapping(policy.get("models"), "policy models")
        base_models: dict[str, BinaryProbabilisticModel] = {}
        calibrated_models: dict[str, CalibratedModel] = {}
        for content_type in ("email", "url"):
            task = _mapping(model_tasks.get(content_type), f"{content_type} model task")
            base_models[content_type] = _artifact_model(
                task.get("artifact"), f"{content_type} base artifact"
            )
            calibrated_models[content_type] = cast(
                CalibratedModel,
                _artifact_model(
                    policy_models.get(content_type), f"{content_type} calibrated artifact"
                ),
            )
        return cls(base_models=base_models, calibrated_models=calibrated_models)

    def analyze(self, content_type: str, text: str) -> dict[str, object]:
        """Analyze content without retaining it or performing network access."""

        if content_type not in {"email", "url"}:
            raise ValueError(f"Unsupported content type: {content_type}")
        return explain(
            content_type,
            text,
            self.base_models[content_type],
            self.calibrated_models[content_type],
        )


class DetectionProvider:
    """Thread-safe lazy loader that keeps startup useful before models are built."""

    def __init__(
        self,
        model_report_path: Path,
        policy_path: Path,
        detector: Analyzer | None = None,
    ) -> None:
        self._model_report_path = model_report_path
        self._policy_path = policy_path
        self._detector = detector
        self._lock = threading.Lock()

    def get(self) -> Analyzer:
        """Return the cached detector or safely translate loading failures."""

        if self._detector is not None:
            return self._detector
        with self._lock:
            if self._detector is not None:
                return self._detector
            try:
                self._detector = DetectionEngine.from_files(
                    self._model_report_path, self._policy_path
                )
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise DetectionUnavailableError(
                    "Verified detection models are unavailable"
                ) from error
            return self._detector
