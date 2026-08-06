"""Tests for baseline training orchestration and reporting."""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Self

import numpy as np
import pytest
from numpy.typing import NDArray

from phishguard.modeling import training
from phishguard.modeling.data import LabeledText


class FakeModel:
    """Deterministic probabilistic model used to test orchestration."""

    def fit(self, texts: Sequence[str], labels: NDArray[np.int_]) -> Self:
        return self

    def predict_proba(self, texts: Sequence[str]) -> NDArray[np.float64]:
        positive = np.asarray([0.8 if "bad" in text else 0.2 for text in texts])
        return np.column_stack((1 - positive, positive))


class InvalidModel(FakeModel):
    def predict_proba(self, texts: Sequence[str]) -> NDArray[np.float64]:
        return np.asarray([0.5 for _ in texts])


def dataset() -> LabeledText:
    return LabeledText(
        texts=["safe message", "bad verify account"],
        labels=np.asarray([0, 1], dtype=np.int_),
    )


def test_probability_shape_validation() -> None:
    with pytest.raises(ValueError, match="two-column"):
        training.positive_probabilities(InvalidModel(), ["one"])


def test_train_task_persists_artifact_and_metrics(tmp_path: Path) -> None:
    artifact = tmp_path / "model.joblib"

    report = training.train_task(
        "email",
        lambda seed: FakeModel(),
        dataset(),
        dataset(),
        dataset(),
        artifact,
        seed=7,
    )

    assert artifact.exists()
    assert report["selected_threshold"] == 0.5
    metadata = report["artifact"]
    assert isinstance(metadata, dict)
    assert metadata["bytes"] == artifact.stat().st_size
    assert len(str(metadata["sha256"])) == 64


def test_markdown_report_contains_both_comparators(tmp_path: Path) -> None:
    result = {
        "test": {
            "samples": 2,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "pr_auc": 1.0,
            "false_positive_rate": 0.0,
        }
    }
    report: dict[str, object] = {"tasks": {"email": {"ml_model": result, "rule_baseline": result}}}
    path = tmp_path / "report.md"

    training.write_markdown_report(report, path)

    content = path.read_text()
    assert "| email | ML |" in content
    assert "| email | Rules |" in content


def write_split(path: Path, split: str) -> None:
    records = []
    for content_type in ("email", "url"):
        for index, (text, label) in enumerate(
            (("safe example", "legitimate"), ("bad verify login", "phishing"))
        ):
            records.append(
                {
                    "id": f"{content_type}-{split}-{index}",
                    "content_type": content_type,
                    "text": text,
                    "label": label,
                }
            )
    path.write_text("".join(json.dumps(record) + "\n" for record in records))


def test_train_all_writes_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    processed = tmp_path / "processed"
    processed.mkdir()
    for split in ("train", "validation", "test", "external_test"):
        write_split(processed / f"{split}.jsonl", split)
    monkeypatch.setattr(training, "build_email_model", lambda seed: FakeModel())
    monkeypatch.setattr(training, "build_url_model", lambda seed: FakeModel())

    report = training.train_all(
        processed,
        tmp_path / "artifacts",
        tmp_path / "report.json",
        tmp_path / "report.md",
        seed=7,
    )

    tasks = report["tasks"]
    assert isinstance(tasks, dict)
    assert set(tasks) == {"email", "url"}
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()
