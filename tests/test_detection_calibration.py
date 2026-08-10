"""Tests for calibration, artifact verification, and policy reporting."""

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pytest

from phishguard.detection.calibration import (
    action_distribution,
    build_policy,
    calibrated_probabilities,
    expected_calibration_error,
    fit_sigmoid_calibrator,
    verify_digest,
)
from phishguard.modeling.baselines import build_email_model, build_url_model
from phishguard.modeling.data import LabeledText


def email_training_data() -> LabeledText:
    return LabeledText(
        texts=[
            "team meeting project update",
            "team lunch project notes",
            "meeting notes and agenda",
            "weekly project planning",
            "urgent verify password account",
            "verify your account login",
            "urgent password reset login",
            "account suspended verify login",
        ],
        labels=np.asarray([0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int_),
    )


def url_training_data() -> LabeledText:
    return LabeledText(
        texts=[
            "https://example.com/docs/about",
            "https://example.com/docs/contact",
            "https://docs.example.org/docs/start",
            "https://docs.example.org/docs/guide",
            "http://bad.test/security/login/verify",
            "http://bad.test/security/login/password",
            "http://evil.test/security/account/verify",
            "http://evil.test/security/account/password",
        ],
        labels=np.asarray([0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int_),
    )


def test_calibration_helpers() -> None:
    labels = np.asarray([0, 0, 1, 1], dtype=np.int_)
    perfect = np.asarray([0.0, 0.0, 1.0, 1.0], dtype=np.float64)

    assert expected_calibration_error(labels, perfect) == 0.0
    assert action_distribution(np.asarray([0.1, 0.4, 0.7, 0.9])) == {
        "allow": 1,
        "warn": 1,
        "quarantine": 1,
        "block": 1,
    }


def test_sigmoid_calibrator_returns_probabilities() -> None:
    training = email_training_data()
    model = build_email_model(seed=7).fit(training.texts, training.labels)
    calibrated = fit_sigmoid_calibrator(model, training)

    probabilities = calibrated_probabilities(calibrated, training.texts)

    assert probabilities.shape == (len(training),)
    assert np.all((probabilities >= 0) & (probabilities <= 1))


def test_verify_digest_rejects_changed_artifact(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"trusted")
    digest = hashlib.sha256(b"trusted").hexdigest()

    verify_digest(path, digest)
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_digest(path, digest)


def write_processed_split(path: Path, split: str) -> None:
    records = []
    for content_type, dataset in (
        ("email", email_training_data()),
        ("url", url_training_data()),
    ):
        for index, (text, label) in enumerate(zip(dataset.texts, dataset.labels, strict=True)):
            records.append(
                {
                    "id": f"{content_type}-{split}-{index}",
                    "content_type": content_type,
                    "text": text,
                    "label": "phishing" if label else "legitimate",
                }
            )
    path.write_text("".join(json.dumps(record) + "\n" for record in records))


def test_complete_policy_build(tmp_path: Path) -> None:
    processed = tmp_path / "processed"
    models = tmp_path / "models"
    processed.mkdir()
    models.mkdir()
    for split in ("validation", "test", "external_test"):
        write_processed_split(processed / f"{split}.jsonl", split)

    email_data = email_training_data()
    url_data = url_training_data()
    base_models = {
        "email": build_email_model(seed=7).fit(email_data.texts, email_data.labels),
        "url": build_url_model(seed=7).fit(url_data.texts, url_data.labels),
    }
    tasks = {}
    for name, model in base_models.items():
        path = models / f"{name}.joblib"
        joblib.dump(model, path)
        tasks[name] = {
            "artifact": {
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        }
    model_report = tmp_path / "model-report.json"
    model_report.write_text(json.dumps({"tasks": tasks}))

    report = build_policy(
        processed,
        model_report,
        tmp_path / "calibrated",
        tmp_path / "policy.json",
        tmp_path / "policy-report.json",
        tmp_path / "policy-report.md",
        tmp_path / "examples.json",
    )

    report_tasks = report["tasks"]
    assert isinstance(report_tasks, dict)
    assert set(report_tasks) == {"email", "url"}
    assert (tmp_path / "policy.json").exists()
    assert (tmp_path / "policy-report.md").exists()
    examples = json.loads((tmp_path / "examples.json").read_text())
    assert set(examples) == {
        "email_low_risk",
        "email_high_risk",
        "url_low_risk",
        "url_linkedin_www",
        "url_linkedin_apex",
        "url_linkedin_lookalike",
        "url_youtube_bare",
        "url_youtube_www",
        "url_youtube_short",
        "url_youtube_lookalike",
        "url_unverified",
        "url_high_risk",
    }
    assert examples["email_low_risk"]["classification"] == "legitimate"
    assert examples["email_high_risk"]["classification"] == "phishing"
    assert examples["url_low_risk"]["classification"] == "legitimate"
    assert examples["url_high_risk"]["classification"] in {"suspicious", "phishing"}
    assert examples["url_linkedin_www"]["classification"] == "legitimate"
    assert examples["url_linkedin_apex"]["classification"] == "legitimate"
    assert examples["url_linkedin_lookalike"]["classification"] != "legitimate"
    assert examples["url_youtube_bare"]["classification"] == "legitimate"
    assert examples["url_youtube_www"]["classification"] == "legitimate"
    assert examples["url_youtube_short"]["classification"] == "legitimate"
    assert examples["url_youtube_lookalike"]["classification"] != "legitimate"
    assert examples["url_unverified"]["classification"] == "unverified"
