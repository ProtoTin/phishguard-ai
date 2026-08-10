"""Calibrate baseline models and evaluate the advisory prevention policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import cast

import joblib
import numpy as np
from numpy.typing import NDArray
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator

from phishguard import __version__
from phishguard.detection.explanations import CalibratedModel, explain
from phishguard.detection.policy import decide, policy_document
from phishguard.modeling.baselines import BinaryProbabilisticModel
from phishguard.modeling.data import ContentType, LabeledText, load_labeled_text
from phishguard.modeling.metrics import binary_metrics
from phishguard.modeling.training import artifact_metadata, positive_probabilities


def verify_digest(path: Path, expected: str) -> None:
    """Verify a model artifact before any pickle-based loading occurs."""

    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError(f"Artifact digest mismatch for {path}")


def load_verified_model(path: Path, expected_digest: str) -> BinaryProbabilisticModel:
    """Load a trusted local artifact only after its digest matches the report."""

    verify_digest(path, expected_digest)
    return cast(BinaryProbabilisticModel, joblib.load(path))


def calibrated_probabilities(model: CalibratedModel, texts: list[str]) -> NDArray[np.float64]:
    matrix = np.asarray(model.predict_proba(texts), dtype=np.float64)
    if matrix.shape != (len(texts), 2):
        raise ValueError(f"Expected two-column calibrated probabilities, got {matrix.shape}")
    return matrix[:, 1]


def fit_sigmoid_calibrator(
    model: BinaryProbabilisticModel, validation: LabeledText
) -> CalibratedModel:
    """Fit sigmoid calibration using data not used to fit the base model."""

    # The estimator is frozen, so the folds only generate one held-out score for
    # each validation row; they never refit the already-trained base detector.
    # Two folds also keeps this helper usable for small, balanced smoke tests.
    calibrator = CalibratedClassifierCV(FrozenEstimator(model), method="sigmoid", cv=2)
    calibrator.fit(validation.texts, validation.labels)
    return cast(CalibratedModel, calibrator)


def expected_calibration_error(
    labels: NDArray[np.int_], probabilities: NDArray[np.float64], bins: int = 10
) -> float:
    """Calculate equal-width expected calibration error."""

    edges = np.linspace(0.0, 1.0, bins + 1)
    total = labels.size
    error = 0.0
    for index in range(bins):
        lower, upper = edges[index], edges[index + 1]
        mask = (
            (probabilities >= lower) & (probabilities < upper)
            if index < bins - 1
            else (probabilities >= lower) & (probabilities <= upper)
        )
        count = int(mask.sum())
        if not count:
            continue
        confidence = float(probabilities[mask].mean())
        observed = float(labels[mask].mean())
        error += count / total * abs(confidence - observed)
    return round(error, 6)


def action_distribution(probabilities: NDArray[np.float64]) -> dict[str, int]:
    """Count policy actions without exposing evaluated content."""

    counts: Counter[str] = Counter(
        decide(float(probability)).recommended_action for probability in probabilities
    )
    return {action: counts.get(action, 0) for action in ("allow", "warn", "quarantine", "block")}


def calibration_metrics(
    labels: NDArray[np.int_],
    raw: NDArray[np.float64],
    calibrated: NDArray[np.float64],
) -> dict[str, object]:
    """Compare raw and calibrated probability behavior at the policy threshold."""

    return {
        "raw": {
            **binary_metrics(labels, raw, 0.6),
            "expected_calibration_error": expected_calibration_error(labels, raw),
        },
        "calibrated": {
            **binary_metrics(labels, calibrated, 0.6),
            "expected_calibration_error": expected_calibration_error(labels, calibrated),
            "action_distribution": action_distribution(calibrated),
        },
    }


def calibrate_task(
    content_type: ContentType,
    base_model: BinaryProbabilisticModel,
    validation: LabeledText,
    test: LabeledText,
    artifact_path: Path,
) -> tuple[CalibratedModel, dict[str, object]]:
    """Fit, persist, and evaluate one validation-only calibrator."""

    calibrated_model = fit_sigmoid_calibrator(base_model, validation)
    raw_validation = positive_probabilities(base_model, validation.texts)
    calibrated_validation = calibrated_probabilities(calibrated_model, validation.texts)
    raw_test = positive_probabilities(base_model, test.texts)
    calibrated_test = calibrated_probabilities(calibrated_model, test.texts)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(calibrated_model, artifact_path, compress=3)
    return calibrated_model, {
        "content_type": content_type,
        "method": "sigmoid",
        "calibration_source": "validation split only",
        "validation": calibration_metrics(validation.labels, raw_validation, calibrated_validation),
        "test": calibration_metrics(test.labels, raw_test, calibrated_test),
        "artifact": artifact_metadata(artifact_path),
    }


def write_markdown(report: dict[str, object], path: Path) -> None:
    """Write a concise calibration and policy evaluation report."""

    tasks = report.get("tasks")
    if not isinstance(tasks, dict):
        raise TypeError("Expected tasks to be an object")
    lines = [
        "# Explanation and Prevention Policy Evaluation",
        "",
        "> Generated by `python scripts/build_detection_policy.py`. Calibration uses",
        "> validation data only; all prevention actions remain advisory.",
        "",
        "## Test-set calibration and policy results",
        "",
        "| Detector | Probability | Brier | ECE | Precision at 60 | Recall at 60 | FPR at 60 |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for task_name, task_value in tasks.items():
        if not isinstance(task_value, dict) or not isinstance(task_value.get("test"), dict):
            raise TypeError(f"Invalid task report for {task_name}")
        test = task_value["test"]
        for probability_type in ("raw", "calibrated"):
            metrics = test[probability_type]
            lines.append(
                f"| {task_name} | {probability_type} | {metrics['brier_score']} | "
                f"{metrics['expected_calibration_error']} | {metrics['precision']} | "
                f"{metrics['recall']} | {metrics['false_positive_rate']} |"
            )
    lines.extend(
        [
            "",
            "## Policy bands",
            "",
            "| Score | Classification | Advisory action |",
            "| ---: | --- | --- |",
            "| 0–29 | Legitimate | Allow with normal caution |",
            "| 30–59 | Suspicious | Warn and verify independently |",
            "| 60–84 | Phishing | Recommend quarantine and review |",
            "| 85–100 | Phishing | Recommend block or isolation |",
            "",
            "## Interpretation",
            "",
            "Calibration maps model output to validation-set event frequencies; it cannot fix",
            "dataset shift. The small external email test remains the most important warning:",
            "email scores may be overconfident on unfamiliar campaigns or writing styles.",
            "Actions are recommendations for a future interface, not automatic enforcement.",
            "",
            "## URL false-positive safeguard",
            "",
            "The URL model vectorizes the true hostname separately from the path and query.",
            "Policy 1.2 caps the score at 20 for exact HTTPS hosts in a pinned Tranco top-1000",
            "snapshot (with an optional `www` prefix). The safeguard does not match lookalikes",
            "or arbitrary subdomains. A missing scheme is analyzed as HTTPS instead of silently",
            "being treated as HTTP. Regression examples cover LinkedIn and YouTube variants,",
            "plus malicious URLs containing those brands only inside their paths.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def build_policy(
    processed_dir: Path,
    model_report_path: Path,
    artifact_dir: Path,
    policy_path: Path,
    report_path: Path,
    report_markdown_path: Path,
    examples_path: Path,
) -> dict[str, object]:
    """Build calibrated artifacts, a versioned policy, and aggregate evaluations."""

    model_report = json.loads(model_report_path.read_text(encoding="utf-8"))
    model_tasks = model_report.get("tasks")
    if not isinstance(model_tasks, dict):
        raise TypeError("Model evaluation report has no tasks object")

    task_inputs: dict[str, tuple[LabeledText, LabeledText]] = {
        "email": (
            load_labeled_text(processed_dir / "validation.jsonl", "email"),
            load_labeled_text(processed_dir / "external_test.jsonl", "email"),
        ),
        "url": (
            load_labeled_text(processed_dir / "validation.jsonl", "url"),
            load_labeled_text(processed_dir / "test.jsonl", "url"),
        ),
    }
    base_models: dict[str, BinaryProbabilisticModel] = {}
    calibrated_models: dict[str, CalibratedModel] = {}
    task_reports: dict[str, object] = {}
    for content_type in ("email", "url"):
        task = model_tasks[content_type]
        if not isinstance(task, dict) or not isinstance(task.get("artifact"), dict):
            raise TypeError(f"Invalid model report for {content_type}")
        artifact = task["artifact"]
        base_model = load_verified_model(Path(artifact["path"]), str(artifact["sha256"]))
        validation, test = task_inputs[content_type]
        calibrated_model, task_report = calibrate_task(
            content_type,
            base_model,
            validation,
            test,
            artifact_dir / f"{content_type}_calibrated.joblib",
        )
        base_models[content_type] = base_model
        calibrated_models[content_type] = calibrated_model
        task_reports[content_type] = task_report

    report: dict[str, object] = {
        "report_version": 1,
        "project_version": __version__,
        "policy": policy_document(),
        "tasks": task_reports,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_markdown(report, report_markdown_path)

    policy = {
        **policy_document(),
        "project_version": __version__,
        "calibration_method": "sigmoid fitted on validation data only",
        "models": {
            name: cast(dict[str, object], task_reports[name])["artifact"]
            for name in ("email", "url")
        },
    }
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")

    synthetic_examples = {
        "email_low_risk": "Subject: Project update\n\nThe team meeting begins Tuesday at 10 AM.",
        "email_high_risk": (
            "Subject: Urgent account warning\n\nClick here immediately to verify your account "
            "password or access will be suspended."
        ),
        "url_low_risk": "https://www.wikipedia.org/",
        "url_linkedin_www": "https://www.linkedin.com/feed/",
        "url_linkedin_apex": "https://linkedin.com/feed/",
        "url_linkedin_lookalike": "https://evil.test/redirect/linkedin.com/login/verify",
        "url_youtube_bare": "youtube.com",
        "url_youtube_www": "https://www.youtube.com/watch?v=example",
        "url_youtube_short": "https://youtu.be/example",
        "url_youtube_lookalike": "https://evil.test/redirect/youtube.com/login/verify",
        "url_high_risk": "http://192.0.2.10/login/verify-account/password",
    }
    examples = {
        name: explain(
            "email" if name.startswith("email") else "url",
            text,
            base_models["email" if name.startswith("email") else "url"],
            calibrated_models["email" if name.startswith("email") else "url"],
        )
        for name, text in synthetic_examples.items()
    }
    expected_classifications = {
        "email_low_risk": ("legitimate",),
        "email_high_risk": ("phishing",),
        "url_low_risk": ("legitimate",),
        "url_linkedin_www": ("legitimate",),
        "url_linkedin_apex": ("legitimate",),
        "url_linkedin_lookalike": ("suspicious", "phishing"),
        "url_youtube_bare": ("legitimate",),
        "url_youtube_www": ("legitimate",),
        "url_youtube_short": ("legitimate",),
        "url_youtube_lookalike": ("suspicious", "phishing"),
        "url_high_risk": ("suspicious", "phishing"),
    }
    for name, allowed in expected_classifications.items():
        actual = examples[name]["classification"]
        if actual not in allowed:
            raise RuntimeError(
                f"Example {name} was expected to be one of {allowed}, "
                f"but the policy returned {actual}"
            )
    examples_path.parent.mkdir(parents=True, exist_ok=True)
    examples_path.write_text(json.dumps(examples, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    """Build calibrated models and the advisory detection policy."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=Path("data/processed"))
    parser.add_argument("--model-report", type=Path, default=Path("reports/model-evaluation.json"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("artifacts/policy"))
    parser.add_argument("--policy", type=Path, default=Path("config/detection-policy.json"))
    parser.add_argument("--report", type=Path, default=Path("reports/policy-evaluation.json"))
    parser.add_argument(
        "--report-markdown", type=Path, default=Path("docs/explanations-and-policy.md")
    )
    parser.add_argument("--examples", type=Path, default=Path("reports/explanation-examples.json"))
    args = parser.parse_args()
    build_policy(
        args.processed_dir,
        args.model_report,
        args.artifact_dir,
        args.policy,
        args.report,
        args.report_markdown,
        args.examples,
    )
    print("built calibrated explanation and prevention policy")


if __name__ == "__main__":
    main()
