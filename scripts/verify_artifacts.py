"""Verify and load the four trusted deployment artifacts."""

from pathlib import Path

from phishguard.detection.runtime import DetectionEngine


def main() -> None:
    """Fail unless every artifact matches its recorded digest and runtime contract."""

    engine = DetectionEngine.from_files(
        Path("reports/model-evaluation.json"),
        Path("config/detection-policy.json"),
    )
    if set(engine.base_models) != {"email", "url"}:
        raise RuntimeError("Expected verified email and URL base models")
    if set(engine.calibrated_models) != {"email", "url"}:
        raise RuntimeError("Expected verified email and URL calibrated models")
    print("verified email and URL base and calibrated artifacts")


if __name__ == "__main__":
    main()
