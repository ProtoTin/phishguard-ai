"""Tests for model-facing processed-data loading."""

import json
from pathlib import Path

import pytest

from phishguard.modeling.data import load_labeled_text


def write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def test_loads_only_requested_content_type(tmp_path: Path) -> None:
    path = tmp_path / "split.jsonl"
    write_jsonl(
        path,
        [
            {"id": "e1", "content_type": "email", "text": "hello", "label": "legitimate"},
            {"id": "u1", "content_type": "url", "text": "https://bad", "label": "phishing"},
            {"id": "e2", "content_type": "email", "text": "verify", "label": "phishing"},
        ],
    )

    dataset = load_labeled_text(path, "email")

    assert dataset.texts == ["hello", "verify"]
    assert dataset.labels.tolist() == [0, 1]
    assert len(dataset) == 2


@pytest.mark.parametrize(
    ("records", "message"),
    [
        (
            [
                {"id": "same", "content_type": "email", "text": "one", "label": "legitimate"},
                {"id": "same", "content_type": "email", "text": "two", "label": "phishing"},
            ],
            "duplicate record ID",
        ),
        ([{"id": "x", "content_type": "email", "text": "", "label": "legitimate"}], "text"),
        ([{"id": "x", "content_type": "email", "text": "one", "label": "unknown"}], "label"),
        ([{"id": "x", "content_type": "url", "text": "one", "label": "phishing"}], "No email"),
    ],
)
def test_rejects_invalid_model_data(
    tmp_path: Path, records: list[dict[str, object]], message: str
) -> None:
    path = tmp_path / "invalid.jsonl"
    write_jsonl(path, records)

    with pytest.raises(ValueError, match=message):
        load_labeled_text(path, "email")
