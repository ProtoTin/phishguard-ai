"""Tests for the versioned dataset source manifest."""

import json
from pathlib import Path

import pytest

from phishguard.data.manifest import load_sources


def valid_document() -> dict[str, object]:
    return {
        "manifest_version": 1,
        "sources": [
            {
                "id": "example",
                "title": "Example dataset",
                "content_type": "email",
                "role": "development",
                "format": "zenodo_validation_csv",
                "url": "https://example.com/data.csv",
                "filename": "data.csv",
                "expected_bytes": 10,
                "checksum": {
                    "algorithm": "sha256",
                    "value": "abc123",
                    "provenance": "test",
                },
                "license": "CC BY 4.0",
                "license_url": "https://creativecommons.org/licenses/by/4.0/",
                "landing_page": "https://example.com/dataset",
                "citation": "Example citation",
                "label_mapping": {"safe": "legitimate", "bad": "phishing"},
                "split_policy": "train_validation",
            }
        ],
    }


def write_document(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "sources.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_project_manifest_is_valid() -> None:
    sources = load_sources(Path("data/sources.json"))

    assert [source.id for source in sources] == [
        "zenodo_curated_enron_2023",
        "zenodo_social_engineering_2025",
        "zenodo_phishing_validation_2024",
        "uci_phiusiil_2024",
    ]
    assert all(source.license == "CC BY 4.0" for source in sources)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda doc: doc.update(manifest_version=2), "Unsupported"),
        (lambda doc: doc.update(sources=[]), "contains no sources"),
        (lambda doc: doc.update(sources=["invalid"]), "JSON object"),
    ],
)
def test_rejects_invalid_manifest_root(tmp_path: Path, mutate: object, message: str) -> None:
    document = valid_document()
    mutate(document)  # type: ignore[operator]

    with pytest.raises(ValueError, match=message):
        load_sources(write_document(tmp_path, document))


def test_rejects_duplicate_ids(tmp_path: Path) -> None:
    document = valid_document()
    sources = document["sources"]
    assert isinstance(sources, list)
    sources.append(dict(sources[0]))

    with pytest.raises(ValueError, match="unique"):
        load_sources(write_document(tmp_path, document))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (("remove", "citation", None), "missing fields"),
        (("set", "url", "http://example.com"), "must use HTTPS"),
        (("set", "checksum", "bad"), "checksum must be"),
        (
            (
                "set",
                "checksum",
                {"algorithm": "sha1", "value": "a", "provenance": "test"},
            ),
            "Unsupported checksum",
        ),
        (("set", "label_mapping", {}), "non-empty"),
        (("set", "label_mapping", {"x": "unknown"}), "Unsupported target"),
    ],
)
def test_rejects_invalid_source_fields(
    tmp_path: Path, change: tuple[str, str, object], message: str
) -> None:
    document = valid_document()
    sources = document["sources"]
    assert isinstance(sources, list)
    source = sources[0]
    assert isinstance(source, dict)
    operation, field, value = change
    if operation == "remove":
        source.pop(field)
    else:
        source[field] = value

    with pytest.raises(ValueError, match=message):
        load_sources(write_document(tmp_path, document))
