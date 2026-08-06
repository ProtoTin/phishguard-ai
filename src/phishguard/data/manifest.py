"""Dataset source-manifest models and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlparse

ContentType = Literal["email", "url"]
DatasetRole = Literal["development", "external_test"]
SourceFormat = Literal[
    "curated_email_csv",
    "zenodo_tsv_in_xlsx",
    "zenodo_validation_csv",
    "uci_phiusiil_zip_csv",
]
SplitPolicy = Literal["train_validation", "external_test", "train_validation_test"]
Label = Literal["legitimate", "phishing"]


@dataclass(frozen=True)
class Checksum:
    """Expected digest for a downloaded source file."""

    algorithm: Literal["md5", "sha256"]
    value: str
    provenance: str


@dataclass(frozen=True)
class DatasetSource:
    """One trusted dataset declared by the project manifest."""

    id: str
    title: str
    content_type: ContentType
    role: DatasetRole
    format: SourceFormat
    url: str
    filename: str
    expected_bytes: int
    checksum: Checksum
    license: str
    license_url: str
    landing_page: str
    citation: str
    label_mapping: dict[str, Label]
    split_policy: SplitPolicy


def load_sources(path: Path) -> list[DatasetSource]:
    """Load and validate dataset sources from a JSON manifest."""

    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("manifest_version") != 1:
        raise ValueError("Unsupported data-source manifest version")

    sources = [_parse_source(item) for item in document.get("sources", [])]
    if not sources:
        raise ValueError("The data-source manifest contains no sources")
    if len({source.id for source in sources}) != len(sources):
        raise ValueError("Dataset source IDs must be unique")
    return sources


def _parse_source(item: object) -> DatasetSource:
    if not isinstance(item, dict):
        raise ValueError("Each dataset source must be a JSON object")

    required = {
        "id",
        "title",
        "content_type",
        "role",
        "format",
        "url",
        "filename",
        "expected_bytes",
        "checksum",
        "license",
        "license_url",
        "landing_page",
        "citation",
        "label_mapping",
        "split_policy",
    }
    missing = required - item.keys()
    if missing:
        raise ValueError(f"Dataset source is missing fields: {sorted(missing)}")

    for key in ("url", "license_url", "landing_page"):
        value = str(item[key])
        if urlparse(value).scheme != "https":
            raise ValueError(f"Dataset source {key} must use HTTPS")

    checksum_item = item["checksum"]
    if not isinstance(checksum_item, dict):
        raise ValueError("Dataset checksum must be a JSON object")
    algorithm = str(checksum_item.get("algorithm"))
    if algorithm not in {"md5", "sha256"}:
        raise ValueError(f"Unsupported checksum algorithm: {algorithm}")

    raw_mapping = item["label_mapping"]
    if not isinstance(raw_mapping, dict) or not raw_mapping:
        raise ValueError("Dataset label_mapping must be a non-empty object")
    label_mapping: dict[str, Label] = {}
    for source_label, target_label in raw_mapping.items():
        if target_label not in {"legitimate", "phishing"}:
            raise ValueError(f"Unsupported target label: {target_label}")
        label_mapping[str(source_label)] = cast(Label, target_label)

    return DatasetSource(
        id=str(item["id"]),
        title=str(item["title"]),
        content_type=cast(ContentType, item["content_type"]),
        role=cast(DatasetRole, item["role"]),
        format=cast(SourceFormat, item["format"]),
        url=str(item["url"]),
        filename=Path(str(item["filename"])).name,
        expected_bytes=int(item["expected_bytes"]),
        checksum=Checksum(
            algorithm=cast(Literal["md5", "sha256"], algorithm),
            value=str(checksum_item["value"]).lower(),
            provenance=str(checksum_item["provenance"]),
        ),
        license=str(item["license"]),
        license_url=str(item["license_url"]),
        landing_page=str(item["landing_page"]),
        citation=str(item["citation"]),
        label_mapping=label_mapping,
        split_policy=cast(SplitPolicy, item["split_policy"]),
    )
