"""Load normalized Phase 2 records for model development."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import numpy as np
from numpy.typing import NDArray

ContentType = Literal["email", "url"]


@dataclass(frozen=True)
class LabeledText:
    """In-memory text and binary labels for one content type and split."""

    texts: list[str]
    labels: NDArray[np.int_]

    def __len__(self) -> int:
        return len(self.texts)


def load_labeled_text(path: Path, content_type: ContentType) -> LabeledText:
    """Load one JSONL split and validate its model-facing fields."""

    texts: list[str] = []
    labels: list[int] = []
    seen_ids: set[str] = set()
    with path.open(encoding="utf-8") as source_file:
        for line_number, line in enumerate(source_file, start=1):
            record = json.loads(line)
            if record.get("content_type") != content_type:
                continue
            record_id = str(record.get("id", ""))
            text = record.get("text")
            label = record.get("label")
            if not record_id or record_id in seen_ids:
                raise ValueError(f"Invalid or duplicate record ID at {path}:{line_number}")
            if not isinstance(text, str) or not text:
                raise ValueError(f"Invalid text at {path}:{line_number}")
            if label not in {"legitimate", "phishing"}:
                raise ValueError(f"Invalid label at {path}:{line_number}")
            seen_ids.add(record_id)
            texts.append(text)
            labels.append(1 if label == "phishing" else 0)
    if not texts:
        raise ValueError(f"No {content_type} records found in {path}")
    return LabeledText(texts=texts, labels=np.asarray(labels, dtype=np.int_))
