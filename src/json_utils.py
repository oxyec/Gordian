"""Shared JSON file loading helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json_file(path: Path) -> Any:
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("JSON input exceeds the 64 MiB limit; split the dataset before loading")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def try_load_json_file(path: Path, *, default: Any) -> Any:
    try:
        return load_json_file(path)
    except (OSError, json.JSONDecodeError):
        return default
