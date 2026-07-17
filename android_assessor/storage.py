"""Small atomic JSON and JSONL helpers rooted inside the project."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from .errors import SessionError
from .redaction import redact_data


def require_under_root(path: Path, root: Path) -> Path:
    resolved = path.expanduser().resolve()
    project_root = root.expanduser().resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError as exc:
        raise SessionError(f"Path is outside project root: {resolved}") from exc
    return resolved


def write_json_atomic(path: Path, value: Any, *, root: Path) -> None:
    target = require_under_root(path, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.part")
    try:
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def write_text_atomic(path: Path, value: str, *, root: Path) -> None:
    target = require_under_root(path, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.part")
    try:
        temporary.write_text(value, encoding="utf-8", newline="\n")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def read_json_object(path: Path, *, root: Path) -> dict[str, Any]:
    source = require_under_root(path, root)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SessionError(f"JSON file not found: {source}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"Could not read JSON file {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise SessionError(f"Expected a JSON object in {source}")
    return value


def append_jsonl(
    path: Path,
    value: Mapping[str, Any],
    *,
    root: Path,
    redact: bool = True,
) -> None:
    target = require_under_root(path, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = redact_data(dict(value)) if redact else dict(value)
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
