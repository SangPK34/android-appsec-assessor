from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "android"


def load_fixture(relative_path: str) -> dict[str, Any]:
    source = (FIXTURE_ROOT / relative_path).resolve()
    try:
        source.relative_to(FIXTURE_ROOT.resolve())
    except ValueError as exc:
        raise ValueError("Fixture path escapes tests/fixtures/android.") from exc
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Android fixture must be a JSON object.")
    if payload.get("source") != "fixture" or payload.get("environment") != "simulated":
        raise ValueError("Android fixtures require fixture/simulated provenance.")
    return payload
