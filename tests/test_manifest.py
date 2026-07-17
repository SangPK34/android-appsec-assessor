from __future__ import annotations

import json
import re
from pathlib import Path


def test_download_manifest_uses_https_and_sha256() -> None:
    root = Path(__file__).resolve().parent.parent
    manifest = json.loads((root / "config" / "tools.lock.json").read_text(encoding="utf-8"))

    for name, tool in manifest["tools"].items():
        assets = tool.get("assets")
        entries = assets.items() if isinstance(assets, dict) else ((name, tool),)
        for asset_name, asset in entries:
            label = f"{name}.{asset_name}" if asset_name != name else name
            assert asset["url"].startswith("https://"), label
            assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]), label
            assert asset["minimum_bytes"] > 0, label
            if "output_sha256" in asset:
                assert re.fullmatch(r"[0-9a-f]{64}", asset["output_sha256"]), label
                assert asset["output_minimum_bytes"] > 0, label
