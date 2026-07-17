from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor.errors import ConfigurationError
from android_assessor.paths import ProjectPaths


def test_layout_supports_spaces_and_unicode(tmp_path: Path) -> None:
    root = tmp_path / "Android Lab có dấu"
    paths = ProjectPaths(root)

    paths.ensure_layout()

    assert paths.logs_dir.is_dir()
    assert paths.results_dir.is_dir()
    assert paths.root == root.resolve()


def test_relative_config_path_is_project_rooted(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")

    resolved = paths.from_config("tools/platform-tools/adb.exe")

    assert resolved == (paths.root / "tools/platform-tools/adb.exe").resolve()


def test_rejects_output_outside_project(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")

    with pytest.raises(ConfigurationError):
        paths.require_inside_root(tmp_path / "outside.json")
