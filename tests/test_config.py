from __future__ import annotations

import json
from pathlib import Path

import pytest

from android_assessor.config import load_config
from android_assessor.errors import ConfigurationError
from android_assessor.paths import ProjectPaths


def write_config(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_accepts_localhost_and_high_port(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path)
    write_config(paths.config_file, {"web": {"host": "127.0.0.1", "port": 9000}})

    config = load_config(paths)

    assert config.web.port == 9000


@pytest.mark.parametrize("host", ["0.0.0.0", "localhost", "192.168.1.5"])
def test_rejects_non_loopback_bind(tmp_path: Path, host: str) -> None:
    paths = ProjectPaths(tmp_path)
    write_config(paths.config_file, {"web": {"host": host, "port": 8765}})

    with pytest.raises(ConfigurationError):
        load_config(paths)


def test_rejects_privileged_port(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path)
    write_config(paths.config_file, {"web": {"host": "127.0.0.1", "port": 80}})

    with pytest.raises(ConfigurationError):
        load_config(paths)
