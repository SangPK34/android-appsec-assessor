from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor import environment
from android_assessor.config import LabConfig
from android_assessor.environment import ToolSpec, resolve_binary
from android_assessor.models import ComponentStatus
from android_assessor.paths import ProjectPaths
from android_assessor.subprocess_utils import CommandResult

SPEC = ToolSpec(
    name="adb",
    config_key="adb",
    executable_name="adb.exe",
    portable_paths=("tools/platform-tools/adb.exe",),
    version_arguments=("version",),
)


def touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"test")


def test_configured_binary_wins(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path)
    configured = paths.root / "custom" / "adb.exe"
    portable = paths.root / "tools" / "platform-tools" / "adb.exe"
    touch(configured)
    touch(portable)
    config = LabConfig(tools={"adb": "custom/adb.exe"})

    result = resolve_binary(SPEC, paths, config, user_path="")

    assert result is not None
    assert result.path == configured.resolve()
    assert result.source == "configured"


def test_portable_binary_wins_over_user_path(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "project")
    portable = paths.root / "tools" / "platform-tools" / "adb.exe"
    user_binary = tmp_path / "user-bin" / "adb.exe"
    touch(portable)
    touch(user_binary)

    result = resolve_binary(SPEC, paths, LabConfig(), user_path=str(user_binary.parent))

    assert result is not None
    assert result.path == portable.resolve()
    assert result.source == "portable"


@pytest.mark.parametrize(
    ("exit_code", "expected_status"),
    ((0, ComponentStatus.OK), (1, ComponentStatus.ERROR)),
)
def test_python_dependency_consistency(
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    expected_status: ComponentStatus,
) -> None:
    result = CommandResult(
        arguments=("python.exe", "-m", "pip", "check"),
        exit_code=exit_code,
        stdout="No broken requirements found." if exit_code == 0 else "",
        stderr="broken dependency" if exit_code else "",
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=False,
    )
    monkeypatch.setattr(environment, "run_command", lambda *_args, **_kwargs: result)

    check = environment._check_python_dependencies()

    assert check.status is expected_status
    assert check.required is True
