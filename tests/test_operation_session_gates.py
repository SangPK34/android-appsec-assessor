from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor.errors import SessionError
from android_assessor.frida_controller import FridaController
from android_assessor.paths import ProjectPaths
from android_assessor.services.validation_service import ValidationService
from android_assessor.session import SessionRepository
from android_assessor.traffic import TrafficCaptureService


class NoAdbContext:
    def __init__(self, paths: ProjectPaths) -> None:
        self.paths = paths
        self.config = object()
        self.adb_calls = 0

    def adb_client(self, **_kwargs: object) -> object:
        self.adb_calls += 1
        raise AssertionError("Inactive sessions must fail before ADB is requested.")


def inactive_session(tmp_path: Path) -> tuple[NoAdbContext, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        "devices: [ABC123]\n"
        "packages: [com.example.app]\n"
        "api_hosts: [127.0.0.1]\n"
        "allowed_actions: [traffic_capture, frida_observe, controlled_validation]\n",
        encoding="utf-8",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    return NoAdbContext(paths), repository, record.session_id


def test_traffic_start_refuses_inactive_session_before_adb(tmp_path: Path) -> None:
    context, repository, session_id = inactive_session(tmp_path)

    with pytest.raises(SessionError, match="active session"):
        TrafficCaptureService(context, repository).start(session_id)  # type: ignore[arg-type]

    assert context.adb_calls == 0


def test_frida_start_refuses_inactive_session_before_adb(tmp_path: Path) -> None:
    context, repository, session_id = inactive_session(tmp_path)

    with pytest.raises(SessionError, match="active session"):
        FridaController(context, repository).start(session_id)  # type: ignore[arg-type]

    assert context.adb_calls == 0


def test_validation_refuses_inactive_session_before_adb(tmp_path: Path) -> None:
    context, repository, session_id = inactive_session(tmp_path)

    with pytest.raises(SessionError, match="active session"):
        ValidationService(context, repository).validate(  # type: ignore[arg-type]
            session_id,
            "finding-asl-mvp-002",
        )

    assert context.adb_calls == 0
