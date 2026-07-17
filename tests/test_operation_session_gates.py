from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from android_assessor.errors import ProxyError, SessionError
from android_assessor.frida_controller import FridaController
from android_assessor.paths import ProjectPaths
from android_assessor.services.validation_service import ValidationService
from android_assessor.session import (
    CleanupActionType,
    SessionRepository,
    SessionStatus,
)
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


def test_cleanup_required_state_remains_open_for_same_session_workflow(
    tmp_path: Path,
) -> None:
    context, repository, session_id = inactive_session(tmp_path)
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.STOP_HOST_PROCESS,
        {"role": "fixture", "identity": {}},
    )

    with pytest.raises(ProxyError, match="original state was not captured"):
        TrafficCaptureService(context, repository).start(session_id)  # type: ignore[arg-type]

    assert context.adb_calls == 0


@pytest.mark.parametrize(
    "status",
    [
        SessionStatus.INITIALIZING,
        SessionStatus.CLEANING,
        SessionStatus.CLEANED,
        SessionStatus.CLEANUP_FAILED,
        SessionStatus.ERROR,
    ],
)
def test_modifying_session_slot_rejects_closed_or_transitional_states(
    tmp_path: Path,
    status: SessionStatus,
) -> None:
    _context, repository, session_id = inactive_session(tmp_path)
    repository.set_status(session_id, status)

    with pytest.raises(SessionError, match="active session"):
        repository.require_modifying_session_slot("ABC123", session_id)


def test_traffic_rechecks_session_state_after_acquiring_device_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, repository, session_id = inactive_session(tmp_path)
    repository.activate(
        session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURED_EMPTY",
            "http_proxy_error": None,
        },
        device={},
        environment={},
    )
    hooks = context.paths.root / "hooks"
    hooks.mkdir()
    (hooks / "mitm_capture.py").write_text("# fixed fixture addon\n", encoding="utf-8")

    class ClosingDeviceLock:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def __enter__(self) -> ClosingDeviceLock:
            repository.set_status(session_id, SessionStatus.ERROR)
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

    monkeypatch.setattr("android_assessor.traffic.DeviceLock", ClosingDeviceLock)
    monkeypatch.setattr(
        "android_assessor.traffic.resolve_binary",
        lambda *_args, **_kwargs: SimpleNamespace(path=tmp_path / "mitmdump.exe"),
    )
    monkeypatch.setattr(TrafficCaptureService, "_free_port", staticmethod(lambda: 18765))

    with pytest.raises(SessionError, match="active session"):
        TrafficCaptureService(context, repository).start(  # type: ignore[arg-type]
            session_id,
            launch_app=False,
        )

    assert context.adb_calls == 0
