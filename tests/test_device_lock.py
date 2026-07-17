from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from threading import Thread

import pytest

from android_assessor.device_lock import DeviceLock
from android_assessor.errors import DeviceBusyError
from android_assessor.paths import ProjectPaths
from android_assessor.services.scan_service import ScanService
from android_assessor.session import SessionRepository


def test_device_lock_blocks_second_modifying_owner(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()

    with DeviceLock(paths, "ABC123", operation="scan") as first:
        assert first.metadata_path.is_file()
        with pytest.raises(DeviceBusyError, match="busy"):
            with DeviceLock(paths, "ABC123", operation="cleanup"):
                pass

    assert not first.metadata_path.exists()


def test_different_devices_have_independent_locks(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()

    with DeviceLock(paths, "ABC123", operation="scan"):
        with DeviceLock(paths, "XYZ987", operation="scan") as second:
            assert second.acquired is True


def test_device_lock_is_reentrant_only_for_same_session_and_thread(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    session_id = "20260717-021530-a8f4c2"
    errors: list[Exception] = []

    with DeviceLock(
        paths,
        "ABC123",
        operation="scan",
        session_id=session_id,
    ):
        with DeviceLock(
            paths,
            "ABC123",
            operation="nested_traffic",
            session_id=session_id,
        ) as nested:
            assert nested.reentrant is True

        def competing_request() -> None:
            try:
                with DeviceLock(
                    paths,
                    "ABC123",
                    operation="validation",
                    session_id=session_id,
                ):
                    pass
            except Exception as exc:  # captured for assertion in the test thread
                errors.append(exc)

        thread = Thread(target=competing_request)
        thread.start()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], DeviceBusyError)


def test_competing_scan_fails_before_any_device_subprocess(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        "devices: [ABC123]\npackages: [com.example.app]\napi_hosts: []\n",
        encoding="utf-8",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    repository.activate(
        record.session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURED_EMPTY",
            "http_proxy_error": None,
        },
        device={},
        environment={},
    )
    adb_calls: list[str] = []

    class Context:
        def __init__(self) -> None:
            self.paths = paths

        def adb_client(self, **_kwargs: object) -> object:
            adb_calls.append("adb_client")
            return object()

    errors: list[Exception] = []
    with DeviceLock(
        paths,
        record.serial,
        operation="active_scan",
        session_id=record.session_id,
    ):
        thread = Thread(
            target=lambda: _capture_error(
                errors,
                lambda: ScanService(
                    Context(),  # type: ignore[arg-type]
                    repository,
                ).scan_session(record.session_id),
            )
        )
        thread.start()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], DeviceBusyError)
    assert adb_calls == []


def _capture_error(errors: list[Exception], operation: Callable[[], object]) -> None:
    try:
        operation()
    except Exception as exc:
        errors.append(exc)
