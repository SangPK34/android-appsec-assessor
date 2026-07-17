from __future__ import annotations

from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from android_assessor.adb import AdbDevice, ReverseMapping
from android_assessor.cleanup import CleanupExecutor
from android_assessor.device_lock import DeviceLock
from android_assessor.errors import DeviceBusyError, ProxyError
from android_assessor.host_process import ProcessIdentity
from android_assessor.paths import ProjectPaths
from android_assessor.services.cleanup_service import CleanupService
from android_assessor.session import (
    CleanupActionStatus,
    CleanupActionType,
    SessionRepository,
    SessionStatus,
)
from android_assessor.subprocess_utils import CommandResult
from android_assessor.traffic import TrafficCaptureService


def result(*, exit_code: int = 0, stdout: str = "") -> CommandResult:
    return CommandResult(
        arguments=(),
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=False,
    )


class FakeAdb:
    def __init__(self) -> None:
        self.proxy: str | None = "127.0.0.1:8080"
        self.mappings = [ReverseMapping("tcp:8080", "tcp:8080")]
        self.operations: list[str] = []

    def require_authorized_device(self, serial: str) -> AdbDevice:
        return AdbDevice(serial, "device")

    def get_setting(self, serial: str, namespace: str, key: str) -> str | None:
        del serial, namespace, key
        return self.proxy

    def delete_setting(self, serial: str, namespace: str, key: str) -> None:
        del serial, namespace, key
        self.operations.append("delete_proxy")
        self.proxy = None

    def put_setting(self, serial: str, namespace: str, key: str, value: str) -> None:
        del serial, namespace, key
        self.operations.append(f"put_proxy:{value}")
        self.proxy = value

    def list_reverse(self, serial: str) -> list[ReverseMapping]:
        del serial
        return list(self.mappings)

    def remove_reverse(self, serial: str, remote: str) -> None:
        del serial
        self.operations.append(f"remove_reverse:{remote}")
        self.mappings = [mapping for mapping in self.mappings if mapping.remote != remote]

    def shell(self, serial: str, arguments: tuple[str, ...], **_kwargs: object) -> CommandResult:
        del serial
        self.operations.append("shell:" + " ".join(arguments))
        return result()


class FakeProcessController:
    def __init__(self) -> None:
        self.terminated: list[ProcessIdentity] = []

    def terminate_owned(self, identity: ProcessIdentity) -> bool:
        self.terminated.append(identity)
        return True


def prepared_session(tmp_path: Path) -> tuple[ProjectPaths, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
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
    return paths, repository, record.session_id


def test_cleanup_runs_reverse_order_and_is_idempotent(tmp_path: Path) -> None:
    paths, repository, session_id = prepared_session(tmp_path)
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.RESTORE_PROXY,
        {
            "previous_proxy": None,
            "applied_proxy": "127.0.0.1:8080",
            "ownership_state": "owned",
        },
    )
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.REMOVE_REVERSE,
        {
            "reverse_remote": "tcp:8080",
            "reverse_local": "tcp:8080",
            "ownership_state": "owned",
        },
    )
    adb = FakeAdb()
    executor = CleanupExecutor(paths, repository, adb)  # type: ignore[arg-type]

    first = executor.cleanup(session_id)
    operations_after_first = list(adb.operations)
    second = executor.cleanup(session_id)

    assert first.success is True
    assert first.status == SessionStatus.CLEANED.value
    assert adb.operations == ["remove_reverse:tcp:8080", "delete_proxy"]
    assert second.success is True
    assert adb.operations == operations_after_first
    assert all(
        action.status in {CleanupActionStatus.COMPLETED, CleanupActionStatus.SKIPPED}
        for action in repository.load(session_id).cleanup_actions
    )


def test_cleanup_rejects_remote_file_outside_managed_directory(tmp_path: Path) -> None:
    paths, repository, session_id = prepared_session(tmp_path)
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.REMOVE_REMOTE_FILE,
        {"path": "/data/local/tmp/not-owned.txt"},
    )
    adb = FakeAdb()

    cleanup = CleanupExecutor(paths, repository, adb).cleanup(session_id)  # type: ignore[arg-type]

    assert cleanup.success is False
    assert cleanup.actions[0].status == CleanupActionStatus.FAILED.value
    assert not any(operation.startswith("shell:rm") for operation in adb.operations)


def test_host_process_cleanup_checks_role_and_identity(tmp_path: Path) -> None:
    paths, repository, session_id = prepared_session(tmp_path)
    executable = paths.tools_dir / "scrcpy" / "scrcpy.exe"
    identity = ProcessIdentity(pid=1234, executable=str(executable), creation_filetime=99)
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.STOP_HOST_PROCESS,
        {"role": "scrcpy", "identity": identity.to_dict()},
    )
    process_controller = FakeProcessController()

    cleanup = CleanupExecutor(
        paths,
        repository,
        FakeAdb(),  # type: ignore[arg-type]
        process_controller=process_controller,  # type: ignore[arg-type]
    ).cleanup(session_id)

    assert cleanup.success is True
    assert process_controller.terminated == [identity]


def test_cleanup_preserves_externally_changed_proxy_and_reverse(tmp_path: Path) -> None:
    paths, repository, session_id = prepared_session(tmp_path)
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.RESTORE_PROXY,
        {
            "previous_proxy": None,
            "applied_proxy": "proxy-a:8080",
            "ownership_state": "owned",
        },
    )
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.REMOVE_REVERSE,
        {
            "reverse_remote": "tcp:8080",
            "reverse_local": "tcp:8080",
            "ownership_state": "owned",
        },
    )
    adb = FakeAdb()
    adb.proxy = "proxy-b:8888"
    adb.mappings = [ReverseMapping("tcp:8080", "tcp:9090")]

    cleanup = CleanupExecutor(paths, repository, adb).cleanup(session_id)  # type: ignore[arg-type]

    assert cleanup.success is False
    assert adb.proxy == "proxy-b:8888"
    assert adb.mappings == [ReverseMapping("tcp:8080", "tcp:9090")]
    assert adb.operations == []
    assert {action.status for action in repository.load(session_id).cleanup_actions} == {
        CleanupActionStatus.CONFLICT
    }


def test_failed_proxy_snapshot_blocks_start_and_cleanup_mutation(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        "devices: [ABC123]\npackages: [com.example.app]\napi_hosts: []\n"
        "allowed_actions: [traffic_capture]\n",
        encoding="utf-8",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    repository.activate(
        record.session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURE_FAILED",
            "http_proxy_error": "settings read failed",
        },
        device={},
        environment={},
    )
    repository.record_cleanup_action(
        record.session_id,
        CleanupActionType.RESTORE_PROXY,
        {},
    )
    adb = FakeAdb()
    adb.proxy = "host:8888"
    context = SimpleNamespace(paths=paths, config={})

    with pytest.raises(ProxyError, match="original state was not captured"):
        TrafficCaptureService(
            context,  # type: ignore[arg-type]
            repository,
        ).start(record.session_id)
    cleanup = CleanupExecutor(paths, repository, adb).cleanup(record.session_id)  # type: ignore[arg-type]

    assert cleanup.success is False
    assert adb.proxy == "host:8888"
    assert not any(
        operation.startswith(("put_proxy:", "delete_proxy"))
        for operation in adb.operations
    )


def test_cleanup_service_holds_device_lock_for_entire_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, repository, session_id = prepared_session(tmp_path)
    entered = Event()
    release = Event()
    errors: list[Exception] = []

    class Context:
        def __init__(self) -> None:
            self.paths = paths

        def adb_client(self, **_kwargs: object) -> FakeAdb:
            return FakeAdb()

    class BlockingFrida:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def load_state(self, _session_id: str) -> None:
            entered.set()
            assert release.wait(timeout=5)
            return None

    class NoTraffic:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def load_state(self, _session_id: str) -> None:
            return None

    monkeypatch.setattr(
        "android_assessor.services.cleanup_service.FridaController",
        BlockingFrida,
    )
    monkeypatch.setattr(
        "android_assessor.services.cleanup_service.TrafficCaptureService",
        NoTraffic,
    )

    def run_cleanup() -> None:
        try:
            CleanupService(
                Context(),  # type: ignore[arg-type]
                repository,
            ).cleanup(session_id)
        except Exception as exc:
            errors.append(exc)

    worker = Thread(target=run_cleanup)
    worker.start()
    assert entered.wait(timeout=5)
    record = repository.load(session_id)
    try:
        with pytest.raises(DeviceBusyError):
            with DeviceLock(
                paths,
                record.serial,
                operation="competing_scan",
                session_id=session_id,
            ):
                pass
    finally:
        release.set()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert errors == []
