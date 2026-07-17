from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor.adb import AdbDevice
from android_assessor.cleanup import CleanupExecutor, RemoteProcessIdentity
from android_assessor.paths import ProjectPaths
from android_assessor.session import (
    CleanupActionStatus,
    CleanupActionType,
    SessionRepository,
)
from android_assessor.subprocess_utils import CommandResult


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


def proc_stat(pid: int, start_time: str) -> str:
    fields = ["S", *(["0"] * 18), start_time]
    return f"{pid} (frida-server) " + " ".join(fields)


class RemoteAdb:
    def __init__(
        self,
        *,
        pid: int,
        executable: str,
        start_time: str,
        command_line: str,
        kill_effective: bool = True,
        existence_probe_fails: bool = False,
    ) -> None:
        self.pid = pid
        self.executable = executable
        self.start_time = start_time
        self.command_line = command_line
        self.kill_effective = kill_effective
        self.existence_probe_fails = existence_probe_fails
        self.exists = True
        self.kill_calls = 0

    def require_authorized_device(self, serial: str) -> AdbDevice:
        return AdbDevice(serial, "device")

    def shell(self, serial: str, arguments: tuple[str, ...], **_kwargs: object) -> CommandResult:
        del serial
        command = arguments[2] if len(arguments) == 3 else ""
        existence_command = (
            f"if [ -d /proc/{self.pid} ]; then echo EXISTS; else echo MISSING; fi"
        )
        if command == existence_command:
            if self.existence_probe_fails:
                return result(exit_code=1)
            return result(stdout="EXISTS\n" if self.exists else "MISSING\n")
        if command == f"readlink /proc/{self.pid}/exe":
            return result(stdout=self.executable + "\n")
        if command == f"cat /proc/{self.pid}/stat":
            return result(stdout=proc_stat(self.pid, self.start_time) + "\n")
        if command == f"cat /proc/{self.pid}/cmdline":
            return result(stdout=self.command_line)
        if command == f"kill {self.pid}":
            self.kill_calls += 1
            if self.kill_effective:
                self.exists = False
            return result()
        raise AssertionError(f"Unexpected shell command: {arguments}")


def prepared_process_session(
    tmp_path: Path,
) -> tuple[ProjectPaths, SessionRepository, str, int, str, dict[str, object]]:
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
    pid = 4242
    remote = f"/data/local/tmp/android-security-lab/{record.session_id}/frida-server"
    identity = RemoteProcessIdentity(
        pid=pid,
        executable_path=remote,
        proc_exe=remote,
        proc_start_time="100",
        command_line=remote + "\x00",
    )
    payload = identity.to_cleanup_payload(
        session_id=record.session_id,
        name="frida-server",
        started_at="2026-07-17T00:00:00+00:00",
    )
    return paths, repository, record.session_id, pid, remote, payload


@pytest.mark.parametrize(
    ("actual_executable", "actual_start"),
    [
        (None, "200"),
        ("similar", "100"),
    ],
)
def test_frida_cleanup_refuses_pid_reuse_and_similar_process_name(
    tmp_path: Path,
    actual_executable: str | None,
    actual_start: str,
) -> None:
    paths, repository, session_id, pid, remote, payload = prepared_process_session(tmp_path)
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.STOP_REMOTE_PROCESS,
        payload,
    )
    executable = remote if actual_executable is None else remote + "-helper"
    adb = RemoteAdb(
        pid=pid,
        executable=executable,
        start_time=actual_start,
        command_line=executable + "\x00",
    )

    cleanup = CleanupExecutor(paths, repository, adb).cleanup(session_id)  # type: ignore[arg-type]

    assert cleanup.success is False
    assert adb.kill_calls == 0
    assert repository.load(session_id).cleanup_actions[0].status is CleanupActionStatus.FAILED


def test_frida_cleanup_reports_failure_when_kill_has_no_effect(tmp_path: Path) -> None:
    paths, repository, session_id, pid, remote, payload = prepared_process_session(tmp_path)
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.STOP_REMOTE_PROCESS,
        payload,
    )
    adb = RemoteAdb(
        pid=pid,
        executable=remote,
        start_time="100",
        command_line=remote + "\x00",
        kill_effective=False,
    )

    cleanup = CleanupExecutor(
        paths,
        repository,
        adb,  # type: ignore[arg-type]
        remote_process_timeout=0.02,
    ).cleanup(session_id)

    assert cleanup.success is False
    assert adb.kill_calls == 1
    assert adb.exists is True


def test_preexisting_frida_server_without_session_action_is_not_stopped(
    tmp_path: Path,
) -> None:
    paths, repository, session_id, pid, remote, _payload = prepared_process_session(tmp_path)
    adb = RemoteAdb(
        pid=pid,
        executable=remote,
        start_time="100",
        command_line=remote + "\x00",
    )

    cleanup = CleanupExecutor(paths, repository, adb).cleanup(session_id)  # type: ignore[arg-type]

    assert cleanup.success is True
    assert adb.kill_calls == 0
    assert adb.exists is True


def test_frida_cleanup_does_not_treat_probe_failure_as_process_exit(
    tmp_path: Path,
) -> None:
    paths, repository, session_id, pid, remote, payload = prepared_process_session(tmp_path)
    repository.record_cleanup_action(
        session_id,
        CleanupActionType.STOP_REMOTE_PROCESS,
        payload,
    )
    adb = RemoteAdb(
        pid=pid,
        executable=remote,
        start_time="100",
        command_line=remote + "\x00",
        existence_probe_fails=True,
    )

    cleanup = CleanupExecutor(paths, repository, adb).cleanup(session_id)  # type: ignore[arg-type]

    assert cleanup.success is False
    assert adb.kill_calls == 0
    assert repository.load(session_id).cleanup_actions[0].status is CleanupActionStatus.FAILED
