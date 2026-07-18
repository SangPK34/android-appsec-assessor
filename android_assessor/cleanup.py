"""Idempotent cleanup for actions explicitly recorded by a session."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .adb import AdbClient
from .device_lock import DeviceLock
from .errors import (
    AdbError,
    AndroidAssessorError,
    CleanupConflictError,
    CleanupError,
)
from .host_process import ProcessIdentity, WindowsProcessController
from .paths import ProjectPaths
from .redaction import redact_text
from .root import root_shell
from .session import (
    CleanupAction,
    CleanupActionStatus,
    CleanupActionType,
    SessionRecord,
    SessionRepository,
    SessionStatus,
)
from .snapshot import ProxySnapshotState, parse_proxy_snapshot
from .validation import validate_managed_remote_path, validate_reverse_endpoint

_ANDROID_ACTIONS = {
    CleanupActionType.RESTORE_PROXY,
    CleanupActionType.REMOVE_REVERSE,
    CleanupActionType.REMOVE_REMOTE_FILE,
    CleanupActionType.STOP_REMOTE_PROCESS,
}
_REMOTE_PROCESS_NAMES = {"frida-server", "re.frida.server"}
_HOST_ROLES: dict[str, set[str]] = {
    "scrcpy": {"scrcpy.exe"},
    "mitmproxy": {"mitmdump.exe", "mitmproxy.exe", "mitmweb.exe"},
    "frida-client": {"frida.exe", "frida-ps.exe", "frida-trace.exe"},
}
_OWNED = "owned"


@dataclass(frozen=True, slots=True)
class RemoteProcessIdentity:
    pid: int
    executable_path: str
    proc_exe: str
    proc_start_time: str
    command_line: str

    def to_cleanup_payload(
        self,
        *,
        session_id: str,
        name: str,
        started_at: str,
    ) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "name": name,
            "executable_path": self.executable_path,
            "proc_exe": self.proc_exe,
            "proc_start_time": self.proc_start_time,
            "command_line": self.command_line,
            "session_id": session_id,
            "ownership_state": _OWNED,
            "started_at": started_at,
        }


def _proc_start_time(value: str) -> str:
    closing = value.rfind(")")
    if closing < 0:
        raise CleanupError("Android process stat is malformed.")
    fields = value[closing + 1 :].split()
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise CleanupError("Android process start time is unavailable.")
    return fields[19]


def _remote_process_exists(adb: AdbClient, serial: str, pid: int) -> bool:
    result = root_shell(
        adb,
        serial,
        f"if [ -d /proc/{pid} ]; then echo EXISTS; else echo MISSING; fi",
        timeout=10,
        check=False,
        operation="checking an owned Android process",
    )
    if result.timed_out or result.exit_code != 0:
        raise CleanupError("Could not verify whether the owned Android process exists.")
    marker = result.stdout.strip()
    if marker == "EXISTS":
        return True
    if marker == "MISSING":
        return False
    raise CleanupError("Android process existence probe returned an invalid result.")


def capture_remote_process_identity(
    adb: AdbClient,
    serial: str,
    pid: int,
    executable_path: str,
) -> RemoteProcessIdentity:
    if pid <= 0:
        raise CleanupError("Remote process PID is invalid.")
    expected = validate_managed_remote_path(executable_path)
    commands = (
        ("exe", f"readlink /proc/{pid}/exe"),
        ("stat", f"cat /proc/{pid}/stat"),
        ("cmdline", f"cat /proc/{pid}/cmdline"),
    )
    values: dict[str, str] = {}
    for name, command in commands:
        result = root_shell(
            adb,
            serial,
            command,
            timeout=10,
            check=False,
            operation="capturing owned Android process identity",
        )
        if result.timed_out or result.exit_code != 0:
            raise CleanupError(f"Could not read Android process identity field {name}.")
        values[name] = result.stdout.rstrip("\r\n")
    proc_exe = values["exe"]
    command_line = values["cmdline"]
    if proc_exe != expected or not command_line:
        raise CleanupError("Android process executable identity does not match.")
    return RemoteProcessIdentity(
        pid=pid,
        executable_path=expected,
        proc_exe=proc_exe,
        proc_start_time=_proc_start_time(values["stat"]),
        command_line=command_line,
    )


def restore_owned_proxy(
    adb: AdbClient,
    record: SessionRecord,
    payload: dict[str, Any],
) -> CleanupActionStatus:
    state, _, snapshot_error = parse_proxy_snapshot(record.snapshot)
    if state is ProxySnapshotState.CAPTURE_FAILED or snapshot_error:
        raise CleanupError(
            "Refusing to modify the proxy because its original state was not "
            f"captured: {snapshot_error or 'unknown snapshot error'}"
        )
    if payload.get("ownership_state") != _OWNED:
        raise CleanupError("Proxy cleanup action has no valid ownership marker.")
    previous = payload.get("previous_proxy")
    applied = payload.get("applied_proxy")
    if previous is not None and not isinstance(previous, str):
        raise CleanupError("Owned proxy previous value is invalid.")
    if not isinstance(applied, str) or not applied:
        raise CleanupError("Owned proxy applied value is invalid.")

    current = adb.get_setting(record.serial, "global", "http_proxy")
    if current == previous:
        return CleanupActionStatus.SKIPPED
    if current != applied:
        raise CleanupConflictError(
            "Current Android proxy no longer matches the value applied by this session."
        )
    if previous is None:
        adb.delete_setting(record.serial, "global", "http_proxy")
    else:
        adb.put_setting(record.serial, "global", "http_proxy", previous)
    return CleanupActionStatus.COMPLETED


def remove_owned_reverse(
    adb: AdbClient,
    record: SessionRecord,
    payload: dict[str, Any],
) -> CleanupActionStatus:
    if payload.get("ownership_state") != _OWNED:
        raise CleanupError("ADB reverse cleanup action has no valid ownership marker.")
    remote = validate_reverse_endpoint(str(payload.get("reverse_remote", "")))
    local = validate_reverse_endpoint(str(payload.get("reverse_local", "")))
    current = adb.list_reverse(record.serial)
    mapping = next((item for item in current if item.remote == remote), None)
    if mapping is None:
        return CleanupActionStatus.SKIPPED
    if mapping.local != local:
        raise CleanupConflictError(
            "ADB reverse endpoint now maps to a different local endpoint."
        )
    adb.remove_reverse(record.serial, remote)
    return CleanupActionStatus.COMPLETED


@dataclass(frozen=True, slots=True)
class CleanupActionResult:
    action_id: str
    action_type: str
    status: str
    error: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "status": self.status,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class CleanupResult:
    session_id: str
    success: bool
    status: str
    actions: tuple[CleanupActionResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "success": self.success,
            "status": self.status,
            "actions": [action.to_dict() for action in self.actions],
        }


class CleanupExecutor:
    def __init__(
        self,
        paths: ProjectPaths,
        repository: SessionRepository,
        adb: AdbClient,
        *,
        process_controller: WindowsProcessController | None = None,
        remote_process_timeout: float = 5,
    ) -> None:
        if not 0.01 <= remote_process_timeout <= 30:
            raise ValueError("Remote process timeout must be between 0.01 and 30 seconds.")
        self.paths = paths
        self.repository = repository
        self.adb = adb
        self.process_controller = process_controller or WindowsProcessController()
        self.remote_process_timeout = remote_process_timeout

    def _restore_proxy(
        self,
        record: SessionRecord,
        payload: dict[str, Any],
    ) -> CleanupActionStatus:
        return restore_owned_proxy(self.adb, record, payload)

    def _remove_reverse(
        self,
        record: SessionRecord,
        payload: dict[str, Any],
    ) -> CleanupActionStatus:
        return remove_owned_reverse(self.adb, record, payload)

    def _remove_remote_file(
        self,
        record: SessionRecord,
        payload: dict[str, Any],
    ) -> CleanupActionStatus:
        remote_path = validate_managed_remote_path(str(payload.get("path", "")))
        exists = self.adb.shell(
            record.serial,
            ("test", "-e", remote_path),
            timeout=10,
            check=False,
            operation="checking a managed Android temporary file",
        )
        if exists.exit_code != 0 or exists.timed_out:
            return CleanupActionStatus.SKIPPED
        self.adb.shell(
            record.serial,
            ("rm", "-f", "--", remote_path),
            timeout=20,
            check=True,
            operation="removing a managed Android temporary file",
        )
        return CleanupActionStatus.COMPLETED

    def _stop_remote_process(
        self,
        record: SessionRecord,
        payload: dict[str, Any],
    ) -> CleanupActionStatus:
        try:
            pid = int(payload.get("pid", 0))
        except (TypeError, ValueError) as exc:
            raise CleanupError("Remote process PID is invalid.") from exc
        name = str(payload.get("name", ""))
        executable_path = validate_managed_remote_path(
            str(payload.get("executable_path", ""))
        )
        if pid <= 0 or name not in _REMOTE_PROCESS_NAMES:
            raise CleanupError("Remote process cleanup is not on the allowlist.")
        if payload.get("ownership_state") != _OWNED:
            raise CleanupError("Remote process cleanup has no valid ownership marker.")
        if payload.get("session_id") != record.session_id:
            raise CleanupError("Remote process ownership belongs to another session.")
        started_at = payload.get("started_at")
        if not isinstance(started_at, str):
            raise CleanupError("Remote process start timestamp is missing.")
        try:
            datetime.fromisoformat(started_at)
        except ValueError as exc:
            raise CleanupError("Remote process start timestamp is invalid.") from exc
        if not _remote_process_exists(self.adb, record.serial, pid):
            return CleanupActionStatus.SKIPPED

        expected_proc_exe = payload.get("proc_exe")
        expected_start = payload.get("proc_start_time")
        expected_command = payload.get("command_line")
        if (
            expected_proc_exe != executable_path
            or not isinstance(expected_start, str)
            or not expected_start.isdecimal()
            or not isinstance(expected_command, str)
            or not expected_command
        ):
            raise CleanupError("Remote process identity ledger is incomplete.")
        actual = capture_remote_process_identity(
            self.adb,
            record.serial,
            pid,
            executable_path,
        )
        if (
            actual.proc_exe != expected_proc_exe
            or actual.proc_start_time != expected_start
            or actual.command_line != expected_command
        ):
            raise CleanupError(f"Refusing to stop reused or mismatched Android PID {pid}.")
        root_shell(
            self.adb,
            record.serial,
            f"kill {pid}",
            timeout=10,
            check=True,
            operation="stopping an owned Android process",
        )
        deadline = time.monotonic() + self.remote_process_timeout
        while time.monotonic() < deadline:
            if not _remote_process_exists(self.adb, record.serial, pid):
                return CleanupActionStatus.COMPLETED
            try:
                current = capture_remote_process_identity(
                    self.adb,
                    record.serial,
                    pid,
                    executable_path,
                )
            except CleanupError:
                # The process can exit between the /proc existence check and
                # identity reads. Re-check before treating that normal teardown
                # race as a cleanup failure; persistent probe failures still
                # reach the bounded timeout below.
                if not _remote_process_exists(self.adb, record.serial, pid):
                    return CleanupActionStatus.COMPLETED
                time.sleep(0.1)
                continue
            if current.proc_start_time != expected_start:
                return CleanupActionStatus.COMPLETED
            time.sleep(0.1)
        raise CleanupError(f"Owned Android process {pid} did not stop within timeout.")

    def _stop_host_process(self, payload: dict[str, Any]) -> CleanupActionStatus:
        role = str(payload.get("role", ""))
        identity_value = payload.get("identity")
        if role not in _HOST_ROLES or not isinstance(identity_value, dict):
            raise CleanupError("Host process cleanup is not on the allowlist.")
        identity = ProcessIdentity.from_dict(identity_value)
        executable = Path(identity.executable).resolve()
        self.paths.require_inside_root(executable)
        if executable.name.lower() not in _HOST_ROLES[role]:
            raise CleanupError("Host process executable does not match its managed role.")
        terminated = self.process_controller.terminate_owned(identity)
        return CleanupActionStatus.COMPLETED if terminated else CleanupActionStatus.SKIPPED

    def _execute(self, record: SessionRecord, action: CleanupAction) -> CleanupActionStatus:
        if action.action_type is CleanupActionType.RESTORE_PROXY:
            return self._restore_proxy(record, action.payload)
        if action.action_type is CleanupActionType.REMOVE_REVERSE:
            return self._remove_reverse(record, action.payload)
        if action.action_type is CleanupActionType.REMOVE_REMOTE_FILE:
            return self._remove_remote_file(record, action.payload)
        if action.action_type is CleanupActionType.STOP_REMOTE_PROCESS:
            return self._stop_remote_process(record, action.payload)
        if action.action_type is CleanupActionType.STOP_HOST_PROCESS:
            return self._stop_host_process(action.payload)
        raise CleanupError(f"Unsupported cleanup action: {action.action_type}")

    def execute_action(
        self,
        record: SessionRecord,
        action: CleanupAction,
    ) -> CleanupActionStatus:
        return self._execute(record, action)

    def rollback_actions(
        self,
        session_id: str,
        action_ids: set[str],
    ) -> CleanupResult:
        """Immediately roll back a transaction's recorded mutations.

        The caller already owns the device lock. Failed actions remain in the ledger
        for stale-session recovery.
        """
        record = self.repository.load(session_id)
        selected = [
            action
            for action in record.cleanup_actions
            if action.action_id in action_ids
            and action.status
            not in {CleanupActionStatus.COMPLETED, CleanupActionStatus.SKIPPED}
        ]
        results: list[CleanupActionResult] = []
        android_ready_error: str | None = None
        if any(action.action_type in _ANDROID_ACTIONS for action in selected):
            try:
                self.adb.require_authorized_device(record.serial)
            except AdbError as exc:
                android_ready_error = redact_text(str(exc))[:500]

        for action in reversed(selected):
            try:
                if action.action_type in _ANDROID_ACTIONS and android_ready_error:
                    raise CleanupError(android_ready_error)
                status = self._execute(record, action)
                self.repository.update_cleanup_action(
                    record.session_id,
                    action.action_id,
                    status=status,
                )
                results.append(
                    CleanupActionResult(
                        action_id=action.action_id,
                        action_type=action.action_type.value,
                        status=status.value,
                    )
                )
            except CleanupConflictError as exc:
                error = redact_text(str(exc))[:500]
                self.repository.update_cleanup_action(
                    record.session_id,
                    action.action_id,
                    status=CleanupActionStatus.CONFLICT,
                    error=error,
                )
                results.append(
                    CleanupActionResult(
                        action_id=action.action_id,
                        action_type=action.action_type.value,
                        status=CleanupActionStatus.CONFLICT.value,
                        error=error,
                    )
                )
            except (AndroidAssessorError, OSError, ValueError) as exc:
                error = redact_text(str(exc))[:500]
                self.repository.update_cleanup_action(
                    record.session_id,
                    action.action_id,
                    status=CleanupActionStatus.FAILED,
                    error=error,
                )
                results.append(
                    CleanupActionResult(
                        action_id=action.action_id,
                        action_type=action.action_type.value,
                        status=CleanupActionStatus.FAILED.value,
                        error=error,
                    )
                )

        latest = self.repository.load(record.session_id)
        success = all(
            action.status in {CleanupActionStatus.COMPLETED, CleanupActionStatus.SKIPPED}
            for action in latest.cleanup_actions
            if action.action_id in action_ids
        )
        if not latest.pending_cleanup:
            self.repository.set_status(record.session_id, SessionStatus.ACTIVE)
        else:
            self.repository.set_status(
                record.session_id,
                SessionStatus.CLEANUP_REQUIRED,
                cleanup_success=False,
                last_error="Transactional rollback left pending cleanup work.",
            )
        self.repository.append_event(
            record.session_id,
            "transaction_rollback",
            {"success": success, "action_count": len(results)},
        )
        return CleanupResult(
            session_id=record.session_id,
            success=success,
            status=self.repository.load(record.session_id).status.value,
            actions=tuple(results),
        )

    def cleanup(self, session_id: str) -> CleanupResult:
        initial = self.repository.load(session_id)
        results: list[CleanupActionResult] = []
        with DeviceLock(
            self.paths,
            initial.serial,
            operation="cleanup",
            session_id=initial.session_id,
            timeout=0,
        ):
            initial = self.repository.load(initial.session_id)
            if initial.status is SessionStatus.CLEANED and not initial.pending_cleanup:
                return CleanupResult(
                    session_id=initial.session_id,
                    success=True,
                    status=SessionStatus.CLEANED.value,
                    actions=(),
                )
            self.repository.set_status(initial.session_id, SessionStatus.CLEANING)
            android_actions = [
                action
                for action in initial.cleanup_actions
                if action.action_type in _ANDROID_ACTIONS
                and action.status
                not in {CleanupActionStatus.COMPLETED, CleanupActionStatus.SKIPPED}
            ]
            android_ready_error: str | None = None
            if android_actions:
                try:
                    self.adb.require_authorized_device(initial.serial)
                except AdbError as exc:
                    android_ready_error = redact_text(str(exc))[:500]

            for action in reversed(initial.cleanup_actions):
                if action.status in {CleanupActionStatus.COMPLETED, CleanupActionStatus.SKIPPED}:
                    continue
                try:
                    if action.action_type in _ANDROID_ACTIONS and android_ready_error:
                        raise CleanupError(android_ready_error)
                    action_status = self._execute(initial, action)
                    updated = self.repository.update_cleanup_action(
                        initial.session_id,
                        action.action_id,
                        status=action_status,
                    )
                    results.append(
                        CleanupActionResult(
                            action_id=action.action_id,
                            action_type=action.action_type.value,
                            status=updated.status.value,
                        )
                    )
                except CleanupConflictError as exc:
                    error = redact_text(str(exc))[:500]
                    self.repository.update_cleanup_action(
                        initial.session_id,
                        action.action_id,
                        status=CleanupActionStatus.CONFLICT,
                        error=error,
                    )
                    results.append(
                        CleanupActionResult(
                            action_id=action.action_id,
                            action_type=action.action_type.value,
                            status=CleanupActionStatus.CONFLICT.value,
                            error=error,
                        )
                    )
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    error = redact_text(str(exc))[:500]
                    self.repository.update_cleanup_action(
                        initial.session_id,
                        action.action_id,
                        status=CleanupActionStatus.FAILED,
                        error=error,
                    )
                    results.append(
                        CleanupActionResult(
                            action_id=action.action_id,
                            action_type=action.action_type.value,
                            status=CleanupActionStatus.FAILED.value,
                            error=error,
                        )
                    )

            final_actions = self.repository.load(initial.session_id).cleanup_actions
            success = all(
                action.status in {CleanupActionStatus.COMPLETED, CleanupActionStatus.SKIPPED}
                for action in final_actions
            )
            final_status = SessionStatus.CLEANED if success else SessionStatus.CLEANUP_FAILED
            self.repository.set_status(
                initial.session_id,
                final_status,
                cleanup_success=success,
                last_error=None if success else "One or more cleanup actions failed.",
            )
            return CleanupResult(
                session_id=initial.session_id,
                success=success,
                status=final_status.value,
                actions=tuple(results),
            )
