"""Session lifecycle, on-disk structure, and cleanup action ledger."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from shutil import rmtree
from typing import Any
from uuid import uuid4

from .adb import mask_serial, validate_serial
from .errors import DeviceBusyError, SessionError
from .file_lock import FileLock
from .paths import ProjectPaths
from .storage import append_jsonl, read_json_object, write_json_atomic
from .validation import validate_package_name, validate_session_id


class SessionStatus(StrEnum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    CLEANUP_REQUIRED = "cleanup_required"
    CLEANING = "cleaning"
    CLEANED = "cleaned"
    CLEANUP_FAILED = "cleanup_failed"
    ERROR = "error"


class CleanupActionType(StrEnum):
    RESTORE_PROXY = "restore_proxy"
    REMOVE_REVERSE = "remove_reverse"
    REMOVE_REMOTE_FILE = "remove_remote_file"
    STOP_REMOTE_PROCESS = "stop_remote_process"
    STOP_HOST_PROCESS = "stop_host_process"


class CleanupActionStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    CONFLICT = "conflict"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class CleanupAction:
    action_id: str
    action_type: CleanupActionType
    payload: dict[str, Any]
    status: CleanupActionStatus = CleanupActionStatus.PENDING
    attempts: int = 0
    last_error: str | None = None
    completed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "payload": dict(self.payload),
            "status": self.status.value,
            "attempts": self.attempts,
            "last_error": self.last_error,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CleanupAction:
        try:
            action_id = str(value["action_id"])
            action_type = CleanupActionType(str(value["action_type"]))
            status = CleanupActionStatus(str(value.get("status", "pending")))
            payload = value.get("payload", {})
            if not isinstance(payload, dict):
                raise TypeError("payload must be an object")
            attempts = int(value.get("attempts", 0))
        except (KeyError, TypeError, ValueError) as exc:
            raise SessionError(f"Invalid cleanup action: {exc}") from exc
        if not action_id.startswith("cleanup-") or len(action_id) != 16:
            raise SessionError("Cleanup action ID has an invalid format.")
        if attempts < 0:
            raise SessionError("Cleanup action attempts cannot be negative.")
        return cls(
            action_id=action_id,
            action_type=action_type,
            payload=dict(payload),
            status=status,
            attempts=attempts,
            last_error=str(value["last_error"]) if value.get("last_error") else None,
            completed_at=str(value["completed_at"]) if value.get("completed_at") else None,
        )


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: str
    created_at: str
    updated_at: str
    status: SessionStatus
    serial: str
    package: str
    snapshot: dict[str, Any]
    cleanup_actions: tuple[CleanupAction, ...] = ()
    cleanup_success: bool | None = None
    last_error: str | None = None

    @property
    def serial_masked(self) -> str:
        return mask_serial(self.serial)

    @property
    def pending_cleanup(self) -> bool:
        return any(
            action.status
            in {
                CleanupActionStatus.PENDING,
                CleanupActionStatus.FAILED,
                CleanupActionStatus.CONFLICT,
            }
            for action in self.cleanup_actions
        )

    def to_dict(self, *, show_serial: bool = True) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status.value,
            "serial": self.serial if show_serial else self.serial_masked,
            "serial_masked": self.serial_masked,
            "package": self.package,
            "snapshot": dict(self.snapshot),
            "cleanup_actions": [action.to_dict() for action in self.cleanup_actions],
            "pending_cleanup": self.pending_cleanup,
            "cleanup_success": self.cleanup_success,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SessionRecord:
        try:
            session_id = validate_session_id(str(value["session_id"]))
            serial = validate_serial(str(value["serial"]))
            package = validate_package_name(str(value["package"]))
            status = SessionStatus(str(value["status"]))
            snapshot = value.get("snapshot", {})
            actions = value.get("cleanup_actions", [])
            if not isinstance(snapshot, dict) or not isinstance(actions, list):
                raise TypeError("snapshot/actions have invalid types")
        except (KeyError, TypeError, ValueError) as exc:
            raise SessionError(f"Invalid session record: {exc}") from exc
        return cls(
            session_id=session_id,
            created_at=str(value["created_at"]),
            updated_at=str(value["updated_at"]),
            status=status,
            serial=serial,
            package=package,
            snapshot=dict(snapshot),
            cleanup_actions=tuple(CleanupAction.from_dict(item) for item in actions),
            cleanup_success=value.get("cleanup_success"),
            last_error=str(value["last_error"]) if value.get("last_error") else None,
        )


@dataclass(frozen=True, slots=True)
class SessionPaths:
    root: Path

    @property
    def session_json(self) -> Path:
        return self.root / "session.json"

    @property
    def device_json(self) -> Path:
        return self.root / "device.json"

    @property
    def app_json(self) -> Path:
        return self.root / "app.json"

    @property
    def environment_json(self) -> Path:
        return self.root / "environment.json"

    @property
    def findings_json(self) -> Path:
        return self.root / "findings.json"

    @property
    def events_jsonl(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def commands_jsonl(self) -> Path:
        return self.root / "commands.jsonl"

    @property
    def report_html(self) -> Path:
        return self.root / "report.html"

    @property
    def report_json(self) -> Path:
        return self.root / "report.json"

    @property
    def scan_json(self) -> Path:
        return self.root / "scan.json"

    @property
    def runtime_control_json(self) -> Path:
        return self.root / "runtime-control.json"

    @property
    def experiment_results_csv(self) -> Path:
        return self.root / "experiment_results.csv"

    @property
    def evidence_index(self) -> Path:
        return self.root / "evidence" / "index.json"

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def redacted_dir(self) -> Path:
        return self.root / "redacted"

    @property
    def apk_dir(self) -> Path:
        return self.root / "apk"

    @property
    def traffic_dir(self) -> Path:
        return self.root / "traffic"

    @property
    def frida_dir(self) -> Path:
        return self.root / "frida"

    @property
    def logcat_dir(self) -> Path:
        return self.root / "logcat"


class SessionRepository:
    _DIRECTORIES = (
        "evidence",
        "raw",
        "redacted",
        "screenshots",
        "traffic",
        "frida",
        "logcat",
        "apk",
    )

    def __init__(self, paths: ProjectPaths) -> None:
        self.paths = paths

    def paths_for(self, session_id: str) -> SessionPaths:
        validated = validate_session_id(session_id)
        root = (self.paths.results_dir / validated).resolve()
        self.paths.require_inside_root(root)
        return SessionPaths(root)

    def state_lock(self, session_id: str, *, timeout: float = 10) -> FileLock:
        paths = self.paths_for(session_id)
        return FileLock(paths.root / ".state.lock", root=self.paths.root, timeout=timeout)

    def require_modifying_session_slot(self, serial: str, session_id: str) -> None:
        selected = validate_serial(serial)
        current_id = validate_session_id(session_id)
        with self.state_lock(current_id):
            current = self.load(current_id)
            if current.serial != selected:
                raise SessionError("Session device does not match the modifying operation.")
            if current.status not in {
                SessionStatus.ACTIVE,
                SessionStatus.CLEANUP_REQUIRED,
            }:
                raise SessionError("Modifying operations require an active session.")
        for record in self.list():
            if record.serial != selected or record.status is SessionStatus.CLEANED:
                continue
            if record.session_id == current_id:
                if any(
                    action.status
                    in {CleanupActionStatus.FAILED, CleanupActionStatus.CONFLICT}
                    for action in record.cleanup_actions
                ):
                    raise DeviceBusyError(
                        "This session has failed cleanup work; run Cleanup before "
                        "modifying the device again."
                    )
                continue
            if record.pending_cleanup:
                raise DeviceBusyError(
                    f"Device has modifying resources owned by session {record.session_id}."
                )

    def _allocate_id(self) -> str:
        for _ in range(20):
            prefix = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
            candidate = f"{prefix}-{uuid4().hex[:6]}"
            if not (self.paths.results_dir / candidate).exists():
                return candidate
        raise SessionError("Could not allocate a unique session ID.")

    def initialize(self, *, serial: str, package: str) -> SessionRecord:
        selected = validate_serial(serial)
        target = validate_package_name(package)
        session_id = self._allocate_id()
        paths = self.paths_for(session_id)
        try:
            paths.root.mkdir(parents=True, exist_ok=False)
            for name in self._DIRECTORIES:
                (paths.root / name).mkdir()
            paths.events_jsonl.touch()
            paths.commands_jsonl.touch()
            (paths.root / "raw" / "README.txt").write_text(
                "WARNING: raw evidence may contain credentials, tokens, personal data, "
                "or other sensitive lab content. Do not share this directory unreviewed.\n",
                encoding="utf-8",
                newline="\n",
            )
        except OSError as exc:
            raise SessionError(f"Could not initialize session directory: {exc}") from exc

        now = datetime.now(UTC).isoformat()
        record = SessionRecord(
            session_id=session_id,
            created_at=now,
            updated_at=now,
            status=SessionStatus.INITIALIZING,
            serial=selected,
            package=target,
            snapshot={},
        )
        try:
            self.save(record)
            write_json_atomic(
                paths.app_json,
                {
                    "schema_version": 1,
                    "package": target,
                    "inspection_status": "not_started",
                },
                root=self.paths.root,
            )
            write_json_atomic(
                paths.findings_json,
                {"schema_version": 1, "findings": []},
                root=self.paths.root,
            )
            write_json_atomic(
                paths.evidence_index,
                {"schema_version": 1, "evidence": []},
                root=self.paths.root,
            )
            self.append_event(record.session_id, "session_initialized")
        except Exception:
            rmtree(paths.root, ignore_errors=True)
            raise
        return record

    def load(self, session_id: str) -> SessionRecord:
        paths = self.paths_for(session_id)
        payload = read_json_object(paths.session_json, root=self.paths.root)
        return SessionRecord.from_dict(payload)

    def save(self, record: SessionRecord) -> None:
        with self.state_lock(record.session_id):
            paths = self.paths_for(record.session_id)
            write_json_atomic(paths.session_json, record.to_dict(), root=self.paths.root)

    def activate(
        self,
        session_id: str,
        *,
        snapshot: dict[str, Any],
        device: dict[str, Any],
        environment: dict[str, Any],
    ) -> SessionRecord:
        with self.state_lock(session_id):
            current = self.load(session_id)
            now = datetime.now(UTC).isoformat()
            updated = replace(
                current,
                status=SessionStatus.ACTIVE,
                snapshot=dict(snapshot),
                updated_at=now,
                last_error=None,
            )
            paths = self.paths_for(session_id)
            write_json_atomic(paths.device_json, device, root=self.paths.root)
            write_json_atomic(paths.environment_json, environment, root=self.paths.root)
            self.save(updated)
            self.append_event(session_id, "session_activated")
            return updated

    def set_status(
        self,
        session_id: str,
        status: SessionStatus,
        *,
        cleanup_success: bool | None = None,
        last_error: str | None = None,
    ) -> SessionRecord:
        with self.state_lock(session_id):
            current = self.load(session_id)
            updated = replace(
                current,
                status=status,
                updated_at=datetime.now(UTC).isoformat(),
                cleanup_success=cleanup_success,
                last_error=last_error,
            )
            self.save(updated)
            self.append_event(
                session_id,
                "session_status_changed",
                {"status": status.value, "error": last_error},
            )
            return updated

    def record_cleanup_action(
        self,
        session_id: str,
        action_type: CleanupActionType,
        payload: dict[str, Any],
    ) -> CleanupAction:
        with self.state_lock(session_id):
            current = self.load(session_id)
            if current.status is SessionStatus.CLEANED:
                raise SessionError("Cannot add cleanup work to a cleaned session.")
            action = CleanupAction(
                action_id=f"cleanup-{uuid4().hex[:8]}",
                action_type=action_type,
                payload=dict(payload),
            )
            updated = replace(
                current,
                status=SessionStatus.CLEANUP_REQUIRED,
                updated_at=datetime.now(UTC).isoformat(),
                cleanup_actions=(*current.cleanup_actions, action),
                cleanup_success=None,
            )
            self.save(updated)
            self.append_event(
                session_id,
                "cleanup_action_recorded",
                {"action_id": action.action_id, "action_type": action.action_type.value},
            )
            return action

    def update_cleanup_action(
        self,
        session_id: str,
        action_id: str,
        *,
        status: CleanupActionStatus,
        error: str | None = None,
    ) -> CleanupAction:
        with self.state_lock(session_id):
            current = self.load(session_id)
            selected: CleanupAction | None = None
            actions: list[CleanupAction] = []
            for action in current.cleanup_actions:
                if action.action_id == action_id:
                    selected = replace(
                        action,
                        status=status,
                        attempts=action.attempts + 1,
                        last_error=error,
                        completed_at=datetime.now(UTC).isoformat()
                        if status
                        in {CleanupActionStatus.COMPLETED, CleanupActionStatus.SKIPPED}
                        else None,
                    )
                    actions.append(selected)
                else:
                    actions.append(action)
            if selected is None:
                raise SessionError(f"Cleanup action not found: {action_id}")
            self.save(
                replace(
                    current,
                    cleanup_actions=tuple(actions),
                    updated_at=datetime.now(UTC).isoformat(),
                )
            )
            self.append_event(
                session_id,
                "cleanup_action_updated",
                {
                    "action_id": action_id,
                    "status": status.value,
                    "error": error,
                },
            )
            return selected

    def update_cleanup_action_payload(
        self,
        session_id: str,
        action_id: str,
        payload: dict[str, Any],
    ) -> CleanupAction:
        with self.state_lock(session_id):
            current = self.load(session_id)
            selected: CleanupAction | None = None
            actions: list[CleanupAction] = []
            for action in current.cleanup_actions:
                if action.action_id == action_id:
                    selected = replace(action, payload=dict(payload))
                    actions.append(selected)
                else:
                    actions.append(action)
            if selected is None:
                raise SessionError(f"Cleanup action not found: {action_id}")
            self.save(
                replace(
                    current,
                    cleanup_actions=tuple(actions),
                    updated_at=datetime.now(UTC).isoformat(),
                )
            )
            self.append_event(
                session_id,
                "cleanup_action_payload_updated",
                {"action_id": action_id},
            )
            return selected

    def append_event(
        self,
        session_id: str,
        event: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        if not event or any(character in event for character in "\r\n\x00"):
            raise SessionError("Session event name is invalid.")
        with self.state_lock(session_id):
            paths = self.paths_for(session_id)
            append_jsonl(
                paths.events_jsonl,
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "session_id": session_id,
                    "event": event,
                    "data": data or {},
                },
                root=self.paths.root,
                redact=True,
            )

    def list(self) -> list[SessionRecord]:
        if not self.paths.results_dir.is_dir():
            return []
        records: list[SessionRecord] = []
        for child in self.paths.results_dir.iterdir():
            if not child.is_dir():
                continue
            try:
                records.append(self.load(child.name))
            except SessionError:
                continue
        return sorted(records, key=lambda record: record.created_at, reverse=True)

    def unfinished(self) -> list[SessionRecord]:
        finished = {SessionStatus.CLEANED, SessionStatus.ERROR}
        return [record for record in self.list() if record.status not in finished]
