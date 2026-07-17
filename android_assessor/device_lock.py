"""Cross-process lock that serializes modifying work per Android device."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from types import TracebackType
from typing import BinaryIO
from uuid import uuid4

from .adb import mask_serial, validate_serial
from .errors import DeviceBusyError, SessionError
from .paths import ProjectPaths
from .storage import read_json_object, write_json_atomic
from .validation import validate_session_id

_THREAD_STATE = threading.local()


def _held_device_locks() -> dict[str, tuple[int, str | None]]:
    held = getattr(_THREAD_STATE, "held", None)
    if held is None:
        held = {}
        _THREAD_STATE.held = held
    return held


class DeviceLock(AbstractContextManager["DeviceLock"]):
    def __init__(
        self,
        paths: ProjectPaths,
        serial: str,
        *,
        operation: str,
        session_id: str | None = None,
        timeout: float = 0,
    ) -> None:
        if timeout < 0 or timeout > 30:
            raise ValueError("Device-lock timeout must be between 0 and 30 seconds.")
        if not operation.strip() or len(operation) > 100 or any(
            character in operation for character in "\r\n\x00"
        ):
            raise ValueError("Device-lock operation is invalid.")
        self.paths = paths
        self.serial = validate_serial(serial)
        self.operation = operation.strip()
        self.session_id = validate_session_id(session_id) if session_id else None
        self.timeout = timeout
        digest = hashlib.sha256(self.serial.encode("utf-8")).hexdigest()[:20]
        self.lock_path = paths.device_locks_dir / f"{digest}.lock"
        self.metadata_path = paths.device_locks_dir / f"{digest}.json"
        self.owner = uuid4().hex
        self.key = os.path.normcase(str(self.lock_path.resolve()))
        self.handle: BinaryIO | None = None
        self.acquired = False
        self.reentrant = False

    def _try_lock(self) -> bool:
        if self.handle is None:
            return False
        self.handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True

    def _busy_detail(self) -> str:
        if not self.metadata_path.is_file():
            return "another process owns the device lock"
        try:
            metadata = read_json_object(self.metadata_path, root=self.paths.root)
        except SessionError:
            return "another process owns the device lock"
        operation = metadata.get("operation", "unknown operation")
        session_id = metadata.get("session_id")
        suffix = f", session {session_id}" if session_id else ""
        return f"operation {operation}{suffix}"

    def __enter__(self) -> DeviceLock:
        held = _held_device_locks()
        owner = held.get(self.key)
        if (
            owner is not None
            and owner[1] is not None
            and self.session_id == owner[1]
        ):
            held[self.key] = (owner[0] + 1, owner[1])
            self.reentrant = True
            self.acquired = True
            return self
        self.paths.device_locks_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.handle = self.lock_path.open("a+b")
        except OSError as exc:
            raise DeviceBusyError(
                f"Device {mask_serial(self.serial)} is busy: {self._busy_detail()}."
            ) from exc
        self.handle.seek(0, os.SEEK_END)
        if self.handle.tell() == 0:
            self.handle.write(b"0")
            self.handle.flush()

        deadline = time.monotonic() + self.timeout
        while not self._try_lock():
            if time.monotonic() >= deadline:
                self.handle.close()
                self.handle = None
                raise DeviceBusyError(
                    f"Device {mask_serial(self.serial)} is busy: {self._busy_detail()}."
                )
            time.sleep(0.1)

        self.acquired = True
        try:
            write_json_atomic(
                self.metadata_path,
                {
                    "schema_version": 1,
                    "owner": self.owner,
                    "pid": os.getpid(),
                    "serial_masked": mask_serial(self.serial),
                    "session_id": self.session_id,
                    "operation": self.operation,
                    "acquired_at": datetime.now(UTC).isoformat(),
                },
                root=self.paths.root,
            )
        except Exception:
            self.__exit__(None, None, None)
            raise
        held[self.key] = (1, self.session_id)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        held = _held_device_locks()
        owner = held.get(self.key)
        depth = owner[0] if owner else 0
        if self.reentrant:
            if depth <= 1:
                held.pop(self.key, None)
            else:
                held[self.key] = (depth - 1, owner[1] if owner else None)
            self.reentrant = False
            self.acquired = False
            return
        held.pop(self.key, None)
        if self.metadata_path.is_file():
            try:
                metadata = read_json_object(self.metadata_path, root=self.paths.root)
                if metadata.get("owner") == self.owner:
                    self.metadata_path.unlink(missing_ok=True)
            except (OSError, SessionError):
                pass
        if self.handle is not None:
            try:
                if self.acquired:
                    self.handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close()
                self.handle = None
                self.acquired = False
