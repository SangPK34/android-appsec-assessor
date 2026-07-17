"""Small re-entrant cross-process lock for session state mutations."""

from __future__ import annotations

import os
import threading
import time
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from .errors import SessionError

_THREAD_STATE = threading.local()


def _held_locks() -> dict[str, int]:
    held = getattr(_THREAD_STATE, "held", None)
    if held is None:
        held = {}
        _THREAD_STATE.held = held
    return held


class FileLock(AbstractContextManager["FileLock"]):
    def __init__(self, path: Path, *, root: Path, timeout: float = 10) -> None:
        if timeout < 0 or timeout > 30:
            raise ValueError("File-lock timeout must be between 0 and 30 seconds.")
        self.root = root.resolve()
        self.path = path.resolve()
        try:
            self.path.relative_to(self.root)
        except ValueError as exc:
            raise SessionError("File lock is outside the project root.") from exc
        self.timeout = timeout
        self.key = os.path.normcase(str(self.path))
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

    def __enter__(self) -> FileLock:
        held = _held_locks()
        if self.key in held:
            held[self.key] += 1
            self.reentrant = True
            self.acquired = True
            return self

        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.handle = self.path.open("a+b")
        except OSError as exc:
            raise SessionError(f"Could not open session state lock: {exc}") from exc
        self.handle.seek(0, os.SEEK_END)
        if self.handle.tell() == 0:
            self.handle.write(b"0")
            self.handle.flush()

        deadline = time.monotonic() + self.timeout
        while not self._try_lock():
            if time.monotonic() >= deadline:
                self.handle.close()
                self.handle = None
                raise SessionError("Session state is busy; retry the operation.")
            time.sleep(0.05)
        held[self.key] = 1
        self.acquired = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        held = _held_locks()
        depth = held.get(self.key, 0)
        if self.reentrant:
            if depth <= 1:
                held.pop(self.key, None)
            else:
                held[self.key] = depth - 1
            self.reentrant = False
            self.acquired = False
            return
        held.pop(self.key, None)
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
