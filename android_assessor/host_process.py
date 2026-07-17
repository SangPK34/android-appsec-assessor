"""Windows process identity checks used by cross-run cleanup."""

from __future__ import annotations

import ctypes
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import CleanupError

_PROCESS_TERMINATE = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_WAIT_TIMEOUT_MS = 5000


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    executable: str
    creation_filetime: int

    def to_dict(self) -> dict[str, int | str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> ProcessIdentity:
        try:
            pid = int(value["pid"])
            executable = str(value["executable"])
            creation_filetime = int(value["creation_filetime"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CleanupError(f"Invalid host process identity: {exc}") from exc
        if pid <= 0 or creation_filetime <= 0 or not Path(executable).is_absolute():
            raise CleanupError("Host process identity contains invalid values.")
        return cls(pid=pid, executable=executable, creation_filetime=creation_filetime)


class WindowsProcessController:
    @staticmethod
    def _kernel32() -> ctypes.WinDLL:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.GetProcessTimes.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        )
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        return kernel32

    @staticmethod
    def _query(handle: int, pid: int) -> ProcessIdentity:
        from ctypes import wintypes

        kernel32 = WindowsProcessController._kernel32()
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise CleanupError(f"Could not query executable for PID {pid}.")
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise CleanupError(f"Could not query creation time for PID {pid}.")
        creation_value = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return ProcessIdentity(
            pid=pid,
            executable=str(Path(buffer.value).resolve()),
            creation_filetime=creation_value,
        )

    def capture(self, pid: int) -> ProcessIdentity | None:
        if os.name != "nt":
            raise CleanupError("Host process capture is only supported on Windows.")
        if pid <= 0:
            raise CleanupError("Host process PID must be positive.")
        kernel32 = self._kernel32()
        handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            return self._query(handle, pid)
        finally:
            kernel32.CloseHandle(handle)

    def terminate_owned(self, expected: ProcessIdentity) -> bool:
        if os.name != "nt":
            raise CleanupError("Host process cleanup is only supported on Windows.")
        kernel32 = self._kernel32()
        handle = kernel32.OpenProcess(
            _PROCESS_QUERY_LIMITED_INFORMATION | _PROCESS_TERMINATE,
            False,
            expected.pid,
        )
        if not handle:
            return False
        try:
            actual = self._query(handle, expected.pid)
            same_path = os.path.normcase(actual.executable) == os.path.normcase(expected.executable)
            if not same_path or actual.creation_filetime != expected.creation_filetime:
                raise CleanupError(
                    f"Refusing to terminate reused or mismatched PID {expected.pid}."
                )
            if not kernel32.TerminateProcess(handle, 1):
                raise CleanupError(f"Could not terminate owned PID {expected.pid}.")
            kernel32.WaitForSingleObject(handle, _WAIT_TIMEOUT_MS)
            return True
        finally:
            kernel32.CloseHandle(handle)
