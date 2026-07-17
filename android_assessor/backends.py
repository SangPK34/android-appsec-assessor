"""Structural seams for Android-facing backends.

Production implementations remain the existing ADB, Frida, and traffic controllers.
Test doubles live only under tests/fakes and conform to these protocols.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

from .adb import AdbDevice, ReverseMapping
from .subprocess_utils import CommandResult


class AdbBackend(Protocol):
    def list_devices(self) -> list[AdbDevice]: ...

    def require_authorized_device(self, serial: str) -> AdbDevice: ...

    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float = 30,
        check: bool = False,
        operation: str = "running an Android shell command",
    ) -> CommandResult: ...

    def push_managed_file(
        self,
        serial: str,
        source: Path,
        remote_path: str,
        *,
        timeout: float = 180,
    ) -> CommandResult: ...


class RootBackend(Protocol):
    def execute_root(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float,
    ) -> CommandResult: ...


class FridaBackend(Protocol):
    def frida_server_state(self, serial: str) -> Mapping[str, object]: ...

    def start_frida_server(
        self,
        serial: str,
        *,
        executable_path: str,
        session_id: str,
    ) -> Mapping[str, object]: ...

    def stop_frida_server(
        self,
        serial: str,
        identity: Mapping[str, object],
        *,
        session_id: str,
    ) -> bool: ...


class TrafficBackend(Protocol):
    def snapshot_proxy(self, serial: str) -> str | None: ...

    def set_proxy(self, serial: str, value: str | None) -> None: ...

    def list_reverse(self, serial: str) -> list[ReverseMapping]: ...

    def add_reverse(self, serial: str, remote: str, local: str) -> None: ...

    def remove_reverse(self, serial: str, remote: str, local: str) -> bool: ...


class PrivateStorageBackend(Protocol):
    evidence_source: str
    environment_type: str

    def inspect_package(self, serial: str, package: str) -> dict[str, object]: ...

    def list_storage(self, serial: str, package: str) -> list[dict[str, object]]: ...
