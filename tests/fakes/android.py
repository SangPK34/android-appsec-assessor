from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from android_assessor.adb import AdbDevice, ReverseMapping, validate_serial
from android_assessor.errors import AdbError, FridaError, ProxyError
from android_assessor.subprocess_utils import CommandResult
from android_assessor.validation import validate_managed_remote_path


class FaultInjected(RuntimeError):
    pass


def _result(
    arguments: Sequence[str],
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        arguments=tuple(arguments),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=datetime.now(UTC).isoformat(),
        duration_ms=1,
        timed_out=timed_out,
    )


@dataclass(slots=True)
class FakeAndroidBackend:
    """Stateful fake used only by tests; every mutation is fault-injectable."""

    serial: str = "FIXTURE_SERIAL"
    connected: bool = True
    adb_state: str = "device"
    model: str = "Fixture Android"
    abi: str = "arm64-v8a"
    root_outcome: str = "available"
    magisk_present: bool = True
    zygisk_enabled: bool = True
    client_version: str = "17.0.0"
    server_version: str | None = None
    server_process: dict[str, Any] | None = None
    proxy: str | None = None
    proxy_snapshot_fails: bool = False
    reverse_mappings: dict[str, str] = field(default_factory=dict)
    packages: dict[str, dict[str, Any]] = field(default_factory=dict)
    storage_entries: list[dict[str, Any]] = field(default_factory=list)
    logcat_lines: list[str] = field(default_factory=list)
    fail_after_mutation: int | None = None
    mutations: int = 0
    operations: list[tuple[str, tuple[Any, ...]]] = field(default_factory=list)
    pushed_files: dict[str, bytes] = field(default_factory=dict)

    def _require_connected(self, serial: str) -> None:
        validate_serial(serial)
        if serial != self.serial or not self.connected:
            raise AdbError("Fixture device is disconnected.")
        if self.adb_state != "device":
            raise AdbError(f"Fixture ADB state is {self.adb_state}.")

    def _mutation(self, name: str, *values: Any) -> None:
        self.operations.append((name, tuple(values)))
        self.mutations += 1
        if self.fail_after_mutation == self.mutations:
            raise FaultInjected(f"Injected fault after mutation {self.mutations}: {name}")

    def list_devices(self) -> list[AdbDevice]:
        if not self.connected:
            return []
        return [
            AdbDevice(
                serial=self.serial,
                state=self.adb_state,
                model=self.model,
                device="fixture",
                product="fixture",
                transport_id="1",
            )
        ]

    def require_authorized_device(self, serial: str) -> AdbDevice:
        self._require_connected(serial)
        return self.list_devices()[0]

    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float = 30,
        check: bool = False,
        operation: str = "fixture shell",
    ) -> CommandResult:
        del timeout, operation
        self._require_connected(serial)
        normalized = tuple(arguments)
        self.operations.append(("shell", normalized))
        result = _result(normalized, stdout="uid=2000(shell) gid=2000(shell)\n")
        if check and result.exit_code != 0:
            raise AdbError("Fixture shell command failed.")
        return result

    def execute_root(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float,
    ) -> CommandResult:
        del timeout
        self._require_connected(serial)
        normalized = tuple(arguments)
        self.operations.append(("root", normalized))
        outcomes = {
            "available": _result(normalized, stdout="uid=0(root) gid=0(root)\n"),
            "denied": _result(normalized, exit_code=1, stderr="permission denied\n"),
            "timeout": _result(normalized, exit_code=-1, timed_out=True),
            "missing": _result(normalized, exit_code=127, stderr="su: not found\n"),
            "shell": _result(normalized, stdout="uid=2000(shell) gid=2000(shell)\n"),
            "malformed": _result(normalized, stdout="unexpected identity\n"),
        }
        return outcomes[self.root_outcome]

    def push_managed_file(
        self,
        serial: str,
        source: Path,
        remote_path: str,
        *,
        timeout: float = 180,
    ) -> CommandResult:
        del timeout
        self._require_connected(serial)
        remote = validate_managed_remote_path(remote_path)
        self.pushed_files[remote] = source.read_bytes()
        self._mutation("push", remote)
        return _result(("push", str(source), remote), stdout="1 file pushed\n")

    def inspect_package(self, serial: str, package: str) -> dict[str, Any]:
        self._require_connected(serial)
        try:
            return deepcopy(self.packages[package])
        except KeyError as exc:
            raise AdbError("Fixture package is not installed.") from exc

    def list_storage(self, serial: str, package: str) -> list[dict[str, Any]]:
        self._require_connected(serial)
        if package not in self.packages:
            raise AdbError("Fixture package is not installed.")
        return deepcopy(self.storage_entries)

    def read_logcat(self, serial: str) -> list[str]:
        self._require_connected(serial)
        return list(self.logcat_lines)

    def snapshot_proxy(self, serial: str) -> str | None:
        self._require_connected(serial)
        if self.proxy_snapshot_fails:
            raise ProxyError("Injected proxy snapshot failure.")
        return self.proxy

    def set_proxy(self, serial: str, value: str | None) -> None:
        self._require_connected(serial)
        self.proxy = value
        self._mutation("set_proxy", value)

    def list_reverse(self, serial: str) -> list[ReverseMapping]:
        self._require_connected(serial)
        return [
            ReverseMapping(remote=remote, local=local)
            for remote, local in sorted(self.reverse_mappings.items())
        ]

    def add_reverse(self, serial: str, remote: str, local: str) -> None:
        self._require_connected(serial)
        self.reverse_mappings[remote] = local
        self._mutation("add_reverse", remote, local)

    def remove_reverse(self, serial: str, remote: str, local: str) -> bool:
        self._require_connected(serial)
        if self.reverse_mappings.get(remote) != local:
            return False
        del self.reverse_mappings[remote]
        self._mutation("remove_reverse", remote, local)
        return True

    def frida_server_state(self, serial: str) -> Mapping[str, object]:
        self._require_connected(serial)
        return {
            "version": self.server_version,
            "process": deepcopy(self.server_process),
            "compatible": self.server_version == self.client_version,
        }

    def start_frida_server(
        self,
        serial: str,
        *,
        executable_path: str,
        session_id: str,
    ) -> Mapping[str, object]:
        self._require_connected(serial)
        if self.server_process is not None:
            raise FridaError("Fixture Frida Server is already running.")
        self.server_version = self.client_version
        self.server_process = {
            "pid": 4242,
            "executable_path": executable_path,
            "proc_exe": executable_path,
            "start_time": "100",
            "command_line": executable_path,
            "session_id": session_id,
            "ownership": "framework",
        }
        self._mutation("start_frida", executable_path, session_id)
        return deepcopy(self.server_process)

    def stop_frida_server(
        self,
        serial: str,
        identity: Mapping[str, object],
        *,
        session_id: str,
    ) -> bool:
        self._require_connected(serial)
        process = self.server_process
        if process is None:
            return True
        expected = {
            "pid": identity.get("pid"),
            "executable_path": identity.get("executable_path"),
            "start_time": identity.get("start_time"),
            "session_id": session_id,
            "ownership": "framework",
        }
        actual = {key: process.get(key) for key in expected}
        if actual != expected:
            return False
        self.server_process = None
        self.server_version = None
        self._mutation("stop_frida", expected["pid"])
        return True

    def reuse_pid(self, *, executable_path: str, start_time: str) -> None:
        if self.server_process is None:
            raise FridaError("Fixture Frida process is not running.")
        self.server_process["executable_path"] = executable_path
        self.server_process["proc_exe"] = executable_path
        self.server_process["start_time"] = start_time
