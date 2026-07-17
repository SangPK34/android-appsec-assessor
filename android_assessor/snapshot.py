"""Best-effort read-only snapshot taken before a session may modify Android state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .adb import AdbClient, ReverseMapping
from .errors import AdbError
from .redaction import redact_text
from .validation import validate_package_name


class ProxySnapshotState(StrEnum):
    CAPTURED_WITH_VALUE = "CAPTURED_WITH_VALUE"
    CAPTURED_EMPTY = "CAPTURED_EMPTY"
    CAPTURE_FAILED = "CAPTURE_FAILED"


@dataclass(frozen=True, slots=True)
class DeviceSnapshot:
    captured_at: str
    http_proxy: str | None
    http_proxy_state: ProxySnapshotState
    http_proxy_error: str | None
    reverse_mappings: tuple[ReverseMapping, ...]
    frida_server_running: bool | None
    frida_process_names: tuple[str, ...]
    target_package_installed: bool | None
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "captured_at": self.captured_at,
            "http_proxy": self.http_proxy,
            "http_proxy_state": self.http_proxy_state.value,
            "http_proxy_error": self.http_proxy_error,
            "reverse_mappings": [mapping.to_dict() for mapping in self.reverse_mappings],
            "frida_server_running": self.frida_server_running,
            "frida_process_names": list(self.frida_process_names),
            "target_package_installed": self.target_package_installed,
            "errors": list(self.errors),
        }


def parse_proxy_snapshot(
    snapshot: dict[str, Any],
) -> tuple[ProxySnapshotState, str | None, str | None]:
    """Parse a persisted proxy snapshot without guessing legacy/failed state."""
    raw_state = snapshot.get("http_proxy_state")
    if raw_state is None:
        return (
            ProxySnapshotState.CAPTURE_FAILED,
            None,
            "Proxy snapshot state is missing; refusing to infer the original value.",
        )
    try:
        state = ProxySnapshotState(str(raw_state))
    except ValueError:
        return ProxySnapshotState.CAPTURE_FAILED, None, "Proxy snapshot state is invalid."

    value = snapshot.get("http_proxy")
    error_value = snapshot.get("http_proxy_error")
    error = str(error_value) if error_value else None
    if state is ProxySnapshotState.CAPTURED_WITH_VALUE:
        if not isinstance(value, str) or not value:
            return state, None, "Captured proxy value is missing or invalid."
        return state, value, None
    if state is ProxySnapshotState.CAPTURED_EMPTY:
        if value is not None:
            return state, None, "Empty proxy snapshot contains an unexpected value."
        return state, None, None
    return state, None, error or "Reading the original proxy setting failed."


def capture_device_snapshot(adb: AdbClient, serial: str, package: str) -> DeviceSnapshot:
    target = validate_package_name(package)
    errors: list[str] = []
    proxy: str | None = None
    proxy_state = ProxySnapshotState.CAPTURE_FAILED
    proxy_error: str | None = None
    mappings: tuple[ReverseMapping, ...] = ()
    frida_names: list[str] = []
    frida_running: bool | None = False
    package_installed: bool | None = None

    try:
        proxy = adb.get_setting(serial, "global", "http_proxy")
        proxy_state = (
            ProxySnapshotState.CAPTURED_WITH_VALUE
            if proxy is not None
            else ProxySnapshotState.CAPTURED_EMPTY
        )
    except AdbError as exc:
        proxy_error = redact_text(str(exc))[:300]
        errors.append(f"http_proxy: {proxy_error}")
    try:
        mappings = tuple(adb.list_reverse(serial))
    except AdbError as exc:
        errors.append(f"adb_reverse: {redact_text(str(exc))[:300]}")
    try:
        for process_name in ("frida-server", "re.frida.server"):
            result = adb.shell(
                serial,
                ("pidof", process_name),
                timeout=10,
                check=False,
                operation="snapshotting Frida Server state",
            )
            if not result.timed_out and result.exit_code == 0 and result.stdout.strip():
                frida_names.append(process_name)
        frida_running = bool(frida_names)
    except AdbError as exc:
        frida_running = None
        errors.append(f"frida_server: {redact_text(str(exc))[:300]}")
    try:
        package_result = adb.shell(
            serial,
            ("pm", "path", target),
            timeout=15,
            check=False,
            operation="snapshotting package installation state",
        )
        package_installed = (
            not package_result.timed_out
            and package_result.exit_code == 0
            and "package:" in package_result.stdout
        )
    except AdbError as exc:
        errors.append(f"target_package: {redact_text(str(exc))[:300]}")

    return DeviceSnapshot(
        captured_at=datetime.now(UTC).isoformat(),
        http_proxy=proxy,
        http_proxy_state=proxy_state,
        http_proxy_error=proxy_error,
        reverse_mappings=mappings,
        frida_server_running=frida_running,
        frida_process_names=tuple(frida_names),
        target_package_installed=package_installed,
        errors=tuple(errors),
    )
