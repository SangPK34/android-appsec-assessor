"""ADB discovery and explicit per-device command execution."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import AdbError, AdbTimeoutError, ExternalCommandError
from .redaction import redact_text_with_values
from .subprocess_utils import CommandResult, run_command
from .validation import (
    validate_android_apk_path,
    validate_managed_remote_path,
    validate_reverse_endpoint,
)

_SERIAL_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SETTING_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_GETPROP_PATTERN = re.compile(r"^\[([^]]+)]\s*:\s*\[(.*)]$")
_REVERSE_TRANSPORT_LABEL_PATTERN = re.compile(r"^host-\d+$")


@dataclass(frozen=True, slots=True)
class AdbDevice:
    serial: str
    state: str
    product: str | None = None
    model: str | None = None
    device: str | None = None
    transport_id: str | None = None
    details: tuple[str, ...] = ()

    @property
    def authorized(self) -> bool:
        return self.state == "device"

    def to_dict(self, *, show_serial: bool = False) -> dict[str, Any]:
        data = asdict(self)
        data["serial"] = self.serial if show_serial else mask_serial(self.serial)
        data["serial_masked"] = mask_serial(self.serial)
        data["authorized"] = self.authorized
        return data


@dataclass(frozen=True, slots=True)
class ReverseMapping:
    remote: str
    local: str

    def to_dict(self) -> dict[str, str]:
        return {"remote": self.remote, "local": self.local}


def mask_serial(serial: str) -> str:
    if len(serial) <= 4:
        return "*" * len(serial)
    visible_prefix = min(2, len(serial) - 4)
    return serial[:visible_prefix] + "*" * (len(serial) - visible_prefix - 4) + serial[-4:]


def parse_adb_devices(output: str) -> list[AdbDevice]:
    devices: list[AdbDevice] = []
    for raw_line in output.replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        columns = line.split()
        if len(columns) < 2:
            continue
        serial, state = columns[0], columns[1]
        if state == "no" and len(columns) >= 3 and columns[2] == "permissions":
            state = "no_permissions"
            metadata = columns[3:]
        else:
            metadata = columns[2:]
        parsed: dict[str, str] = {}
        leftovers: list[str] = []
        for item in metadata:
            if ":" in item:
                key, value = item.split(":", 1)
                parsed[key] = value
            else:
                leftovers.append(item)
        devices.append(
            AdbDevice(
                serial=serial,
                state=state,
                product=parsed.get("product"),
                model=parsed.get("model"),
                device=parsed.get("device"),
                transport_id=parsed.get("transport_id"),
                details=tuple(leftovers),
            )
        )
    return devices


def parse_getprop(output: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in output.replace("\r", "").splitlines():
        match = _GETPROP_PATTERN.match(raw_line.strip())
        if match:
            properties[match.group(1)] = match.group(2)
    return properties


def parse_reverse_list(output: str, serial: str) -> list[ReverseMapping]:
    mappings: list[ReverseMapping] = []
    for raw_line in output.replace("\r", "").splitlines():
        columns = raw_line.split()
        if len(columns) == 3:
            listed_serial, remote, local = columns
            if listed_serial != serial and not _REVERSE_TRANSPORT_LABEL_PATTERN.fullmatch(
                listed_serial
            ):
                continue
        elif len(columns) == 2:
            remote, local = columns
        else:
            continue
        mappings.append(ReverseMapping(remote=remote, local=local))
    return mappings


def validate_serial(serial: str) -> str:
    if not _SERIAL_PATTERN.fullmatch(serial):
        raise AdbError("Device serial contains unsupported characters.")
    return serial


def _validate_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(str(argument) for argument in arguments)
    if any("\x00" in argument or "\r" in argument or "\n" in argument for argument in normalized):
        raise AdbError("ADB arguments may not contain NUL or newline characters.")
    return normalized


def device_state_guidance(state: str) -> str:
    guidance = {
        "unauthorized": "Unlock Android and accept the USB debugging RSA prompt.",
        "offline": "Reconnect USB and wait for ADB to report state 'device'.",
        "no_permissions": (
            "Install or repair the Android device manufacturer's Windows USB driver, "
            "then reconnect the device."
        ),
        "recovery": "Boot Android normally before running an app assessment.",
        "sideload": "Exit sideload mode and boot Android normally.",
        "bootloader": "The device is in Fastboot mode; boot Android for ADB inspection.",
    }
    return guidance.get(state, f"ADB device is not ready (state: {state}).")


class AdbClient:
    def __init__(self, executable: Path, *, command_log: Path | None = None) -> None:
        self.executable = executable.resolve()
        self.command_log = command_log.resolve() if command_log is not None else None
        if not self.executable.is_file():
            raise AdbError(f"ADB executable not found: {self.executable}")

    def _run(
        self,
        arguments: Sequence[str],
        *,
        timeout: float,
        sensitive_values: Sequence[str] = (),
    ) -> CommandResult:
        normalized = _validate_arguments(arguments)
        kwargs: dict[str, Any] = {"timeout": timeout, "check": False}
        redacted_values = [str(value) for value in sensitive_values if value]
        if "-s" in normalized:
            serial_index = normalized.index("-s") + 1
            if serial_index < len(normalized):
                redacted_values.append(normalized[serial_index])
        if redacted_values:
            kwargs["sensitive_values"] = tuple(dict.fromkeys(redacted_values))
        if self.command_log is not None:
            kwargs["command_log"] = self.command_log
        try:
            return run_command([self.executable, *normalized], **kwargs)
        except ExternalCommandError as exc:
            raise AdbError(f"Could not execute ADB: {exc}") from exc

    @staticmethod
    def _require_success(
        result: CommandResult,
        operation: str,
        *,
        sensitive_values: Sequence[str] = (),
    ) -> CommandResult:
        if result.timed_out:
            raise AdbTimeoutError(f"ADB timed out while {operation}.")
        if result.exit_code != 0:
            detail = redact_text_with_values(
                (result.stderr or result.stdout).strip(),
                sensitive_values,
            )[-1000:]
            suffix = f": {detail}" if detail else ""
            raise AdbError(f"ADB failed while {operation}{suffix}")
        return result

    def list_devices(self) -> list[AdbDevice]:
        result = self._run(("devices", "-l"), timeout=20)
        self._require_success(result, "listing devices")
        return parse_adb_devices(result.stdout)

    def start_server(self) -> CommandResult:
        result = self._run(("start-server",), timeout=30)
        return self._require_success(result, "starting the ADB server")

    def find_device(self, serial: str) -> AdbDevice | None:
        selected = validate_serial(serial)
        return next((device for device in self.list_devices() if device.serial == selected), None)

    def require_authorized_device(self, serial: str) -> AdbDevice:
        selected = validate_serial(serial)
        device = self.find_device(selected)
        if device is None:
            raise AdbError(f"ADB device is no longer connected: {mask_serial(selected)}")
        if not device.authorized:
            raise AdbError(device_state_guidance(device.state))
        return device

    def run_for_device(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float = 30,
        check: bool = False,
        operation: str = "running a device command",
        sensitive_values: Sequence[str] = (),
    ) -> CommandResult:
        selected = validate_serial(serial)
        protected_values = tuple(dict.fromkeys((selected, *sensitive_values)))
        result = self._run(
            ("-s", selected, *_validate_arguments(arguments)),
            timeout=timeout,
            sensitive_values=protected_values,
        )
        return (
            self._require_success(
                result,
                operation,
                sensitive_values=protected_values,
            )
            if check
            else result
        )

    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float = 30,
        check: bool = False,
        operation: str = "running an Android shell command",
        sensitive_values: Sequence[str] = (),
    ) -> CommandResult:
        return self.run_for_device(
            serial,
            ("shell", *_validate_arguments(arguments)),
            timeout=timeout,
            check=check,
            operation=operation,
            sensitive_values=sensitive_values,
        )

    def get_properties(self, serial: str) -> dict[str, str]:
        result = self.shell(
            serial,
            ("getprop",),
            timeout=30,
            check=True,
            operation="reading Android properties",
        )
        return parse_getprop(result.stdout)

    def pull_file(
        self,
        serial: str,
        remote_path: str,
        destination: Path,
        *,
        timeout: float = 180,
    ) -> CommandResult:
        remote = validate_android_apk_path(remote_path)
        return self.run_for_device(
            serial,
            ("pull", remote, str(destination.resolve())),
            timeout=timeout,
            check=True,
            operation="pulling an application APK",
        )

    def push_managed_file(
        self,
        serial: str,
        source: Path,
        remote_path: str,
        *,
        timeout: float = 180,
    ) -> CommandResult:
        local = source.resolve()
        if not local.is_file():
            raise AdbError(f"Local file does not exist: {local.name}")
        remote = validate_managed_remote_path(remote_path)
        return self.run_for_device(
            serial,
            ("push", str(local), remote),
            timeout=timeout,
            check=True,
            operation="pushing a managed Android lab file",
        )

    def get_setting(self, serial: str, namespace: str, key: str) -> str | None:
        if namespace not in {"global", "secure", "system"}:
            raise AdbError(f"Unsupported Android settings namespace: {namespace}")
        if not _SETTING_NAME_PATTERN.fullmatch(key):
            raise AdbError("Android setting key contains unsupported characters.")
        result = self.shell(
            serial,
            ("settings", "get", namespace, key),
            timeout=20,
            check=True,
            operation=f"reading Android setting {namespace}.{key}",
        )
        value = result.stdout.strip()
        return None if value in {"", "null"} else value

    def put_setting(self, serial: str, namespace: str, key: str, value: str) -> None:
        if namespace != "global" or key != "http_proxy":
            raise AdbError("Only the managed global HTTP proxy setting may be changed.")
        self.shell(
            serial,
            ("settings", "put", namespace, key, value),
            timeout=20,
            check=True,
            operation="setting the managed Android HTTP proxy",
        )

    def delete_setting(self, serial: str, namespace: str, key: str) -> None:
        if namespace != "global" or key != "http_proxy":
            raise AdbError("Only the managed global HTTP proxy setting may be deleted.")
        self.shell(
            serial,
            ("settings", "delete", namespace, key),
            timeout=20,
            check=True,
            operation="clearing the Android HTTP proxy",
        )

    def list_reverse(self, serial: str) -> list[ReverseMapping]:
        result = self.run_for_device(
            serial,
            ("reverse", "--list"),
            timeout=20,
            check=True,
            operation="listing ADB reverse mappings",
        )
        return parse_reverse_list(result.stdout, validate_serial(serial))

    def add_reverse(self, serial: str, remote: str, local: str) -> None:
        remote_endpoint = validate_reverse_endpoint(remote)
        local_endpoint = validate_reverse_endpoint(local)
        self.run_for_device(
            serial,
            ("reverse", remote_endpoint, local_endpoint),
            timeout=20,
            check=True,
            operation=f"creating ADB reverse mapping {remote_endpoint}",
        )

    def remove_reverse(self, serial: str, remote: str) -> None:
        endpoint = validate_reverse_endpoint(remote)
        self.run_for_device(
            serial,
            ("reverse", "--remove", endpoint),
            timeout=20,
            check=True,
            operation=f"removing ADB reverse mapping {endpoint}",
        )

    def launch_package(self, serial: str, package: str) -> CommandResult:
        from .validation import validate_package_name

        target = validate_package_name(package)
        return self.shell(
            serial,
            (
                "monkey",
                "-p",
                target,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ),
            timeout=30,
            check=True,
            operation="launching the selected package",
        )

    def force_stop_package(self, serial: str, package: str) -> None:
        from .validation import validate_package_name

        target = validate_package_name(package)
        self.shell(
            serial,
            ("am", "force-stop", target),
            timeout=20,
            check=True,
            operation="stopping the selected package",
        )

    def start_activity(
        self,
        serial: str,
        package: str,
        component: str,
        *,
        canary: str,
        data_uri: str | None = None,
    ) -> CommandResult:
        from .validation import validate_component_name, validate_package_name

        target = validate_package_name(package)
        activity = validate_component_name(component)
        if not re.fullmatch(r"THESIS_CANARY_\d{8}T\d{6}Z_[a-f0-9]{12}", canary):
            raise AdbError("Controlled-validation canary has an invalid format.")
        arguments = ["am", "start", "-W"]
        if data_uri is not None:
            if len(data_uri) > 2048 or not data_uri.startswith("http://"):
                raise AdbError("Cleartext validation URI is invalid.")
            arguments.extend(("-a", "android.intent.action.VIEW", "-d", data_uri))
        arguments.extend(
            (
                "-n",
                f"{target}/{activity}",
                "--es",
                "thesis_canary",
                canary,
            )
        )
        return self.shell(
            serial,
            tuple(arguments),
            timeout=30,
            check=False,
            operation="starting an allowlisted activity for controlled validation",
        )
