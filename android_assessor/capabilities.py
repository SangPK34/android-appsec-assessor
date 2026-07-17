"""Automatic host and Android capability detection."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .adb import AdbClient, mask_serial
from .errors import AdbError
from .magisk import probe_magisk
from .redaction import redact_text
from .root import probe_root
from .validation import validate_package_name


class CapabilityName(StrEnum):
    ADB_AVAILABLE = "ADB_AVAILABLE"
    ADB_AUTHORIZED = "ADB_AUTHORIZED"
    ANDROID_ROOT = "ANDROID_ROOT"
    MAGISK_AVAILABLE = "MAGISK_AVAILABLE"
    ZYGISK_AVAILABLE = "ZYGISK_AVAILABLE"
    FRIDA_CLIENT = "FRIDA_CLIENT"
    FRIDA_SERVER = "FRIDA_SERVER"
    APP_DATA_READ = "APP_DATA_READ"
    APK_PULL = "APK_PULL"
    LOGCAT_ACCESS = "LOGCAT_ACCESS"
    PROXY_CONFIGURATION = "PROXY_CONFIGURATION"
    SCREEN_CAPTURE = "SCREEN_CAPTURE"
    SCRCPY_AVAILABLE = "SCRCPY_AVAILABLE"
    AAPT2_AVAILABLE = "AAPT2_AVAILABLE"
    MITMPROXY_AVAILABLE = "MITMPROXY_AVAILABLE"


class CapabilityState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Capability:
    name: CapabilityName
    state: CapabilityState
    reason: str
    detail: str | None = None

    @property
    def available(self) -> bool:
        return self.state is CapabilityState.AVAILABLE

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["name"] = self.name.value
        value["state"] = self.state.value
        value["available"] = self.available
        return value


@dataclass(frozen=True, slots=True)
class CapabilityReport:
    serial: str
    package: str | None
    generated_at: str
    capabilities: tuple[Capability, ...]

    def get(self, name: CapabilityName) -> Capability:
        return next(capability for capability in self.capabilities if capability.name is name)

    def to_dict(self, *, show_serial: bool = False) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "serial": self.serial if show_serial else mask_serial(self.serial),
            "serial_masked": mask_serial(self.serial),
            "package": self.package,
            "generated_at": self.generated_at,
            "capabilities": [capability.to_dict() for capability in self.capabilities],
        }


class CapabilityDetector:
    def __init__(
        self,
        adb: AdbClient,
        host_tools: Mapping[CapabilityName, str | None],
    ) -> None:
        self.adb = adb
        self.host_tools = dict(host_tools)

    @staticmethod
    def _host_capability(
        name: CapabilityName,
        path: str | None,
        missing_reason: str,
    ) -> Capability:
        if path:
            return Capability(
                name=name,
                state=CapabilityState.AVAILABLE,
                reason="Host dependency was discovered.",
                detail=path,
            )
        return Capability(
            name=name,
            state=CapabilityState.UNAVAILABLE,
            reason=missing_reason,
        )

    def _shell_probe(
        self,
        serial: str,
        name: CapabilityName,
        arguments: Sequence[str],
        *,
        available_reason: str,
        unavailable_reason: str,
        require_output: bool = False,
        timeout: float = 15,
    ) -> Capability:
        try:
            result = self.adb.shell(
                serial,
                arguments,
                timeout=timeout,
                check=False,
                operation=f"probing {name.value}",
            )
        except AdbError as exc:
            return Capability(
                name=name,
                state=CapabilityState.ERROR,
                reason="Capability probe failed.",
                detail=redact_text(str(exc))[:300],
            )
        successful = not result.timed_out and result.exit_code == 0
        if require_output:
            successful = successful and bool(result.stdout.strip())
        return Capability(
            name=name,
            state=CapabilityState.AVAILABLE if successful else CapabilityState.UNAVAILABLE,
            reason=available_reason if successful else unavailable_reason,
        )

    def _probe_frida_server(self, serial: str) -> Capability:
        try:
            for process_name in ("frida-server", "re.frida.server"):
                result = self.adb.shell(
                    serial,
                    ("pidof", process_name),
                    timeout=10,
                    check=False,
                    operation="probing Frida Server",
                )
                if not result.timed_out and result.exit_code == 0 and result.stdout.strip():
                    return Capability(
                        name=CapabilityName.FRIDA_SERVER,
                        state=CapabilityState.AVAILABLE,
                        reason="A known Frida Server process is running.",
                        detail=process_name,
                    )
        except AdbError as exc:
            return Capability(
                name=CapabilityName.FRIDA_SERVER,
                state=CapabilityState.ERROR,
                reason="Frida Server process detection failed.",
                detail=redact_text(str(exc))[:300],
            )
        return Capability(
            name=CapabilityName.FRIDA_SERVER,
            state=CapabilityState.UNAVAILABLE,
            reason="No known Frida Server process was detected.",
        )

    def _probe_app_data(self, serial: str, package: str | None, root_available: bool) -> Capability:
        if package is None:
            return Capability(
                name=CapabilityName.APP_DATA_READ,
                state=CapabilityState.SKIPPED,
                reason="A package is required for app-data capability detection.",
            )
        target = validate_package_name(package)
        try:
            run_as = self.adb.shell(
                serial,
                ("run-as", target, "id"),
                timeout=10,
                check=False,
                operation="probing run-as app-data access",
            )
        except AdbError as exc:
            return Capability(
                name=CapabilityName.APP_DATA_READ,
                state=CapabilityState.ERROR,
                reason="App-data capability probe failed.",
                detail=redact_text(str(exc))[:300],
            )
        if not run_as.timed_out and run_as.exit_code == 0 and "uid=" in run_as.stdout:
            return Capability(
                name=CapabilityName.APP_DATA_READ,
                state=CapabilityState.AVAILABLE,
                reason="App data is readable through run-as.",
                detail="run-as",
            )
        if root_available:
            command = f"test -d /data/user/0/{target} || test -d /data/data/{target}"
            try:
                root_result = self.adb.shell(
                    serial,
                    ("su", "-c", command),
                    timeout=10,
                    check=False,
                    operation="probing root-assisted app-data access",
                )
            except AdbError as exc:
                return Capability(
                    name=CapabilityName.APP_DATA_READ,
                    state=CapabilityState.ERROR,
                    reason="Root-assisted app-data capability probe failed.",
                    detail=redact_text(str(exc))[:300],
                )
            if not root_result.timed_out and root_result.exit_code == 0:
                return Capability(
                    name=CapabilityName.APP_DATA_READ,
                    state=CapabilityState.AVAILABLE,
                    reason="App data is readable only with Android root.",
                    detail="root_assisted; this does not establish an app vulnerability",
                )
        return Capability(
            name=CapabilityName.APP_DATA_READ,
            state=CapabilityState.UNAVAILABLE,
            reason="Neither run-as nor root-assisted access was available for the package.",
        )

    def detect(self, serial: str, *, package: str | None = None) -> CapabilityReport:
        self.adb.require_authorized_device(serial)
        root = probe_root(self.adb, serial)
        magisk = probe_magisk(self.adb, serial, root)

        capabilities: list[Capability] = [
            Capability(
                CapabilityName.ADB_AVAILABLE,
                CapabilityState.AVAILABLE,
                "The configured ADB client is available.",
                str(self.adb.executable),
            ),
            Capability(
                CapabilityName.ADB_AUTHORIZED,
                CapabilityState.AVAILABLE,
                "The selected device is in ADB state 'device'.",
            ),
            Capability(
                CapabilityName.ANDROID_ROOT,
                CapabilityState.AVAILABLE if root.available else CapabilityState.UNAVAILABLE,
                "su returned uid=0." if root.available else "su did not provide uid=0.",
                root.identity if root.available else root.error,
            ),
            Capability(
                CapabilityName.MAGISK_AVAILABLE,
                CapabilityState.AVAILABLE if magisk.available else CapabilityState.UNAVAILABLE,
                "Magisk CLI is available through su."
                if magisk.available
                else "Magisk CLI was not available through su.",
                magisk.version if magisk.available else magisk.error,
            ),
        ]
        if magisk.zygisk_enabled is None:
            capabilities.append(
                Capability(
                    CapabilityName.ZYGISK_AVAILABLE,
                    CapabilityState.UNKNOWN,
                    "Zygisk state could not be determined without changing the device.",
                )
            )
        else:
            capabilities.append(
                Capability(
                    CapabilityName.ZYGISK_AVAILABLE,
                    CapabilityState.AVAILABLE
                    if magisk.zygisk_enabled
                    else CapabilityState.UNAVAILABLE,
                    "Zygisk is enabled."
                    if magisk.zygisk_enabled
                    else "Zygisk is disabled.",
                )
            )

        capabilities.extend(
            (
                self._host_capability(
                    CapabilityName.FRIDA_CLIENT,
                    self.host_tools.get(CapabilityName.FRIDA_CLIENT),
                    "Frida client is missing; run repair.cmd.",
                ),
                self._probe_frida_server(serial),
                self._probe_app_data(serial, package, root.available),
                self._shell_probe(
                    serial,
                    CapabilityName.APK_PULL,
                    ("pm", "path", "android"),
                    available_reason="Package Manager returned an APK path.",
                    unavailable_reason="Package Manager did not return an APK path.",
                    require_output=True,
                ),
                self._shell_probe(
                    serial,
                    CapabilityName.LOGCAT_ACCESS,
                    ("logcat", "-d", "-t", "1"),
                    available_reason="A bounded logcat read succeeded.",
                    unavailable_reason="The bounded logcat read failed.",
                ),
                self._shell_probe(
                    serial,
                    CapabilityName.PROXY_CONFIGURATION,
                    ("settings", "get", "global", "http_proxy"),
                    available_reason="The global HTTP proxy setting is readable.",
                    unavailable_reason="The global HTTP proxy setting is not accessible.",
                ),
                self._shell_probe(
                    serial,
                    CapabilityName.SCREEN_CAPTURE,
                    ("command", "-v", "screencap"),
                    available_reason="Android screencap is present.",
                    unavailable_reason="Android screencap was not found.",
                    require_output=True,
                ),
                self._host_capability(
                    CapabilityName.SCRCPY_AVAILABLE,
                    self.host_tools.get(CapabilityName.SCRCPY_AVAILABLE),
                    "scrcpy is missing; run repair.cmd.",
                ),
                self._host_capability(
                    CapabilityName.AAPT2_AVAILABLE,
                    self.host_tools.get(CapabilityName.AAPT2_AVAILABLE),
                    "aapt2 is missing; run repair.cmd.",
                ),
                self._host_capability(
                    CapabilityName.MITMPROXY_AVAILABLE,
                    self.host_tools.get(CapabilityName.MITMPROXY_AVAILABLE),
                    "mitmdump is missing; run repair.cmd.",
                ),
            )
        )
        return CapabilityReport(
            serial=serial,
            package=package,
            generated_at=datetime.now(UTC).isoformat(),
            capabilities=tuple(capabilities),
        )
