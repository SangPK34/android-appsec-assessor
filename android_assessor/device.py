"""Explicit device selection and normalized Android identity data."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from .adb import AdbClient, AdbDevice, device_state_guidance, mask_serial, validate_serial
from .errors import DeviceSelectionError, SessionError
from .paths import ProjectPaths
from .storage import read_json_object, write_json_atomic


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    serial: str
    state: str
    model: str | None
    manufacturer: str | None
    product: str | None
    device: str | None
    android_version: str | None
    sdk: str | None
    security_patch: str | None
    build_id: str | None
    build_fingerprint: str | None
    abi: str | None
    transport_id: str | None

    @classmethod
    def from_adb(cls, device: AdbDevice, properties: dict[str, str]) -> DeviceInfo:
        return cls(
            serial=device.serial,
            state=device.state,
            model=properties.get("ro.product.model") or device.model,
            manufacturer=properties.get("ro.product.manufacturer"),
            product=properties.get("ro.product.name") or device.product,
            device=properties.get("ro.product.device") or device.device,
            android_version=properties.get("ro.build.version.release"),
            sdk=properties.get("ro.build.version.sdk"),
            security_patch=properties.get("ro.build.version.security_patch"),
            build_id=properties.get("ro.build.id"),
            build_fingerprint=properties.get("ro.build.fingerprint"),
            abi=properties.get("ro.product.cpu.abi"),
            transport_id=device.transport_id,
        )

    def to_dict(self, *, show_serial: bool = False) -> dict[str, Any]:
        data = asdict(self)
        data["serial"] = self.serial if show_serial else mask_serial(self.serial)
        data["serial_masked"] = mask_serial(self.serial)
        return data


class DeviceSelectionStore:
    def __init__(self, paths: ProjectPaths) -> None:
        self.paths = paths

    def save(self, device: AdbDevice) -> None:
        write_json_atomic(
            self.paths.active_device_file,
            {
                "schema_version": 1,
                "serial": device.serial,
                "serial_masked": mask_serial(device.serial),
                "model": device.model,
                "transport_id": device.transport_id,
                "selected_at": datetime.now(UTC).isoformat(),
            },
            root=self.paths.root,
        )

    def read_serial(self) -> str | None:
        if not self.paths.active_device_file.is_file():
            return None
        try:
            payload = read_json_object(self.paths.active_device_file, root=self.paths.root)
            serial = payload.get("serial")
            if not isinstance(serial, str):
                raise DeviceSelectionError("Active-device state does not contain a serial.")
            return validate_serial(serial)
        except SessionError as exc:
            raise DeviceSelectionError(f"Could not read active-device state: {exc}") from exc

    def clear(self) -> None:
        self.paths.active_device_file.unlink(missing_ok=True)


class DeviceSelector:
    def __init__(self, adb: AdbClient, store: DeviceSelectionStore) -> None:
        self.adb = adb
        self.store = store

    def select(self, serial: str) -> AdbDevice:
        selected = validate_serial(serial)
        device = next((item for item in self.adb.list_devices() if item.serial == selected), None)
        if device is None:
            raise DeviceSelectionError(
                f"ADB device is not connected: {mask_serial(selected)}"
            )
        if not device.authorized:
            raise DeviceSelectionError(device_state_guidance(device.state))
        self.store.save(device)
        return device

    def resolve(self, explicit_serial: str | None = None) -> AdbDevice:
        devices = self.adb.list_devices()
        serial = validate_serial(explicit_serial) if explicit_serial else self.store.read_serial()
        if serial is not None:
            device = next((item for item in devices if item.serial == serial), None)
            if device is None:
                raise DeviceSelectionError(
                    f"Selected ADB device is disconnected: {mask_serial(serial)}"
                )
            if not device.authorized:
                raise DeviceSelectionError(device_state_guidance(device.state))
            return device

        authorized = [device for device in devices if device.authorized]
        if not authorized:
            if devices:
                states = ", ".join(sorted({device.state for device in devices}))
                raise DeviceSelectionError(
                    f"No authorized ADB device is available (states: {states})."
                )
            raise DeviceSelectionError("No ADB devices are connected.")
        if len(authorized) == 1:
            raise DeviceSelectionError(
                "One authorized device is available but not selected. "
                "Run 'run.cmd devices --show-serial', then select it explicitly."
            )
        raise DeviceSelectionError(
            "Multiple authorized devices are connected. Use 'run.cmd devices --show-serial' "
            "and select one explicitly."
        )
