"""Read-only Android device inspection service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..adb import AdbClient
from ..capabilities import CapabilityDetector, CapabilityReport
from ..device import DeviceInfo, DeviceSelector


@dataclass(frozen=True, slots=True)
class DeviceInspection:
    device: DeviceInfo
    capabilities: CapabilityReport

    def to_dict(self, *, show_serial: bool = False) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "device": self.device.to_dict(show_serial=show_serial),
            "capabilities": self.capabilities.to_dict(show_serial=show_serial),
        }


class DeviceService:
    def __init__(
        self,
        adb: AdbClient,
        selector: DeviceSelector,
        detector: CapabilityDetector,
    ) -> None:
        self.adb = adb
        self.selector = selector
        self.detector = detector

    def inspect(
        self,
        *,
        serial: str | None = None,
        package: str | None = None,
    ) -> DeviceInspection:
        selected = self.selector.resolve(serial)
        properties = self.adb.get_properties(selected.serial)
        info = DeviceInfo.from_adb(selected, properties)
        capabilities = self.detector.detect(selected.serial, package=package)
        return DeviceInspection(device=info, capabilities=capabilities)
