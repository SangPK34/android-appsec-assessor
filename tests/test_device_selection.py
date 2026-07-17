from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor.adb import AdbDevice
from android_assessor.device import DeviceSelectionStore, DeviceSelector
from android_assessor.errors import DeviceSelectionError
from android_assessor.paths import ProjectPaths


class FakeAdb:
    def __init__(self, devices: list[AdbDevice]) -> None:
        self.devices = devices

    def list_devices(self) -> list[AdbDevice]:
        return list(self.devices)


def selector_for(tmp_path: Path, devices: list[AdbDevice]) -> DeviceSelector:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    return DeviceSelector(FakeAdb(devices), DeviceSelectionStore(paths))  # type: ignore[arg-type]


def test_single_device_is_proposed_but_not_silently_selected(tmp_path: Path) -> None:
    selector = selector_for(tmp_path, [AdbDevice("ABC123", "device", model="Pixel")])

    with pytest.raises(DeviceSelectionError, match="not selected"):
        selector.resolve()


def test_multiple_devices_require_explicit_selection(tmp_path: Path) -> None:
    selector = selector_for(
        tmp_path,
        [AdbDevice("ABC123", "device"), AdbDevice("XYZ987", "device")],
    )

    with pytest.raises(DeviceSelectionError, match="Multiple authorized"):
        selector.resolve()


def test_selection_is_persisted_and_reused(tmp_path: Path) -> None:
    devices = [AdbDevice("ABC123", "device", model="Pixel_4_XL")]
    selector = selector_for(tmp_path, devices)

    selected = selector.select("ABC123")
    resolved = selector.resolve()

    assert selected.serial == "ABC123"
    assert resolved.serial == "ABC123"


def test_unauthorized_device_cannot_be_selected(tmp_path: Path) -> None:
    selector = selector_for(tmp_path, [AdbDevice("ABC123", "unauthorized")])

    with pytest.raises(DeviceSelectionError, match="RSA prompt"):
        selector.select("ABC123")
