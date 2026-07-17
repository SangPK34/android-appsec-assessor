from __future__ import annotations

from pathlib import Path

from android_assessor.adb import AdbDevice
from android_assessor.capabilities import (
    CapabilityDetector,
    CapabilityName,
    CapabilityState,
)
from android_assessor.subprocess_utils import CommandResult


def command_result(
    arguments: tuple[str, ...],
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        arguments=arguments,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=timed_out,
    )


class FakeAdb:
    executable = Path("D:/lab/tools/platform-tools/adb.exe")

    def __init__(
        self,
        *,
        rooted: bool,
        zygisk: bool = False,
        adbd_root: bool = False,
    ) -> None:
        self.rooted = rooted
        self.zygisk = zygisk
        self.adbd_root = adbd_root

    def require_authorized_device(self, serial: str) -> AdbDevice:
        return AdbDevice(serial, "device", model="Pixel_4_XL")

    def shell(
        self,
        serial: str,
        arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> CommandResult:
        del serial
        if arguments == ("id",):
            return command_result(
                arguments,
                stdout=(
                    "uid=0(root) gid=0(root)"
                    if self.adbd_root
                    else "uid=2000(shell) gid=2000(shell)"
                ),
            )
        if arguments == ("command", "-v", "su"):
            return command_result(
                arguments,
                exit_code=0 if self.rooted else 1,
                stdout="/system/xbin/su\n" if self.rooted else "",
            )
        if arguments == ("su", "-c", "id"):
            return command_result(
                arguments,
                exit_code=0 if self.rooted else 1,
                stdout="uid=0(root) gid=0(root)" if self.rooted else "",
            )
        if arguments[0:2] == ("su", "-c") and "magisk -v" in arguments[-1]:
            return command_result(arguments, stdout="28.1")
        if arguments[0:2] == ("su", "-c") and "SELECT value" in arguments[-1]:
            return command_result(arguments, stdout=f"value={1 if self.zygisk else 0}")
        if arguments[0] == "pidof":
            return command_result(arguments, exit_code=1)
        if arguments[0] == "run-as":
            return command_result(arguments, exit_code=1)
        if arguments[0:2] == ("su", "-c") and arguments[-1].startswith("test -d"):
            return command_result(arguments, exit_code=0 if self.rooted else 1)
        if arguments[0:2] == ("pm", "path"):
            return command_result(arguments, stdout="package:/system/framework/framework-res.apk")
        if arguments[0] == "command":
            return command_result(arguments, stdout="/system/bin/screencap")
        return command_result(arguments)


def test_unrooted_detection_skips_package_specific_capability() -> None:
    detector = CapabilityDetector(
        FakeAdb(rooted=False),  # type: ignore[arg-type]
        {
            CapabilityName.FRIDA_CLIENT: None,
            CapabilityName.SCRCPY_AVAILABLE: "D:/lab/tools/scrcpy/scrcpy.exe",
            CapabilityName.AAPT2_AVAILABLE: "D:/lab/tools/build-tools/aapt2.exe",
            CapabilityName.MITMPROXY_AVAILABLE: None,
        },
    )

    report = detector.detect("ABC123")

    assert len(report.capabilities) == len(CapabilityName)
    assert report.get(CapabilityName.ANDROID_ROOT).state is CapabilityState.UNAVAILABLE
    assert report.get(CapabilityName.APP_DATA_READ).state is CapabilityState.SKIPPED
    assert report.get(CapabilityName.SCRCPY_AVAILABLE).available is True
    assert report.get(CapabilityName.MITMPROXY_AVAILABLE).available is False


def test_root_assisted_storage_is_labeled_without_claiming_vulnerability() -> None:
    detector = CapabilityDetector(FakeAdb(rooted=True, zygisk=True), {})  # type: ignore[arg-type]

    report = detector.detect("ABC123", package="com.example.app")
    app_data = report.get(CapabilityName.APP_DATA_READ)

    assert report.get(CapabilityName.ANDROID_ROOT).available is True
    assert report.get(CapabilityName.ANDROID_ROOT).metadata["root_mode"] == "su_root"
    assert report.get(CapabilityName.ZYGISK_AVAILABLE).available is True
    assert app_data.available is True
    assert app_data.detail is not None
    assert "does not establish an app vulnerability" in app_data.detail


def test_adbd_root_capability_exposes_mode_status_and_evidence() -> None:
    detector = CapabilityDetector(
        FakeAdb(rooted=True, adbd_root=True),  # type: ignore[arg-type]
        {},
    )

    root = detector.detect("ABC123").get(CapabilityName.ANDROID_ROOT)

    assert root.available is True
    assert root.metadata["root_available"] is True
    assert root.metadata["root_mode"] == "adb_root"
    assert root.metadata["root_probe_status"] == "verified"
    assert root.metadata["root_probe_evidence"]["strategy"] == "adb_shell_id"
