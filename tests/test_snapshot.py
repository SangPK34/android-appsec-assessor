from __future__ import annotations

from android_assessor.adb import ReverseMapping
from android_assessor.errors import AdbError
from android_assessor.snapshot import ProxySnapshotState, capture_device_snapshot
from android_assessor.subprocess_utils import CommandResult


def command_result(*, exit_code: int = 0, stdout: str = "") -> CommandResult:
    return CommandResult(
        arguments=(),
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=False,
    )


class FakeAdb:
    def get_setting(self, serial: str, namespace: str, key: str) -> str:
        del serial, namespace, key
        return "10.0.0.1:8888"

    def list_reverse(self, serial: str) -> list[ReverseMapping]:
        del serial
        return [ReverseMapping("tcp:8080", "tcp:8080")]

    def shell(self, serial: str, arguments: tuple[str, ...], **_kwargs: object) -> CommandResult:
        del serial
        if arguments == ("pidof", "frida-server"):
            return command_result(stdout="4321")
        if arguments[0:2] == ("pm", "path"):
            return command_result(stdout="package:/data/app/base.apk")
        return command_result(exit_code=1)


def test_snapshot_records_only_initial_read_only_state() -> None:
    snapshot = capture_device_snapshot(
        FakeAdb(),  # type: ignore[arg-type]
        "ABC123",
        "com.example.app",
    )

    assert snapshot.http_proxy == "10.0.0.1:8888"
    assert snapshot.http_proxy_state is ProxySnapshotState.CAPTURED_WITH_VALUE
    assert snapshot.http_proxy_error is None
    assert snapshot.reverse_mappings[0].remote == "tcp:8080"
    assert snapshot.frida_server_running is True
    assert snapshot.frida_process_names == ("frida-server",)
    assert snapshot.target_package_installed is True
    assert snapshot.errors == ()


class FailedProxySnapshotAdb(FakeAdb):
    def get_setting(self, serial: str, namespace: str, key: str) -> str:
        del serial, namespace, key
        raise AdbError("settings read failed")


def test_snapshot_records_proxy_capture_failure_explicitly() -> None:
    snapshot = capture_device_snapshot(
        FailedProxySnapshotAdb(),  # type: ignore[arg-type]
        "ABC123",
        "com.example.app",
    )

    assert snapshot.http_proxy is None
    assert snapshot.http_proxy_state is ProxySnapshotState.CAPTURE_FAILED
    assert snapshot.http_proxy_error == "settings read failed"
    assert snapshot.to_dict()["http_proxy_state"] == "CAPTURE_FAILED"
