from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor import adb as adb_module
from android_assessor.adb import (
    AdbClient,
    mask_serial,
    parse_adb_devices,
    parse_getprop,
    parse_reverse_list,
    validate_serial,
)
from android_assessor.errors import AdbError, AdbTimeoutError
from android_assessor.subprocess_utils import CommandResult

ADB_OUTPUT = """List of devices attached
ABC123 device product:coral model:Pixel_4_XL device:coral transport_id:1
ZXCV987 unauthorized usb:2-1 transport_id:2
emulator-5554 offline transport_id:3
"""


def test_parses_multiple_adb_states_and_metadata() -> None:
    devices = parse_adb_devices(ADB_OUTPUT)

    assert [device.state for device in devices] == ["device", "unauthorized", "offline"]
    assert devices[0].model == "Pixel_4_XL"
    assert devices[0].transport_id == "1"


def test_mask_serial_keeps_only_small_edges() -> None:
    masked = mask_serial("ABC1234567")

    assert masked.startswith("AB")
    assert masked.endswith("4567")
    assert "C123" not in masked


@pytest.mark.parametrize("serial", ["ABC123", "emulator-5554", "192.168.1.8:5555"])
def test_accepts_expected_serial_formats(serial: str) -> None:
    assert validate_serial(serial) == serial


@pytest.mark.parametrize("serial", ["", "A B", "abc;whoami", "../device"])
def test_rejects_unsafe_serial_formats(serial: str) -> None:
    with pytest.raises(AdbError):
        validate_serial(serial)


def test_parses_getprop_without_shell_tools() -> None:
    output = """[ro.product.model]: [Pixel 4 XL]
[ro.build.version.release]: [13]
garbage
"""

    assert parse_getprop(output) == {
        "ro.product.model": "Pixel 4 XL",
        "ro.build.version.release": "13",
    }


def test_parses_reverse_list_for_only_selected_serial() -> None:
    output = "ABC123 tcp:8080 tcp:8080\nOTHER tcp:9000 tcp:9000\n"

    mappings = parse_reverse_list(output, "ABC123")

    assert [(item.remote, item.local) for item in mappings] == [("tcp:8080", "tcp:8080")]


def test_parses_reverse_list_with_scoped_transport_label() -> None:
    output = (
        "host-12 tcp:8080 tcp:8080\n"
        "ABC123 tcp:8081 tcp:8081\n"
        "OTHER tcp:9000 tcp:9000\n"
        "host-invalid tcp:9001 tcp:9001\n"
    )

    mappings = parse_reverse_list(output, "ABC123")

    assert [(item.remote, item.local) for item in mappings] == [
        ("tcp:8080", "tcp:8080"),
        ("tcp:8081", "tcp:8081"),
    ]


def test_list_reverse_scopes_command_to_selected_serial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "platform tools" / "adb.exe"
    executable.parent.mkdir()
    executable.touch()
    captured: list[str] = []

    def fake_run(arguments: object, **_kwargs: object) -> CommandResult:
        captured.extend(str(item) for item in arguments)  # type: ignore[union-attr]
        return CommandResult(
            arguments=(),
            exit_code=0,
            stdout="host-12 tcp:8080 tcp:8080\n",
            stderr="",
            started_at="2026-07-17T00:00:00+00:00",
            duration_ms=1,
            timed_out=False,
        )

    monkeypatch.setattr(adb_module, "run_command", fake_run)
    client = AdbClient(executable)

    mappings = client.list_reverse("ABC123")

    assert captured[1:] == ["-s", "ABC123", "reverse", "--list"]
    assert [(item.remote, item.local) for item in mappings] == [("tcp:8080", "tcp:8080")]


def test_device_command_always_includes_explicit_serial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "platform tools" / "adb.exe"
    executable.parent.mkdir()
    executable.touch()
    captured: list[object] = []

    def fake_run(arguments: object, **_kwargs: object) -> CommandResult:
        captured.extend(arguments)  # type: ignore[arg-type]
        return CommandResult(
            arguments=(),
            exit_code=0,
            stdout="ok",
            stderr="",
            started_at="2026-07-17T00:00:00+00:00",
            duration_ms=1,
            timed_out=False,
        )

    monkeypatch.setattr(adb_module, "run_command", fake_run)
    client = AdbClient(executable)

    client.shell("ABC123", ("getprop", "ro.product.model"), check=True)

    assert captured[1:4] == ["-s", "ABC123", "shell"]


def test_apk_pull_uses_explicit_serial_and_list_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "platform tools" / "adb.exe"
    destination = tmp_path / "session with spaces" / "base.apk.part"
    executable.parent.mkdir()
    destination.parent.mkdir()
    executable.touch()
    captured: list[str] = []

    def fake_run(arguments: object, **_kwargs: object) -> CommandResult:
        captured.extend(str(item) for item in arguments)  # type: ignore[union-attr]
        return CommandResult(
            arguments=(),
            exit_code=0,
            stdout="1 file pulled",
            stderr="",
            started_at="2026-07-17T00:00:00+00:00",
            duration_ms=1,
            timed_out=False,
        )

    monkeypatch.setattr(adb_module, "run_command", fake_run)

    AdbClient(executable).pull_file("ABC123", "/data/app/example/base.apk", destination)

    assert captured[1:5] == ["-s", "ABC123", "pull", "/data/app/example/base.apk"]
    assert captured[5] == str(destination.resolve())


def test_checked_device_timeout_is_typed_and_forwards_sensitive_log_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "platform tools" / "adb.exe"
    command_log = tmp_path / "session" / "commands.jsonl"
    executable.parent.mkdir()
    executable.touch()
    captured: dict[str, object] = {}

    def fake_run(arguments: object, **kwargs: object) -> CommandResult:
        captured["arguments"] = arguments
        captured.update(kwargs)
        return CommandResult(
            arguments=(),
            exit_code=-1,
            stdout="",
            stderr="",
            started_at="2026-07-18T00:00:00+00:00",
            duration_ms=1000,
            timed_out=True,
        )

    monkeypatch.setattr(adb_module, "run_command", fake_run)
    canary = "THESIS_CANARY_20260718T010203Z_deadbeefcafe"
    client = AdbClient(executable, command_log=command_log)

    with pytest.raises(AdbTimeoutError, match="entering bounded fixture input"):
        client.shell(
            "ABC123",
            ("input", "text", canary),
            timeout=1,
            check=True,
            operation="entering bounded fixture input",
            sensitive_values=(canary,),
        )

    assert captured["command_log"] == command_log.resolve()
    sensitive_values = captured["sensitive_values"]
    assert isinstance(sensitive_values, tuple)
    assert set(sensitive_values) == {"ABC123", canary}
