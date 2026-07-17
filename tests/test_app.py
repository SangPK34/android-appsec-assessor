from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor.adb import AdbDevice
from android_assessor.app import (
    ApplicationSelectionStore,
    ApplicationService,
    parse_user_packages,
)
from android_assessor.device import DeviceSelectionStore, DeviceSelector
from android_assessor.errors import AndroidAssessorError
from android_assessor.paths import ProjectPaths
from android_assessor.subprocess_utils import CommandResult


def command_result(stdout: str) -> CommandResult:
    return CommandResult(
        arguments=(),
        exit_code=0,
        stdout=stdout,
        stderr="",
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=False,
    )


class FakeAdb:
    def __init__(self) -> None:
        self.commands: list[tuple[str, tuple[str, ...]]] = []

    def list_devices(self) -> list[AdbDevice]:
        return [AdbDevice("ABC123", "device", model="Pixel_4_XL")]

    def shell(
        self,
        serial: str,
        arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> CommandResult:
        self.commands.append((serial, arguments))
        return command_result(
            "package:/data/app/~~x/com.example.beta/base.apk=com.example.beta uid:10102\r\n"
            "package:/data/app/~~x/com.example.alpha/base.apk=com.example.alpha uid:10101\n"
            "garbage\n"
        )


def make_service(tmp_path: Path) -> tuple[ApplicationService, ApplicationSelectionStore, FakeAdb]:
    paths = ProjectPaths(tmp_path / "Android Security Lab")
    paths.ensure_layout()
    adb = FakeAdb()
    selector = DeviceSelector(adb, DeviceSelectionStore(paths))  # type: ignore[arg-type]
    selector.select("ABC123")
    store = ApplicationSelectionStore(paths)
    return ApplicationService(adb, selector, store), store, adb  # type: ignore[arg-type]


def test_parse_user_packages_extracts_path_uid_and_sorts() -> None:
    apps = parse_user_packages(
        "package:/data/app/b/base.apk=com.example.beta uid:10102\n"
        "package:/data/app/a/base.apk=com.example.alpha uid:not-a-number\n"
        "package:invalid package uid:10000\n"
    )

    assert [app.package for app in apps] == ["com.example.alpha", "com.example.beta"]
    assert apps[0].apk_path == "/data/app/a/base.apk"
    assert apps[0].uid is None
    assert apps[1].uid == 10102


def test_list_user_apps_uses_fixed_adb_arguments_and_python_filter(tmp_path: Path) -> None:
    service, _store, adb = make_service(tmp_path)

    serial, apps = service.list_user_apps(query="ALPHA")

    assert serial == "ABC123"
    assert [app.package for app in apps] == ["com.example.alpha"]
    assert adb.commands == [
        ("ABC123", ("pm", "list", "packages", "-3", "-f", "-U"))
    ]


def test_select_package_persists_target_for_selected_device(tmp_path: Path) -> None:
    service, store, _adb = make_service(tmp_path)

    selected = service.select("com.example.beta")

    assert selected.package == "com.example.beta"
    assert store.read(serial="ABC123") == "com.example.beta"
    assert store.read(serial="OTHER123") is None


def test_rejects_search_control_characters(tmp_path: Path) -> None:
    service, _store, _adb = make_service(tmp_path)

    with pytest.raises(AndroidAssessorError, match="query is invalid"):
        service.list_user_apps(query="alpha\ncommand")
