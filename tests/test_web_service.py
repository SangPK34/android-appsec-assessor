from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from android_assessor.adb import AdbDevice
from android_assessor.device import DeviceSelectionStore, DeviceSelector
from android_assessor.errors import AndroidAssessorError
from android_assessor.paths import ProjectPaths
from android_assessor.session import SessionRepository
from android_assessor.storage import write_json_atomic
from android_assessor.web_service import RepairController, WebBackend


class FakePopen:
    def __init__(self) -> None:
        self.pid = 4321
        self.exit_code: int | None = None

    def poll(self) -> int | None:
        return self.exit_code


def test_repair_controller_starts_only_fixed_project_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "Lab With Spaces"
    root.mkdir()
    script = root / "repair.cmd"
    script.write_text("@exit /b 0\n", encoding="utf-8")
    process = FakePopen()
    captured: dict[str, Any] = {}

    def fake_popen(command: list[str], **kwargs: Any) -> FakePopen:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setenv("COMSPEC", "C:\\Windows\\System32\\cmd.exe")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    controller = RepairController(root)

    state = controller.start()

    assert state.running is True
    assert state.pid == 4321
    assert captured["command"] == [
        "C:\\Windows\\System32\\cmd.exe",
        "/d",
        "/c",
        str(script),
    ]
    assert captured["kwargs"]["cwd"] == root.resolve()
    assert captured["kwargs"]["shell"] is False
    with pytest.raises(AndroidAssessorError, match="already running"):
        controller.start()


def test_repair_controller_rejects_missing_script(tmp_path: Path) -> None:
    controller = RepairController(tmp_path)

    with pytest.raises(AndroidAssessorError, match="repair.cmd is missing"):
        controller.start()


class FakeAdb:
    def list_devices(self) -> list[AdbDevice]:
        return [AdbDevice("ABCDEF7890", "device", model="Pixel_4_XL", transport_id="1")]


class FakeContext:
    def __init__(self, paths: ProjectPaths, adb: FakeAdb) -> None:
        self.paths = paths
        self.config = None
        self._adb = adb

    def adb_client(self, **_kwargs: object) -> FakeAdb:
        return self._adb

    def device_selector(self, adb: FakeAdb | None = None) -> DeviceSelector:
        return DeviceSelector(
            adb or self._adb,
            DeviceSelectionStore(self.paths),
        )  # type: ignore[arg-type]


def test_web_device_inventory_masks_display_but_keeps_selection_value(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    context = FakeContext(paths, FakeAdb())
    context.device_selector().select("ABCDEF7890")
    backend = WebBackend(context)  # type: ignore[arg-type]

    inventory = backend.devices()

    assert inventory["active_serial_masked"] == "AB****7890"
    assert inventory["devices"][0]["serial"] == "AB****7890"
    assert inventory["devices"][0]["selection_value"] == "ABCDEF7890"
    assert inventory["devices"][0]["selected"] is True


def test_web_setup_log_is_bounded_and_redacted(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    (paths.logs_dir / "setup.log").write_text(
        "Authorization: Bearer top-secret-token\nSetup complete\n",
        encoding="utf-8",
    )
    backend = WebBackend(FakeContext(paths, FakeAdb()))  # type: ignore[arg-type]

    content = backend.setup_log()

    assert "top-secret-token" not in content
    assert "<redacted>" in content
    assert "Setup complete" in content


def test_session_detail_renders_report_dict_findings_without_to_dict_error(
    tmp_path: Path,
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    repository = SessionRepository(paths)
    record = repository.initialize(serial="emulator-5554", package="com.example.app")
    repository.activate(record.session_id, snapshot={}, device={}, environment={})
    write_json_atomic(
        repository.paths_for(record.session_id).report_json,
        {
            "findings": [{"rule_id": "STATIC-001", "status": "potential"}],
            "runtime_checks": [],
            "runtime_observations": [],
        },
        root=paths.root,
    )

    detail = WebBackend(FakeContext(paths, FakeAdb())).session_detail(record.session_id)  # type: ignore[arg-type]

    assert detail["findings"] == [{"rule_id": "STATIC-001", "status": "potential"}]
