# ruff: noqa: E501
from __future__ import annotations

import json
from pathlib import Path

import pytest

from android_assessor import manifest as manifest_module
from android_assessor import signature as signature_module
from android_assessor.config import LabConfig
from android_assessor.paths import ProjectPaths
from android_assessor.services.app_inspection_service import AppInspectionService
from android_assessor.session import SessionRepository, SessionStatus
from android_assessor.subprocess_utils import CommandResult

PM_PATHS = """package:/data/app/example/base.apk
package:/data/app/example/split_config.arm64_v8a.apk
"""

DUMPSYS = """Package [com.example.lab]:
  userId=10123
  versionCode=42 minSdk=23 targetSdk=34
  versionName=4.2
  dataDir=/data/user/0/com.example.lab
"""

BADGING = """package: name='com.example.lab' versionCode='42' versionName='4.2' compileSdkVersion='35'
sdkVersion:'23'
targetSdkVersion:'34'
application-label:'Lab App'
uses-permission: name='android.permission.INTERNET'
"""

XMLTREE = """E: manifest
  A: package="com.example.lab" (Raw: "com.example.lab")
  E: uses-permission
    A: android:name="android.permission.INTERNET" (Raw: "android.permission.INTERNET")
  E: application
    A: android:debuggable=(type 0x12)0x0
    A: android:allowBackup=(type 0x12)0xffffffff
    A: api_key="MANIFEST_API_KEY_SUPER_SECRET"
    E: activity
      A: android:name=".MainActivity" (Raw: ".MainActivity")
      A: android:exported=(type 0x12)0xffffffff
"""

SIGNATURE = """Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Signer #1 certificate DN: CN=Lab,O=Thesis,C=VN
Signer #1 certificate SHA-256 digest: aabbccdd
"""


def result(stdout: str) -> CommandResult:
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
    def shell(
        self,
        serial: str,
        arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> CommandResult:
        assert serial == "ABC123"
        if arguments[:2] == ("pm", "path"):
            return result(PM_PATHS)
        if arguments[:2] == ("dumpsys", "package"):
            return result(DUMPSYS)
        raise AssertionError(arguments)

    def pull_file(
        self,
        serial: str,
        remote_path: str,
        destination: Path,
        *,
        timeout: float = 180,
    ) -> CommandResult:
        del timeout
        assert serial == "ABC123"
        destination.write_bytes(("APK:" + remote_path).encode())
        return result("1 file pulled")


class FakeContext:
    def __init__(self, paths: ProjectPaths, config: LabConfig) -> None:
        self.paths = paths
        self.config = config
        self.adb = FakeAdb()

    def adb_client(self, **_kwargs: object) -> FakeAdb:
        return self.adb


def prepared_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    with_tools: bool,
) -> tuple[AppInspectionService, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "Android Lab có dấu")
    paths.ensure_layout()
    tools: dict[str, str | None] = {}
    if with_tools:
        aapt2 = paths.tools_dir / "build-tools" / "aapt2.exe"
        java = paths.tools_dir / "java" / "bin" / "java.exe"
        jar = paths.tools_dir / "build-tools" / "lib" / "apksigner.jar"
        for path in (aapt2, java, jar):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"tool")
        tools = {
            "aapt2": "tools/build-tools/aapt2.exe",
            "java": "tools/java/bin/java.exe",
        }
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.lab")
    repository.activate(record.session_id, snapshot={}, device={}, environment={})
    service = AppInspectionService(
        FakeContext(paths, LabConfig(tools=tools)),  # type: ignore[arg-type]
        repository,
    )
    monkeypatch.setattr(service, "_create_session", lambda _package, _serial: record)
    return service, repository, record.session_id


def test_app_inspection_collects_split_apks_manifest_signature_and_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, repository, session_id = prepared_service(
        tmp_path,
        monkeypatch,
        with_tools=True,
    )

    def fake_aapt(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        values = [str(item) for item in arguments]
        return result(BADGING if "badging" in values else XMLTREE)

    monkeypatch.setattr(manifest_module, "run_command", fake_aapt)
    monkeypatch.setattr(
        signature_module,
        "run_command",
        lambda *_args, **_kwargs: result(SIGNATURE),
    )

    inspection = service.inspect(package="com.example.lab", serial="ABC123")

    assert inspection.session_id == session_id
    assert inspection.status == "completed"
    assert inspection.metadata.label == "Lab App"
    assert len(inspection.apks) == 2
    assert inspection.manifest is not None
    assert inspection.manifest["components"][0]["name"] == "com.example.lab.MainActivity"
    assert inspection.signature is not None
    assert inspection.signature["schemes"]["v2"] is True
    assert len(inspection.evidence) == 9
    session_paths = repository.paths_for(session_id)
    raw_manifest = session_paths.raw_dir / "manifest" / "manifest-xmltree.txt"
    redacted_manifest = (
        session_paths.redacted_dir / "manifest" / "manifest-xmltree.txt"
    )
    assert "MANIFEST_API_KEY_SUPER_SECRET" in raw_manifest.read_text(encoding="utf-8")
    assert "MANIFEST_API_KEY_SUPER_SECRET" not in redacted_manifest.read_text(
        encoding="utf-8"
    )
    manifest_evidence = {
        item["evidence_type"]: item
        for item in inspection.evidence
        if item["evidence_type"] in {"manifest_tree", "manifest_tree_raw"}
    }
    assert manifest_evidence["manifest_tree_raw"]["redacted"] is False
    assert manifest_evidence["manifest_tree_raw"]["relative_path"].startswith("raw/")
    assert manifest_evidence["manifest_tree"]["redacted"] is True
    assert manifest_evidence["manifest_tree"]["relative_path"].startswith("redacted/")
    app_json = json.loads(repository.paths_for(session_id).app_json.read_text(encoding="utf-8"))
    assert app_json["inspection_status"] == "completed"
    assert all(len(apk["sha256"]) == 64 for apk in app_json["apks"])
    assert repository.load(session_id).status is SessionStatus.ACTIVE


def test_app_inspection_degrades_cleanly_when_optional_tools_are_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, repository, session_id = prepared_service(
        tmp_path,
        monkeypatch,
        with_tools=False,
    )

    inspection = service.inspect(package="com.example.lab")

    assert inspection.status == "partial"
    assert inspection.steps["package_metadata"] == "completed"
    assert inspection.steps["apk_pull"] == "completed"
    assert inspection.steps["aapt2_manifest"] == "skipped"
    assert inspection.steps["apksigner"] == "skipped"
    assert len(inspection.limitations) == 2
    assert inspection.errors == ()
    assert repository.paths_for(session_id).app_json.is_file()
