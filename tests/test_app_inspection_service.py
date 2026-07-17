# ruff: noqa: E501
from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from android_assessor import manifest as manifest_module
from android_assessor import signature as signature_module
from android_assessor.config import LabConfig
from android_assessor.errors import ApkInspectionError
from android_assessor.paths import ProjectPaths
from android_assessor.services.app_inspection_service import (
    AppInspectionService,
    _merge_manifest_payloads,
)
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
    E: meta-data
      A: android:name="com.example.lab.APP_CONFIG" (Raw: "com.example.lab.APP_CONFIG")
      A: android:value="opaque-application-secret-4c3b2a1z" (Raw: "opaque-application-secret-4c3b2a1z")
    E: activity
      A: android:name=".MainActivity" (Raw: ".MainActivity")
      A: android:exported=(type 0x12)0xffffffff
    E: provider
      A: android:name=".ShareProvider" (Raw: ".ShareProvider")
      A: android:authorities="com.example.lab.files" (Raw: "com.example.lab.files")
      A: android:exported=(type 0x12)0x0
      A: android:grantUriPermissions=(type 0x12)0xffffffff
      E: meta-data
        A: android:name="android.support.FILE_PROVIDER_PATHS" (Raw: "android.support.FILE_PROVIDER_PATHS")
        A: android:resource=(type 0x01)0x7f120001
      E: meta-data
        A: android:name="com.example.lab.RUNTIME_CONFIG" (Raw: "com.example.lab.RUNTIME_CONFIG")
        A: android:value="opaque-metadata-value-9x8y7z6w" (Raw: "opaque-metadata-value-9x8y7z6w")
"""

SPLIT_XMLTREE = """E: manifest
  A: package="com.example.lab" (Raw: "com.example.lab")
  E: application
    E: service
      A: android:name=".SyncService" (Raw: ".SyncService")
      A: android:exported=(type 0x12)0xffffffff
      E: intent-filter
        E: action
          A: android:name="com.example.lab.SYNC" (Raw: "com.example.lab.SYNC")
    E: activity
      A: android:name=".LinkActivity" (Raw: ".LinkActivity")
      A: android:exported=(type 0x12)0xffffffff
      E: intent-filter
        E: action
          A: android:name="android.intent.action.VIEW" (Raw: "android.intent.action.VIEW")
        E: category
          A: android:name="android.intent.category.BROWSABLE" (Raw: "android.intent.category.BROWSABLE")
        E: category
          A: android:name="android.intent.category.DEFAULT" (Raw: "android.intent.category.DEFAULT")
        E: data
          A: android:scheme="labapp" (Raw: "labapp")
"""

FILE_PROVIDER_PATHS = """E: paths
  E: files-path
    A: name="documents" (Raw: "documents")
    A: path="shared/documents" (Raw: "shared/documents")
"""

RESOURCE_TABLE = """Package name=com.example.lab id=0x7f
  resource 0x7f120001 com.example.lab:xml/share_paths
    () (file) res/xml/share_paths.xml type=XML
  resource 0x7f130001 com.example.lab:string/unrelated_value
    () "opaque-resource-secret-7y6x5w4v"
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


def test_split_manifest_merge_records_custom_permission_conflicts() -> None:
    limitations: list[str] = []
    base = {
        "custom_permissions": [
            {"name": "com.example.CONFLICT", "protection_level": "signature"}
        ],
        "permissions": [],
        "components": [],
        "deep_links": [],
        "file_provider_paths": [],
    }
    split = {
        **base,
        "custom_permissions": [
            {"name": "com.example.CONFLICT", "protection_level": "dangerous"}
        ],
    }

    merged = _merge_manifest_payloads(
        [("base:0", base), ("split:1", split)],
        limitations,
    )

    assert merged["manifest_complete"] is False
    assert merged["manifest_limitations"] == [
        "split:1:conflicting_custom_permission:com.example.CONFLICT"
    ]
    assert len(merged["custom_permissions"]) == 2


class FakeAdb:
    @staticmethod
    def apk_bytes(remote_path: str) -> bytes:
        output = BytesIO()
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr(
                "assets/inspection.txt",
                f"source={Path(remote_path).name}\nendpoint=https://example.test/",
            )
        return output.getvalue()

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
        if arguments[:4] == ("stat", "-c", "%s", "--"):
            return result(str(len(self.apk_bytes(arguments[4]))))
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
        destination.write_bytes(self.apk_bytes(remote_path))
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
    paths.scope_file.write_text(
        "devices: [ABC123]\n"
        "packages: [com.example.lab]\n"
        "api_hosts: [example.test]\n"
        "allowed_actions: [inspect]\n"
        "limits: {max_evidence_size_mb: 50}\n",
        encoding="utf-8",
    )
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
        if "badging" in values:
            return result(BADGING)
        if "strings" in values:
            return result("String #0 : https://resource.example.test/config\n")
        if "resources" in values:
            return result(RESOURCE_TABLE)
        if "res/xml/share_paths.xml" in values:
            return result(FILE_PROVIDER_PATHS)
        if any("split_config" in value for value in values):
            return result(SPLIT_XMLTREE)
        return result(XMLTREE)

    monkeypatch.setattr(manifest_module, "run_command", fake_aapt)
    monkeypatch.setattr(
        signature_module,
        "run_command",
        lambda *_args, **_kwargs: result(SIGNATURE),
    )

    inspection = service.inspect(package="com.example.lab", serial="ABC123")

    assert inspection.session_id == session_id
    assert inspection.status == "partial"
    assert inspection.steps["aapt2_manifest"] == "partial"
    assert any(
        "split_resource_variants_not_correlated" in item
        for item in inspection.limitations
    )
    assert inspection.metadata.label == "Lab App"
    assert len(inspection.apks) == 2
    assert inspection.manifest is not None
    assert inspection.manifest["components"][0]["name"] == "com.example.lab.MainActivity"
    assert inspection.signature is not None
    assert inspection.signature["schemes"]["v2"] is True
    assert inspection.static_analysis is not None
    assert inspection.static_analysis["status"] == "completed"
    assert inspection.static_analysis["metrics"]["resource_strings_scanned"] == 2
    assert len(inspection.evidence) == 18
    session_paths = repository.paths_for(session_id)
    raw_manifest = session_paths.raw_dir / "manifest" / "manifest-xmltree.txt"
    redacted_manifest = (
        session_paths.redacted_dir / "manifest" / "manifest-xmltree.txt"
    )
    assert "MANIFEST_API_KEY_SUPER_SECRET" in raw_manifest.read_text(encoding="utf-8")
    assert "MANIFEST_API_KEY_SUPER_SECRET" not in redacted_manifest.read_text(
        encoding="utf-8"
    )
    assert "opaque-metadata-value-9x8y7z6w" not in redacted_manifest.read_text(
        encoding="utf-8"
    )
    assert "opaque-application-secret-4c3b2a1z" not in redacted_manifest.read_text(
        encoding="utf-8"
    )
    redacted_resource_table = (
        session_paths.redacted_dir / "manifest" / "resources" / "resources.txt"
    )
    assert redacted_resource_table.read_text(encoding="utf-8") == (
        "0x7f120001 res/xml/share_paths.xml\n"
    )
    assert "opaque-resource-secret-7y6x5w4v" not in redacted_resource_table.read_text(
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
    assert app_json["inspection_status"] == "partial"
    assert app_json["static_analysis"]["sources"] == ["base:0", "split:1"]
    assert app_json["manifest"]["file_provider_paths"][0]["resolution_status"] == (
        "resolved"
    )
    assert app_json["manifest"]["manifest_complete"] is True
    assert app_json["manifest"]["manifest_limitations"] == []
    assert app_json["manifest"]["file_provider_limitations"] == [
        "split_resource_variants_not_correlated"
    ]
    service_component = next(
        item
        for item in app_json["manifest"]["components"]
        if item["component_type"] == "service"
    )
    assert service_component["name"] == "com.example.lab.SyncService"
    assert service_component["source_apk"] == "split:1"
    assert app_json["manifest"]["deep_links"][0]["source_apk"] == "split:1"
    metadata = app_json["manifest"]["components"][1]["meta_data"][1]
    assert metadata["value"] is None
    assert metadata["value_length"] == len("opaque-metadata-value-9x8y7z6w")
    assert "opaque-metadata-value-9x8y7z6w" not in json.dumps(app_json)
    assert {
        item["evidence_type"]
        for item in inspection.evidence
        if item["evidence_type"].startswith("manifest_resource_xml")
    } == {"manifest_resource_xml", "manifest_resource_xml_raw"}
    assert all(len(apk["sha256"]) == 64 for apk in app_json["apks"])
    assert repository.load(session_id).status is SessionStatus.ACTIVE


def test_base_badging_target_sdk_is_used_for_split_manifest_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _repository, _session_id = prepared_service(
        tmp_path,
        monkeypatch,
        with_tools=True,
    )
    adb = service.context.adb_client()
    original_shell = adb.shell

    def fake_shell(
        serial: str,
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> CommandResult:
        if arguments[:2] == ("dumpsys", "package"):
            return result(DUMPSYS.replace(" targetSdk=34", ""))
        return original_shell(serial, arguments, **kwargs)

    monkeypatch.setattr(adb, "shell", fake_shell)
    base_manifest = """E: manifest
  A: package=\"com.example.lab\" (Raw: \"com.example.lab\")
  E: application
"""
    split_manifest = """E: manifest
  A: package=\"com.example.lab\" (Raw: \"com.example.lab\")
  E: application
    E: provider
      A: android:name=\".LegacyProvider\" (Raw: \".LegacyProvider\")
      A: android:authorities=\"com.example.lab.legacy\" (Raw: \"com.example.lab.legacy\")
"""

    def fake_aapt(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        values = [str(item) for item in arguments]
        is_split = any("split_config" in value for value in values)
        if "badging" in values:
            badging = BADGING.replace("targetSdkVersion:'34'", "targetSdkVersion:'16'")
            if is_split:
                badging = badging.replace("targetSdkVersion:'16'\n", "")
            return result(badging)
        if "strings" in values:
            return result("")
        return result(split_manifest if is_split else base_manifest)

    monkeypatch.setattr(manifest_module, "run_command", fake_aapt)
    monkeypatch.setattr(
        signature_module,
        "run_command",
        lambda *_args, **_kwargs: result(SIGNATURE),
    )

    inspection = service.inspect(package="com.example.lab", serial="ABC123")

    provider = next(
        item
        for item in inspection.manifest["components"]  # type: ignore[index]
        if item["component_type"] == "provider"
    )
    assert provider["effective_exported"] is True
    assert provider["exported_source"] == "legacy_provider_default"


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
    assert inspection.steps["static_apk_analysis"] == "partial"
    assert inspection.static_analysis is not None
    assert "resource_strings:aapt2_unavailable" in inspection.static_analysis[
        "limitations"
    ]
    assert inspection.steps["apksigner"] == "skipped"
    assert len(inspection.limitations) == 3
    assert inspection.errors == ()
    assert repository.paths_for(session_id).app_json.is_file()


def test_resource_string_failure_makes_secret_coverage_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _repository, _session_id = prepared_service(
        tmp_path,
        monkeypatch,
        with_tools=True,
    )

    def fake_aapt(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        values = [str(item) for item in arguments]
        return result(BADGING if "badging" in values else XMLTREE)

    def unavailable_strings(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        raise ApkInspectionError("resource string fixture unavailable")

    monkeypatch.setattr(manifest_module, "run_command", fake_aapt)
    monkeypatch.setattr(
        manifest_module.Aapt2Inspector,
        "dump_strings",
        unavailable_strings,
    )
    monkeypatch.setattr(
        signature_module,
        "run_command",
        lambda *_args, **_kwargs: result(SIGNATURE),
    )

    inspection = service.inspect(package="com.example.lab", serial="ABC123")

    assert inspection.status == "partial"
    assert inspection.steps["static_apk_analysis"] == "partial"
    assert inspection.static_analysis is not None
    assert inspection.static_analysis["secret_candidates"] == []
    assert sorted(inspection.static_analysis["limitations"]) == [
        "base:0:resource_strings_unavailable",
        "split:1:resource_strings_unavailable",
    ]
