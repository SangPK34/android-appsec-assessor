from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor.apk import (
    ApkPuller,
    PackageMetadata,
    merge_badging,
    parse_aapt_badging,
    parse_package_metadata,
    parse_pm_paths,
)
from android_assessor.errors import ApkInspectionError
from android_assessor.paths import ProjectPaths

PM_PATHS = """package:/data/app/~~abc/com.example.app-xyz==/base.apk
package:/data/app/~~abc/com.example.app-xyz==/split_config.arm64_v8a.apk
"""

DUMPSYS = """Package [com.example.app] (abc):
  userId=10123
  versionCode=420 minSdk=23 targetSdk=34
  versionName=4.2.0
  installerPackageName=com.android.vending
  firstInstallTime=2026-07-16 10:00:00
  lastUpdateTime=2026-07-17 10:00:00
  dataDir=/data/user/0/com.example.app
  pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
"""

BADGING = """package: name='com.example.app' versionCode='420' versionName='4.2.0' \
compileSdkVersion='35'
sdkVersion:'23'
targetSdkVersion:'34'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.CAMERA'
application-label:'Lab App'
application-label-vi:'Ứng dụng Lab'
"""


def test_parses_split_paths_and_dumpsys_metadata() -> None:
    paths = parse_pm_paths(PM_PATHS)
    metadata = parse_package_metadata("com.example.app", DUMPSYS, paths)

    assert len(metadata.apk_paths) == 2
    assert metadata.uid == 10123
    assert metadata.version_code == 420
    assert metadata.version_name == "4.2.0"
    assert metadata.min_sdk == 23
    assert metadata.target_sdk == 34
    assert metadata.flags == ("HAS_CODE", "ALLOW_CLEAR_USER_DATA")
    assert metadata.to_dict()["split_apk"] is True


def test_pm_path_parser_rejects_missing_or_unsafe_output() -> None:
    with pytest.raises(ApkInspectionError, match="did not return"):
        parse_pm_paths("Error: package not found")
    with pytest.raises(ApkInspectionError, match="invalid Android APK path"):
        parse_pm_paths("package:/data/app/base.apk;whoami")


def test_badging_parser_and_metadata_merge() -> None:
    badging = parse_aapt_badging(BADGING)
    metadata = PackageMetadata(package="com.example.app", apk_paths=("/data/app/base.apk",))

    merged = merge_badging(metadata, badging)

    assert badging.permissions == (
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    )
    assert merged.label == "Lab App"
    assert merged.compile_sdk == 35
    assert merged.version_code == 420


def test_badging_merge_rejects_package_mismatch() -> None:
    metadata = PackageMetadata(package="com.example.app", apk_paths=("/data/app/base.apk",))
    badging = parse_aapt_badging(BADGING.replace("com.example.app", "com.attacker.app"))

    with pytest.raises(ApkInspectionError, match="package mismatch"):
        merge_badging(metadata, badging)


class FakePullAdb:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Path]] = []

    def pull_file(
        self,
        serial: str,
        remote_path: str,
        destination: Path,
        *,
        timeout: float = 180,
    ) -> object:
        del timeout
        self.calls.append((serial, remote_path, destination))
        destination.write_bytes(("APK:" + remote_path).encode())
        return object()


def test_apk_puller_handles_split_files_spaces_and_atomic_parts(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "Android Lab có dấu")
    paths.ensure_layout()
    session_root = paths.results_dir / "20260717-120102-a8f4c2"
    destination = session_root / "apk"
    session_root.mkdir(parents=True)
    adb = FakePullAdb()
    puller = ApkPuller(paths, adb)  # type: ignore[arg-type]

    artifacts = puller.pull(
        "ABC123",
        parse_pm_paths(PM_PATHS),
        session_root=session_root,
        destination_dir=destination,
    )

    assert [artifact.role for artifact in artifacts] == ["base", "split"]
    assert artifacts[0].relative_path == "apk/000-base.apk"
    assert artifacts[1].relative_path.endswith("split_config.arm64_v8a.apk")
    assert all(len(artifact.sha256) == 64 for artifact in artifacts)
    assert not list(destination.glob("*.part"))
    assert all(call[0] == "ABC123" for call in adb.calls)
