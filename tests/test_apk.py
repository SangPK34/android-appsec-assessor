from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from android_assessor.apk import (
    ApkPuller,
    PackageMetadata,
    merge_badging,
    parse_aapt_badging,
    parse_package_metadata,
    parse_pm_paths,
)
from android_assessor.errors import AdbError, ApkInspectionError
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
    def __init__(
        self,
        *,
        remote_sizes: dict[str, int] | None = None,
        pulled_sizes: dict[str, int] | None = None,
        stat_outputs: dict[str, str] | None = None,
        stat_error: AdbError | None = None,
        pull_error: AdbError | None = None,
    ) -> None:
        self.calls: list[tuple[str, str, Path]] = []
        self.stat_calls: list[tuple[str, tuple[str, ...], float, bool, str]] = []
        self.pull_timeouts: list[float] = []
        self.remote_sizes = remote_sizes or {}
        self.pulled_sizes = pulled_sizes or {}
        self.stat_outputs = stat_outputs or {}
        self.stat_error = stat_error
        self.pull_error = pull_error

    @staticmethod
    def _default_size(remote_path: str) -> int:
        return len(("APK:" + remote_path).encode())

    def shell(
        self,
        serial: str,
        arguments: tuple[str, ...],
        *,
        timeout: float,
        check: bool,
        operation: str,
    ) -> object:
        self.stat_calls.append((serial, arguments, timeout, check, operation))
        if self.stat_error is not None:
            raise self.stat_error
        remote_path = arguments[-1]
        output = self.stat_outputs.get(
            remote_path,
            str(self.remote_sizes.get(remote_path, self._default_size(remote_path))),
        )
        return SimpleNamespace(stdout=output)

    def pull_file(
        self,
        serial: str,
        remote_path: str,
        destination: Path,
        *,
        timeout: float = 180,
    ) -> object:
        self.pull_timeouts.append(timeout)
        self.calls.append((serial, remote_path, destination))
        if self.pull_error is not None:
            raise self.pull_error
        size = self.pulled_sizes.get(
            remote_path,
            self.remote_sizes.get(remote_path, self._default_size(remote_path)),
        )
        destination.write_bytes(b"A" * size)
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
    assert [call[1] for call in adb.stat_calls] == [
        ("stat", "-c", "%s", "--", "/data/app/~~abc/com.example.app-xyz==/base.apk"),
        (
            "stat",
            "-c",
            "%s",
            "--",
            "/data/app/~~abc/com.example.app-xyz==/split_config.arm64_v8a.apk",
        ),
    ]


def _puller_paths(tmp_path: Path) -> tuple[ProjectPaths, Path, Path]:
    paths = ProjectPaths(tmp_path / "project")
    paths.ensure_layout()
    session_root = paths.results_dir / "20260717-120102-a8f4c2"
    session_root.mkdir(parents=True)
    return paths, session_root, session_root / "apk"


def test_apk_puller_rejects_file_count_before_stat_or_pull(tmp_path: Path) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    adb = FakePullAdb()

    with pytest.raises(ApkInspectionError, match=r"\[file_count_limit]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            parse_pm_paths(PM_PATHS),
            session_root=session_root,
            destination_dir=destination,
            max_files=1,
        )

    assert adb.stat_calls == []
    assert adb.calls == []


@pytest.mark.parametrize(
    ("stat_output", "error_code"),
    [
        ("", "invalid_remote_size"),
        ("0", "invalid_remote_size"),
        ("-1", "invalid_remote_size"),
        ("12 bytes", "invalid_remote_size"),
        ("12\n13", "invalid_remote_size"),
        ("9" * 21, "invalid_remote_size"),
    ],
)
def test_apk_puller_rejects_invalid_remote_size_without_pull(
    tmp_path: Path,
    stat_output: str,
    error_code: str,
) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    remote = "/data/app/example/base.apk"
    adb = FakePullAdb(stat_outputs={remote: stat_output})

    with pytest.raises(ApkInspectionError, match=rf"\[{error_code}]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            (remote,),
            session_root=session_root,
            destination_dir=destination,
        )

    assert adb.calls == []


def test_apk_puller_wraps_stat_failure_without_pull(tmp_path: Path) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    adb = FakePullAdb(stat_error=AdbError("ADB timed out while reading remote APK size."))

    with pytest.raises(ApkInspectionError, match=r"\[remote_stat_failed]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            ("/data/app/example/base.apk",),
            session_root=session_root,
            destination_dir=destination,
            stat_timeout=3,
        )

    assert adb.stat_calls[0][2] == 3
    assert adb.calls == []


def test_apk_puller_preflights_all_files_before_per_file_limit_failure(
    tmp_path: Path,
) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    first = "/data/app/example/base.apk"
    second = "/data/app/example/split_config.en.apk"
    adb = FakePullAdb(remote_sizes={first: 10, second: 101})

    with pytest.raises(ApkInspectionError, match=r"\[file_size_limit]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            (first, second),
            session_root=session_root,
            destination_dir=destination,
            max_file_bytes=100,
        )

    assert len(adb.stat_calls) == 2
    assert adb.calls == []


def test_apk_puller_rejects_aggregate_size_before_pull(tmp_path: Path) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    first = "/data/app/example/base.apk"
    second = "/data/app/example/split_config.en.apk"
    adb = FakePullAdb(remote_sizes={first: 60, second: 50})

    with pytest.raises(ApkInspectionError, match=r"\[total_size_limit]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            (first, second),
            session_root=session_root,
            destination_dir=destination,
            max_file_bytes=100,
            max_total_bytes=100,
        )

    assert len(adb.stat_calls) == 2
    assert adb.calls == []


def test_apk_puller_rejects_unsafe_path_before_adb_dispatch(tmp_path: Path) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    adb = FakePullAdb()

    with pytest.raises(ApkInspectionError, match=r"\[invalid_remote_path]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            ("/data/app/base.apk;whoami",),
            session_root=session_root,
            destination_dir=destination,
        )

    assert adb.stat_calls == []
    assert adb.calls == []


def test_apk_puller_verifies_pulled_size_and_removes_partial(tmp_path: Path) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    remote = "/data/app/example/base.apk"
    adb = FakePullAdb(remote_sizes={remote: 20}, pulled_sizes={remote: 19})

    with pytest.raises(ApkInspectionError, match=r"\[pull_size_mismatch]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            (remote,),
            session_root=session_root,
            destination_dir=destination,
            pull_timeout=7,
        )

    assert adb.pull_timeouts == [7]
    assert not list(destination.glob("*.part"))
    assert not (destination / "000-base.apk").exists()


def test_apk_puller_wraps_adb_pull_failure(tmp_path: Path) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    adb = FakePullAdb(pull_error=AdbError("device went offline"))

    with pytest.raises(ApkInspectionError, match=r"\[pull_failed]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            ("/data/app/example/base.apk",),
            session_root=session_root,
            destination_dir=destination,
        )

    assert len(adb.stat_calls) == 1
    assert len(adb.calls) == 1
    assert not list(destination.glob("*.part"))


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("max_files", 0),
        ("max_file_bytes", -1),
        ("max_total_bytes", True),
        ("stat_timeout", 0),
        ("stat_timeout", float("nan")),
        ("pull_timeout", -1),
    ],
)
def test_apk_puller_rejects_invalid_limits_before_adb(
    tmp_path: Path,
    option: str,
    value: object,
) -> None:
    paths, session_root, destination = _puller_paths(tmp_path)
    adb = FakePullAdb()
    options = {option: value}

    with pytest.raises(ApkInspectionError, match=r"\[invalid_limit]"):
        ApkPuller(paths, adb).pull(  # type: ignore[arg-type]
            "ABC123",
            ("/data/app/example/base.apk",),
            session_root=session_root,
            destination_dir=destination,
            **options,  # type: ignore[arg-type]
        )

    assert adb.stat_calls == []
    assert adb.calls == []
