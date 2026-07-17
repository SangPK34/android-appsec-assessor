"""Package metadata parsing and atomic base/split APK collection."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from .adb import AdbClient
from .errors import ApkInspectionError, SessionError
from .evidence import sha256_file
from .paths import ProjectPaths
from .storage import require_under_root
from .validation import validate_android_apk_path, validate_package_name


@dataclass(frozen=True, slots=True)
class PackageMetadata:
    package: str
    apk_paths: tuple[str, ...]
    version_name: str | None = None
    version_code: int | None = None
    uid: int | None = None
    target_sdk: int | None = None
    min_sdk: int | None = None
    compile_sdk: int | None = None
    label: str | None = None
    installer_package: str | None = None
    first_install_time: str | None = None
    last_update_time: str | None = None
    data_dir: str | None = None
    flags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["apk_paths"] = list(self.apk_paths)
        value["flags"] = list(self.flags)
        value["split_apk"] = len(self.apk_paths) > 1
        return value


@dataclass(frozen=True, slots=True)
class BadgingInfo:
    package: str | None
    version_name: str | None
    version_code: int | None
    min_sdk: int | None
    target_sdk: int | None
    compile_sdk: int | None
    label: str | None
    permissions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["permissions"] = list(self.permissions)
        return value


@dataclass(frozen=True, slots=True)
class ApkArtifact:
    role: str
    split_name: str
    remote_path: str
    relative_path: str
    size_bytes: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PackageInspectionData:
    metadata: PackageMetadata
    pm_paths_output: str
    dumpsys_output: str


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return None if normalized in {"", "null", "None"} else normalized


def _optional_int(value: str | None) -> int | None:
    if value is None or not value.isdigit():
        return None
    return int(value)


def _line_value(output: str, key: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(key)}=(.*?)\s*$", output)
    return _optional_text(match.group(1) if match else None)


def parse_pm_paths(output: str) -> tuple[str, ...]:
    paths: list[str] = []
    for raw_line in output.replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line.startswith("package:"):
            continue
        try:
            path = validate_android_apk_path(line.removeprefix("package:"))
        except SessionError as exc:
            raise ApkInspectionError(str(exc)) from exc
        if path not in paths:
            paths.append(path)
    if not paths:
        raise ApkInspectionError("Package Manager did not return an APK path.")
    return tuple(paths)


def parse_package_metadata(
    package: str,
    dumpsys_output: str,
    apk_paths: tuple[str, ...],
) -> PackageMetadata:
    target = validate_package_name(package)
    version_match = re.search(r"\bversionCode=(\d+)", dumpsys_output)
    min_match = re.search(r"\bminSdk=(\d+)", dumpsys_output)
    target_match = re.search(r"\btargetSdk=(\d+)", dumpsys_output)
    uid_match = re.search(r"(?m)^\s*(?:userId|appId)=(\d+)\s*$", dumpsys_output)
    flags_match = re.search(r"(?m)^\s*(?:pkgFlags|flags)=\[([^]]*)]", dumpsys_output)
    flags = tuple(flags_match.group(1).split()) if flags_match else ()
    return PackageMetadata(
        package=target,
        apk_paths=apk_paths,
        version_name=_line_value(dumpsys_output, "versionName"),
        version_code=_optional_int(version_match.group(1) if version_match else None),
        uid=_optional_int(uid_match.group(1) if uid_match else None),
        target_sdk=_optional_int(target_match.group(1) if target_match else None),
        min_sdk=_optional_int(min_match.group(1) if min_match else None),
        installer_package=_line_value(dumpsys_output, "installerPackageName"),
        first_install_time=_line_value(dumpsys_output, "firstInstallTime"),
        last_update_time=_line_value(dumpsys_output, "lastUpdateTime"),
        data_dir=_line_value(dumpsys_output, "dataDir"),
        flags=flags,
    )


def _single_quoted_value(line: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}='([^']*)'", line)
    return match.group(1) if match else None


def _colon_quoted_value(line: str) -> str | None:
    match = re.search(r":'([^']*)'", line)
    return match.group(1) if match else None


def parse_aapt_badging(output: str) -> BadgingInfo:
    package: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    compile_sdk: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    label: str | None = None
    permissions: list[str] = []
    for raw_line in output.replace("\r", "").splitlines():
        line = raw_line.strip()
        if line.startswith("package:"):
            package = _single_quoted_value(line, "name")
            version_name = _single_quoted_value(line, "versionName")
            version_code = _optional_int(_single_quoted_value(line, "versionCode"))
            compile_sdk = _optional_int(_single_quoted_value(line, "compileSdkVersion"))
        elif line.startswith("sdkVersion:"):
            min_sdk = _optional_int(_colon_quoted_value(line))
        elif line.startswith("targetSdkVersion:"):
            target_sdk = _optional_int(_colon_quoted_value(line))
        elif line.startswith("application-label:"):
            label = _colon_quoted_value(line)
        elif line.startswith("uses-permission:"):
            permission = _single_quoted_value(line, "name")
            if permission and permission not in permissions:
                permissions.append(permission)
    return BadgingInfo(
        package=package,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        compile_sdk=compile_sdk,
        label=label,
        permissions=tuple(permissions),
    )


def merge_badging(metadata: PackageMetadata, badging: BadgingInfo) -> PackageMetadata:
    if badging.package and badging.package != metadata.package:
        raise ApkInspectionError(
            f"APK package mismatch: expected {metadata.package}, got {badging.package}."
        )
    return replace(
        metadata,
        version_name=metadata.version_name or badging.version_name,
        version_code=metadata.version_code or badging.version_code,
        target_sdk=metadata.target_sdk or badging.target_sdk,
        min_sdk=metadata.min_sdk or badging.min_sdk,
        compile_sdk=badging.compile_sdk,
        label=badging.label,
    )


class PackageInspector:
    def __init__(self, adb: AdbClient) -> None:
        self.adb = adb

    def collect(self, serial: str, package: str) -> PackageInspectionData:
        target = validate_package_name(package)
        paths_result = self.adb.shell(
            serial,
            ("pm", "path", target),
            timeout=30,
            check=True,
            operation="reading installed APK paths",
        )
        apk_paths = parse_pm_paths(paths_result.stdout)
        dumpsys_result = self.adb.shell(
            serial,
            ("dumpsys", "package", target),
            timeout=45,
            check=True,
            operation="reading package metadata",
        )
        return PackageInspectionData(
            metadata=parse_package_metadata(target, dumpsys_result.stdout, apk_paths),
            pm_paths_output=paths_result.stdout,
            dumpsys_output=dumpsys_result.stdout,
        )

    def inspect(self, serial: str, package: str) -> PackageMetadata:
        return self.collect(serial, package).metadata


class ApkPuller:
    def __init__(self, paths: ProjectPaths, adb: AdbClient) -> None:
        self.paths = paths
        self.adb = adb

    def pull(
        self,
        serial: str,
        remote_paths: tuple[str, ...],
        *,
        session_root: Path,
        destination_dir: Path,
    ) -> tuple[ApkArtifact, ...]:
        root = require_under_root(session_root, self.paths.root)
        destination = require_under_root(destination_dir, root)
        destination.mkdir(parents=True, exist_ok=True)
        artifacts: list[ApkArtifact] = []
        for index, raw_remote in enumerate(remote_paths):
            remote = validate_android_apk_path(raw_remote)
            remote_name = PurePosixPath(remote).name
            role = "base" if remote_name.casefold() == "base.apk" else "split"
            split_name = "base" if role == "base" else PurePosixPath(remote_name).stem
            final = destination / f"{index:03d}-{remote_name}"
            partial = destination / f".{final.name}.{uuid4().hex}.part"
            try:
                self.adb.pull_file(serial, remote, partial)
                if not partial.is_file() or partial.stat().st_size <= 0:
                    raise ApkInspectionError(f"ADB did not produce APK file {remote_name}.")
                partial.replace(final)
            except OSError as exc:
                raise ApkInspectionError(
                    f"Could not store pulled APK {remote_name}: {exc}"
                ) from exc
            finally:
                partial.unlink(missing_ok=True)
            artifacts.append(
                ApkArtifact(
                    role=role,
                    split_name=split_name,
                    remote_path=remote,
                    relative_path=final.relative_to(root).as_posix(),
                    size_bytes=final.stat().st_size,
                    sha256=sha256_file(final),
                )
            )
        return tuple(artifacts)
