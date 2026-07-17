"""Bounded root-assisted private-storage inventory and offline analysis."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from .adb import AdbClient
from .backends import PrivateStorageBackend
from .device_lock import DeviceLock
from .errors import SessionError
from .evidence import EvidenceRepository
from .redaction import redact_text
from .root import (
    RootMode,
    RootProbe,
    app_data_root,
    probe_root,
    root_shell,
    validate_root_remote_path,
)
from .scope import load_scope
from .session import SessionRepository, SessionStatus
from .storage import write_json_atomic
from .validation import validate_package_name

_SENSITIVE_NAME = re.compile(
    r"(?i)(token|secret|credential|password|passwd|session|cookie|auth|key)"
)
_CANARY = re.compile(r"THESIS_CANARY_[A-Z0-9_]+")
_INTERNAL_DATA_DIRECTORY = re.compile(r"^/data/user/([0-9]{1,3})/([A-Za-z0-9._]+)$")
_LEGACY_DATA_DIRECTORY = re.compile(r"^/data/data/([A-Za-z0-9._]+)$")
_EXTERNAL_DATA_DIRECTORY = re.compile(
    r"^/(?:storage/emulated/[0-9]{1,3}|sdcard)/Android/data/([A-Za-z0-9._]+)$"
)


class StorageArtifactType(StrEnum):
    SHARED_PREFERENCES = "shared_preferences"
    SQLITE = "sqlite"
    INTERNAL_FILE = "internal_file"
    CACHE = "cache"
    NO_BACKUP = "no_backup"
    WEBVIEW = "webview"
    EXTERNAL = "external"
    DIRECTORY = "directory"
    OTHER = "other"


class StorageAnalysisStatus(StrEnum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    POST_COMPROMISE_OBSERVATION = "post_compromise_observation"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class StorageInspectionPolicy:
    max_file_size_bytes: int = 5 * 1024 * 1024
    max_evidence_count: int = 50
    allowed_extensions: frozenset[str] = frozenset(
        {".xml", ".json", ".txt", ".db", ".sqlite", ".sqlite3", ".bin"}
    )

    def __post_init__(self) -> None:
        if not 1 <= self.max_file_size_bytes <= 50 * 1024 * 1024:
            raise ValueError("Storage max file size must be between 1 byte and 50 MiB.")
        if not 1 <= self.max_evidence_count <= 1000:
            raise ValueError("Storage evidence count must be between 1 and 1000.")
        if any(not value.startswith(".") for value in self.allowed_extensions):
            raise ValueError("Storage extension allowlist entries must start with '.'.")


@dataclass(frozen=True, slots=True)
class StorageArtifact:
    relative_path: str
    type: StorageArtifactType
    size: int
    owner: str
    permissions: str
    sha256: str
    hash_scope: str
    sensitive: bool
    encrypted_or_unknown: str
    collection_method: str
    root_used: bool
    canonical_path: str
    content_collected: bool
    content_preview_redacted: str | None
    source: str
    environment: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["type"] = self.type.value
        return payload


@dataclass(frozen=True, slots=True)
class StorageObservation:
    observation_id: str
    title: str
    status: StorageAnalysisStatus
    validation_type: str
    artifact_paths: tuple[str, ...]
    rationale: str
    finding_eligible: bool
    physical_validation_status: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


@dataclass(frozen=True, slots=True)
class StorageInspectionResult:
    package: str
    data_directory: str
    artifacts: tuple[StorageArtifact, ...]
    observations: tuple[StorageObservation, ...]
    skipped: tuple[dict[str, str], ...]
    source: str
    environment: str
    root_mode: str = RootMode.NON_ROOT.value
    implementation_status: str = "IMPLEMENTED_UNVERIFIED"
    physical_validation_status: str = "UNVERIFIED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "data_directory": self.data_directory,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "observations": [item.to_dict() for item in self.observations],
            "skipped": list(self.skipped),
            "source": self.source,
            "environment": self.environment,
            "root_mode": self.root_mode,
            "implementation_status": self.implementation_status,
            "physical_validation_status": self.physical_validation_status,
        }


def _metadata_hash(payload: Mapping[str, Any]) -> str:
    normalized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _artifact_type(relative_path: str, raw_type: str) -> StorageArtifactType:
    if raw_type == "shared_preferences" or relative_path.startswith("shared_prefs/"):
        return StorageArtifactType.SHARED_PREFERENCES
    if raw_type == "sqlite" or relative_path.startswith("databases/"):
        return StorageArtifactType.SQLITE
    if raw_type == "cache" or relative_path.startswith(("cache/", "code_cache/")):
        return StorageArtifactType.CACHE
    if raw_type == "no_backup" or relative_path.startswith("no_backup/"):
        return StorageArtifactType.NO_BACKUP
    if raw_type == "webview" or relative_path.startswith("app_webview/"):
        return StorageArtifactType.WEBVIEW
    if raw_type == "external" or relative_path.startswith("external/"):
        return StorageArtifactType.EXTERNAL
    if raw_type == "directory":
        return StorageArtifactType.DIRECTORY
    if raw_type in {"file", "regular"} or relative_path.startswith("files/"):
        return StorageArtifactType.INTERNAL_FILE
    return StorageArtifactType.OTHER


def _permission_is_unusual(artifact: StorageArtifact) -> bool:
    if artifact.type is StorageArtifactType.EXTERNAL:
        return False
    try:
        mode = int(artifact.permissions[-3:], 8)
    except ValueError:
        return False
    return bool(mode & 0o077)


class PrivateStorageInspector:
    def __init__(self, policy: StorageInspectionPolicy | None = None) -> None:
        self.policy = policy or StorageInspectionPolicy()

    def inspect(
        self,
        *,
        package: str,
        data_directory: str,
        entries: Iterable[Mapping[str, Any]],
        content_requests: Sequence[str] = (),
        external_data_directory: str | None = None,
        source: str,
        environment: str,
        root_mode: str = RootMode.NON_ROOT.value,
    ) -> StorageInspectionResult:
        target = validate_package_name(package)
        if (source == "fixture") != (environment == "simulated"):
            raise ValueError("Fixture storage evidence must use simulated provenance.")
        internal_match = _INTERNAL_DATA_DIRECTORY.fullmatch(data_directory)
        legacy_match = _LEGACY_DATA_DIRECTORY.fullmatch(data_directory)
        matched_package = (
            internal_match.group(2)
            if internal_match
            else legacy_match.group(1)
            if legacy_match
            else None
        )
        if matched_package != target:
            raise ValueError("App data directory does not match the target package.")
        internal_root = validate_root_remote_path(
            data_directory,
            allowed_roots=(data_directory,),
        )
        allowed_roots = [internal_root]
        if external_data_directory is not None:
            external_match = _EXTERNAL_DATA_DIRECTORY.fullmatch(external_data_directory)
            if external_match is None or external_match.group(1) != target:
                raise ValueError("External app data directory does not match the package.")
            external_root = validate_root_remote_path(
                external_data_directory,
                allowed_roots=(external_data_directory,),
            )
            allowed_roots.append(external_root)
        requested = frozenset(content_requests)
        raw_entries = list(entries)
        artifacts: list[StorageArtifact] = []
        skipped: list[dict[str, str]] = []
        for raw in raw_entries:
            if len(artifacts) >= self.policy.max_evidence_count:
                skipped.append({"path": "<remaining>", "reason": "evidence_count_limit"})
                break
            relative = str(raw.get("path", ""))
            relative_path = PurePosixPath(relative)
            if (
                not relative
                or relative_path.is_absolute()
                or ".." in relative_path.parts
                or "." in relative_path.parts
            ):
                skipped.append({"path": redact_text(relative), "reason": "invalid_relative_path"})
                continue
            if raw.get("type") == "symlink" or raw.get("symlink_target"):
                skipped.append({"path": relative, "reason": "symlink_not_followed"})
                continue
            raw_type = str(raw.get("type", "other"))
            artifact_type = _artifact_type(relative, raw_type)
            default_root = (
                external_data_directory
                if artifact_type is StorageArtifactType.EXTERNAL
                and external_data_directory is not None
                else internal_root
            )
            canonical = str(
                raw.get("canonical_path")
                or (PurePosixPath(str(default_root)) / relative_path).as_posix()
            )
            try:
                canonical = validate_root_remote_path(
                    canonical,
                    allowed_roots=tuple(allowed_roots),
                )
            except ValueError:
                skipped.append({"path": relative, "reason": "canonical_path_outside_scope"})
                continue
            try:
                size = int(raw.get("size", -1))
                uid = int(raw.get("uid", -1))
                gid = int(raw.get("gid", -1))
            except (TypeError, ValueError):
                skipped.append({"path": relative, "reason": "invalid_metadata"})
                continue
            permissions = str(raw.get("mode", ""))
            if size < 0 or uid < 0 or gid < 0 or not re.fullmatch(r"0?[0-7]{3,4}", permissions):
                skipped.append({"path": relative, "reason": "invalid_metadata"})
                continue
            suffix = PurePosixPath(relative).suffix.casefold()
            collect_content = (
                relative in requested
                and size <= self.policy.max_file_size_bytes
                and suffix in self.policy.allowed_extensions
                and isinstance(raw.get("content_fixture"), str)
            )
            content = str(raw["content_fixture"]) if collect_content else None
            metadata = {
                "relative_path": relative,
                "canonical_path": canonical,
                "type": artifact_type.value,
                "size": size,
                "uid": uid,
                "gid": gid,
                "permissions": permissions,
            }
            digest = (
                hashlib.sha256(content.encode("utf-8")).hexdigest()
                if content is not None
                else _metadata_hash(metadata)
            )
            sensitive = bool(_SENSITIVE_NAME.search(relative)) or bool(
                content and (_CANARY.search(content) or _SENSITIVE_NAME.search(content))
            )
            encryption = (
                "plaintext"
                if content and _CANARY.search(content)
                else "encrypted"
                if suffix in {".enc", ".cipher"}
                else "unknown"
            )
            preview: str | None = None
            if content is not None:
                preview = redact_text(content)
                preview = _CANARY.sub("<canary-redacted>", preview)
                if _SENSITIVE_NAME.search(relative):
                    preview = "<redacted>"
            artifacts.append(
                StorageArtifact(
                    relative_path=relative,
                    type=artifact_type,
                    size=size,
                    owner=f"{uid}:{gid}",
                    permissions=permissions,
                    sha256=digest,
                    hash_scope="content" if content is not None else "metadata",
                    sensitive=sensitive,
                    encrypted_or_unknown=encryption,
                    collection_method=(
                        "root_bounded_content" if content is not None else "root_metadata"
                    ),
                    root_used=True,
                    canonical_path=canonical,
                    content_collected=content is not None,
                    content_preview_redacted=preview[:200] if preview is not None else None,
                    source=source,
                    environment=environment,
                )
            )
        observations = self._analyze(artifacts, raw_entries)
        return StorageInspectionResult(
            package=target,
            data_directory=internal_root,
            artifacts=tuple(artifacts),
            observations=tuple(observations),
            skipped=tuple(skipped),
            source=source,
            environment=environment,
            root_mode=RootMode(root_mode).value,
        )
    @staticmethod
    def _analyze(
        artifacts: Sequence[StorageArtifact],
        raw_entries: Iterable[Mapping[str, Any]],
    ) -> list[StorageObservation]:
        entries = {str(item.get("path")): item for item in raw_entries}
        output: list[StorageObservation] = []
        plaintext = [
            item
            for item in artifacts
            if item.content_collected and item.encrypted_or_unknown == "plaintext"
        ]
        for artifact in plaintext:
            raw = entries.get(artifact.relative_path, {})
            if artifact.type is StorageArtifactType.SHARED_PREFERENCES:
                title = "Sensitive canary in SharedPreferences"
            elif artifact.type is StorageArtifactType.SQLITE:
                title = "Sensitive canary in SQLite"
            elif raw.get("after_logout") is True:
                title = "Sensitive canary remains after logout"
            else:
                title = "Sensitive canary stored in plaintext"
            output.append(
                StorageObservation(
                    observation_id=f"storage-plaintext-{len(output) + 1}",
                    title=title,
                    status=StorageAnalysisStatus.CONFIRMED,
                    validation_type="root_assisted_validation",
                    artifact_paths=(artifact.relative_path,),
                    rationale="A requested synthetic canary was present in bounded content.",
                    finding_eligible=artifact.source != "fixture",
                    physical_validation_status="UNVERIFIED",
                )
            )
        unusual = [item.relative_path for item in artifacts if _permission_is_unusual(item)]
        if unusual:
            output.append(
                StorageObservation(
                    observation_id="storage-permissions",
                    title="Unusual private-storage permissions",
                    status=StorageAnalysisStatus.POTENTIAL,
                    validation_type="root_assisted_validation",
                    artifact_paths=tuple(unusual),
                    rationale="Group or other permission bits are set on internal app data.",
                    finding_eligible=False,
                    physical_validation_status="UNVERIFIED",
                )
            )
        key_paths = [
            item
            for item in artifacts
            if re.search(r"(?i)(^|/)(key|keys)[^/]*$", item.relative_path)
        ]
        cipher_paths = [
            item
            for item in artifacts
            if re.search(r"(?i)(cipher|encrypt|\.enc$)", item.relative_path)
        ]
        adjacent: list[str] = []
        for key in key_paths:
            key_parent = PurePosixPath(key.relative_path).parent
            for cipher in cipher_paths:
                if PurePosixPath(cipher.relative_path).parent == key_parent:
                    adjacent.extend((key.relative_path, cipher.relative_path))
        if adjacent:
            output.append(
                StorageObservation(
                    observation_id="storage-key-adjacent",
                    title="Potential key material stored beside ciphertext",
                    status=StorageAnalysisStatus.POTENTIAL,
                    validation_type="root_assisted_validation",
                    artifact_paths=tuple(dict.fromkeys(adjacent)),
                    rationale=(
                        "Filenames and location suggest co-located key and ciphertext; "
                        "content semantics require validation."
                    ),
                    finding_eligible=False,
                    physical_validation_status="UNVERIFIED",
                )
            )
        if not output:
            output.append(
                StorageObservation(
                    observation_id="storage-root-readable",
                    title="Private app storage observable with root",
                    status=StorageAnalysisStatus.POST_COMPROMISE_OBSERVATION,
                    validation_type="post_compromise_observation",
                    artifact_paths=tuple(item.relative_path for item in artifacts),
                    rationale=(
                        "Root-assisted readability alone does not establish an "
                        "application vulnerability."
                    ),
                    finding_eligible=False,
                    physical_validation_status="UNVERIFIED",
                )
            )
        elif not plaintext:
            output.append(
                StorageObservation(
                    observation_id="storage-content-unverified",
                    title="Private-storage content not validated",
                    status=StorageAnalysisStatus.INCONCLUSIVE,
                    validation_type="post_compromise_observation",
                    artifact_paths=tuple(item.relative_path for item in artifacts),
                    rationale=(
                        "Metadata is available but no requested canary content was "
                        "collected."
                    ),
                    finding_eligible=False,
                    physical_validation_status="UNVERIFIED",
                )
            )
        return output


class AdbPrivateStorageBackend:
    """Production ADB backend for bounded, metadata-first app-data inventory."""

    evidence_source = "adb_root"
    environment_type = "physical"

    def __init__(
        self,
        adb: AdbClient,
        *,
        max_entries: int = 50,
        max_depth: int = 4,
        timeout: float = 30,
    ) -> None:
        if not 1 <= max_entries <= 1000:
            raise ValueError("Storage entry limit must be between 1 and 1000.")
        if not 1 <= max_depth <= 8:
            raise ValueError("Storage traversal depth must be between 1 and 8.")
        if timeout <= 0 or timeout > 300:
            raise ValueError("Storage command timeout must be between 0 and 300 seconds.")
        self.adb = adb
        self.max_entries = max_entries
        self.max_depth = max_depth
        self.timeout = timeout

    def _root_probe(self, serial: str) -> RootProbe:
        probe = probe_root(self.adb, serial)
        if not probe.available:
            raise SessionError(
                "Private storage inspection skipped because Android root is unavailable: "
                f"{probe.error or probe.probe_status}"
            )
        return probe

    def inspect_package(self, serial: str, package: str) -> dict[str, object]:
        target = validate_package_name(package)
        installed = self.adb.shell(
            serial,
            ("pm", "path", target),
            timeout=15,
            check=False,
            operation="checking the private-storage target package",
        )
        if installed.exit_code != 0 or not installed.stdout.strip():
            raise SessionError("Private storage inspection skipped: package is not installed.")
        probe = self._root_probe(serial)
        candidates = (app_data_root(target), f"/data/data/{target}")
        selected: str | None = None
        for candidate in candidates:
            result = root_shell(
                self.adb,
                serial,
                f"stat -c '%F' {shlex.quote(candidate)}",
                timeout=self.timeout,
                check=False,
                operation="resolving the private application data directory",
                probe=probe,
            )
            if result.exit_code == 0 and "directory" in result.stdout.casefold():
                selected = candidate
                break
        if selected is None:
            raise SessionError("Private application data directory could not be resolved.")
        return {
            "package": target,
            "data_directory": selected,
            "external_data_directory": f"/storage/emulated/0/Android/data/{target}",
            "root_available": True,
            "root_mode": probe.mode.value,
            "root_probe_status": probe.probe_status,
            "root_probe_evidence": probe.probe_evidence,
        }

    def list_storage(self, serial: str, package: str) -> list[dict[str, object]]:
        target = validate_package_name(package)
        metadata = self.inspect_package(serial, target)
        root = str(metadata["data_directory"])
        probe = self._root_probe(serial)
        format_value = "%n|%F|%s|%u|%g|%a"
        command = (
            f"find {shlex.quote(root)} -mindepth 1 -maxdepth {self.max_depth} "
            f"-exec stat -c {shlex.quote(format_value)} '{{}}' + "
            f"| head -n {self.max_entries + 1}"
        )
        result = root_shell(
            self.adb,
            serial,
            command,
            timeout=self.timeout,
            check=False,
            operation="collecting bounded private-storage metadata",
            probe=probe,
        )
        if result.timed_out:
            raise SessionError("Private storage metadata collection timed out.")
        if result.exit_code != 0:
            detail = redact_text((result.stderr or result.stdout).strip())[:300]
            raise SessionError(
                "Private storage metadata collection failed"
                + (f": {detail}" if detail else ".")
            )
        entries: list[dict[str, object]] = []
        root_prefix = root.rstrip("/") + "/"
        for line in result.stdout.splitlines()[: self.max_entries]:
            parts = line.split("|")
            if len(parts) != 6:
                continue
            path, file_type, size, uid, gid, mode = parts
            if not path.startswith(root_prefix):
                continue
            relative = path[len(root_prefix) :]
            if not relative:
                continue
            normalized_type = (
                "directory"
                if "directory" in file_type
                else "symlink"
                if "symbolic link" in file_type
                else "file"
            )
            entries.append(
                {
                    "path": relative,
                    "canonical_path": path,
                    "type": normalized_type,
                    "size": size,
                    "uid": uid,
                    "gid": gid,
                    "mode": mode,
                    "symlink_target": "unresolved" if normalized_type == "symlink" else None,
                }
            )
        return entries


class PrivateStorageService:
    """Scope- and session-gated storage collection seam for a real or fake backend."""

    def __init__(
        self,
        repository: SessionRepository,
        backend: PrivateStorageBackend,
    ) -> None:
        self.repository = repository
        self.paths = repository.paths
        self.backend = backend
        self.evidence = EvidenceRepository(self.paths, self.repository)

    def collect(
        self,
        session_id: str,
        *,
        content_requests: Sequence[str] = (),
    ) -> StorageInspectionResult:
        record = self.repository.load(session_id)
        if record.status not in {
            SessionStatus.ACTIVE,
            SessionStatus.CLEANUP_REQUIRED,
        }:
            raise SessionError("Root storage inspection requires an active session.")
        scope = load_scope(self.paths)
        scope.require_device_package(
            record.serial,
            record.package,
            action="root_storage_read",
        )
        self.repository.require_modifying_session_slot(record.serial, record.session_id)
        with DeviceLock(
            self.paths,
            record.serial,
            operation="root_storage_read",
            session_id=record.session_id,
            timeout=0,
        ):
            self.repository.require_modifying_session_slot(
                record.serial,
                record.session_id,
            )
            current = self.repository.load(record.session_id)
            metadata = self.backend.inspect_package(current.serial, current.package)
            data_directory = str(metadata.get("data_directory", ""))
            external_directory = str(
                metadata.get("external_data_directory")
                or f"/storage/emulated/0/Android/data/{current.package}"
            )
            entries = self.backend.list_storage(current.serial, current.package)
            policy = StorageInspectionPolicy(
                max_file_size_bytes=scope.limits.max_evidence_size_mb * 1024 * 1024,
            )
            result = PrivateStorageInspector(policy).inspect(
                package=current.package,
                data_directory=data_directory,
                external_data_directory=external_directory,
                entries=entries,
                content_requests=content_requests,
                source=self.backend.evidence_source,
                environment=self.backend.environment_type,
                root_mode=str(metadata.get("root_mode", RootMode.NON_ROOT.value)),
            )
            current_paths = self.repository.paths_for(current.session_id)
            output = current_paths.redacted_dir / "storage" / "private-storage.json"
            write_json_atomic(output, result.to_dict(), root=self.paths.root)
            self.evidence.register_file(
                current.session_id,
                output,
                evidence_type="private_storage_metadata",
                source=result.source,
                description="Bounded, redacted private-application-storage metadata.",
                sensitive=True,
                redacted=True,
            )
            self.repository.append_event(
                current.session_id,
                "root_storage_fixture_analyzed"
                if result.source == "fixture"
                else "root_storage_analyzed",
                {
                    "source": result.source,
                    "environment": result.environment,
                    "artifact_count": len(result.artifacts),
                    "physical_validation_status": result.physical_validation_status,
                },
            )
            return result
