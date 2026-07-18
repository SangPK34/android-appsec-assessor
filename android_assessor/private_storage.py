"""Bounded root-assisted private-storage inventory and offline analysis."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import time
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
from .validation import validate_package_name, validate_session_canary

_SENSITIVE_NAME = re.compile(
    r"(?i)(token|secret|credential|password|passwd|session|cookie|auth|key)"
)
_CANARY_CANDIDATE = re.compile(r"THESIS_CANARY_[A-Za-z0-9_]+")
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
    max_total_scan_bytes: int = 10 * 1024 * 1024
    max_scan_seconds: float = 30.0
    allowed_extensions: frozenset[str] = frozenset(
        {".xml", ".json", ".txt", ".db", ".sqlite", ".sqlite3", ".bin"}
    )

    def __post_init__(self) -> None:
        if not 1 <= self.max_file_size_bytes <= 50 * 1024 * 1024:
            raise ValueError("Storage max file size must be between 1 byte and 50 MiB.")
        if not 1 <= self.max_evidence_count <= 1000:
            raise ValueError("Storage evidence count must be between 1 and 1000.")
        if not 1 <= self.max_total_scan_bytes <= 50 * 1024 * 1024:
            raise ValueError("Storage total scan limit must be between 1 byte and 50 MiB.")
        if not 0.1 <= self.max_scan_seconds <= 300:
            raise ValueError("Storage scan time must be between 0.1 and 300 seconds.")
        if any(not value.startswith(".") for value in self.allowed_extensions):
            raise ValueError("Storage extension allowlist entries must start with '.'.")


@dataclass(frozen=True, slots=True)
class StorageCanaryProbeResult:
    matches: dict[str, bool]
    status: str
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"completed", "partial", "timed_out", "error"}:
            raise ValueError("Storage canary probe status is invalid.")
        if any(
            not isinstance(key, str) or not isinstance(value, bool)
            for key, value in self.matches.items()
        ):
            raise ValueError("Storage canary probe matches are invalid.")
        if any(not isinstance(item, str) or not item for item in self.limitations):
            raise ValueError("Storage canary probe limitations are invalid.")


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
    content_scanned: bool
    exact_canary_match: bool
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
    inventory_status: str = "completed"
    inventory_limitations: tuple[str, ...] = ()
    content_scan_status: str = "not_requested"
    content_scan_limitations: tuple[str, ...] = ()

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
            "inventory_status": self.inventory_status,
            "inventory_limitations": list(self.inventory_limitations),
            "content_scan_status": self.content_scan_status,
            "content_scan_limitations": list(self.content_scan_limitations),
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


def _permission_bits(artifact: StorageArtifact) -> int | None:
    if artifact.type in {StorageArtifactType.EXTERNAL, StorageArtifactType.DIRECTORY}:
        return None
    try:
        return int(artifact.permissions[-3:], 8)
    except ValueError:
        return None


def _validate_session_canary(value: str | None) -> str | None:
    if value is None:
        return None
    if value != value.strip():
        raise ValueError("Storage session canary has an invalid format.")
    try:
        return validate_session_canary(value)
    except SessionError as exc:
        raise ValueError("Storage session canary has an invalid format.") from exc


def _contains_exact_canary(content: str, canary: str) -> bool:
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(canary)}(?![A-Za-z0-9_])",
            content,
        )
    )


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
        session_canary: str | None = None,
        external_data_directory: str | None = None,
        source: str,
        environment: str,
        root_mode: str = RootMode.NON_ROOT.value,
        inventory_status: str = "completed",
        inventory_limitations: Sequence[str] = (),
        content_scan_status: str = "not_requested",
        content_scan_limitations: Sequence[str] = (),
    ) -> StorageInspectionResult:
        target = validate_package_name(package)
        selected_canary = _validate_session_canary(session_canary)
        if inventory_status not in {"completed", "partial", "error"}:
            raise ValueError("Storage inventory status is invalid.")
        if content_scan_status not in {
            "not_requested",
            "completed",
            "partial",
            "timed_out",
            "error",
        }:
            raise ValueError("Storage content scan status is invalid.")
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
            backend_scanned = raw.get("content_scanned") is True
            if (
                selected_canary is not None
                and raw.get("content_scan_eligible") is True
                and not backend_scanned
            ):
                reason = {
                    "timed_out": "canary_scan_timed_out",
                    "error": "canary_scan_error",
                    "partial": "canary_scan_partial",
                }.get(content_scan_status, "canary_scan_not_completed")
                skipped.append(
                    {"path": relative, "reason": reason}
                )
            expected_canary_hash = (
                hashlib.sha256(selected_canary.encode("utf-8")).hexdigest()
                if selected_canary
                else None
            )
            backend_match = bool(
                selected_canary
                and raw.get("exact_canary_match") is True
                and raw.get("session_canary_sha256") == expected_canary_hash
            )
            content_scanned = backend_scanned or content is not None
            exact_canary_match = bool(
                selected_canary
                and (
                    backend_match
                    or (
                        content is not None
                        and _contains_exact_canary(content, selected_canary)
                    )
                )
            )
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
                content
                and (
                    exact_canary_match
                    or _CANARY_CANDIDATE.search(content)
                    or _SENSITIVE_NAME.search(content)
                )
            )
            encryption = (
                "plaintext"
                if exact_canary_match
                else "encrypted"
                if suffix in {".enc", ".cipher"}
                else "unknown"
            )
            preview: str | None = None
            if content is not None:
                preview = redact_text(content)
                preview = _CANARY_CANDIDATE.sub("<canary-redacted>", preview)
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
                        "root_bounded_content"
                        if content is not None
                        else "root_bounded_exact_match"
                        if content_scanned
                        else "root_metadata"
                    ),
                    root_used=True,
                    canonical_path=canonical,
                    content_scanned=content_scanned,
                    exact_canary_match=exact_canary_match,
                    content_collected=content is not None,
                    content_preview_redacted=preview[:200] if preview is not None else None,
                    source=source,
                    environment=environment,
                )
            )
        observations = self._analyze(artifacts, raw_entries)
        effective_inventory_status = inventory_status
        effective_inventory_limitations = list(inventory_limitations)
        if any(item.get("reason") == "evidence_count_limit" for item in skipped):
            effective_inventory_status = "partial"
            if "evidence_count_limit" not in effective_inventory_limitations:
                effective_inventory_limitations.append("evidence_count_limit")
        return StorageInspectionResult(
            package=target,
            data_directory=internal_root,
            artifacts=tuple(artifacts),
            observations=tuple(observations),
            skipped=tuple(skipped),
            source=source,
            environment=environment,
            root_mode=RootMode(root_mode).value,
            inventory_status=effective_inventory_status,
            inventory_limitations=tuple(effective_inventory_limitations),
            content_scan_status=content_scan_status,
            content_scan_limitations=tuple(content_scan_limitations),
        )
    @staticmethod
    def _analyze(
        artifacts: Sequence[StorageArtifact],
        raw_entries: Iterable[Mapping[str, Any]],
    ) -> list[StorageObservation]:
        entries = {str(item.get("path")): item for item in raw_entries}
        output: list[StorageObservation] = []
        plaintext = [item for item in artifacts if item.exact_canary_match]
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
                    rationale=(
                        "The exact session canary matched during a bounded, "
                        "package-scoped content probe."
                    ),
                    finding_eligible=artifact.source != "fixture",
                    physical_validation_status="UNVERIFIED",
                )
            )
        world_readable = [
            item.relative_path
            for item in artifacts
            if (bits := _permission_bits(item)) is not None and bool(bits & 0o004)
        ]
        if world_readable:
            output.append(
                StorageObservation(
                    observation_id="storage-world-readable",
                    title="World-readable private-storage file",
                    status=StorageAnalysisStatus.POTENTIAL,
                    validation_type="root_assisted_validation",
                    artifact_paths=tuple(world_readable),
                    rationale="The file mode grants read access to other Android UIDs.",
                    finding_eligible=any(
                        item.source != "fixture"
                        for item in artifacts
                        if item.relative_path in world_readable
                    ),
                    physical_validation_status="UNVERIFIED",
                )
            )
        world_writable = [
            item.relative_path
            for item in artifacts
            if (bits := _permission_bits(item)) is not None and bool(bits & 0o002)
        ]
        if world_writable:
            output.append(
                StorageObservation(
                    observation_id="storage-world-writable",
                    title="World-writable private-storage file",
                    status=StorageAnalysisStatus.POTENTIAL,
                    validation_type="root_assisted_validation",
                    artifact_paths=tuple(world_writable),
                    rationale="The file mode grants write access to other Android UIDs.",
                    finding_eligible=any(
                        item.source != "fixture"
                        for item in artifacts
                        if item.relative_path in world_writable
                    ),
                    physical_validation_status="UNVERIFIED",
                )
            )
        group_accessible = [
            item.relative_path
            for item in artifacts
            if (bits := _permission_bits(item)) is not None and bool(bits & 0o070)
        ]
        if group_accessible:
            output.append(
                StorageObservation(
                    observation_id="storage-group-access",
                    title="Group-accessible private-storage file",
                    status=StorageAnalysisStatus.POTENTIAL,
                    validation_type="post_compromise_observation",
                    artifact_paths=tuple(group_accessible),
                    rationale=(
                        "The file mode grants group access; effective exposure depends "
                        "on Android UID/GID ownership and requires additional context."
                    ),
                    finding_eligible=False,
                    physical_validation_status="UNVERIFIED",
                )
            )
        sensitive_unattributed = [
            item.relative_path
            for item in artifacts
            if item.content_collected and item.sensitive and not item.exact_canary_match
        ]
        if sensitive_unattributed:
            output.append(
                StorageObservation(
                    observation_id="storage-sensitive-unattributed",
                    title="Sensitive private-storage content candidate",
                    status=StorageAnalysisStatus.POTENTIAL,
                    validation_type="root_assisted_validation",
                    artifact_paths=tuple(sensitive_unattributed),
                    rationale=(
                        "Bounded content classification found a sensitive marker, but "
                        "the exact session canary was not present."
                    ),
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


def _canary_probe_candidate(
    raw: Mapping[str, object],
    policy: StorageInspectionPolicy,
) -> tuple[str, int] | None:
    relative = str(raw.get("path", ""))
    relative_path = PurePosixPath(relative)
    if (
        not relative
        or relative_path.is_absolute()
        or ".." in relative_path.parts
        or "." in relative_path.parts
        or str(raw.get("type", "")) not in {"file", "regular", "external"}
        or raw.get("symlink_target")
    ):
        return None
    try:
        size = int(raw.get("size", -1))
    except (TypeError, ValueError):
        return None
    if (
        size < 0
        or size > policy.max_file_size_bytes
        or relative_path.suffix.casefold() not in policy.allowed_extensions
    ):
        return None
    return relative, size


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
        self._root_probe_cache: dict[str, RootProbe] = {}
        self._metadata_cache: dict[tuple[str, str], dict[str, object]] = {}
        self.last_inventory_status = "completed"
        self.last_inventory_limitations: tuple[str, ...] = ()

    def _root_probe(self, serial: str) -> RootProbe:
        probe = self._root_probe_cache.get(serial)
        if probe is None:
            probe = probe_root(self.adb, serial)
            self._root_probe_cache[serial] = probe
        if not probe.available:
            raise SessionError(
                "Private storage inspection skipped because Android root is unavailable: "
                f"{probe.error or probe.probe_status}"
            )
        return probe

    def inspect_package(self, serial: str, package: str) -> dict[str, object]:
        target = validate_package_name(package)
        cache_key = (serial, target)
        cached = self._metadata_cache.get(cache_key)
        if cached is not None:
            return dict(cached)
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
        metadata: dict[str, object] = {
            "package": target,
            "data_directory": selected,
            "external_data_directory": f"/storage/emulated/0/Android/data/{target}",
            "root_available": True,
            "root_mode": probe.mode.value,
            "root_probe_status": probe.probe_status,
            "root_probe_evidence": probe.probe_evidence,
        }
        self._metadata_cache[cache_key] = metadata
        return dict(metadata)

    def list_storage(self, serial: str, package: str) -> list[dict[str, object]]:
        target = validate_package_name(package)
        metadata = self.inspect_package(serial, target)
        internal_root = str(metadata["data_directory"])
        external_root = str(metadata["external_data_directory"])
        probe = self._root_probe(serial)
        format_value = "%n|%F|%s|%u|%g|%a"
        find_commands = " ".join(
            "if [ -d {root} ]; then find {root} -mindepth 1 -maxdepth {depth} "
            "-exec stat -c {format_value} '{{}}' + | head -n {limit}; fi;".format(
                root=shlex.quote(root),
                depth=self.max_depth,
                format_value=shlex.quote(format_value),
                limit=self.max_entries + 1,
            )
            for root in (internal_root, external_root)
        )
        command = f"{{ {find_commands} }}"
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
        roots = (
            ("internal", internal_root.rstrip("/") + "/", ""),
            ("external", external_root.rstrip("/") + "/", "external/"),
        )
        by_root: dict[str, list[dict[str, object]]] = {
            "internal": [],
            "external": [],
        }
        limitations: list[str] = []
        for line in result.stdout.splitlines():
            parts = line.split("|")
            if len(parts) != 6:
                if "malformed_inventory_entry" not in limitations:
                    limitations.append("malformed_inventory_entry")
                continue
            path, file_type, size, uid, gid, mode = parts
            selected_root = next(
                (
                    (root_name, root_prefix, relative_prefix)
                    for root_name, root_prefix, relative_prefix in roots
                    if path.startswith(root_prefix)
                ),
                None,
            )
            if selected_root is None:
                if "path_outside_package_roots" not in limitations:
                    limitations.append("path_outside_package_roots")
                continue
            root_name, root_prefix, relative_prefix = selected_root
            relative = relative_prefix + path[len(root_prefix) :]
            if not relative:
                continue
            normalized_type = (
                "directory"
                if "directory" in file_type
                else "symlink"
                if "symbolic link" in file_type
                else "file"
            )
            by_root[root_name].append(
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
        for root_name, values in by_root.items():
            if len(values) > self.max_entries:
                limitations.append(f"{root_name}_entry_limit")
                del values[self.max_entries :]

        entries: list[dict[str, object]] = []
        longest = max((len(values) for values in by_root.values()), default=0)
        for index in range(longest):
            for root_name in ("internal", "external"):
                values = by_root[root_name]
                if index < len(values) and len(entries) < self.max_entries:
                    entries.append(values[index])
        if sum(len(values) for values in by_root.values()) > len(entries):
            limitations.append("aggregate_entry_limit")
        self.last_inventory_limitations = tuple(dict.fromkeys(limitations))
        self.last_inventory_status = (
            "partial" if self.last_inventory_limitations else "completed"
        )
        return entries

    def probe_exact_canary(
        self,
        serial: str,
        package: str,
        *,
        entries: Sequence[Mapping[str, object]],
        session_canary: str,
        data_directory: str,
        external_data_directory: str | None,
        policy: StorageInspectionPolicy,
    ) -> StorageCanaryProbeResult:
        """Return bounded exact-match results without returning file content."""
        target = validate_package_name(package)
        canary = _validate_session_canary(session_canary)
        if canary is None:  # Defensive; the public method requires a string.
            return StorageCanaryProbeResult(matches={}, status="error", limitations=(
                "missing_session_canary",
            ))
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
        roots = [
            validate_root_remote_path(data_directory, allowed_roots=(data_directory,))
        ]
        if external_data_directory is not None:
            external_match = _EXTERNAL_DATA_DIRECTORY.fullmatch(external_data_directory)
            if external_match is None or external_match.group(1) != target:
                raise ValueError("External app data directory does not match the package.")
            roots.append(
                validate_root_remote_path(
                    external_data_directory,
                    allowed_roots=(external_data_directory,),
                )
            )
        probe = self._root_probe(serial)
        output: dict[str, bool] = {}
        scanned_bytes = 0
        deadline = time.monotonic() + policy.max_scan_seconds
        limitations: list[str] = []
        final_status = "completed"
        boundary_pattern = (
            rf"(^|[^A-Za-z0-9_]){re.escape(canary)}([^A-Za-z0-9_]|$)"
        )
        candidates = [
            (raw, candidate)
            for raw in entries
            if (candidate := _canary_probe_candidate(raw, policy)) is not None
        ]
        if len(candidates) > policy.max_evidence_count:
            final_status = "partial"
            limitations.append("probe_entry_limit")
        for raw, candidate in candidates[: policy.max_evidence_count]:
            relative, size = candidate
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                final_status = "partial"
                limitations.append("probe_time_budget_exhausted")
                break
            if scanned_bytes + size > policy.max_total_scan_bytes:
                final_status = "partial"
                limitations.append("probe_byte_budget_exhausted")
                break
            canonical = str(raw.get("canonical_path", ""))
            try:
                canonical = validate_root_remote_path(
                    canonical,
                    allowed_roots=tuple(roots),
                )
            except ValueError:
                final_status = "partial"
                limitations.append("probe_path_rejected")
                continue
            result = root_shell(
                self.adb,
                serial,
                "grep -a -E -q "
                f"{shlex.quote(boundary_pattern)} {shlex.quote(canonical)}",
                timeout=min(self.timeout, max(0.1, remaining)),
                check=False,
                operation="probing bounded private-storage canary attribution",
                probe=probe,
            )
            scanned_bytes += size
            if result.timed_out:
                final_status = "timed_out"
                limitations.append("probe_command_timed_out")
                break
            if result.exit_code in {0, 1}:
                output[relative] = result.exit_code == 0
                continue
            final_status = "error"
            limitations.append("probe_command_failed")
            break
        return StorageCanaryProbeResult(
            matches=output,
            status=final_status,
            limitations=tuple(dict.fromkeys(limitations)),
        )


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
        session_canary: str | None = None,
    ) -> StorageInspectionResult:
        selected_canary = _validate_session_canary(session_canary)
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
            inventory_status = str(
                getattr(self.backend, "last_inventory_status", "completed")
            )
            inventory_limitations = tuple(
                str(item)
                for item in getattr(
                    self.backend,
                    "last_inventory_limitations",
                    (),
                )
            )
            scope_evidence_bytes = scope.limits.max_evidence_size_mb * 1024 * 1024
            policy = StorageInspectionPolicy(
                max_file_size_bytes=min(scope_evidence_bytes, 5 * 1024 * 1024),
                max_total_scan_bytes=min(scope_evidence_bytes, 20 * 1024 * 1024),
                max_scan_seconds=min(
                    float(scope.limits.command_timeout_seconds),
                    30.0,
                ),
            )
            content_scan_status = "not_requested"
            content_scan_limitations: tuple[str, ...] = ()
            probe_method = getattr(self.backend, "probe_exact_canary", None)
            if selected_canary is not None and callable(probe_method):
                entries = [
                    {
                        **entry,
                        "content_scan_eligible": (
                            _canary_probe_candidate(entry, policy) is not None
                        ),
                    }
                    for entry in entries
                ]
                raw_probe_result = probe_method(
                    current.serial,
                    current.package,
                    entries=entries,
                    session_canary=selected_canary,
                    data_directory=data_directory,
                    external_data_directory=external_directory,
                    policy=policy,
                )
                if isinstance(raw_probe_result, StorageCanaryProbeResult):
                    matches = raw_probe_result.matches
                    content_scan_status = raw_probe_result.status
                    content_scan_limitations = raw_probe_result.limitations
                elif isinstance(raw_probe_result, Mapping):
                    matches = dict(raw_probe_result)
                    eligible_paths = {
                        str(entry.get("path"))
                        for entry in entries
                        if entry.get("content_scan_eligible") is True
                    }
                    content_scan_status = (
                        "completed"
                        if eligible_paths.issubset(matches)
                        else "partial"
                    )
                    if content_scan_status == "partial":
                        content_scan_limitations = ("legacy_probe_incomplete",)
                else:
                    raise SessionError(
                        "Private storage canary probe returned invalid metadata."
                    )
                if any(
                    not isinstance(key, str) or not isinstance(value, bool)
                    for key, value in matches.items()
                ):
                    raise SessionError(
                        "Private storage canary probe returned invalid metadata."
                    )
                entries = [
                    {
                        **entry,
                        **(
                            {
                                "content_scanned": True,
                                "exact_canary_match": bool(matches[str(entry.get("path"))]),
                                "session_canary_sha256": hashlib.sha256(
                                    selected_canary.encode("utf-8")
                                ).hexdigest(),
                            }
                            if str(entry.get("path")) in matches
                            else {}
                        ),
                    }
                    for entry in entries
                ]
            elif selected_canary is not None:
                content_scan_status = "partial"
                content_scan_limitations = ("canary_probe_unavailable",)
            result = PrivateStorageInspector(policy).inspect(
                package=current.package,
                data_directory=data_directory,
                external_data_directory=external_directory,
                entries=entries,
                content_requests=content_requests,
                session_canary=selected_canary,
                source=self.backend.evidence_source,
                environment=self.backend.environment_type,
                root_mode=str(metadata.get("root_mode", RootMode.NON_ROOT.value)),
                inventory_status=inventory_status,
                inventory_limitations=inventory_limitations,
                content_scan_status=content_scan_status,
                content_scan_limitations=content_scan_limitations,
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
                    "exact_canary_match_count": sum(
                        item.exact_canary_match for item in result.artifacts
                    ),
                    "inventory_status": result.inventory_status,
                    "inventory_limitations": list(result.inventory_limitations),
                    "content_scan_status": result.content_scan_status,
                    "content_scan_limitations": list(result.content_scan_limitations),
                    "physical_validation_status": result.physical_validation_status,
                },
            )
            return result
