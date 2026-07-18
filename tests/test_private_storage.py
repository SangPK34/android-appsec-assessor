from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from android_assessor.errors import ScopeError, SessionError
from android_assessor.paths import ProjectPaths
from android_assessor.private_storage import (
    AdbPrivateStorageBackend,
    PrivateStorageInspector,
    PrivateStorageService,
    StorageAnalysisStatus,
    StorageArtifactType,
    StorageCanaryProbeResult,
    StorageInspectionPolicy,
)
from android_assessor.session import SessionRepository
from android_assessor.subprocess_utils import CommandResult
from tests.fakes import FakeAndroidBackend, load_fixture

PACKAGE = "com.example.rootedlab"
DATA_DIRECTORY = "/data/user/0/com.example.rootedlab"
EXTERNAL_DIRECTORY = "/storage/emulated/0/Android/data/com.example.rootedlab"
SESSION_CANARY = "THESIS_CANARY_20260718T120000Z_abcdef123456"
STALE_CANARY = "THESIS_CANARY_20260718T120001Z_012345abcdef"


def inventory_entries() -> list[dict[str, Any]]:
    return list(load_fixture("storage/inventory.json")["entries"])


def inspect(
    entries: Iterable[Mapping[str, Any]] | None = None,
    *,
    content_requests: tuple[str, ...] = (),
    session_canary: str | None = None,
    policy: StorageInspectionPolicy | None = None,
):
    return PrivateStorageInspector(policy).inspect(
        package=PACKAGE,
        data_directory=DATA_DIRECTORY,
        external_data_directory=EXTERNAL_DIRECTORY,
        entries=entries if entries is not None else inventory_entries(),
        content_requests=content_requests,
        session_canary=session_canary,
        source="fixture",
        environment="simulated",
    )


def test_storage_inventory_is_metadata_first_bounded_and_hashed() -> None:
    result = inspect()

    assert result.implementation_status == "IMPLEMENTED_UNVERIFIED"
    assert result.physical_validation_status == "UNVERIFIED"
    assert result.source == "fixture"
    assert all(not artifact.content_collected for artifact in result.artifacts)
    assert all(artifact.hash_scope == "metadata" for artifact in result.artifacts)
    assert all(len(artifact.sha256) == 64 for artifact in result.artifacts)
    assert all(artifact.root_used for artifact in result.artifacts)
    assert any(item["reason"] == "symlink_not_followed" for item in result.skipped)
    assert {artifact.type for artifact in result.artifacts} >= {
        StorageArtifactType.SHARED_PREFERENCES,
        StorageArtifactType.SQLITE,
        StorageArtifactType.INTERNAL_FILE,
        StorageArtifactType.CACHE,
        StorageArtifactType.NO_BACKUP,
        StorageArtifactType.WEBVIEW,
        StorageArtifactType.EXTERNAL,
    }


def test_targeted_canary_content_is_logically_detected_but_not_finding_eligible() -> None:
    result = inspect(
        content_requests=(
            "shared_prefs/session.xml",
            "databases/lab.db",
            "cache/stale-token.txt",
        ),
        session_canary=SESSION_CANARY,
    )

    confirmed = [
        item for item in result.observations if item.status is StorageAnalysisStatus.CONFIRMED
    ]
    assert {item.title for item in confirmed} == {
        "Sensitive canary in SharedPreferences",
        "Sensitive canary in SQLite",
        "Sensitive canary remains after logout",
    }
    assert all(not item.finding_eligible for item in confirmed)
    assert all(item.physical_validation_status == "UNVERIFIED" for item in confirmed)
    serialized = result.to_dict()
    rendered = str(serialized)
    assert SESSION_CANARY not in rendered
    assert all(item.content_scanned for item in result.artifacts if item.content_collected)
    assert sum(item.exact_canary_match for item in result.artifacts) == 3


def test_storage_requires_exact_current_session_canary_for_confirmation() -> None:
    result = inspect(
        content_requests=("shared_prefs/session.xml",),
        session_canary=STALE_CANARY,
    )

    artifact = next(
        item for item in result.artifacts if item.relative_path == "shared_prefs/session.xml"
    )
    assert artifact.content_scanned is True
    assert artifact.exact_canary_match is False
    assert not any(
        item.status is StorageAnalysisStatus.CONFIRMED
        for item in result.observations
    )


def test_storage_rejects_canary_prefix_or_suffix_as_exact_attribution() -> None:
    entry = {
        "path": "files/value.txt",
        "type": "file",
        "size": 100,
        "uid": 10123,
        "gid": 10123,
        "mode": "0600",
        "content_fixture": f"prefix {SESSION_CANARY}_STALE suffix",
    }

    result = inspect(
        [entry],
        content_requests=("files/value.txt",),
        session_canary=SESSION_CANARY,
    )

    assert result.artifacts[0].content_scanned is True
    assert result.artifacts[0].exact_canary_match is False
    assert not any(
        item.status is StorageAnalysisStatus.CONFIRMED
        for item in result.observations
    )


def test_backend_match_metadata_must_be_attributed_to_current_session_canary() -> None:
    entry = {
        "path": "files/value.txt",
        "type": "file",
        "size": 100,
        "uid": 10123,
        "gid": 10123,
        "mode": "0600",
        "content_scanned": True,
        "exact_canary_match": True,
        "session_canary_sha256": hashlib.sha256(
            STALE_CANARY.encode("utf-8")
        ).hexdigest(),
    }

    result = inspect([entry], session_canary=SESSION_CANARY)

    assert result.artifacts[0].content_scanned is True
    assert result.artifacts[0].exact_canary_match is False
    assert not any(
        item.status is StorageAnalysisStatus.CONFIRMED
        for item in result.observations
    )


def test_storage_without_session_canary_remains_backward_compatible_but_unattributed() -> None:
    result = inspect(content_requests=("shared_prefs/session.xml",))

    artifact = next(
        item for item in result.artifacts if item.relative_path == "shared_prefs/session.xml"
    )
    assert artifact.content_collected is True
    assert artifact.content_scanned is True
    assert artifact.exact_canary_match is False
    assert not any(
        item.status is StorageAnalysisStatus.CONFIRMED
        for item in result.observations
    )


@pytest.mark.parametrize(
    "session_canary",
    (
        "THESIS_CANARY_STORAGE_TOKEN",
        "THESIS_CANARY_20260718T120000Z_ABCDEF123456",
        "THESIS_CANARY_20260718T120000Z_abcdef123456_extra",
    ),
)
def test_storage_rejects_invalid_session_canary_format(session_canary: str) -> None:
    with pytest.raises(ValueError, match="invalid format"):
        inspect(session_canary=session_canary)


def test_sensitive_candidate_without_exact_canary_is_ambiguous_and_redacted() -> None:
    entry = {
        "path": "files/profile.json",
        "type": "file",
        "size": 40,
        "uid": 10123,
        "gid": 10123,
        "mode": "0600",
        "content_fixture": '{"password":"not-the-session-canary"}',
    }

    result = inspect(
        [entry],
        content_requests=("files/profile.json",),
        session_canary=SESSION_CANARY,
    )
    by_id = {item.observation_id: item for item in result.observations}

    assert by_id["storage-sensitive-unattributed"].status is StorageAnalysisStatus.POTENTIAL
    assert by_id["storage-sensitive-unattributed"].finding_eligible is False
    assert result.artifacts[0].exact_canary_match is False
    assert "not-the-session-canary" not in str(result.to_dict())


def test_storage_flow_not_triggered_records_no_content_scan_or_confirmation() -> None:
    result = inspect(session_canary=SESSION_CANARY)

    assert all(item.content_scanned is False for item in result.artifacts)
    assert all(item.exact_canary_match is False for item in result.artifacts)
    assert not any(
        item.status is StorageAnalysisStatus.CONFIRMED
        for item in result.observations
    )


def test_key_and_ciphertext_colocation_and_permissions_remain_potential() -> None:
    result = inspect()

    by_id = {item.observation_id: item for item in result.observations}
    assert by_id["storage-key-adjacent"].status is StorageAnalysisStatus.POTENTIAL
    assert by_id["storage-world-readable"].status is StorageAnalysisStatus.POTENTIAL
    assert by_id["storage-group-access"].status is StorageAnalysisStatus.POTENTIAL
    assert by_id["storage-content-unverified"].status is StorageAnalysisStatus.INCONCLUSIVE


def test_root_readability_alone_is_post_compromise_observation() -> None:
    result = inspect(
        [
            {
                "path": "files/state.bin",
                "type": "file",
                "size": 16,
                "uid": 10123,
                "gid": 10123,
                "mode": "0600",
            }
        ]
    )

    assert len(result.observations) == 1
    observation = result.observations[0]
    assert observation.status is StorageAnalysisStatus.POST_COMPROMISE_OBSERVATION
    assert observation.validation_type == "post_compromise_observation"
    assert observation.finding_eligible is False


def test_storage_permissions_distinguish_world_and_group_access() -> None:
    result = inspect(
        [
            {
                "path": "files/world-readable.txt",
                "type": "file",
                "size": 10,
                "uid": 10123,
                "gid": 10123,
                "mode": "0604",
            },
            {
                "path": "files/world-writable.txt",
                "type": "file",
                "size": 10,
                "uid": 10123,
                "gid": 10123,
                "mode": "0602",
            },
            {
                "path": "files/group-only.txt",
                "type": "file",
                "size": 10,
                "uid": 10123,
                "gid": 10123,
                "mode": "0660",
            },
        ]
    )
    by_id = {item.observation_id: item for item in result.observations}

    assert by_id["storage-world-readable"].artifact_paths == (
        "files/world-readable.txt",
    )
    assert by_id["storage-world-writable"].artifact_paths == (
        "files/world-writable.txt",
    )
    assert by_id["storage-group-access"].artifact_paths == (
        "files/group-only.txt",
    )
    assert by_id["storage-group-access"].finding_eligible is False


def test_external_storage_mode_is_not_treated_as_world_exposure_without_context() -> None:
    result = inspect(
        [
            {
                "path": "external/files/export.txt",
                "canonical_path": f"{EXTERNAL_DIRECTORY}/files/export.txt",
                "type": "external",
                "size": 10,
                "uid": 10123,
                "gid": 10123,
                "mode": "0644",
            }
        ]
    )

    ids = {item.observation_id for item in result.observations}
    assert "storage-world-readable" not in ids
    assert "storage-world-writable" not in ids
    assert "storage-group-access" not in ids
    assert ids == {"storage-root-readable"}


@pytest.mark.parametrize(
    ("entry", "reason"),
    (
        (
            {
                "path": "../other/secret.txt",
                "type": "file",
                "size": 10,
                "uid": 1,
                "gid": 1,
                "mode": "0600",
            },
            "invalid_relative_path",
        ),
        (
            {
                "path": "files/outside.txt",
                "canonical_path": "/data/local/tmp/outside.txt",
                "type": "file",
                "size": 10,
                "uid": 1,
                "gid": 1,
                "mode": "0600",
            },
            "canonical_path_outside_scope",
        ),
        (
            {
                "path": "files/link",
                "type": "symlink",
                "symlink_target": "/data/local/tmp/outside",
                "size": 0,
                "uid": 1,
                "gid": 1,
                "mode": "0777",
            },
            "symlink_not_followed",
        ),
    ),
)
def test_storage_rejects_traversal_outside_canonical_path_and_symlinks(
    entry: dict[str, Any],
    reason: str,
) -> None:
    result = inspect([entry])

    assert result.artifacts == ()
    assert result.skipped[0]["reason"] == reason


def test_storage_enforces_evidence_count_limit() -> None:
    result = inspect(
        inventory_entries(),
        policy=StorageInspectionPolicy(max_evidence_count=2),
    )

    assert len(result.artifacts) == 2
    assert result.skipped[-1]["reason"] == "evidence_count_limit"


def test_storage_does_not_collect_oversized_or_disallowed_extension() -> None:
    entries = inventory_entries()
    entries.append(
        {
            "path": "files/certificate.pem",
            "type": "file",
            "size": 20,
            "uid": 10123,
            "gid": 10123,
            "mode": "0600",
            "content_fixture": "THESIS_CANARY_PEM",
        }
    )
    result = inspect(
        entries,
        content_requests=("files/oversized.txt", "files/certificate.pem"),
    )
    artifacts = {item.relative_path: item for item in result.artifacts}

    assert artifacts["files/oversized.txt"].content_collected is False
    assert artifacts["files/certificate.pem"].content_collected is False
    assert artifacts["files/oversized.txt"].hash_scope == "metadata"


@pytest.mark.parametrize(
    "data_directory",
    (
        "/data/user/0/com.other.app",
        "/data/local/tmp/com.example.rootedlab",
        "/data/user/0/com.example.rootedlab/extra",
    ),
)
def test_storage_rejects_mismatched_or_non_app_data_directory(
    data_directory: str,
) -> None:
    with pytest.raises(ValueError, match="does not match"):
        PrivateStorageInspector().inspect(
            package=PACKAGE,
            data_directory=data_directory,
            entries=[],
            source="fixture",
            environment="simulated",
        )


def test_external_artifact_requires_package_specific_external_root() -> None:
    result = inspect()
    external = next(
        item for item in result.artifacts if item.type is StorageArtifactType.EXTERNAL
    )
    assert external.canonical_path.startswith(EXTERNAL_DIRECTORY + "/")

    with pytest.raises(ValueError, match="External app data"):
        PrivateStorageInspector().inspect(
            package=PACKAGE,
            data_directory=DATA_DIRECTORY,
            external_data_directory="/storage/emulated/0/Android/data/com.other.app",
            entries=[],
            source="fixture",
            environment="simulated",
        )


def test_fixture_provenance_cannot_be_mislabeled() -> None:
    with pytest.raises(ValueError, match="simulated provenance"):
        PrivateStorageInspector().inspect(
            package=PACKAGE,
            data_directory=DATA_DIRECTORY,
            entries=[],
            source="fixture",
            environment="physical",
        )


def active_storage_session(
    tmp_path: Path,
    *,
    allowed_actions: str = "root_storage_read",
) -> tuple[SessionRepository, str, FakeAndroidBackend]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        "devices: [FIXTURE_SERIAL]\n"
        f"packages: [{PACKAGE}]\n"
        "api_hosts: []\n"
        f"allowed_actions: [{allowed_actions}]\n",
        encoding="utf-8",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="FIXTURE_SERIAL", package=PACKAGE)
    repository.activate(record.session_id, snapshot={}, device={}, environment={})
    package_fixture = load_fixture("packages/rooted_lab.json")
    backend = FakeAndroidBackend(
        packages={PACKAGE: package_fixture["metadata"]},
        storage_entries=inventory_entries(),
    )
    return repository, record.session_id, backend


def test_storage_service_enforces_scope_session_lock_and_fixture_provenance(
    tmp_path: Path,
) -> None:
    repository, session_id, backend = active_storage_session(tmp_path)

    result = PrivateStorageService(repository, backend).collect(session_id)

    assert result.source == "fixture"
    assert result.environment == "simulated"
    assert [name for name, _arguments in backend.operations] == [
        "inspect_package",
        "list_storage",
    ]
    events = repository.paths_for(session_id).events_jsonl.read_text(encoding="utf-8")
    assert "root_storage_fixture_analyzed" in events
    assert "UNVERIFIED" in events


class ExactCanaryFakeBackend(FakeAndroidBackend):
    def probe_exact_canary(
        self,
        serial: str,
        package: str,
        **_kwargs: object,
    ) -> StorageCanaryProbeResult:
        self._require_connected(serial)
        self.operations.append(("probe_exact_canary", (package,)))
        return StorageCanaryProbeResult(
            matches={
                "shared_prefs/session.xml": True,
                "databases/lab.db": False,
            },
            status="partial",
            limitations=("fixture_probe_limit",),
        )


def test_storage_service_wires_exact_session_canary_without_requiring_fake_changes(
    tmp_path: Path,
) -> None:
    repository, session_id, original = active_storage_session(tmp_path)
    backend = ExactCanaryFakeBackend(
        packages=original.packages,
        storage_entries=original.storage_entries,
    )

    result = PrivateStorageService(repository, backend).collect(
        session_id,
        session_canary=SESSION_CANARY,
    )
    by_path = {item.relative_path: item for item in result.artifacts}

    assert by_path["shared_prefs/session.xml"].content_scanned is True
    assert by_path["shared_prefs/session.xml"].exact_canary_match is True
    assert by_path["shared_prefs/session.xml"].content_collected is False
    assert by_path["databases/lab.db"].content_scanned is True
    assert by_path["databases/lab.db"].exact_canary_match is False
    assert any(
        item["reason"] == "canary_scan_partial" for item in result.skipped
    )
    assert result.content_scan_status == "partial"
    assert result.content_scan_limitations == ("fixture_probe_limit",)
    assert any(name == "probe_exact_canary" for name, _args in backend.operations)
    assert SESSION_CANARY not in str(result.to_dict())


class FailedCanaryFakeBackend(FakeAndroidBackend):
    def probe_exact_canary(
        self,
        serial: str,
        package: str,
        **_kwargs: object,
    ) -> StorageCanaryProbeResult:
        self._require_connected(serial)
        self.operations.append(("probe_exact_canary", (package,)))
        return StorageCanaryProbeResult(
            matches={},
            status="error",
            limitations=("probe_command_failed",),
        )


def test_storage_service_preserves_structured_canary_probe_failure(
    tmp_path: Path,
) -> None:
    repository, session_id, original = active_storage_session(tmp_path)
    backend = FailedCanaryFakeBackend(
        packages=original.packages,
        storage_entries=original.storage_entries,
    )

    result = PrivateStorageService(repository, backend).collect(
        session_id,
        session_canary=SESSION_CANARY,
    )

    assert result.content_scan_status == "error"
    assert result.content_scan_limitations == ("probe_command_failed",)
    assert any(item["reason"] == "canary_scan_error" for item in result.skipped)


def test_storage_service_denies_action_before_backend_call(tmp_path: Path) -> None:
    repository, session_id, backend = active_storage_session(
        tmp_path,
        allowed_actions="inspect",
    )

    with pytest.raises(ScopeError, match="root_storage_read"):
        PrivateStorageService(repository, backend).collect(session_id)

    assert backend.operations == []


def test_storage_service_requires_active_session(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    repository = SessionRepository(paths)
    record = repository.initialize(serial="FIXTURE_SERIAL", package=PACKAGE)
    backend = FakeAndroidBackend()

    with pytest.raises(SessionError, match="active session"):
        PrivateStorageService(repository, backend).collect(record.session_id)

    assert backend.operations == []


class AdbdRootStorageAdb:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def require_authorized_device(self, serial: str) -> object:
        assert serial == "FIXTURE_SERIAL"
        return object()

    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        **_kwargs: object,
    ) -> CommandResult:
        assert serial == "FIXTURE_SERIAL"
        selected = tuple(arguments)
        self.calls.append(selected)
        if selected == ("pm", "path", PACKAGE):
            return _storage_command_result("package:/data/app/fixture/base.apk\n")
        if selected == ("id",):
            return _storage_command_result("uid=0(root) gid=0(root)\n")
        if selected[:2] == ("sh", "-c") and "find " in selected[-1]:
            return _storage_command_result(
                f"{DATA_DIRECTORY}/shared_prefs/settings.xml|regular file|120|10123|10123|600\n"
                f"{DATA_DIRECTORY}/databases/app.db|regular file|4096|10123|10123|600\n"
                f"{DATA_DIRECTORY}/files/note.txt|regular file|32|10123|10123|600\n"
                f"{EXTERNAL_DIRECTORY}/files/export.txt|regular file|24|10123|10123|644\n"
            )
        if selected[:2] == ("sh", "-c") and "stat -c" in selected[-1]:
            return _storage_command_result("directory\n")
        if selected[:2] == ("sh", "-c") and "grep -a -E -q" in selected[-1]:
            if "/shared_prefs/settings.xml" in selected[-1]:
                return _storage_command_result("")
            if "/databases/app.db" in selected[-1]:
                return _storage_command_result("", exit_code=1)
        raise AssertionError(f"Unexpected ADB call: {selected}")


def _storage_command_result(stdout: str, *, exit_code: int = 0) -> CommandResult:
    return CommandResult(
        arguments=(),
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=False,
    )


def test_adbd_root_private_storage_is_bounded_metadata_only() -> None:
    adb = AdbdRootStorageAdb()
    backend = AdbPrivateStorageBackend(
        adb,  # type: ignore[arg-type]
        max_entries=3,
        max_depth=2,
    )

    metadata = backend.inspect_package("FIXTURE_SERIAL", PACKAGE)
    entries = backend.list_storage("FIXTURE_SERIAL", PACKAGE)
    result = PrivateStorageInspector(
        StorageInspectionPolicy(max_evidence_count=3)
    ).inspect(
        package=PACKAGE,
        data_directory=str(metadata["data_directory"]),
        external_data_directory=str(metadata["external_data_directory"]),
        entries=entries,
        source=backend.evidence_source,
        environment=backend.environment_type,
        root_mode=str(metadata["root_mode"]),
        inventory_status=backend.last_inventory_status,
        inventory_limitations=backend.last_inventory_limitations,
    )

    assert result.root_mode == "adb_root"
    assert len(result.artifacts) == 3
    assert {item.type for item in result.artifacts} == {
        StorageArtifactType.SHARED_PREFERENCES,
        StorageArtifactType.SQLITE,
        StorageArtifactType.EXTERNAL,
    }
    assert backend.last_inventory_status == "partial"
    assert "aggregate_entry_limit" in backend.last_inventory_limitations
    assert result.inventory_status == "partial"
    assert "aggregate_entry_limit" in result.inventory_limitations
    assert all(item.hash_scope == "metadata" for item in result.artifacts)
    assert all(item.content_collected is False for item in result.artifacts)
    assert all(item.root_used is True for item in result.artifacts)
    assert all(item.finding_eligible is False for item in result.observations)
    assert all("su" not in call for call in adb.calls)


def test_adbd_root_inventory_includes_only_package_scoped_external_storage() -> None:
    adb = AdbdRootStorageAdb()
    backend = AdbPrivateStorageBackend(
        adb,  # type: ignore[arg-type]
        max_entries=5,
        max_depth=2,
    )

    entries = backend.list_storage("FIXTURE_SERIAL", PACKAGE)
    external = next(item for item in entries if item["path"] == "external/files/export.txt")

    assert external["canonical_path"] == f"{EXTERNAL_DIRECTORY}/files/export.txt"
    assert all(
        str(item["canonical_path"]).startswith((DATA_DIRECTORY, EXTERNAL_DIRECTORY))
        for item in entries
    )


class DenseStorageAdb(AdbdRootStorageAdb):
    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> CommandResult:
        selected = tuple(arguments)
        if selected[:2] == ("sh", "-c") and "find " in selected[-1]:
            self.calls.append(selected)
            internal = "".join(
                f"{DATA_DIRECTORY}/files/internal-{index}.txt|regular file|8|10123|10123|600\n"
                for index in range(6)
            )
            external = (
                f"{EXTERNAL_DIRECTORY}/files/external.txt|regular file|8|10123|10123|644\n"
            )
            return _storage_command_result(internal + external)
        return super().shell(serial, arguments, **kwargs)


class CanaryRedactionStorageAdb(AdbdRootStorageAdb):
    def __init__(self) -> None:
        super().__init__()
        self.protected_values: list[tuple[str, ...]] = []

    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> CommandResult:
        selected = tuple(arguments)
        if selected[:2] == ("sh", "-c") and "grep -a -E -q" in selected[-1]:
            values = kwargs.get("sensitive_values", ())
            assert isinstance(values, tuple)
            self.protected_values.append(values)
        return super().shell(serial, arguments, **kwargs)


def test_dense_internal_inventory_reserves_external_coverage_and_reports_limit() -> None:
    adb = DenseStorageAdb()
    backend = AdbPrivateStorageBackend(
        adb,  # type: ignore[arg-type]
        max_entries=4,
        max_depth=2,
    )

    entries = backend.list_storage("FIXTURE_SERIAL", PACKAGE)

    assert len(entries) == 4
    assert any(item["path"] == "external/files/external.txt" for item in entries)
    assert backend.last_inventory_status == "partial"
    assert set(backend.last_inventory_limitations) >= {
        "internal_entry_limit",
        "aggregate_entry_limit",
    }


def test_storage_backend_reuses_package_metadata_and_root_probe() -> None:
    adb = AdbdRootStorageAdb()
    backend = AdbPrivateStorageBackend(adb)  # type: ignore[arg-type]

    backend.inspect_package("FIXTURE_SERIAL", PACKAGE)
    backend.list_storage("FIXTURE_SERIAL", PACKAGE)

    assert adb.calls.count(("pm", "path", PACKAGE)) == 1
    assert adb.calls.count(("id",)) == 1


def test_adbd_root_exact_canary_probe_is_bounded_and_returns_only_booleans() -> None:
    adb = CanaryRedactionStorageAdb()
    backend = AdbPrivateStorageBackend(
        adb,  # type: ignore[arg-type]
        max_entries=5,
        max_depth=2,
    )
    entries = [
        {
            "path": "shared_prefs/settings.xml",
            "canonical_path": f"{DATA_DIRECTORY}/shared_prefs/settings.xml",
            "type": "file",
            "size": 120,
        },
        {
            "path": "databases/app.db",
            "canonical_path": f"{DATA_DIRECTORY}/databases/app.db",
            "type": "file",
            "size": 4096,
        },
        {
            "path": "files/oversized.txt",
            "canonical_path": f"{DATA_DIRECTORY}/files/oversized.txt",
            "type": "file",
            "size": 10_000,
        },
        {
            "path": "files/certificate.pem",
            "canonical_path": f"{DATA_DIRECTORY}/files/certificate.pem",
            "type": "file",
            "size": 10,
        },
        {
            "path": "files/link.txt",
            "canonical_path": f"{DATA_DIRECTORY}/files/link.txt",
            "type": "symlink",
            "size": 10,
            "symlink_target": "/data/local/tmp/outside",
        },
    ]

    probe = backend.probe_exact_canary(
        "FIXTURE_SERIAL",
        PACKAGE,
        entries=entries,
        session_canary=SESSION_CANARY,
        data_directory=DATA_DIRECTORY,
        external_data_directory=EXTERNAL_DIRECTORY,
        policy=StorageInspectionPolicy(max_file_size_bytes=5000),
    )

    assert probe.matches == {
        "shared_prefs/settings.xml": True,
        "databases/app.db": False,
    }
    assert probe.status == "completed"
    assert probe.limitations == ()
    grep_calls = [call[-1] for call in adb.calls if "grep -a -E -q" in call[-1]]
    assert len(grep_calls) == 2
    assert all(DATA_DIRECTORY in command for command in grep_calls)
    assert all("su -c" not in command for command in grep_calls)
    assert all("THESIS_CANARY_STORAGE_TOKEN" not in command for command in grep_calls)
    assert adb.protected_values == [(SESSION_CANARY,), (SESSION_CANARY,)]


class TimedOutCanaryProbeAdb(AdbdRootStorageAdb):
    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> CommandResult:
        selected = tuple(arguments)
        if selected[:2] == ("sh", "-c") and "grep -a -E -q" in selected[-1]:
            self.calls.append(selected)
            return CommandResult(
                arguments=(),
                exit_code=124,
                stdout="",
                stderr="",
                started_at="2026-07-17T00:00:00+00:00",
                duration_ms=1,
                timed_out=True,
            )
        return super().shell(serial, arguments, **kwargs)


def test_exact_canary_probe_stops_after_first_timeout() -> None:
    adb = TimedOutCanaryProbeAdb()
    backend = AdbPrivateStorageBackend(adb)  # type: ignore[arg-type]
    entries = [
        {
            "path": f"files/value-{index}.txt",
            "canonical_path": f"{DATA_DIRECTORY}/files/value-{index}.txt",
            "type": "file",
            "size": 32,
        }
        for index in range(50)
    ]

    probe = backend.probe_exact_canary(
        "FIXTURE_SERIAL",
        PACKAGE,
        entries=entries,
        session_canary=SESSION_CANARY,
        data_directory=DATA_DIRECTORY,
        external_data_directory=EXTERNAL_DIRECTORY,
        policy=StorageInspectionPolicy(max_scan_seconds=1),
    )

    grep_calls = [call for call in adb.calls if "grep -a -E -q" in call[-1]]
    assert probe.matches == {}
    assert probe.status == "timed_out"
    assert probe.limitations == ("probe_command_timed_out",)
    assert len(grep_calls) == 1


class FailedCanaryProbeAdb(AdbdRootStorageAdb):
    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> CommandResult:
        selected = tuple(arguments)
        if selected[:2] == ("sh", "-c") and "grep -a -E -q" in selected[-1]:
            self.calls.append(selected)
            return _storage_command_result("", exit_code=2)
        return super().shell(serial, arguments, **kwargs)


def test_exact_canary_probe_distinguishes_tool_failure_from_no_match() -> None:
    adb = FailedCanaryProbeAdb()
    backend = AdbPrivateStorageBackend(adb)  # type: ignore[arg-type]

    probe = backend.probe_exact_canary(
        "FIXTURE_SERIAL",
        PACKAGE,
        entries=[
            {
                "path": "files/value.txt",
                "canonical_path": f"{DATA_DIRECTORY}/files/value.txt",
                "type": "file",
                "size": 32,
            }
        ],
        session_canary=SESSION_CANARY,
        data_directory=DATA_DIRECTORY,
        external_data_directory=EXTERNAL_DIRECTORY,
        policy=StorageInspectionPolicy(),
    )

    assert probe.matches == {}
    assert probe.status == "error"
    assert probe.limitations == ("probe_command_failed",)


def test_exact_canary_probe_reports_aggregate_byte_budget_as_partial() -> None:
    adb = AdbdRootStorageAdb()
    backend = AdbPrivateStorageBackend(adb)  # type: ignore[arg-type]

    probe = backend.probe_exact_canary(
        "FIXTURE_SERIAL",
        PACKAGE,
        entries=[
            {
                "path": "shared_prefs/settings.xml",
                "canonical_path": f"{DATA_DIRECTORY}/shared_prefs/settings.xml",
                "type": "file",
                "size": 120,
            },
            {
                "path": "databases/app.db",
                "canonical_path": f"{DATA_DIRECTORY}/databases/app.db",
                "type": "file",
                "size": 4096,
            },
        ],
        session_canary=SESSION_CANARY,
        data_directory=DATA_DIRECTORY,
        external_data_directory=EXTERNAL_DIRECTORY,
        policy=StorageInspectionPolicy(max_total_scan_bytes=200),
    )

    assert probe.matches == {"shared_prefs/settings.xml": True}
    assert probe.status == "partial"
    assert probe.limitations == ("probe_byte_budget_exhausted",)
