from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest

from android_assessor.errors import ScopeError, SessionError
from android_assessor.paths import ProjectPaths
from android_assessor.private_storage import (
    PrivateStorageInspector,
    PrivateStorageService,
    StorageAnalysisStatus,
    StorageArtifactType,
    StorageInspectionPolicy,
)
from android_assessor.session import SessionRepository
from tests.fakes import FakeAndroidBackend, load_fixture

PACKAGE = "com.example.rootedlab"
DATA_DIRECTORY = "/data/user/0/com.example.rootedlab"
EXTERNAL_DIRECTORY = "/storage/emulated/0/Android/data/com.example.rootedlab"


def inventory_entries() -> list[dict[str, Any]]:
    return list(load_fixture("storage/inventory.json")["entries"])


def inspect(
    entries: Iterable[Mapping[str, Any]] | None = None,
    *,
    content_requests: tuple[str, ...] = (),
    policy: StorageInspectionPolicy | None = None,
):
    return PrivateStorageInspector(policy).inspect(
        package=PACKAGE,
        data_directory=DATA_DIRECTORY,
        external_data_directory=EXTERNAL_DIRECTORY,
        entries=entries if entries is not None else inventory_entries(),
        content_requests=content_requests,
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
        )
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
    assert "THESIS_CANARY_STORAGE_TOKEN" not in rendered
    assert "THESIS_CANARY_SQLITE_TOKEN" not in rendered
    assert "THESIS_CANARY_LOGOUT_TOKEN" not in rendered


def test_key_and_ciphertext_colocation_and_permissions_remain_potential() -> None:
    result = inspect()

    by_id = {item.observation_id: item for item in result.observations}
    assert by_id["storage-key-adjacent"].status is StorageAnalysisStatus.POTENTIAL
    assert by_id["storage-permissions"].status is StorageAnalysisStatus.POTENTIAL
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
