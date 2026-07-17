from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from android_assessor.errors import ScopeError
from android_assessor.findings import FindingRecord, FindingRepository, FindingStatus
from android_assessor.paths import ProjectPaths
from android_assessor.scope import load_scope
from android_assessor.services.validation_service import ValidationService
from android_assessor.session import SessionRepository
from android_assessor.storage import write_json_atomic
from android_assessor.traffic import TrafficCaptureService


class NoAdbContext:
    def __init__(self, paths: ProjectPaths) -> None:
        self.paths = paths
        self.config = object()
        self.adb_calls = 0

    def adb_client(self, **_kwargs: object) -> object:
        self.adb_calls += 1
        raise AssertionError("ADB must not be called for an out-of-scope action")


def active_session(tmp_path: Path) -> tuple[ProjectPaths, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    repository.activate(
        record.session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURED_EMPTY",
            "http_proxy_error": None,
        },
        device={},
        environment={},
    )
    return paths, repository, record.session_id


def cleartext_finding() -> FindingRecord:
    now = datetime.now(UTC).isoformat()
    return FindingRecord(
        finding_id="finding-asl-mvp-002",
        rule_id="ASL-MVP-002",
        title="Cleartext",
        category="network",
        description="test",
        severity="medium",
        confidence="medium",
        status=FindingStatus.POTENTIAL,
        analysis_type="static",
        root_required=False,
        root_used=False,
        frida_used=False,
        validation_supported=True,
        validation=None,
        evidence_ids=(),
        remediation="test",
        mappings={},
        details={},
        created_at=now,
        updated_at=now,
    )


def test_missing_scope_denies_validation_before_adb(tmp_path: Path) -> None:
    paths, repository, session_id = active_session(tmp_path)
    context = NoAdbContext(paths)

    with pytest.raises(ScopeError, match="outside config/scope.yaml"):
        ValidationService(
            context,  # type: ignore[arg-type]
            repository,
        ).validate(session_id, "finding-asl-mvp-002")

    assert context.adb_calls == 0


def test_out_of_scope_package_denies_traffic_before_adb(tmp_path: Path) -> None:
    paths, repository, session_id = active_session(tmp_path)
    paths.scope_file.write_text(
        "devices: [ABC123]\npackages: [com.other.app]\napi_hosts: []\n",
        encoding="utf-8",
    )
    context = NoAdbContext(paths)

    with pytest.raises(ScopeError, match="Package com.example.app"):
        TrafficCaptureService(
            context,  # type: ignore[arg-type]
            repository,
        ).start(session_id)

    assert context.adb_calls == 0


def test_manifest_host_is_not_implicitly_allowlisted(tmp_path: Path) -> None:
    paths, repository, session_id = active_session(tmp_path)
    paths.scope_file.write_text(
        "devices: [ABC123]\n"
        "packages: [com.example.app]\n"
        "api_hosts: [api.lab.local]\n",
        encoding="utf-8",
    )
    session_paths = repository.paths_for(session_id)
    write_json_atomic(
        session_paths.app_json,
        {
            "schema_version": 1,
            "package": "com.example.app",
            "manifest": {
                "deep_links": [
                    {
                        "scheme": "http",
                        "host": "outside.example",
                        "component": "com.example.app.DeepLinkActivity",
                    }
                ]
            },
        },
        root=paths.root,
    )
    FindingRepository(paths, repository).save(session_id, [cleartext_finding()])
    context = NoAdbContext(paths)

    with pytest.raises(ScopeError, match="outside.example"):
        ValidationService(
            context,  # type: ignore[arg-type]
            repository,
        ).validate(session_id, "finding-asl-mvp-002")

    assert context.adb_calls == 0


def test_scope_rejects_unapproved_url_scheme(tmp_path: Path) -> None:
    paths, _repository, _session_id = active_session(tmp_path)
    paths.scope_file.write_text(
        "devices: [ABC123]\n"
        "packages: [com.example.app]\n"
        "api_hosts: [api.lab.local]\n",
        encoding="utf-8",
    )

    with pytest.raises(ScopeError, match="scheme ftp"):
        load_scope(paths).require_url("ftp://api.lab.local/canary")
