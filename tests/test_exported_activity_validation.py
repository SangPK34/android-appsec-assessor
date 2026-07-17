from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from android_assessor.evidence import EvidenceRepository
from android_assessor.findings import FindingRecord, FindingRepository, FindingStatus
from android_assessor.paths import ProjectPaths
from android_assessor.services.validation_service import ValidationService
from android_assessor.session import SessionRepository
from android_assessor.subprocess_utils import CommandResult


def command_result() -> CommandResult:
    return CommandResult(
        arguments=(),
        exit_code=0,
        stdout="Status: ok\nComplete\n",
        stderr="",
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=False,
    )


class ActivityAdb:
    def __init__(self) -> None:
        self.launches = 0

    def start_activity(self, *_args: object, **_kwargs: object) -> CommandResult:
        self.launches += 1
        return command_result()


class Context:
    def __init__(self, paths: ProjectPaths, adb: ActivityAdb) -> None:
        self.paths = paths
        self.adb = adb

    def adb_client(self, **_kwargs: object) -> ActivityAdb:
        return self.adb


def exported_finding() -> FindingRecord:
    now = datetime.now(UTC).isoformat()
    return FindingRecord(
        finding_id="finding-asl-mvp-004",
        rule_id="ASL-MVP-004",
        title="Exported component",
        category="platform",
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
        details={
            "unprotected_exported_components": [
                {
                    "component_type": "activity",
                    "name": "com.example.app.ExportedActivity",
                }
            ],
            "validation_observable": "Target logcat contains the exact canary.",
        },
        created_at=now,
        updated_at=now,
    )


@pytest.mark.parametrize(
    ("observed", "expected"),
    [
        (False, FindingStatus.POTENTIAL),
        (True, FindingStatus.CONFIRMED),
    ],
)
def test_exported_activity_requires_observable_canary_impact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observed: bool,
    expected: FindingStatus,
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        "devices: [ABC123]\npackages: [com.example.app]\napi_hosts: []\n"
        "allowed_actions: [controlled_validation]\n",
        encoding="utf-8",
    )
    repository = SessionRepository(paths)
    session = repository.initialize(serial="ABC123", package="com.example.app")
    repository.activate(
        session.session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURED_EMPTY",
            "http_proxy_error": None,
        },
        device={},
        environment={},
    )
    FindingRepository(paths, repository).save(session.session_id, [exported_finding()])
    evidence_id: str | None = None
    if observed:
        log = repository.paths_for(session.session_id).logcat_dir / "canary.log"
        log.write_text("controlled canary evidence\n", encoding="utf-8")
        evidence_id = EvidenceRepository(paths, repository).register_file(
            session.session_id,
            log,
            evidence_type="target_logcat",
            source="test",
            description="Controlled target logcat evidence.",
            sensitive=False,
            redacted=False,
        ).evidence_id

    class Collector:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(
                canary_observed=observed,
                evidence_id=evidence_id,
            )

    monkeypatch.setattr(
        "android_assessor.services.validation_service.LogcatCollector",
        Collector,
    )
    monkeypatch.setattr(
        "android_assessor.services.validation_service.time.sleep",
        lambda _seconds: None,
    )
    monkeypatch.setattr(
        "android_assessor.services.validation_service.ReportService.generate",
        lambda *_args, **_kwargs: None,
    )
    adb = ActivityAdb()

    updated = ValidationService(
        Context(paths, adb),  # type: ignore[arg-type]
        repository,
    ).validate(session.session_id, "finding-asl-mvp-004")

    assert adb.launches == 1
    assert updated.status is expected
    assert updated.validation is not None
    assert updated.validation.status is expected
    if observed:
        assert evidence_id in updated.validation.evidence_ids
    else:
        assert "no defined canary impact" in updated.validation.summary
