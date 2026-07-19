from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from shutil import copyfile
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


class StorageAdb:
    def __init__(self) -> None:
        self.broadcasts = 0

    def shell(self, *_args: object, **_kwargs: object) -> CommandResult:
        self.broadcasts += 1
        return CommandResult(
            arguments=(),
            exit_code=0,
            stdout="Broadcast completed: result=0\n",
            stderr="",
            started_at="2026-07-17T00:00:00+00:00",
            duration_ms=1,
            timed_out=False,
        )


class Context:
    def __init__(self, paths: ProjectPaths, adb: object) -> None:
        self.paths = paths
        self.adb = adb

    def adb_client(self, **_kwargs: object) -> object:
        return self.adb


def exported_finding() -> FindingRecord:
    now = datetime.now(UTC).isoformat()
    return FindingRecord(
        finding_id="finding-asl-ipc-exported-component",
        rule_id="ASL-IPC-EXPORTED-COMPONENT",
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


def storage_finding() -> FindingRecord:
    now = datetime.now(UTC).isoformat()
    return FindingRecord(
        finding_id="finding-storage-world-readable",
        rule_id="STORAGE-WORLD-READABLE",
        title="World-readable storage",
        category="data-storage",
        description="test",
        severity="medium",
        confidence="high",
        status=FindingStatus.POTENTIAL,
        analysis_type="static",
        root_required=True,
        root_used=False,
        frida_used=False,
        validation_supported=True,
        validation=None,
        evidence_ids=(),
        remediation="test",
        mappings={},
        details={
            "static_behavior_candidates": [
                {
                    "rule_id": "STORAGE-WORLD-READABLE",
                    "confidence": "high",
                    "source_id": "base:0",
                    "dex_entry": "classes.dex",
                    "caller_class_descriptor": (
                        "Lcom/example/app/StorageReceiver;"
                    ),
                    "caller_method_name": "onReceive",
                    "caller_prototype": (
                        "(Landroid/content/Context;Landroid/content/Intent;)V"
                    ),
                    "indicators": [
                        "storage_api:getSharedPreferences",
                        "storage_mode:world_readable",
                    ],
                }
            ],
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
    rule_evaluations: list[str] = []

    class Rules:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def evaluate(self, evaluated_session: str) -> list[object]:
            rule_evaluations.append(evaluated_session)
            return []

    monkeypatch.setattr(
        "android_assessor.services.validation_service.RuleEngine",
        Rules,
    )
    adb = ActivityAdb()

    updated = ValidationService(
        Context(paths, adb),  # type: ignore[arg-type]
        repository,
    ).validate(session.session_id, "finding-asl-ipc-exported-component")

    assert adb.launches == 1
    assert updated.status is expected
    assert updated.validation is not None
    assert updated.validation.status is expected
    assert rule_evaluations == [session.session_id]
    if observed:
        assert evidence_id in updated.validation.evidence_ids
    else:
        assert "no defined canary impact" in updated.validation.summary


@pytest.mark.parametrize(
    ("observed", "expected"),
    [
        (False, FindingStatus.PASS),
        (True, FindingStatus.CONFIRMED),
    ],
)
def test_world_readable_storage_receiver_validation_re_evaluates_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observed: bool,
    expected: FindingStatus,
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    (paths.root / "rules").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "rules" / "core.yaml",
        paths.root / "rules" / "core.yaml",
    )
    paths.scope_file.write_text(
        "devices: [ABC123]\npackages: [com.example.app]\napi_hosts: []\n"
        "allowed_actions: [controlled_validation, root_storage_read]\n",
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
    session_paths = repository.paths_for(session.session_id)
    write_app = {
        "package": "com.example.app",
        "manifest": {
            "debuggable": False,
            "test_only": False,
            "uses_cleartext_traffic": False,
            "network_security_config": None,
            "components": [
                {
                    "component_type": "receiver",
                    "name": "com.example.app.StorageReceiver",
                    "effective_exported": True,
                    "permission": None,
                    "intent_filters": [
                        {
                            "actions": ["com.example.app.STORAGE_PROBE"],
                        }
                    ],
                }
            ],
        },
        "static_analysis": {
            "status": "completed",
            "security_api_candidates": [],
            "static_behavior_candidates": storage_finding().details[
                "static_behavior_candidates"
            ],
        },
    }
    (session_paths.app_json).write_text(
        json.dumps(write_app),
        encoding="utf-8",
    )
    EvidenceRepository(paths, repository).register_file(
        session.session_id,
        session_paths.app_json,
        evidence_type="static_apk_inventory",
        source="fixture",
        description="Static inventory fixture.",
        sensitive=False,
        redacted=True,
    )
    FindingRepository(paths, repository).save(session.session_id, [storage_finding()])

    class StorageCollector:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(self, session_id: str, **_kwargs: object) -> SimpleNamespace:
            output = (
                repository.paths_for(session_id).redacted_dir
                / "storage"
                / "private-storage.json"
            )
            observations = (
                [
                    {
                        "observation_id": "storage-world-readable",
                        "status": "confirmed",
                        "finding_eligible": True,
                        "artifact_paths": ["shared_prefs/public.xml"],
                        "rationale": (
                            "A package-owned file grants read access to other UIDs."
                        ),
                    }
                ]
                if observed
                else []
            )
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(
                    {
                        "root_mode": "adb_root",
                        "inventory_status": "completed",
                        "inventory_limitations": [],
                        "content_scan_status": "completed",
                        "content_scan_limitations": [],
                        "observations": observations,
                    }
                ),
                encoding="utf-8",
            )
            EvidenceRepository(paths, repository).register_file(
                session_id,
                output,
                evidence_type="private_storage_metadata",
                source="fixture",
                description="Storage fixture.",
                sensitive=True,
                redacted=True,
            )
            return SimpleNamespace(
                observations=tuple(
                    SimpleNamespace(
                        observation_id=item["observation_id"],
                        finding_eligible=item["finding_eligible"],
                    )
                    for item in observations
                ),
                inventory_status="completed",
                inventory_limitations=(),
            )

    monkeypatch.setattr(
        "android_assessor.services.validation_service.PrivateStorageService",
        StorageCollector,
    )
    monkeypatch.setattr(
        "android_assessor.services.validation_service.ReportService.generate",
        lambda *_args, **_kwargs: None,
    )
    adb = StorageAdb()

    updated = ValidationService(
        Context(paths, adb),  # type: ignore[arg-type]
        repository,
    ).validate(session.session_id, "finding-storage-world-readable")

    assert adb.broadcasts == 1
    assert updated.status is expected
    assert updated.validation is not None
    assert updated.validation.status is expected
    assert any(
        item.get("source") == "adb_am_broadcast"
        for item in EvidenceRepository(paths, repository).list(session.session_id)
    )
    if expected is FindingStatus.PASS:
        assert updated.details["static_behavior_outcome"] == (
            "candidate_scoped_rejected"
        )
        assert updated.validation.candidate_key
        assert updated.validation.candidate_context == {
            "candidate_key": updated.validation.candidate_key,
            "caller_class_descriptor": "Lcom/example/app/StorageReceiver;",
            "caller_method_name": "onReceive",
            "component": "com.example.app.StorageReceiver",
            "action": "com.example.app.STORAGE_PROBE",
            "route": "explicit_receiver_broadcast",
            "route_reached": True,
        }
