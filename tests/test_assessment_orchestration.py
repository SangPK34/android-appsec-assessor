from __future__ import annotations

import json
from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

import pytest

from android_assessor.evidence import EvidenceRepository
from android_assessor.findings import FindingStatus
from android_assessor.paths import ProjectPaths
from android_assessor.redaction import redact_report_data
from android_assessor.report import (
    ReportService,
    _capability_used_by_security_findings,
    _environment_type,
    _is_aggregate_alias,
)
from android_assessor.rules import RuleEngine
from android_assessor.services.scan_service import ScanProfile, ScanService
from android_assessor.session import SessionRepository
from android_assessor.storage import read_json_object, write_json_atomic


def _rule_session(tmp_path: Path) -> tuple[ProjectPaths, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    (paths.root / "rules").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "rules" / "mvp.yaml",
        paths.root / "rules" / "mvp.yaml",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="emulator-5554", package="com.example.app")
    repository.activate(
        record.session_id,
        snapshot={},
        device={
            "device": {"model": "sdk_gphone_x86_64", "android_version": "11"},
            "capabilities": {"capabilities": [{"name": "ANDROID_ROOT", "available": True}]},
        },
        environment={"environment_type": "emulator"},
    )
    write_json_atomic(
        repository.paths_for(record.session_id).app_json,
        {
            "package": record.package,
            "manifest": {
                "debuggable": False,
                "test_only": False,
                "allow_backup": False,
                "uses_cleartext_traffic": False,
                "network_security_config": None,
                "components": [],
            },
        },
        root=paths.root,
    )
    return paths, repository, record.session_id


def test_profiles_are_explicit_and_rule_catalog_is_extended() -> None:
    assert ScanProfile.parse("quick") is ScanProfile.QUICK
    assert ScanProfile.parse("FULL") is ScanProfile.FULL
    assert len(__import__("yaml").safe_load(Path("rules/mvp.yaml").read_text())["rules"]) >= 10


@pytest.mark.parametrize(
    ("profile", "expected_dynamic_calls"),
    [(ScanProfile.QUICK, []), (ScanProfile.FULL, ["traffic", "frida", "storage"])],
)
def test_scan_profile_starts_only_planned_controllers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: ScanProfile,
    expected_dynamic_calls: list[str],
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    repository = SessionRepository(paths)
    record = repository.initialize(serial="emulator-5554", package="com.example.app")
    repository.activate(record.session_id, snapshot={}, device={}, environment={})
    calls: list[str] = []

    class Adb:
        def force_stop_package(self, _serial: str, _package: str) -> None:
            pass

        def launch_package(self, _serial: str, _package: str) -> None:
            pass

    class Context:
        def __init__(self) -> None:
            self.paths = paths

        def adb_client(self, **_kwargs: object) -> Adb:
            return Adb()

    class Traffic:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def start(self, *_args: object, **_kwargs: object) -> None:
            calls.append("traffic")

        def stop(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(status="stopped")

    class Frida(Traffic):
        def start(self, *_args: object, **_kwargs: object) -> None:
            calls.append("frida")

    class Storage:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(self, *_args: object, **_kwargs: object) -> None:
            calls.append("storage")

    class Logcat:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(status="completed", error=None)

    class Rules:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def evaluate(self, *_args: object) -> list[object]:
            return []

    class Report:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def generate(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            return {}

    monkeypatch.setattr("android_assessor.services.scan_service.TrafficCaptureService", Traffic)
    monkeypatch.setattr("android_assessor.services.scan_service.FridaController", Frida)
    monkeypatch.setattr("android_assessor.services.scan_service.PrivateStorageService", Storage)
    monkeypatch.setattr("android_assessor.services.scan_service.AdbPrivateStorageBackend", Traffic)
    monkeypatch.setattr("android_assessor.services.scan_service.LogcatCollector", Logcat)
    monkeypatch.setattr("android_assessor.services.scan_service.RuleEngine", Rules)
    monkeypatch.setattr("android_assessor.services.scan_service.ReportService", Report)

    result = ScanService(Context(), repository)._scan_session_locked(  # type: ignore[arg-type]
        repository.load(record.session_id),
        profile=profile,
        runtime_seconds=0,
    )

    assert calls == expected_dynamic_calls
    assert result.profile == profile.value
    assert "rule_evaluation" in result.phase_timings
    scan = read_json_object(repository.paths_for(record.session_id).scan_json, root=paths.root)
    assert scan["runtime_termination"] in {"completed_no_wait", "not_started"}
    assert "runtime_analysis" in result.phase_timings


def test_crypto_analyzer_output_is_consumed_by_rule_engine(tmp_path: Path) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    event = {
        "category": "crypto",
        "method": "cipher.do_final",
        "arguments_redacted": [{
            "operation_id": "pivaa-crypto-1",
            "transformation": "AES/ECB/PKCS5Padding",
            "purpose": "encrypt",
            "executed": True,
            "canary_match": False,
            "key_length_bits": 128,
            "iv_sha256": "<redacted>",
            "iv_source": "none",
            "key_origin": "generated",
        }],
    }
    event_path = session_paths.frida_dir / "events.jsonl"
    event_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    previous_path = session_paths.redacted_dir / "frida" / "previous.jsonl"
    previous_path.parent.mkdir(parents=True, exist_ok=True)
    previous_path.write_text(
        json.dumps(
            {
                "category": "webview",
                "method": "webview.load_url",
                "arguments_redacted": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    EvidenceRepository(paths, repository).register_file(
        session_id,
        previous_path,
        evidence_type="frida_events",
        source="frida_observer",
        description="Prior normalized observer phase.",
        sensitive=True,
        redacted=True,
    )
    write_json_atomic(
        session_paths.frida_dir / "state.json",
        {"events_path": "frida/events.jsonl", "server_started_by_framework": True},
        root=paths.root,
    )

    findings = {item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)}

    assert findings["CRYPTO-ECB"].status is FindingStatus.CONFIRMED
    assert findings["CRYPTO-ECB"].details["operation_ids"] == ["pivaa-crypto-1"]
    assert findings["ASL-RUNTIME-WEBVIEW"].status is FindingStatus.PASS


def test_emulator_environment_is_not_reported_as_physical_device() -> None:
    assert _environment_type(
        "emulator-5554",
        {"device": {"model": "sdk_gphone"}},
        "physical",
    ) == "emulator"
    assert _environment_type(
        "USB123",
        {"device": {"model": "Pixel"}},
        "physical",
    ) == "physical_device"
    assert redact_report_data(
        {"root_used_in_session": True, "frida_used_in_session": True}
    ) == {"root_used_in_session": True, "frida_used_in_session": True}


def test_observation_only_capabilities_are_not_security_finding_usage() -> None:
    findings = [
        {"root_used": True, "frida_used": True, "details": {"observation_only": True}},
        {"root_used": False, "frida_used": True, "details": {}},
    ]
    assert _capability_used_by_security_findings(findings, "root_used") is False
    assert _capability_used_by_security_findings(findings, "frida_used") is True
    assert redact_report_data(
        {"root_used_in_session": True, "frida_used_in_session": True}
    ) == {"root_used_in_session": True, "frida_used_in_session": True}


def test_report_summary_separates_security_checks_and_runtime_observations(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    (paths.root / "templates").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "templates" / "report.html.j2",
        paths.root / "templates" / "report.html.j2",
    )
    RuleEngine(paths, repository).evaluate(session_id)
    report = ReportService(paths, repository).generate(session_id)
    summary = report["summary"]
    assert summary["total_checks_executed"] == (
        summary["security_rules_evaluated"] + summary["runtime_checks_executed"]
    )
    assert summary["security_findings_total"] == sum(
        1
        for item in report["findings"]
        if item["status"] in {"confirmed", "potential"}
    )
    assert all(item["rule_id"].startswith("ASL-RUNTIME-") is False for item in report["findings"])
    assert all(item["observation_status"] in {
        "observed", "not_observed", "insufficient_activity", "skipped", "error"
    } for item in report["runtime_checks"])


def test_runtime_stop_request_is_idempotent_marker(tmp_path: Path) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    write_json_atomic(
        repository.paths_for(session_id).scan_json,
        {"profile": "full", "status": "running"},
        root=paths.root,
    )
    service = ScanService(SimpleNamespace(paths=paths), repository)  # type: ignore[arg-type]
    assert service.request_runtime_stop(session_id)["stop_requested"] is True
    assert service.request_runtime_stop(session_id)["stop_requested"] is True
    assert read_json_object(
        repository.paths_for(session_id).runtime_control_json,
        root=paths.root,
    )["stop_requested"] is True
    repository.paths_for(session_id).runtime_control_json.write_text(
        '{"stop_requested": true}', encoding="utf-8-sig"
    )
    assert service._runtime_stop_requested(session_id) is True


def test_exported_component_aggregate_is_suppressed_when_specific_rules_run() -> None:
    rule_ids = {
        "ASL-MVP-004",
        "ASL-MANIFEST-EXPORTED-ACTIVITY",
        "ASL-MANIFEST-EXPORTED-RECEIVER",
    }
    assert _is_aggregate_alias({"rule_id": "ASL-MVP-004"}, rule_ids) is True
    assert _is_aggregate_alias({"rule_id": "ASL-MVP-004"}, {"ASL-MVP-004"}) is False
