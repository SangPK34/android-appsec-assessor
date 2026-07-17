from __future__ import annotations

import json
from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

import pytest

from android_assessor.evidence import EvidenceRepository
from android_assessor.explorer import ExplorerConfig
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
from android_assessor.services.scan_service import (
    ScanProfile,
    ScanProfileResolution,
    ScanResult,
    ScanService,
    resolve_scan_profile,
)
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


def test_profile_resolution_preserves_direct_api_compatibility() -> None:
    omitted = resolve_scan_profile(None)
    quick = resolve_scan_profile("quick", autonomous=True)
    full = resolve_scan_profile("full", autonomous=True)

    assert omitted.requested_profile is None
    assert omitted.effective_profile is ScanProfile.FULL
    assert omitted.autonomous_exploration_requested is False
    assert omitted.autonomous_exploration_enabled is False
    assert quick.effective_profile is ScanProfile.QUICK
    assert quick.autonomous_exploration_requested is True
    assert quick.autonomous_exploration_enabled is False
    assert full.effective_profile is ScanProfile.FULL
    assert full.autonomous_exploration_enabled is True
    assert ScanService.scan.__kwdefaults__["profile"] is ScanProfile.QUICK
    assert ScanService.scan_session.__kwdefaults__["profile"] is None


def test_direct_scan_uses_legacy_quick_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    service = ScanService(SimpleNamespace(paths=paths))  # type: ignore[arg-type]
    captured: dict[str, object] = {}

    class Inspection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def inspect(self, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(session_id="20260717-210000-abcdef")

    def fake_scan_session(_session_id: str, **kwargs: object) -> str:
        captured.update(kwargs)
        return "quick"

    monkeypatch.setattr(
        "android_assessor.services.scan_service.AppInspectionService",
        Inspection,
    )
    monkeypatch.setattr(service, "scan_session", fake_scan_session)

    assert service.scan(package="com.example.app", serial="FAKE_SERIAL") == "quick"
    assert captured["profile"] is ScanProfile.QUICK
    assert captured["autonomous"] is None
    assert captured["explorer_config"] is None


def test_direct_scan_session_uses_legacy_profile_without_autonomous(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    captured: dict[str, object] = {}
    service = ScanService(SimpleNamespace(paths=paths), repository)  # type: ignore[arg-type]

    class Scope:
        def require_device_package(self, _serial: str, _package: str) -> None:
            pass

    def fake_locked(_record: object, **kwargs: object) -> str:
        captured.update(kwargs)
        return "legacy"

    monkeypatch.setattr("android_assessor.services.scan_service.load_scope", lambda _paths: Scope())
    monkeypatch.setattr(service, "_scan_session_locked", fake_locked)
    monkeypatch.setattr(service, "_finalize_full_assessment", lambda result: result)

    assert service.scan_session(session_id) == "legacy"
    resolution = captured["resolution"]
    assert isinstance(resolution, ScanProfileResolution)
    assert resolution.effective_profile is ScanProfile.FULL
    assert resolution.autonomous_exploration_enabled is False


def test_full_assessment_finalization_cleans_session_and_regenerates_final_report(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    (paths.root / "templates").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "templates" / "report.html.j2",
        paths.root / "templates" / "report.html.j2",
    )
    session_paths = repository.paths_for(session_id)
    write_json_atomic(
        session_paths.scan_json,
        {
            "profile": "full",
            "status": "completed",
            "dynamic_steps": {"report": "completed", "cleanup": "pending"},
            "limitations": [],
        },
        root=paths.root,
    )

    class Context:
        def __init__(self) -> None:
            self.paths = paths

        def adb_client(self, **_kwargs: object) -> object:
            return object()

    result = ScanResult(
        session_id=session_id,
        findings=(),
        limitations=(),
        dynamic_steps={"report": "completed", "cleanup": "pending"},
        report_path="report.html",
        profile="full",
        effective_profile="full",
    )
    finalized = ScanService(Context(), repository)._finalize_full_assessment(result)  # type: ignore[arg-type]

    report = read_json_object(session_paths.report_json, root=paths.root)
    assert finalized.dynamic_steps["cleanup"] == "completed"
    assert repository.load(session_id).cleanup_success is True
    assert report["report_state"] == "final"
    assert report["cleanup"] == {"status": "cleaned", "success": True, "pending": False}


def test_full_assessment_exception_still_runs_owned_resource_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    service = ScanService(SimpleNamespace(paths=paths), repository)  # type: ignore[arg-type]
    cleanup_calls: list[str] = []

    class Scope:
        def require_device_package(self, _serial: str, _package: str) -> None:
            pass

    class Cleanup:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def cleanup(self, current_session_id: str) -> SimpleNamespace:
            cleanup_calls.append(current_session_id)
            return SimpleNamespace(success=True)

    monkeypatch.setattr("android_assessor.services.scan_service.load_scope", lambda _paths: Scope())
    monkeypatch.setattr("android_assessor.services.scan_service.CleanupService", Cleanup)
    monkeypatch.setattr(
        "android_assessor.services.scan_service.ReportService.generate",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        service,
        "_scan_session_locked",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("scan failed")),
    )

    with pytest.raises(RuntimeError, match="scan failed"):
        service.scan_session(session_id, profile="full")

    assert cleanup_calls == [session_id]
    scan = read_json_object(repository.paths_for(session_id).scan_json, root=paths.root)
    assert scan["status"] == "error"
    assert scan["cleanup_success"] is True
    assert scan["dynamic_steps"]["cleanup"] == "completed"


@pytest.mark.parametrize(
    ("profile", "traffic_fails", "expected_dynamic_calls"),
    [
        (ScanProfile.QUICK, False, []),
        (ScanProfile.FULL, False, ["traffic", "frida", "explorer", "storage"]),
        (ScanProfile.FULL, True, ["traffic", "storage"]),
    ],
)
def test_scan_profile_starts_only_planned_controllers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: ScanProfile,
    traffic_fails: bool,
    expected_dynamic_calls: list[str],
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        "devices: [FAKE_SERIAL]\n"
        "packages: [com.example.app]\n"
        "api_hosts: [10.0.2.2]\n"
        "allowed_actions: [inspect, traffic_capture, frida_observe, "
        "controlled_validation]\n",
        encoding="utf-8",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="FAKE_SERIAL", package="com.example.app")
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
            if traffic_fails:
                raise ValueError("synthetic traffic guard failure")

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

    class Explorer:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            calls.append("explorer")
            return SimpleNamespace(
                status="completed",
                termination_reason="coverage_plateau",
                runtime_categories=(),
                to_dict=lambda: {"status": "completed", "states_visited": 2},
            )

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
    monkeypatch.setattr("android_assessor.services.scan_service.ExplorerService", Explorer)
    monkeypatch.setattr("android_assessor.services.scan_service.RuleEngine", Rules)
    monkeypatch.setattr("android_assessor.services.scan_service.ReportService", Report)

    explorer_config = (
        ExplorerConfig(max_runtime_seconds=1) if profile is ScanProfile.FULL else None
    )
    result = ScanService(Context(), repository)._scan_session_locked(  # type: ignore[arg-type]
        repository.load(record.session_id),
        resolution=resolve_scan_profile(
            profile,
            autonomous=profile is ScanProfile.FULL,
            explorer_config=explorer_config,
        ),
        runtime_seconds=0,
        explorer_config=explorer_config,
    )

    assert calls == expected_dynamic_calls
    assert result.profile == profile.value
    assert "rule_evaluation" in result.phase_timings
    scan = read_json_object(repository.paths_for(record.session_id).scan_json, root=paths.root)
    assert scan["requested_profile"] == profile.value
    assert scan["effective_profile"] == profile.value
    assert scan["autonomous_exploration_requested"] is (profile is ScanProfile.FULL)
    assert scan["autonomous_exploration_executed"] is (
        profile is ScanProfile.FULL and not traffic_fails
    )
    assert scan["runtime_termination"] in {
        "coverage_plateau",
        "completed_no_wait",
        "not_started",
    }
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


@pytest.mark.parametrize(
    ("inventory_status", "candidates", "expected_status"),
    (
        ("completed", [], FindingStatus.PASS),
        ("partial", [], FindingStatus.INCONCLUSIVE),
        (
            "completed",
            [
                {
                    "kind": "contextual_secret",
                    "confidence": "medium",
                    "source_id": "base:0",
                    "location": "assets/config.properties:line:4",
                    "key_name": "client_secret",
                    "value_sha256": "a" * 64,
                    "value_length": 32,
                }
            ],
            FindingStatus.POTENTIAL,
        ),
    ),
)
def test_static_secret_inventory_is_consumed_without_confirming_presence_only(
    tmp_path: Path,
    inventory_status: str,
    candidates: list[dict[str, object]],
    expected_status: FindingStatus,
) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    app = read_json_object(session_paths.app_json, root=paths.root)
    app["static_analysis"] = {
        "schema_version": 1,
        "status": inventory_status,
        "secret_candidates": candidates,
        "limitations": ["entry_budget"] if inventory_status == "partial" else [],
    }
    write_json_atomic(session_paths.app_json, app, root=paths.root)
    inventory_path = session_paths.redacted_dir / "static" / "inventory.json"
    write_json_atomic(
        inventory_path,
        app["static_analysis"],
        root=paths.root,
    )
    evidence = EvidenceRepository(paths, repository).register_file(
        session_id,
        inventory_path,
        evidence_type="static_apk_inventory",
        source="bounded_apk_static_analysis",
        description="Redacted static inventory fixture.",
        sensitive=False,
        redacted=True,
    )

    finding = next(
        item
        for item in RuleEngine(paths, repository).evaluate(session_id)
        if item.rule_id == "ASL-STATIC-HARDCODED-SECRET"
    )

    assert finding.status is expected_status
    assert finding.status is not FindingStatus.CONFIRMED
    assert finding.evidence_ids == (evidence.evidence_id,)
    serialized = json.dumps(finding.to_dict()).casefold()
    assert "raw_value" not in serialized
    assert "client-secret-material" not in serialized


def test_phase_one_manifest_rules_are_wired_with_specific_evidence(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    app = read_json_object(session_paths.app_json, root=paths.root)
    app["manifest"] = {
        "debuggable": False,
        "test_only": False,
        "allow_backup": False,
        "uses_cleartext_traffic": False,
        "network_security_config": None,
        "application_permission": None,
        "custom_permissions": [
            {
                "name": "com.example.app.CALL_INTERNAL",
                "protection_level": "normal",
            }
        ],
        "components": [
            {
                "component_type": "service",
                "name": "com.example.app.SyncService",
                "effective_exported": True,
                "enabled": True,
                "permission": None,
                "intent_filters": [],
            },
            {
                "component_type": "activity",
                "name": "com.example.app.LinkActivity",
                "effective_exported": True,
                "enabled": True,
                "permission": None,
                "intent_filters": [],
            },
        ],
        "deep_links": [
            {
                "component": "com.example.app.LinkActivity",
                "component_effective_exported": True,
                "scheme": "example",
                "host": None,
                "path": None,
            }
        ],
        "deep_links_truncated": False,
        "file_provider_paths": [
            {
                "provider": "com.example.app.ShareProvider",
                "authorities": "com.example.app.files",
                "grant_uri_permissions": True,
                "resource_reference": "@xml/share_paths",
                "resource_path": "res/xml/share_paths.xml",
                "resolution_status": "resolved",
                "entries": [
                    {"kind": "root-path", "name": "root", "path": "."}
                ],
            }
        ],
    }
    write_json_atomic(session_paths.app_json, app, root=paths.root)
    manifest_path = session_paths.redacted_dir / "manifest" / "manifest.txt"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("redacted manifest fixture", encoding="utf-8")
    resource_path = session_paths.redacted_dir / "manifest" / "share-paths.txt"
    resource_path.write_text("redacted FileProvider path fixture", encoding="utf-8")
    evidence = EvidenceRepository(paths, repository)
    manifest_evidence = evidence.register_file(
        session_id,
        manifest_path,
        evidence_type="manifest_tree",
        source="aapt2_dump_xmltree",
        description="Redacted manifest fixture.",
        sensitive=True,
        redacted=True,
    )
    resource_evidence = evidence.register_file(
        session_id,
        resource_path,
        evidence_type="manifest_resource_xml",
        source="aapt2_dump_xmltree",
        description="Redacted manifest resource fixture.",
        sensitive=True,
        redacted=True,
    )

    findings = {
        item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)
    }

    for rule_id in (
        "ASL-MANIFEST-EXPORTED-SERVICE",
        "ASL-MANIFEST-CUSTOM-PERMISSION",
        "ASL-MANIFEST-FILEPROVIDER-PATHS",
        "ASL-MANIFEST-DEEP-LINK-EXPOSURE",
    ):
        assert findings[rule_id].status is FindingStatus.POTENTIAL
        assert findings[rule_id].status is not FindingStatus.CONFIRMED
        assert findings[rule_id].details["method"] == "normalized_manifest_policy"
        assert findings[rule_id].details["missing_evidence"]
    assert findings["ASL-MANIFEST-EXPORTED-SERVICE"].evidence_ids == (
        manifest_evidence.evidence_id,
    )
    assert findings["ASL-MANIFEST-FILEPROVIDER-PATHS"].evidence_ids == (
        manifest_evidence.evidence_id,
        resource_evidence.evidence_id,
    )


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


def test_report_module_coverage_registers_explorer_without_double_counting_runtime(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    write_json_atomic(
        session_paths.scan_json,
        {
            "profile": "full",
            "dynamic_steps": {"autonomous_exploration": "completed"},
            "phase_timings": {
                "exploration": 2500,
                "runtime_interaction": 2500,
                "runtime_analysis": 100,
            },
            "autonomous_exploration": {"actions_executed": 7},
        },
        root=paths.root,
    )
    (paths.root / "templates").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "templates" / "report.html.j2",
        paths.root / "templates" / "report.html.j2",
    )
    report = ReportService(paths, repository).generate(session_id)
    explorer = next(
        item
        for item in report["module_execution_coverage"]
        if item["module"] == "autonomous_exploration"
    )
    assert explorer["executed"] is True
    assert explorer["event_item_count"] == 7
    assert report["summary"]["sum_of_module_durations_ms"] < 5200


@pytest.mark.parametrize(
    ("profile", "step", "expected_planned", "expected_result"),
    [
        ("quick", "skipped", False, "not_planned"),
        ("full", "error", True, "error"),
    ],
)
def test_report_explorer_coverage_respects_profile_and_failure(
    tmp_path: Path,
    profile: str,
    step: str,
    expected_planned: bool,
    expected_result: str,
) -> None:
    paths, repository, session_id = _rule_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    write_json_atomic(
        session_paths.scan_json,
        {
            "profile": profile,
            "dynamic_steps": {"autonomous_exploration": step},
            "phase_timings": {"exploration": 100} if step == "error" else {},
            "limitations": ["Autonomous exploration failed: bounded test error."],
        },
        root=paths.root,
    )
    (paths.root / "templates").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "templates" / "report.html.j2",
        paths.root / "templates" / "report.html.j2",
    )

    report = ReportService(paths, repository).generate(session_id)
    explorer = next(
        item
        for item in report["module_execution_coverage"]
        if item["module"] == "autonomous_exploration"
    )
    assert explorer["planned"] is expected_planned
    assert explorer["result"] == expected_result


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
    conclusive = {
        "ASL-MVP-004": "potential",
        "ASL-MANIFEST-EXPORTED-ACTIVITY": "pass",
        "ASL-MANIFEST-EXPORTED-SERVICE": "pass",
        "ASL-MANIFEST-EXPORTED-RECEIVER": "potential",
        "ASL-MANIFEST-EXPORTED-PROVIDER": "pass",
    }
    assert _is_aggregate_alias({"rule_id": "ASL-MVP-004"}, conclusive) is True
    assert _is_aggregate_alias(
        {"rule_id": "ASL-MVP-004"},
        {**conclusive, "ASL-MANIFEST-EXPORTED-SERVICE": "inconclusive"},
    ) is False
    assert _is_aggregate_alias(
        {"rule_id": "ASL-MVP-004"},
        {"ASL-MVP-004": "potential"},
    ) is False
