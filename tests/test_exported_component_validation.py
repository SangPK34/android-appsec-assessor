from __future__ import annotations

import json
from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

import pytest

from android_assessor.evidence import EvidenceRepository
from android_assessor.exported_component_validation import (
    ExportedComponentValidationService,
    IpcRouteOutcome,
    build_ipc_candidates,
)
from android_assessor.findings import FindingStatus
from android_assessor.paths import ProjectPaths
from android_assessor.rules import RuleEngine
from android_assessor.session import SessionRepository
from android_assessor.storage import write_json_atomic
from android_assessor.subprocess_utils import CommandResult

PACKAGE = "com.example.ipclab"
SERIAL = "FIXTURE_SERIAL"


def _result(
    arguments: tuple[str, ...],
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
) -> CommandResult:
    return CommandResult(
        arguments=arguments,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at="2026-07-19T00:00:00+00:00",
        duration_ms=1,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        output_limit_stream="stdout" if output_limit_exceeded else None,
    )


class ScriptedIpcAdb:
    def __init__(self, *, activity_impact: bool = True, mode: str = "positive") -> None:
        self.activity_impact = activity_impact
        self.mode = mode
        self.canary: str | None = None
        self.calls: list[tuple[str, ...]] = []
        self.resumed = f"{PACKAGE}/com.example.ipclab.HomeActivity"

    def start_activity(
        self,
        _serial: str,
        _package: str,
        component: str,
        *,
        canary: str,
    ) -> CommandResult:
        self.canary = canary
        self.calls.append(("am", "start", component))
        if self.mode == "activity_denied":
            return _result(("am", "start"), stderr="Permission Denial: protected")
        if self.mode == "activity_timeout":
            return _result(("am", "start"), timed_out=True, exit_code=-1)
        if self.mode == "activity_escape":
            self.resumed = "com.other.app/OtherActivity"
            return _result(("am", "start"), stdout="Status: ok\nComplete\n")
        if self.activity_impact:
            self.resumed = f"{PACKAGE}/{component}"
        return _result(("am", "start"), stdout="Status: ok\nComplete\n")

    def shell_bounded(
        self,
        _serial: str,
        arguments: tuple[str, ...],
        *,
        timeout: float = 8,
        max_stdout_bytes: int = 65536,
        max_stderr_bytes: int = 16384,
        check: bool = False,
        operation: str = "",
        sensitive_values: tuple[str, ...] = (),
    ) -> CommandResult:
        del timeout, max_stdout_bytes, max_stderr_bytes, check, operation, sensitive_values
        self.calls.append(tuple(arguments))
        if arguments[:2] == ("dumpsys", "activity"):
            return _result(arguments, stdout=f"mResumedActivity= {self.resumed}\n")
        if arguments[:1] == ("pidof",):
            return _result(arguments, stdout="4242\n")
        if arguments[:1] == ("logcat",):
            output = self.canary if self.mode in {"positive", "receiver_positive"} else ""
            return _result(arguments, stdout=output or "no target marker\n")
        if arguments[:2] == ("input", "keyevent"):
            self.resumed = f"{PACKAGE}/com.example.ipclab.HomeActivity"
            return _result(arguments)
        if arguments[:2] == ("am", "broadcast"):
            if self.mode == "receiver_denied":
                return _result(arguments, stderr="SecurityException: requires permission")
            self.canary = arguments[-1]
            return _result(arguments, stdout="Broadcast completed: result=0\n")
        if arguments[:2] == ("content", "query") or arguments[:4] == (
            "su",
            "2000",
            "content",
            "query",
        ):
            if self.mode == "provider_denied":
                return _result(arguments, stderr="Permission Denial")
            if self.mode == "provider_zero":
                return _result(arguments, stdout="No result found.\n")
            if self.mode == "provider_unknown":
                return _result(arguments, stderr="Unknown URI")
            if self.mode == "provider_limit":
                return _result(arguments, output_limit_exceeded=True)
            return _result(arguments, stdout="Row: 0 secret_value=FIXTURE_SECRET\n")
        if arguments[:2] == ("su", "2000") and arguments[2:] == ("id", "-u"):
            return _result(arguments, stdout="2000\n")
        if arguments == ("id", "-u"):
            return _result(arguments, stdout="2000\n")
        return _result(arguments)


def _manifest(*, protected: bool = False) -> dict[str, object]:
    permission = "com.example.ipclab.SIGNATURE" if protected else None
    return {
        "application_permission": permission,
        "custom_permissions": (
            [{"name": permission, "protection_level": "signature"}]
            if permission
            else []
        ),
        "components": [
            {
                "component_type": "activity",
                "name": f"{PACKAGE}.PublicActivity",
                "effective_exported": True,
                "enabled": True,
                "permission": permission,
                "intent_filters": [],
            },
            {
                "component_type": "receiver",
                "name": f"{PACKAGE}.ProbeReceiver",
                "effective_exported": True,
                "enabled": True,
                "permission": permission,
                "intent_filters": [{"actions": [f"{PACKAGE}.PROBE"]}],
            },
            {
                "component_type": "provider",
                "name": f"{PACKAGE}.DataProvider",
                "effective_exported": True,
                "enabled": True,
                "permission": permission,
                "read_permission": permission,
                "authorities": f"{PACKAGE}.data",
                "intent_filters": [],
            },
        ],
    }


def _session(
    tmp_path: Path,
    manifest: dict[str, object],
) -> tuple[ProjectPaths, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        f"devices: [{SERIAL}]\npackages: [{PACKAGE}]\n"
        "allowed_actions: [controlled_validation]\n",
        encoding="utf-8",
    )
    (paths.root / "rules").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "rules" / "mvp.yaml",
        paths.root / "rules" / "mvp.yaml",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial=SERIAL, package=PACKAGE)
    write_json_atomic(
        repository.paths_for(record.session_id).app_json,
        {"package": PACKAGE, "manifest": manifest, "static_analysis": {"status": "completed"}},
        root=paths.root,
    )
    return paths, repository, record.session_id


def test_ipc_artifact_is_consumed_by_manifest_rules(tmp_path: Path) -> None:
    paths, repository, session_id = _session(tmp_path, _manifest())
    session_paths = repository.paths_for(session_id)
    manifest_path = session_paths.redacted_dir / "manifest" / "manifest.txt"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("normalized manifest fixture", encoding="utf-8")
    EvidenceRepository(paths, repository).register_file(
        session_id,
        manifest_path,
        evidence_type="manifest_tree",
        source="fixture",
        description="Manifest fixture.",
        sensitive=False,
        redacted=True,
    )
    ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=ScriptedIpcAdb(),
        scope=load_scope_for_test(paths),
    )

    findings = {
        item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)
    }
    assert findings["ASL-MANIFEST-EXPORTED-ACTIVITY"].status is FindingStatus.CONFIRMED
    assert findings["ASL-MANIFEST-EXPORTED-RECEIVER"].status is FindingStatus.CONFIRMED
    assert findings["ASL-MANIFEST-EXPORTED-PROVIDER"].status is FindingStatus.CONFIRMED


def test_candidates_preserve_manifest_routes_and_do_not_guess() -> None:
    candidates = build_ipc_candidates(_manifest())

    assert {item.component_type for item in candidates} == {
        "activity",
        "receiver",
        "provider",
    }
    assert [item.action for item in candidates if item.component_type == "receiver"] == [
        f"{PACKAGE}.PROBE"
    ]
    assert [item.authority for item in candidates if item.component_type == "provider"] == [
        f"{PACKAGE}.data"
    ]


def test_positive_activity_requires_target_observable_impact(tmp_path: Path) -> None:
    paths, repository, session_id = _session(tmp_path, _manifest())
    result = ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=ScriptedIpcAdb(activity_impact=True),
        scope=load_scope_for_test(paths),
    )

    activity = next(
        route for route in result.routes if route.candidate.component_type == "activity"
    )
    assert activity.outcome is IpcRouteOutcome.CONFIRMED
    assert activity.evidence_id == result.evidence_id
    artifact = repository.paths_for(session_id).redacted_dir / "ipc" / "exported-components.json"
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert "THESIS_CANARY_" not in artifact.read_text(encoding="utf-8")
    assert "FIXTURE_SECRET" not in artifact.read_text(encoding="utf-8")
    assert payload["routes"]


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("activity_denied", IpcRouteOutcome.REJECTED),
        ("activity_timeout", IpcRouteOutcome.INCONCLUSIVE),
        ("activity_escape", IpcRouteOutcome.OUT_OF_SCOPE),
    ],
)
def test_activity_block_timeout_and_package_escape_are_classified(
    tmp_path: Path,
    mode: str,
    expected: IpcRouteOutcome,
) -> None:
    paths, repository, session_id = _session(tmp_path, _manifest())
    result = ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=ScriptedIpcAdb(mode=mode),
        scope=load_scope_for_test(paths),
    )
    activity = next(
        route for route in result.routes if route.candidate.component_type == "activity"
    )
    assert activity.outcome is expected


def test_activity_command_success_without_impact_is_inconclusive(tmp_path: Path) -> None:
    paths, repository, session_id = _session(tmp_path, _manifest())
    result = ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=ScriptedIpcAdb(activity_impact=False),
        scope=load_scope_for_test(paths),
    )
    activity = next(
        route for route in result.routes if route.candidate.component_type == "activity"
    )
    assert activity.outcome is IpcRouteOutcome.INCONCLUSIVE
    assert "observable impact" in activity.reason


@pytest.mark.parametrize(
    "mode",
    [
        "receiver_denied",
        "provider_denied",
        "provider_zero",
        "provider_unknown",
        "provider_limit",
    ],
)
def test_negative_ipc_routes_are_not_false_positive(tmp_path: Path, mode: str) -> None:
    paths, repository, session_id = _session(tmp_path, _manifest())
    result = ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=ScriptedIpcAdb(mode=mode),
        scope=load_scope_for_test(paths),
    )
    if mode in {"provider_unknown", "provider_limit"}:
        provider = next(
            route for route in result.routes if route.candidate.component_type == "provider"
        )
        assert provider.outcome is IpcRouteOutcome.INCONCLUSIVE
    else:
        target_type = "receiver" if mode == "receiver_denied" else "provider"
        target = next(
            route
            for route in result.routes
            if route.candidate.component_type == target_type
        )
        expected = (
            IpcRouteOutcome.REJECTED
            if mode != "provider_unknown"
            else IpcRouteOutcome.INCONCLUSIVE
        )
        assert target.outcome is expected


def test_scope_denial_makes_no_adb_calls(tmp_path: Path) -> None:
    paths, repository, session_id = _session(tmp_path, _manifest())
    paths.scope_file.write_text(
        f"devices: [{SERIAL}]\npackages: [{PACKAGE}]\nallowed_actions: [inspect]\n",
        encoding="utf-8",
    )
    adb = ScriptedIpcAdb()
    result = ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=adb,
        scope=load_scope_for_test(paths),
    )
    assert result.routes
    assert all(route.outcome is IpcRouteOutcome.OUT_OF_SCOPE for route in result.routes)
    assert adb.calls == []


def test_quota_marks_remaining_routes_not_exercised(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["components"] = [
        {
            "component_type": "activity",
            "name": f"{PACKAGE}.A{index}",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        }
        for index in range(3)
    ]
    paths, repository, session_id = _session(tmp_path, manifest)
    result = ExportedComponentValidationService(
        paths_context(paths), repository, total_quota=1, type_quotas={"activity": 1}
    ).run(session_id, adb=ScriptedIpcAdb(), scope=load_scope_for_test(paths))
    assert sum(route.attempted for route in result.routes) == 1
    assert any(route.outcome is IpcRouteOutcome.NOT_EXERCISED for route in result.routes)


def test_unexercised_receiver_preserves_manifest_potential(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["components"] = [
        {
            "component_type": "receiver",
            "name": f"{PACKAGE}.UnboundedReceiver",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [{"actions": [f"{PACKAGE}.SYNC"]}],
        }
    ]
    paths, repository, session_id = _session(tmp_path, manifest)
    result = ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=ScriptedIpcAdb(),
        scope=load_scope_for_test(paths),
    )

    receiver = result.routes[0]
    assert receiver.outcome is IpcRouteOutcome.NOT_EXERCISED
    findings = {
        item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)
    }
    finding = findings["ASL-MANIFEST-EXPORTED-RECEIVER"]

    assert finding.status is FindingStatus.POTENTIAL
    assert finding.analysis_type == "adb_ipc_validation"
    validation = finding.details["ipc_validation"]
    assert validation["activation_state"] == "not_exercised"
    assert validation["validation_state"] == "not_exercised"
    assert validation["runtime_reached"] is None
    assert "potential finding" in finding.details["reason"]


def test_inconclusive_provider_preserves_manifest_potential(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["components"] = [
        {
            "component_type": "provider",
            "name": f"{PACKAGE}.UnknownProvider",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "read_permission": None,
            "authorities": f"{PACKAGE}.unknown",
            "intent_filters": [],
        }
    ]
    paths, repository, session_id = _session(tmp_path, manifest)
    result = ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=ScriptedIpcAdb(mode="provider_unknown"),
        scope=load_scope_for_test(paths),
    )

    provider = result.routes[0]
    assert provider.outcome is IpcRouteOutcome.INCONCLUSIVE
    findings = {
        item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)
    }
    finding = findings["ASL-MANIFEST-EXPORTED-PROVIDER"]

    assert finding.status is FindingStatus.POTENTIAL
    validation = finding.details["ipc_validation"]
    assert validation["activation_state"] == "attempted_inconclusive"
    assert validation["validation_state"] == "inconclusive"
    assert validation["runtime_reached"] is False
    assert validation["outcome_counts"] == {"inconclusive": 1}


def test_permission_rejection_remains_route_scoped_pass(tmp_path: Path) -> None:
    manifest = _manifest(protected=True)
    manifest["components"] = [manifest["components"][0]]
    paths, repository, session_id = _session(tmp_path, manifest)
    result = ExportedComponentValidationService(paths_context(paths), repository).run(
        session_id,
        adb=ScriptedIpcAdb(mode="activity_denied"),
        scope=load_scope_for_test(paths),
    )

    assert result.routes[0].outcome is IpcRouteOutcome.REJECTED
    findings = {
        item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)
    }
    finding = findings["ASL-MANIFEST-EXPORTED-ACTIVITY"]

    assert finding.status is FindingStatus.PASS
    validation = finding.details["ipc_validation"]
    assert validation["validation_state"] == "rejected_for_tested_route"
    assert validation["runtime_reached"] is False
    assert "tested route" in finding.details["reason"]


def paths_context(paths: ProjectPaths) -> SimpleNamespace:
    return SimpleNamespace(paths=paths)


def load_scope_for_test(paths: ProjectPaths):
    from android_assessor.scope import load_scope

    return load_scope(paths)
