from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from android_assessor.errors import AdbTimeoutError, ScopeError
from android_assessor.micro_scenario import CandidateMicroScenarioService
from android_assessor.scenario_correlation import correlate_scenario_events
from android_assessor.services.scan_service import _apply_sink_verification_quota
from android_assessor.session import SessionRecord, SessionStatus

PACKAGE = "com.example.lab"
ACTIVITY = f"{PACKAGE}.LoginActivity"
SESSION = "20260719-000000-abcdef"
CANARY = "session-owned-canary"
RAW_MARKER = CANARY


def _record() -> SessionRecord:
    return SessionRecord(
        session_id=SESSION,
        created_at="2026-07-19T00:00:00+00:00",
        updated_at="2026-07-19T00:00:00+00:00",
        status=SessionStatus.ACTIVE,
        serial="emulator-5554",
        package=PACKAGE,
        snapshot={},
    )


def _manifest() -> dict[str, object]:
    return {
        "uses_cleartext_traffic": True,
        "components": [
            {
                "component_type": "activity",
                "name": ACTIVITY,
                "effective_exported": True,
                "enabled": True,
                "intent_filters": [
                    {
                        "actions": ["android.intent.action.MAIN"],
                        "categories": ["android.intent.category.LAUNCHER"],
                    }
                ],
            }
        ],
    }


def _static_analysis() -> dict[str, object]:
    return {
        "endpoints": [{"scheme": "http", "host": "127.0.0.1"}],
        "static_behavior_candidates": [
            {
                "caller_class_descriptor": "Lcom/example/lab/LoginActivity;",
                "rule_id": "crypto-callsite",
                "indicators": ["Cipher.getInstance", "Log.d", "SharedPreferences"],
            }
        ],
        "security_api_candidates": [
            {"category": "logging", "inventory_id": "logcat"},
            {"category": "storage", "inventory_id": "preferences"},
        ],
    }


class _Scope:
    def __init__(self, *, denied: bool = False) -> None:
        self.denied = denied
        self.calls: list[str | None] = []

    def require_device_package(
        self,
        serial: str,
        package: str,
        *,
        action: str | None = None,
    ) -> None:
        assert serial == "emulator-5554"
        assert package == PACKAGE
        self.calls.append(action)
        if self.denied and action == "controlled_validation":
            raise ScopeError("controlled validation denied")

    def require_url(self, value: str) -> None:
        assert value.startswith("http://127.0.0.1")


@dataclass
class _FakeExplorerBackend:
    mode: str = "positive"

    def __post_init__(self) -> None:
        self.package = PACKAGE
        self.pid = 4242
        self.current_package = "com.other.app" if self.mode == "wrong_package" else PACKAGE
        self.launch_count = 0
        self.input_values: list[str] = []
        self.tap_count = 0
        self.hide_keyboard_count = 0

    def current_activity(self) -> tuple[str, str]:
        if self.mode == "wrong_package" or self.current_package != PACKAGE:
            return "com.other.app", "com.other.app.ExternalActivity"
        return PACKAGE, ACTIVITY

    def dump_ui(self) -> str:
        if self.mode == "initial_timeout":
            raise AdbTimeoutError("UI dump timed out")
        package = self.current_package
        return f"""<?xml version='1.0' encoding='utf-8'?>
<hierarchy>
  <node index='0' text='' resource-id='{package}:id/username'
        class='android.widget.EditText' package='{package}'
        clickable='false' editable='true' enabled='true' visible-to-user='true'
        bounds='[10,100][500,180]' />
  <node index='1' text='' resource-id='{package}:id/password'
        class='android.widget.EditText' package='{package}' password='true'
        clickable='false' editable='true' enabled='true' visible-to-user='true'
        bounds='[10,200][500,280]' />
  <node index='2' text='Login' resource-id='{package}:id/login'
        class='android.widget.Button' package='{package}' clickable='true'
        enabled='true' visible-to-user='true' bounds='[10,300][500,380]' />
</hierarchy>"""

    def process_id(self) -> int:
        return self.pid

    def launch(self) -> None:
        self.launch_count += 1

    def input_text(self, x: int, y: int, value: str) -> None:
        if self.mode == "mutation_timeout":
            raise AdbTimeoutError("ADB timeout after input dispatch")
        self.input_values.append(value)

    def tap(self, x: int, y: int) -> None:
        self.tap_count += 1
        if self.mode == "mutation_timeout":
            raise AdbTimeoutError("ADB timeout after click dispatch")
        if self.mode == "package_escape":
            self.current_package = "com.other.app"

    def hide_keyboard(self) -> None:
        self.hide_keyboard_count += 1


def _service() -> CandidateMicroScenarioService:
    # Planning and execution do not need a live repository. Persistence is tested
    # by the scan-service integration; this keeps fixture tests device-independent.
    return CandidateMicroScenarioService(object())


def _seed() -> tuple[CandidateMicroScenarioService, object]:
    service = _service()
    return service, service.prepare(
        _record(),
        manifest=_manifest(),
        static_analysis=_static_analysis(),
        session_canary=CANARY,
    )


def test_prepare_uses_app_code_candidates_and_redacted_owned_metadata() -> None:
    _service_instance, seed = _seed()

    assert seed.candidate_classes == ("logging", "cleartext", "storage", "crypto")
    assert seed.owned_values
    assert all("fingerprint" in item for item in seed.owned_value_metadata)
    serialized = json.dumps(
        {
            "candidate_classes": seed.candidate_classes,
            "owned_value_metadata": seed.owned_value_metadata,
        }
    )
    assert RAW_MARKER not in serialized
    assert all(
        set(item) >= {"reference", "type", "length", "fingerprint"}
        for item in seed.owned_value_metadata
    )


def test_runtime_candidate_enrichment_preserves_session_fingerprints() -> None:
    service, seed = _seed()
    enriched = service.enrich_runtime_candidates(seed, ("crypto", "logging"))

    assert enriched.candidate_classes == seed.candidate_classes
    assert enriched.candidate_reasons["crypto"][-1] == "runtime_observer_category"
    assert enriched.owned_values == seed.owned_values
    assert enriched.canary_fingerprint == seed.canary_fingerprint


def test_local_http_mapping_comes_only_from_scoped_static_endpoint() -> None:
    service = _service()
    static = _static_analysis()
    static["endpoints"] = [{"scheme": "http", "host": "127.0.0.1", "port": 8888}]
    seed = service.prepare(
        _record(),
        manifest=_manifest(),
        static_analysis=static,
        session_canary=CANARY,
        allowed_hosts=("127.0.0.1",),
    )

    assert seed.upstream_mapping == {"127.0.0.1:8888": "127.0.0.1:8888"}
    unscoped = service.prepare(
        _record(),
        manifest=_manifest(),
        static_analysis=static,
        session_canary=CANARY,
    )
    assert unscoped.upstream_mapping == {}


def test_positive_micro_scenario_completes_once_and_cleans_up() -> None:
    service, seed = _seed()
    backend = _FakeExplorerBackend()

    execution = service.run(
        seed,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("frida", "traffic", "logcat", "private_storage"),
        serial="emulator-5554",
    )

    assert execution.completed
    assert execution.result is not None
    assert execution.result.outcome.value == "completed"
    assert backend.tap_count == 1
    assert backend.hide_keyboard_count == 1
    assert len(backend.input_values) == 2
    assert RAW_MARKER not in json.dumps(execution.to_dict())


def test_static_ui_after_activation_does_not_replay_mutation() -> None:
    service, seed = _seed()
    backend = _FakeExplorerBackend()

    execution = service.run(
        seed,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )

    assert execution.result is not None
    assert backend.tap_count == 1


def test_activation_quota_blocks_route_before_input() -> None:
    service, seed = _seed()
    exhausted = replace(seed, activation_quota=2)
    backend = _FakeExplorerBackend()

    execution = service.run(
        exhausted,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )

    assert execution.outcome == "not_exercised"
    assert execution.reason == "activation_quota_exhausted"
    assert backend.input_values == []
    assert backend.tap_count == 0


def test_persist_uses_session_paths_and_keeps_artifact_redacted(tmp_path: Path) -> None:
    service, seed = _seed()
    backend = _FakeExplorerBackend()
    execution = service.run(
        seed,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )
    session_root = tmp_path / SESSION
    session_paths = SimpleNamespace(root=session_root, redacted_dir=session_root / "redacted")
    evidence_calls: list[Path] = []
    service = CandidateMicroScenarioService(
        SimpleNamespace(
            repository=SimpleNamespace(paths_for=lambda _session_id: session_paths),
            evidence=SimpleNamespace(
                register_file=lambda _session_id, path, **_kwargs: evidence_calls.append(path)
            ),
        )
    )

    artifact = service.persist(SESSION, execution)

    assert artifact == session_paths.redacted_dir / "micro-scenario" / "result.json"
    assert artifact.is_file()
    assert evidence_calls == [artifact]
    assert RAW_MARKER not in artifact.read_text(encoding="utf-8")


def test_sink_verification_quota_is_independent_and_truthful() -> None:
    payload = {
        "events": [{"id": "one"}, {"id": "two"}, {"id": "three"}],
        "accepted_count": 3,
    }

    bounded = _apply_sink_verification_quota(payload, 2)

    assert [item["id"] for item in bounded["events"]] == ["one", "two"]
    assert bounded["accepted_count"] == 2
    assert bounded["sink_verification_quota"] == 2
    assert bounded["quota_exhausted"] is True


def test_no_safe_form_is_not_exercised() -> None:
    service, seed = _seed()
    backend = _FakeExplorerBackend()
    backend.dump_ui = lambda: """<hierarchy>
      <node index='0' text='Home' resource-id='com.example.lab:id/home'
        class='android.widget.TextView' package='com.example.lab'
        clickable='false' enabled='true' visible-to-user='true'
        bounds='[10,100][500,180]' />
    </hierarchy>"""

    execution = service.run(
        seed,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )

    assert execution.outcome == "not_exercised"
    assert execution.result is None
    assert backend.tap_count == 0


@pytest.mark.parametrize("mode", ["wrong_package", "package_escape"])
def test_package_escape_never_becomes_a_positive_route(mode: str) -> None:
    service, seed = _seed()
    backend = _FakeExplorerBackend(mode=mode)

    execution = service.run(
        seed,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )

    assert execution.outcome == "out_of_scope"
    assert backend.tap_count == (0 if mode == "wrong_package" else 1)
    assert backend.hide_keyboard_count == (0 if mode == "wrong_package" else 1)


def test_mutation_timeout_is_unknown_without_replay_and_cleanup_runs() -> None:
    service, seed = _seed()
    backend = _FakeExplorerBackend(mode="mutation_timeout")

    execution = service.run(
        seed,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )

    assert execution.outcome == "timeout_unknown"
    assert execution.result is not None
    assert len(backend.input_values) == 0
    assert backend.tap_count == 0
    assert backend.hide_keyboard_count == 1


def test_initial_timeout_is_not_exercised() -> None:
    service, seed = _seed()
    execution = service.run(
        seed,
        backend=_FakeExplorerBackend(mode="initial_timeout"),  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )

    assert execution.outcome == "not_exercised"
    assert execution.result is None


def test_scope_denial_stops_before_mutation() -> None:
    service, seed = _seed()
    backend = _FakeExplorerBackend()
    execution = service.run(
        seed,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(denied=True),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )

    assert execution.outcome == "out_of_scope"
    assert backend.input_values == []
    assert backend.tap_count == 0
    assert backend.hide_keyboard_count == 0


def test_wrong_pid_package_and_window_events_are_rejected() -> None:
    service, seed = _seed()
    backend = _FakeExplorerBackend()
    execution = service.run(
        seed,
        backend=backend,  # type: ignore[arg-type]
        scope=_Scope(),  # type: ignore[arg-type]
        network_guard_active=True,
        available_observers=("traffic",),
        serial="emulator-5554",
    )
    assert execution.result is not None
    summary = execution.result.to_dict()
    summary.update(
        {
            "canary_fingerprint": seed.canary_fingerprint,
            "owned_value_fingerprints": list(seed.owned_values),
            "scoped_backend_ids": ["backend-local"],
        }
    )
    assert execution.result.steps
    step = next(item for item in execution.result.steps if item.completed)
    event = {
        "session_id": SESSION,
        "scenario_id": seed.scenario_id,
        "package": PACKAGE,
        "pid": 4242,
        "process": PACKAGE,
        "timestamp": step.ended_at,
        "step_id": step.step_id,
        "evidence_id": "ev-local",
        "canary_fingerprint": seed.canary_fingerprint,
        "attribution": "scenario_owned_value",
        "backend_id": "backend-local",
        "event": "request",
        "backend_scope": "scoped_local",
        "exact_owned_value_match": True,
    }
    wrong_pid = dict(event, pid=9999)
    wrong_package = dict(event, package="com.other.app")
    outside_window = dict(event, timestamp="2027-01-01T00:00:00+00:00")
    result = correlate_scenario_events(
        summary,
        traffic_events=[event, wrong_pid, wrong_package, outside_window],
    )
    assert len(result.events) == 1
    reasons = {item["rejection_reason"] for item in result.rejected}
    assert {"wrong_pid", "wrong_package", "outside_step_window"} <= reasons
