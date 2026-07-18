from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any

import pytest

from android_assessor.errors import AdbTimeoutError, ConfigurationError, ScopeError
from android_assessor.scenario import (
    ScenarioAction,
    ScenarioBackend,
    ScenarioBundle,
    ScenarioCollection,
    ScenarioDefinition,
    ScenarioLoader,
    ScenarioNode,
    ScenarioObservation,
    ScenarioOutcome,
    ScenarioProfile,
    ScenarioRunner,
    ScenarioSecretResolver,
    ScenarioSelector,
    ScenarioStep,
    ScenarioTransition,
    ScenarioValueSpec,
)

PACKAGE = "com.example.scenario"
LOGIN = "com.example.scenario.LoginActivity"
HOME = "com.example.scenario.HomeActivity"
RAW_SECRET = "fixture-owned-password"


def _node(
    resource_id: str,
    *,
    text: str = "",
    editable: bool = False,
    clickable: bool = False,
    y: int = 100,
) -> ScenarioNode:
    return ScenarioNode(
        resource_id=resource_id,
        content_description="",
        visible_text=text,
        class_name=(
            "android.widget.EditText" if editable else "android.widget.Button"
        ),
        bounds=(10, y, 500, y + 80),
        clickable=clickable,
        editable=editable,
    )


LOGIN_STATE = ScenarioObservation(
    package=PACKAGE,
    activity=LOGIN,
    pid=4242,
    process=PACKAGE,
    nodes=(
        _node(f"{PACKAGE}:id/username", editable=True, y=100),
        _node(f"{PACKAGE}:id/password", editable=True, y=200),
        _node(f"{PACKAGE}:id/login", text="Login", clickable=True, y=300),
        _node(f"{PACKAGE}:id/safe", text="Safe", clickable=True, y=400),
    ),
)
HOME_STATE = ScenarioObservation(
    package=PACKAGE,
    activity=HOME,
    pid=4242,
    process=PACKAGE,
    nodes=(_node(f"{PACKAGE}:id/home", text="Home", clickable=True),),
)


class FakeScope:
    def __init__(self, *, deny_controlled: bool = False) -> None:
        self.deny_controlled = deny_controlled
        self.actions: list[str | None] = []
        self.urls: list[str] = []

    def require_device_package(
        self,
        serial: str,
        package: str,
        *,
        action: str | None = None,
    ) -> None:
        assert serial == "emulator-5554"
        assert package == PACKAGE
        self.actions.append(action)
        if action == "controlled_validation" and self.deny_controlled:
            raise ScopeError("controlled scenario denied")

    def require_url(self, value: str) -> None:
        self.urls.append(value)


class FakeBackend(ScenarioBackend):
    def __init__(self) -> None:
        self.state = LOGIN_STATE
        self.observe_script: deque[ScenarioObservation | BaseException] = deque()
        self.launch_count = 0
        self.input_count = 0
        self.click_count = 0
        self.collect_count = 0
        self.cleanup_count = 0
        self.transition_on_click = True
        self.input_error: BaseException | None = None
        self.click_error: BaseException | None = None
        self.cleanup_error: BaseException | None = None
        self.collection = ScenarioCollection(
            evidence_references=("ev-scenario",),
            observed_categories=("crypto", "logging"),
        )
        self.collect_script: deque[ScenarioCollection | BaseException] = deque()
        self.entered_values: list[str] = []
        self.sensitive_values: list[tuple[str, ...]] = []

    def launch(self, activity: str | None, *, timeout: float) -> None:
        assert activity == LOGIN
        assert timeout > 0
        self.launch_count += 1
        self.state = LOGIN_STATE

    def observe(self, *, timeout: float) -> ScenarioObservation:
        assert timeout > 0
        value: ScenarioObservation | BaseException = (
            self.observe_script.popleft() if self.observe_script else self.state
        )
        if isinstance(value, BaseException):
            raise value
        return value

    def input_text(
        self,
        x: int,
        y: int,
        value: str,
        *,
        timeout: float,
        sensitive_values: tuple[str, ...] = (),
    ) -> None:
        assert x > 0 and y > 0 and timeout > 0
        self.input_count += 1
        self.entered_values.append(value)
        self.sensitive_values.append(sensitive_values)
        if self.input_error is not None:
            raise self.input_error

    def click(self, x: int, y: int, *, timeout: float) -> None:
        assert x > 0 and y > 0 and timeout > 0
        self.click_count += 1
        if self.click_error is not None:
            raise self.click_error
        if self.transition_on_click:
            self.state = HOME_STATE

    def collect_observations(
        self,
        observers: tuple[str, ...],
        *,
        scenario_id: str,
        step_id: str,
        timeout: float,
    ) -> ScenarioCollection:
        assert observers
        assert scenario_id == "login"
        assert step_id == "collect"
        assert timeout > 0
        self.collect_count += 1
        value: ScenarioCollection | BaseException = (
            self.collect_script.popleft() if self.collect_script else self.collection
        )
        if isinstance(value, BaseException):
            raise value
        return value

    def cleanup(self, *, timeout: float) -> None:
        assert timeout > 0
        self.cleanup_count += 1
        if self.cleanup_error is not None:
            raise self.cleanup_error


def _profile(*, expected_classes: tuple[str, ...] = ()) -> ScenarioProfile:
    return ScenarioProfile(
        profile_id="generic-lab",
        package=PACKAGE,
        launch_activity=LOGIN,
        selectors={
            "username": ScenarioSelector(resource_id=f"{PACKAGE}:id/username"),
            "password": ScenarioSelector(resource_id=f"{PACKAGE}:id/password"),
            "submit": ScenarioSelector(resource_id=f"{PACKAGE}:id/login"),
            "safe": ScenarioSelector(visible_text="Safe"),
            "missing": ScenarioSelector(resource_id=f"{PACKAGE}:id/missing"),
        },
        values={
            "username": ScenarioValueSpec(
                kind="literal",
                literal="fixture-user",
                sensitive=False,
            ),
            "password": ScenarioValueSpec(
                kind="secret_ref",
                reference="fixture.password",
            ),
        },
        transitions={"authenticated": ScenarioTransition(activity=HOME)},
        expected_vulnerability_classes=expected_classes,
    )


def _step(
    step_id: str,
    action: ScenarioAction,
    **kwargs: Any,
) -> ScenarioStep:
    return ScenarioStep(
        step_id=step_id,
        action=action,
        timeout_seconds=5,
        **kwargs,
    )


def _bundle(*steps: ScenarioStep, expected_classes: tuple[str, ...] = ()) -> ScenarioBundle:
    return ScenarioBundle(
        _profile(expected_classes=expected_classes),
        ScenarioDefinition(
            scenario_id="login",
            total_timeout_seconds=30,
            steps=steps,
        ),
    )


def _full_bundle(*, collect_retries: int = 0) -> ScenarioBundle:
    return _bundle(
        _step("launch", ScenarioAction.LAUNCH),
        _step("wait", ScenarioAction.WAIT_FOR, selector_ref="username"),
        _step(
            "username",
            ScenarioAction.INPUT,
            selector_ref="username",
            value_ref="username",
        ),
        _step(
            "password",
            ScenarioAction.INPUT,
            selector_ref="password",
            value_ref="password",
        ),
        _step("submit", ScenarioAction.CLICK, selector_ref="submit"),
        _step(
            "transition",
            ScenarioAction.WAIT_FOR_TRANSITION,
            transition_ref="authenticated",
            max_read_retries=1,
        ),
        _step(
            "collect",
            ScenarioAction.COLLECT_OBSERVATIONS,
            observers=("frida", "traffic"),
            max_read_retries=collect_retries,
        ),
        _step("cleanup", ScenarioAction.CLEANUP),
        expected_classes=("sensitive_logging", "weak_cryptography"),
    )


def _runner(
    backend: FakeBackend,
    bundle: ScenarioBundle,
    *,
    scope: FakeScope | None = None,
) -> ScenarioRunner:
    return ScenarioRunner(
        backend,
        scope=scope or FakeScope(),
        serial="emulator-5554",
        package=PACKAGE,
        session_id="20260719-000000-abcdef",
        bundle=bundle,
        secrets=ScenarioSecretResolver(
            {"fixture": {"password": RAW_SECRET}},
            session_key=b"0123456789abcdef0123456789abcdef",
        ),
        network_guard_active=True,
        available_observers=("frida", "traffic", "logcat", "private_storage"),
    )


def _by_id(result: Any) -> dict[str, Any]:
    return {step.step_id: step for step in result.steps}


def test_positive_scenario_completes_with_bounded_attributed_steps() -> None:
    backend = FakeBackend()

    result = _runner(backend, _full_bundle()).run()

    assert result.outcome is ScenarioOutcome.COMPLETED
    assert all(step.completed for step in result.steps)
    assert backend.launch_count == 1
    assert backend.input_count == 2
    assert backend.click_count == 1
    assert backend.collect_count == 1
    assert backend.cleanup_count == 1
    assert result.verified_pids == (4242,)
    assert result.verified_processes == (PACKAGE,)
    assert _by_id(result)["password"].resolved_selector == {
        "selector_ref": "password",
        "strategy": "resource_id",
        "resource_id": f"{PACKAGE}:id/password",
    }
    assert _by_id(result)["transition"].observed_transition["to_activity"] == HOME


def test_negative_safe_scenario_completes_without_inventing_a_positive_class() -> None:
    backend = FakeBackend()
    backend.collection = ScenarioCollection(
        evidence_references=("ev-safe",),
        observed_categories=(),
    )

    result = _runner(backend, _full_bundle()).run()

    assert result.outcome is ScenarioOutcome.COMPLETED
    collected = _by_id(result)["collect"]
    assert collected.completed is True
    assert collected.observed_transition == {
        "observers": ["frida", "traffic"],
        "observed_categories": [],
    }
    assert "confirmed" not in json.dumps(result.to_dict())


def test_missing_selector_fails_activation_and_still_cleans_up() -> None:
    backend = FakeBackend()
    bundle = _bundle(
        _step("launch", ScenarioAction.LAUNCH),
        _step("missing", ScenarioAction.WAIT_FOR, selector_ref="missing"),
        _step("cleanup", ScenarioAction.CLEANUP),
    )

    result = _runner(backend, bundle).run()

    assert result.outcome is ScenarioOutcome.FAILED_ACTIVATION
    assert _by_id(result)["missing"].failure_reason == "selector_missing"
    assert _by_id(result)["cleanup"].completed is True
    assert backend.cleanup_count == 1


def test_transition_timeout_is_failed_activation_not_completion() -> None:
    backend = FakeBackend()
    backend.transition_on_click = False
    bundle = _bundle(
        _step("launch", ScenarioAction.LAUNCH),
        _step("submit", ScenarioAction.CLICK, selector_ref="submit"),
        _step(
            "transition",
            ScenarioAction.WAIT_FOR_TRANSITION,
            transition_ref="authenticated",
            max_read_retries=1,
        ),
        _step("cleanup", ScenarioAction.CLEANUP),
    )

    result = _runner(backend, bundle).run()

    transition = _by_id(result)["transition"]
    assert result.outcome is ScenarioOutcome.FAILED_ACTIVATION
    assert transition.failure_reason == "transition_timeout"
    assert transition.retry_count == 1
    assert backend.click_count == 1


def test_package_escape_stops_scenario_without_following_actions() -> None:
    backend = FakeBackend()
    backend.observe_script.append(
        ScenarioObservation(
            package="com.other.app",
            activity="com.other.app.ExternalActivity",
            nodes=(),
            pid=9999,
            process="com.other.app",
        )
    )

    result = _runner(backend, _full_bundle()).run()

    assert result.outcome is ScenarioOutcome.OUT_OF_SCOPE
    assert _by_id(result)["launch"].failure_reason == "package_escape"
    assert _by_id(result)["username"].attempted is False
    assert backend.input_count == 0
    assert backend.click_count == 0
    assert backend.cleanup_count == 1


def test_read_only_timeout_retries_once_and_preserves_retry_count() -> None:
    backend = FakeBackend()
    backend.observe_script.extend(
        [LOGIN_STATE, AdbTimeoutError("read timed out"), LOGIN_STATE]
    )
    bundle = _bundle(
        _step("launch", ScenarioAction.LAUNCH),
        _step(
            "wait",
            ScenarioAction.WAIT_FOR,
            selector_ref="username",
            max_read_retries=1,
        ),
        _step("cleanup", ScenarioAction.CLEANUP),
    )

    result = _runner(backend, bundle).run()

    assert result.outcome is ScenarioOutcome.COMPLETED
    assert _by_id(result)["wait"].retry_count == 1


def test_mutation_timeout_is_unknown_and_is_never_replayed() -> None:
    backend = FakeBackend()
    backend.input_error = AdbTimeoutError("ADB timeout after dispatch")
    bundle = _bundle(
        _step("launch", ScenarioAction.LAUNCH),
        _step(
            "password",
            ScenarioAction.INPUT,
            selector_ref="password",
            value_ref="password",
        ),
        _step(
            "collect",
            ScenarioAction.COLLECT_OBSERVATIONS,
            observers=("frida",),
        ),
        _step("cleanup", ScenarioAction.CLEANUP),
    )

    result = _runner(backend, bundle).run()

    assert result.outcome is ScenarioOutcome.TIMEOUT_UNKNOWN
    assert _by_id(result)["password"].failure_reason == "mutation_timeout_unknown"
    assert backend.input_count == 1
    assert backend.collect_count == 0
    assert backend.cleanup_count == 1


def test_scope_denial_occurs_before_any_backend_action() -> None:
    backend = FakeBackend()
    scope = FakeScope(deny_controlled=True)

    result = _runner(backend, _full_bundle(), scope=scope).run()

    assert result.outcome is ScenarioOutcome.OUT_OF_SCOPE
    assert _by_id(result)["launch"].failure_reason == "scope_denied"
    assert backend.launch_count == 0
    assert backend.input_count == 0
    assert backend.cleanup_count == 0
    assert result.cleanup_status == "not_required"


def test_cleanup_failure_is_truthfully_partial_after_completed_route() -> None:
    backend = FakeBackend()
    backend.cleanup_error = AdbTimeoutError("cleanup timeout")

    result = _runner(backend, _full_bundle()).run()

    assert result.outcome is ScenarioOutcome.PARTIAL
    assert result.cleanup_status == "failed"
    assert _by_id(result)["cleanup"].failure_reason == "cleanup_failed"
    assert backend.cleanup_count == 1


def test_secret_is_redacted_from_repr_result_and_failure_metadata() -> None:
    backend = FakeBackend()
    backend.input_error = AdbTimeoutError(f"timeout while sending {RAW_SECRET}")
    resolver = ScenarioSecretResolver(
        {"fixture": {"password": RAW_SECRET}},
        session_key=b"0123456789abcdef0123456789abcdef",
    )
    resolved = resolver.resolve(_profile().values["password"])
    runner = ScenarioRunner(
        backend,
        scope=FakeScope(),
        serial="emulator-5554",
        package=PACKAGE,
        session_id="20260719-000000-abcdef",
        bundle=_bundle(
            _step("launch", ScenarioAction.LAUNCH),
            _step(
                "password",
                ScenarioAction.INPUT,
                selector_ref="password",
                value_ref="password",
            ),
            _step("cleanup", ScenarioAction.CLEANUP),
        ),
        secrets=resolver,
        network_guard_active=True,
    )

    result = runner.run()
    serialized = json.dumps(result.to_dict(), ensure_ascii=False)

    assert RAW_SECRET not in repr(resolver)
    assert RAW_SECRET not in repr(resolved)
    assert RAW_SECRET not in str(resolved)
    assert RAW_SECRET not in serialized
    assert resolver.redact(f"value={RAW_SECRET}") == "value=<redacted>"
    assert backend.entered_values == [RAW_SECRET]
    assert backend.sensitive_values == [(RAW_SECRET,)]


def test_strict_yaml_loader_rejects_unknown_keys_and_sensitive_literals(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile.yaml"
    scenario = tmp_path / "login.yaml"
    profile.write_text(
        f"""
schema_version: 1
profile_id: generic-lab
package: {PACKAGE}
launch_activity: {LOGIN}
selectors:
  submit:
    visible_text: Login
values: {{}}
transitions: {{}}
expected_vulnerability_classes: []
""".strip(),
        encoding="utf-8",
    )
    scenario.write_text(
        """
schema_version: 1
scenario_id: login
total_timeout_seconds: 30
preconditions: {}
steps:
  - id: launch
    action: launch
    timeout_seconds: 5
  - id: cleanup
    action: cleanup
    timeout_seconds: 5
""".strip(),
        encoding="utf-8",
    )
    loader = ScenarioLoader(tmp_path)

    bundle = loader.load_bundle(profile, scenario)
    assert bundle.profile.package == PACKAGE

    profile.write_text(
        profile.read_text(encoding="utf-8")
        + "\nunknown_production_shortcut: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="unsupported keys"):
        loader.load_profile(profile)

    profile.write_text(
        f"""
schema_version: 1
profile_id: generic-lab
package: {PACKAGE}
launch_activity: {LOGIN}
selectors: {{}}
values:
  password:
    literal: raw-password
    sensitive: true
transitions: {{}}
expected_vulnerability_classes: []
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="sensitive literals are forbidden"):
        loader.load_profile(profile)
