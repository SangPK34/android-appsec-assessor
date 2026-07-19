"""Strict, generic deterministic UI scenario execution primitives.

This module deliberately contains no benchmark-specific identifiers.  It loads
tracked scenario metadata, resolves sensitive runtime values without making
them serializable, and executes one bounded sequence against an injected
backend.  Persistence and assessment orchestration belong to a service layer.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import yaml

from .errors import (
    AdbTimeoutError,
    AndroidAssessorError,
    ConfigurationError,
    ScopeError,
)
from .redaction import REDACTED, redact_text_with_values
from .validation import validate_component_name, validate_package_name

_SAFE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,79}$")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9_-]{1,64})*$")
_SAFE_RESOURCE_ID = re.compile(r"^[A-Za-z0-9_.:$/-]{1,255}$")
_SAFE_CLASS = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
_MAX_YAML_BYTES = 256 * 1024
_MAX_STEPS = 50
_MAX_SELECTORS = 100
_MAX_VALUES = 100
_MAX_TEXT_CHARS = 512
_MAX_COORDINATE = 10_000
_READ_ONLY_ACTIONS = {
    "wait_for",
    "wait_for_transition",
    "collect_observations",
}
_MUTATING_ACTIONS = {"input", "click"}
_OBSERVERS = {"frida", "traffic", "logcat", "private_storage", "runtime"}


class ScenarioAction(StrEnum):
    LAUNCH = "launch"
    WAIT_FOR = "wait_for"
    INPUT = "input"
    CLICK = "click"
    WAIT_FOR_TRANSITION = "wait_for_transition"
    COLLECT_OBSERVATIONS = "collect_observations"
    CLEANUP = "cleanup"


class ScenarioOutcome(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED_PRECONDITION = "failed_precondition"
    FAILED_ACTIVATION = "failed_activation"
    TIMEOUT_UNKNOWN = "timeout_unknown"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True, slots=True)
class ScenarioCoordinate:
    x: int
    y: int


@dataclass(frozen=True, slots=True)
class ScenarioSelector:
    resource_id: str | None = None
    content_description: str | None = None
    visible_text: str | None = None
    class_name: str | None = None
    index: int | None = None
    coordinate_fallback: ScenarioCoordinate | None = None


@dataclass(frozen=True, slots=True)
class ScenarioValueSpec:
    kind: str
    reference: str | None = None
    literal: str | None = field(default=None, repr=False)
    sensitive: bool = True


@dataclass(frozen=True, slots=True)
class ScenarioTransition:
    activity: str | None = None
    selector_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ScenarioProfile:
    profile_id: str
    package: str
    launch_activity: str | None
    selectors: Mapping[str, ScenarioSelector]
    values: Mapping[str, ScenarioValueSpec]
    transitions: Mapping[str, ScenarioTransition] = field(default_factory=dict)
    local_backend_url: str | None = None
    upstream_backend_url: str | None = None
    expected_vulnerability_classes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    step_id: str
    action: ScenarioAction
    timeout_seconds: int
    selector_ref: str | None = None
    value_ref: str | None = None
    expected_activity: str | None = None
    transition_ref: str | None = None
    observers: tuple[str, ...] = ()
    max_read_retries: int = 0


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    scenario_id: str
    total_timeout_seconds: int
    steps: tuple[ScenarioStep, ...]
    require_network_guard: bool = False
    required_observers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScenarioBundle:
    profile: ScenarioProfile
    scenario: ScenarioDefinition


@dataclass(frozen=True, slots=True, repr=False)
class ScenarioNode:
    resource_id: str
    content_description: str
    visible_text: str
    class_name: str
    bounds: tuple[int, int, int, int]
    clickable: bool
    editable: bool
    enabled: bool = True
    visible: bool = True

    @property
    def center(self) -> tuple[int, int]:
        left, top, right, bottom = self.bounds
        return (left + right) // 2, (top + bottom) // 2


@dataclass(frozen=True, slots=True, repr=False)
class ScenarioObservation:
    package: str
    activity: str
    nodes: tuple[ScenarioNode, ...]
    pid: int | None = None
    process: str | None = None
    timestamp: str | None = None
    display_width: int = 1080
    display_height: int = 1920


@dataclass(frozen=True, slots=True)
class ScenarioCollection:
    evidence_references: tuple[str, ...] = ()
    observed_categories: tuple[str, ...] = ()


class ScenarioBackend(Protocol):
    def launch(self, activity: str | None, *, timeout: float) -> None: ...

    def observe(self, *, timeout: float) -> ScenarioObservation: ...

    def input_text(
        self,
        x: int,
        y: int,
        value: str,
        *,
        timeout: float,
        sensitive_values: Sequence[str] = (),
    ) -> None: ...

    def click(self, x: int, y: int, *, timeout: float) -> None: ...

    def collect_observations(
        self,
        observers: tuple[str, ...],
        *,
        scenario_id: str,
        step_id: str,
        timeout: float,
    ) -> ScenarioCollection: ...

    def cleanup(self, *, timeout: float) -> None: ...


class ScenarioScope(Protocol):
    def require_device_package(
        self,
        serial: str,
        package: str,
        *,
        action: str | None = None,
    ) -> None: ...

    def require_url(self, value: str) -> None: ...


class ScenarioResolvedValue:
    """Opaque runtime value whose string/repr form cannot expose a secret."""

    __slots__ = ("_fingerprint", "_sensitive", "_value")

    def __init__(
        self,
        value: str,
        *,
        sensitive: bool,
        fingerprint: str | None,
    ) -> None:
        self._value = value
        self._sensitive = sensitive
        self._fingerprint = fingerprint

    @property
    def sensitive(self) -> bool:
        return self._sensitive

    @property
    def fingerprint(self) -> str | None:
        return self._fingerprint

    def reveal_for_input(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return (
            "ScenarioResolvedValue(<redacted>)"
            if self.sensitive
            else "ScenarioResolvedValue(<literal>)"
        )

    def __str__(self) -> str:
        return REDACTED if self.sensitive else self._value


class ScenarioSecretResolver:
    """Resolve explicit references while retaining raw values only in memory."""

    def __init__(
        self,
        variables: Mapping[str, Any] | None = None,
        *,
        session_key: bytes | None = None,
        session_canary: str | None = None,
    ) -> None:
        selected_key = session_key or secrets.token_bytes(32)
        if not isinstance(selected_key, bytes) or len(selected_key) < 16:
            raise ConfigurationError("Scenario correlation key must contain at least 16 bytes.")
        self._session_key = selected_key
        self._variables = _validate_variable_tree(variables or {}, "scenario variables")
        self._session_canary = session_canary
        self._resolved_sensitive: set[str] = set()

    @classmethod
    def from_yaml(
        cls,
        path: Path,
        *,
        root: Path,
        session_key: bytes | None = None,
        session_canary: str | None = None,
    ) -> ScenarioSecretResolver:
        payload = _load_yaml_mapping(path, root=root, label="scenario variables")
        return cls(
            payload,
            session_key=session_key,
            session_canary=session_canary,
        )

    def _fingerprint(self, value: str) -> str:
        digest = hmac.new(self._session_key, value.encode("utf-8"), hashlib.sha256)
        return f"hmac-sha256:{digest.hexdigest()}"

    def _lookup(self, reference: str) -> str:
        current: Any = self._variables
        for part in reference.split("."):
            if not isinstance(current, Mapping) or part not in current:
                raise ConfigurationError(f"Scenario secret reference is missing: {reference}.")
            current = current[part]
        if not isinstance(current, str) or not current:
            raise ConfigurationError(
                f"Scenario secret reference does not resolve to a non-empty string: {reference}."
            )
        return current

    def resolve(self, spec: ScenarioValueSpec) -> ScenarioResolvedValue:
        if spec.kind == "secret_ref":
            if spec.reference is None:
                raise ConfigurationError("Scenario secret reference is missing.")
            value = self._lookup(spec.reference)
            sensitive = True
        elif spec.kind == "session_canary":
            if not self._session_canary:
                raise ConfigurationError("Scenario session canary is unavailable.")
            value = self._session_canary
            sensitive = True
        elif spec.kind == "literal":
            if spec.literal is None:
                raise ConfigurationError("Scenario literal value is missing.")
            value = spec.literal
            sensitive = spec.sensitive
        else:
            raise ConfigurationError("Scenario value kind is unsupported.")
        if not value or len(value) > 512 or any(character in value for character in "\r\n\x00"):
            raise ConfigurationError("Scenario input value is empty, too long, or unsafe.")
        fingerprint = self._fingerprint(value) if sensitive else None
        if sensitive:
            self._resolved_sensitive.add(value)
        return ScenarioResolvedValue(
            value,
            sensitive=sensitive,
            fingerprint=fingerprint,
        )

    def redact(self, value: str) -> str:
        return redact_text_with_values(value, tuple(self._resolved_sensitive))

    def __repr__(self) -> str:
        return "ScenarioSecretResolver(<redacted>)"


@dataclass(frozen=True, slots=True)
class ScenarioStepResult:
    step_id: str
    action: str
    attempted: bool
    completed: bool
    retry_count: int
    timeout_seconds: int
    resolved_selector: Mapping[str, Any] | None
    observed_transition: Mapping[str, Any] | None
    failure_reason: str | None
    evidence_reference: str
    started_at: str | None = None
    ended_at: str | None = None
    pid: int | None = None
    process: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "action": self.action,
            "attempted": self.attempted,
            "completed": self.completed,
            "retry_count": self.retry_count,
            "timeout_seconds": self.timeout_seconds,
            "resolved_selector": (
                dict(self.resolved_selector) if self.resolved_selector is not None else None
            ),
            "observed_transition": (
                dict(self.observed_transition) if self.observed_transition is not None else None
            ),
            "failure_reason": self.failure_reason,
            "evidence_reference": self.evidence_reference,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "pid": self.pid,
            "process": self.process,
        }


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    session_id: str
    scenario_id: str
    package: str
    outcome: ScenarioOutcome
    started_at: str
    ended_at: str
    steps: tuple[ScenarioStepResult, ...]
    verified_pids: tuple[int, ...]
    verified_processes: tuple[str, ...]
    cleanup_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "scenario_id": self.scenario_id,
            "package": self.package,
            "outcome": self.outcome.value,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "steps": [step.to_dict() for step in self.steps],
            "verified_pids": list(self.verified_pids),
            "verified_processes": list(self.verified_processes),
            "cleanup_status": self.cleanup_status,
        }


@dataclass(frozen=True, slots=True)
class _ResolvedSelector:
    node: ScenarioNode | None
    x: int
    y: int
    metadata: Mapping[str, Any]


class _ScenarioPackageEscape(Exception):
    pass


class _StepFailure(Exception):
    def __init__(
        self,
        reason: str,
        outcome: ScenarioOutcome,
        *,
        retry_count: int = 0,
        selector: Mapping[str, Any] | None = None,
        transition: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.outcome = outcome
        self.retry_count = retry_count
        self.selector = selector
        self.transition = transition


class ScenarioLoader:
    """Load strict, bounded profile and scenario YAML below one project root."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def load_profile(self, path: Path) -> ScenarioProfile:
        payload = _load_yaml_mapping(path, root=self.root, label="scenario profile")
        _require_keys(
            payload,
            {
                "schema_version",
                "profile_id",
                "package",
                "launch_activity",
                "selectors",
                "values",
                "transitions",
            "local_backend_url",
            "upstream_backend_url",
            "expected_vulnerability_classes",
            },
            "scenario profile",
        )
        _require_schema_version(payload, "scenario profile")
        profile_id = _safe_id(payload.get("profile_id"), "profile_id")
        try:
            package = validate_package_name(_string(payload.get("package"), "package"))
            launch_activity = _optional_component(
                payload.get("launch_activity"), "launch_activity"
            )
        except AndroidAssessorError as exc:
            raise ConfigurationError("Scenario profile package or activity is invalid.") from exc
        selectors_payload = _mapping(payload.get("selectors", {}), "selectors")
        if len(selectors_payload) > _MAX_SELECTORS:
            raise ConfigurationError("Scenario profile contains too many selectors.")
        selectors = {
            _safe_id(name, "selector name"): _parse_selector(value, str(name))
            for name, value in selectors_payload.items()
        }
        values_payload = _mapping(payload.get("values", {}), "values")
        if len(values_payload) > _MAX_VALUES:
            raise ConfigurationError("Scenario profile contains too many values.")
        values = {
            _safe_id(name, "value name"): _parse_value(value, str(name))
            for name, value in values_payload.items()
        }
        transitions_payload = _mapping(payload.get("transitions", {}), "transitions")
        transitions = {
            _safe_id(name, "transition name"): _parse_transition(value, str(name))
            for name, value in transitions_payload.items()
        }
        backend_url = payload.get("local_backend_url")
        if backend_url is not None:
            backend_url = _bounded_text(backend_url, "local_backend_url", maximum=2048)
        upstream_backend_url = payload.get("upstream_backend_url")
        if upstream_backend_url is not None:
            upstream_backend_url = _bounded_text(
                upstream_backend_url,
                "upstream_backend_url",
                maximum=2048,
            )
        expected = tuple(
            _safe_id(item, "expected vulnerability class")
            for item in _string_list(
                payload.get("expected_vulnerability_classes", []),
                "expected_vulnerability_classes",
            )
        )
        return ScenarioProfile(
            profile_id=profile_id,
            package=package,
            launch_activity=launch_activity,
            selectors=selectors,
            values=values,
            transitions=transitions,
            local_backend_url=backend_url,
            upstream_backend_url=upstream_backend_url,
            expected_vulnerability_classes=expected,
        )

    def load_scenario(self, path: Path) -> ScenarioDefinition:
        payload = _load_yaml_mapping(path, root=self.root, label="scenario definition")
        _require_keys(
            payload,
            {"schema_version", "scenario_id", "total_timeout_seconds", "preconditions", "steps"},
            "scenario definition",
        )
        _require_schema_version(payload, "scenario definition")
        scenario_id = _safe_id(payload.get("scenario_id"), "scenario_id")
        total_timeout = _bounded_int(
            payload.get("total_timeout_seconds"),
            "total_timeout_seconds",
            minimum=1,
            maximum=300,
        )
        preconditions = _mapping(payload.get("preconditions", {}), "preconditions")
        _require_keys(
            preconditions,
            {"network_guard", "required_observers"},
            "scenario preconditions",
        )
        network_guard = preconditions.get("network_guard", False)
        if not isinstance(network_guard, bool):
            raise ConfigurationError("Scenario network_guard must be boolean.")
        required_observers = tuple(
            _observer(item)
            for item in _string_list(
                preconditions.get("required_observers", []),
                "required_observers",
            )
        )
        raw_steps = payload.get("steps")
        if not isinstance(raw_steps, list) or not raw_steps:
            raise ConfigurationError("Scenario steps must be a non-empty list.")
        if len(raw_steps) > _MAX_STEPS:
            raise ConfigurationError("Scenario contains too many steps.")
        steps = tuple(_parse_step(item, index) for index, item in enumerate(raw_steps))
        if len({step.step_id for step in steps}) != len(steps):
            raise ConfigurationError("Scenario step IDs must be unique.")
        if steps[0].action is not ScenarioAction.LAUNCH:
            raise ConfigurationError("Scenario must begin with a launch step.")
        cleanup = [step for step in steps if step.action is ScenarioAction.CLEANUP]
        if len(cleanup) != 1 or steps[-1].action is not ScenarioAction.CLEANUP:
            raise ConfigurationError("Scenario must end with exactly one cleanup step.")
        return ScenarioDefinition(
            scenario_id=scenario_id,
            total_timeout_seconds=total_timeout,
            steps=steps,
            require_network_guard=network_guard,
            required_observers=required_observers,
        )

    def load_bundle(self, profile_path: Path, scenario_path: Path) -> ScenarioBundle:
        bundle = ScenarioBundle(
            self.load_profile(profile_path),
            self.load_scenario(scenario_path),
        )
        _validate_bundle_references(bundle)
        return bundle


class ScenarioRunner:
    """Execute one bounded deterministic scenario without persisting raw values."""

    def __init__(
        self,
        backend: ScenarioBackend,
        *,
        scope: ScenarioScope,
        serial: str,
        package: str,
        session_id: str,
        bundle: ScenarioBundle,
        secrets: ScenarioSecretResolver,
        network_guard_active: bool,
        available_observers: Sequence[str] = (),
        monotonic: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.backend = backend
        self.scope = scope
        self.serial = serial
        self.package = validate_package_name(package)
        self.session_id = session_id
        self.bundle = bundle
        self.secrets = secrets
        self.network_guard_active = network_guard_active
        self.available_observers = frozenset(str(item) for item in available_observers)
        self.monotonic = monotonic
        self.now = now or (lambda: datetime.now(UTC))
        self.sleeper = sleeper
        self._deadline = 0.0
        self._last_observation: ScenarioObservation | None = None
        self._transition_origin: ScenarioObservation | None = None
        self._verified_pids: set[int] = set()
        self._verified_processes: set[str] = set()

    def _timestamp(self) -> str:
        value = self.now()
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()

    def _evidence_reference(self, step: ScenarioStep) -> str:
        return f"scenario:{self.bundle.scenario.scenario_id}:step:{step.step_id}"

    def _remaining_timeout(self, requested: int) -> float:
        remaining = self._deadline - self.monotonic()
        if remaining <= 0:
            raise _StepFailure("scenario_timeout", ScenarioOutcome.FAILED_ACTIVATION)
        return min(float(requested), remaining)

    def _preflight(self) -> None:
        profile = self.bundle.profile
        scenario = self.bundle.scenario
        _validate_bundle_references(self.bundle)
        if profile.package != self.package:
            raise ScopeError("Scenario profile package does not match the assessment target.")
        self.scope.require_device_package(self.serial, self.package, action="inspect")
        if any(step.action.value in _MUTATING_ACTIONS for step in scenario.steps):
            self.scope.require_device_package(
                self.serial,
                self.package,
                action="controlled_validation",
            )
        if profile.local_backend_url is not None:
            self.scope.require_url(profile.local_backend_url)
        if scenario.require_network_guard and not self.network_guard_active:
            raise ConfigurationError("Scenario requires an active scoped network guard.")
        missing_observers = set(scenario.required_observers) - self.available_observers
        requested_observers = {
            observer
            for step in scenario.steps
            if step.action is ScenarioAction.COLLECT_OBSERVATIONS
            for observer in step.observers
        }
        missing_observers.update(requested_observers - self.available_observers)
        if missing_observers:
            raise ConfigurationError("Scenario required observer is unavailable.")

    def _checked_observation(self, timeout: float) -> ScenarioObservation:
        observation = self.backend.observe(timeout=timeout)
        try:
            observed_package = validate_package_name(observation.package)
        except AndroidAssessorError as exc:
            raise _ScenarioPackageEscape from exc
        if observed_package != self.package:
            raise _ScenarioPackageEscape
        if not 1 <= observation.display_width <= _MAX_COORDINATE:
            raise _StepFailure("invalid_display_bounds", ScenarioOutcome.FAILED_ACTIVATION)
        if not 1 <= observation.display_height <= _MAX_COORDINATE:
            raise _StepFailure("invalid_display_bounds", ScenarioOutcome.FAILED_ACTIVATION)
        if observation.pid is not None:
            if isinstance(observation.pid, bool) or observation.pid <= 0:
                raise _ScenarioPackageEscape
            process = observation.process or self.package
            if process != self.package and not process.startswith(self.package + ":"):
                raise _ScenarioPackageEscape
            self._verified_pids.add(observation.pid)
            self._verified_processes.add(process)
        self._last_observation = observation
        return observation

    @staticmethod
    def _selector_metadata(
        selector_ref: str,
        selector: ScenarioSelector,
        strategy: str,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "selector_ref": selector_ref,
            "strategy": strategy,
        }
        if strategy == "resource_id":
            metadata["resource_id"] = selector.resource_id
        elif strategy in {"content_description", "visible_text"}:
            value = (
                selector.content_description
                if strategy == "content_description"
                else selector.visible_text
            )
            metadata["selector_value_sha256"] = hashlib.sha256(
                (value or "").encode("utf-8")
            ).hexdigest()
        elif strategy == "class_index":
            metadata["class_name"] = selector.class_name
            metadata["index"] = selector.index
        elif strategy == "coordinate_fallback" and selector.coordinate_fallback:
            metadata["coordinate"] = {
                "x": selector.coordinate_fallback.x,
                "y": selector.coordinate_fallback.y,
            }
        return metadata

    def _resolve_selector(
        self,
        selector_ref: str,
        observation: ScenarioObservation,
    ) -> tuple[_ResolvedSelector | None, str]:
        selector = self.bundle.profile.selectors[selector_ref]
        nodes = [
            node
            for node in observation.nodes
            if node.enabled
            and node.visible
            and _valid_node_bounds(
                node,
                width=observation.display_width,
                height=observation.display_height,
            )
        ]
        ambiguous = False
        strategies: tuple[tuple[str, str | None, Callable[[ScenarioNode], str]], ...] = (
            ("resource_id", selector.resource_id, lambda node: node.resource_id),
            (
                "content_description",
                selector.content_description,
                lambda node: node.content_description,
            ),
            ("visible_text", selector.visible_text, lambda node: node.visible_text),
        )
        for strategy, expected, accessor in strategies:
            if expected is None:
                continue
            matches = [node for node in nodes if accessor(node) == expected]
            if len(matches) == 1:
                node = matches[0]
                x, y = node.center
                return (
                    _ResolvedSelector(
                        node,
                        x,
                        y,
                        self._selector_metadata(selector_ref, selector, strategy),
                    ),
                    "",
                )
            ambiguous = ambiguous or len(matches) > 1
        if selector.class_name is not None and selector.index is not None:
            matches = [node for node in nodes if node.class_name == selector.class_name]
            if selector.index < len(matches):
                node = matches[selector.index]
                x, y = node.center
                return (
                    _ResolvedSelector(
                        node,
                        x,
                        y,
                        self._selector_metadata(selector_ref, selector, "class_index"),
                    ),
                    "",
                )
        fallback = selector.coordinate_fallback
        if fallback is not None:
            if fallback.x >= observation.display_width or fallback.y >= observation.display_height:
                return None, "coordinate_out_of_bounds"
            return (
                _ResolvedSelector(
                    None,
                    fallback.x,
                    fallback.y,
                    self._selector_metadata(selector_ref, selector, "coordinate_fallback"),
                ),
                "",
            )
        return None, "selector_ambiguous" if ambiguous else "selector_missing"

    def _transition_metadata(
        self,
        before: ScenarioObservation | None,
        after: ScenarioObservation,
    ) -> dict[str, Any]:
        return {
            "from_activity": before.activity if before is not None else None,
            "to_activity": after.activity,
            "from_pid": before.pid if before is not None else None,
            "to_pid": after.pid,
            "from_process": before.process if before is not None else None,
            "to_process": after.process,
            "package": self.package,
        }

    def _step_identity(self) -> dict[str, Any]:
        observation = self._last_observation
        return {
            "pid": observation.pid if observation is not None else None,
            "process": observation.process if observation is not None else None,
        }

    def _run_launch(self, step: ScenarioStep) -> tuple[None, Mapping[str, Any], int, str]:
        timeout = self._remaining_timeout(step.timeout_seconds)
        try:
            self.backend.launch(self.bundle.profile.launch_activity, timeout=timeout)
        except (AdbTimeoutError, TimeoutError) as exc:
            raise _StepFailure("mutation_timeout_unknown", ScenarioOutcome.TIMEOUT_UNKNOWN) from exc
        except ScopeError as exc:
            raise _StepFailure("scope_denied", ScenarioOutcome.OUT_OF_SCOPE) from exc
        except (AndroidAssessorError, OSError, ValueError) as exc:
            raise _StepFailure("launch_failed", ScenarioOutcome.FAILED_ACTIVATION) from exc
        except Exception as exc:
            raise _StepFailure("launch_failed", ScenarioOutcome.FAILED_ACTIVATION) from exc
        try:
            observation = self._checked_observation(
                self._remaining_timeout(step.timeout_seconds)
            )
        except (AdbTimeoutError, TimeoutError) as exc:
            raise _StepFailure(
                "launch_observation_timeout",
                ScenarioOutcome.FAILED_ACTIVATION,
            ) from exc
        expected = step.expected_activity or self.bundle.profile.launch_activity
        transition = self._transition_metadata(None, observation)
        if expected is not None and observation.activity != expected:
            raise _StepFailure(
                "launch_transition_mismatch",
                ScenarioOutcome.FAILED_ACTIVATION,
                transition=transition,
            )
        self._transition_origin = observation
        return None, transition, 0, self._evidence_reference(step)

    def _wait_for_selector(
        self,
        step: ScenarioStep,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any], int, str]:
        assert step.selector_ref is not None
        last_reason = "selector_missing"
        for attempt in range(step.max_read_retries + 1):
            try:
                observation = self._checked_observation(
                    self._remaining_timeout(step.timeout_seconds)
                )
                resolved, last_reason = self._resolve_selector(step.selector_ref, observation)
            except _ScenarioPackageEscape:
                raise
            except (AdbTimeoutError, TimeoutError):
                resolved = None
                last_reason = "read_timeout"
            if resolved is not None:
                return (
                    resolved.metadata,
                    self._transition_metadata(self._transition_origin, observation),
                    attempt,
                    self._evidence_reference(step),
                )
        raise _StepFailure(
            last_reason,
            ScenarioOutcome.FAILED_ACTIVATION,
            retry_count=step.max_read_retries,
        )

    def _current_selector(self, step: ScenarioStep) -> _ResolvedSelector:
        assert step.selector_ref is not None
        try:
            observation = self._checked_observation(
                self._remaining_timeout(step.timeout_seconds)
            )
        except (AdbTimeoutError, TimeoutError) as exc:
            raise _StepFailure(
                "pre_mutation_observation_timeout",
                ScenarioOutcome.FAILED_ACTIVATION,
            ) from exc
        resolved, reason = self._resolve_selector(step.selector_ref, observation)
        if resolved is None:
            raise _StepFailure(reason, ScenarioOutcome.FAILED_ACTIVATION)
        self._transition_origin = observation
        return resolved

    def _run_input(self, step: ScenarioStep) -> tuple[Mapping[str, Any], None, int, str]:
        assert step.value_ref is not None
        resolved = self._current_selector(step)
        if resolved.node is None:
            raise _StepFailure(
                "coordinate_input_forbidden",
                ScenarioOutcome.FAILED_ACTIVATION,
                selector=resolved.metadata,
            )
        if not resolved.node.editable:
            raise _StepFailure(
                "selector_not_editable",
                ScenarioOutcome.FAILED_ACTIVATION,
                selector=resolved.metadata,
            )
        try:
            value = self.secrets.resolve(self.bundle.profile.values[step.value_ref])
        except ConfigurationError as exc:
            raise _StepFailure(
                "input_value_unavailable",
                ScenarioOutcome.FAILED_PRECONDITION,
                selector=resolved.metadata,
            ) from exc
        raw_value = value.reveal_for_input()
        try:
            self.backend.input_text(
                resolved.x,
                resolved.y,
                raw_value,
                timeout=self._remaining_timeout(step.timeout_seconds),
                sensitive_values=(raw_value,) if value.sensitive else (),
            )
        except (AdbTimeoutError, TimeoutError) as exc:
            raise _StepFailure(
                "mutation_timeout_unknown",
                ScenarioOutcome.TIMEOUT_UNKNOWN,
                selector=resolved.metadata,
            ) from exc
        except ScopeError as exc:
            raise _StepFailure(
                "scope_denied",
                ScenarioOutcome.OUT_OF_SCOPE,
                selector=resolved.metadata,
            ) from exc
        except (AndroidAssessorError, OSError, ValueError) as exc:
            raise _StepFailure(
                "input_failed",
                ScenarioOutcome.FAILED_ACTIVATION,
                selector=resolved.metadata,
            ) from exc
        except Exception as exc:
            raise _StepFailure(
                "input_failed",
                ScenarioOutcome.FAILED_ACTIVATION,
                selector=resolved.metadata,
            ) from exc
        return resolved.metadata, None, 0, self._evidence_reference(step)

    def _run_click(self, step: ScenarioStep) -> tuple[Mapping[str, Any], None, int, str]:
        resolved = self._current_selector(step)
        if resolved.node is not None and not resolved.node.clickable:
            raise _StepFailure(
                "selector_not_clickable",
                ScenarioOutcome.FAILED_ACTIVATION,
                selector=resolved.metadata,
            )
        try:
            self.backend.click(
                resolved.x,
                resolved.y,
                timeout=self._remaining_timeout(step.timeout_seconds),
            )
        except (AdbTimeoutError, TimeoutError) as exc:
            raise _StepFailure(
                "mutation_timeout_unknown",
                ScenarioOutcome.TIMEOUT_UNKNOWN,
                selector=resolved.metadata,
            ) from exc
        except ScopeError as exc:
            raise _StepFailure(
                "scope_denied",
                ScenarioOutcome.OUT_OF_SCOPE,
                selector=resolved.metadata,
            ) from exc
        except (AndroidAssessorError, OSError, ValueError) as exc:
            raise _StepFailure(
                "click_failed",
                ScenarioOutcome.FAILED_ACTIVATION,
                selector=resolved.metadata,
            ) from exc
        except Exception as exc:
            raise _StepFailure(
                "click_failed",
                ScenarioOutcome.FAILED_ACTIVATION,
                selector=resolved.metadata,
            ) from exc
        return resolved.metadata, None, 0, self._evidence_reference(step)

    def _expected_transition(self, step: ScenarioStep) -> ScenarioTransition:
        if step.transition_ref is not None:
            return self.bundle.profile.transitions[step.transition_ref]
        return ScenarioTransition(activity=step.expected_activity)

    def _wait_before_read_retry(self, step: ScenarioStep, attempt: int) -> None:
        """Allow a bounded asynchronous activity transition to settle."""

        if attempt >= step.max_read_retries:
            return
        self.sleeper(min(0.25, self._remaining_timeout(step.timeout_seconds)))

    def _run_wait_transition(
        self,
        step: ScenarioStep,
    ) -> tuple[Mapping[str, Any] | None, Mapping[str, Any], int, str]:
        expected = self._expected_transition(step)
        last_transition: Mapping[str, Any] | None = None
        selector_metadata: Mapping[str, Any] | None = None
        failure_reason = "transition_timeout"
        for attempt in range(step.max_read_retries + 1):
            try:
                observation = self._checked_observation(
                    self._remaining_timeout(step.timeout_seconds)
                )
            except _ScenarioPackageEscape:
                raise
            except (AdbTimeoutError, TimeoutError):
                failure_reason = "transition_observation_timeout"
                self._wait_before_read_retry(step, attempt)
                continue
            except ScopeError as exc:
                raise _StepFailure(
                    "scope_denied",
                    ScenarioOutcome.OUT_OF_SCOPE,
                    retry_count=attempt,
                ) from exc
            except (AndroidAssessorError, OSError, ValueError):
                failure_reason = "transition_observation_unavailable"
                self._wait_before_read_retry(step, attempt)
                continue
            last_transition = self._transition_metadata(self._transition_origin, observation)
            activity_matches = (
                expected.activity is None or observation.activity == expected.activity
            )
            selector_matches = expected.selector_ref is None
            if expected.selector_ref is not None:
                resolved, _reason = self._resolve_selector(
                    expected.selector_ref,
                    observation,
                )
                selector_matches = resolved is not None
                selector_metadata = resolved.metadata if resolved is not None else None
            if activity_matches and selector_matches:
                self._transition_origin = observation
                return (
                    selector_metadata,
                    last_transition,
                    attempt,
                    self._evidence_reference(step),
                )
            self._wait_before_read_retry(step, attempt)
        raise _StepFailure(
            failure_reason,
            ScenarioOutcome.FAILED_ACTIVATION,
            retry_count=step.max_read_retries,
            transition=last_transition,
        )

    def _run_collect(
        self,
        step: ScenarioStep,
    ) -> tuple[None, Mapping[str, Any], int, str]:
        for attempt in range(step.max_read_retries + 1):
            try:
                collection = self.backend.collect_observations(
                    step.observers,
                    scenario_id=self.bundle.scenario.scenario_id,
                    step_id=step.step_id,
                    timeout=self._remaining_timeout(step.timeout_seconds),
                )
            except (AdbTimeoutError, TimeoutError):
                if attempt < step.max_read_retries:
                    continue
                raise _StepFailure(
                    "observation_timeout",
                    ScenarioOutcome.PARTIAL,
                    retry_count=attempt,
                ) from None
            except (AndroidAssessorError, OSError, ValueError) as exc:
                raise _StepFailure(
                    "observation_failed",
                    ScenarioOutcome.PARTIAL,
                    retry_count=attempt,
                ) from exc
            except Exception as exc:
                raise _StepFailure(
                    "observation_failed",
                    ScenarioOutcome.PARTIAL,
                    retry_count=attempt,
                ) from exc
            if not isinstance(collection, ScenarioCollection):
                raise _StepFailure("invalid_observation", ScenarioOutcome.PARTIAL)
            try:
                categories = tuple(
                    sorted(
                        {
                            _safe_id(item, "observed category")
                            for item in collection.observed_categories
                        }
                    )
                )
            except ConfigurationError as exc:
                raise _StepFailure("invalid_observation", ScenarioOutcome.PARTIAL) from exc
            references = tuple(
                item
                for item in collection.evidence_references
                if isinstance(item, str) and _SAFE_REFERENCE.fullmatch(item)
            )
            evidence_reference = (
                references[0] if references else self._evidence_reference(step)
            )
            return (
                None,
                {
                    "observers": list(step.observers),
                    "observed_categories": list(categories),
                },
                attempt,
                evidence_reference,
            )
        raise AssertionError("unreachable")

    def _execute_step(
        self,
        step: ScenarioStep,
    ) -> tuple[Mapping[str, Any] | None, Mapping[str, Any] | None, int, str]:
        if step.action is ScenarioAction.LAUNCH:
            return self._run_launch(step)
        if step.action is ScenarioAction.WAIT_FOR:
            return self._wait_for_selector(step)
        if step.action is ScenarioAction.INPUT:
            return self._run_input(step)
        if step.action is ScenarioAction.CLICK:
            return self._run_click(step)
        if step.action is ScenarioAction.WAIT_FOR_TRANSITION:
            return self._run_wait_transition(step)
        if step.action is ScenarioAction.COLLECT_OBSERVATIONS:
            return self._run_collect(step)
        raise _StepFailure("unsupported_action", ScenarioOutcome.FAILED_PRECONDITION)

    def _cleanup_result(self, step: ScenarioStep) -> tuple[ScenarioStepResult, str]:
        started = self._timestamp()
        try:
            # Cleanup has its own hard bound and must still run if the scenario
            # activation budget was exhausted.
            self.backend.cleanup(timeout=float(step.timeout_seconds))
        except Exception:
            return (
                ScenarioStepResult(
                    step_id=step.step_id,
                    action=step.action.value,
                    attempted=True,
                    completed=False,
                    retry_count=0,
                    timeout_seconds=step.timeout_seconds,
                    resolved_selector=None,
                    observed_transition=None,
                    failure_reason="cleanup_failed",
                    evidence_reference=self._evidence_reference(step),
                    started_at=started,
                    ended_at=self._timestamp(),
                    **self._step_identity(),
                ),
                "failed",
            )
        return (
            ScenarioStepResult(
                step_id=step.step_id,
                action=step.action.value,
                attempted=True,
                completed=True,
                retry_count=0,
                timeout_seconds=step.timeout_seconds,
                resolved_selector=None,
                observed_transition=None,
                failure_reason=None,
                evidence_reference=self._evidence_reference(step),
                started_at=started,
                ended_at=self._timestamp(),
                **self._step_identity(),
            ),
            "completed",
        )

    def _not_reached(
        self,
        step: ScenarioStep,
        reason: str = "not_reached",
    ) -> ScenarioStepResult:
        return ScenarioStepResult(
            step_id=step.step_id,
            action=step.action.value,
            attempted=False,
            completed=False,
            retry_count=0,
            timeout_seconds=step.timeout_seconds,
            resolved_selector=None,
            observed_transition=None,
            failure_reason=reason,
            evidence_reference=self._evidence_reference(step),
        )

    def run(self) -> ScenarioResult:
        scenario = self.bundle.scenario
        started_at = self._timestamp()
        self._deadline = self.monotonic() + scenario.total_timeout_seconds
        results: dict[str, ScenarioStepResult] = {}
        outcome = ScenarioOutcome.COMPLETED
        backend_activated = False
        cleanup_status = "not_required"
        try:
            try:
                self._preflight()
            except ScopeError:
                outcome = ScenarioOutcome.OUT_OF_SCOPE
                first = scenario.steps[0]
                results[first.step_id] = self._not_reached(first, "scope_denied")
                return self._result(
                    started_at,
                    outcome,
                    results,
                    cleanup_status,
                )
            except (AndroidAssessorError, ValueError):
                outcome = ScenarioOutcome.FAILED_PRECONDITION
                first = scenario.steps[0]
                results[first.step_id] = self._not_reached(
                    first,
                    "precondition_failed",
                )
                return self._result(
                    started_at,
                    outcome,
                    results,
                    cleanup_status,
                )
            except Exception:
                outcome = ScenarioOutcome.FAILED_PRECONDITION
                first = scenario.steps[0]
                results[first.step_id] = self._not_reached(
                    first,
                    "precondition_failed",
                )
                return self._result(
                    started_at,
                    outcome,
                    results,
                    cleanup_status,
                )
            backend_activated = True
            for step in scenario.steps[:-1]:
                step_started = self._timestamp()
                try:
                    selector, transition, retries, evidence = self._execute_step(step)
                except _ScenarioPackageEscape:
                    outcome = ScenarioOutcome.OUT_OF_SCOPE
                    results[step.step_id] = ScenarioStepResult(
                        step_id=step.step_id,
                        action=step.action.value,
                        attempted=True,
                        completed=False,
                        retry_count=0,
                        timeout_seconds=step.timeout_seconds,
                        resolved_selector=None,
                        observed_transition=None,
                        failure_reason="package_escape",
                        evidence_reference=self._evidence_reference(step),
                        started_at=step_started,
                        ended_at=self._timestamp(),
                        **self._step_identity(),
                    )
                    break
                except _StepFailure as failure:
                    outcome = failure.outcome
                    results[step.step_id] = ScenarioStepResult(
                        step_id=step.step_id,
                        action=step.action.value,
                        attempted=True,
                        completed=False,
                        retry_count=failure.retry_count,
                        timeout_seconds=step.timeout_seconds,
                        resolved_selector=failure.selector,
                        observed_transition=failure.transition,
                        failure_reason=failure.reason,
                        evidence_reference=self._evidence_reference(step),
                        started_at=step_started,
                        ended_at=self._timestamp(),
                        **self._step_identity(),
                    )
                    break
                except Exception:
                    outcome = ScenarioOutcome.FAILED_ACTIVATION
                    results[step.step_id] = ScenarioStepResult(
                        step_id=step.step_id,
                        action=step.action.value,
                        attempted=True,
                        completed=False,
                        retry_count=0,
                        timeout_seconds=step.timeout_seconds,
                        resolved_selector=None,
                        observed_transition=None,
                        failure_reason="backend_error",
                        evidence_reference=self._evidence_reference(step),
                        started_at=step_started,
                        ended_at=self._timestamp(),
                        **self._step_identity(),
                    )
                    break
                results[step.step_id] = ScenarioStepResult(
                    step_id=step.step_id,
                    action=step.action.value,
                    attempted=True,
                    completed=True,
                    retry_count=retries,
                    timeout_seconds=step.timeout_seconds,
                    resolved_selector=selector,
                    observed_transition=transition,
                    failure_reason=None,
                    evidence_reference=evidence,
                    started_at=step_started,
                    ended_at=self._timestamp(),
                    **self._step_identity(),
                )
        finally:
            cleanup_step = scenario.steps[-1]
            if backend_activated:
                cleanup_result, cleanup_status = self._cleanup_result(cleanup_step)
                results[cleanup_step.step_id] = cleanup_result
                if cleanup_status == "failed" and outcome is ScenarioOutcome.COMPLETED:
                    outcome = ScenarioOutcome.PARTIAL
        return self._result(started_at, outcome, results, cleanup_status)

    def _result(
        self,
        started_at: str,
        outcome: ScenarioOutcome,
        results: Mapping[str, ScenarioStepResult],
        cleanup_status: str,
    ) -> ScenarioResult:
        ordered = tuple(
            results.get(step.step_id, self._not_reached(step))
            for step in self.bundle.scenario.steps
        )
        return ScenarioResult(
            session_id=self.session_id,
            scenario_id=self.bundle.scenario.scenario_id,
            package=self.package,
            outcome=outcome,
            started_at=started_at,
            ended_at=self._timestamp(),
            steps=ordered,
            verified_pids=tuple(sorted(self._verified_pids)),
            verified_processes=tuple(sorted(self._verified_processes)),
            cleanup_status=cleanup_status,
        )


def _load_yaml_mapping(path: Path, *, root: Path, label: str) -> dict[str, Any]:
    target = path.resolve()
    selected_root = root.resolve()
    if not target.is_relative_to(selected_root):
        raise ConfigurationError(f"{label.capitalize()} path is outside the project root.")
    try:
        if target.stat().st_size > _MAX_YAML_BYTES:
            raise ConfigurationError(f"{label.capitalize()} exceeds the YAML size limit.")
        payload = yaml.safe_load(target.read_text(encoding="utf-8"))
    except ConfigurationError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Could not load {label}.") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError(f"{label.capitalize()} must be a YAML mapping.")
    return {str(key): value for key, value in payload.items()}


def _validate_variable_tree(value: Any, label: str, *, depth: int = 0) -> dict[str, Any]:
    if depth > 8 or not isinstance(value, Mapping):
        raise ConfigurationError(f"{label.capitalize()} must contain bounded mappings.")
    output: dict[str, Any] = {}
    if len(value) > 100:
        raise ConfigurationError(f"{label.capitalize()} contains too many entries.")
    for raw_key, item in value.items():
        key = str(raw_key)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key):
            raise ConfigurationError(f"{label.capitalize()} contains an invalid key.")
        if isinstance(item, Mapping):
            output[key] = _validate_variable_tree(item, label, depth=depth + 1)
        elif isinstance(item, str) and 0 < len(item) <= 512 and not any(
            character in item for character in "\r\n\x00"
        ):
            output[key] = item
        else:
            raise ConfigurationError(
                f"{label.capitalize()} values must be bounded non-empty strings."
            )
    return output


def _require_keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigurationError(
            f"{label.capitalize()} contains unsupported keys: {', '.join(unknown)}."
        )


def _require_schema_version(value: Mapping[str, Any], label: str) -> None:
    if value.get("schema_version") != 1:
        raise ConfigurationError(f"{label.capitalize()} schema_version must be 1.")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label.capitalize()} must be a mapping.")
    return {str(key): item for key, item in value.items()}


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{label.capitalize()} must be a non-empty string.")
    return value.strip()


def _bounded_text(value: Any, label: str, *, maximum: int = _MAX_TEXT_CHARS) -> str:
    text = _string(value, label)
    if len(text) > maximum or any(character in text for character in "\r\n\x00"):
        raise ConfigurationError(f"{label.capitalize()} is too long or contains unsafe characters.")
    return text


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"{label.capitalize()} must be a list of strings.")
    return list(value)


def _bounded_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigurationError(
            f"{label.capitalize()} must be an integer between {minimum} and {maximum}."
        )
    return value


def _safe_id(value: Any, label: str) -> str:
    text = _string(value, label)
    if not _SAFE_ID.fullmatch(text):
        raise ConfigurationError(f"{label.capitalize()} is invalid.")
    return text


def _reference(value: Any, label: str) -> str:
    text = _string(value, label)
    if not _SAFE_REFERENCE.fullmatch(text):
        raise ConfigurationError(f"{label.capitalize()} is invalid.")
    return text


def _optional_component(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return validate_component_name(_string(value, label))


def _observer(value: str) -> str:
    observer = value.strip()
    if observer not in _OBSERVERS:
        raise ConfigurationError(f"Unsupported scenario observer: {observer}.")
    return observer


def _valid_node_bounds(
    node: ScenarioNode,
    *,
    width: int,
    height: int,
) -> bool:
    left, top, right, bottom = node.bounds
    return 0 <= left < right <= width and 0 <= top < bottom <= height


def _parse_selector(value: Any, name: str) -> ScenarioSelector:
    payload = _mapping(value, f"selector {name}")
    _require_keys(
        payload,
        {
            "resource_id",
            "content_description",
            "visible_text",
            "class_name",
            "index",
            "coordinate_fallback",
        },
        f"selector {name}",
    )
    resource_id = payload.get("resource_id")
    if resource_id is not None:
        resource_id = _bounded_text(resource_id, f"selector {name} resource_id", maximum=255)
        if not _SAFE_RESOURCE_ID.fullmatch(resource_id):
            raise ConfigurationError(f"Selector {name} resource_id is invalid.")
    description = payload.get("content_description")
    if description is not None:
        description = _bounded_text(description, f"selector {name} content_description")
    visible_text = payload.get("visible_text")
    if visible_text is not None:
        visible_text = _bounded_text(visible_text, f"selector {name} visible_text")
    class_name = payload.get("class_name")
    index = payload.get("index")
    if (class_name is None) != (index is None):
        raise ConfigurationError(f"Selector {name} class_name and index must be paired.")
    if class_name is not None:
        class_name = _bounded_text(class_name, f"selector {name} class_name", maximum=255)
        if not _SAFE_CLASS.fullmatch(class_name):
            raise ConfigurationError(f"Selector {name} class_name is invalid.")
        index = _bounded_int(index, f"selector {name} index", minimum=0, maximum=99)
    coordinate = payload.get("coordinate_fallback")
    parsed_coordinate = None
    if coordinate is not None:
        coordinate_payload = _mapping(coordinate, f"selector {name} coordinate_fallback")
        _require_keys(
            coordinate_payload,
            {"x", "y"},
            f"selector {name} coordinate_fallback",
        )
        parsed_coordinate = ScenarioCoordinate(
            _bounded_int(
                coordinate_payload.get("x"),
                f"selector {name} x",
                minimum=0,
                maximum=_MAX_COORDINATE,
            ),
            _bounded_int(
                coordinate_payload.get("y"),
                f"selector {name} y",
                minimum=0,
                maximum=_MAX_COORDINATE,
            ),
        )
    if not any(
        item is not None
        for item in (resource_id, description, visible_text, class_name, parsed_coordinate)
    ):
        raise ConfigurationError(f"Selector {name} has no resolution strategy.")
    return ScenarioSelector(
        resource_id=resource_id,
        content_description=description,
        visible_text=visible_text,
        class_name=class_name,
        index=index,
        coordinate_fallback=parsed_coordinate,
    )


def _parse_value(value: Any, name: str) -> ScenarioValueSpec:
    payload = _mapping(value, f"value {name}")
    _require_keys(
        payload,
        {"secret_ref", "literal", "session_canary", "sensitive"},
        f"value {name}",
    )
    kinds = [
        key
        for key in ("secret_ref", "literal", "session_canary")
        if key in payload
    ]
    if len(kinds) != 1:
        raise ConfigurationError(f"Value {name} must define exactly one value source.")
    kind = kinds[0]
    sensitive = payload.get("sensitive", kind != "literal")
    if not isinstance(sensitive, bool):
        raise ConfigurationError(f"Value {name} sensitive flag must be boolean.")
    if kind in {"secret_ref", "session_canary"} and not sensitive:
        raise ConfigurationError(f"Value {name} protected sources must remain sensitive.")
    if kind == "secret_ref":
        return ScenarioValueSpec(
            kind=kind,
            reference=_reference(payload[kind], f"value {name} secret_ref"),
            sensitive=True,
        )
    if kind == "session_canary":
        if payload[kind] is not True:
            raise ConfigurationError(f"Value {name} session_canary must be true.")
        return ScenarioValueSpec(kind=kind, sensitive=True)
    if sensitive:
        raise ConfigurationError(
            f"Value {name} sensitive literals are forbidden; use secret_ref."
        )
    return ScenarioValueSpec(
        kind=kind,
        literal=_bounded_text(payload[kind], f"value {name} literal"),
        sensitive=False,
    )


def _parse_transition(value: Any, name: str) -> ScenarioTransition:
    payload = _mapping(value, f"transition {name}")
    _require_keys(payload, {"activity", "selector_ref"}, f"transition {name}")
    try:
        activity = _optional_component(payload.get("activity"), f"transition {name} activity")
    except AndroidAssessorError as exc:
        raise ConfigurationError(f"Transition {name} activity is invalid.") from exc
    selector_ref = payload.get("selector_ref")
    if selector_ref is not None:
        selector_ref = _safe_id(selector_ref, f"transition {name} selector_ref")
    if activity is None and selector_ref is None:
        raise ConfigurationError(f"Transition {name} has no expected state.")
    return ScenarioTransition(activity, selector_ref)


def _parse_step(value: Any, index: int) -> ScenarioStep:
    payload = _mapping(value, f"step {index}")
    _require_keys(
        payload,
        {
            "id",
            "action",
            "timeout_seconds",
            "selector_ref",
            "value_ref",
            "expected_activity",
            "transition_ref",
            "observers",
            "max_read_retries",
        },
        f"step {index}",
    )
    step_id = _safe_id(payload.get("id"), f"step {index} id")
    try:
        action = ScenarioAction(_string(payload.get("action"), f"step {step_id} action"))
    except ValueError as exc:
        raise ConfigurationError(f"Step {step_id} action is unsupported.") from exc
    timeout = _bounded_int(
        payload.get("timeout_seconds"),
        f"step {step_id} timeout_seconds",
        minimum=1,
        maximum=30,
    )
    retries = _bounded_int(
        payload.get("max_read_retries", 0),
        f"step {step_id} max_read_retries",
        minimum=0,
        maximum=3,
    )
    if action.value not in _READ_ONLY_ACTIONS and retries:
        raise ConfigurationError(f"Step {step_id} retries are only valid for read-only actions.")
    selector_ref = payload.get("selector_ref")
    if selector_ref is not None:
        selector_ref = _safe_id(selector_ref, f"step {step_id} selector_ref")
    value_ref = payload.get("value_ref")
    if value_ref is not None:
        value_ref = _safe_id(value_ref, f"step {step_id} value_ref")
    transition_ref = payload.get("transition_ref")
    if transition_ref is not None:
        transition_ref = _safe_id(transition_ref, f"step {step_id} transition_ref")
    try:
        expected_activity = _optional_component(
            payload.get("expected_activity"),
            f"step {step_id} expected_activity",
        )
    except AndroidAssessorError as exc:
        raise ConfigurationError(f"Step {step_id} expected_activity is invalid.") from exc
    observers = tuple(
        _observer(item)
        for item in _string_list(payload.get("observers", []), f"step {step_id} observers")
    )
    if action in {ScenarioAction.WAIT_FOR, ScenarioAction.INPUT, ScenarioAction.CLICK}:
        if selector_ref is None:
            raise ConfigurationError(f"Step {step_id} requires selector_ref.")
    elif selector_ref is not None:
        raise ConfigurationError(f"Step {step_id} does not support selector_ref.")
    if action is ScenarioAction.INPUT:
        if value_ref is None:
            raise ConfigurationError(f"Step {step_id} requires value_ref.")
    elif value_ref is not None:
        raise ConfigurationError(f"Step {step_id} does not support value_ref.")
    if action is ScenarioAction.WAIT_FOR_TRANSITION:
        if (transition_ref is None) == (expected_activity is None):
            raise ConfigurationError(
                f"Step {step_id} requires exactly one of transition_ref or "
                "expected_activity."
            )
    elif transition_ref is not None:
        raise ConfigurationError(f"Step {step_id} does not support transition_ref.")
    if action not in {
        ScenarioAction.LAUNCH,
        ScenarioAction.WAIT_FOR_TRANSITION,
    } and expected_activity is not None:
        raise ConfigurationError(f"Step {step_id} does not support expected_activity.")
    if action is ScenarioAction.COLLECT_OBSERVATIONS:
        if not observers:
            raise ConfigurationError(f"Step {step_id} requires observers.")
    elif observers:
        raise ConfigurationError(f"Step {step_id} does not support observers.")
    return ScenarioStep(
        step_id=step_id,
        action=action,
        timeout_seconds=timeout,
        selector_ref=selector_ref,
        value_ref=value_ref,
        expected_activity=expected_activity,
        transition_ref=transition_ref,
        observers=observers,
        max_read_retries=retries,
    )


def _validate_bundle_references(bundle: ScenarioBundle) -> None:
    profile = bundle.profile
    steps = bundle.scenario.steps
    if not steps or steps[0].action is not ScenarioAction.LAUNCH:
        raise ConfigurationError("Scenario must begin with a launch step.")
    cleanup = [step for step in steps if step.action is ScenarioAction.CLEANUP]
    if len(cleanup) != 1 or steps[-1].action is not ScenarioAction.CLEANUP:
        raise ConfigurationError("Scenario must end with exactly one cleanup step.")
    for transition_name, transition in profile.transitions.items():
        if transition.selector_ref is not None and transition.selector_ref not in profile.selectors:
            raise ConfigurationError(
                f"Transition {transition_name} references an unknown selector."
            )
    for step in bundle.scenario.steps:
        if step.selector_ref is not None and step.selector_ref not in profile.selectors:
            raise ConfigurationError(f"Step {step.step_id} references an unknown selector.")
        if step.value_ref is not None and step.value_ref not in profile.values:
            raise ConfigurationError(f"Step {step.step_id} references an unknown value.")
        if step.transition_ref is not None and step.transition_ref not in profile.transitions:
            raise ConfigurationError(f"Step {step.step_id} references an unknown transition.")
