"""Generic candidate-driven micro-scenario activation for unattended scans.

The planner deliberately separates candidate selection from route execution.  It
uses only normalized manifest/static/runtime metadata and the currently visible
UI; no benchmark package, selector, credential, or backend is embedded here.
Sensitive values live in memory for the duration of the bounded run and are
represented on disk only by HMAC fingerprints, type, and length.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlunsplit

from .errors import AndroidAssessorError, ScopeError
from .explorer import AdbExplorerBackend
from .scenario import (
    ScenarioAction,
    ScenarioBackend,
    ScenarioBundle,
    ScenarioDefinition,
    ScenarioNode,
    ScenarioObservation,
    ScenarioOutcome,
    ScenarioProfile,
    ScenarioResult,
    ScenarioRunner,
    ScenarioSecretResolver,
    ScenarioSelector,
    ScenarioStep,
    ScenarioTransition,
    ScenarioValueSpec,
)
from .scope import ScopeConfig
from .services.scenario_service import AdbScenarioBackend, ScenarioService
from .session import SessionRecord
from .validation import validate_package_name

_DANGEROUS_ACTION_MARKERS = (
    "delete",
    "remove",
    "purchase",
    "pay",
    "transfer",
    "send money",
    "factory reset",
    "uninstall",
    "logout all",
    "submit order",
    "register",
    "sign up",
    "create account",
    "change password",
    "reset password",
    "update password",
    "deposit",
    "withdraw",
    "send sms",
    "place call",
    "dial",
)
_ACTION_MARKERS = (
    "login",
    "sign in",
    "authenticate",
    "connect",
    "request",
    "search",
    "lookup",
    "check",
    "save",
    "encrypt",
    "decrypt",
    "hash",
    "digest",
    "crypto",
    "log",
    "storage",
)
_INPUT_MARKERS = {
    "username": ("user", "login", "account"),
    "password": ("password", "passwd", "pin", "secret"),
    "email": ("email", "mail"),
    "token": ("token", "canary", "credential", "auth"),
    "url": ("url", "uri", "host", "server", "web"),
    "text": ("text", "message", "query", "input"),
}
_OUTPUT_MARKERS = (
    "result",
    "output",
    "digest",
    "hash_result",
    "ciphertext",
    "response",
    "status",
)
_CLASS_TO_CATEGORY = {
    "sensitive_logging": "logging",
    "logging": "logging",
    "cleartext_transport": "cleartext",
    "cleartext": "cleartext",
    "sensitive_local_storage": "storage",
    "storage": "storage",
    "weak_cryptography": "crypto",
    "cryptography": "crypto",
    "crypto": "crypto",
}


@dataclass(frozen=True, slots=True)
class MicroScenarioSeed:
    session_id: str
    scenario_id: str
    package: str
    launcher_activity: str | None
    candidate_classes: tuple[str, ...]
    candidate_reasons: Mapping[str, tuple[str, ...]]
    value_specs: Mapping[str, ScenarioValueSpec]
    resolver: ScenarioSecretResolver
    owned_values: Mapping[str, str]
    owned_value_metadata: tuple[Mapping[str, Any], ...]
    canary_fingerprint: str | None
    upstream_mapping: Mapping[str, str]
    activation_quota: int = 4
    sink_verification_quota: int = 8
    timeout_seconds: int = 36


@dataclass(frozen=True, slots=True)
class MicroScenarioPlan:
    bundle: ScenarioBundle
    resolver: ScenarioSecretResolver
    owned_values: Mapping[str, str]
    upstream_mapping: Mapping[str, str]
    owned_value_metadata: tuple[Mapping[str, Any], ...]
    canary_fingerprint: str | None
    candidate_classes: tuple[str, ...]
    route: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class MicroScenarioExecution:
    seed: MicroScenarioSeed
    plan: MicroScenarioPlan | None
    result: ScenarioResult | None
    outcome: str
    reason: str | None

    @property
    def completed(self) -> bool:
        return bool(self.result is not None and self.result.outcome is ScenarioOutcome.COMPLETED)

    def to_dict(self) -> dict[str, Any]:
        result = self.result.to_dict() if self.result is not None else None
        return {
            "schema_version": 1,
            "scenario_id": self.seed.scenario_id,
            "package": self.seed.package,
            "outcome": self.outcome,
            "reason": self.reason,
            "candidate_classes": list(self.seed.candidate_classes),
            "candidate_reasons": {
                key: list(value) for key, value in self.seed.candidate_reasons.items()
            },
            "owned_value_metadata": [dict(item) for item in self.seed.owned_value_metadata],
            "canary_fingerprint": self.seed.canary_fingerprint,
            "activation_quota": self.seed.activation_quota,
            "sink_verification_quota": self.seed.sink_verification_quota,
            "scoped_upstream_mapping": dict(self.seed.upstream_mapping),
            "route": dict(self.plan.route) if self.plan is not None else None,
            "result": result,
            "redaction": "raw values are retained only in memory during bounded execution",
        }


def _safe_identifier(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_.-")
    return normalized[:48] or "target"


def _descriptor_is_app_code(package: str, descriptor: Any) -> bool:
    if not isinstance(descriptor, str):
        return False
    prefix = "L" + package.replace(".", "/")
    return descriptor.startswith(prefix + "/") or descriptor.startswith(prefix + "$")


def _launcher_activity(manifest: Mapping[str, Any], package: str) -> str | None:
    components = manifest.get("components", [])
    if not isinstance(components, list):
        return None
    for component in components:
        if not isinstance(component, Mapping):
            continue
        if component.get("component_type") != "activity":
            continue
        name = component.get("name")
        if not isinstance(name, str):
            continue
        filters = component.get("intent_filters", [])
        if not isinstance(filters, list):
            continue
        for intent_filter in filters:
            if not isinstance(intent_filter, Mapping):
                continue
            actions = intent_filter.get("actions", [])
            categories = intent_filter.get("categories", [])
            if (
                isinstance(actions, list)
                and "android.intent.action.MAIN" in actions
                and isinstance(categories, list)
                and "android.intent.category.LAUNCHER" in categories
            ):
                return name
    for component in components:
        if not isinstance(component, Mapping):
            continue
        if component.get("component_type") != "activity":
            continue
        name = component.get("name")
        if (
            isinstance(name, str)
            and component.get("effective_exported") is True
            and component.get("enabled") is not False
            and (name == package or name.startswith(package + "."))
        ):
            return name
    return None


def _candidate_classes(
    package: str,
    manifest: Mapping[str, Any],
    static_analysis: Mapping[str, Any],
    runtime_categories: Sequence[str],
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    reasons: dict[str, list[str]] = {}

    def add(category: str, reason: str) -> None:
        reasons.setdefault(category, []).append(reason)

    if manifest.get("uses_cleartext_traffic") is True:
        add("cleartext", "normalized_manifest_allows_cleartext")
    endpoints = static_analysis.get("endpoints", [])
    if isinstance(endpoints, list) and any(
        isinstance(item, Mapping) and str(item.get("scheme", "")).casefold() == "http"
        for item in endpoints
    ):
        add("cleartext", "static_http_endpoint_candidate")

    behavior = static_analysis.get("static_behavior_candidates", [])
    if isinstance(behavior, list):
        for item in behavior:
            if not isinstance(item, Mapping):
                continue
            if not _descriptor_is_app_code(package, item.get("caller_class_descriptor")):
                continue
            rule_id = str(item.get("rule_id", "")).casefold()
            indicators = " ".join(str(value) for value in item.get("indicators", []))
            text = f"{rule_id} {indicators}".casefold()
            if "storage" in text or "sharedpreferences" in text or "sqlite" in text:
                add("storage", "application_code_storage_callsite")
            if "crypto" in text or "digest" in text or "cipher" in text:
                add("crypto", "application_code_crypto_callsite")
            if "log" in text or "logging" in text:
                add("logging", "application_code_logging_callsite")

    api_candidates = static_analysis.get("security_api_candidates", [])
    if isinstance(api_candidates, list):
        for item in api_candidates:
            if not isinstance(item, Mapping):
                continue
            category = str(item.get("category", "")).casefold()
            inventory = str(item.get("inventory_id", "")).casefold()
            if "crypto" in category or "cipher" in inventory or "digest" in inventory:
                add("crypto", "runtime_crypto_api_candidate")
            if "log" in category or "log" in inventory:
                add("logging", "runtime_logging_api_candidate")
            if "storage" in category or "sqlite" in inventory or "preference" in inventory:
                add("storage", "runtime_storage_api_candidate")

    for raw_category in runtime_categories:
        category = _CLASS_TO_CATEGORY.get(str(raw_category).casefold())
        if category is not None:
            add(category, "runtime_observer_category")

    ordered = tuple(
        category
        for category in ("logging", "cleartext", "storage", "crypto")
        if category in reasons
    )
    return ordered, {key: tuple(dict.fromkeys(value)) for key, value in reasons.items()}


def _node_label(node: ScenarioNode) -> str:
    return " ".join(
        value.strip()
        for value in (node.visible_text, node.content_description, node.resource_id)
        if value and value.strip()
    ).casefold()


def _input_kind(node: ScenarioNode) -> str:
    label = _node_label(node)
    if any(marker in label for marker in _INPUT_MARKERS["password"]):
        return "password"
    if any(marker in label for marker in _INPUT_MARKERS["email"]):
        return "email"
    if any(marker in label for marker in _INPUT_MARKERS["token"]):
        return "token"
    if any(marker in label for marker in _INPUT_MARKERS["url"]):
        return "url"
    if any(marker in label for marker in _INPUT_MARKERS["username"]):
        return "username"
    return "text"


def _input_eligible(node: ScenarioNode) -> bool:
    if not node.editable or not node.enabled or not node.visible:
        return False
    marker = _node_label(node)
    return not any(item in marker for item in _OUTPUT_MARKERS)


def _action_score(node: ScenarioNode, candidate_classes: Sequence[str]) -> int:
    label = _node_label(node)
    score = 0
    for marker in _ACTION_MARKERS:
        if marker in label:
            score += 10
    for category in candidate_classes:
        if category in label:
            score += 25
    if "button" in node.class_name.casefold():
        score += 5
    return score


def _action_eligible(node: ScenarioNode) -> bool:
    if not node.clickable or not node.enabled or not node.visible or node.editable:
        return False
    label = _node_label(node)
    return not any(marker in label for marker in _DANGEROUS_ACTION_MARKERS)


def _selector(nodes: Sequence[ScenarioNode], index: int) -> ScenarioSelector:
    node = nodes[index]
    if node.resource_id:
        return ScenarioSelector(resource_id=node.resource_id)
    if node.content_description:
        return ScenarioSelector(content_description=node.content_description)
    class_index = sum(1 for item in nodes[:index] if item.class_name == node.class_name)
    return ScenarioSelector(class_name=node.class_name, index=class_index)


def _value_for_kind(kind: str, canary: str) -> str:
    if kind == "email":
        return f"{canary}@example.test"
    if kind == "url":
        return f"http://10.0.2.2/{canary}"
    if kind == "number":
        return "424242"
    return canary


def _local_http_route(
    static_analysis: Mapping[str, Any],
    allowed_hosts: Sequence[str],
    canary: str,
) -> tuple[str, dict[str, str]]:
    allowed = {str(item).casefold().rstrip(".") for item in allowed_hosts}
    endpoints = static_analysis.get("endpoints", [])
    if isinstance(endpoints, list):
        for endpoint in endpoints:
            if not isinstance(endpoint, Mapping):
                continue
            if str(endpoint.get("scheme", "")).casefold() != "http":
                continue
            host = str(endpoint.get("host", "")).casefold().rstrip(".")
            if not host or host not in allowed:
                continue
            port = endpoint.get("port")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                port = None
            authority = host if port is None else f"{host}:{port}"
            mapping = {f"{host}:{port}": f"127.0.0.1:{port}"} if port else {}
            return urlunsplit(("http", authority, f"/{canary}", "", "")), mapping
    fallback_host = sorted(allowed)[0] if allowed else None
    return (
        urlunsplit(("http", fallback_host, f"/{canary}", "", "")),
        {},
    ) if fallback_host is not None else (canary, {})


class CandidateMicroScenarioService:
    """Plan and execute one bounded form route using a separate action budget."""

    def __init__(self, scenario_service: ScenarioService) -> None:
        self.scenario_service = scenario_service

    def prepare(
        self,
        record: SessionRecord,
        *,
        manifest: Mapping[str, Any],
        static_analysis: Mapping[str, Any],
        session_canary: str,
        runtime_categories: Sequence[str] = (),
        allowed_hosts: Sequence[str] = (),
    ) -> MicroScenarioSeed:
        package = validate_package_name(record.package)
        launcher = _launcher_activity(manifest, package)
        classes, reasons = _candidate_classes(
            package,
            manifest,
            static_analysis,
            runtime_categories,
        )
        resolver = ScenarioSecretResolver(
            session_canary=session_canary,
            session_key=secrets.token_bytes(32),
        )
        url_value, upstream_mapping = _local_http_route(
            static_analysis,
            allowed_hosts,
            session_canary,
        )
        value_specs = {
            "username": ScenarioValueSpec(kind="session_canary"),
            "password": ScenarioValueSpec(kind="session_canary"),
            "email": ScenarioValueSpec(
                kind="literal",
                literal=_value_for_kind("email", session_canary),
                sensitive=True,
            ),
            "url": ScenarioValueSpec(
                kind="literal",
                literal=url_value,
                sensitive=True,
            ),
            "token": ScenarioValueSpec(kind="session_canary"),
            "text": ScenarioValueSpec(kind="session_canary"),
        }
        owned_values: dict[str, str] = {}
        metadata: list[Mapping[str, Any]] = []
        for reference, spec in value_specs.items():
            resolved = resolver.resolve(spec)
            fingerprint = resolved.fingerprint
            if fingerprint is None:
                continue
            owned_values[fingerprint] = resolved.reveal_for_input()
            metadata.append(
                {
                    "reference": reference,
                    "type": reference,
                    "length": len(resolved.reveal_for_input()),
                    "fingerprint": fingerprint,
                }
            )
        canary_fp = resolver.resolve(ScenarioValueSpec(kind="session_canary")).fingerprint
        return MicroScenarioSeed(
            session_id=record.session_id,
            scenario_id=f"auto_micro_{_safe_identifier(record.session_id[-12:])}",
            package=package,
            launcher_activity=launcher,
            candidate_classes=classes,
            candidate_reasons=reasons,
            value_specs=value_specs,
            resolver=resolver,
            owned_values=owned_values,
            owned_value_metadata=tuple(metadata),
            canary_fingerprint=canary_fp,
            upstream_mapping=upstream_mapping,
        )

    def enrich_runtime_candidates(
        self,
        seed: MicroScenarioSeed,
        runtime_categories: Sequence[str],
    ) -> MicroScenarioSeed:
        """Merge live observer categories without regenerating session values."""

        runtime_classes, runtime_reasons = _candidate_classes(
            seed.package,
            {},
            {},
            runtime_categories,
        )
        merged_classes = tuple(
            category
            for category in ("logging", "cleartext", "storage", "crypto")
            if category in (*seed.candidate_classes, *runtime_classes)
        )
        merged_reasons: dict[str, tuple[str, ...]] = {
            key: tuple(value) for key, value in seed.candidate_reasons.items()
        }
        for category, reasons in runtime_reasons.items():
            merged_reasons[category] = tuple(
                dict.fromkeys((*merged_reasons.get(category, ()), *reasons))
            )
        return replace(
            seed,
            candidate_classes=merged_classes,
            candidate_reasons=merged_reasons,
        )

    def _plan_from_observation(
        self,
        seed: MicroScenarioSeed,
        observation: ScenarioObservation,
        *,
        available_observers: Sequence[str],
    ) -> MicroScenarioPlan | None:
        if observation.package != seed.package:
            return None
        nodes = tuple(observation.nodes)
        editable = [
            (index, node)
            for index, node in enumerate(nodes)
            if _input_eligible(node)
        ]
        editable.sort(
            key=lambda item: (
                0 if _input_kind(item[1]) == "password" else 1,
                0 if _input_kind(item[1]) in {"username", "email", "token", "url"} else 1,
                item[0],
            )
        )
        selected_inputs: list[tuple[int, ScenarioNode, str]] = []
        seen_kinds: set[str] = set()
        for index, node in editable:
            kind = _input_kind(node)
            if kind in seen_kinds and len(selected_inputs) >= 2:
                continue
            selected_inputs.append((index, node, kind))
            seen_kinds.add(kind)
            if len(selected_inputs) >= 2:
                break
        actions = [
            (index, node)
            for index, node in enumerate(nodes)
            if _action_eligible(node)
        ]
        actions.sort(key=lambda item: (-_action_score(item[1], seed.candidate_classes), item[0]))
        selected_action = actions[0] if actions else None
        if not selected_inputs or selected_action is None:
            return None
        selectors: dict[str, ScenarioSelector] = {}
        values: dict[str, ScenarioValueSpec] = {}
        steps: list[ScenarioStep] = [
            ScenarioStep(
                step_id="launch",
                action=ScenarioAction.LAUNCH,
                timeout_seconds=6,
                expected_activity=seed.launcher_activity,
            ),
            ScenarioStep(
                step_id="wait_for_form",
                action=ScenarioAction.WAIT_FOR,
                timeout_seconds=8,
                selector_ref="input_0",
                max_read_retries=2,
            ),
        ]
        for index, (node_index, _node, kind) in enumerate(selected_inputs):
            selector_name = f"input_{index}"
            value_name = f"value_{index}"
            selectors[selector_name] = _selector(nodes, node_index)
            values[value_name] = seed.value_specs.get(kind, seed.value_specs["text"])
            steps.append(
                ScenarioStep(
                    step_id=f"input_{index}",
                    action=ScenarioAction.INPUT,
                    timeout_seconds=6,
                    selector_ref=selector_name,
                    value_ref=value_name,
                )
            )
        action_index, _action_node = selected_action
        selectors["activation"] = _selector(nodes, action_index)
        steps.extend(
            (
                ScenarioStep(
                    step_id="activate",
                    action=ScenarioAction.CLICK,
                    timeout_seconds=8,
                    selector_ref="activation",
                ),
                ScenarioStep(
                    step_id="observe_transition",
                    action=ScenarioAction.WAIT_FOR_TRANSITION,
                    timeout_seconds=6,
                    transition_ref="package_transition",
                    max_read_retries=2,
                ),
                ScenarioStep(
                    step_id="collect_sinks",
                    action=ScenarioAction.COLLECT_OBSERVATIONS,
                    timeout_seconds=4,
                    observers=tuple(
                        item
                        for item in ("frida", "traffic", "logcat", "private_storage")
                        if item in available_observers
                    ),
                    max_read_retries=1,
                ),
                ScenarioStep(
                    step_id="cleanup",
                    action=ScenarioAction.CLEANUP,
                    timeout_seconds=6,
                ),
            )
        )
        bundle = ScenarioBundle(
            profile=ScenarioProfile(
                profile_id=seed.scenario_id,
                package=seed.package,
                launch_activity=seed.launcher_activity,
                selectors=selectors,
                values=values,
                transitions={"package_transition": ScenarioTransition()},
                expected_vulnerability_classes=seed.candidate_classes,
            ),
            scenario=ScenarioDefinition(
                scenario_id=seed.scenario_id,
                total_timeout_seconds=seed.timeout_seconds,
                steps=tuple(steps),
                require_network_guard=True,
                required_observers=tuple(
                    item for item in ("frida", "traffic") if item in available_observers
                ),
            ),
        )
        route = {
            "activity": observation.activity,
            "pid": observation.pid,
            "process": observation.process,
            "input_count": len(selected_inputs),
            "activation_selector": "activation",
            "input_kinds": [kind for _index, _node, kind in selected_inputs],
        }
        return MicroScenarioPlan(
            bundle=bundle,
            resolver=seed.resolver,
            owned_values=seed.owned_values,
            upstream_mapping=seed.upstream_mapping,
            owned_value_metadata=seed.owned_value_metadata,
            canary_fingerprint=seed.canary_fingerprint,
            candidate_classes=seed.candidate_classes,
            route=route,
        )

    def run(
        self,
        seed: MicroScenarioSeed,
        *,
        backend: AdbExplorerBackend,
        scope: ScopeConfig,
        network_guard_active: bool,
        available_observers: Sequence[str],
        serial: str,
    ) -> MicroScenarioExecution:
        scenario_backend: ScenarioBackend = AdbScenarioBackend(backend)
        try:
            initial = scenario_backend.observe(timeout=6)
        except ScopeError:
            return MicroScenarioExecution(seed, None, None, "out_of_scope", "package_escape")
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return MicroScenarioExecution(
                seed,
                None,
                None,
                "not_exercised",
                f"initial UI observation failed: {str(exc)[:180]}",
            )
        if initial.package != seed.package:
            return MicroScenarioExecution(
                seed,
                None,
                None,
                "out_of_scope",
                "package_escape",
            )
        plan = self._plan_from_observation(
            seed,
            initial,
            available_observers=available_observers,
        )
        if seed.activation_quota < 3:
            return MicroScenarioExecution(
                seed,
                None,
                None,
                "not_exercised",
                "activation_quota_exhausted",
            )
        if plan is None:
            return MicroScenarioExecution(
                seed,
                None,
                None,
                "not_exercised",
                "no bounded editable form and safe activation control were resolved",
            )
        try:
            result = ScenarioRunner(
                scenario_backend,
                scope=scope,
                serial=serial,
                package=seed.package,
                session_id=seed.session_id,
                bundle=plan.bundle,
                secrets=plan.resolver,
                network_guard_active=network_guard_active,
                available_observers=available_observers,
            ).run()
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return MicroScenarioExecution(
                seed,
                plan,
                None,
                "failed_activation",
                f"micro-scenario execution failed: {str(exc)[:180]}",
            )
        return MicroScenarioExecution(
            seed,
            plan,
            result,
            result.outcome.value,
            (
                None
                if result.outcome is ScenarioOutcome.COMPLETED
                else "bounded route did not complete"
            ),
        )

    def persist(
        self,
        session_id: str,
        execution: MicroScenarioExecution,
    ) -> Any:
        paths = self.scenario_service.repository.paths_for(session_id)
        path = paths.redacted_dir / "micro-scenario" / "result.json"
        from .storage import write_json_atomic

        write_json_atomic(path, execution.to_dict(), root=paths.root)
        self.scenario_service.evidence.register_file(
            session_id,
            path,
            evidence_type="micro_scenario",
            source="candidate_micro_scenario",
            description="Redacted candidate-driven micro-scenario result.",
            sensitive=True,
            redacted=True,
        )
        return path
