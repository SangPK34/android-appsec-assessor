"""Generic deterministic scenario orchestration for authorized local assessments."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..app_context import AppContext
from ..errors import AndroidAssessorError, ConfigurationError
from ..evidence import EvidenceRepository
from ..explorer import AdbExplorerBackend, parse_ui_hierarchy
from ..scenario import (
    ScenarioBackend,
    ScenarioBundle,
    ScenarioCollection,
    ScenarioLoader,
    ScenarioNode,
    ScenarioObservation,
    ScenarioResult,
    ScenarioRunner,
    ScenarioSecretResolver,
)
from ..scope import ScopeConfig
from ..session import SessionRepository
from ..storage import write_json_atomic


@dataclass(frozen=True, slots=True)
class ScenarioRequest:
    profile_path: Path
    scenario_path: Path
    variables_path: Path | None = None


@dataclass(frozen=True, slots=True)
class ScenarioPlan:
    request: ScenarioRequest
    bundle: ScenarioBundle
    resolver: ScenarioSecretResolver
    owned_values: Mapping[str, str]
    upstream_mapping: Mapping[str, str]


class AdbScenarioBackend(ScenarioBackend):
    """Adapter from the bounded explorer ADB backend to scenario primitives."""

    def __init__(self, backend: AdbExplorerBackend) -> None:
        self.backend = backend

    def launch(self, activity: str | None, *, timeout: float) -> None:
        package, current_activity = self.backend.current_activity()
        if package == self.backend.package and (
            activity is None or current_activity == activity
        ):
            return
        self.backend.launch()

    def observe(self, *, timeout: float) -> ScenarioObservation:
        package, activity = self.backend.current_activity()
        if not package or not activity:
            raise AndroidAssessorError("Target activity could not be resolved.")
        xml = self.backend.dump_ui()
        state = parse_ui_hierarchy(
            xml,
            expected_package=package,
            activity=activity,
        )
        nodes = tuple(
            ScenarioNode(
                resource_id=node.resource_id,
                content_description=node.content_description,
                visible_text=node.text,
                class_name=node.class_name,
                bounds=node.bounds,
                clickable=node.clickable,
                editable=node.editable,
                enabled=node.enabled,
                visible=node.visible,
            )
            for node in state.nodes
        )
        width = max((node.bounds[2] for node in state.nodes), default=1080)
        height = max((node.bounds[3] for node in state.nodes), default=1920)
        return ScenarioObservation(
            package=state.package,
            activity=state.activity,
            nodes=nodes,
            pid=self.backend.process_id(),
            process=self.backend.package,
            display_width=width,
            display_height=height,
        )

    def input_text(
        self,
        x: int,
        y: int,
        value: str,
        *,
        timeout: float,
        sensitive_values: Sequence[str] = (),
    ) -> None:
        self.backend.input_text(x, y, value)

    def click(self, x: int, y: int, *, timeout: float) -> None:
        self.backend.tap(x, y)

    def collect_observations(
        self,
        observers: tuple[str, ...],
        *,
        scenario_id: str,
        step_id: str,
        timeout: float,
    ) -> ScenarioCollection:
        # The collectors are owned by ScanService.  This bounded read confirms
        # that the target process is still in scope at the collection boundary;
        # evidence files are registered after observers stop.
        self.observe(timeout=timeout)
        return ScenarioCollection(
            evidence_references=tuple(
                f"scenario:{scenario_id}:step:{step_id}:{observer}"
                for observer in observers
            ),
            observed_categories=tuple(observers),
        )

    def cleanup(self, *, timeout: float) -> None:
        # Do not stop the target here: logcat/storage snapshots happen after the
        # scenario and need the stable process/data window. Assessment cleanup
        # owns the eventual force-stop through the normal cleanup ledger.
        self.backend.hide_keyboard()


class ScenarioService:
    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
    ) -> None:
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)
        self.evidence = EvidenceRepository(self.paths, self.repository)

    def prepare(
        self,
        request: ScenarioRequest,
        *,
        session_canary: str | None,
    ) -> ScenarioPlan:
        loader = ScenarioLoader(self.paths.root)
        bundle = loader.load_bundle(request.profile_path, request.scenario_path)
        resolver = (
            ScenarioSecretResolver.from_yaml(
                request.variables_path,
                root=self.paths.root,
                session_canary=session_canary,
            )
            if request.variables_path is not None
            else ScenarioSecretResolver(session_canary=session_canary)
        )
        owned_values: dict[str, str] = {}
        for spec in bundle.profile.values.values():
            resolved = resolver.resolve(spec)
            if resolved.sensitive and resolved.fingerprint is not None:
                owned_values[resolved.fingerprint] = resolved.reveal_for_input()
        upstream_mapping: dict[str, str] = {}
        if bundle.profile.local_backend_url and bundle.profile.upstream_backend_url:
            source = _backend_endpoint(bundle.profile.local_backend_url, "local_backend_url")
            target = _backend_endpoint(
                bundle.profile.upstream_backend_url,
                "upstream_backend_url",
            )
            if target.split(":", 1)[0] not in {"127.0.0.1", "localhost"}:
                raise ConfigurationError("Scenario upstream must remain on the local host.")
            upstream_mapping[source] = target
        return ScenarioPlan(request, bundle, resolver, owned_values, upstream_mapping)

    def run(
        self,
        session_id: str,
        *,
        plan: ScenarioPlan,
        adb: AdbExplorerBackend,
        scope: ScopeConfig,
        network_guard_active: bool,
        available_observers: Sequence[str],
    ) -> ScenarioResult:
        record = self.repository.load(session_id)
        result = ScenarioRunner(
            AdbScenarioBackend(adb),
            scope=scope,
            serial=record.serial,
            package=record.package,
            session_id=session_id,
            bundle=plan.bundle,
            secrets=plan.resolver,
            network_guard_active=network_guard_active,
            available_observers=available_observers,
        ).run()
        self.persist_result(session_id, result)
        return result

    def persist_result(self, session_id: str, result: ScenarioResult) -> Path:
        return self.persist_summary(session_id, result.scenario_id, result.to_dict())

    def persist_summary(
        self,
        session_id: str,
        scenario_id: str,
        summary: Mapping[str, Any],
    ) -> Path:
        paths = self.repository.paths_for(session_id)
        directory = paths.redacted_dir / "scenario" / scenario_id
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "summary.json"
        write_json_atomic(path, dict(summary), root=self.paths.root)
        self.evidence.register_file(
            session_id,
            path,
            evidence_type="scenario_summary",
            source="scenario_runner",
            description="Redacted deterministic scenario execution summary.",
            sensitive=True,
            redacted=True,
        )
        return path

    def persist_correlation(
        self,
        session_id: str,
        scenario_id: str,
        payload: Mapping[str, Any],
    ) -> Path:
        """Persist only normalized, redacted correlation output as evidence."""

        if not isinstance(payload, Mapping):
            raise ValueError("Scenario correlation payload must be a mapping.")
        paths = self.repository.paths_for(session_id)
        directory = paths.redacted_dir / "scenario" / scenario_id
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "correlation.json"
        write_json_atomic(path, dict(payload), root=self.paths.root)
        self.evidence.register_file(
            session_id,
            path,
            evidence_type="scenario_correlation",
            source="scenario_correlator",
            description="Fail-closed normalized scenario evidence correlation.",
            sensitive=True,
            redacted=True,
        )
        return path


def load_scenario_summary(paths: Any, scenario_id: str) -> dict[str, Any] | None:
    path = paths.redacted_dir / "scenario" / scenario_id / "summary.json"
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _backend_endpoint(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError(f"Scenario {label} must be an HTTP(S) URL.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ConfigurationError(f"Scenario {label} port is invalid.")
    return f"{parsed.hostname.casefold().rstrip('.')}:{port}"
