"""Profile-driven assessment orchestration with bounded capability use."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from ..app_context import AppContext
from ..device_lock import DeviceLock
from ..errors import AndroidAssessorError
from ..explorer import (
    AdbExplorerBackend,
    ExplorerConfig,
    ExplorerResult,
    ExplorerService,
    RuntimeFeedbackCollector,
)
from ..exported_component_validation import ExportedComponentValidationService
from ..findings import FindingRecord
from ..frida_controller import FridaController
from ..logcat import LogcatCollector
from ..micro_scenario import (
    CandidateMicroScenarioService,
    MicroScenarioExecution,
    MicroScenarioSeed,
)
from ..private_storage import AdbPrivateStorageBackend, PrivateStorageService
from ..redaction import redact_text
from ..report import ReportService
from ..rules import RuleEngine
from ..scenario_correlation import correlate_scenario_events
from ..scope import load_scope
from ..session import SessionRecord, SessionRepository
from ..storage import read_json_object, write_json_atomic
from ..traffic import TrafficCaptureService
from ..validation import generate_session_canary
from .app_inspection_service import AppInspectionService
from .cleanup_service import CleanupService
from .scenario_service import ScenarioPlan, ScenarioRequest, ScenarioService

LOGGER = logging.getLogger(__name__)

_EXPLORER_HARD_BOUND_TERMINATIONS = frozenset(
    {
        "max_runtime",
        "max_actions",
        "max_states",
        "action_failure_limit",
        "action_recovery_failed",
        "state_refresh_failed",
        "process_state_unavailable",
        "process_restart_failed",
    }
)
_EXPLORER_LIMIT_BLOCK_REASONS = frozenset(
    {
        "hard_limit",
        "insufficient_action_budget",
        "max_actions",
        "max_states",
        "action_failure_limit",
        "action_recovery_failed",
        "state_refresh_failed",
        "process_state_unavailable",
        "process_restart_failed",
    }
)


def _read_redacted_jsonl(path: Any, *, maximum: int = 20_000) -> list[dict[str, Any]]:
    """Read a bounded redacted JSONL observer stream without retaining raw data."""

    if not hasattr(path, "is_file") or not path.is_file():
        return []
    output: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            if len(output) >= maximum:
                break
            value = json.loads(line)
            if isinstance(value, dict):
                output.append(value)
    except (OSError, ValueError):
        return []
    return output


def _non_negative_count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _apply_sink_verification_quota(
    payload: dict[str, Any],
    quota: int,
) -> dict[str, Any]:
    """Bound accepted observer evidence without changing eligibility rules."""

    bounded_quota = max(0, int(quota))
    accepted = payload.get("events", [])
    if isinstance(accepted, list) and len(accepted) > bounded_quota:
        payload["events"] = accepted[:bounded_quota]
        payload["accepted_count"] = bounded_quota
        payload["quota_exhausted"] = True
    payload["sink_verification_quota"] = bounded_quota
    return payload


def _exploration_coverage_limitation(result: ExplorerResult) -> str | None:
    raw_termination = getattr(result, "termination_reason", "")
    termination = raw_termination if isinstance(raw_termination, str) else ""

    def attempts(attribute: str) -> tuple[Mapping[str, Any], ...]:
        raw_attempts = getattr(result, attribute, ())
        if not isinstance(raw_attempts, (list, tuple)):
            return ()
        return tuple(item for item in raw_attempts if isinstance(item, Mapping))

    activity_attempts = attempts("activity_attempts")
    deep_link_attempts = attempts("deep_link_attempts")

    def limit_blocked(items: tuple[Mapping[str, Any], ...]) -> int:
        return sum(
            item.get("status") == "blocked"
            and item.get("reason") in _EXPLORER_LIMIT_BLOCK_REASONS
            for item in items
        )

    blocked_activities = limit_blocked(activity_attempts)
    blocked_deep_links = limit_blocked(deep_link_attempts)
    action_failures = _non_negative_count(getattr(result, "actions_failed", 0))
    status = getattr(result, "status", "")
    if (
        termination not in _EXPLORER_HARD_BOUND_TERMINATIONS
        and blocked_activities == 0
        and blocked_deep_links == 0
        and action_failures == 0
        and status != "partial"
    ):
        return None

    executed_actions = _non_negative_count(getattr(result, "actions_executed", 0))
    actions = _non_negative_count(
        getattr(result, "actions_attempted", executed_actions)
    )
    states = _non_negative_count(getattr(result, "states_visited", 0))
    return (
        "Autonomous exploration coverage was bounded: "
        f"status={status or 'unknown'}; termination={termination or 'unknown'}; "
        f"actions={actions}; executed_actions={executed_actions}; "
        f"failed_actions={action_failures}; states={states}; "
        f"observation_retries={_non_negative_count(getattr(result, 'observation_retries', 0))}; "
        f"state_refreshes={_non_negative_count(getattr(result, 'state_refreshes', 0))}; "
        f"targeted activity attempts={len(activity_attempts)} "
        f"(limit-blocked={blocked_activities}); targeted deep-link attempts="
        f"{len(deep_link_attempts)} (limit-blocked={blocked_deep_links})."
    )


@dataclass(frozen=True, slots=True)
class ScanResult:
    session_id: str
    findings: tuple[FindingRecord, ...]
    limitations: tuple[str, ...]
    dynamic_steps: dict[str, str]
    report_path: str
    profile: str = "quick"
    phase_timings: dict[str, float] | None = None
    requested_profile: str | None = None
    effective_profile: str = "quick"
    autonomous_exploration_requested: bool = False
    autonomous_exploration_executed: bool = False
    controlled_canary_requested: bool = False
    controlled_canary_executed: bool = False
    ipc_validation_requested: bool = False
    ipc_validation_executed: bool = False
    micro_scenario_requested: bool = False
    micro_scenario_executed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "findings": [finding.to_dict() for finding in self.findings],
            "limitations": list(self.limitations),
            "dynamic_steps": dict(self.dynamic_steps),
            "profile": self.profile,
            "requested_profile": self.requested_profile,
            "effective_profile": self.effective_profile,
            "autonomous_exploration_requested": self.autonomous_exploration_requested,
            "autonomous_exploration_executed": self.autonomous_exploration_executed,
            "controlled_canary_requested": self.controlled_canary_requested,
            "controlled_canary_executed": self.controlled_canary_executed,
            "ipc_validation_requested": self.ipc_validation_requested,
            "ipc_validation_executed": self.ipc_validation_executed,
            "micro_scenario_requested": self.micro_scenario_requested,
            "micro_scenario_executed": self.micro_scenario_executed,
            "phase_timings": dict(self.phase_timings or {}),
            "report_path": self.report_path,
        }


class ScanProfile(StrEnum):
    QUICK = "quick"
    FULL = "full"

    @classmethod
    def parse(cls, value: str | ScanProfile) -> ScanProfile:
        try:
            return value if isinstance(value, cls) else cls(str(value).casefold())
        except ValueError as exc:
            raise ValueError("Scan profile must be 'quick' or 'full'.") from exc


@dataclass(frozen=True, slots=True)
class ScanProfileResolution:
    requested_profile: str | None
    effective_profile: ScanProfile
    autonomous_exploration_requested: bool

    @property
    def autonomous_exploration_enabled(self) -> bool:
        return (
            self.effective_profile is ScanProfile.FULL
            and self.autonomous_exploration_requested
        )


def resolve_scan_profile(
    profile: str | ScanProfile | None,
    *,
    autonomous: bool | None = None,
    explorer_config: ExplorerConfig | None = None,
) -> ScanProfileResolution:
    """Resolve legacy direct calls and explicit scan profiles consistently."""
    requested_profile = None if profile is None else ScanProfile.parse(profile).value
    effective_profile = (
        ScanProfile.FULL if requested_profile is None else ScanProfile(requested_profile)
    )
    autonomous_requested = autonomous is True or (
        autonomous is None and explorer_config is not None
    )
    return ScanProfileResolution(
        requested_profile=requested_profile,
        effective_profile=effective_profile,
        autonomous_exploration_requested=autonomous_requested,
    )


def _require_explicit_controlled_canary_request(
    *,
    explorer_config: ExplorerConfig | None,
    controlled_canary: bool,
) -> None:
    if (
        explorer_config is not None
        and explorer_config.controlled_canary_delivery
        and not controlled_canary
    ):
        raise AndroidAssessorError(
            "Controlled canary delivery must be requested via controlled_canary=True."
        )


class ScanService:
    DEFAULT_RUNTIME_SECONDS = 30
    DEFAULT_AUTONOMOUS_RUNTIME_SECONDS = 45
    MIN_RUNTIME_SECONDS = 0
    MAX_RUNTIME_SECONDS = 300

    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
    ) -> None:
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)

    def scan(
        self,
        *,
        package: str,
        serial: str | None = None,
        profile: str | ScanProfile | None = ScanProfile.QUICK,
        runtime_seconds: int | None = None,
        autonomous: bool | None = None,
        explorer_config: ExplorerConfig | None = None,
        controlled_canary: bool = False,
        ipc_validation: bool = False,
        micro_scenario: bool = False,
        scenario_request: ScenarioRequest | None = None,
    ) -> ScanResult:
        _require_explicit_controlled_canary_request(
            explorer_config=explorer_config,
            controlled_canary=controlled_canary,
        )
        inspection = AppInspectionService(self.context, self.repository).inspect(
            package=package,
            serial=serial,
        )
        return self.scan_session(
            inspection.session_id,
            profile=profile,
            runtime_seconds=runtime_seconds,
            autonomous=autonomous,
            explorer_config=explorer_config,
            controlled_canary=controlled_canary,
            ipc_validation=ipc_validation,
            micro_scenario=micro_scenario,
            scenario_request=scenario_request,
        )

    def scan_session(
        self,
        session_id: str,
        *,
        profile: str | ScanProfile | None = None,
        runtime_seconds: int | None = None,
        autonomous: bool | None = None,
        explorer_config: ExplorerConfig | None = None,
        controlled_canary: bool = False,
        ipc_validation: bool = False,
        micro_scenario: bool = False,
        scenario_request: ScenarioRequest | None = None,
    ) -> ScanResult:
        _require_explicit_controlled_canary_request(
            explorer_config=explorer_config,
            controlled_canary=controlled_canary,
        )
        resolution = resolve_scan_profile(
            profile,
            autonomous=autonomous,
            explorer_config=explorer_config,
        )
        if resolution.autonomous_exploration_enabled and runtime_seconds == 0:
            raise AndroidAssessorError(
                "Autonomous exploration requires a runtime greater than zero."
            )
        record = self.repository.load(session_id)
        scope = load_scope(self.paths)
        scope.require_device_package(record.serial, record.package)
        if controlled_canary:
            if not resolution.autonomous_exploration_enabled:
                raise AndroidAssessorError(
                    "Controlled canary delivery requires an autonomous Full Assessment."
                )
            scope.require_device_package(
                record.serial,
                record.package,
                action="controlled_validation",
            )
        if scenario_request is not None:
            if resolution.effective_profile is not ScanProfile.FULL:
                raise AndroidAssessorError(
                    "Deterministic scenarios require a Full Assessment."
                )
            scope.require_device_package(
                record.serial,
                record.package,
                action="controlled_validation",
            )
        self.repository.require_modifying_session_slot(record.serial, record.session_id)
        try:
            with DeviceLock(
                self.paths,
                record.serial,
                operation="scan",
                session_id=record.session_id,
                timeout=0,
            ):
                self.repository.require_modifying_session_slot(
                    record.serial,
                    record.session_id,
                )
                result = self._scan_session_locked(
                    self.repository.load(record.session_id),
                    resolution=resolution,
                    runtime_seconds=runtime_seconds,
                    explorer_config=explorer_config,
                    controlled_canary=controlled_canary,
                    ipc_validation=ipc_validation,
                    micro_scenario=micro_scenario,
                    scenario_request=scenario_request,
                )
        except BaseException:
            if resolution.effective_profile is ScanProfile.FULL:
                try:
                    self._finalize_failed_full_assessment(record.session_id)
                except Exception:
                    LOGGER.exception(
                        "Failed to finalize resources after Full Assessment error for %s.",
                        record.session_id,
                    )
            raise
        if resolution.effective_profile is ScanProfile.FULL:
            result = self._finalize_full_assessment(result)
        return result

    def _finalize_full_assessment(self, result: ScanResult) -> ScanResult:
        """Run the owned-resource ledger after releasing the assessment device lock."""
        limitations = list(result.limitations)
        steps = dict(result.dynamic_steps)
        cleanup_success = False
        try:
            cleanup = CleanupService(self.context, self.repository).cleanup(result.session_id)
            cleanup_success = cleanup.success
            steps["cleanup"] = "completed" if cleanup.success else "error"
            if not cleanup.success:
                limitations.append("Full Assessment cleanup left pending owned resources.")
        except (AndroidAssessorError, OSError, ValueError) as exc:
            steps["cleanup"] = "error"
            limitations.append(f"Full Assessment cleanup failed: {redact_text(str(exc))[:300]}")
        except Exception as exc:
            LOGGER.exception(
                "Unexpected Full Assessment cleanup failure for session %s.",
                result.session_id,
            )
            steps["cleanup"] = "error"
            limitations.append(
                f"Full Assessment cleanup failed unexpectedly: {redact_text(str(exc))[:300]}"
            )

        paths = self.repository.paths_for(result.session_id)
        scan = read_json_object(paths.scan_json, root=self.paths.root)
        scan["dynamic_steps"] = steps
        scan["limitations"] = limitations
        scan["cleanup_success"] = cleanup_success
        write_json_atomic(paths.scan_json, scan, root=self.paths.root)
        try:
            ReportService(self.paths, self.repository).generate(result.session_id)
            steps["report"] = "completed"
        except (AndroidAssessorError, OSError, ValueError) as exc:
            steps["report"] = "error"
            limitations.append(f"Final report generation failed: {redact_text(str(exc))[:300]}")
        except Exception as exc:
            LOGGER.exception(
                "Unexpected final report failure for session %s.",
                result.session_id,
            )
            steps["report"] = "error"
            limitations.append(
                f"Final report generation failed unexpectedly: {redact_text(str(exc))[:300]}"
            )
        scan["dynamic_steps"] = steps
        scan["limitations"] = limitations
        write_json_atomic(paths.scan_json, scan, root=self.paths.root)
        return replace(
            result,
            limitations=tuple(limitations),
            dynamic_steps=steps,
        )

    def _finalize_failed_full_assessment(self, session_id: str) -> None:
        """Best-effort owned-resource cleanup after an interrupted Full Assessment."""
        paths = self.repository.paths_for(session_id)
        scan = (
            read_json_object(paths.scan_json, root=self.paths.root)
            if paths.scan_json.is_file()
            else {"schema_version": 1, "session_id": session_id}
        )
        steps = dict(scan.get("dynamic_steps", {}))
        limitations = list(scan.get("limitations", []))
        cleanup_success = False
        try:
            cleanup = CleanupService(self.context, self.repository).cleanup(session_id)
            cleanup_success = cleanup.success
            steps["cleanup"] = "completed" if cleanup.success else "error"
            if not cleanup.success:
                limitations.append(
                    "Full Assessment failure cleanup left pending owned resources."
                )
        except Exception as exc:
            steps["cleanup"] = "error"
            limitations.append(
                "Full Assessment failure cleanup failed: "
                f"{redact_text(str(exc))[:300]}"
            )
            LOGGER.exception(
                "Full Assessment failure cleanup failed for session %s.",
                session_id,
            )
        scan.update(
            {
                "status": "error",
                "dynamic_steps": steps,
                "limitations": limitations,
                "cleanup_success": cleanup_success,
            }
        )
        write_json_atomic(paths.scan_json, scan, root=self.paths.root)
        try:
            ReportService(self.paths, self.repository).generate(session_id)
        except Exception:
            LOGGER.exception(
                "Could not generate a failure report after cleanup for session %s.",
                session_id,
            )

    def request_runtime_stop(self, session_id: str) -> dict[str, Any]:
        """Request a running full assessment to flush and analyze early."""
        record = self.repository.load(session_id)
        paths = self.repository.paths_for(record.session_id)
        scan = (
            read_json_object(paths.scan_json, root=self.paths.root)
            if paths.scan_json.is_file()
            else {}
        )
        if scan.get("profile") != ScanProfile.FULL.value:
            raise AndroidAssessorError("Runtime stop is only available for Full Assessment.")
        write_json_atomic(
            paths.runtime_control_json,
            {"stop_requested": True, "requested_at": time.time()},
            root=self.paths.root,
        )
        self.repository.append_event(record.session_id, "runtime_stop_requested", {})
        return {"session_id": record.session_id, "stop_requested": True}

    def _runtime_stop_requested(self, session_id: str) -> bool:
        path = self.repository.paths_for(session_id).runtime_control_json
        if not path.is_file():
            return False
        try:
            return bool(read_json_object(path, root=self.paths.root).get("stop_requested"))
        except (AndroidAssessorError, OSError, ValueError):
            try:
                payload = json.loads(path.read_text(encoding="utf-8-sig"))
                return bool(payload.get("stop_requested"))
            except (OSError, ValueError, TypeError):
                return False

    def _finalize_scenario_correlation(
        self,
        record: SessionRecord,
        *,
        scenario_result: Any,
        scenario_plan: Any,
        scenario_service: ScenarioService,
        sink_verification_quota: int | None = None,
        allow_post_scenario_observation_window: bool = True,
    ) -> dict[str, Any] | None:
        """Join completed scenario windows to redacted observer evidence."""

        if getattr(scenario_result, "outcome", None) is None:
            return None
        summary = scenario_result.to_dict()
        verified_pids = summary.get("verified_pids", [])
        verified_processes = summary.get("verified_processes", [])
        if not isinstance(verified_pids, list) or not verified_pids:
            return None
        pid = verified_pids[0]
        process = (
            verified_processes[0]
            if isinstance(verified_processes, list) and verified_processes
            else record.package
        )
        evidence_values = scenario_service.evidence.list(record.session_id)

        def evidence_id(evidence_type: str) -> str | None:
            for item in evidence_values:
                if item.get("evidence_type") == evidence_type:
                    value = item.get("evidence_id")
                    return str(value) if value else None
            return None

        summary.update(
            {
                "process": process,
                "owned_value_fingerprints": sorted(scenario_plan.owned_values),
                "owned_value_metadata": [
                    dict(item)
                    for item in getattr(scenario_plan, "owned_value_metadata", ())
                    if isinstance(item, Mapping)
                ],
                "scoped_backend_ids": sorted(scenario_plan.upstream_mapping),
                "evidence_ids": {
                    key: value
                    for key, value in (
                        ("traffic", evidence_id("traffic_events")),
                        ("frida", evidence_id("frida_events")),
                    )
                    if value is not None
                },
            }
        )
        if getattr(scenario_plan, "canary_fingerprint", None):
            summary["canary_fingerprint"] = scenario_plan.canary_fingerprint
        verification_started = summary.get("ended_at")
        if not allow_post_scenario_observation_window:
            post_scenario_window = "disabled_after_subsequent_runtime_actions"
        elif not isinstance(verification_started, str):
            post_scenario_window = "unavailable_without_scenario_end_time"
        else:
            post_scenario_window = "enabled"
        summary["post_scenario_observation_window"] = post_scenario_window
        if post_scenario_window == "enabled":
            verification_ended = datetime.now(UTC).isoformat()
            raw_steps = summary.get("steps")
            if isinstance(raw_steps, list):
                raw_steps.append(
                    {
                        "step_id": "sink_verification",
                        "action": "collect_observations",
                        "attempted": True,
                        "completed": True,
                        "retry_count": 0,
                        "timeout_seconds": 1,
                        "resolved_selector": None,
                        "observed_transition": None,
                        "failure_reason": None,
                        "evidence_reference": "scenario:sink_verification",
                        "started_at": verification_started,
                        "ended_at": verification_ended,
                        "pid": pid,
                        "process": process,
                    }
                )
        scenario_service.persist_summary(
            record.session_id,
            str(summary["scenario_id"]),
            summary,
        )
        paths = self.repository.paths_for(record.session_id)

        def state_events(state_path: Any) -> list[dict[str, Any]]:
            try:
                state = read_json_object(state_path, root=self.paths.root)
                relative = state.get("events_path")
                if not isinstance(relative, str) or not relative:
                    return []
                event_path = self.paths.require_inside_root(paths.root / relative)
                return _read_redacted_jsonl(event_path)
            except (AndroidAssessorError, OSError, ValueError):
                return []

        traffic_events = state_events(paths.traffic_dir / "state.json")
        frida_events = state_events(paths.frida_dir / "state.json")
        logcat_events: list[dict[str, Any]] = []
        logcat_state_path = paths.logcat_dir / "state.json"
        try:
            logcat_state = read_json_object(logcat_state_path, root=self.paths.root)
            if (
                logcat_state.get("canary_observed") is True
                and logcat_state.get("collected_at")
                and summary.get("canary_fingerprint")
            ):
                logcat_events.append(
                    {
                        "observer": "logcat",
                        "session_id": record.session_id,
                        "scenario_id": summary["scenario_id"],
                        "step_id": "sink_verification",
                        "package": record.package,
                        "pid": logcat_state.get("target_pid", pid),
                        "process": process,
                        "timestamp": logcat_state["collected_at"],
                        "canary_fingerprint": summary["canary_fingerprint"],
                        "exact_owned_value_match": True,
                        "canary_match": True,
                        "evidence_id": logcat_state.get("evidence_id"),
                    }
                )
        except (AndroidAssessorError, OSError, ValueError):
            logcat_events = []
        normalized_traffic = []
        for event in traffic_events:
            value = dict(event)
            value.setdefault("observer", "traffic")
            value.setdefault("session_id", record.session_id)
            value.setdefault("scenario_id", summary["scenario_id"])
            value.setdefault("package", record.package)
            value.setdefault("pid", pid)
            value.setdefault("process", process)
            if value.get("attribution") == "validation_canary":
                value["canary_match"] = True
            normalized_traffic.append(value)
        normalized_frida = []
        for event in frida_events:
            value = dict(event)
            value.setdefault("observer", "frida")
            value.setdefault("session_id", record.session_id)
            value.setdefault("scenario_id", summary["scenario_id"])
            value.setdefault("package", record.package)
            value.setdefault("pid", pid)
            value.setdefault("process", process)
            normalized_frida.append(value)
        try:
            correlation = correlate_scenario_events(
                summary,
                traffic_events=normalized_traffic,
                frida_events=normalized_frida,
                logcat_events=logcat_events,
            )
            payload = correlation.to_dict()
        except (TypeError, ValueError) as exc:
            payload = {
                "events": [],
                "rejected": [],
                "accepted_count": 0,
                "rejected_count": 0,
                "correlation_error": redact_text(str(exc))[:300],
            }
        if sink_verification_quota is not None:
            _apply_sink_verification_quota(payload, sink_verification_quota)
        payload = {
            "schema_version": 1,
            "session_id": record.session_id,
            "scenario_id": summary["scenario_id"],
            "post_scenario_observation_window": post_scenario_window,
            **payload,
        }
        scenario_service.persist_correlation(
            record.session_id,
            str(summary["scenario_id"]),
            payload,
        )
        return payload

    def _scan_session_locked(
        self,
        record: SessionRecord,
        *,
        resolution: ScanProfileResolution,
        runtime_seconds: int | None = None,
        explorer_config: ExplorerConfig | None = None,
        controlled_canary: bool = False,
        ipc_validation: bool = False,
        micro_scenario: bool = False,
        scenario_request: ScenarioRequest | None = None,
    ) -> ScanResult:
        profile = resolution.effective_profile
        autonomous_enabled = resolution.autonomous_exploration_enabled
        paths = self.repository.paths_for(record.session_id)
        limitations: list[str] = []
        steps = {
            "profile": profile.value,
            "traffic_capture": "skipped" if profile is ScanProfile.QUICK else "pending",
            "frida_observation": "skipped" if profile is ScanProfile.QUICK else "pending",
            "autonomous_exploration": (
                "pending" if resolution.autonomous_exploration_enabled else "skipped"
            ),
            "deterministic_scenario": (
                "pending" if scenario_request is not None else "skipped"
            ),
            "controlled_canary": "pending" if controlled_canary else "skipped",
            "exported_component_validation": "pending" if ipc_validation else "skipped",
            "micro_scenario": "pending" if micro_scenario else "skipped",
            "target_logcat": "pending",
            "private_storage": "skipped" if profile is ScanProfile.QUICK else "pending",
            "rules": "pending",
            "report": "pending",
            "cleanup": "not_planned" if profile is ScanProfile.QUICK else "pending",
        }
        phase_timings: dict[str, float] = {}
        wall_started = time.perf_counter()
        runtime_termination = "not_started"
        runtime_started_at: str | None = None
        exploration_result: ExplorerResult | None = None
        exploration_executed = False
        controlled_canary_executed = False
        ipc_validation_executed = False
        ipc_validation_result = None
        micro_scenario_executed = False
        micro_scenario_execution: MicroScenarioExecution | None = None
        micro_scenario_seed: MicroScenarioSeed | None = None
        runtime_feedback_collector = RuntimeFeedbackCollector(paths)
        micro_scope = load_scope(self.paths) if micro_scenario else None
        scenario_result = None
        scenario_plan: ScenarioPlan | None = None
        scenario_correlation: dict[str, Any] | None = None
        scenario_service = (
            ScenarioService(self.context, self.repository)
            if scenario_request is not None
            else None
        )
        micro_scenario_service = (
            CandidateMicroScenarioService(ScenarioService(self.context, self.repository))
            if micro_scenario
            else None
        )
        assessment_canary = (
            generate_session_canary() if profile is ScanProfile.FULL else None
        )
        if scenario_service is not None and scenario_request is not None:
            try:
                scenario_plan = scenario_service.prepare(
                    scenario_request,
                    session_canary=assessment_canary,
                )
            except (AndroidAssessorError, OSError, ValueError) as exc:
                limitations.append(
                    f"Deterministic scenario preparation failed: {redact_text(str(exc))[:300]}"
                )
        if micro_scenario_service is not None and profile is ScanProfile.FULL:
            try:
                app_payload = read_json_object(paths.app_json, root=self.paths.root)
                manifest_payload = app_payload.get("manifest")
                static_payload = app_payload.get("static_analysis")
                micro_scenario_seed = micro_scenario_service.prepare(
                    record,
                    manifest=(
                        manifest_payload if isinstance(manifest_payload, Mapping) else {}
                    ),
                    static_analysis=(
                        static_payload if isinstance(static_payload, Mapping) else {}
                    ),
                    session_canary=assessment_canary or "",
                    allowed_hosts=(micro_scope.api_hosts if micro_scope is not None else ()),
                )
            except (AndroidAssessorError, OSError, ValueError) as exc:
                steps["micro_scenario"] = "failed_precondition"
                limitations.append(
                    "Micro-scenario preparation failed: "
                    f"{redact_text(str(exc))[:300]}"
                )
        paths.runtime_control_json.unlink(missing_ok=True)
        write_json_atomic(
            paths.scan_json,
            {
                "schema_version": 1,
                "session_id": record.session_id,
                "status": "running",
                "dynamic_steps": steps,
                "profile": profile.value,
                "requested_profile": resolution.requested_profile,
                "effective_profile": profile.value,
                "autonomous_exploration_requested": (
                    resolution.autonomous_exploration_requested
                ),
                "autonomous_exploration_executed": False,
                "controlled_canary_requested": controlled_canary,
                "controlled_canary_executed": False,
                "ipc_validation_requested": ipc_validation,
                "ipc_validation_executed": False,
                "micro_scenario_requested": micro_scenario,
                "micro_scenario_executed": False,
                "micro_scenario": None,
                "phase_timings": {},
            },
            root=self.paths.root,
        )

        def timed(name: str, started: float) -> None:
            phase_timings[name] = round((time.perf_counter() - started) * 1000, 2)

        traffic = TrafficCaptureService(self.context, self.repository)
        frida = FridaController(self.context, self.repository)
        traffic_started = False
        frida_started = False
        launched = False
        adb = self.context.adb_client(command_log=paths.commands_jsonl)
        preflight_started = time.perf_counter()
        try:
            adb.force_stop_package(record.serial, record.package)
        except AndroidAssessorError as exc:
            limitations.append(f"App reset before scan failed: {redact_text(str(exc))[:300]}")
        timed("preflight", preflight_started)

        try:
            if profile is ScanProfile.FULL:
                traffic_started_at = time.perf_counter()
                try:
                    traffic_kwargs: dict[str, Any] = {
                        "launch_app": False,
                        "canary": assessment_canary,
                    }
                    if micro_scenario_seed is not None:
                        traffic_kwargs["owned_value_fingerprints"] = dict(
                            micro_scenario_seed.owned_values
                        )
                        traffic_kwargs["upstream_mapping"] = dict(
                            micro_scenario_seed.upstream_mapping
                        )
                    if scenario_request is not None:
                        traffic_kwargs.update(
                            {
                                "retain_raw_flows": False,
                                "owned_value_fingerprints": (
                                    scenario_plan.owned_values
                                    if scenario_plan is not None
                                    else None
                                ),
                                "upstream_mapping": (
                                    scenario_plan.upstream_mapping
                                    if scenario_plan is not None
                                    else None
                                ),
                            }
                        )
                    traffic.start(record.session_id, **traffic_kwargs)
                    traffic_started = True
                    steps["traffic_capture"] = "running"
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["traffic_capture"] = "skipped"
                    limitations.append(f"Traffic capture skipped: {redact_text(str(exc))[:300]}")
                timed("traffic_startup", traffic_started_at)
                phase_timings["traffic"] = phase_timings["traffic_startup"]

                frida_started_at = time.perf_counter()
                if autonomous_enabled and not traffic_started:
                    steps["frida_observation"] = "skipped"
                    steps["autonomous_exploration"] = "skipped"
                    limitations.append(
                        "Autonomous runtime skipped because the scoped outbound "
                        "traffic guard did not start."
                    )
                else:
                    try:
                        frida.start(
                            record.session_id,
                            spawn=True,
                            canary=assessment_canary,
                        )
                        frida_started = True
                        launched = True
                        steps["frida_observation"] = "running"
                    except (AndroidAssessorError, OSError, ValueError) as exc:
                        steps["frida_observation"] = "skipped"
                        limitations.append(
                            f"Frida observation skipped: {redact_text(str(exc))[:300]}"
                        )
                timed("frida_startup", frida_started_at)
                phase_timings["frida_start"] = phase_timings["frida_startup"]

            if not launched and (not autonomous_enabled or traffic_started):
                try:
                    adb.launch_package(record.serial, record.package)
                    launched = True
                except AndroidAssessorError as exc:
                    limitations.append(f"App launch failed: {redact_text(str(exc))[:300]}")

            if launched or traffic_started or frida_started:
                runtime_started = time.perf_counter()
                wait_seconds = (
                    0
                    if profile is ScanProfile.QUICK
                    else runtime_seconds
                    if runtime_seconds is not None
                    else (
                        self.DEFAULT_AUTONOMOUS_RUNTIME_SECONDS
                        if autonomous_enabled
                        else self.DEFAULT_RUNTIME_SECONDS
                    )
                )
                if not self.MIN_RUNTIME_SECONDS <= wait_seconds <= self.MAX_RUNTIME_SECONDS:
                    raise ValueError(
                        "runtime_seconds must be between "
                        f"{self.MIN_RUNTIME_SECONDS} and {self.MAX_RUNTIME_SECONDS}."
                )
                runtime_started_at = datetime.now(UTC).isoformat()
                if micro_scenario_seed is not None and micro_scenario_service is not None:
                    runtime_feedback = runtime_feedback_collector.poll()
                    if runtime_feedback.categories:
                        micro_scenario_seed = micro_scenario_service.enrich_runtime_candidates(
                            micro_scenario_seed,
                            tuple(runtime_feedback.categories),
                        )
                if scenario_service is not None and scenario_plan is None:
                    steps["deterministic_scenario"] = "failed_precondition"
                    if not autonomous_enabled:
                        runtime_termination = "scenario_failed_precondition"
                elif scenario_service is not None and scenario_plan is not None:
                    scenario_started = time.perf_counter()
                    try:
                        scenario_scope = load_scope(self.paths)
                        scenario_result = scenario_service.run(
                            record.session_id,
                            plan=scenario_plan,
                            adb=AdbExplorerBackend(
                                adb,
                                serial=record.serial,
                                package=record.package,
                                session_id=record.session_id,
                                per_action_timeout=min(10, self.DEFAULT_RUNTIME_SECONDS),
                            ),
                            scope=scenario_scope,
                            network_guard_active=traffic_started,
                            available_observers=tuple(
                                observer
                                for observer, active in (
                                    ("frida", frida_started),
                                    ("traffic", traffic_started),
                                    ("logcat", True),
                                    ("private_storage", profile is ScanProfile.FULL),
                                )
                                if active
                            ),
                        )
                        steps["deterministic_scenario"] = scenario_result.outcome.value
                        if not autonomous_enabled:
                            runtime_termination = "scenario_" + scenario_result.outcome.value
                        if scenario_result.outcome.value != "completed":
                            limitations.append(
                                "Deterministic scenario did not complete: "
                                + scenario_result.outcome.value
                            )
                    except (AndroidAssessorError, OSError, ValueError) as exc:
                        steps["deterministic_scenario"] = "error"
                        if not autonomous_enabled:
                            runtime_termination = "scenario_error"
                        limitations.append(
                            f"Deterministic scenario failed: {redact_text(str(exc))[:300]}"
                        )
                    timed("scenario", scenario_started)
                if (
                    micro_scenario_seed is not None
                    and micro_scenario_service is not None
                    and scenario_request is None
                ):
                    micro_started = time.perf_counter()
                    try:
                        micro_backend = AdbExplorerBackend(
                            adb,
                            serial=record.serial,
                            package=record.package,
                            session_id=record.session_id,
                            per_action_timeout=min(8, max(1, wait_seconds)),
                        )
                        micro_backend.set_runtime_budget(
                            min(micro_scenario_seed.timeout_seconds, max(1, wait_seconds))
                        )
                        micro_scenario_execution = micro_scenario_service.run(
                            micro_scenario_seed,
                            backend=micro_backend,
                            scope=micro_scope or load_scope(self.paths),
                            network_guard_active=traffic_started,
                            available_observers=tuple(
                                observer
                                for observer, active in (
                                    ("frida", frida_started),
                                    ("traffic", traffic_started),
                                    ("logcat", True),
                                    ("private_storage", profile is ScanProfile.FULL),
                                )
                                if active
                            ),
                            serial=record.serial,
                        )
                        micro_scenario_executed = True
                        if micro_scenario_execution.completed:
                            steps["micro_scenario"] = "completed"
                        elif micro_scenario_execution.outcome == "out_of_scope":
                            steps["micro_scenario"] = "out_of_scope"
                        elif micro_scenario_execution.result is not None:
                            steps["micro_scenario"] = "partial"
                        else:
                            steps["micro_scenario"] = "not_exercised"
                        micro_scenario_service.persist(
                            record.session_id,
                            micro_scenario_execution,
                        )
                    except (AndroidAssessorError, OSError, ValueError) as exc:
                        steps["micro_scenario"] = "error"
                        limitations.append(
                            "Micro-scenario execution failed: "
                            f"{redact_text(str(exc))[:300]}"
                        )
                    timed("micro_scenario", micro_started)
                elif micro_scenario and scenario_request is not None:
                    steps["micro_scenario"] = "not_exercised"
                    limitations.append(
                        "Candidate micro-scenario was not exercised because the supplied "
                        "deterministic scenario owns the bounded mutation route."
                    )
                if autonomous_enabled:
                    selected_config = explorer_config or ExplorerConfig(
                        max_runtime_seconds=wait_seconds,
                    )
                    if controlled_canary:
                        selected_config = replace(
                            selected_config,
                            controlled_canary_delivery=True,
                        )
                    feedback_collector = runtime_feedback_collector
                    exploration_started = time.perf_counter()
                    try:
                        explorer_scope = load_scope(self.paths)
                        explorer_scope.require_device_package(
                            record.serial,
                            record.package,
                            action="inspect",
                        )
                        explorer_scope.require_device_package(
                            record.serial,
                            record.package,
                            action="autonomous_exploration",
                        )
                        exploration_executed = True
                        exploration_result = ExplorerService(
                            self.paths,
                            self.repository,
                        ).run(
                            record.session_id,
                            adb=adb,
                            scope=explorer_scope,
                            config=selected_config,
                            feedback=feedback_collector.poll,
                            stop_requested=lambda: self._runtime_stop_requested(record.session_id),
                            network_guard_active=traffic_started,
                            session_canary=assessment_canary,
                        )
                        runtime_termination = exploration_result.termination_reason
                        steps["autonomous_exploration"] = exploration_result.status
                        coverage_limitation = _exploration_coverage_limitation(
                            exploration_result
                        )
                        if coverage_limitation is not None:
                            limitations.append(coverage_limitation)
                        controlled_canary_executed = (
                            getattr(
                                exploration_result,
                                "controlled_canary_deliveries",
                                0,
                            )
                            > 0
                        )
                        if controlled_canary:
                            canary_attempts = _non_negative_count(
                                getattr(
                                    exploration_result,
                                    "controlled_canary_attempts",
                                    0,
                                )
                            )
                            canary_failures = _non_negative_count(
                                getattr(
                                    exploration_result,
                                    "controlled_canary_failures",
                                    0,
                                )
                            )
                            canary_budget_skips = _non_negative_count(
                                getattr(
                                    exploration_result,
                                    "controlled_canary_budget_skips",
                                    0,
                                )
                            )
                            if controlled_canary_executed:
                                steps["controlled_canary"] = "completed"
                            elif canary_attempts and canary_failures:
                                steps["controlled_canary"] = "delivery_failed"
                                limitations.append(
                                    "Controlled canary delivery was attempted but its "
                                    "bounded ADB action failed; completion is unknown and "
                                    "the action was not replayed."
                                )
                            elif canary_attempts:
                                steps["controlled_canary"] = "delivery_incomplete"
                                limitations.append(
                                    "Controlled canary delivery started but the bounded "
                                    "route did not reach a verified submit observation."
                                )
                            elif canary_budget_skips:
                                steps["controlled_canary"] = "not_exercised"
                                limitations.append(
                                    "A compatible bounded form was reached, but the "
                                    "remaining explorer action quota was insufficient for "
                                    "the complete controlled canary route."
                                )
                            else:
                                steps["controlled_canary"] = "not_exercised"
                                limitations.append(
                                    "Controlled canary delivery was not exercised because "
                                    "no compatible bounded form action was reached."
                                )
                    except (AndroidAssessorError, OSError, ValueError) as exc:
                        runtime_termination = "explorer_error"
                        steps["autonomous_exploration"] = "error"
                        if controlled_canary:
                            steps["controlled_canary"] = "error"
                        limitations.append(
                            f"Autonomous exploration failed: {redact_text(str(exc))[:300]}"
                        )
                    timed("exploration", exploration_started)
                elif scenario_service is None:
                    deadline = time.monotonic() + wait_seconds
                    while time.monotonic() < deadline:
                        if self._runtime_stop_requested(record.session_id):
                            runtime_termination = "stop_requested"
                            break
                        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
                    else:
                        runtime_termination = "timeout" if wait_seconds else "completed_no_wait"
                timed("runtime_interaction", runtime_started)
                phase_timings["runtime_observation"] = phase_timings["runtime_interaction"]
            else:
                runtime_termination = "not_started"
                if controlled_canary:
                    steps["controlled_canary"] = "not_exercised"
            if ipc_validation and profile is ScanProfile.FULL:
                ipc_started = time.perf_counter()
                if launched or traffic_started or frida_started:
                    try:
                        ipc_validation_result = ExportedComponentValidationService(
                            self.context,
                            self.repository,
                        ).run(
                            record.session_id,
                            adb=adb,
                            scope=load_scope(self.paths),
                        )
                        ipc_validation_executed = True
                        outcomes = {
                            route.outcome.value for route in ipc_validation_result.routes
                        }
                        if "confirmed" in outcomes:
                            steps["exported_component_validation"] = "completed"
                        elif any(route.attempted for route in ipc_validation_result.routes):
                            steps["exported_component_validation"] = "partial"
                        elif outcomes and outcomes <= {"out_of_scope"}:
                            steps["exported_component_validation"] = "out_of_scope"
                        else:
                            steps["exported_component_validation"] = "not_exercised"
                    except (AndroidAssessorError, OSError, ValueError) as exc:
                        steps["exported_component_validation"] = "error"
                        limitations.append(
                            "Exported-component validation failed: "
                            f"{redact_text(str(exc))[:300]}"
                        )
                else:
                    steps["exported_component_validation"] = "not_exercised"
                    limitations.append(
                        "Exported-component validation was not exercised because the "
                        "target runtime did not start."
                    )
                timed("exported_component_validation", ipc_started)
        finally:
            analysis_started = time.perf_counter()
            if frida_started:
                try:
                    stopped = frida.stop(record.session_id)
                    steps["frida_observation"] = stopped.status
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["frida_observation"] = "stop_failed"
                    limitations.append(f"Frida stop failed: {redact_text(str(exc))[:300]}")
                except Exception as exc:
                    LOGGER.exception(
                        "Unexpected Frida stop failure for session %s.",
                        record.session_id,
                    )
                    steps["frida_observation"] = "stop_failed"
                    limitations.append(
                        f"Frida stop failed unexpectedly: {redact_text(str(exc))[:300]}"
                    )
            if traffic_started:
                try:
                    stopped = traffic.stop(record.session_id)
                    steps["traffic_capture"] = stopped.status
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["traffic_capture"] = "stop_failed"
                    limitations.append(f"Traffic stop failed: {redact_text(str(exc))[:300]}")
                except Exception as exc:
                    LOGGER.exception(
                        "Unexpected traffic stop failure for session %s.",
                        record.session_id,
                    )
                    steps["traffic_capture"] = "stop_failed"
                    limitations.append(
                        f"Traffic stop failed unexpectedly: {redact_text(str(exc))[:300]}"
                    )
            timed("runtime_analysis", analysis_started)

        runtime_phases = []
        if runtime_started_at is not None:
            frida_mode = None
            try:
                state_path = paths.frida_dir / "state.json"
                if state_path.is_file():
                    frida_mode = read_json_object(state_path, root=self.paths.root).get("mode")
            except (AndroidAssessorError, OSError, ValueError):
                frida_mode = None
            runtime_phases.append(
                {
                    "name": "runtime_interaction",
                    "mode": "automatic_startup_and_window",
                    "start_time": runtime_started_at,
                    "duration_ms": phase_timings.get("runtime_interaction"),
                    "event_count": None,
                    "categories": (
                        list(exploration_result.runtime_categories)
                        if exploration_result is not None
                        else []
                    ),
                    "effective_frida_mode": frida_mode,
                    "termination_reason": runtime_termination,
                }
            )

        if profile is ScanProfile.FULL:
            storage_started = time.perf_counter()
            try:
                backend = AdbPrivateStorageBackend(adb)
                if record.serial.startswith("emulator-"):
                    backend.environment_type = "emulator"
                PrivateStorageService(self.repository, backend).collect(
                    record.session_id,
                    session_canary=assessment_canary,
                )
                steps["private_storage"] = "completed"
            except (AndroidAssessorError, OSError, ValueError) as exc:
                steps["private_storage"] = "skipped"
                limitations.append(f"Private storage skipped: {redact_text(str(exc))[:300]}")
            timed("storage", storage_started)

        logcat_started = time.perf_counter()
        try:
            logcat = LogcatCollector(self.context, self.repository).collect(
                record.session_id,
                canary=assessment_canary,
            )
            steps["target_logcat"] = logcat.status
            if logcat.error:
                limitations.append(logcat.error)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            steps["target_logcat"] = "skipped"
            limitations.append(f"Target logcat skipped: {redact_text(str(exc))[:300]}")
        timed("logcat", logcat_started)

        correlation_result = scenario_result
        correlation_plan: Any = scenario_plan
        correlation_service = scenario_service
        correlation_quota: int | None = None
        if micro_scenario_execution is not None and micro_scenario_execution.result is not None:
            correlation_result = micro_scenario_execution.result
            correlation_plan = micro_scenario_execution.plan
            correlation_service = (
                micro_scenario_service.scenario_service
                if micro_scenario_service is not None
                else None
            )
            correlation_quota = micro_scenario_execution.seed.sink_verification_quota
        if (
            correlation_result is not None
            and correlation_plan is not None
            and correlation_service is not None
        ):
            correlation_started = time.perf_counter()
            try:
                scenario_correlation = self._finalize_scenario_correlation(
                    record,
                    scenario_result=correlation_result,
                    scenario_plan=correlation_plan,
                    scenario_service=correlation_service,
                    sink_verification_quota=correlation_quota,
                    allow_post_scenario_observation_window=not (
                        exploration_executed or ipc_validation_executed
                    ),
                )
            except (AndroidAssessorError, OSError, ValueError) as exc:
                limitations.append(
                    "Scenario evidence correlation failed: "
                    f"{redact_text(str(exc))[:300]}"
                )
            timed("scenario_correlation", correlation_started)

        metadata_result = scenario_result
        if micro_scenario_execution is not None and micro_scenario_execution.result is not None:
            metadata_result = micro_scenario_execution.result
        scenario_metadata = {
            "scenario_id": (
                metadata_result.scenario_id if metadata_result is not None else None
            ),
            "scenario_correlation_path": (
                "redacted/scenario/"
                + metadata_result.scenario_id
                + "/correlation.json"
                if scenario_correlation is not None and metadata_result is not None
                else None
            ),
            "micro_scenario_path": (
                "redacted/micro-scenario/result.json"
                if micro_scenario_execution is not None
                else None
            ),
        }
        micro_scenario_payload = (
            micro_scenario_execution.to_dict()
            if micro_scenario_execution is not None
            else None
        )

        # Persist the execution outcome before rule evaluation so capability-
        # dependent rules can distinguish an unavailable module from a failed
        # planned execution. The final scan artifact is still written below.
        steps["rules"] = "running"
        write_json_atomic(
            paths.scan_json,
            {
                "schema_version": 1,
                "session_id": record.session_id,
                "status": "running",
                "dynamic_steps": steps,
                "limitations": limitations,
                "profile": profile.value,
                "requested_profile": resolution.requested_profile,
                "effective_profile": profile.value,
                "autonomous_exploration_requested": (
                    resolution.autonomous_exploration_requested
                ),
                "autonomous_exploration_executed": exploration_executed,
                "controlled_canary_requested": controlled_canary,
                "controlled_canary_executed": controlled_canary_executed,
                "ipc_validation_requested": ipc_validation,
                "ipc_validation_executed": ipc_validation_executed,
                "micro_scenario_requested": micro_scenario,
                "micro_scenario_executed": micro_scenario_executed,
                "micro_scenario": micro_scenario_payload,
                "ipc_validation": (
                    ipc_validation_result.to_dict()
                    if ipc_validation_result is not None
                    else None
                ),
                "phase_timings": phase_timings,
                "runtime_termination": runtime_termination,
                **scenario_metadata,
            },
            root=self.paths.root,
        )
        rules_started = time.perf_counter()
        findings = RuleEngine(self.paths, self.repository).evaluate(record.session_id)
        steps["rules"] = "completed"
        timed("rule_evaluation", rules_started)
        steps["report"] = "completed"
        write_json_atomic(
            paths.scan_json,
            {
                "schema_version": 1,
                "session_id": record.session_id,
                "status": "completed",
                "dynamic_steps": steps,
                "limitations": limitations,
                "profile": profile.value,
                "requested_profile": resolution.requested_profile,
                "effective_profile": profile.value,
                "autonomous_exploration_requested": (
                    resolution.autonomous_exploration_requested
                ),
                "autonomous_exploration_executed": exploration_executed,
                "controlled_canary_requested": controlled_canary,
                "controlled_canary_executed": controlled_canary_executed,
                "ipc_validation_requested": ipc_validation,
                "ipc_validation_executed": ipc_validation_executed,
                "micro_scenario_requested": micro_scenario,
                "micro_scenario_executed": micro_scenario_executed,
                "micro_scenario": micro_scenario_payload,
                "ipc_validation": (
                    ipc_validation_result.to_dict()
                    if ipc_validation_result is not None
                    else None
                ),
                "phase_timings": phase_timings,
                "runtime_termination": runtime_termination,
                "runtime_started_at": runtime_started_at,
                "wall_clock_duration_ms": round((time.perf_counter() - wall_started) * 1000, 2),
                "parallel_phases": [],
                "runtime_phases": runtime_phases,
                "autonomous_exploration": (
                    exploration_result.to_dict() if exploration_result is not None else None
                ),
                **scenario_metadata,
            },
            root=self.paths.root,
        )
        try:
            report_started = time.perf_counter()
            ReportService(self.paths, self.repository).generate(
                record.session_id,
                limitations=limitations,
            )
            timed("report", report_started)
            write_json_atomic(
                paths.scan_json,
                {
                    "schema_version": 1,
                    "session_id": record.session_id,
                    "status": "completed",
                    "dynamic_steps": steps,
                    "limitations": limitations,
                    "profile": profile.value,
                    "requested_profile": resolution.requested_profile,
                    "effective_profile": profile.value,
                    "autonomous_exploration_requested": (
                        resolution.autonomous_exploration_requested
                    ),
                    "autonomous_exploration_executed": exploration_executed,
                    "controlled_canary_requested": controlled_canary,
                    "controlled_canary_executed": controlled_canary_executed,
                    "ipc_validation_requested": ipc_validation,
                    "ipc_validation_executed": ipc_validation_executed,
                    "micro_scenario_requested": micro_scenario,
                    "micro_scenario_executed": micro_scenario_executed,
                    "micro_scenario": micro_scenario_payload,
                    "ipc_validation": (
                        ipc_validation_result.to_dict()
                        if ipc_validation_result is not None
                        else None
                    ),
                    "phase_timings": phase_timings,
                    "runtime_termination": runtime_termination,
                    "runtime_started_at": runtime_started_at,
                    "wall_clock_duration_ms": round((time.perf_counter() - wall_started) * 1000, 2),
                    "parallel_phases": [],
                    "runtime_phases": runtime_phases,
                    "autonomous_exploration": (
                        exploration_result.to_dict() if exploration_result is not None else None
                    ),
                    **scenario_metadata,
                },
                root=self.paths.root,
            )
            # Re-render once with the measured report phase so coverage timing
            # describes the final artifact rather than a missing placeholder.
            ReportService(self.paths, self.repository).generate(
                record.session_id,
                limitations=limitations,
            )
        except (AndroidAssessorError, OSError, ValueError):
            steps["report"] = "error"
            write_json_atomic(
                paths.scan_json,
                {
                    "schema_version": 1,
                    "session_id": record.session_id,
                    "status": "error",
                    "dynamic_steps": steps,
                    "limitations": limitations,
                    "profile": profile.value,
                    "requested_profile": resolution.requested_profile,
                    "effective_profile": profile.value,
                    "autonomous_exploration_requested": (
                        resolution.autonomous_exploration_requested
                    ),
                    "autonomous_exploration_executed": exploration_executed,
                    "runtime_termination": runtime_termination,
                    "ipc_validation_requested": ipc_validation,
                    "ipc_validation_executed": ipc_validation_executed,
                    "micro_scenario_requested": micro_scenario,
                    "micro_scenario_executed": micro_scenario_executed,
                    "micro_scenario": micro_scenario_payload,
                },
                root=self.paths.root,
            )
            raise
        self.repository.append_event(
            record.session_id,
            "scan_completed",
            {"steps": steps, "profile": profile.value, "limitation_count": len(limitations)},
        )
        return ScanResult(
            session_id=record.session_id,
            findings=tuple(findings),
            limitations=tuple(limitations),
            dynamic_steps=steps,
            profile=profile.value,
            phase_timings=phase_timings,
            requested_profile=resolution.requested_profile,
            effective_profile=profile.value,
            autonomous_exploration_requested=(
                resolution.autonomous_exploration_requested
            ),
            autonomous_exploration_executed=exploration_executed,
            controlled_canary_requested=controlled_canary,
            controlled_canary_executed=controlled_canary_executed,
            ipc_validation_requested=ipc_validation,
            ipc_validation_executed=ipc_validation_executed,
            micro_scenario_requested=micro_scenario,
            micro_scenario_executed=micro_scenario_executed,
            report_path="report.html",
        )
