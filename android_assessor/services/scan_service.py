"""Profile-driven assessment orchestration with bounded capability use."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from ..app_context import AppContext
from ..device_lock import DeviceLock
from ..errors import AndroidAssessorError
from ..explorer import (
    ExplorerConfig,
    ExplorerResult,
    ExplorerService,
    RuntimeFeedbackCollector,
)
from ..findings import FindingRecord
from ..frida_controller import FridaController
from ..logcat import LogcatCollector
from ..private_storage import AdbPrivateStorageBackend, PrivateStorageService
from ..redaction import redact_text
from ..report import ReportService
from ..rules import RuleEngine
from ..scope import load_scope
from ..session import SessionRecord, SessionRepository
from ..storage import read_json_object, write_json_atomic
from ..traffic import TrafficCaptureService
from ..validation import generate_session_canary
from .app_inspection_service import AppInspectionService
from .cleanup_service import CleanupService

LOGGER = logging.getLogger(__name__)


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
    ) -> ScanResult:
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
        )

    def scan_session(
        self,
        session_id: str,
        *,
        profile: str | ScanProfile | None = None,
        runtime_seconds: int | None = None,
        autonomous: bool | None = None,
        explorer_config: ExplorerConfig | None = None,
    ) -> ScanResult:
        resolution = resolve_scan_profile(
            profile,
            autonomous=autonomous,
            explorer_config=explorer_config,
        )
        record = self.repository.load(session_id)
        scope = load_scope(self.paths)
        scope.require_device_package(record.serial, record.package)
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

    def _scan_session_locked(
        self,
        record: SessionRecord,
        *,
        resolution: ScanProfileResolution,
        runtime_seconds: int | None = None,
        explorer_config: ExplorerConfig | None = None,
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
        assessment_canary = (
            generate_session_canary() if profile is ScanProfile.FULL else None
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
                    traffic.start(
                        record.session_id,
                        launch_app=False,
                        canary=assessment_canary,
                    )
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
                if autonomous_enabled:
                    selected_config = explorer_config or ExplorerConfig(
                        max_runtime_seconds=wait_seconds,
                    )
                    feedback_collector = RuntimeFeedbackCollector(paths)
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
                            action="controlled_validation",
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
                    except (AndroidAssessorError, OSError, ValueError) as exc:
                        runtime_termination = "explorer_error"
                        steps["autonomous_exploration"] = "error"
                        limitations.append(
                            f"Autonomous exploration failed: {redact_text(str(exc))[:300]}"
                        )
                    timed("exploration", exploration_started)
                else:
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
                "phase_timings": phase_timings,
                "runtime_termination": runtime_termination,
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
                "phase_timings": phase_timings,
                "runtime_termination": runtime_termination,
                "runtime_started_at": runtime_started_at,
                "wall_clock_duration_ms": round((time.perf_counter() - wall_started) * 1000, 2),
                "parallel_phases": [],
                "runtime_phases": runtime_phases,
                "autonomous_exploration": (
                    exploration_result.to_dict() if exploration_result is not None else None
                ),
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
                    "phase_timings": phase_timings,
                    "runtime_termination": runtime_termination,
                    "runtime_started_at": runtime_started_at,
                    "wall_clock_duration_ms": round((time.perf_counter() - wall_started) * 1000, 2),
                    "parallel_phases": [],
                    "runtime_phases": runtime_phases,
                    "autonomous_exploration": (
                        exploration_result.to_dict() if exploration_result is not None else None
                    ),
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
                },
                root=self.paths.root,
            )
            raise
        self.repository.append_event(
            record.session_id,
            "mvp_scan_completed",
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
            report_path="report.html",
        )
