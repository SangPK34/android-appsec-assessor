"""Profile-driven assessment orchestration with bounded capability use."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..app_context import AppContext
from ..device_lock import DeviceLock
from ..errors import AndroidAssessorError
from ..findings import FindingRecord
from ..frida_controller import FridaController
from ..logcat import LogcatCollector
from ..private_storage import AdbPrivateStorageBackend, PrivateStorageService
from ..redaction import redact_text
from ..report import ReportService
from ..rules import RuleEngine
from ..scope import load_scope
from ..session import SessionRecord, SessionRepository
from ..storage import write_json_atomic
from ..traffic import TrafficCaptureService
from .app_inspection_service import AppInspectionService


@dataclass(frozen=True, slots=True)
class ScanResult:
    session_id: str
    findings: tuple[FindingRecord, ...]
    limitations: tuple[str, ...]
    dynamic_steps: dict[str, str]
    report_path: str
    profile: str = "quick"
    phase_timings: dict[str, float] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "findings": [finding.to_dict() for finding in self.findings],
            "limitations": list(self.limitations),
            "dynamic_steps": dict(self.dynamic_steps),
            "profile": self.profile,
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


class ScanService:
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
        profile: str | ScanProfile = ScanProfile.QUICK,
    ) -> ScanResult:
        inspection = AppInspectionService(self.context, self.repository).inspect(
            package=package,
            serial=serial,
        )
        return self.scan_session(inspection.session_id, profile=profile)

    def scan_session(
        self,
        session_id: str,
        *,
        profile: str | ScanProfile | None = None,
        runtime_seconds: int | None = None,
    ) -> ScanResult:
        # Direct callers from the pre-profile API retain the dynamic workflow;
        # CLI/Web callers pass ``quick`` explicitly.
        selected_profile = ScanProfile.FULL if profile is None else ScanProfile.parse(profile)
        record = self.repository.load(session_id)
        scope = load_scope(self.paths)
        scope.require_device_package(record.serial, record.package)
        self.repository.require_modifying_session_slot(record.serial, record.session_id)
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
            return self._scan_session_locked(
                self.repository.load(record.session_id),
                profile=selected_profile,
                runtime_seconds=runtime_seconds,
            )

    def _scan_session_locked(
        self,
        record: SessionRecord,
        *,
        profile: ScanProfile,
        runtime_seconds: int | None = None,
    ) -> ScanResult:
        paths = self.repository.paths_for(record.session_id)
        limitations: list[str] = []
        steps = {
            "profile": profile.value,
            "traffic_capture": "skipped" if profile is ScanProfile.QUICK else "pending",
            "frida_observation": "skipped" if profile is ScanProfile.QUICK else "pending",
            "target_logcat": "pending",
            "private_storage": "skipped" if profile is ScanProfile.QUICK else "pending",
            "rules": "pending",
            "report": "pending",
        }
        phase_timings: dict[str, float] = {}

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
                    traffic.start(record.session_id, launch_app=False)
                    traffic_started = True
                    steps["traffic_capture"] = "running"
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["traffic_capture"] = "skipped"
                    limitations.append(
                        f"Traffic capture skipped: {redact_text(str(exc))[:300]}"
                    )
                timed("traffic", traffic_started_at)

                frida_started_at = time.perf_counter()
                try:
                    frida.start(record.session_id, spawn=True)
                    frida_started = True
                    launched = True
                    steps["frida_observation"] = "running"
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["frida_observation"] = "skipped"
                    limitations.append(
                        f"Frida observation skipped: {redact_text(str(exc))[:300]}"
                    )
                timed("frida_start", frida_started_at)

            if not launched:
                try:
                    adb.launch_package(record.serial, record.package)
                    launched = True
                except AndroidAssessorError as exc:
                    limitations.append(
                        f"App launch failed: {redact_text(str(exc))[:300]}"
                    )

            if launched or traffic_started or frida_started:
                runtime_started = time.perf_counter()
                wait_seconds = runtime_seconds if runtime_seconds is not None else (
                    5 if profile is ScanProfile.FULL else 0
                )
                if wait_seconds < 0 or wait_seconds > 300:
                    raise ValueError("runtime_seconds must be between 0 and 300.")
                if wait_seconds:
                    time.sleep(wait_seconds)
                timed("runtime_observation", runtime_started)
        finally:
            if frida_started:
                try:
                    stopped = frida.stop(record.session_id)
                    steps["frida_observation"] = stopped.status
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["frida_observation"] = "stop_failed"
                    limitations.append(
                        f"Frida stop failed: {redact_text(str(exc))[:300]}"
                    )
            if traffic_started:
                try:
                    stopped = traffic.stop(record.session_id)
                    steps["traffic_capture"] = stopped.status
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["traffic_capture"] = "stop_failed"
                    limitations.append(
                        f"Traffic stop failed: {redact_text(str(exc))[:300]}"
                    )

        if profile is ScanProfile.FULL:
            storage_started = time.perf_counter()
            try:
                backend = AdbPrivateStorageBackend(adb)
                if record.serial.startswith("emulator-"):
                    backend.environment_type = "emulator"
                PrivateStorageService(self.repository, backend).collect(record.session_id)
                steps["private_storage"] = "completed"
            except (AndroidAssessorError, OSError, ValueError) as exc:
                steps["private_storage"] = "skipped"
                limitations.append(
                    f"Private storage skipped: {redact_text(str(exc))[:300]}"
                )
            timed("storage", storage_started)

        logcat_started = time.perf_counter()
        try:
            logcat = LogcatCollector(self.context, self.repository).collect(record.session_id)
            steps["target_logcat"] = logcat.status
            if logcat.error:
                limitations.append(logcat.error)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            steps["target_logcat"] = "skipped"
            limitations.append(f"Target logcat skipped: {redact_text(str(exc))[:300]}")
        timed("logcat", logcat_started)

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
                "phase_timings": phase_timings,
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
                    "phase_timings": phase_timings,
                },
                root=self.paths.root,
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
            report_path="report.html",
        )
