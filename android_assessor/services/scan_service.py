"""End-to-end MVP scan orchestration with optional capabilities degrading safely."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ..app_context import AppContext
from ..device_lock import DeviceLock
from ..errors import AndroidAssessorError
from ..findings import FindingRecord
from ..frida_controller import FridaController
from ..logcat import LogcatCollector
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "findings": [finding.to_dict() for finding in self.findings],
            "limitations": list(self.limitations),
            "dynamic_steps": dict(self.dynamic_steps),
            "report_path": self.report_path,
        }


class ScanService:
    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
    ) -> None:
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)

    def scan(self, *, package: str, serial: str | None = None) -> ScanResult:
        inspection = AppInspectionService(self.context, self.repository).inspect(
            package=package,
            serial=serial,
        )
        return self.scan_session(inspection.session_id)

    def scan_session(self, session_id: str) -> ScanResult:
        record = self.repository.load(session_id)
        scope = load_scope(self.paths)
        scope.require_device_package(record.serial, record.package)
        scope.require_actions(("inspect", "traffic_capture", "frida_observe"))
        self.repository.require_modifying_session_slot(record.serial, record.session_id)
        with DeviceLock(
            self.paths,
            record.serial,
            operation="scan",
            session_id=record.session_id,
            timeout=0,
        ):
            return self._scan_session_locked(record)

    def _scan_session_locked(self, record: SessionRecord) -> ScanResult:
        paths = self.repository.paths_for(record.session_id)
        limitations: list[str] = []
        steps = {
            "traffic_capture": "pending",
            "frida_observation": "pending",
            "target_logcat": "pending",
            "rules": "pending",
            "report": "pending",
        }
        traffic = TrafficCaptureService(self.context, self.repository)
        frida = FridaController(self.context, self.repository)
        traffic_started = False
        frida_started = False
        launched = False
        adb = self.context.adb_client(command_log=paths.commands_jsonl)
        try:
            adb.force_stop_package(record.serial, record.package)
        except AndroidAssessorError as exc:
            limitations.append(f"App reset before scan failed: {redact_text(str(exc))[:300]}")

        try:
            try:
                traffic.start(record.session_id, launch_app=False)
                traffic_started = True
                steps["traffic_capture"] = "running"
            except (AndroidAssessorError, OSError, ValueError) as exc:
                steps["traffic_capture"] = "skipped"
                limitations.append(
                    f"Traffic capture skipped: {redact_text(str(exc))[:300]}"
                )

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

            if not launched:
                try:
                    adb.launch_package(record.serial, record.package)
                    launched = True
                except AndroidAssessorError as exc:
                    limitations.append(
                        f"App launch failed: {redact_text(str(exc))[:300]}"
                    )

            if launched or traffic_started or frida_started:
                time.sleep(5)
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

        try:
            logcat = LogcatCollector(self.context, self.repository).collect(record.session_id)
            steps["target_logcat"] = logcat.status
            if logcat.error:
                limitations.append(logcat.error)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            steps["target_logcat"] = "skipped"
            limitations.append(f"Target logcat skipped: {redact_text(str(exc))[:300]}")

        findings = RuleEngine(self.paths, self.repository).evaluate(record.session_id)
        steps["rules"] = "completed"
        steps["report"] = "completed"
        write_json_atomic(
            paths.scan_json,
            {
                "schema_version": 1,
                "session_id": record.session_id,
                "status": "completed",
                "dynamic_steps": steps,
                "limitations": limitations,
            },
            root=self.paths.root,
        )
        try:
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
                },
                root=self.paths.root,
            )
            raise
        self.repository.append_event(
            record.session_id,
            "mvp_scan_completed",
            {"steps": steps, "limitation_count": len(limitations)},
        )
        return ScanResult(
            session_id=record.session_id,
            findings=tuple(findings),
            limitations=tuple(limitations),
            dynamic_steps=steps,
            report_path="report.html",
        )
