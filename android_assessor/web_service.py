"""Safe service facade used by the local FastAPI user interface."""

from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .adb import device_state_guidance, mask_serial
from .app import ApplicationSelectionStore, ApplicationService
from .app_context import AppContext
from .capabilities import CapabilityDetector
from .device import DeviceSelectionStore
from .device_lock import DeviceLock
from .environment import collect_environment
from .errors import AndroidAssessorError, DeviceBusyError, SessionError
from .findings import FindingRepository
from .frida_controller import FridaController
from .paths import ProjectPaths
from .redaction import redact_text
from .report import ReportService
from .rules import RuleEngine
from .services.app_inspection_service import AppInspectionService
from .services.cleanup_service import CleanupService
from .services.device_service import DeviceService
from .services.scan_service import ScanService
from .services.validation_service import ValidationService
from .session import SessionRepository
from .storage import read_json_object
from .traffic import TrafficCaptureService
from .validation import validate_package_name


class WebBackendProtocol(Protocol):
    def dashboard(self) -> dict[str, Any]: ...

    def devices(self) -> dict[str, Any]: ...

    def select_device(self, serial: str) -> dict[str, Any]: ...

    def applications(self, query: str = "") -> dict[str, Any]: ...

    def select_application(self, package: str) -> dict[str, Any]: ...

    def inspect_application(self, package: str) -> dict[str, Any]: ...

    def app_inspection(self, session_id: str) -> dict[str, Any]: ...

    def session_detail(self, session_id: str) -> dict[str, Any]: ...

    def scan_session(
        self,
        session_id: str,
        profile: str = "quick",
        *,
        runtime_seconds: int | None = None,
        autonomous: bool | None = None,
    ) -> dict[str, Any]: ...

    def request_runtime_stop(self, session_id: str) -> dict[str, Any]: ...

    def validate_finding(self, session_id: str, finding_id: str) -> dict[str, Any]: ...

    def start_traffic(self, session_id: str) -> dict[str, Any]: ...

    def stop_traffic(self, session_id: str) -> dict[str, Any]: ...

    def start_frida(self, session_id: str) -> dict[str, Any]: ...

    def stop_frida(self, session_id: str) -> dict[str, Any]: ...

    def generate_report(self, session_id: str) -> dict[str, Any]: ...

    def report_path(self, session_id: str) -> Path: ...

    def sessions(self) -> list[dict[str, Any]]: ...

    def cleanup_session(self, session_id: str) -> dict[str, Any]: ...

    def environment(self) -> dict[str, Any]: ...

    def repair_status(self) -> dict[str, Any]: ...

    def start_repair(self) -> dict[str, Any]: ...

    def setup_log(self) -> str: ...


@dataclass(frozen=True, slots=True)
class RepairState:
    running: bool
    pid: int | None = None
    exit_code: int | None = None
    started_at: str | None = None
    finished_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RepairController:
    """Starts only the project's fixed repair.cmd, never a user-supplied command."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.script = self.root / "repair.cmd"
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._started_at: str | None = None
        self._finished_at: str | None = None
        self._exit_code: int | None = None

    def _status_unlocked(self) -> RepairState:
        running = False
        pid: int | None = None
        if self._process is not None:
            pid = self._process.pid
            exit_code = self._process.poll()
            running = exit_code is None
            if exit_code is not None and self._exit_code is None:
                self._exit_code = exit_code
                self._finished_at = datetime.now(UTC).isoformat()
        return RepairState(
            running=running,
            pid=pid,
            exit_code=self._exit_code,
            started_at=self._started_at,
            finished_at=self._finished_at,
        )

    def status(self) -> RepairState:
        with self._lock:
            return self._status_unlocked()

    def start(self) -> RepairState:
        with self._lock:
            if self._status_unlocked().running:
                raise AndroidAssessorError("Repair is already running.")
            if not self.script.is_file():
                raise AndroidAssessorError("repair.cmd is missing from the project root.")
            command_processor = os.environ.get("COMSPEC", "cmd.exe")
            creation_flags = 0
            if os.name == "nt":
                creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            try:
                self._process = subprocess.Popen(
                    [command_processor, "/d", "/c", str(self.script)],
                    cwd=self.root,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    creationflags=creation_flags,
                    close_fds=True,
                )
            except OSError as exc:
                raise AndroidAssessorError(f"Could not start repair.cmd: {exc}") from exc
            self._started_at = datetime.now(UTC).isoformat()
            self._finished_at = None
            self._exit_code = None
            return self._status_unlocked()


class WebBackend:
    def __init__(self, context: AppContext) -> None:
        self.context = context
        self.paths = context.paths
        self.device_store = DeviceSelectionStore(self.paths)
        self.target_store = ApplicationSelectionStore(self.paths)
        self.repository = SessionRepository(self.paths)
        self.repair = RepairController(self.paths.root)

    @classmethod
    def create(cls, paths: ProjectPaths | None = None) -> WebBackend:
        return cls(AppContext.create(paths))

    def _device_lock_state(self, serial: str) -> dict[str, Any] | None:
        probe = DeviceLock(self.paths, serial, operation="web_status_probe", timeout=0)
        if not probe.metadata_path.is_file():
            return None
        try:
            with probe:
                return None
        except DeviceBusyError:
            try:
                payload = read_json_object(probe.metadata_path, root=self.paths.root)
            except SessionError:
                return {"busy": True, "operation": "unknown", "session_id": None}
            return {
                "busy": True,
                "operation": str(payload.get("operation", "unknown"))[:100],
                "session_id": payload.get("session_id"),
                "acquired_at": payload.get("acquired_at"),
            }

    def devices(self) -> dict[str, Any]:
        adb = self.context.adb_client()
        active_serial = self.device_store.read_serial()
        items: list[dict[str, Any]] = []
        for device in adb.list_devices():
            item = device.to_dict(show_serial=False)
            item["selection_value"] = device.serial
            item["selected"] = device.serial == active_serial
            item["guidance"] = None if device.authorized else device_state_guidance(device.state)
            item["lock"] = self._device_lock_state(device.serial)
            items.append(item)
        return {
            "devices": items,
            "active_serial": active_serial,
            "active_serial_masked": mask_serial(active_serial) if active_serial else None,
            "selected_connected": any(item["selected"] for item in items),
        }

    def select_device(self, serial: str) -> dict[str, Any]:
        previous = self.device_store.read_serial()
        selected = self.context.device_selector().select(serial)
        if previous != selected.serial:
            self.target_store.clear()
        return selected.to_dict(show_serial=False)

    def _application_service(self) -> ApplicationService:
        adb = self.context.adb_client()
        selector = self.context.device_selector(adb)
        return ApplicationService(adb, selector, self.target_store)

    def applications(self, query: str = "") -> dict[str, Any]:
        serial, applications = self._application_service().list_user_apps(query=query)
        selected_package = self.target_store.read(serial=serial)
        return {
            "serial_masked": mask_serial(serial),
            "selected_package": selected_package,
            "query": query.strip(),
            "applications": [
                {**application.to_dict(), "selected": application.package == selected_package}
                for application in applications
            ],
        }

    def select_application(self, package: str) -> dict[str, Any]:
        return self._application_service().select(package).to_dict()

    def inspect_application(self, package: str) -> dict[str, Any]:
        target = validate_package_name(package)
        serial = self.device_store.read_serial()
        if serial is None:
            raise AndroidAssessorError("Select an authorized device before inspecting an app.")
        selected_target = self.target_store.read(serial=serial)
        if selected_target != target:
            raise AndroidAssessorError("Select the package before starting app inspection.")
        return (
            AppInspectionService(self.context, self.repository)
            .inspect(
                package=target,
                serial=serial,
            )
            .to_dict()
        )

    def app_inspection(self, session_id: str) -> dict[str, Any]:
        session_paths = self.repository.paths_for(session_id)
        return read_json_object(session_paths.app_json, root=self.paths.root)

    def _optional_session_json(self, path: Path) -> dict[str, Any] | None:
        if not path.is_file():
            return None
        try:
            return read_json_object(path, root=self.paths.root)
        except SessionError:
            return None

    def session_detail(self, session_id: str) -> dict[str, Any]:
        record = self.repository.load(session_id)
        paths = self.repository.paths_for(record.session_id)
        findings = FindingRepository(self.paths, self.repository).list(record.session_id)
        evidence_state = self._optional_session_json(paths.evidence_index) or {}
        evidence_values = evidence_state.get("evidence", [])
        report = self._optional_session_json(paths.report_json) or {}
        report_findings = report.get("findings")
        finding_payload = (
            report_findings
            if isinstance(report_findings, list)
            else [finding.to_dict() for finding in findings]
        )
        observations = report.get("runtime_observations", [])
        runtime_categories = (
            sorted(
                {
                    str(item.get("rule_id", "")).removeprefix("ASL-RUNTIME-").casefold()
                    for item in observations
                    if isinstance(item, dict)
                    and item.get("status") not in {"skipped", "inconclusive"}
                }
            )
            if isinstance(observations, list)
            else []
        )
        return {
            "session": record.to_dict(show_serial=False),
            "app": self._optional_session_json(paths.app_json),
            "scan": self._optional_session_json(paths.scan_json),
            "traffic": self._optional_session_json(paths.traffic_dir / "state.json"),
            "frida": self._optional_session_json(paths.frida_dir / "state.json"),
            "findings": finding_payload,
            "evidence_count": len(evidence_values) if isinstance(evidence_values, list) else 0,
            "report_available": paths.report_html.is_file(),
            "runtime_categories": runtime_categories,
            "runtime_checks": report.get("runtime_checks", []),
            "runtime_observations": observations if isinstance(observations, list) else [],
        }

    def scan_session(
        self,
        session_id: str,
        profile: str = "quick",
        *,
        runtime_seconds: int | None = None,
        autonomous: bool | None = None,
    ) -> dict[str, Any]:
        return (
            ScanService(self.context, self.repository)
            .scan_session(
                session_id,
                profile=profile,
                runtime_seconds=runtime_seconds,
                autonomous=autonomous,
            )
            .to_dict()
        )

    def request_runtime_stop(self, session_id: str) -> dict[str, Any]:
        return ScanService(self.context, self.repository).request_runtime_stop(session_id)

    def validate_finding(self, session_id: str, finding_id: str) -> dict[str, Any]:
        return (
            ValidationService(self.context, self.repository)
            .validate(
                session_id,
                finding_id,
            )
            .to_dict()
        )

    def start_traffic(self, session_id: str) -> dict[str, Any]:
        return (
            TrafficCaptureService(self.context, self.repository)
            .start(
                session_id,
                launch_app=True,
            )
            .to_dict()
        )

    def stop_traffic(self, session_id: str) -> dict[str, Any]:
        state = TrafficCaptureService(self.context, self.repository).stop(session_id)
        RuleEngine(self.paths, self.repository).evaluate(session_id)
        ReportService(self.paths, self.repository).generate(session_id)
        return state.to_dict()

    def start_frida(self, session_id: str) -> dict[str, Any]:
        return FridaController(self.context, self.repository).start(session_id).to_dict()

    def stop_frida(self, session_id: str) -> dict[str, Any]:
        state = FridaController(self.context, self.repository).stop(session_id)
        RuleEngine(self.paths, self.repository).evaluate(session_id)
        ReportService(self.paths, self.repository).generate(session_id)
        return state.to_dict()

    def generate_report(self, session_id: str) -> dict[str, Any]:
        return ReportService(self.paths, self.repository).generate(session_id)

    def report_path(self, session_id: str) -> Path:
        path = self.repository.paths_for(session_id).report_html
        if not path.is_file():
            raise SessionError("Report has not been generated for this session.")
        return path

    def sessions(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for record in self.repository.list():
            item = record.to_dict(show_serial=False)
            item["pending_cleanup"] = record.pending_cleanup
            item["cleanup_action_count"] = len(record.cleanup_actions)
            item["report_available"] = self.repository.paths_for(
                record.session_id
            ).report_html.is_file()
            try:
                app_state = read_json_object(
                    self.repository.paths_for(record.session_id).app_json,
                    root=self.paths.root,
                )
                inspection_status = str(app_state.get("inspection_status", "not_started"))
            except SessionError:
                inspection_status = "error"
            item["app_inspection_status"] = inspection_status
            item["app_inspection_available"] = inspection_status != "not_started"
            records.append(item)
        return records

    def cleanup_session(self, session_id: str) -> dict[str, Any]:
        result = CleanupService(self.context, self.repository).cleanup(session_id)
        try:
            ReportService(self.paths, self.repository).generate(result.session_id)
        except (AndroidAssessorError, OSError, ValueError):
            pass
        return result.to_dict()

    def environment(self) -> dict[str, Any]:
        return collect_environment(self.paths, self.context.config).to_dict()

    def dashboard(self) -> dict[str, Any]:
        environment = self.environment()
        records = self.repository.list()
        payload: dict[str, Any] = {
            "environment": environment,
            "device_count": 0,
            "authorized_count": 0,
            "device": None,
            "device_error": None,
            "target_package": None,
            "proxy": None,
            "capabilities": [],
            "active_session": None,
            "session_count": len(records),
            "pending_cleanup_count": sum(record.pending_cleanup for record in records),
            "device_lock": None,
        }
        try:
            inventory = self.devices()
            payload["device_count"] = len(inventory["devices"])
            payload["authorized_count"] = sum(
                bool(device["authorized"]) for device in inventory["devices"]
            )
            active_serial = inventory["active_serial"]
            if active_serial is None:
                if inventory["devices"]:
                    payload["device_error"] = "Select an authorized device to continue."
                else:
                    payload["device_error"] = "No ADB device is connected."
                return payload

            target = self.target_store.read(serial=active_serial)
            payload["target_package"] = target
            adb = self.context.adb_client()
            selector = self.context.device_selector(adb)
            detector = CapabilityDetector(adb, self.context.host_capability_paths())
            inspection = DeviceService(adb, selector, detector).inspect(
                serial=active_serial,
                package=target,
            )
            payload["device"] = inspection.device.to_dict(show_serial=False)
            payload["capabilities"] = [
                capability.to_dict() for capability in inspection.capabilities.capabilities
            ]
            payload["proxy"] = adb.get_setting(active_serial, "global", "http_proxy")
            payload["device_lock"] = self._device_lock_state(active_serial)
            active = next(
                (
                    record
                    for record in records
                    if record.serial == active_serial
                    and record.status.value not in {"cleaned", "error"}
                ),
                None,
            )
            if active is not None:
                payload["active_session"] = active.to_dict(show_serial=False)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            payload["device_error"] = redact_text(str(exc))[:500]
        return payload

    def repair_status(self) -> dict[str, Any]:
        return self.repair.status().to_dict()

    def start_repair(self) -> dict[str, Any]:
        return self.repair.start().to_dict()

    def setup_log(self) -> str:
        path = self.paths.logs_dir / "setup.log"
        if not path.is_file():
            return "Setup log has not been created yet.\n"
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise AndroidAssessorError(f"Could not read setup.log: {exc}") from exc
        return redact_text(content[-200_000:])
