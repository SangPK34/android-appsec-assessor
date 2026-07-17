"""Create reproducible sessions from selected-device state."""

from __future__ import annotations

from ..app_context import AppContext
from ..capabilities import CapabilityDetector
from ..environment import collect_environment
from ..redaction import redact_text
from ..session import SessionRecord, SessionRepository, SessionStatus
from ..snapshot import capture_device_snapshot
from .device_service import DeviceService


class SessionService:
    def __init__(self, context: AppContext, repository: SessionRepository | None = None) -> None:
        self.context = context
        self.repository = repository or SessionRepository(context.paths)

    def create(self, *, package: str, serial: str | None = None) -> SessionRecord:
        discovery_adb = self.context.adb_client()
        selected = self.context.device_selector(discovery_adb).resolve(serial)
        record = self.repository.initialize(serial=selected.serial, package=package)
        session_paths = self.repository.paths_for(record.session_id)
        try:
            session_adb = self.context.adb_client(command_log=session_paths.commands_jsonl)
            selector = self.context.device_selector(session_adb)
            detector = CapabilityDetector(
                session_adb,
                self.context.host_capability_paths(),
            )
            inspection = DeviceService(session_adb, selector, detector).inspect(
                serial=selected.serial,
                package=record.package,
            )
            snapshot = capture_device_snapshot(session_adb, selected.serial, record.package)
            environment = collect_environment(self.context.paths, self.context.config)
            return self.repository.activate(
                record.session_id,
                snapshot=snapshot.to_dict(),
                device=inspection.to_dict(show_serial=False),
                environment=environment.to_dict(),
            )
        except Exception as exc:
            error = redact_text(str(exc))[:1000]
            self.repository.set_status(
                record.session_id,
                SessionStatus.ERROR,
                cleanup_success=False,
                last_error=error,
            )
            raise
