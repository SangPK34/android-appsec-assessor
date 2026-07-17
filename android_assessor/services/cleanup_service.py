"""Coordinate controller shutdown before the generic idempotent cleanup ledger."""

from __future__ import annotations

from ..app_context import AppContext
from ..cleanup import CleanupExecutor, CleanupResult
from ..device_lock import DeviceLock
from ..errors import AndroidAssessorError
from ..frida_controller import FridaController
from ..session import SessionRepository
from ..traffic import TrafficCaptureService


class CleanupService:
    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
    ) -> None:
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)

    def cleanup(self, session_id: str) -> CleanupResult:
        record = self.repository.load(session_id)
        with DeviceLock(
            self.paths,
            record.serial,
            operation="cleanup_workflow",
            session_id=record.session_id,
            timeout=0,
        ):
            return self._cleanup_locked(record.session_id)

    def _cleanup_locked(self, session_id: str) -> CleanupResult:
        record = self.repository.load(session_id)
        frida = FridaController(self.context, self.repository)
        traffic = TrafficCaptureService(self.context, self.repository)
        try:
            state = frida.load_state(record.session_id)
            if state and state.status == "running":
                frida.stop(record.session_id)
        except (AndroidAssessorError, OSError, ValueError):
            pass
        try:
            state = traffic.load_state(record.session_id)
            if state and state.status == "running":
                traffic.stop(record.session_id)
        except (AndroidAssessorError, OSError, ValueError):
            pass
        refreshed = self.repository.load(record.session_id)
        command_log = self.repository.paths_for(refreshed.session_id).commands_jsonl
        result = CleanupExecutor(
            self.paths,
            self.repository,
            self.context.adb_client(command_log=command_log),
        ).cleanup(refreshed.session_id)
        if result.success:
            # Finalize the machine-readable/HTML report only after cleanup has
            # persisted its terminal status, so it cannot claim cleanup is pending.
            from ..report import ReportService

            try:
                ReportService(self.paths, self.repository).generate(result.session_id)
            except (AndroidAssessorError, OSError, ValueError):
                pass
        return result
