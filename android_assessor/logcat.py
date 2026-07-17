"""Bounded, target-PID-only logcat evidence collection."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from .app_context import AppContext
from .errors import AdbError
from .evidence import EvidenceRepository
from .redaction import redact_text
from .session import SessionRepository
from .storage import write_json_atomic, write_text_atomic

_SENSITIVE_LOG_PATTERN = re.compile(
    r"(?i)\b(authorization|bearer|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|session[_-]?id|jwt|token)\b\s*[:=]\s*([^\s,;]{6,})"
)
_THREADTIME_LINE_PATTERN = re.compile(
    r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(\d+)\s+\d+\s+[A-Z]\s"
)


@dataclass(frozen=True, slots=True)
class LogcatState:
    session_id: str
    status: str
    collected_at: str
    target_pid: int | None
    relative_path: str | None
    sensitive_marker_types: tuple[str, ...]
    sensitive_match_count: int
    canary_observed: bool
    evidence_id: str | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["sensitive_marker_types"] = list(self.sensitive_marker_types)
        return value


class LogcatCollector:
    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
    ) -> None:
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)
        self.evidence = EvidenceRepository(self.paths, self.repository)

    @staticmethod
    def _pid(output: str) -> int | None:
        for token in output.split():
            if token.isdecimal() and int(token) > 0:
                return int(token)
        return None

    @staticmethod
    def _filter_threadtime_for_pid(output: str, pid: int) -> str:
        selected: list[str] = []
        include_continuation = False
        for line in output.splitlines():
            match = _THREADTIME_LINE_PATTERN.match(line)
            if match is not None:
                include_continuation = int(match.group(1)) == pid
            if include_continuation:
                selected.append(line)
        return "\n".join(selected) + ("\n" if selected else "")

    def collect(self, session_id: str, *, canary: str | None = None) -> LogcatState:
        record = self.repository.load(session_id)
        paths = self.repository.paths_for(record.session_id)
        adb = self.context.adb_client(command_log=paths.commands_jsonl)
        now = datetime.now(UTC)
        state_path = paths.logcat_dir / "state.json"
        process = adb.shell(
            record.serial,
            ("pidof", record.package),
            timeout=10,
            check=False,
            operation="locating the target app for bounded logcat collection",
        )
        pid = self._pid(process.stdout)
        if pid is None:
            state = LogcatState(
                session_id=record.session_id,
                status="skipped",
                collected_at=now.isoformat(),
                target_pid=None,
                relative_path=None,
                sensitive_marker_types=(),
                sensitive_match_count=0,
                canary_observed=False,
                evidence_id=None,
                error="Target app is not running; broad device log collection was refused.",
            )
            write_json_atomic(state_path, state.to_dict(), root=self.paths.root)
            return state
        result = adb.shell(
            record.serial,
            ("logcat", "--pid", str(pid), "-d", "-t", "500"),
            timeout=30,
            check=False,
            operation="collecting bounded target-app logcat",
        )
        evidence_source = "adb_logcat_pid"
        if result.timed_out or result.exit_code != 0:
            fallback = adb.shell(
                record.serial,
                ("logcat", "-d", "-t", "500", "-v", "threadtime"),
                timeout=30,
                check=False,
                operation="collecting bounded legacy Android logcat",
            )
            if fallback.timed_out or fallback.exit_code != 0:
                detail = redact_text((fallback.stderr or result.stderr).strip())[:500]
                raise AdbError(f"Bounded target logcat collection failed: {detail}")
            raw = self._filter_threadtime_for_pid(fallback.stdout[-2_000_000:], pid)
            evidence_source = "adb_logcat_threadtime_pid_filter"
        else:
            raw = result.stdout[-2_000_000:]
        matches = list(_SENSITIVE_LOG_PATTERN.finditer(raw))
        marker_types = tuple(sorted({match.group(1).casefold() for match in matches}))
        output = redact_text(raw)
        stamp = now.strftime("%Y%m%d-%H%M%S")
        log_path = paths.redacted_dir / "logcat" / f"target-{stamp}.log"
        write_text_atomic(log_path, output, root=self.paths.root)
        evidence = self.evidence.register_file(
            record.session_id,
            log_path,
            evidence_type="target_logcat",
            source=evidence_source,
            description="Bounded target-process logcat with basic secret redaction.",
            sensitive=True,
            redacted=True,
        )
        state = LogcatState(
            session_id=record.session_id,
            status="completed",
            collected_at=now.isoformat(),
            target_pid=pid,
            relative_path=log_path.relative_to(paths.root).as_posix(),
            sensitive_marker_types=marker_types,
            sensitive_match_count=len(matches),
            canary_observed=bool(canary and canary in raw),
            evidence_id=evidence.evidence_id,
        )
        write_json_atomic(state_path, state.to_dict(), root=self.paths.root)
        self.repository.append_event(
            record.session_id,
            "target_logcat_collected",
            {
                "sensitive_match_count": len(matches),
                "canary_observed": state.canary_observed,
            },
        )
        return state
