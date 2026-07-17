"""Managed localhost mitmdump capture with Android proxy/reverse restoration."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .app_context import AppContext
from .cleanup import CleanupExecutor, remove_owned_reverse, restore_owned_proxy
from .device_lock import DeviceLock
from .environment import find_tool_spec, resolve_binary
from .errors import (
    AndroidAssessorError,
    CleanupConflictError,
    ProxyError,
    SessionError,
)
from .evidence import EvidenceRepository
from .host_process import ProcessIdentity, WindowsProcessController
from .redaction import redact_text
from .scope import load_scope
from .session import (
    CleanupActionStatus,
    CleanupActionType,
    SessionRepository,
    SessionStatus,
)
from .snapshot import ProxySnapshotState, parse_proxy_snapshot
from .storage import (
    read_json_object,
    require_under_root,
    write_json_atomic,
    write_text_atomic,
)


@dataclass(frozen=True, slots=True)
class TrafficCaptureState:
    session_id: str
    status: str
    port: int
    started_at: str
    stopped_at: str | None
    process_identity: dict[str, Any]
    reverse_created: bool
    proxy_changed: bool
    cleanup_action_ids: dict[str, str]
    flow_path: str
    events_path: str
    ca_path: str
    evidence_registered: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_traffic_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                events.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise ProxyError(f"Could not parse traffic events: {exc}") from exc
    return events


class TrafficCaptureService:
    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
        *,
        process_controller: WindowsProcessController | None = None,
    ) -> None:
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)
        self.process_controller = process_controller or WindowsProcessController()
        self.evidence = EvidenceRepository(self.paths, self.repository)

    def _state_path(self, session_id: str) -> Path:
        return self.repository.paths_for(session_id).traffic_dir / "state.json"

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    @staticmethod
    def _wait_ready(process: subprocess.Popen[bytes], port: int) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ProxyError(f"mitmdump exited during startup with code {process.returncode}.")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    return
            except OSError:
                time.sleep(0.2)
        raise ProxyError("mitmdump did not listen on localhost within 15 seconds.")

    def load_state(self, session_id: str) -> TrafficCaptureState | None:
        path = self._state_path(session_id)
        if not path.is_file():
            return None
        payload = read_json_object(path, root=self.paths.root)
        try:
            state = TrafficCaptureState(**payload)
        except TypeError as exc:
            raise SessionError(f"Traffic state is invalid: {exc}") from exc
        if state.session_id != session_id or state.status not in {
            "running",
            "stopped",
            "stop_failed",
        }:
            raise SessionError("Traffic state identity or status is invalid.")
        if isinstance(state.port, bool) or not isinstance(state.port, int):
            raise SessionError("Traffic state port is invalid.")
        if not 1 <= state.port <= 65535 or not isinstance(state.process_identity, dict):
            raise SessionError("Traffic state process or port is invalid.")
        if (
            not isinstance(state.cleanup_action_ids, dict)
            or not isinstance(state.reverse_created, bool)
            or not isinstance(state.proxy_changed, bool)
            or not isinstance(state.evidence_registered, bool)
        ):
            raise SessionError("Traffic state flags are invalid.")
        ProcessIdentity.from_dict(state.process_identity)
        session_root = self.repository.paths_for(session_id).root
        for relative in (state.flow_path, state.events_path, state.ca_path):
            if not isinstance(relative, str) or Path(relative).is_absolute():
                raise SessionError("Traffic state path must be session-relative.")
            require_under_root(session_root / relative, session_root)
        return state

    def start(
        self,
        session_id: str,
        *,
        launch_app: bool = True,
        canary: str | None = None,
    ) -> TrafficCaptureState:
        record = self.repository.load(session_id)
        load_scope(self.paths).require_device_package(
            record.serial,
            record.package,
            action="traffic_capture",
        )
        if record.status not in {
            SessionStatus.ACTIVE,
            SessionStatus.CLEANUP_REQUIRED,
        }:
            raise SessionError("Traffic capture requires an active session.")
        existing = self.load_state(record.session_id)
        if existing and existing.status in {"running", "stop_failed"}:
            raise ProxyError("Traffic capture is running or requires cleanup for this session.")
        self.repository.require_modifying_session_slot(record.serial, record.session_id)
        proxy_state, _, proxy_error = parse_proxy_snapshot(record.snapshot)
        if proxy_state is ProxySnapshotState.CAPTURE_FAILED or proxy_error:
            raise ProxyError(
                "Traffic capture cannot modify the proxy because its original state "
                f"was not captured: {proxy_error or 'unknown snapshot error'}"
            )
        mitmdump = resolve_binary(
            find_tool_spec("mitmproxy"),
            self.paths,
            self.context.config,
        )
        if mitmdump is None:
            raise ProxyError("mitmdump is missing. Run repair.cmd.")
        if canary is not None and not re.fullmatch(
            r"THESIS_CANARY_\d{8}T\d{6}Z_[a-f0-9]{12}", canary
        ):
            raise ProxyError("Controlled-validation canary has an invalid format.")
        paths = self.repository.paths_for(record.session_id)
        port = self._free_port()
        endpoint = f"tcp:{port}"
        raw_traffic = paths.raw_dir / "traffic"
        redacted_traffic = paths.redacted_dir / "traffic"
        raw_traffic.mkdir(parents=True, exist_ok=True)
        redacted_traffic.mkdir(parents=True, exist_ok=True)
        flow_path = raw_traffic / "capture.mitm"
        events_path = redacted_traffic / "events.jsonl"
        stdout_path = raw_traffic / "mitmdump.stdout.log"
        stderr_path = raw_traffic / "mitmdump.stderr.log"
        confdir = raw_traffic / "mitm-home"
        confdir.mkdir(parents=True, exist_ok=True)
        addon = self.paths.root / "hooks" / "mitm_capture.py"
        if not addon.is_file():
            raise ProxyError("Managed mitmproxy addon is missing.")
        command = [
            str(mitmdump.path),
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(port),
            "--set",
            "block_global=false",
            "--set",
            f"confdir={confdir}",
            "-w",
            str(flow_path),
            "-s",
            str(addon),
            "--set",
            f"android_assessor_events={events_path}",
        ]
        if canary is not None:
            command.extend(("--set", f"android_assessor_canary={canary}"))
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        process: subprocess.Popen[bytes] | None = None
        identity: ProcessIdentity | None = None
        cleanup_ids: dict[str, str] = {}
        reverse_created = False
        proxy_changed = False
        with DeviceLock(
            self.paths,
            record.serial,
            operation="start_traffic_capture",
            session_id=record.session_id,
        ):
            latest = self.load_state(record.session_id)
            if latest and latest.status in {"running", "stop_failed"}:
                raise ProxyError(
                    "Traffic capture is running or requires cleanup for this session."
                )
            adb = self.context.adb_client(command_log=paths.commands_jsonl)
            adb.require_authorized_device(record.serial)
            current_reverse = adb.list_reverse(record.serial)
            conflict = next(
                (mapping for mapping in current_reverse if mapping.remote == endpoint),
                None,
            )
            if conflict and conflict.local != endpoint:
                raise ProxyError(f"ADB reverse endpoint {endpoint} is already in use.")
            try:
                with stdout_path.open("ab") as stdout_handle, stderr_path.open(
                    "ab"
                ) as stderr_handle:
                    process = subprocess.Popen(
                        command,
                        cwd=self.paths.root,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_handle,
                        stderr=stderr_handle,
                        shell=False,
                        creationflags=creation_flags,
                        close_fds=True,
                    )
                self._wait_ready(process, port)
                identity = self.process_controller.capture(process.pid)
                if identity is None:
                    raise ProxyError("Could not capture mitmdump process identity.")
                action = self.repository.record_cleanup_action(
                    record.session_id,
                    CleanupActionType.STOP_HOST_PROCESS,
                    {"role": "mitmproxy", "identity": identity.to_dict()},
                )
                cleanup_ids["process"] = action.action_id
                if conflict is None:
                    action = self.repository.record_cleanup_action(
                        record.session_id,
                        CleanupActionType.REMOVE_REVERSE,
                        {
                            "reverse_remote": endpoint,
                            "reverse_local": endpoint,
                            "ownership_state": "owned",
                        },
                    )
                    cleanup_ids["reverse"] = action.action_id
                    adb.add_reverse(record.serial, endpoint, endpoint)
                    reverse_created = True
                desired_proxy = f"127.0.0.1:{port}"
                current_proxy = adb.get_setting(record.serial, "global", "http_proxy")
                if current_proxy != desired_proxy:
                    action = self.repository.record_cleanup_action(
                        record.session_id,
                        CleanupActionType.RESTORE_PROXY,
                        {
                            "previous_proxy": current_proxy,
                            "applied_proxy": desired_proxy,
                            "ownership_state": "owned",
                        },
                    )
                    cleanup_ids["proxy"] = action.action_id
                    adb.put_setting(record.serial, "global", "http_proxy", desired_proxy)
                    proxy_changed = True
                if launch_app:
                    adb.launch_package(record.serial, record.package)
                state = TrafficCaptureState(
                    session_id=record.session_id,
                    status="running",
                    port=port,
                    started_at=datetime.now(UTC).isoformat(),
                    stopped_at=None,
                    process_identity=identity.to_dict(),
                    reverse_created=reverse_created,
                    proxy_changed=proxy_changed,
                    cleanup_action_ids=cleanup_ids,
                    flow_path=flow_path.relative_to(paths.root).as_posix(),
                    events_path=events_path.relative_to(paths.root).as_posix(),
                    ca_path=(confdir / "mitmproxy-ca-cert.cer").relative_to(paths.root).as_posix(),
                )
                write_json_atomic(
                    self._state_path(record.session_id),
                    state.to_dict(),
                    root=self.paths.root,
                )
                self.repository.append_event(
                    record.session_id,
                    "traffic_capture_started",
                    {"port": port, "launch_app": launch_app},
                )
                return state
            except BaseException:
                if cleanup_ids:
                    CleanupExecutor(
                        self.paths,
                        self.repository,
                        adb,
                        process_controller=self.process_controller,
                    ).rollback_actions(record.session_id, set(cleanup_ids.values()))
                if (
                    process is not None
                    and "process" not in cleanup_ids
                    and process.poll() is None
                ):
                    if identity is not None:
                        self.process_controller.terminate_owned(identity)
                    else:
                        try:
                            process.terminate()
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                raise

    def _mark_action(
        self,
        session_id: str,
        action_id: str | None,
        status: CleanupActionStatus,
        error: str | None = None,
    ) -> None:
        if action_id:
            self.repository.update_cleanup_action(
                session_id,
                action_id,
                status=status,
                error=error,
            )

    def stop(self, session_id: str) -> TrafficCaptureState:
        record = self.repository.load(session_id)
        state = self.load_state(record.session_id)
        if state is None:
            raise ProxyError("Traffic capture state does not exist for this session.")
        if state.status == "stopped":
            return state
        paths = self.repository.paths_for(record.session_id)
        errors: list[str] = []
        with DeviceLock(
            self.paths,
            record.serial,
            operation="stop_traffic_capture",
            session_id=record.session_id,
        ):
            latest = self.load_state(record.session_id)
            if latest is None:
                raise ProxyError("Traffic capture state does not exist for this session.")
            if latest.status == "stopped":
                return latest
            state = latest
            adb = self.context.adb_client(command_log=paths.commands_jsonl)
            try:
                identity = ProcessIdentity.from_dict(state.process_identity)
                stopped = self.process_controller.terminate_owned(identity)
                self._mark_action(
                    record.session_id,
                    state.cleanup_action_ids.get("process"),
                    CleanupActionStatus.COMPLETED if stopped else CleanupActionStatus.SKIPPED,
                )
            except (AndroidAssessorError, OSError, ValueError) as exc:
                error = redact_text(str(exc))[:500]
                errors.append(error)
                self._mark_action(
                    record.session_id,
                    state.cleanup_action_ids.get("process"),
                    CleanupActionStatus.FAILED,
                    error,
                )
            if state.proxy_changed:
                try:
                    proxy_action_id = state.cleanup_action_ids.get("proxy")
                    proxy_action = next(
                        action
                        for action in self.repository.load(record.session_id).cleanup_actions
                        if action.action_id == proxy_action_id
                    )
                    proxy_status = restore_owned_proxy(adb, record, proxy_action.payload)
                    self._mark_action(
                        record.session_id,
                        state.cleanup_action_ids.get("proxy"),
                        proxy_status,
                    )
                except CleanupConflictError as exc:
                    error = redact_text(str(exc))[:500]
                    errors.append(error)
                    self._mark_action(
                        record.session_id,
                        state.cleanup_action_ids.get("proxy"),
                        CleanupActionStatus.CONFLICT,
                        error,
                    )
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    error = redact_text(str(exc))[:500]
                    errors.append(error)
                    self._mark_action(
                        record.session_id,
                        state.cleanup_action_ids.get("proxy"),
                        CleanupActionStatus.FAILED,
                        error,
                    )
            if state.reverse_created:
                try:
                    reverse_action_id = state.cleanup_action_ids.get("reverse")
                    reverse_action = next(
                        action
                        for action in self.repository.load(record.session_id).cleanup_actions
                        if action.action_id == reverse_action_id
                    )
                    reverse_status = remove_owned_reverse(adb, record, reverse_action.payload)
                    self._mark_action(
                        record.session_id,
                        state.cleanup_action_ids.get("reverse"),
                        reverse_status,
                    )
                except CleanupConflictError as exc:
                    error = redact_text(str(exc))[:500]
                    errors.append(error)
                    self._mark_action(
                        record.session_id,
                        state.cleanup_action_ids.get("reverse"),
                        CleanupActionStatus.CONFLICT,
                        error,
                    )
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    error = redact_text(str(exc))[:500]
                    errors.append(error)
                    self._mark_action(
                        record.session_id,
                        state.cleanup_action_ids.get("reverse"),
                        CleanupActionStatus.FAILED,
                        error,
                    )

            evidence_registered = state.evidence_registered
            if not evidence_registered:
                try:
                    raw_stdout = paths.raw_dir / "traffic" / "mitmdump.stdout.log"
                    raw_stderr = paths.raw_dir / "traffic" / "mitmdump.stderr.log"
                    redacted_stdout = (
                        paths.redacted_dir / "traffic" / "mitmdump.stdout.log"
                    )
                    redacted_stderr = (
                        paths.redacted_dir / "traffic" / "mitmdump.stderr.log"
                    )
                    event_file = paths.root / state.events_path
                    if event_file.is_file():
                        write_text_atomic(
                            event_file,
                            redact_text(
                                event_file.read_text(
                                    encoding="utf-8",
                                    errors="replace",
                                )
                            ),
                            root=self.paths.root,
                        )
                    for source, destination in (
                        (raw_stdout, redacted_stdout),
                        (raw_stderr, redacted_stderr),
                    ):
                        if source.is_file():
                            write_text_atomic(
                                destination,
                                redact_text(
                                    source.read_text(encoding="utf-8", errors="replace")
                                ),
                                root=self.paths.root,
                            )
                    for relative, evidence_type, description, sensitive, redacted in (
                        (
                            state.flow_path,
                            "traffic_flow",
                            "Raw mitmproxy flow capture.",
                            True,
                            False,
                        ),
                        (
                            state.events_path,
                            "traffic_events",
                            "Redacted HTTP metadata events.",
                            True,
                            True,
                        ),
                        (
                            "raw/traffic/mitmdump.stdout.log",
                            "traffic_log_raw",
                            "Raw mitmdump stdout log.",
                            True,
                            False,
                        ),
                        (
                            "raw/traffic/mitmdump.stderr.log",
                            "traffic_log_raw",
                            "Raw mitmdump stderr log.",
                            True,
                            False,
                        ),
                        (
                            "redacted/traffic/mitmdump.stdout.log",
                            "traffic_log",
                            "Redacted mitmdump stdout log.",
                            True,
                            True,
                        ),
                        (
                            "redacted/traffic/mitmdump.stderr.log",
                            "traffic_log",
                            "Redacted mitmdump stderr log.",
                            True,
                            True,
                        ),
                    ):
                        target = paths.root / relative
                        if target.is_file():
                            self.evidence.register_file(
                                record.session_id,
                                target,
                                evidence_type=evidence_type,
                                source="mitmdump",
                                description=description,
                                sensitive=sensitive,
                                redacted=redacted,
                            )
                    evidence_registered = True
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    errors.append(redact_text(str(exc))[:500])
            stopped_state = TrafficCaptureState(
                **{
                    **state.to_dict(),
                    "status": "stopped" if not errors else "stop_failed",
                    "stopped_at": datetime.now(UTC).isoformat(),
                    "evidence_registered": evidence_registered,
                    "error": "; ".join(errors) if errors else None,
                }
            )
            write_json_atomic(
                self._state_path(record.session_id),
                stopped_state.to_dict(),
                root=self.paths.root,
            )
            if not errors:
                self.repository.set_status(record.session_id, SessionStatus.ACTIVE)
            self.repository.append_event(
                record.session_id,
                "traffic_capture_stopped",
                {"success": not errors, "errors": errors},
            )
            return stopped_state
