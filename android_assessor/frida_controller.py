"""Managed Frida Server and one fixed, observation-only client hook."""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .app_context import AppContext
from .cleanup import CleanupExecutor, capture_remote_process_identity
from .device_lock import DeviceLock
from .environment import find_tool_spec, resolve_binary
from .errors import AndroidAssessorError, FridaError
from .evidence import EvidenceRepository, sha256_file
from .host_process import ProcessIdentity, WindowsProcessController
from .redaction import redact_text
from .root import probe_root
from .scope import load_scope
from .session import (
    CleanupActionStatus,
    CleanupActionType,
    SessionRepository,
    SessionStatus,
)
from .storage import (
    read_json_object,
    require_under_root,
    write_json_atomic,
    write_text_atomic,
)
from .subprocess_utils import run_command
from .validation import validate_managed_remote_path

_VERSION_PATTERN = re.compile(r"\b(\d+\.\d+\.\d+)\b")
_REMOTE_EXECUTABLE_PATTERN = re.compile(r"^/[A-Za-z0-9._/+@=:-]+$")
_ABI_ARCH = {
    "arm64-v8a": "arm64",
    "arm64": "arm64",
    "aarch64": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "armv7l": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
    "i686": "x86",
}


@dataclass(frozen=True, slots=True)
class FridaProbe:
    client_path: str | None
    client_version: str | None
    architecture: str | None
    server_running: bool
    server_pid: int | None
    server_version: str | None
    compatible: bool | None
    server_binary: str | None
    guidance: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FridaObservationState:
    session_id: str
    status: str
    mode: str
    started_at: str
    stopped_at: str | None
    client_version: str
    server_version: str | None
    server_pid: int
    server_started_by_framework: bool
    server_remote_path: str | None
    process_identity: dict[str, Any]
    cleanup_action_ids: dict[str, str]
    hook_path: str
    hook_sha256: str
    events_path: str
    raw_events_path: str | None = None
    evidence_registered: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FridaController:
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
        return self.repository.paths_for(session_id).frida_dir / "state.json"

    @staticmethod
    def _version(output: str) -> str | None:
        match = _VERSION_PATTERN.search(output)
        return match.group(1) if match else None

    def _client(self) -> tuple[Path, str]:
        resolved = resolve_binary(
            find_tool_spec("frida-client"),
            self.paths,
            self.context.config,
        )
        if resolved is None:
            raise FridaError("Frida client is missing. Run repair.cmd.")
        result = run_command(
            [resolved.path, "--version"],
            timeout=15,
            cwd=self.paths.root,
            check=False,
        )
        version = self._version(result.stdout or result.stderr)
        if result.timed_out or result.exit_code != 0 or version is None:
            raise FridaError("Frida client did not return a valid version.")
        return resolved.path, version

    def _architecture(self, serial: str, command_log: Path | None) -> str:
        adb = self.context.adb_client(command_log=command_log)
        result = adb.shell(
            serial,
            ("getprop", "ro.product.cpu.abi"),
            timeout=10,
            check=True,
            operation="detecting Android architecture for Frida",
        )
        abi = result.stdout.strip().casefold()
        architecture = _ABI_ARCH.get(abi)
        if architecture is None:
            abi_list_result = adb.shell(
                serial,
                ("getprop", "ro.product.cpu.abilist"),
                timeout=10,
                check=False,
                operation="detecting supported Android architectures for Frida",
            )
            for candidate in abi_list_result.stdout.casefold().split(","):
                architecture = _ABI_ARCH.get(candidate.strip())
                if architecture is not None:
                    break
        if architecture is None:
            raise FridaError(f"Unsupported Android ABI for Frida: {abi or 'unknown'}")
        return architecture

    @staticmethod
    def _pid(output: str) -> int | None:
        for token in output.split():
            if token.isdecimal() and int(token) > 0:
                return int(token)
        return None

    def _running_server(
        self,
        serial: str,
        command_log: Path | None,
    ) -> tuple[int | None, str | None]:
        adb = self.context.adb_client(command_log=command_log)
        for name in ("frida-server", "re.frida.server"):
            result = adb.shell(
                serial,
                ("pidof", name),
                timeout=10,
                check=False,
                operation="detecting Frida Server",
            )
            pid = self._pid(result.stdout)
            if not result.timed_out and result.exit_code == 0 and pid is not None:
                return pid, name
        return None, None

    def _server_version(
        self,
        serial: str,
        pid: int,
        command_log: Path | None,
    ) -> str | None:
        adb = self.context.adb_client(command_log=command_log)
        path_result = adb.shell(
            serial,
            ("su", "-c", f"readlink /proc/{pid}/exe"),
            timeout=10,
            check=False,
            operation="locating Frida Server",
        )
        executable = path_result.stdout.strip()
        if (
            path_result.timed_out
            or path_result.exit_code != 0
            or not _REMOTE_EXECUTABLE_PATTERN.fullmatch(executable)
        ):
            return None
        result = adb.shell(
            serial,
            ("su", "-c", f"{executable} --version"),
            timeout=15,
            check=False,
            operation="reading Frida Server version",
        )
        if result.timed_out or result.exit_code != 0:
            return None
        return self._version(result.stdout or result.stderr)

    def _server_binary(self, version: str, architecture: str) -> Path | None:
        directory = self.paths.tools_dir / "frida"
        candidates = (
            directory / f"frida-server-{version}-android-{architecture}",
            directory / f"frida-server-android-{architecture}",
            directory / f"frida-server-{architecture}",
            directory / "frida-server",
        )
        return next((path.resolve() for path in candidates if path.is_file()), None)

    def _connectivity_check(self, client: Path, serial: str) -> bool:
        frida_ps = client.with_name("frida-ps.exe")
        if not frida_ps.is_file():
            return False
        result = run_command(
            [frida_ps, "-D", serial],
            timeout=15,
            cwd=self.paths.root,
            check=False,
            sensitive_values=(serial,),
        )
        return not result.timed_out and result.exit_code == 0

    def probe(self, serial: str, *, command_log: Path | None = None) -> FridaProbe:
        client, client_version = self._client()
        architecture = self._architecture(serial, command_log)
        pid, _name = self._running_server(serial, command_log)
        server_version = (
            self._server_version(serial, pid, command_log) if pid is not None else None
        )
        compatible: bool | None = None
        if pid is not None:
            compatible = (
                server_version == client_version
                if server_version is not None
                else self._connectivity_check(client, serial)
            )
        binary = self._server_binary(client_version, architecture)
        guidance = None
        if pid is None and binary is None:
            guidance = "Matching Frida Server asset is missing. Run repair.cmd."
        elif pid is None:
            guidance = (
                "Matching Frida Server asset is ready; Android root is required "
                "for framework-managed startup."
            )
        elif pid is not None and compatible is False:
            guidance = "Frida client and Frida Server are incompatible."
        return FridaProbe(
            client_path=str(client),
            client_version=client_version,
            architecture=architecture,
            server_running=pid is not None,
            server_pid=pid,
            server_version=server_version,
            compatible=compatible,
            server_binary=str(binary) if binary else None,
            guidance=guidance,
        )

    def load_state(self, session_id: str) -> FridaObservationState | None:
        path = self._state_path(session_id)
        if not path.is_file():
            return None
        payload = read_json_object(path, root=self.paths.root)
        try:
            state = FridaObservationState(**payload)
        except TypeError as exc:
            raise FridaError(f"Frida state is invalid: {exc}") from exc
        if state.session_id != session_id or state.status not in {
            "running",
            "stopped",
            "stop_failed",
        }:
            raise FridaError("Frida state identity or status is invalid.")
        if state.mode not in {"attach", "spawn"}:
            raise FridaError("Frida observation mode is invalid.")
        if (
            isinstance(state.server_pid, bool)
            or not isinstance(state.server_pid, int)
            or state.server_pid <= 0
            or not isinstance(state.process_identity, dict)
            or not isinstance(state.cleanup_action_ids, dict)
            or not isinstance(state.server_started_by_framework, bool)
            or not isinstance(state.evidence_registered, bool)
        ):
            raise FridaError("Frida process state is invalid.")
        ProcessIdentity.from_dict(state.process_identity)
        if state.server_remote_path is not None:
            validate_managed_remote_path(state.server_remote_path)
        session_root = self.repository.paths_for(session_id).root
        for relative in (state.hook_path, state.events_path, state.raw_events_path):
            if relative is None:
                continue
            if not isinstance(relative, str) or Path(relative).is_absolute():
                raise FridaError("Frida state path must be session-relative.")
            require_under_root(session_root / relative, session_root)
        return state

    def _start_server(
        self,
        session_id: str,
        serial: str,
        probe: FridaProbe,
        cleanup_ids: dict[str, str],
        command_log: Path,
    ) -> tuple[int, str, str]:
        if probe.client_version is None or probe.server_binary is None:
            raise FridaError(probe.guidance or "A matching Frida Server is unavailable.")
        adb = self.context.adb_client(command_log=command_log)
        if not probe_root(adb, serial).available:
            raise FridaError("Android root is required to start Frida Server.")
        remote_dir = f"/data/local/tmp/android-security-lab/{session_id}"
        remote = f"{remote_dir}/frida-server"
        adb.shell(
            serial,
            ("mkdir", "-p", remote_dir),
            timeout=15,
            check=True,
            operation="creating the managed Frida directory",
        )
        action = self.repository.record_cleanup_action(
            session_id,
            CleanupActionType.REMOVE_REMOTE_FILE,
            {"path": remote},
        )
        cleanup_ids["server_file"] = action.action_id
        adb.push_managed_file(serial, Path(probe.server_binary), remote)
        adb.shell(
            serial,
            ("chmod", "700", remote),
            timeout=15,
            check=True,
            operation="making the managed Frida Server executable",
        )
        version_result = adb.shell(
            serial,
            ("su", "-c", f"{remote} --version"),
            timeout=15,
            check=True,
            operation="verifying the managed Frida Server",
        )
        server_version = self._version(version_result.stdout or version_result.stderr)
        if server_version != probe.client_version:
            raise FridaError(
                "Managed Frida Server version does not match the local client."
            )
        started_at = datetime.now(UTC).isoformat()
        start_result = adb.shell(
            serial,
            ("su", "-c", f"{remote} >/dev/null 2>&1 & echo $!"),
            timeout=15,
            check=True,
            operation="starting the managed Frida Server",
        )
        pid = self._pid(start_result.stdout)
        if pid is None:
            raise FridaError("Frida Server did not return a process ID.")
        action = self.repository.record_cleanup_action(
            session_id,
            CleanupActionType.STOP_REMOTE_PROCESS,
            {
                "pid": pid,
                "name": "frida-server",
                "executable_path": remote,
                "proc_exe": None,
                "proc_start_time": None,
                "command_line": None,
                "session_id": session_id,
                "ownership_state": "owned",
                "started_at": started_at,
            },
        )
        cleanup_ids["server_process"] = action.action_id
        deadline = time.monotonic() + 10
        last_error: str | None = None
        while time.monotonic() < deadline:
            try:
                identity = capture_remote_process_identity(adb, serial, pid, remote)
                self.repository.update_cleanup_action_payload(
                    session_id,
                    action.action_id,
                    identity.to_cleanup_payload(
                        session_id=session_id,
                        name="frida-server",
                        started_at=started_at,
                    ),
                )
                return pid, remote, server_version
            except AndroidAssessorError as exc:
                last_error = redact_text(str(exc))[:300]
            time.sleep(0.25)
        raise FridaError(
            "Frida Server identity did not become verifiable within 10 seconds"
            + (f": {last_error}" if last_error else ".")
        )

    def start(self, session_id: str, *, spawn: bool = False) -> FridaObservationState:
        record = self.repository.load(session_id)
        load_scope(self.paths).require_device_package(record.serial, record.package)
        existing = self.load_state(record.session_id)
        if existing and existing.status in {"running", "stop_failed"}:
            raise FridaError("Frida observation is running or requires cleanup.")
        self.repository.require_modifying_session_slot(record.serial, record.session_id)
        paths = self.repository.paths_for(record.session_id)
        hook = (self.paths.root / "hooks" / "basic_observer.js").resolve()
        self.paths.require_inside_root(hook)
        if not hook.is_file():
            raise FridaError("The fixed Frida observer hook is missing.")
        session_hook = paths.frida_dir / "basic_observer.js"
        try:
            write_text_atomic(
                session_hook,
                hook.read_text(encoding="utf-8"),
                root=paths.root,
            )
        except OSError as exc:
            raise FridaError(f"Could not stage the Frida observer hook: {exc}") from exc
        cleanup_ids: dict[str, str] = {}
        server_started = False
        server_remote: str | None = None
        process: subprocess.Popen[bytes] | None = None
        identity: ProcessIdentity | None = None
        with DeviceLock(
            self.paths,
            record.serial,
            operation="start_frida_observation",
            session_id=record.session_id,
        ):
            latest = self.load_state(record.session_id)
            if latest and latest.status in {"running", "stop_failed"}:
                raise FridaError("Frida observation is running or requires cleanup.")
            adb = self.context.adb_client(command_log=paths.commands_jsonl)
            try:
                adb.require_authorized_device(record.serial)
                probe = self.probe(record.serial, command_log=paths.commands_jsonl)
                if probe.client_path is None or probe.client_version is None:
                    raise FridaError("Frida client is unavailable.")
                server_pid = probe.server_pid
                server_version = probe.server_version
                if server_pid is None:
                    server_pid, server_remote, server_version = self._start_server(
                        record.session_id,
                        record.serial,
                        probe,
                        cleanup_ids,
                        paths.commands_jsonl,
                    )
                    server_started = True
                elif probe.compatible is False:
                    raise FridaError(probe.guidance or "Frida versions are incompatible.")

                mode = "spawn" if spawn else "attach"
                if not spawn:
                    running = adb.shell(
                        record.serial,
                        ("pidof", record.package),
                        timeout=10,
                        check=False,
                        operation="checking whether the target app is running",
                    )
                    if self._pid(running.stdout) is None:
                        mode = "spawn"
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                raw_frida = paths.raw_dir / "frida"
                redacted_frida = paths.redacted_dir / "frida"
                raw_frida.mkdir(parents=True, exist_ok=True)
                redacted_frida.mkdir(parents=True, exist_ok=True)
                raw_events = raw_frida / f"observer-{stamp}.jsonl"
                events = redacted_frida / f"observer-{stamp}.jsonl"
                stdout_path = raw_frida / f"observer-{stamp}.stdout.log"
                stderr_path = raw_frida / f"observer-{stamp}.stderr.log"
                target_args = (
                    ["-f", record.package]
                    if mode == "spawn"
                    else ["-N", record.package]
                )
                command = [
                    probe.client_path,
                    "-D",
                    record.serial,
                    *target_args,
                    "-l",
                    str(session_hook),
                    "--no-auto-reload",
                    "-q",
                    "-t",
                    "inf",
                    "-o",
                    str(raw_events),
                    "--exit-on-error",
                ]
                flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
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
                        creationflags=flags,
                        close_fds=True,
                    )
                time.sleep(2)
                if process.poll() is not None:
                    detail = stderr_path.read_text(
                        encoding="utf-8", errors="replace"
                    )[-1000:]
                    raise FridaError(
                        f"Frida client exited during startup: {redact_text(detail)}"
                    )
                identity = self.process_controller.capture(process.pid)
                if identity is None:
                    raise FridaError("Could not capture Frida client process identity.")
                action = self.repository.record_cleanup_action(
                    record.session_id,
                    CleanupActionType.STOP_HOST_PROCESS,
                    {"role": "frida-client", "identity": identity.to_dict()},
                )
                cleanup_ids["client_process"] = action.action_id

                self.evidence.register_file(
                    record.session_id,
                    session_hook,
                    evidence_type="frida_hook",
                    source="framework",
                    description="Fixed observation-only Frida hook.",
                    sensitive=False,
                    redacted=False,
                )
                state = FridaObservationState(
                    session_id=record.session_id,
                    status="running",
                    mode=mode,
                    started_at=datetime.now(UTC).isoformat(),
                    stopped_at=None,
                    client_version=probe.client_version,
                    server_version=server_version,
                    server_pid=server_pid,
                    server_started_by_framework=server_started,
                    server_remote_path=server_remote,
                    process_identity=identity.to_dict(),
                    cleanup_action_ids=cleanup_ids,
                    hook_path=session_hook.relative_to(paths.root).as_posix(),
                    hook_sha256=sha256_file(session_hook),
                    events_path=events.relative_to(paths.root).as_posix(),
                    raw_events_path=raw_events.relative_to(paths.root).as_posix(),
                )
                write_json_atomic(
                    self._state_path(record.session_id),
                    state.to_dict(),
                    root=self.paths.root,
                )
                self.repository.append_event(
                    record.session_id,
                    "frida_observation_started",
                    {"mode": mode, "server_started": server_started},
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
                    and "client_process" not in cleanup_ids
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

    def stop(self, session_id: str) -> FridaObservationState:
        record = self.repository.load(session_id)
        state = self.load_state(record.session_id)
        if state is None:
            raise FridaError("Frida observation state does not exist.")
        if state.status == "stopped":
            return state
        paths = self.repository.paths_for(record.session_id)
        errors: list[str] = []
        with DeviceLock(
            self.paths,
            record.serial,
            operation="stop_frida_observation",
            session_id=record.session_id,
        ):
            latest = self.load_state(record.session_id)
            if latest is None:
                raise FridaError("Frida observation state does not exist.")
            if latest.status == "stopped":
                return latest
            state = latest
            adb = self.context.adb_client(command_log=paths.commands_jsonl)
            try:
                identity = ProcessIdentity.from_dict(state.process_identity)
                stopped = self.process_controller.terminate_owned(identity)
                self._mark_action(
                    record.session_id,
                    state.cleanup_action_ids.get("client_process"),
                    CleanupActionStatus.COMPLETED
                    if stopped
                    else CleanupActionStatus.SKIPPED,
                )
            except (AndroidAssessorError, OSError, ValueError) as exc:
                error = redact_text(str(exc))[:500]
                errors.append(error)
                self._mark_action(
                    record.session_id,
                    state.cleanup_action_ids.get("client_process"),
                    CleanupActionStatus.FAILED,
                    error,
                )

            if state.server_started_by_framework:
                try:
                    action_id = state.cleanup_action_ids.get("server_process")
                    action = next(
                        (
                            item
                            for item in self.repository.load(
                                record.session_id
                            ).cleanup_actions
                            if item.action_id == action_id
                        ),
                        None,
                    )
                    if action is None:
                        raise FridaError("Owned Frida Server cleanup action is missing.")
                    server_status = CleanupExecutor(
                        self.paths,
                        self.repository,
                        adb,
                        process_controller=self.process_controller,
                    ).execute_action(record, action)
                    self._mark_action(
                        record.session_id,
                        state.cleanup_action_ids.get("server_process"),
                        server_status,
                    )
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    error = redact_text(str(exc))[:500]
                    errors.append(error)
                    self._mark_action(
                        record.session_id,
                        state.cleanup_action_ids.get("server_process"),
                        CleanupActionStatus.FAILED,
                        error,
                    )

                if state.server_remote_path:
                    try:
                        exists = adb.shell(
                            record.serial,
                            ("test", "-e", state.server_remote_path),
                            timeout=10,
                            check=False,
                            operation="checking the managed Frida Server file",
                        )
                        if exists.exit_code == 0:
                            adb.shell(
                                record.serial,
                                ("rm", "-f", "--", state.server_remote_path),
                                timeout=15,
                                check=True,
                                operation="removing the managed Frida Server file",
                            )
                            file_status = CleanupActionStatus.COMPLETED
                        else:
                            file_status = CleanupActionStatus.SKIPPED
                        self._mark_action(
                            record.session_id,
                            state.cleanup_action_ids.get("server_file"),
                            file_status,
                        )
                    except (AndroidAssessorError, OSError, ValueError) as exc:
                        error = redact_text(str(exc))[:500]
                        errors.append(error)
                        self._mark_action(
                            record.session_id,
                            state.cleanup_action_ids.get("server_file"),
                            CleanupActionStatus.FAILED,
                            error,
                        )

            evidence_registered = state.evidence_registered
            output_events_path = state.events_path
            if not evidence_registered:
                try:
                    raw_events = require_under_root(
                        paths.root / (state.raw_events_path or state.events_path),
                        paths.root,
                    )
                    events = require_under_root(
                        paths.root / state.events_path,
                        paths.root,
                    )
                    if raw_events == events:
                        events = paths.redacted_dir / "frida" / raw_events.name
                        output_events_path = events.relative_to(paths.root).as_posix()
                    stem = raw_events.name.removesuffix(".jsonl")
                    for suffix in ("stdout.log", "stderr.log"):
                        raw_log = raw_events.parent / f"{stem}.{suffix}"
                        redacted_log = events.parent / f"{stem}.{suffix}"
                        if not raw_log.is_file():
                            continue
                        write_text_atomic(
                            redacted_log,
                            redact_text(
                                raw_log.read_text(
                                    encoding="utf-8",
                                    errors="replace",
                                )
                            ),
                            root=self.paths.root,
                        )
                        self.evidence.register_file(
                            record.session_id,
                            raw_log,
                            evidence_type="frida_log_raw",
                            source="frida",
                            description=f"Raw Frida observer {suffix}.",
                            sensitive=True,
                            redacted=False,
                        )
                        self.evidence.register_file(
                            record.session_id,
                            redacted_log,
                            evidence_type="frida_log",
                            source="frida",
                            description=f"Redacted Frida observer {suffix}.",
                            sensitive=True,
                            redacted=True,
                        )
                    if raw_events.is_file():
                        write_text_atomic(
                            events,
                            redact_text(
                                raw_events.read_text(
                                    encoding="utf-8",
                                    errors="replace",
                                )
                            ),
                            root=self.paths.root,
                        )
                        self.evidence.register_file(
                            record.session_id,
                            raw_events,
                            evidence_type="frida_events_raw",
                            source="frida",
                            description="Raw Frida observer event stream.",
                            sensitive=True,
                            redacted=False,
                        )
                        self.evidence.register_file(
                            record.session_id,
                            events,
                            evidence_type="frida_events",
                            source="frida",
                            description="Redacted observation-only Frida event stream.",
                            sensitive=True,
                            redacted=True,
                        )
                    evidence_registered = True
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    errors.append(redact_text(str(exc))[:500])

            stopped_state = FridaObservationState(
                **{
                    **state.to_dict(),
                    "status": "stopped" if not errors else "stop_failed",
                    "stopped_at": datetime.now(UTC).isoformat(),
                    "evidence_registered": evidence_registered,
                    "events_path": output_events_path,
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
                "frida_observation_stopped",
                {"success": not errors, "errors": errors},
            )
            return stopped_state
