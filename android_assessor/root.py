"""Conservative Android root probing and typed root-command execution."""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4

from .adb import AdbClient, validate_serial
from .backends import RootBackend
from .errors import AdbError
from .redaction import redact_text
from .subprocess_utils import CommandResult
from .validation import validate_package_name

_IDENTITY_PATTERN = re.compile(r"(?:^|\s)uid=(\d+)(?:\([^)]*\))?(?=\s|$)")
_UNSAFE_REMOTE_TOKEN = re.compile(r"[;&|`$<>\x00\r\n]")
_ALLOWED_ROOT_EXECUTABLES = frozenset({"id", "stat", "find", "head"})


class ExecutionPrincipal(StrEnum):
    ADB_SHELL = "ADB_SHELL"
    ANDROID_ROOT = "ANDROID_ROOT"
    APP_UID = "APP_UID"
    HOST_WINDOWS_USER = "HOST_WINDOWS_USER"


class RootMode(StrEnum):
    ADBD_ROOT = "adb_root"
    SU_ROOT = "su_root"
    NON_ROOT = "none"


class RootFailure(StrEnum):
    NONE = "none"
    ROOT_DENIED = "root_denied"
    SU_MISSING = "su_missing"
    TIMEOUT = "timeout"
    NOT_ROOT = "not_root"
    MALFORMED_IDENTITY = "malformed_identity"
    COMMAND_FAILED = "command_failed"
    BACKEND_ERROR = "backend_error"


@dataclass(frozen=True, slots=True)
class RootProbe:
    available: bool
    identity: str | None = None
    error: str | None = None
    mode: RootMode = RootMode.NON_ROOT
    probe_status: str = "unknown"
    probe_evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["mode"] = self.mode.value
        return payload


@dataclass(frozen=True, slots=True)
class RootCommand:
    operation: str
    arguments: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.arguments or self.arguments[0] not in _ALLOWED_ROOT_EXECUTABLES:
            raise ValueError("Root command executable is not allowlisted.")
        if any(not value or _UNSAFE_REMOTE_TOKEN.search(value) for value in self.arguments):
            raise ValueError("Root command contains unsupported characters.")

    @classmethod
    def identity(cls) -> RootCommand:
        return cls("identity", ("id",))

    @classmethod
    def stat_path(
        cls,
        path: str,
        *,
        allowed_roots: Sequence[str],
    ) -> RootCommand:
        remote = validate_root_remote_path(path, allowed_roots=allowed_roots)
        return cls("stat", ("stat", "-c", "%u:%g:%a:%s:%F", remote))

    @classmethod
    def list_directory(
        cls,
        path: str,
        *,
        allowed_roots: Sequence[str],
    ) -> RootCommand:
        remote = validate_root_remote_path(path, allowed_roots=allowed_roots)
        return cls(
            "list_directory",
            (
                "find",
                remote,
                "-mindepth",
                "1",
                "-maxdepth",
                "1",
                "-printf",
                "%P\\t%y\\t%s\\t%u\\t%g\\t%m\\n",
            ),
        )

    @classmethod
    def read_prefix(
        cls,
        path: str,
        *,
        allowed_roots: Sequence[str],
        max_bytes: int,
    ) -> RootCommand:
        if isinstance(max_bytes, bool) or not 1 <= max_bytes <= 52_428_800:
            raise ValueError("Root read limit must be between 1 byte and 50 MiB.")
        remote = validate_root_remote_path(path, allowed_roots=allowed_roots)
        return cls("read_prefix", ("head", "-c", str(max_bytes), remote))


@dataclass(frozen=True, slots=True)
class RootExecutionResult:
    command_id: str
    started_at: str
    ended_at: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    root_granted: bool
    backend: str
    root_mode: RootMode
    principal: ExecutionPrincipal
    failure: RootFailure
    operation: str

    def to_dict(self, *, redacted: bool = True) -> dict[str, Any]:
        payload = asdict(self)
        payload["principal"] = self.principal.value
        payload["failure"] = self.failure.value
        payload["root_mode"] = self.root_mode.value
        if redacted:
            payload["stdout"] = redact_text(self.stdout)
            payload["stderr"] = redact_text(self.stderr)
        return payload


def app_data_root(package: str, *, user_id: int = 0) -> str:
    target = validate_package_name(package)
    if isinstance(user_id, bool) or not 0 <= user_id <= 999:
        raise ValueError("Android user ID is outside the supported range.")
    return f"/data/user/{user_id}/{target}"


def validate_root_remote_path(path: str, *, allowed_roots: Sequence[str]) -> str:
    if not isinstance(path, str) or not path or _UNSAFE_REMOTE_TOKEN.search(path):
        raise ValueError("Root-assisted path contains unsupported characters.")
    candidate = PurePosixPath(path)
    if not candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise ValueError("Root-assisted path must be absolute and traversal-free.")
    normalized = candidate.as_posix()
    roots: list[PurePosixPath] = []
    for raw_root in allowed_roots:
        if not isinstance(raw_root, str) or _UNSAFE_REMOTE_TOKEN.search(raw_root):
            raise ValueError("Allowed root path is invalid.")
        root = PurePosixPath(raw_root)
        if not root.is_absolute() or ".." in root.parts:
            raise ValueError("Allowed root path is invalid.")
        roots.append(root)
    if not roots or not any(candidate == root or root in candidate.parents for root in roots):
        raise ValueError("Root-assisted path is outside the allowlisted data directory.")
    return normalized


def quote_remote_arguments(arguments: Sequence[str]) -> str:
    command = RootCommand("quoted", tuple(arguments))
    return " ".join(shlex.quote(value) for value in command.arguments)


def _identity_uid(output: str) -> int | None:
    match = _IDENTITY_PATTERN.search(output.strip())
    return int(match.group(1)) if match else None


def _classify_identity(result: CommandResult) -> tuple[bool, RootFailure]:
    combined = f"{result.stdout}\n{result.stderr}".casefold()
    if result.timed_out:
        return False, RootFailure.TIMEOUT
    if result.exit_code == 127 or "su: not found" in combined or "su: inaccessible" in combined:
        return False, RootFailure.SU_MISSING
    if any(marker in combined for marker in ("permission denied", "not allowed", "access denied")):
        return False, RootFailure.ROOT_DENIED
    if result.exit_code != 0:
        return False, RootFailure.COMMAND_FAILED
    uid = _identity_uid(result.stdout)
    if uid is None:
        return False, RootFailure.MALFORMED_IDENTITY
    if uid != 0:
        return False, RootFailure.NOT_ROOT
    return True, RootFailure.NONE


class AdbdRootBackend:
    backend_name = "adbd_root"
    root_mode = RootMode.ADBD_ROOT

    def __init__(self, adb: AdbClient) -> None:
        self.adb = adb

    def execute_root(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float,
    ) -> CommandResult:
        remote_command = quote_remote_arguments(arguments)
        return self.adb.shell(
            validate_serial(serial),
            ("sh", "-c", shlex.quote(remote_command)),
            timeout=timeout,
            check=False,
            operation="running a typed Android ADBD-root command",
        )


class SuRootBackend:
    backend_name = "su"
    root_mode = RootMode.SU_ROOT

    def __init__(self, adb: AdbClient) -> None:
        self.adb = adb

    def execute_root(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float,
    ) -> CommandResult:
        selected = validate_serial(serial)
        remote_command = quote_remote_arguments(arguments)
        return self.adb.shell(
            selected,
            ("su", "-c", shlex.quote(remote_command)),
            timeout=timeout,
            check=False,
            operation="running a typed Android root command",
        )


# Compatibility name retained for existing callers and fixtures.  The backend
# uses su only when the detector has selected SU_ROOT.
AdbRootBackend = SuRootBackend


class NonRootBackend:
    backend_name = "none"
    root_mode = RootMode.NON_ROOT

    def execute_root(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float,
    ) -> CommandResult:
        del serial, timeout
        return CommandResult(
            arguments=tuple(arguments),
            exit_code=126,
            stdout="",
            stderr="Android root is unavailable.",
            started_at=datetime.now(UTC).isoformat(),
            duration_ms=0,
            timed_out=False,
        )


class RootCommandExecutor:
    def __init__(self, backend: RootBackend, *, timeout: float = 30) -> None:
        if timeout <= 0 or timeout > 300:
            raise ValueError("Root command timeout must be between 0 and 300 seconds.")
        self.backend = backend
        self.timeout = timeout

    @property
    def backend_name(self) -> str:
        return str(getattr(self.backend, "backend_name", type(self.backend).__name__))

    def _build_result(
        self,
        command: RootCommand,
        result: CommandResult,
        *,
        command_id: str,
        started_at: str,
        root_granted: bool,
        failure: RootFailure,
    ) -> RootExecutionResult:
        return RootExecutionResult(
            command_id=command_id,
            started_at=started_at,
            ended_at=datetime.now(UTC).isoformat(),
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
            root_granted=root_granted,
            backend=self.backend_name,
            root_mode=RootMode(
                getattr(
                    self.backend,
                    "root_mode",
                    RootMode.SU_ROOT if root_granted else RootMode.NON_ROOT,
                )
            ),
            principal=(
                ExecutionPrincipal.ANDROID_ROOT
                if root_granted
                else ExecutionPrincipal.ADB_SHELL
            ),
            failure=failure,
            operation=command.operation,
        )

    def execute(self, serial: str, command: RootCommand) -> RootExecutionResult:
        selected = validate_serial(serial)
        command_id = uuid4().hex
        started_at = datetime.now(UTC).isoformat()
        identity_command = RootCommand.identity()
        try:
            identity = self.backend.execute_root(
                selected,
                identity_command.arguments,
                timeout=self.timeout,
            )
        except AdbError as exc:
            failed = CommandResult(
                arguments=identity_command.arguments,
                exit_code=-1,
                stdout="",
                stderr=redact_text(str(exc)),
                started_at=started_at,
                duration_ms=0,
                timed_out=False,
            )
            return self._build_result(
                command,
                failed,
                command_id=command_id,
                started_at=started_at,
                root_granted=False,
                failure=RootFailure.BACKEND_ERROR,
            )
        root_granted, failure = _classify_identity(identity)
        if command.operation == "identity" or not root_granted:
            return self._build_result(
                command,
                identity,
                command_id=command_id,
                started_at=started_at,
                root_granted=root_granted,
                failure=failure,
            )
        try:
            result = self.backend.execute_root(
                selected,
                command.arguments,
                timeout=self.timeout,
            )
        except AdbError as exc:
            result = CommandResult(
                arguments=command.arguments,
                exit_code=-1,
                stdout="",
                stderr=redact_text(str(exc)),
                started_at=started_at,
                duration_ms=0,
                timed_out=False,
            )
            command_failure = RootFailure.BACKEND_ERROR
        else:
            command_failure = (
                RootFailure.TIMEOUT
                if result.timed_out
                else RootFailure.COMMAND_FAILED
                if result.exit_code != 0
                else RootFailure.NONE
            )
        return self._build_result(
            command,
            result,
            command_id=command_id,
            started_at=started_at,
            root_granted=True,
            failure=command_failure,
        )


def probe_root(adb: AdbClient, serial: str) -> RootProbe:
    adb.require_authorized_device(serial)
    direct = adb.shell(
        serial,
        ("id",),
        timeout=8,
        check=False,
        operation="probing the ADB shell identity",
    )
    direct_granted, direct_failure = _classify_identity(direct)
    evidence: dict[str, Any] = {
        "shell_identity": redact_text(direct.stdout.strip())[:300],
        "shell_exit_code": direct.exit_code,
        "shell_timed_out": direct.timed_out,
    }
    if direct_granted:
        return RootProbe(
            available=True,
            identity=direct.stdout.strip()[:300],
            mode=RootMode.ADBD_ROOT,
            probe_status="verified",
            probe_evidence={**evidence, "strategy": "adb_shell_id"},
        )
    if direct.timed_out:
        return RootProbe(
            available=False,
            error="ADB shell identity probe timed out.",
            probe_status="timeout",
            probe_evidence={**evidence, "strategy": "adb_shell_id"},
        )

    su_path = adb.shell(
        serial,
        ("command", "-v", "su"),
        timeout=8,
        check=False,
        operation="checking for the su executable",
    )
    su_present = bool(su_path.stdout.strip())
    evidence["su_path"] = redact_text(su_path.stdout.strip())[:300]
    evidence["su_present"] = su_present
    if su_path.timed_out:
        return RootProbe(
            available=False,
            error="Android su discovery timed out.",
            mode=RootMode.NON_ROOT,
            probe_status="timeout",
            probe_evidence={**evidence, "strategy": "command_v_su"},
        )
    if su_path.exit_code != 0 or not su_present:
        status = (
            "malformed"
            if direct_failure is RootFailure.MALFORMED_IDENTITY
            else "not_root"
        )
        error = (
            "Android shell returned a malformed identity and su is unavailable."
            if status == "malformed"
            else "Android shell is not root and su is unavailable."
        )
        return RootProbe(
            available=False,
            error=error,
            mode=RootMode.NON_ROOT,
            probe_status=status,
            probe_evidence={**evidence, "strategy": "command_v_su"},
        )
    su_result = adb.shell(
        serial,
        ("su", "-c", "id"),
        timeout=8,
        check=False,
        operation="probing the su root identity",
    )
    su_granted, su_failure = _classify_identity(su_result)
    evidence.update(
        {
            "su_identity": redact_text(su_result.stdout.strip())[:300],
            "su_exit_code": su_result.exit_code,
            "su_timed_out": su_result.timed_out,
            "strategy": "su_c_id",
        }
    )
    if su_granted:
        return RootProbe(
            available=True,
            identity=su_result.stdout.strip()[:300],
            mode=RootMode.SU_ROOT,
            probe_status="verified",
            probe_evidence=evidence,
        )
    if su_failure is RootFailure.TIMEOUT:
        error = "Android su probe timed out."
        status = "timeout"
    elif su_failure is RootFailure.ROOT_DENIED:
        error = "Android su root request was denied."
        status = "denied"
    elif su_failure is RootFailure.MALFORMED_IDENTITY:
        error = "Android su returned a malformed identity."
        status = "malformed"
    else:
        detail = redact_text((su_result.stderr or su_result.stdout).strip())[:300]
        error = detail or (
            "Android shell is not root and su is unavailable."
            if not su_present
            else "Android su did not return a verified uid=0 identity."
        )
        status = "not_root"
    return RootProbe(
        available=False,
        error=error,
        mode=RootMode.NON_ROOT,
        probe_status=status,
        probe_evidence=evidence,
    )


def root_shell(
    adb: AdbClient,
    serial: str,
    command: str,
    *,
    timeout: float,
    check: bool,
    operation: str,
    probe: RootProbe | None = None,
) -> CommandResult:
    if not command or "\x00" in command or "\r" in command or "\n" in command:
        raise ValueError("Root shell command contains unsupported characters.")
    selected_probe = probe or probe_root(adb, serial)
    if selected_probe.mode is RootMode.ADBD_ROOT:
        arguments = ("sh", "-c", shlex.quote(command))
    elif selected_probe.mode is RootMode.SU_ROOT:
        arguments = ("su", "-c", shlex.quote(command))
    else:
        result = NonRootBackend().execute_root(serial, ("id",), timeout=timeout)
        if check:
            raise AdbError(selected_probe.error or "Android root is unavailable.")
        return result
    return adb.shell(
        serial,
        arguments,
        timeout=timeout,
        check=check,
        operation=operation,
    )
