"""Safe external process execution using list arguments and explicit timeouts."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Final

from .errors import CommandTimeoutError, ExternalCommandError
from .paths import ProjectPaths
from .redaction import redact_arguments, redact_text_with_values

_DEFAULT_LOG: Final = object()


@dataclass(frozen=True, slots=True)
class CommandResult:
    arguments: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    started_at: str
    duration_ms: int
    timed_out: bool
    output_limit_exceeded: bool = False
    output_limit_stream: str | None = None


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
        return
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        pass
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=1)
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        pass


def _read_bounded_text(path: Path, maximum: int) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(maximum).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _detect_output_limit(
    stdout_handle: BinaryIO,
    stderr_handle: BinaryIO,
    *,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> str | None:
    stdout_size = os.fstat(stdout_handle.fileno()).st_size
    stderr_size = os.fstat(stderr_handle.fileno()).st_size
    if stdout_size > max_stdout_bytes:
        return "stdout"
    if stderr_size > max_stderr_bytes:
        return "stderr"
    return None


def _cleanup_temporary_directory(
    temporary: tempfile.TemporaryDirectory[str],
) -> None:
    """Remove command output files after transient Windows handle release."""

    attempts = 20
    for attempt in range(attempts):
        try:
            temporary.cleanup()
            return
        except PermissionError as exc:
            windows_sharing_violation = getattr(exc, "winerror", None) in {5, 32}
            if (
                os.name != "nt" and not windows_sharing_violation
            ) or attempt + 1 >= attempts:
                raise
            time.sleep(0.01 * (attempt + 1))


def _log_result(
    normalized: tuple[str, ...],
    result: CommandResult,
    *,
    sensitive_values: Sequence[str],
    command_log: Path | None | object,
) -> None:
    log_path = ProjectPaths.discover().command_log if command_log is _DEFAULT_LOG else command_log
    if not isinstance(log_path, Path):
        return
    payload: dict[str, object] = {
        "executable": normalized[0],
        "arguments": redact_arguments(normalized[1:], sensitive_values),
        "start": result.started_at,
        "end": datetime.now(UTC).isoformat(),
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "timeout": result.timed_out,
        "stderr": redact_text_with_values(result.stderr[-2048:], sensitive_values),
    }
    if result.output_limit_exceeded:
        payload["output_limit_exceeded"] = True
        payload["output_limit_stream"] = result.output_limit_stream
    _append_command_log(log_path, payload)


def _raise_for_result(
    result: CommandResult,
    *,
    timeout: float,
    check: bool,
    sensitive_values: Sequence[str],
) -> None:
    if not check:
        return
    executable = result.arguments[0]
    if result.timed_out:
        raise CommandTimeoutError(f"Command timed out after {timeout}s: {executable}")
    if result.output_limit_exceeded:
        stream = result.output_limit_stream or "output"
        raise ExternalCommandError(f"Command {stream} exceeded its byte limit: {executable}")
    if result.exit_code != 0:
        detail = redact_text_with_values(result.stderr[-1000:], sensitive_values).strip()
        suffix = f": {detail}" if detail else ""
        message = f"Command failed with exit code {result.exit_code}: {executable}{suffix}"
        raise ExternalCommandError(message)


def _append_command_log(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def run_command(
    arguments: Sequence[str | os.PathLike[str]],
    *,
    timeout: float,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = False,
    sensitive_values: Sequence[str] = (),
    command_log: Path | None | object = _DEFAULT_LOG,
) -> CommandResult:
    if not arguments:
        raise ValueError("arguments must not be empty")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    normalized = tuple(os.fspath(argument) for argument in arguments)
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    started = datetime.now(UTC)
    start_counter = time.perf_counter()
    timed_out = False

    try:
        completed = subprocess.run(
            normalized,
            cwd=cwd,
            env=process_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
            creationflags=creation_flags,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = -1
        stdout = (
            (exc.stdout or "").decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        stderr = (
            (exc.stderr or "").decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
    except OSError as exc:
        raise ExternalCommandError(f"Could not start {normalized[0]}: {exc}") from exc

    duration_ms = round((time.perf_counter() - start_counter) * 1000)
    result = CommandResult(
        arguments=normalized,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started.isoformat(),
        duration_ms=duration_ms,
        timed_out=timed_out,
    )

    _log_result(
        normalized,
        result,
        sensitive_values=sensitive_values,
        command_log=command_log,
    )
    _raise_for_result(
        result,
        timeout=timeout,
        check=check,
        sensitive_values=sensitive_values,
    )
    return result


def run_command_bounded_output(
    arguments: Sequence[str | os.PathLike[str]],
    *,
    timeout: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = False,
    sensitive_values: Sequence[str] = (),
    command_log: Path | None | object = _DEFAULT_LOG,
) -> CommandResult:
    """Run a process without buffering unbounded child output in parent memory."""

    if not arguments:
        raise ValueError("arguments must not be empty")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not isinstance(max_stdout_bytes, int) or max_stdout_bytes <= 0:
        raise ValueError("max_stdout_bytes must be a positive integer")
    if not isinstance(max_stderr_bytes, int) or max_stderr_bytes <= 0:
        raise ValueError("max_stderr_bytes must be a positive integer")

    normalized = tuple(os.fspath(argument) for argument in arguments)
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    started = datetime.now(UTC)
    start_counter = time.perf_counter()
    deadline = start_counter + timeout
    exit_code = -1
    timed_out = False
    output_limit_stream: str | None = None
    stdout = ""
    stderr = ""

    temporary = tempfile.TemporaryDirectory(prefix="asl-command-")
    try:
        temporary_path = Path(temporary.name)
        stdout_path = temporary_path / "stdout.bin"
        stderr_path = temporary_path / "stderr.bin"
        process: subprocess.Popen[bytes] | None = None
        with stdout_path.open("w+b", buffering=0) as stdout_handle, stderr_path.open(
            "w+b", buffering=0
        ) as stderr_handle:
            try:
                process = subprocess.Popen(
                    normalized,
                    cwd=cwd,
                    env=process_env,
                    stdin=None,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    shell=False,
                    creationflags=creation_flags,
                    start_new_session=os.name != "nt",
                )
            except OSError as exc:
                raise ExternalCommandError(
                    f"Could not start {normalized[0]}: {exc}"
                ) from exc

            try:
                while True:
                    output_limit_stream = _detect_output_limit(
                        stdout_handle,
                        stderr_handle,
                        max_stdout_bytes=max_stdout_bytes,
                        max_stderr_bytes=max_stderr_bytes,
                    )
                    if output_limit_stream is not None:
                        _stop_process(process)
                        break
                    return_code = process.poll()
                    if return_code is not None:
                        exit_code = process.wait()
                        output_limit_stream = _detect_output_limit(
                            stdout_handle,
                            stderr_handle,
                            max_stdout_bytes=max_stdout_bytes,
                            max_stderr_bytes=max_stderr_bytes,
                        )
                        if output_limit_stream is not None:
                            exit_code = -1
                        break
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0:
                        timed_out = True
                        _stop_process(process)
                        break
                    time.sleep(min(0.01, remaining))
            except BaseException:
                _stop_process(process)
                raise
        stdout = _read_bounded_text(stdout_path, max_stdout_bytes)
        stderr = _read_bounded_text(stderr_path, max_stderr_bytes)
    finally:
        _cleanup_temporary_directory(temporary)

    duration_ms = round((time.perf_counter() - start_counter) * 1000)
    result = CommandResult(
        arguments=normalized,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started.isoformat(),
        duration_ms=duration_ms,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_stream is not None,
        output_limit_stream=output_limit_stream,
    )
    _log_result(
        normalized,
        result,
        sensitive_values=sensitive_values,
        command_log=command_log,
    )
    _raise_for_result(
        result,
        timeout=timeout,
        check=check,
        sensitive_values=sensitive_values,
    )
    return result
