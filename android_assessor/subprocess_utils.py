"""Safe external process execution using list arguments and explicit timeouts."""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

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

    log_path = ProjectPaths.discover().command_log if command_log is _DEFAULT_LOG else command_log
    if isinstance(log_path, Path):
        _append_command_log(
            log_path,
            {
                "executable": normalized[0],
                "arguments": redact_arguments(normalized[1:], sensitive_values),
                "start": result.started_at,
                "end": datetime.now(UTC).isoformat(),
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "timeout": result.timed_out,
                "stderr": redact_text_with_values(result.stderr[-2048:], sensitive_values),
            },
        )

    if check and timed_out:
        raise CommandTimeoutError(f"Command timed out after {timeout}s: {normalized[0]}")
    if check and exit_code != 0:
        detail = redact_text_with_values(stderr[-1000:], sensitive_values).strip()
        suffix = f": {detail}" if detail else ""
        message = f"Command failed with exit code {exit_code}: {normalized[0]}{suffix}"
        raise ExternalCommandError(message)
    return result
