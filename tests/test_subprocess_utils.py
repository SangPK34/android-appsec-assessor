from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import BinaryIO

import pytest

from android_assessor import subprocess_utils
from android_assessor.errors import ExternalCommandError
from android_assessor.subprocess_utils import run_command, run_command_bounded_output


def test_list_arguments_preserve_spaces_and_unicode(tmp_path: Path) -> None:
    value = "thư mục có khoảng trắng"

    result = run_command(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", value],
        timeout=10,
        command_log=None,
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == value


def test_timeout_is_reported_without_shell(tmp_path: Path) -> None:
    result = run_command(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout=0.05,
        command_log=None,
    )

    assert result.timed_out is True
    assert result.exit_code == -1


def test_command_log_redacts_secret(tmp_path: Path) -> None:
    log_path = tmp_path / "commands.jsonl"

    run_command(
        [sys.executable, "-c", "print('ok')", "exact-secret"],
        timeout=10,
        sensitive_values=["exact-secret"],
        command_log=log_path,
    )

    payload = json.loads(log_path.read_text(encoding="utf-8"))
    assert "exact-secret" not in json.dumps(payload)


def test_command_log_redacts_sensitive_value_from_stderr(tmp_path: Path) -> None:
    log_path = tmp_path / "commands.jsonl"

    run_command(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1], file=sys.stderr); raise SystemExit(1)",
            "device-serial-123",
        ],
        timeout=10,
        sensitive_values=["device-serial-123"],
        command_log=log_path,
    )

    assert "device-serial-123" not in log_path.read_text(encoding="utf-8")


def test_bounded_output_preserves_success_output_and_list_arguments() -> None:
    value = "đầu ra có khoảng trắng"

    result = run_command_bounded_output(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", value],
        timeout=10,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        command_log=None,
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == value
    assert result.output_limit_exceeded is False
    assert result.output_limit_stream is None


def test_bounded_output_preserves_nonzero_result_and_check_semantics() -> None:
    arguments = [
        sys.executable,
        "-c",
        "import sys; print('bounded-error', file=sys.stderr); raise SystemExit(7)",
    ]

    result = run_command_bounded_output(
        arguments,
        timeout=10,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        command_log=None,
    )

    assert result.exit_code == 7
    assert result.stderr.strip() == "bounded-error"
    with pytest.raises(ExternalCommandError, match="exit code 7"):
        run_command_bounded_output(
            arguments,
            timeout=10,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            check=True,
            command_log=None,
        )


def test_bounded_output_timeout_terminates_process() -> None:
    result = run_command_bounded_output(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout=0.05,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        command_log=None,
    )

    assert result.timed_out is True
    assert result.exit_code == -1
    assert result.duration_ms < 1500


def test_bounded_output_stops_at_stdout_cap() -> None:
    result = run_command_bounded_output(
        [
            sys.executable,
            "-c",
            "import os,time; os.write(1, b'x' * 100000); time.sleep(2)",
        ],
        timeout=10,
        max_stdout_bytes=1024,
        max_stderr_bytes=4096,
        command_log=None,
    )

    assert result.exit_code == -1
    assert result.output_limit_exceeded is True
    assert result.output_limit_stream == "stdout"
    assert len(result.stdout.encode("utf-8")) <= 1024
    assert result.duration_ms < 1500


def test_bounded_output_stops_at_stderr_cap() -> None:
    result = run_command_bounded_output(
        [
            sys.executable,
            "-c",
            "import os,time; os.write(2, b'e' * 100000); time.sleep(2)",
        ],
        timeout=10,
        max_stdout_bytes=4096,
        max_stderr_bytes=1024,
        command_log=None,
    )

    assert result.exit_code == -1
    assert result.output_limit_exceeded is True
    assert result.output_limit_stream == "stderr"
    assert len(result.stderr.encode("utf-8")) <= 1024
    assert result.duration_ms < 1500


def test_bounded_output_checks_cap_after_fast_child_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = subprocess_utils._detect_output_limit
    calls = 0

    def delay_first_check(
        stdout_handle: BinaryIO,
        stderr_handle: BinaryIO,
        *,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> str | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            subprocess_utils.time.sleep(0.05)
            return None
        return original(
            stdout_handle,
            stderr_handle,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )

    monkeypatch.setattr(
        subprocess_utils,
        "_detect_output_limit",
        delay_first_check,
    )

    result = run_command_bounded_output(
        [sys.executable, "-c", "import os; os.write(1, b'x' * 65536)"],
        timeout=10,
        max_stdout_bytes=1024,
        max_stderr_bytes=4096,
        command_log=None,
    )

    assert calls >= 2
    assert result.exit_code == -1
    assert result.output_limit_exceeded is True
    assert result.output_limit_stream == "stdout"
    assert len(result.stdout.encode("utf-8")) <= 1024


def test_bounded_output_fast_exit_cleanup_stress() -> None:
    for _index in range(30):
        result = run_command_bounded_output(
            [sys.executable, "-c", "import os; os.write(2, b'e' * 8192)"],
            timeout=10,
            max_stdout_bytes=4096,
            max_stderr_bytes=512,
            command_log=None,
        )

        assert result.output_limit_exceeded is True
        assert result.output_limit_stream == "stderr"
        assert len(result.stderr.encode("utf-8")) <= 512


def test_bounded_output_check_reports_output_limit() -> None:
    with pytest.raises(ExternalCommandError, match="stdout exceeded its byte limit"):
        run_command_bounded_output(
            [
                sys.executable,
                "-c",
                "import os,time; os.write(1, b'x' * 100000); time.sleep(2)",
            ],
            timeout=10,
            max_stdout_bytes=1024,
            max_stderr_bytes=4096,
            check=True,
            command_log=None,
        )


def test_bounded_output_command_log_uses_shared_redaction(tmp_path: Path) -> None:
    log_path = tmp_path / "commands.jsonl"
    secret = "bounded-command-secret"

    run_command_bounded_output(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1], file=sys.stderr)",
            secret,
        ],
        timeout=10,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        sensitive_values=(secret,),
        command_log=log_path,
    )

    payload = json.loads(log_path.read_text(encoding="utf-8"))
    assert secret not in json.dumps(payload)
    assert payload["timeout"] is False


def test_bounded_output_removes_temporary_directories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = subprocess_utils.tempfile.TemporaryDirectory
    created: list[Path] = []

    def tracking_directory(*args: object, **kwargs: object) -> object:
        temporary = original(*args, **kwargs)
        created.append(Path(temporary.name))
        return temporary

    monkeypatch.setattr(
        subprocess_utils.tempfile,
        "TemporaryDirectory",
        tracking_directory,
    )

    run_command_bounded_output(
        [sys.executable, "-c", "print('ok')"],
        timeout=10,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        command_log=None,
    )
    run_command_bounded_output(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout=0.02,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        command_log=None,
    )
    run_command_bounded_output(
        [
            sys.executable,
            "-c",
            "import os,time; os.write(1, b'x' * 100000); time.sleep(2)",
        ],
        timeout=10,
        max_stdout_bytes=1024,
        max_stderr_bytes=4096,
        command_log=None,
    )

    assert len(created) == 3
    assert all(not path.exists() for path in created)


def test_bounded_output_retries_transient_windows_cleanup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = subprocess_utils.tempfile.TemporaryDirectory
    wrappers: list[object] = []

    class FlakyTemporaryDirectory:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.inner = original(*args, **kwargs)
            self.name = self.inner.name
            self.cleanup_calls = 0
            wrappers.append(self)

        def cleanup(self) -> None:
            self.cleanup_calls += 1
            if self.cleanup_calls < 3:
                error = PermissionError("temporary Windows sharing violation")
                error.winerror = 32
                raise error
            self.inner.cleanup()

    monkeypatch.setattr(
        subprocess_utils.tempfile,
        "TemporaryDirectory",
        FlakyTemporaryDirectory,
    )
    monkeypatch.setattr(subprocess_utils.time, "sleep", lambda _seconds: None)

    result = run_command_bounded_output(
        [sys.executable, "-c", "print('ok')"],
        timeout=10,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        command_log=None,
    )

    assert result.exit_code == 0
    assert len(wrappers) == 1
    wrapper = wrappers[0]
    assert isinstance(wrapper, FlakyTemporaryDirectory)
    assert wrapper.cleanup_calls == 3
    assert not Path(wrapper.name).exists()


def test_bounded_output_does_not_hide_persistent_cleanup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LockedTemporaryDirectory:
        name = "unused"
        cleanup_calls = 0

        def cleanup(self) -> None:
            self.cleanup_calls += 1
            error = PermissionError("persistent Windows sharing violation")
            error.winerror = 32
            raise error

    temporary = LockedTemporaryDirectory()
    monkeypatch.setattr(subprocess_utils.time, "sleep", lambda _seconds: None)

    with pytest.raises(PermissionError, match="persistent Windows sharing violation"):
        subprocess_utils._cleanup_temporary_directory(temporary)

    assert temporary.cleanup_calls == 20
