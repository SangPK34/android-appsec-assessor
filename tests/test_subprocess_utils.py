from __future__ import annotations

import json
import sys
from pathlib import Path

from android_assessor.subprocess_utils import run_command


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
