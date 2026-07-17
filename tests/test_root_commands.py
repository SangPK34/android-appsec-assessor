from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from android_assessor.root import (
    AdbRootBackend,
    ExecutionPrincipal,
    RootCommand,
    RootCommandExecutor,
    RootFailure,
    app_data_root,
    validate_root_remote_path,
)
from android_assessor.subprocess_utils import CommandResult
from tests.fakes import FakeAndroidBackend


def command_result(
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        arguments=(),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=timed_out,
    )


@dataclass
class ScriptedRootBackend:
    results: list[CommandResult]
    backend_name: str = "fixture_root"
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def execute_root(
        self,
        serial: str,
        arguments: Sequence[str],
        *,
        timeout: float,
    ) -> CommandResult:
        del serial, timeout
        self.calls.append(tuple(arguments))
        return self.results.pop(0)


@pytest.mark.parametrize(
    ("outcome", "granted", "failure"),
    (
        ("available", True, RootFailure.NONE),
        ("shell", False, RootFailure.NOT_ROOT),
        ("denied", False, RootFailure.ROOT_DENIED),
        ("timeout", False, RootFailure.TIMEOUT),
        ("missing", False, RootFailure.SU_MISSING),
        ("malformed", False, RootFailure.MALFORMED_IDENTITY),
    ),
)
def test_root_identity_outcomes(
    outcome: str,
    granted: bool,
    failure: RootFailure,
) -> None:
    backend = FakeAndroidBackend(root_outcome=outcome)

    result = RootCommandExecutor(backend, timeout=5).execute(
        backend.serial,
        RootCommand.identity(),
    )

    assert result.root_granted is granted
    assert result.failure is failure
    assert result.principal is (
        ExecutionPrincipal.ANDROID_ROOT if granted else ExecutionPrincipal.ADB_SHELL
    )
    assert result.command_id
    assert result.started_at <= result.ended_at
    assert result.backend == "FakeAndroidBackend"


def test_exit_zero_with_stderr_still_requires_verified_uid_zero() -> None:
    backend = ScriptedRootBackend(
        [command_result(stdout="uid=0(root) gid=0(root)", stderr="fixture warning")]
    )

    result = RootCommandExecutor(backend).execute("FIXTURE_SERIAL", RootCommand.identity())

    assert result.root_granted is True
    assert result.failure is RootFailure.NONE
    assert result.stderr == "fixture warning"


def test_malformed_uid_zero_substring_is_not_root_identity() -> None:
    backend = ScriptedRootBackend([command_result(stdout="prefix uid=0evil suffix")])

    result = RootCommandExecutor(backend).execute("FIXTURE_SERIAL", RootCommand.identity())

    assert result.root_granted is False
    assert result.failure is RootFailure.MALFORMED_IDENTITY


def test_failed_root_command_retains_grant_but_reports_command_failure() -> None:
    backend = ScriptedRootBackend(
        [
            command_result(stdout="uid=0(root) gid=0(root)"),
            command_result(exit_code=2, stderr="stat failed"),
        ]
    )
    root = app_data_root("com.example.rootedlab")
    command = RootCommand.stat_path(f"{root}/files/item.txt", allowed_roots=(root,))

    result = RootCommandExecutor(backend).execute("FIXTURE_SERIAL", command)

    assert result.root_granted is True
    assert result.exit_code == 2
    assert result.failure is RootFailure.COMMAND_FAILED
    assert backend.calls[1][0] == "stat"


class CaptureAdb:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        **_kwargs: object,
    ) -> CommandResult:
        assert serial == "FIXTURE_SERIAL"
        self.calls.append(tuple(arguments))
        if arguments[-1] == "id":
            return command_result(stdout="uid=0(root) gid=0(root)")
        return command_result(stdout="10123:10123:600:10:regular file")


@pytest.mark.parametrize(
    "name",
    ("file with spaces.txt", "dữ-liệu-canary.txt"),
)
def test_remote_paths_with_spaces_or_unicode_are_single_quoted_tokens(name: str) -> None:
    adb = CaptureAdb()
    root = app_data_root("com.example.rootedlab")
    command = RootCommand.stat_path(f"{root}/files/{name}", allowed_roots=(root,))

    result = RootCommandExecutor(
        AdbRootBackend(adb),  # type: ignore[arg-type]
    ).execute("FIXTURE_SERIAL", command)

    assert result.root_granted is True
    remote_command = adb.calls[1][-1]
    assert remote_command.startswith("stat -c")
    assert f"'{root}/files/{name}'" in remote_command
    assert adb.calls[1][:2] == ("su", "-c")


@pytest.mark.parametrize(
    "path",
    (
        "/data/user/0/com.example.rootedlab/files/a;id",
        "/data/user/0/com.example.rootedlab/files/$(id)",
        "/data/user/0/com.example.rootedlab/files/a|id",
        "/data/user/0/com.example.rootedlab/../other/secret",
    ),
)
def test_root_path_rejects_injection_and_traversal(path: str) -> None:
    root = app_data_root("com.example.rootedlab")

    with pytest.raises(ValueError):
        RootCommand.stat_path(path, allowed_roots=(root,))


def test_root_path_must_remain_inside_target_data_directory() -> None:
    root = app_data_root("com.example.rootedlab")

    with pytest.raises(ValueError, match="outside"):
        validate_root_remote_path(
            "/data/user/0/com.other.app/files/a.txt",
            allowed_roots=(root,),
        )


def test_result_serialization_redacts_command_output() -> None:
    backend = ScriptedRootBackend(
        [
            command_result(
                stdout="uid=0(root) gid=0(root)",
                stderr="Authorization: Bearer fixture-secret-token",
            )
        ]
    )

    payload = RootCommandExecutor(backend).execute(
        "FIXTURE_SERIAL",
        RootCommand.identity(),
    ).to_dict()

    assert "fixture-secret-token" not in payload["stderr"]
    assert payload["principal"] == "ANDROID_ROOT"
    assert payload["failure"] == "none"


def test_execution_principals_are_not_conflated() -> None:
    assert {
        principal.value
        for principal in ExecutionPrincipal
    } == {"ADB_SHELL", "ANDROID_ROOT", "APP_UID", "HOST_WINDOWS_USER"}
