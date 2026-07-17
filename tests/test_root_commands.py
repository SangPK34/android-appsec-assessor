from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from android_assessor.root import (
    AdbdRootBackend,
    AdbRootBackend,
    ExecutionPrincipal,
    NonRootBackend,
    RootCommand,
    RootCommandExecutor,
    RootFailure,
    RootMode,
    app_data_root,
    probe_root,
    root_shell,
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
        if "id" in arguments[-1]:
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
    assert "stat -c" in remote_command
    assert root in remote_command
    assert name in remote_command
    assert adb.calls[1][:2] == ("su", "-c")


def test_adbd_root_backend_dispatches_directly_without_su() -> None:
    adb = CaptureAdb()

    result = RootCommandExecutor(
        AdbdRootBackend(adb),  # type: ignore[arg-type]
    ).execute("FIXTURE_SERIAL", RootCommand.identity())

    assert len(adb.calls) == 1
    assert adb.calls[0][:2] == ("sh", "-c")
    assert "su" not in adb.calls[0]
    assert result.root_granted is True
    assert result.root_mode is RootMode.ADBD_ROOT
    assert result.backend == "adbd_root"


def test_non_root_backend_never_dispatches_adb_command() -> None:
    result = RootCommandExecutor(NonRootBackend()).execute(
        "FIXTURE_SERIAL",
        RootCommand.identity(),
    )

    assert result.root_granted is False
    assert result.root_mode is RootMode.NON_ROOT
    assert result.exit_code == 126


@dataclass
class ProbeAdb:
    results: dict[tuple[str, ...], CommandResult]
    calls: list[tuple[str, ...]] = field(default_factory=list)
    offline: bool = False

    def require_authorized_device(self, serial: str) -> object:
        if self.offline:
            from android_assessor.errors import AdbError

            raise AdbError("Android device is offline.")
        return object()

    def shell(
        self,
        serial: str,
        arguments: Sequence[str],
        **_kwargs: object,
    ) -> CommandResult:
        assert serial == "FIXTURE_SERIAL"
        selected = tuple(arguments)
        self.calls.append(selected)
        return self.results[selected]


def probe_adb(
    *,
    direct: CommandResult,
    su_path: CommandResult | None = None,
    su_id: CommandResult | None = None,
) -> ProbeAdb:
    results = {("id",): direct}
    if su_path is not None:
        results[("command", "-v", "su")] = su_path
    if su_id is not None:
        results[("su", "-c", "id")] = su_id
    return ProbeAdb(results)


def test_probe_root_prefers_adbd_root_without_probing_su() -> None:
    adb = probe_adb(direct=command_result(stdout="uid=0(root) gid=0(root)"))

    result = probe_root(adb, "FIXTURE_SERIAL")  # type: ignore[arg-type]

    assert result.available is True
    assert result.mode is RootMode.ADBD_ROOT
    assert result.probe_status == "verified"
    assert adb.calls == [("id",)]


def test_probe_root_uses_su_only_after_discovery() -> None:
    adb = probe_adb(
        direct=command_result(stdout="uid=2000(shell) gid=2000(shell)"),
        su_path=command_result(stdout="/system/xbin/su\n"),
        su_id=command_result(stdout="uid=0(root) gid=0(root)"),
    )

    result = probe_root(adb, "FIXTURE_SERIAL")  # type: ignore[arg-type]

    assert result.available is True
    assert result.mode is RootMode.SU_ROOT
    assert adb.calls[-1] == ("su", "-c", "id")


def test_probe_root_without_su_is_non_root_and_does_not_dispatch_su() -> None:
    adb = probe_adb(
        direct=command_result(stdout="uid=2000(shell) gid=2000(shell)"),
        su_path=command_result(exit_code=1),
    )

    result = probe_root(adb, "FIXTURE_SERIAL")  # type: ignore[arg-type]

    assert result.mode is RootMode.NON_ROOT
    assert result.probe_status == "not_root"
    assert ("su", "-c", "id") not in adb.calls


def test_probe_root_su_timeout_is_conservative() -> None:
    adb = probe_adb(
        direct=command_result(stdout="uid=2000(shell) gid=2000(shell)"),
        su_path=command_result(stdout="/system/xbin/su\n"),
        su_id=command_result(timed_out=True),
    )

    result = probe_root(adb, "FIXTURE_SERIAL")  # type: ignore[arg-type]

    assert result.available is False
    assert result.mode is RootMode.NON_ROOT
    assert result.probe_status == "timeout"


def test_probe_root_malformed_output_is_conservative() -> None:
    adb = probe_adb(
        direct=command_result(stdout="unexpected identity"),
        su_path=command_result(exit_code=1),
    )

    result = probe_root(adb, "FIXTURE_SERIAL")  # type: ignore[arg-type]

    assert result.available is False
    assert result.mode is RootMode.NON_ROOT
    assert result.probe_status == "malformed"


def test_probe_root_preserves_offline_as_adb_error() -> None:
    from android_assessor.errors import AdbError

    adb = ProbeAdb({}, offline=True)

    with pytest.raises(AdbError, match="offline"):
        probe_root(adb, "FIXTURE_SERIAL")  # type: ignore[arg-type]


def test_root_shell_adbd_mode_quotes_special_command_without_su() -> None:
    command = "echo 'value with spaces' >/data/local/tmp/fixture & echo $!"
    adb = ProbeAdb(
        {
            ("id",): command_result(stdout="uid=0(root) gid=0(root)"),
        }
    )

    def shell(
        serial: str,
        arguments: Sequence[str],
        **_kwargs: object,
    ) -> CommandResult:
        assert serial == "FIXTURE_SERIAL"
        selected = tuple(arguments)
        adb.calls.append(selected)
        if selected == ("id",):
            return adb.results[selected]
        return command_result(stdout="4242\n")

    adb.shell = shell  # type: ignore[method-assign]
    result = root_shell(
        adb,  # type: ignore[arg-type]
        "FIXTURE_SERIAL",
        command,
        timeout=5,
        check=True,
        operation="starting a fixture server",
    )

    assert result.stdout == "4242\n"
    assert adb.calls[1][:2] == ("sh", "-c")
    assert "su" not in adb.calls[1]
    assert "value with spaces" in adb.calls[1][-1]


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
