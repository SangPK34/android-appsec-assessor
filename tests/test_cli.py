from __future__ import annotations

from types import SimpleNamespace

import pytest

from android_assessor import cli
from android_assessor.cli import build_parser
from android_assessor.errors import AndroidAssessorError
from android_assessor.explorer import ExplorerConfig
from android_assessor.paths import ProjectPaths


def test_inspect_app_cli_contract() -> None:
    args = build_parser().parse_args(
        [
            "inspect-app",
            "--package",
            "com.example.lab",
            "--serial",
            "ABC123",
            "--json",
        ]
    )

    assert args.command == "inspect-app"
    assert args.package == "com.example.lab"
    assert args.serial == "ABC123"
    assert args.as_json is True


def test_full_scan_cli_forwards_autonomous_configuration(
    tmp_path,
    monkeypatch,
) -> None:
    calls: list[dict[str, object]] = []

    class FakeScanService:
        def __init__(self, _context: object) -> None:
            pass

        def scan(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            return SimpleNamespace(to_dict=lambda: {"status": "completed"})

    monkeypatch.setattr(cli, "ScanService", FakeScanService)
    args = build_parser().parse_args(
        [
            "scan",
            "--package",
            "com.example.lab",
            "--profile",
            "full",
            "--autonomous",
            "--max-runtime",
            "37",
            "--max-actions",
            "12",
            "--controlled-canary",
            "--json",
        ]
    )

    assert cli._run_scan(  # type: ignore[attr-defined]
        args,
        SimpleNamespace(paths=ProjectPaths(tmp_path)),  # type: ignore[arg-type]
    ) == 0
    assert calls[0]["profile"] == "full"
    assert calls[0]["autonomous"] is True
    assert calls[0]["runtime_seconds"] == 37
    assert calls[0]["controlled_canary"] is True
    assert calls[0]["ipc_validation"] is False
    assert calls[0]["micro_scenario"] is False
    config = calls[0]["explorer_config"]
    assert isinstance(config, ExplorerConfig)
    assert config.max_runtime_seconds == 37
    assert config.max_actions == 12

    calls.clear()
    no_wait = build_parser().parse_args(
        [
            "scan",
            "--package",
            "com.example.lab",
            "--profile",
            "full",
            "--runtime-seconds",
            "0",
            "--json",
        ]
    )
    assert cli._run_scan(  # type: ignore[attr-defined]
        no_wait,
        SimpleNamespace(paths=ProjectPaths(tmp_path)),  # type: ignore[arg-type]
    ) == 0
    assert calls[0]["autonomous"] is False
    assert calls[0]["explorer_config"] is None
    assert calls[0]["controlled_canary"] is False


def test_controlled_canary_cli_requires_autonomous_full_profile(tmp_path) -> None:
    args = build_parser().parse_args(
        [
            "scan",
            "--package",
            "com.example.lab",
            "--profile",
            "quick",
            "--controlled-canary",
        ]
    )

    with pytest.raises(AndroidAssessorError, match="autonomous Full Assessment"):
        cli._run_scan(  # type: ignore[attr-defined]
            args,
            SimpleNamespace(paths=ProjectPaths(tmp_path)),  # type: ignore[arg-type]
        )


def test_auto_cli_enables_bounded_controlled_exploration(tmp_path, monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    class FakeScanService:
        def __init__(self, _context: object) -> None:
            pass

        def scan(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            return SimpleNamespace(to_dict=lambda: {"status": "completed"})

    monkeypatch.setattr(cli, "ScanService", FakeScanService)
    args = build_parser().parse_args(
        [
            "scan",
            "--package",
            "com.example.lab",
            "--auto",
            "--max-runtime",
            "41",
            "--json",
        ]
    )

    assert cli._run_scan(  # type: ignore[attr-defined]
        args,
        SimpleNamespace(paths=ProjectPaths(tmp_path)),  # type: ignore[arg-type]
    ) == 0
    assert calls[0]["profile"] == "full"
    assert calls[0]["autonomous"] is True
    assert calls[0]["runtime_seconds"] == 41
    assert calls[0]["controlled_canary"] is True
    assert calls[0]["ipc_validation"] is True
    assert calls[0]["micro_scenario"] is True
    config = calls[0]["explorer_config"]
    assert isinstance(config, ExplorerConfig)
    assert config.per_action_timeout_seconds == 8
    assert config.max_observation_retries == 2
    assert config.max_action_failures == 4


def test_auto_cli_runs_profiled_scenario_before_exploration(tmp_path, monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    class FakeScanService:
        def __init__(self, _context: object) -> None:
            pass

        def scan(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            return SimpleNamespace(to_dict=lambda: {"status": "completed"})

    monkeypatch.setattr(cli, "ScanService", FakeScanService)
    args = build_parser().parse_args(
        [
            "scan",
            "--package",
            "com.example.lab",
            "--auto",
            "--max-runtime",
            "41",
            "--scenario-profile",
            "profile.yaml",
            "--scenario",
            "scenario.yaml",
            "--scenario-vars",
            "variables.local.yaml",
            "--json",
        ]
    )

    assert cli._run_scan(  # type: ignore[attr-defined]
        args,
        SimpleNamespace(paths=ProjectPaths(tmp_path)),  # type: ignore[arg-type]
    ) == 0
    assert calls[0]["autonomous"] is True
    assert calls[0]["controlled_canary"] is True
    assert calls[0]["micro_scenario"] is False
    request = calls[0]["scenario_request"]
    assert request is not None
    assert request.profile_path == tmp_path / "profile.yaml"
    assert request.scenario_path == tmp_path / "scenario.yaml"
    assert request.variables_path == tmp_path / "variables.local.yaml"
