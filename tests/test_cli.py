from __future__ import annotations

from types import SimpleNamespace

from android_assessor import cli
from android_assessor.cli import build_parser
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
