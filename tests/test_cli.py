from __future__ import annotations

from android_assessor.cli import build_parser


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
