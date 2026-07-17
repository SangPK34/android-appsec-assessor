from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import frida
import pytest

from android_assessor.frida_controller import FridaController
from android_assessor.frida_events import (
    PACKAGE_PLACEHOLDER,
    SESSION_PLACEHOLDER,
    FridaHandshakeStatus,
    FridaVersionCompatibility,
    FridaVersionState,
    parse_frida_jsonl,
    stage_observer_hook,
)
from tests.fakes import FIXTURE_ROOT

SESSION_ID = "fixture-session"
PACKAGE = "com.example.rootedlab"


def fixture_events() -> str:
    return (FIXTURE_ROOT / "frida" / "events.jsonl").read_text(encoding="utf-8")


def test_frida_event_fixture_parses_handshake_runtime_and_stop() -> None:
    result = parse_frida_jsonl(
        fixture_events(),
        expected_session_id=SESSION_ID,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )

    assert result.errors == ()
    assert result.handshake_status is FridaHandshakeStatus.VALID
    assert result.runtime_event_count == 3
    assert result.observer_stopped is True
    assert result.physical_validation_status == "UNVERIFIED"
    assert any(event.canary_match for event in result.events)
    normalized = result.to_jsonl()
    assert "fixture-secret-token" not in normalized
    assert "fixture-return-token" not in normalized
    assert "fixture@example.invalid" not in normalized
    assert "<redacted>" in normalized


def test_frida_parser_accepts_cli_prefix_and_nested_payload() -> None:
    event = json.loads(fixture_events().splitlines()[2])
    nested = json.dumps({"type": "log", "payload": json.dumps(event)})
    value = f"[Local::RootedLab ]-> {json.dumps(event)}\n{nested}\n"

    result = parse_frida_jsonl(
        value,
        expected_session_id=SESSION_ID,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )

    assert len(result.events) == 2
    assert result.handshake_status is FridaHandshakeStatus.INVALID


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("session_id", "other-session", "session attribution"),
        ("package", "com.other.app", "package attribution"),
        ("pid", 0, "positive integer"),
        ("thread_id", -1, "non-negative"),
        ("canary_match", "yes", "boolean"),
        ("observer_version", "latest", "observer_version"),
    ),
)
def test_frida_parser_rejects_wrong_attribution_or_schema(
    field: str,
    value: object,
    message: str,
) -> None:
    event = json.loads(fixture_events().splitlines()[2])
    event[field] = value

    result = parse_frida_jsonl(
        json.dumps(event),
        expected_session_id=SESSION_ID,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )

    assert result.events == ()
    assert message in result.errors[0]
    assert result.handshake_status is FridaHandshakeStatus.MISSING


def test_frida_parser_reports_missing_json_and_oversized_lines() -> None:
    result = parse_frida_jsonl(
        "not-json\n" + ("x" * 1_048_577),
        expected_session_id=SESSION_ID,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )

    assert len(result.errors) == 2
    assert result.events == ()


@pytest.mark.parametrize(
    ("client", "server", "expected"),
    (
        (None, "17.0.0", FridaVersionCompatibility.CLIENT_MISSING),
        ("17.0.0", None, FridaVersionCompatibility.SERVER_MISSING),
        ("17.0", "17.0", FridaVersionCompatibility.INVALID_VERSION),
        ("17.0.0", "17.0.1", FridaVersionCompatibility.VERSION_MISMATCH),
        ("17.0.0", "17.0.0", FridaVersionCompatibility.COMPATIBLE),
    ),
)
def test_frida_version_state_model(
    client: str | None,
    server: str | None,
    expected: FridaVersionCompatibility,
) -> None:
    state = FridaVersionState.evaluate(client, server)
    assert state.compatibility is expected
    assert state.to_dict()["compatibility"] == expected.value


def test_observer_hook_staging_injects_only_session_and_target(tmp_path: Path) -> None:
    template = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"
    destination = tmp_path / "session" / "basic_observer.js"

    digest = stage_observer_hook(
        template,
        destination,
        session_id=SESSION_ID,
        package=PACKAGE,
        project_root=tmp_path,
    )

    source = destination.read_text(encoding="utf-8")
    assert SESSION_PLACEHOLDER not in source
    assert PACKAGE_PLACEHOLDER not in source
    assert SESSION_ID in source
    assert PACKAGE in source
    assert digest == hashlib.sha256(source.encode("utf-8")).hexdigest()


def test_observer_hook_has_no_hardcoded_target_and_compiles() -> None:
    hook = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"
    source = hook.read_text(encoding="utf-8")

    assert source.count(SESSION_PLACEHOLDER) == 1
    assert source.count(PACKAGE_PLACEHOLDER) == 1
    assert "com.example" not in source
    assert "universal bypass" not in source.casefold()
    compiled = frida.Compiler().build(str(hook), project_root=str(hook.parent.parent))
    assert isinstance(compiled, str)
    assert compiled


class FakeProcess:
    returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode


def test_controller_handshake_gate_accepts_normalized_fixture(tmp_path: Path) -> None:
    events = tmp_path / "observer.jsonl"
    events.write_text(fixture_events(), encoding="utf-8")

    FridaController._wait_observer_handshake(
        FakeProcess(),  # type: ignore[arg-type]
        events,
        session_id=SESSION_ID,
        package=PACKAGE,
        timeout=0.1,
    )


def test_controller_handshake_gate_rejects_timeout_and_early_exit(tmp_path: Path) -> None:
    missing = tmp_path / "missing.jsonl"
    with pytest.raises(Exception, match="handshake"):
        FridaController._wait_observer_handshake(
            FakeProcess(),  # type: ignore[arg-type]
            missing,
            session_id=SESSION_ID,
            package=PACKAGE,
            timeout=0,
        )

    exited = SimpleNamespace(poll=lambda: 2, returncode=2)
    with pytest.raises(Exception, match="exited"):
        FridaController._wait_observer_handshake(
            exited,  # type: ignore[arg-type]
            missing,
            session_id=SESSION_ID,
            package=PACKAGE,
            timeout=0.1,
        )


def test_fixture_provenance_cannot_be_labeled_physical() -> None:
    with pytest.raises(ValueError, match="simulated provenance"):
        parse_frida_jsonl(
            fixture_events(),
            expected_session_id=SESSION_ID,
            expected_package=PACKAGE,
            source="fixture",
            environment="physical",
        )
