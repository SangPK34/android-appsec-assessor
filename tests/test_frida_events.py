from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import frida
import pytest

from android_assessor.frida_controller import FridaController
from android_assessor.frida_events import (
    CANARY_PLACEHOLDER,
    OBSERVER_VERSION,
    PACKAGE_PLACEHOLDER,
    SESSION_PLACEHOLDER,
    FridaHandshakeStatus,
    FridaVersionCompatibility,
    FridaVersionState,
    parse_frida_jsonl,
    stage_observer_hook,
)
from android_assessor.paths import ProjectPaths
from android_assessor.storage import write_json_atomic
from tests.fakes import FIXTURE_ROOT

SESSION_ID = "fixture-session"
PACKAGE = "com.example.rootedlab"
CANARY = "THESIS_CANARY_20260717T100000Z_abcdef123456"


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
        ("observer_version", "0.7.0", "incompatible"),
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


def test_frida_parser_redacts_nested_values_under_sensitive_parent_keys() -> None:
    event = json.loads(fixture_events().splitlines()[2])
    event["arguments_redacted"] = [
        {"password": {"pin": 123456}},
        {"client_secret": {"bytes": [65, 66]}},
        {"key_sha256": "a" * 64},
    ]

    result = parse_frida_jsonl(
        json.dumps(event),
        expected_session_id=SESSION_ID,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )

    assert result.errors == ()
    arguments = result.events[0].arguments_redacted
    assert arguments[0]["password"] == "<redacted>"
    assert arguments[1]["client_secret"] == "<redacted>"
    assert arguments[2]["key_sha256"] == "a" * 64
    assert result.handshake_status is FridaHandshakeStatus.VALID


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


def test_frida_parser_redacts_unknown_raw_string_fields_fail_closed() -> None:
    event = json.loads(fixture_events().splitlines()[3])
    event["arguments_redacted"] = [
        "opaque-fixture-secret",
        {
            "value": "raw-value-secret",
            "custom_field": "raw-custom-secret",
        },
    ]
    event["return_value_redacted"] = "raw-return-secret"

    result = parse_frida_jsonl(
        json.dumps(event),
        expected_session_id=SESSION_ID,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )
    rendered = result.to_jsonl()

    assert result.errors == ()
    for secret in (
        "opaque-fixture-secret",
        "raw-value-secret",
        "raw-custom-secret",
        "raw-return-secret",
    ):
        assert secret not in rendered
    assert rendered.count("<redacted>") >= 4


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


def test_observer_hook_staging_injects_session_target_and_exact_canary(
    tmp_path: Path,
) -> None:
    template = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"
    destination = tmp_path / "session" / "basic_observer.js"

    digest = stage_observer_hook(
        template,
        destination,
        session_id=SESSION_ID,
        package=PACKAGE,
        canary=CANARY,
        project_root=tmp_path,
    )

    source = destination.read_text(encoding="utf-8")
    assert SESSION_PLACEHOLDER not in source
    assert PACKAGE_PLACEHOLDER not in source
    assert CANARY_PLACEHOLDER not in source
    assert SESSION_ID in source
    assert PACKAGE in source
    assert CANARY in source
    assert "CANARY_PREFIX" not in source
    assert digest == hashlib.sha256(source.encode("utf-8")).hexdigest()


def test_observer_hook_staging_without_canary_disables_matching(tmp_path: Path) -> None:
    template = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"
    destination = tmp_path / "session" / "basic_observer.js"

    stage_observer_hook(
        template,
        destination,
        session_id=SESSION_ID,
        package=PACKAGE,
        project_root=tmp_path,
    )

    source = destination.read_text(encoding="utf-8")
    assert "const OBSERVER_CANARY = '';" in source
    assert "OBSERVER_CANARY.length === 0" in source
    assert "containsExactCanaryText" in source
    assert "CANARY_PREFIX" not in source


def test_observer_hook_has_no_hardcoded_target_and_compiles() -> None:
    hook = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"
    source = hook.read_text(encoding="utf-8")

    assert source.count(SESSION_PLACEHOLDER) == 1
    assert source.count(PACKAGE_PLACEHOLDER) == 1
    assert source.count(CANARY_PLACEHOLDER) == 1
    assert "com.example" not in source
    assert "universal bypass" not in source.casefold()
    compiled = frida.Compiler().build(str(hook), project_root=str(hook.parent.parent))
    assert isinstance(compiled, str)
    assert compiled


def test_observer_hook_uses_conservative_webview_and_sink_correlation() -> None:
    hook = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"
    source = hook.read_text(encoding="utf-8")

    assert "args[0] === 0 ? 'always_allow'" in source
    assert "args[0] === 1 ? 'never_allow'" in source
    assert "webview.javascript_interface_removed" in source
    assert "knownJavaText(value)" in source
    assert "java.lang.String" in source
    assert "System.identityHashCode(value)" in source
    assert ".hashCode()" not in source
    assert "containsCanaryByteRange(args[0], Number(args[1]), Number(args[2]))" in source
    assert "MAX_TRACKED_OBJECTS = 512" in source
    assert "delete fileStreams[objectId(this, 'file-stream')]" in source
    assert "bundleContainsCanary" in source
    assert "sensitive.content_provider_" in source
    assert "sensitive.intent_" in source
    assert "sensitive.notification." in source
    assert "weakRandomOutputs[state.iv_sha256]" in source
    assert "weakRandomOutputs[state.key_sha256]" in source
    assert "instrumentTrustManager" in source
    assert "instrumentHostnameVerifier" in source
    assert "tls.check_server_trusted" in source
    assert "tls.hostname_verify" in source
    assert "instrumentWebViewClient(args[0])" in source
    assert "webview.ssl_error_callback.dynamic" in source
    assert "webViewClientInstrumentedClasses" in source
    assert "package_scoped: packageScoped" in source
    assert "userRoot[0] + TARGET_PACKAGE" in source


def test_observer_bounds_random_fingerprints_and_retries_tls_instrumentation() -> None:
    hook = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"
    source = hook.read_text(encoding="utf-8")

    assert "MAX_RANDOM_FINGERPRINT_BYTES = 65536" in source
    assert "outputLength <= MAX_RANDOM_FINGERPRINT_BYTES" in source
    assert "output_sha256: digest" in source
    assert "fingerprint_status: fingerprintStatus" in source
    assert "'size_limit'" in source

    assert source.count(
        "boundedPut(tlsInstrumentedClasses, instrumentationId, 'installing')"
    ) == 2
    assert source.count(
        "tlsInstrumentedClasses[instrumentationId] = 'installed'"
    ) == 2
    assert source.count("delete tlsInstrumentedClasses[instrumentationId]") == 2
    assert "className !== 'unknown'" in source
    assert "className === 'unknown'" in source
    assert "com.android.okhttp.internal.tls.okhostnameverifier" in source
    assert "com.squareup.okhttp.internal.tls.okhostnameverifier" in source


def test_observer_hook_rejects_non_session_canary(tmp_path: Path) -> None:
    template = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"

    with pytest.raises(ValueError, match="canary"):
        stage_observer_hook(
            template,
            tmp_path / "observer.js",
            session_id=SESSION_ID,
            package=PACKAGE,
            canary="THESIS_CANARY_stale-or-injected",
            project_root=tmp_path,
        )


class FakeProcess:
    returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode


def loading_event(*, pid: int = 4242, package: str = PACKAGE) -> str:
    return json.dumps(
        {
            "timestamp": "2026-07-17T10:00:00+00:00",
            "session_id": SESSION_ID,
            "package": package,
            "pid": pid,
            "thread_id": 1,
            "hook_id": "observer.lifecycle",
            "category": "lifecycle",
            "method": "observer_loading",
            "arguments_redacted": [],
            "return_value_redacted": None,
            "canary_match": False,
            "observer_version": OBSERVER_VERSION,
        }
    )


def test_controller_spawn_loading_gate_returns_attributed_pid(tmp_path: Path) -> None:
    events = tmp_path / "observer.jsonl"
    events.write_text(loading_event(pid=7331), encoding="utf-8")

    assert (
        FridaController._wait_observer_loading(
            FakeProcess(),  # type: ignore[arg-type]
            events,
            session_id=SESSION_ID,
            package=PACKAGE,
            timeout=0.1,
        )
        == 7331
    )


def test_controller_spawn_loading_gate_rejects_timeout_and_early_exit(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.jsonl"
    with pytest.raises(Exception, match="script load"):
        FridaController._wait_observer_loading(
            FakeProcess(),  # type: ignore[arg-type]
            missing,
            session_id=SESSION_ID,
            package=PACKAGE,
            timeout=0,
        )

    exited = SimpleNamespace(poll=lambda: 3, returncode=3)
    with pytest.raises(Exception, match="before the observer script loaded"):
        FridaController._wait_observer_loading(
            exited,  # type: ignore[arg-type]
            missing,
            session_id=SESSION_ID,
            package=PACKAGE,
            timeout=0.1,
        )


def test_controller_spawn_command_pauses_before_resume_and_attach_does_not(
    tmp_path: Path,
) -> None:
    hook = tmp_path / "observer.js"
    events = tmp_path / "events.jsonl"

    spawn = FridaController._observer_command(
        "frida.exe",
        "fixture-device",
        PACKAGE,
        hook,
        events,
        mode="spawn",
    )
    attach = FridaController._observer_command(
        "frida.exe",
        "fixture-device",
        PACKAGE,
        hook,
        events,
        mode="attach",
    )

    assert spawn[spawn.index("-f") + 1] == PACKAGE
    assert "--pause" in spawn
    assert attach[attach.index("-N") + 1] == PACKAGE
    assert "--pause" not in attach


class SpawnPidAdb:
    def __init__(self, output: str, *, timed_out: bool = False) -> None:
        self.output = output
        self.timed_out = timed_out

    def shell(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            stdout=self.output,
            timed_out=self.timed_out,
            exit_code=0,
        )


def test_controller_spawn_pid_must_match_target_package() -> None:
    FridaController._require_spawn_pid(
        SpawnPidAdb("7331 7332"),
        "fixture-device",
        PACKAGE,
        7331,
    )

    with pytest.raises(Exception, match="does not match"):
        FridaController._require_spawn_pid(
            SpawnPidAdb("7332"),
            "fixture-device",
            PACKAGE,
            7331,
        )


def test_controller_spawn_resume_dispatches_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resumed: list[int] = []
    device = SimpleNamespace(resume=lambda pid: resumed.append(pid))
    devices: list[tuple[str, int]] = []

    def get_device(serial: str, *, timeout: int) -> SimpleNamespace:
        devices.append((serial, timeout))
        return device

    monkeypatch.setattr(frida, "get_device", get_device)

    FridaController._resume_spawned_process("fixture-device", 7331)

    assert devices == [("fixture-device", 5)]
    assert resumed == [7331]


def test_controller_failed_spawn_cleanup_force_stops_target_once() -> None:
    calls: list[tuple[str, str]] = []
    adb = SimpleNamespace(
        force_stop_package=lambda serial, package: calls.append((serial, package))
    )

    cleaned = FridaController._cleanup_failed_spawn(
        adb,
        "fixture-device",
        PACKAGE,
    )

    assert cleaned is True
    assert calls == [("fixture-device", PACKAGE)]


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


@pytest.mark.parametrize("architecture", ("arm64", "x86_64"))
def test_frida_server_asset_requires_pinned_output_hash(
    tmp_path: Path,
    architecture: str,
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    server = paths.tools_dir / "frida" / f"frida-server-17.0.0-android-{architecture}"
    server.parent.mkdir(parents=True)
    server.write_bytes(b"fixture-frida-server")
    digest = hashlib.sha256(server.read_bytes()).hexdigest()
    write_json_atomic(
        paths.config_dir / "tools.lock.json",
        {
            "tools": {
                "frida_servers": {
                    "version": "17.0.0",
                    "assets": {
                        architecture: {
                            "output_sha256": digest,
                            "output_minimum_bytes": server.stat().st_size,
                        }
                    },
                }
            }
        },
        root=paths.root,
    )
    context = SimpleNamespace(paths=paths)
    controller = FridaController(context)  # type: ignore[arg-type]

    selected, selected_hash = controller._server_binary("17.0.0", architecture)

    assert selected == server.resolve()
    assert selected_hash == digest

    server.write_bytes(b"tampered-frida-server")
    assert controller._server_binary("17.0.0", architecture) == (None, None)


def test_frida_server_asset_does_not_use_unpinned_generic_fallback(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    generic = paths.tools_dir / "frida" / "frida-server"
    generic.parent.mkdir(parents=True)
    generic.write_bytes(b"unversioned")
    write_json_atomic(
        paths.config_dir / "tools.lock.json",
        {
            "tools": {
                "frida_servers": {
                    "version": "17.0.0",
                    "assets": {
                        "arm64": {
                            "output_sha256": hashlib.sha256(b"unversioned").hexdigest(),
                            "output_minimum_bytes": 1,
                        }
                    },
                }
            }
        },
        root=paths.root,
    )

    controller = FridaController(SimpleNamespace(paths=paths))  # type: ignore[arg-type]

    assert controller._server_binary("17.0.0", "arm64") == (None, None)
