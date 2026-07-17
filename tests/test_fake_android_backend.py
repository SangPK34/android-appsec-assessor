from __future__ import annotations

import json
from pathlib import Path

import pytest

from android_assessor.errors import AdbError, ProxyError
from tests.fakes import FIXTURE_ROOT, FakeAndroidBackend, FaultInjected, load_fixture


def test_every_json_fixture_has_simulated_provenance() -> None:
    fixtures = sorted(FIXTURE_ROOT.rglob("*.json"))
    assert fixtures
    for path in fixtures:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["source"] == "fixture", path
        assert payload["environment"] == "simulated", path


def test_fixture_loader_rejects_path_escape() -> None:
    with pytest.raises(ValueError, match="escapes"):
        load_fixture("../../outside.json")


@pytest.mark.parametrize(
    ("scenario", "expected_state", "device_count"),
    (
        ("disconnected", None, 0),
        ("unauthorized", "unauthorized", 1),
        ("offline", "offline", 1),
        ("non_root_arm64", "device", 1),
        ("rooted_arm64", "device", 1),
        ("rooted_x86_64", "device", 1),
    ),
)
def test_fake_backend_models_device_states(
    scenario: str,
    expected_state: str | None,
    device_count: int,
) -> None:
    state = load_fixture("devices/states.json")["scenarios"][scenario]
    backend = FakeAndroidBackend(
        connected=bool(state["connected"]),
        adb_state=str(state.get("adb_state", "device")),
        abi=str(state.get("abi", "arm64-v8a")),
    )

    devices = backend.list_devices()
    assert len(devices) == device_count
    if devices:
        assert devices[0].state == expected_state


@pytest.mark.parametrize("state", ("unauthorized", "offline"))
def test_fake_backend_rejects_non_authorized_adb(state: str) -> None:
    backend = FakeAndroidBackend(adb_state=state)

    with pytest.raises(AdbError, match=state):
        backend.require_authorized_device(backend.serial)


@pytest.mark.parametrize(
    ("outcome", "exit_code", "timed_out", "marker"),
    (
        ("available", 0, False, "uid=0"),
        ("shell", 0, False, "uid=2000"),
        ("denied", 1, False, "permission denied"),
        ("timeout", -1, True, ""),
        ("missing", 127, False, "not found"),
        ("malformed", 0, False, "unexpected"),
    ),
)
def test_fake_backend_models_root_outcomes(
    outcome: str,
    exit_code: int,
    timed_out: bool,
    marker: str,
) -> None:
    backend = FakeAndroidBackend(root_outcome=outcome)

    result = backend.execute_root(backend.serial, ("id",), timeout=5)

    assert result.exit_code == exit_code
    assert result.timed_out is timed_out
    assert marker in result.stdout + result.stderr


def test_fake_backend_models_package_splits_storage_and_logcat() -> None:
    package_fixture = load_fixture("packages/rooted_lab.json")
    storage_fixture = load_fixture("storage/inventory.json")
    logcat_fixture = load_fixture("logcat/modern.json")
    package = str(package_fixture["package"])
    backend = FakeAndroidBackend(
        packages={package: package_fixture["metadata"]},
        storage_entries=storage_fixture["entries"],
        logcat_lines=logcat_fixture["lines"],
    )

    metadata = backend.inspect_package(backend.serial, package)

    assert metadata["base_apk"].endswith("base.apk")
    assert len(metadata["split_apks"]) == 2
    assert len(backend.list_storage(backend.serial, package)) >= 6
    assert backend.read_logcat(backend.serial)[0].startswith("1784263200")


def test_fake_proxy_snapshot_and_reverse_conflicts_preserve_external_state() -> None:
    fixture = load_fixture("traffic/states.json")
    backend = FakeAndroidBackend(
        proxy=str(fixture["proxy_scenarios"]["preexisting"]),
        reverse_mappings=dict(fixture["reverse_scenarios"]["owned"]),
    )
    assert backend.snapshot_proxy(backend.serial) == "host.lab.local:8888"

    backend.proxy_snapshot_fails = True
    with pytest.raises(ProxyError, match="snapshot"):
        backend.snapshot_proxy(backend.serial)

    backend.proxy_snapshot_fails = False
    backend.reverse_mappings = dict(
        fixture["reverse_scenarios"]["externally_changed"]
    )
    assert backend.remove_reverse(backend.serial, "tcp:8080", "tcp:8080") is False
    assert backend.reverse_mappings["tcp:8080"] == "tcp:9090"


def test_fake_frida_preserves_preexisting_server_and_detects_version_mismatch() -> None:
    fixture = load_fixture("frida/states.json")
    preexisting = fixture["scenarios"]["preexisting"]
    backend = FakeAndroidBackend(
        client_version=str(fixture["client_version"]),
        server_version=str(preexisting["server_version"]),
        server_process=dict(preexisting["process"]),
    )

    state = backend.frida_server_state(backend.serial)
    assert state["compatible"] is True
    assert (
        backend.stop_frida_server(
            backend.serial,
            dict(preexisting["process"]),
            session_id="fixture-session",
        )
        is False
    )
    assert backend.server_process is not None

    mismatch = fixture["scenarios"]["version_mismatch"]
    backend.server_version = str(mismatch["server_version"])
    assert backend.frida_server_state(backend.serial)["compatible"] is False


def test_fake_frida_owned_process_stops_only_with_exact_identity() -> None:
    backend = FakeAndroidBackend(client_version="17.0.0")
    identity = backend.start_frida_server(
        backend.serial,
        executable_path="/data/local/tmp/android-assessor/s/frida-server",
        session_id="fixture-session",
    )
    backend.reuse_pid(executable_path="/system/bin/sleep", start_time="200")

    assert (
        backend.stop_frida_server(
            backend.serial,
            identity,
            session_id="fixture-session",
        )
        is False
    )
    assert backend.server_process is not None


@pytest.mark.parametrize("mutation", ("proxy", "reverse", "push", "frida"))
def test_fake_backend_can_fault_after_each_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    backend = FakeAndroidBackend(fail_after_mutation=1)
    source = tmp_path / "fixture.bin"
    source.write_bytes(b"fixture")

    with pytest.raises(FaultInjected, match="after mutation 1"):
        if mutation == "proxy":
            backend.set_proxy(backend.serial, "127.0.0.1:8080")
        elif mutation == "reverse":
            backend.add_reverse(backend.serial, "tcp:8080", "tcp:8080")
        elif mutation == "push":
            backend.push_managed_file(
                backend.serial,
                source,
                "/data/local/tmp/android-security-lab/fixture.bin",
            )
        else:
            backend.start_frida_server(
                backend.serial,
                executable_path="/data/local/tmp/android-assessor/frida-server",
                session_id="fixture-session",
            )

    assert backend.mutations == 1


def test_production_package_does_not_import_test_fakes() -> None:
    source_root = Path(__file__).resolve().parent.parent / "android_assessor"
    for source in source_root.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "tests.fakes" not in text
        assert "FakeAndroidBackend" not in text
