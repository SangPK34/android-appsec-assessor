from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from android_assessor.adb import AdbDevice, ReverseMapping
from android_assessor.environment import BinaryResolution
from android_assessor.errors import AdbError, ProxyError
from android_assessor.host_process import ProcessIdentity
from android_assessor.paths import ProjectPaths
from android_assessor.services.scan_service import ScanService
from android_assessor.session import CleanupActionStatus, SessionRepository
from android_assessor.traffic import TrafficCaptureService


class FakeProcess:
    def __init__(self) -> None:
        self.pid = 4321
        self.running = True
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return None if self.running else self.returncode

    def terminate(self) -> None:
        self.running = False
        self.returncode = 1

    def kill(self) -> None:
        self.terminate()

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.running:
            raise TimeoutError
        return self.returncode or 0


class FakeProcessController:
    def __init__(self, executable: Path, process: FakeProcess) -> None:
        self.identity = ProcessIdentity(
            pid=process.pid,
            executable=str(executable.resolve()),
            creation_filetime=1,
        )
        self.process = process

    def capture(self, pid: int) -> ProcessIdentity | None:
        assert pid == self.process.pid
        return self.identity

    def terminate_owned(self, identity: ProcessIdentity) -> bool:
        assert identity == self.identity
        if not self.process.running:
            return False
        self.process.terminate()
        return True


class FaultAdb:
    def __init__(self, fault: str) -> None:
        self.fault = fault
        self.proxy: str | None = None
        self.mappings: list[ReverseMapping] = []

    def require_authorized_device(self, serial: str) -> AdbDevice:
        return AdbDevice(serial, "device")

    def list_reverse(self, serial: str) -> list[ReverseMapping]:
        del serial
        return list(self.mappings)

    def add_reverse(self, serial: str, remote: str, local: str) -> None:
        del serial
        self.mappings = [ReverseMapping(remote, local)]
        if self.fault == "reverse":
            raise AdbError("fault after reverse mutation")

    def remove_reverse(self, serial: str, remote: str) -> None:
        del serial
        self.mappings = [item for item in self.mappings if item.remote != remote]

    def get_setting(self, serial: str, namespace: str, key: str) -> str | None:
        del serial, namespace, key
        return self.proxy

    def put_setting(self, serial: str, namespace: str, key: str, value: str) -> None:
        del serial, namespace, key
        self.proxy = value
        if self.fault == "proxy":
            raise AdbError("fault after proxy mutation")

    def delete_setting(self, serial: str, namespace: str, key: str) -> None:
        del serial, namespace, key
        self.proxy = None

    def launch_package(self, serial: str, package: str) -> None:
        del serial, package
        if self.fault == "launch":
            raise AdbError("fault after all traffic mutations")


class FakeContext:
    def __init__(self, paths: ProjectPaths, adb: FaultAdb) -> None:
        self.paths = paths
        self.config = SimpleNamespace()
        self.adb = adb

    def adb_client(self, **_kwargs: object) -> FaultAdb:
        return self.adb


def prepared_service(
    tmp_path: Path,
    fault: str,
) -> tuple[TrafficCaptureService, SessionRepository, str, FaultAdb, FakeProcess, Path]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        "devices: [ABC123]\npackages: [com.example.app]\napi_hosts: []\n"
        "allowed_actions: [traffic_capture]\n",
        encoding="utf-8",
    )
    (paths.root / "hooks").mkdir()
    (paths.root / "hooks" / "mitm_capture.py").write_text("# fixed addon\n", encoding="utf-8")
    executable = paths.tools_dir / "mitmproxy" / "mitmdump.exe"
    executable.parent.mkdir(parents=True)
    executable.touch()
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    repository.activate(
        record.session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURED_EMPTY",
            "http_proxy_error": None,
        },
        device={},
        environment={},
    )
    adb = FaultAdb(fault)
    process = FakeProcess()
    controller = FakeProcessController(executable, process)
    service = TrafficCaptureService(
        FakeContext(paths, adb),  # type: ignore[arg-type]
        repository,
        process_controller=controller,  # type: ignore[arg-type]
    )
    return service, repository, record.session_id, adb, process, executable


@pytest.mark.parametrize("fault", ["wait", "reverse", "proxy", "launch"])
def test_traffic_start_rolls_back_each_partial_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    service, repository, session_id, adb, process, executable = prepared_service(
        tmp_path, fault
    )
    monkeypatch.setattr(
        "android_assessor.traffic.resolve_binary",
        lambda *_args, **_kwargs: BinaryResolution(executable, "test"),
    )
    monkeypatch.setattr(
        "android_assessor.traffic.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )
    if fault == "wait":
        monkeypatch.setattr(
            TrafficCaptureService,
            "_wait_ready",
            staticmethod(
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    ProxyError("fault while waiting")
                )
            ),
        )
    else:
        monkeypatch.setattr(
            TrafficCaptureService,
            "_wait_ready",
            staticmethod(lambda *_args, **_kwargs: None),
        )

    with pytest.raises((AdbError, ProxyError)):
        service.start(session_id)

    assert process.running is False
    assert adb.proxy is None
    assert adb.mappings == []
    assert all(
        action.status in {CleanupActionStatus.COMPLETED, CleanupActionStatus.SKIPPED}
        for action in repository.load(session_id).cleanup_actions
    )
    assert repository.load(session_id).pending_cleanup is False


def test_traffic_uses_lazy_upstream_and_exact_host_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _repository, session_id, _adb, process, executable = prepared_service(
        tmp_path,
        "launch",
    )
    service.paths.scope_file.write_text(
        "devices: [ABC123]\n"
        "packages: [com.example.app]\n"
        "api_hosts: [10.0.2.2]\n"
        "allowed_actions: [traffic_capture]\n",
        encoding="utf-8",
    )
    commands: list[list[str]] = []
    monkeypatch.setattr(
        "android_assessor.traffic.resolve_binary",
        lambda *_args, **_kwargs: BinaryResolution(executable, "test"),
    )
    monkeypatch.setattr(
        "android_assessor.traffic.subprocess.Popen",
        lambda command, **_kwargs: commands.append(command) or process,
    )
    monkeypatch.setattr(
        TrafficCaptureService,
        "_wait_ready",
        staticmethod(lambda *_args, **_kwargs: None),
    )

    with pytest.raises(AdbError):
        service.start(session_id)

    assert "connection_strategy=lazy" in commands[0]
    assert "android_assessor_allowed_hosts=10.0.2.2" in commands[0]


@pytest.mark.parametrize("frida_stop_error", [False, True])
def test_scan_stops_started_resources_when_wait_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frida_stop_error: bool,
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    paths.scope_file.write_text(
        "devices: [ABC123]\npackages: [com.example.app]\napi_hosts: []\n"
        "allowed_actions: [inspect, traffic_capture, frida_observe]\n",
        encoding="utf-8",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    repository.activate(
        record.session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURED_EMPTY",
            "http_proxy_error": None,
        },
        device={},
        environment={},
    )
    calls: list[str] = []

    class ScanAdb:
        def force_stop_package(self, serial: str, package: str) -> None:
            del serial, package

    class ScanContext:
        def __init__(self) -> None:
            self.paths = paths

        def adb_client(self, **_kwargs: object) -> ScanAdb:
            return ScanAdb()

    class Traffic:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def start(self, session_id: str, *, launch_app: bool) -> None:
            del session_id, launch_app
            calls.append("traffic_start")

        def stop(self, session_id: str) -> SimpleNamespace:
            del session_id
            calls.append("traffic_stop")
            return SimpleNamespace(status="stopped")

    class Frida:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def start(self, session_id: str, *, spawn: bool) -> None:
            del session_id, spawn
            calls.append("frida_start")

        def stop(self, session_id: str) -> SimpleNamespace:
            del session_id
            calls.append("frida_stop")
            if frida_stop_error:
                raise RuntimeError("synthetic Frida stop failure")
            return SimpleNamespace(status="stopped")

    monkeypatch.setattr("android_assessor.services.scan_service.TrafficCaptureService", Traffic)
    monkeypatch.setattr("android_assessor.services.scan_service.FridaController", Frida)
    monkeypatch.setattr(
        "android_assessor.services.scan_service.time.sleep",
        lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        ScanService(
            ScanContext(),  # type: ignore[arg-type]
            repository,
        ).scan_session(record.session_id)

    assert calls == ["traffic_start", "frida_start", "frida_stop", "traffic_stop"]


def test_traffic_stop_keeps_raw_artifacts_and_creates_redacted_copies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _repository, session_id, _adb, process, executable = prepared_service(
        tmp_path,
        "none",
    )
    monkeypatch.setattr(
        "android_assessor.traffic.resolve_binary",
        lambda *_args, **_kwargs: BinaryResolution(executable, "test"),
    )
    monkeypatch.setattr(
        "android_assessor.traffic.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        TrafficCaptureService,
        "_wait_ready",
        staticmethod(lambda *_args, **_kwargs: None),
    )
    state = service.start(session_id, launch_app=False)
    session_paths = service.repository.paths_for(session_id)
    raw_secret = "custom-traffic-credential"
    (session_paths.root / state.flow_path).write_bytes(b"raw-flow")
    (session_paths.root / state.events_path).write_text(
        f'{{"X-Lab-Credential":"{raw_secret}","sensitive_query_keys":["access_token"]}}\n',
        encoding="utf-8",
    )
    raw_stdout = session_paths.raw_dir / "traffic" / "mitmdump.stdout.log"
    raw_stdout.write_text(
        f"X-Lab-Credential: {raw_secret}\n",
        encoding="utf-8",
    )

    stopped = service.stop(session_id)

    assert stopped.status == "stopped"
    assert raw_secret in raw_stdout.read_text(encoding="utf-8")
    assert raw_secret not in (
        session_paths.redacted_dir / "traffic" / "mitmdump.stdout.log"
    ).read_text(encoding="utf-8")
    assert raw_secret not in (session_paths.root / state.events_path).read_text(
        encoding="utf-8"
    )
    events = json.loads(
        (session_paths.root / state.events_path).read_text(encoding="utf-8")
    )
    assert events["sensitive_query_keys"] == ["access_token"]
    evidence = service.evidence.list(session_id)
    raw = next(item for item in evidence if item["evidence_type"] == "traffic_flow")
    redacted = next(
        item for item in evidence if item["evidence_type"] == "traffic_events"
    )
    assert raw["relative_path"].startswith("raw/") and raw["redacted"] is False
    assert redacted["relative_path"].startswith("redacted/")
    assert redacted["redacted"] is True
