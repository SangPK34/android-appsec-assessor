"""Dependency wiring for CLI and web services."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .adb import AdbClient
from .capabilities import CapabilityName
from .config import LabConfig, load_config
from .device import DeviceSelectionStore, DeviceSelector
from .environment import find_tool_spec, resolve_binary
from .errors import AdbError
from .paths import ProjectPaths


@dataclass(frozen=True, slots=True)
class AppContext:
    paths: ProjectPaths
    config: LabConfig

    @classmethod
    def create(cls, paths: ProjectPaths | None = None) -> AppContext:
        project_paths = paths or ProjectPaths.discover()
        project_paths.ensure_layout()
        return cls(paths=project_paths, config=load_config(project_paths))

    def adb_client(self, *, command_log: Path | None = None) -> AdbClient:
        resolution = resolve_binary(find_tool_spec("adb"), self.paths, self.config)
        if resolution is None:
            raise AdbError("ADB not found. Run repair.cmd.")
        return AdbClient(resolution.path, command_log=command_log)

    def device_selector(self, adb: AdbClient | None = None) -> DeviceSelector:
        client = adb or self.adb_client()
        return DeviceSelector(client, DeviceSelectionStore(self.paths))

    def host_capability_paths(self) -> dict[CapabilityName, str | None]:
        mapping = {
            CapabilityName.FRIDA_CLIENT: "frida-client",
            CapabilityName.SCRCPY_AVAILABLE: "scrcpy",
            CapabilityName.AAPT2_AVAILABLE: "aapt2",
            CapabilityName.MITMPROXY_AVAILABLE: "mitmproxy",
        }
        result: dict[CapabilityName, str | None] = {}
        for capability, tool_name in mapping.items():
            resolution = resolve_binary(find_tool_spec(tool_name), self.paths, self.config)
            result[capability] = str(resolution.path) if resolution is not None else None
        return result
