"""Project-rooted path handling with no username assumptions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class ProjectPaths:
    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", self.root.expanduser().resolve())

    @classmethod
    def discover(cls) -> ProjectPaths:
        return cls(Path(__file__).resolve().parent.parent)

    @property
    def config_dir(self) -> Path:
        return self.root / "config"

    @property
    def config_file(self) -> Path:
        return self.config_dir / "lab.json"

    @property
    def scope_file(self) -> Path:
        return self.config_dir / "scope.yaml"

    @property
    def runtime_dir(self) -> Path:
        return self.root / "runtime"

    @property
    def state_dir(self) -> Path:
        return self.runtime_dir / "state"

    @property
    def active_device_file(self) -> Path:
        return self.state_dir / "active-device.json"

    @property
    def active_target_file(self) -> Path:
        return self.state_dir / "active-target.json"

    @property
    def device_locks_dir(self) -> Path:
        return self.state_dir / "device-locks"

    @property
    def tools_dir(self) -> Path:
        return self.root / "tools"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def results_dir(self) -> Path:
        return self.root / "results"

    @property
    def app_log(self) -> Path:
        return self.logs_dir / "app.log"

    @property
    def command_log(self) -> Path:
        return self.logs_dir / "commands.jsonl"

    @property
    def environment_report(self) -> Path:
        return self.root / "lab_environment.json"

    def ensure_layout(self) -> None:
        for path in (
            self.config_dir,
            self.runtime_dir,
            self.state_dir,
            self.device_locks_dir,
            self.tools_dir,
            self.logs_dir,
            self.results_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def from_config(self, value: str | None) -> Path | None:
        if value is None or not value.strip():
            return None
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.root / candidate
        return candidate.resolve()

    def require_inside_root(self, path: Path) -> Path:
        resolved = path.expanduser().resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise ConfigurationError(f"Path is outside project root: {resolved}") from exc
        return resolved
