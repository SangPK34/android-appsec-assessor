"""Small serializable models used by bootstrap and diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ComponentStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    MISSING = "missing"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class ComponentCheck:
    name: str
    status: ComponentStatus
    required: bool
    version: str | None = None
    path: str | None = None
    source: str | None = None
    error: str | None = None
    repair_hint: str | None = None

    @property
    def healthy(self) -> bool:
        return self.status in {ComponentStatus.OK, ComponentStatus.DEGRADED}

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["healthy"] = self.healthy
        return data


@dataclass(frozen=True, slots=True)
class EnvironmentReport:
    schema_version: int
    generated_at: str
    project_root: str
    host: dict[str, Any]
    components: tuple[ComponentCheck, ...] = field(default_factory=tuple)

    @property
    def ready(self) -> bool:
        return all(component.healthy for component in self.components if component.required)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "project_root": self.project_root,
            "ready": self.ready,
            "host": self.host,
            "components": [component.to_dict() for component in self.components],
        }
