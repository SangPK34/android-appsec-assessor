"""Load the intentionally small project-local JSON configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .paths import ProjectPaths


@dataclass(frozen=True, slots=True)
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 8765

    def validate(self) -> None:
        if self.host != "127.0.0.1":
            raise ConfigurationError("The web server must bind to 127.0.0.1.")
        if not 1024 < self.port <= 65535:
            raise ConfigurationError("Web port must be between 1025 and 65535.")


@dataclass(frozen=True, slots=True)
class LabConfig:
    web: WebConfig = field(default_factory=WebConfig)
    tools: dict[str, str | None] = field(default_factory=dict)


def _expect_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{name} must be a JSON object.")
    return value


def load_config(paths: ProjectPaths | None = None, file_path: Path | None = None) -> LabConfig:
    project_paths = paths or ProjectPaths.discover()
    source = file_path or project_paths.config_file
    if not source.exists():
        config = LabConfig()
        config.web.validate()
        return config

    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Could not load configuration {source}: {exc}") from exc

    root = _expect_mapping(raw, "configuration")
    web_raw = _expect_mapping(root.get("web", {}), "web")
    tools_raw = _expect_mapping(root.get("tools", {}), "tools")
    try:
        web = WebConfig(
            host=str(web_raw.get("host", "127.0.0.1")),
            port=int(web_raw.get("port", 8765)),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("web.port must be an integer.") from exc
    web.validate()

    tools: dict[str, str | None] = {}
    for name, value in tools_raw.items():
        if value is not None and not isinstance(value, str):
            raise ConfigurationError(f"tools.{name} must be a string or null.")
        tools[str(name)] = value
    return LabConfig(web=web, tools=tools)
