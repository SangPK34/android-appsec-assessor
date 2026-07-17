"""UTF-8 structured application logging."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from typing import Any

from .paths import ProjectPaths


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(paths: ProjectPaths | None = None, verbose: bool = False) -> None:
    project_paths = paths or ProjectPaths.discover()
    project_paths.ensure_layout()
    root_logger = logging.getLogger()
    if getattr(root_logger, "_android_lab_configured", False):
        return

    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    file_handler = RotatingFileHandler(
        project_paths.app_log,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(JsonFormatter())
    root_logger.addHandler(file_handler)

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    root_logger.addHandler(console)
    root_logger._android_lab_configured = True
