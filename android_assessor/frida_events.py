"""Normalized Frida observer event schema, parser, and staging helpers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .errors import AndroidAssessorError
from .redaction import REDACTED, is_sensitive_name, redact_data, redact_text
from .storage import write_text_atomic
from .validation import validate_package_name

OBSERVER_VERSION = "0.5.1"
SESSION_PLACEHOLDER = "__ANDROID_ASSESSOR_SESSION_ID__"
PACKAGE_PLACEHOLDER = "__ANDROID_ASSESSOR_PACKAGE__"
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_METADATA = re.compile(r"^[A-Za-z0-9._:/+-]{1,128}$")
_LIFECYCLE_METHODS = {
    "observer_loading",
    "observer_started",
    "hook_installed",
    "hook_error",
    "observer_stopped",
}


class FridaHandshakeStatus(StrEnum):
    VALID = "VALID"
    MISSING = "MISSING"
    INVALID = "INVALID"


class FridaVersionCompatibility(StrEnum):
    COMPATIBLE = "COMPATIBLE"
    CLIENT_MISSING = "CLIENT_MISSING"
    SERVER_MISSING = "SERVER_MISSING"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    INVALID_VERSION = "INVALID_VERSION"


@dataclass(frozen=True, slots=True)
class FridaVersionState:
    client_version: str | None
    server_version: str | None
    compatibility: FridaVersionCompatibility

    @classmethod
    def evaluate(
        cls,
        client_version: str | None,
        server_version: str | None,
    ) -> FridaVersionState:
        if client_version is None:
            status = FridaVersionCompatibility.CLIENT_MISSING
        elif server_version is None:
            status = FridaVersionCompatibility.SERVER_MISSING
        elif not _VERSION.fullmatch(client_version) or not _VERSION.fullmatch(server_version):
            status = FridaVersionCompatibility.INVALID_VERSION
        elif client_version != server_version:
            status = FridaVersionCompatibility.VERSION_MISMATCH
        else:
            status = FridaVersionCompatibility.COMPATIBLE
        return cls(client_version, server_version, status)

    def to_dict(self) -> dict[str, str | None]:
        return {
            "client_version": self.client_version,
            "server_version": self.server_version,
            "compatibility": self.compatibility.value,
        }


@dataclass(frozen=True, slots=True)
class FridaObserverEvent:
    timestamp: str
    session_id: str
    package: str
    pid: int
    thread_id: int
    hook_id: str
    category: str
    method: str
    arguments_redacted: tuple[Any, ...]
    return_value_redacted: Any
    canary_match: bool
    observer_version: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["arguments_redacted"] = list(self.arguments_redacted)
        return payload


@dataclass(frozen=True, slots=True)
class FridaEventParseResult:
    events: tuple[FridaObserverEvent, ...]
    errors: tuple[str, ...]
    handshake_status: FridaHandshakeStatus
    runtime_event_count: int
    observer_stopped: bool
    source: str
    environment: str
    physical_validation_status: str

    def to_jsonl(self) -> str:
        return "".join(
            json.dumps(event.to_dict(), ensure_ascii=False) + "\n"
            for event in self.events
        )


def _timestamp(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value


def _safe_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"{name} is invalid")
    return value


def _parse_event(payload: dict[str, Any]) -> FridaObserverEvent:
    package = validate_package_name(str(payload.get("package", "")))
    pid = payload.get("pid")
    thread_id = payload.get("thread_id")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("pid must be a positive integer")
    if isinstance(thread_id, bool) or not isinstance(thread_id, int) or thread_id < 0:
        raise ValueError("thread_id must be a non-negative integer")
    arguments = payload.get("arguments_redacted")
    if not isinstance(arguments, list):
        raise ValueError("arguments_redacted must be a list")
    canary = payload.get("canary_match")
    if not isinstance(canary, bool):
        raise ValueError("canary_match must be boolean")
    observer_version = str(payload.get("observer_version", ""))
    if not _VERSION.fullmatch(observer_version):
        raise ValueError("observer_version is invalid")
    return FridaObserverEvent(
        timestamp=_timestamp(payload.get("timestamp")),
        session_id=_safe_id(payload.get("session_id"), "session_id"),
        package=package,
        pid=pid,
        thread_id=thread_id,
        hook_id=_safe_id(payload.get("hook_id"), "hook_id"),
        category=_safe_id(payload.get("category"), "category"),
        method=_safe_id(payload.get("method"), "method"),
        arguments_redacted=tuple(_redact_observer_value(arguments)),
        return_value_redacted=_redact_observer_value(
            payload.get("return_value_redacted")
        ),
        canary_match=canary,
        observer_version=observer_version,
    )


def _redact_observer_value(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, list):
        return [_redact_observer_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(name): _redact_observer_value(item, key=str(name))
            for name, item in value.items()
        }
    if key in {
        "key_sha256",
        "iv_sha256",
        "input_sha256",
        "output_sha256",
        "indicator_hash",
    }:
        return value if isinstance(value, str) and _SHA256.fullmatch(value) else "<redacted>"
    if key in {
        "algorithm",
        "transformation",
        "mode",
        "padding",
        "purpose",
        "iv_source",
        "key_origin",
        "operation_id",
        "check_id",
        "indicator_type",
        "response",
        "type",
        "value",
    }:
        return (
            value
            if isinstance(value, str) and _SAFE_METADATA.fullmatch(value)
            else "<redacted>"
        )
    if key in {"length", "key_length_bits"}:
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    if key in {"executed", "canary_match", "detected", "bypass_instrumented"}:
        if value is None and key == "detected":
            return None
        return value if isinstance(value, bool) else False
    if key is not None and is_sensitive_name(key):
        return REDACTED
    return redact_data(value)


def parse_frida_jsonl(
    value: str,
    *,
    expected_session_id: str,
    expected_package: str,
    source: str,
    environment: str,
) -> FridaEventParseResult:
    session_id = _safe_id(expected_session_id, "expected_session_id")
    package = validate_package_name(expected_package)
    if (source == "fixture") != (environment == "simulated"):
        raise ValueError("Fixture Frida events must use simulated provenance.")
    events: list[FridaObserverEvent] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate(value.splitlines(), start=1):
        if not raw_line.strip():
            continue
        if len(raw_line) > 1_048_576:
            errors.append(f"line {line_number}: event exceeds 1 MiB")
            continue
        start = raw_line.find("{")
        if start < 0:
            errors.append(f"line {line_number}: JSON object missing")
            continue
        try:
            payload = json.loads(raw_line[start:])
            if not isinstance(payload, dict):
                raise ValueError("event must be an object")
            nested = payload.get("payload")
            if "timestamp" not in payload and isinstance(nested, str):
                payload = json.loads(nested)
            elif "timestamp" not in payload and isinstance(nested, dict):
                payload = nested
            if not isinstance(payload, dict):
                raise ValueError("nested event must be an object")
            event = _parse_event(payload)
            if event.session_id != session_id:
                raise ValueError("session attribution mismatch")
            if event.package != package:
                raise ValueError("package attribution mismatch")
        except (AndroidAssessorError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"line {line_number}: {redact_text(str(exc))[:200]}")
            continue
        events.append(event)
    handshake_events = [
        item
        for item in events
        if item.category == "lifecycle" and item.method == "observer_started"
    ]
    handshake = (
        FridaHandshakeStatus.VALID
        if len(handshake_events) == 1
        else FridaHandshakeStatus.MISSING
        if not handshake_events
        else FridaHandshakeStatus.INVALID
    )
    lifecycle_count = sum(
        item.category == "lifecycle" and item.method in _LIFECYCLE_METHODS
        for item in events
    )
    stopped = any(
        item.category == "lifecycle" and item.method == "observer_stopped"
        for item in events
    )
    return FridaEventParseResult(
        events=tuple(events),
        errors=tuple(errors),
        handshake_status=handshake,
        runtime_event_count=len(events) - lifecycle_count,
        observer_stopped=stopped,
        source=source,
        environment=environment,
        physical_validation_status=(
            "UNVERIFIED" if environment == "simulated" else "UNVERIFIED"
        ),
    )


def stage_observer_hook(
    template_path: Path,
    destination: Path,
    *,
    session_id: str,
    package: str,
    project_root: Path,
) -> str:
    selected_session = _safe_id(session_id, "session_id")
    selected_package = validate_package_name(package)
    source = template_path.read_text(encoding="utf-8")
    if source.count(SESSION_PLACEHOLDER) != 1 or source.count(PACKAGE_PLACEHOLDER) != 1:
        raise ValueError("Observer hook placeholders are missing or duplicated.")
    staged = source.replace(SESSION_PLACEHOLDER, selected_session).replace(
        PACKAGE_PLACEHOLDER,
        selected_package,
    )
    write_text_atomic(destination, staged, root=project_root)
    return hashlib.sha256(staged.encode("utf-8")).hexdigest()
