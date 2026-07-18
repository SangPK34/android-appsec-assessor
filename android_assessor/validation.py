"""Validation for values that cross process or filesystem boundaries."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from .errors import SessionError

_PACKAGE_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)
_SESSION_PATTERN = re.compile(r"^\d{8}-\d{6}-[a-f0-9]{6}$")
_REVERSE_PATTERN = re.compile(r"^tcp:(\d{1,5})$")
_ANDROID_APK_PATTERN = re.compile(r"^/[A-Za-z0-9._~+/=@:-]+\.apk$")
_COMPONENT_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_$]*)+$"
)
_REMOTE_TEMP_PREFIX = PurePosixPath("/data/local/tmp/android-security-lab")
_SESSION_CANARY_PATTERN = re.compile(
    r"^THESIS_CANARY_\d{8}T\d{6}Z_[a-f0-9]{12}$"
)


def validate_package_name(package: str) -> str:
    value = package.strip()
    if len(value) > 255 or not _PACKAGE_PATTERN.fullmatch(value):
        raise SessionError(f"Invalid Android package name: {package!r}")
    return value


def validate_session_id(session_id: str) -> str:
    value = session_id.strip()
    if not _SESSION_PATTERN.fullmatch(value):
        raise SessionError("Session ID has an invalid format.")
    return value


def generate_session_canary() -> str:
    """Create an opaque marker for one assessment or validation session."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"THESIS_CANARY_{stamp}_{secrets.token_hex(6)}"


def validate_session_canary(canary: str) -> str:
    value = canary.strip()
    if not _SESSION_CANARY_PATTERN.fullmatch(value):
        raise SessionError("Session canary has an invalid format.")
    return value


def static_candidate_key(candidate: Mapping[str, Any]) -> str:
    """Return a stable, non-sensitive identity for one static call-site candidate."""
    identity = {
        key: candidate.get(key)
        for key in (
            "rule_id",
            "source_id",
            "dex_entry",
            "caller_class_descriptor",
            "caller_method_name",
            "caller_prototype",
            "callee_class_descriptor",
            "callee_method_name",
            "callee_prototype",
        )
        if candidate.get(key) is not None
    }
    indicators = candidate.get("indicators")
    if isinstance(indicators, (list, tuple)):
        identity["indicators"] = sorted(str(item) for item in indicators)
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_reverse_endpoint(endpoint: str) -> str:
    match = _REVERSE_PATTERN.fullmatch(endpoint.strip())
    if match is None or not 1 <= int(match.group(1)) <= 65535:
        raise SessionError(f"Unsupported ADB reverse endpoint: {endpoint!r}")
    return endpoint.strip()


def validate_android_apk_path(path: str) -> str:
    value = path.strip()
    parsed = PurePosixPath(value)
    if (
        len(value) > 1024
        or not _ANDROID_APK_PATTERN.fullmatch(value)
        or not parsed.is_absolute()
        or ".." in parsed.parts
    ):
        raise SessionError("Package Manager returned an invalid Android APK path.")
    return parsed.as_posix()


def validate_component_name(component: str) -> str:
    value = component.strip()
    if len(value) > 512 or not _COMPONENT_PATTERN.fullmatch(value):
        raise SessionError(f"Invalid Android component name: {component!r}")
    return value


def validate_managed_remote_path(path: str) -> str:
    value = PurePosixPath(path)
    if not value.is_absolute() or ".." in value.parts:
        raise SessionError("Managed Android path must be absolute and traversal-free.")
    if value == _REMOTE_TEMP_PREFIX or _REMOTE_TEMP_PREFIX not in value.parents:
        raise SessionError(
            "Cleanup may only remove files below /data/local/tmp/android-security-lab/."
        )
    return value.as_posix()
