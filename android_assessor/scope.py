"""Deny-by-default device, package, and API-host scope allowlist."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .adb import mask_serial, validate_serial
from .errors import ConfigurationError, ScopeError
from .paths import ProjectPaths
from .validation import validate_package_name

_HOST_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_ALLOWED_URL_SCHEMES = {"http", "https"}
_ALLOWED_ACTIONS = {
    "inspect",
    "root_storage_read",
    "frida_observe",
    "traffic_capture",
    "autonomous_exploration",
    "controlled_validation",
}


@dataclass(frozen=True, slots=True)
class ScopeLimits:
    max_validation_requests: int = 10
    command_timeout_seconds: int = 30
    max_evidence_size_mb: int = 50


def _positive_int(value: Any, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ConfigurationError(
            f"scope.limits.{name} must be an integer between 1 and {maximum}."
        )
    return value


def _string_list(value: Any, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"scope.{name} must be a list of strings.")
    return list(value)


def _normalize_host(value: str) -> str:
    host = value.strip().casefold().rstrip(".")
    if not host or "://" in host or "/" in host or "@" in host:
        raise ConfigurationError(f"Invalid scope API host: {value!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        if not _HOST_PATTERN.fullmatch(host):
            raise ConfigurationError(f"Invalid scope API host: {value!r}") from exc
    return host


@dataclass(frozen=True, slots=True)
class ScopeConfig:
    devices: frozenset[str]
    packages: frozenset[str]
    api_hosts: frozenset[str]
    allowed_actions: frozenset[str] = frozenset()
    limits: ScopeLimits = ScopeLimits()
    allow_read_only_outside_scope: bool = False
    source: Path | None = None

    def require_action(self, action: str) -> None:
        if action not in _ALLOWED_ACTIONS:
            raise ScopeError(f"Unsupported scoped action: {action!r}.")
        if action not in self.allowed_actions:
            raise ScopeError(f"Action {action} is not allowed by config/scope.yaml.")

    def require_actions(self, actions: Iterable[str]) -> None:
        for action in actions:
            self.require_action(action)

    def require_device_package(
        self,
        serial: str,
        package: str,
        *,
        action: str | None = None,
    ) -> None:
        selected = validate_serial(serial)
        target = validate_package_name(package)
        if selected not in self.devices:
            raise ScopeError(
                f"Device {mask_serial(selected)} is outside config/scope.yaml."
            )
        if target not in self.packages:
            raise ScopeError(f"Package {target} is outside config/scope.yaml.")
        if action is not None:
            self.require_action(action)

    def require_inspection(self, serial: str, package: str) -> None:
        self.require_action("inspect")
        if self.allow_read_only_outside_scope:
            validate_serial(serial)
            validate_package_name(package)
            return
        self.require_device_package(serial, package)

    def require_url(self, value: str) -> None:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ScopeError("Validation URL is invalid.") from exc
        del port
        scheme = parsed.scheme.casefold()
        if scheme not in _ALLOWED_URL_SCHEMES:
            raise ScopeError(f"URL scheme {scheme or '<missing>'} is outside scope.")
        if parsed.username or parsed.password or not parsed.hostname:
            raise ScopeError("Validation URL authority is invalid.")
        try:
            host = _normalize_host(parsed.hostname)
        except ConfigurationError as exc:
            raise ScopeError("Validation URL host is invalid.") from exc
        if host not in self.api_hosts:
            raise ScopeError(f"API host {host} is outside config/scope.yaml.")


def load_scope(paths: ProjectPaths, file_path: Path | None = None) -> ScopeConfig:
    source = (file_path or paths.scope_file).resolve()
    paths.require_inside_root(source)
    if not source.is_file():
        return ScopeConfig(frozenset(), frozenset(), frozenset(), source=source)
    try:
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Could not load scope config: {exc}") from exc
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ConfigurationError("Scope config must be a YAML mapping.")

    devices = frozenset(
        validate_serial(item)
        for item in _string_list(payload.get("devices"), "devices")
    )
    packages = frozenset(
        validate_package_name(item) for item in _string_list(payload.get("packages"), "packages")
    )
    api_hosts = frozenset(
        _normalize_host(item) for item in _string_list(payload.get("api_hosts"), "api_hosts")
    )
    allowed_actions = frozenset(
        item.strip()
        for item in _string_list(payload.get("allowed_actions"), "allowed_actions")
    )
    invalid_actions = sorted(allowed_actions - _ALLOWED_ACTIONS)
    if invalid_actions:
        raise ConfigurationError(
            "scope.allowed_actions contains unsupported actions: "
            + ", ".join(invalid_actions)
        )
    raw_limits = payload.get("limits", {})
    if raw_limits is None:
        raw_limits = {}
    if not isinstance(raw_limits, dict):
        raise ConfigurationError("scope.limits must be a mapping.")
    unknown_limits = sorted(
        set(raw_limits)
        - {
            "max_validation_requests",
            "command_timeout_seconds",
            "max_evidence_size_mb",
        }
    )
    if unknown_limits:
        raise ConfigurationError(
            "scope.limits contains unsupported keys: " + ", ".join(unknown_limits)
        )
    defaults = ScopeLimits()
    limits = ScopeLimits(
        max_validation_requests=_positive_int(
            raw_limits.get(
                "max_validation_requests", defaults.max_validation_requests
            ),
            "max_validation_requests",
            maximum=1000,
        ),
        command_timeout_seconds=_positive_int(
            raw_limits.get(
                "command_timeout_seconds", defaults.command_timeout_seconds
            ),
            "command_timeout_seconds",
            maximum=300,
        ),
        max_evidence_size_mb=_positive_int(
            raw_limits.get("max_evidence_size_mb", defaults.max_evidence_size_mb),
            "max_evidence_size_mb",
            maximum=1024,
        ),
    )
    allow_read_only = payload.get("allow_read_only_outside_scope", False)
    if not isinstance(allow_read_only, bool):
        raise ConfigurationError("scope.allow_read_only_outside_scope must be boolean.")
    return ScopeConfig(
        devices=devices,
        packages=packages,
        api_hosts=api_hosts,
        allowed_actions=allowed_actions,
        limits=limits,
        allow_read_only_outside_scope=allow_read_only,
        source=source,
    )
