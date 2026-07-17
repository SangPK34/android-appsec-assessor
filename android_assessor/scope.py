"""Deny-by-default device, package, and API-host scope allowlist."""

from __future__ import annotations

import ipaddress
import re
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
    allow_read_only_outside_scope: bool = False
    source: Path | None = None

    def require_device_package(self, serial: str, package: str) -> None:
        selected = validate_serial(serial)
        target = validate_package_name(package)
        if selected not in self.devices:
            raise ScopeError(
                f"Device {mask_serial(selected)} is outside config/scope.yaml."
            )
        if target not in self.packages:
            raise ScopeError(f"Package {target} is outside config/scope.yaml.")

    def require_url(self, value: str) -> None:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ScopeError("Validation URL is invalid.") from exc
        del port
        scheme = parsed.scheme.casefold()
        host = parsed.hostname.casefold().rstrip(".") if parsed.hostname else ""
        if scheme not in _ALLOWED_URL_SCHEMES:
            raise ScopeError(f"URL scheme {scheme or '<missing>'} is outside scope.")
        if parsed.username or parsed.password or not host:
            raise ScopeError("Validation URL authority is invalid.")
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
    allow_read_only = payload.get("allow_read_only_outside_scope", False)
    if not isinstance(allow_read_only, bool):
        raise ConfigurationError("scope.allow_read_only_outside_scope must be boolean.")
    return ScopeConfig(
        devices=devices,
        packages=packages,
        api_hosts=api_hosts,
        allow_read_only_outside_scope=allow_read_only,
        source=source,
    )
