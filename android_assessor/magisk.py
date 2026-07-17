"""Read-only Magisk and Zygisk capability probes."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .adb import AdbClient
from .errors import AdbError
from .root import RootProbe

_ZYGISK_QUERY = "magisk --sqlite \"SELECT value FROM settings WHERE key='zygisk';\""


@dataclass(frozen=True, slots=True)
class MagiskProbe:
    available: bool
    version: str | None = None
    zygisk_enabled: bool | None = None
    error: str | None = None


def probe_magisk(adb: AdbClient, serial: str, root: RootProbe) -> MagiskProbe:
    if not root.available:
        return MagiskProbe(
            available=False,
            error="Root is unavailable, so the Magisk CLI cannot be queried.",
        )
    try:
        version_result = adb.shell(
            serial,
            ("su", "-c", "magisk -v"),
            timeout=10,
            check=False,
            operation="probing Magisk",
        )
    except AdbError as exc:
        return MagiskProbe(available=False, error=str(exc)[:300])
    if version_result.timed_out or version_result.exit_code != 0:
        return MagiskProbe(available=False, error="Magisk CLI was not available through su.")
    version = version_result.stdout.strip().splitlines()[0][:100] or None
    try:
        zygisk_result = adb.shell(
            serial,
            ("su", "-c", _ZYGISK_QUERY),
            timeout=10,
            check=False,
            operation="reading the Magisk Zygisk setting",
        )
    except AdbError:
        return MagiskProbe(available=True, version=version, zygisk_enabled=None)
    zygisk_enabled: bool | None = None
    if not zygisk_result.timed_out and zygisk_result.exit_code == 0:
        match = re.search(r"(?:value\s*=\s*)?([01])\b", zygisk_result.stdout)
        if match:
            zygisk_enabled = match.group(1) == "1"
    return MagiskProbe(
        available=True,
        version=version,
        zygisk_enabled=zygisk_enabled,
    )
