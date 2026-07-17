"""Conservative Android root capability probe."""

from __future__ import annotations

from dataclasses import dataclass

from .adb import AdbClient
from .errors import AdbError
from .redaction import redact_text


@dataclass(frozen=True, slots=True)
class RootProbe:
    available: bool
    identity: str | None = None
    error: str | None = None


def probe_root(adb: AdbClient, serial: str) -> RootProbe:
    try:
        result = adb.shell(
            serial,
            ("su", "-c", "id"),
            timeout=8,
            check=False,
            operation="probing Android root",
        )
    except AdbError as exc:
        return RootProbe(available=False, error=redact_text(str(exc))[:300])
    output = result.stdout.strip()
    if not result.timed_out and result.exit_code == 0 and "uid=0" in output:
        return RootProbe(available=True, identity=output[:300])
    if result.timed_out:
        return RootProbe(available=False, error="Android su probe timed out.")
    detail = redact_text((result.stderr or output).strip())[:300]
    return RootProbe(
        available=False,
        error=detail or "Android su did not return uid=0.",
    )
