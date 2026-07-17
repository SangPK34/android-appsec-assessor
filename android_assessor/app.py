"""Lightweight user-app inventory and explicit package selection."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from .adb import AdbClient, mask_serial, validate_serial
from .device import DeviceSelector
from .errors import AndroidAssessorError, SessionError
from .paths import ProjectPaths
from .storage import read_json_object, write_json_atomic
from .validation import validate_package_name


@dataclass(frozen=True, slots=True)
class AppSummary:
    package: str
    uid: int | None = None
    apk_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_user_packages(output: str) -> list[AppSummary]:
    applications: list[AppSummary] = []
    for raw_line in output.replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line.startswith("package:"):
            continue
        value = line.removeprefix("package:")
        uid: int | None = None
        if " uid:" in value:
            value, raw_uid = value.rsplit(" uid:", 1)
            try:
                uid = int(raw_uid.strip())
            except ValueError:
                uid = None
        apk_path: str | None = None
        package = value
        if "=" in value:
            apk_path, package = value.rsplit("=", 1)
        try:
            package = validate_package_name(package.strip())
        except SessionError:
            continue
        applications.append(
            AppSummary(
                package=package,
                uid=uid,
                apk_path=apk_path.strip() if apk_path else None,
            )
        )
    return sorted(applications, key=lambda app: app.package.casefold())


class ApplicationSelectionStore:
    def __init__(self, paths: ProjectPaths) -> None:
        self.paths = paths

    def save(self, *, serial: str, package: str) -> None:
        selected_serial = validate_serial(serial)
        target = validate_package_name(package)
        write_json_atomic(
            self.paths.active_target_file,
            {
                "schema_version": 1,
                "serial": selected_serial,
                "serial_masked": mask_serial(selected_serial),
                "package": target,
                "selected_at": datetime.now(UTC).isoformat(),
            },
            root=self.paths.root,
        )

    def read(self, *, serial: str) -> str | None:
        selected_serial = validate_serial(serial)
        if not self.paths.active_target_file.is_file():
            return None
        try:
            payload = read_json_object(self.paths.active_target_file, root=self.paths.root)
            if payload.get("serial") != selected_serial:
                return None
            package = payload.get("package")
            if not isinstance(package, str):
                raise AndroidAssessorError("Active-target state has no package.")
            return validate_package_name(package)
        except SessionError as exc:
            raise AndroidAssessorError(f"Could not read active-target state: {exc}") from exc

    def clear(self) -> None:
        self.paths.active_target_file.unlink(missing_ok=True)


class ApplicationService:
    def __init__(
        self,
        adb: AdbClient,
        selector: DeviceSelector,
        store: ApplicationSelectionStore,
    ) -> None:
        self.adb = adb
        self.selector = selector
        self.store = store

    def list_user_apps(
        self,
        *,
        serial: str | None = None,
        query: str = "",
    ) -> tuple[str, list[AppSummary]]:
        if len(query) > 100 or any(character in query for character in "\r\n\x00"):
            raise AndroidAssessorError("Application search query is invalid.")
        selected = self.selector.resolve(serial)
        result = self.adb.shell(
            selected.serial,
            ("pm", "list", "packages", "-3", "-f", "-U"),
            timeout=45,
            check=True,
            operation="listing user applications",
        )
        applications = parse_user_packages(result.stdout)
        needle = query.strip().casefold()
        if needle:
            applications = [app for app in applications if needle in app.package.casefold()]
        return selected.serial, applications

    def select(self, package: str, *, serial: str | None = None) -> AppSummary:
        target = validate_package_name(package)
        selected_serial, applications = self.list_user_apps(serial=serial)
        selected = next((app for app in applications if app.package == target), None)
        if selected is None:
            raise AndroidAssessorError(f"User application is not installed: {target}")
        self.store.save(serial=selected_serial, package=target)
        return selected
