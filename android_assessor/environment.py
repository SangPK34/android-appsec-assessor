"""Host dependency discovery and self-test reporting."""

from __future__ import annotations

import ctypes
import hashlib
import importlib.metadata
import json
import platform
import shutil
import struct
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .config import LabConfig, load_config
from .models import ComponentCheck, ComponentStatus, EnvironmentReport
from .paths import ProjectPaths
from .redaction import redact_text
from .subprocess_utils import run_command


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    config_key: str
    executable_name: str
    portable_paths: tuple[str, ...]
    version_arguments: tuple[str, ...]
    required: bool = False


@dataclass(frozen=True, slots=True)
class BinaryResolution:
    path: Path
    source: str


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="adb",
        config_key="adb",
        executable_name="adb.exe",
        portable_paths=("tools/platform-tools/adb.exe",),
        version_arguments=("version",),
        required=True,
    ),
    ToolSpec(
        name="fastboot",
        config_key="fastboot",
        executable_name="fastboot.exe",
        portable_paths=("tools/platform-tools/fastboot.exe",),
        version_arguments=("--version",),
    ),
    ToolSpec(
        name="scrcpy",
        config_key="scrcpy",
        executable_name="scrcpy.exe",
        portable_paths=("tools/scrcpy/scrcpy.exe",),
        version_arguments=("--version",),
        required=True,
    ),
    ToolSpec(
        name="aapt2",
        config_key="aapt2",
        executable_name="aapt2.exe",
        portable_paths=("tools/build-tools/aapt2.exe",),
        version_arguments=("version",),
    ),
    ToolSpec(
        name="java",
        config_key="java",
        executable_name="java.exe",
        portable_paths=("tools/java/bin/java.exe",),
        version_arguments=("-version",),
    ),
    ToolSpec(
        name="frida-client",
        config_key="frida",
        executable_name="frida.exe",
        portable_paths=(
            "tools/frida/frida.exe",
            "runtime/venv/Scripts/frida.exe",
            "runtime/python/Scripts/frida.exe",
        ),
        version_arguments=("--version",),
    ),
    ToolSpec(
        name="mitmproxy",
        config_key="mitmdump",
        executable_name="mitmdump.exe",
        portable_paths=(
            "tools/mitmproxy/mitmdump.exe",
            "runtime/venv/Scripts/mitmdump.exe",
            "runtime/python/Scripts/mitmdump.exe",
        ),
        version_arguments=("--version",),
    ),
)

_PACKAGE_COMPONENTS: tuple[tuple[str, bool], ...] = (
    ("fastapi", True),
    ("uvicorn", True),
    ("jinja2", True),
    ("pydantic", True),
    ("httpx", True),
    ("python-multipart", True),
    ("PyYAML", True),
    ("frida-tools", False),
    ("mitmproxy", False),
)

_ANDROID_FRIDA_ARCHITECTURES = ("arm", "arm64", "x86", "x86_64")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_binary(
    spec: ToolSpec,
    paths: ProjectPaths,
    config: LabConfig,
    *,
    user_path: str | None = None,
) -> BinaryResolution | None:
    candidates: list[tuple[Path, str]] = []
    configured = paths.from_config(config.tools.get(spec.config_key))
    if configured is not None:
        candidates.append((configured, "configured"))
    candidates.extend((paths.root / relative, "portable") for relative in spec.portable_paths)

    discovered = shutil.which(spec.executable_name, path=user_path)
    if discovered:
        candidates.append((Path(discovered), "user_path"))

    seen: set[str] = set()
    for candidate, source in candidates:
        normalized = str(candidate.resolve()).casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        if candidate.is_file():
            return BinaryResolution(candidate.resolve(), source)
    return None


def find_tool_spec(name: str) -> ToolSpec:
    for spec in TOOL_SPECS:
        if spec.name == name:
            return spec
    raise KeyError(name)


def _first_version_line(stdout: str, stderr: str) -> str | None:
    for line in (*stdout.splitlines(), *stderr.splitlines()):
        if line.strip():
            return redact_text(line.strip())[:300]
    return None


def _check_tool(spec: ToolSpec, paths: ProjectPaths, config: LabConfig) -> ComponentCheck:
    resolution = resolve_binary(spec, paths, config)
    if resolution is None:
        return ComponentCheck(
            name=spec.name,
            status=ComponentStatus.MISSING,
            required=spec.required,
            error="Executable not found in config, portable tools, or user PATH.",
            repair_hint="Run repair.cmd.",
        )
    try:
        result = run_command(
            [resolution.path, *spec.version_arguments],
            timeout=15,
            check=False,
        )
    except Exception as exc:  # diagnostics must report failures instead of crashing
        return ComponentCheck(
            name=spec.name,
            status=ComponentStatus.ERROR,
            required=spec.required,
            path=str(resolution.path),
            source=resolution.source,
            error=redact_text(str(exc)),
            repair_hint="Run repair.cmd.",
        )
    if result.timed_out or result.exit_code != 0:
        detail = _first_version_line(result.stderr, result.stdout) or "Version probe failed."
        return ComponentCheck(
            name=spec.name,
            status=ComponentStatus.ERROR,
            required=spec.required,
            path=str(resolution.path),
            source=resolution.source,
            error=detail,
            repair_hint="Run repair.cmd.",
        )
    return ComponentCheck(
        name=spec.name,
        status=ComponentStatus.OK,
        required=spec.required,
        version=_first_version_line(result.stdout, result.stderr),
        path=str(resolution.path),
        source=resolution.source,
    )


def _check_python() -> ComponentCheck:
    compatible = sys.version_info[:2] == (3, 12) and struct.calcsize("P") * 8 == 64
    return ComponentCheck(
        name="python",
        status=ComponentStatus.OK if compatible else ComponentStatus.ERROR,
        required=True,
        version=platform.python_version(),
        path=sys.executable,
        source="project_runtime",
        error=None if compatible else "Expected CPython 3.12 x64 local runtime.",
        repair_hint=None if compatible else "Run repair.cmd.",
    )


def _check_package(distribution: str, required: bool) -> ComponentCheck:
    try:
        version = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return ComponentCheck(
            name=f"python:{distribution}",
            status=ComponentStatus.MISSING,
            required=required,
            error="Python distribution is not installed in the local runtime.",
            repair_hint="Run repair.cmd.",
        )
    return ComponentCheck(
        name=f"python:{distribution}",
        status=ComponentStatus.OK,
        required=required,
        version=version,
        path=sys.executable,
        source="project_runtime",
    )


def _check_python_dependencies() -> ComponentCheck:
    try:
        result = run_command(
            [sys.executable, "-m", "pip", "check"],
            timeout=60,
            check=False,
        )
    except Exception as exc:  # diagnostics must report failures instead of crashing
        return ComponentCheck(
            name="python:dependency-consistency",
            status=ComponentStatus.ERROR,
            required=True,
            path=sys.executable,
            source="project_runtime",
            error=redact_text(str(exc)),
            repair_hint="Run repair.cmd.",
        )
    if result.timed_out or result.exit_code != 0:
        detail = _first_version_line(result.stderr, result.stdout)
        return ComponentCheck(
            name="python:dependency-consistency",
            status=ComponentStatus.ERROR,
            required=True,
            path=sys.executable,
            source="project_runtime",
            error=detail or "pip check reported inconsistent dependencies.",
            repair_hint="Run repair.cmd.",
        )
    return ComponentCheck(
        name="python:dependency-consistency",
        status=ComponentStatus.OK,
        required=True,
        version="consistent",
        path=sys.executable,
        source="project_runtime",
    )


def _check_htmx(paths: ProjectPaths) -> ComponentCheck:
    asset = paths.root / "web" / "static" / "htmx.min.js"
    manifest_path = paths.config_dir / "tools.lock.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest["tools"]["htmx"]
        expected_hash = str(expected["sha256"]).lower()
        version = str(expected["version"])
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return ComponentCheck(
            name="web:htmx",
            status=ComponentStatus.ERROR,
            required=True,
            error=f"Could not read the pinned HTMX manifest: {exc}",
            repair_hint="Run repair.cmd.",
        )
    if not asset.is_file():
        return ComponentCheck(
            name="web:htmx",
            status=ComponentStatus.MISSING,
            required=True,
            version=version,
            path=str(asset),
            source="portable",
            error="Pinned HTMX asset is missing.",
            repair_hint="Run repair.cmd.",
        )
    try:
        actual_hash = _sha256_file(asset)
    except OSError as exc:
        return ComponentCheck(
            name="web:htmx",
            status=ComponentStatus.ERROR,
            required=True,
            version=version,
            path=str(asset),
            source="portable",
            error=f"Could not hash HTMX: {exc}",
            repair_hint="Run repair.cmd.",
        )
    if actual_hash != expected_hash:
        return ComponentCheck(
            name="web:htmx",
            status=ComponentStatus.ERROR,
            required=True,
            version=version,
            path=str(asset),
            source="portable",
            error="HTMX SHA-256 does not match the pinned manifest.",
            repair_hint="Run repair.cmd.",
        )
    return ComponentCheck(
        name="web:htmx",
        status=ComponentStatus.OK,
        required=True,
        version=version,
        path=str(asset),
        source="portable",
    )


def _check_frida_server_assets(paths: ProjectPaths) -> list[ComponentCheck]:
    manifest_path = paths.config_dir / "tools.lock.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        definition = manifest["tools"]["frida_servers"]
        version = str(definition["version"])
        assets = definition["assets"]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return [
            ComponentCheck(
                name="frida-server-assets",
                status=ComponentStatus.ERROR,
                required=False,
                error=f"Pinned Frida Server manifest is invalid: {exc}",
                repair_hint="Restore config/tools.lock.json and run repair.cmd.",
            )
        ]
    checks: list[ComponentCheck] = []
    for architecture in _ANDROID_FRIDA_ARCHITECTURES:
        path = paths.tools_dir / "frida" / (
            f"frida-server-{version}-android-{architecture}"
        )
        try:
            expected = assets[architecture]
            expected_hash = str(expected["output_sha256"]).casefold()
            minimum_bytes = int(expected["output_minimum_bytes"])
        except (KeyError, TypeError, ValueError) as exc:
            checks.append(
                ComponentCheck(
                    name=f"frida-server:{architecture}",
                    status=ComponentStatus.ERROR,
                    required=False,
                    version=version,
                    path=str(path),
                    source="portable",
                    error=f"Pinned asset metadata is invalid: {exc}",
                    repair_hint="Restore config/tools.lock.json and run repair.cmd.",
                )
            )
            continue
        if not path.is_file():
            checks.append(
                ComponentCheck(
                    name=f"frida-server:{architecture}",
                    status=ComponentStatus.MISSING,
                    required=False,
                    version=version,
                    path=str(path),
                    source="portable",
                    error="Matching Android Frida Server asset is missing.",
                    repair_hint="Run repair.cmd.",
                )
            )
            continue
        try:
            healthy = path.stat().st_size >= minimum_bytes and _sha256_file(path) == expected_hash
        except OSError as exc:
            checks.append(
                ComponentCheck(
                    name=f"frida-server:{architecture}",
                    status=ComponentStatus.ERROR,
                    required=False,
                    version=version,
                    path=str(path),
                    source="portable",
                    error=f"Could not verify Frida Server asset: {exc}",
                    repair_hint="Run repair.cmd.",
                )
            )
            continue
        checks.append(
            ComponentCheck(
                name=f"frida-server:{architecture}",
                status=ComponentStatus.OK if healthy else ComponentStatus.ERROR,
                required=False,
                version=version,
                path=str(path),
                source="portable",
                error=(
                    None
                    if healthy
                    else "Frida Server SHA-256 does not match the pinned manifest."
                ),
                repair_hint=None if healthy else "Run repair.cmd.",
            )
        )
    return checks


def _check_apksigner(
    paths: ProjectPaths,
    java_check: ComponentCheck,
) -> ComponentCheck:
    jar = paths.tools_dir / "build-tools" / "lib" / "apksigner.jar"
    if not jar.is_file():
        return ComponentCheck(
            name="apksigner",
            status=ComponentStatus.MISSING,
            required=False,
            error="apksigner.jar is missing.",
            repair_hint="Run repair.cmd.",
        )
    if java_check.status is not ComponentStatus.OK or not java_check.path:
        return ComponentCheck(
            name="apksigner",
            status=ComponentStatus.DEGRADED,
            required=False,
            path=str(jar),
            source="portable",
            error="apksigner.jar is present but no Java runtime is available.",
            repair_hint="Configure Java or install a user-scoped JRE to enable apksigner.",
        )
    result = run_command([java_check.path, "-jar", jar, "--version"], timeout=20)
    if result.exit_code != 0 or result.timed_out:
        return ComponentCheck(
            name="apksigner",
            status=ComponentStatus.ERROR,
            required=False,
            path=str(jar),
            source="portable",
            error=_first_version_line(result.stderr, result.stdout) or "apksigner probe failed.",
            repair_hint="Run repair.cmd.",
        )
    return ComponentCheck(
        name="apksigner",
        status=ComponentStatus.OK,
        required=False,
        version=_first_version_line(result.stdout, result.stderr),
        path=str(jar),
        source="portable",
    )


def _is_windows_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def collect_environment(
    paths: ProjectPaths | None = None,
    config: LabConfig | None = None,
) -> EnvironmentReport:
    project_paths = paths or ProjectPaths.discover()
    project_paths.ensure_layout()
    lab_config = config or load_config(project_paths)

    tool_checks = [_check_tool(spec, project_paths, lab_config) for spec in TOOL_SPECS]
    java_check = next(check for check in tool_checks if check.name == "java")
    components: list[ComponentCheck] = [_check_python()]
    components.extend(_check_package(name, required) for name, required in _PACKAGE_COMPONENTS)
    components.append(_check_python_dependencies())
    components.append(_check_htmx(project_paths))
    components.extend(tool_checks)
    components.extend(_check_frida_server_assets(project_paths))
    components.append(_check_apksigner(project_paths, java_check))

    host = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "is_64_bit_os": platform.machine().endswith("64"),
        "windows_admin": _is_windows_admin(),
        "daily_admin_required": False,
        "device_model_specific": False,
        "android_root_optional": True,
        "supported_frida_architectures": list(_ANDROID_FRIDA_ARCHITECTURES),
    }
    return EnvironmentReport(
        schema_version=1,
        generated_at=datetime.now(UTC).isoformat(),
        project_root=str(project_paths.root),
        host=host,
        components=tuple(components),
    )


def write_environment_report(
    report: EnvironmentReport,
    output: Path,
    paths: ProjectPaths | None = None,
) -> None:
    project_paths = paths or ProjectPaths.discover()
    target = project_paths.require_inside_root(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".part")
    temporary.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(target)


def required_failures(report: EnvironmentReport) -> Iterable[ComponentCheck]:
    return (
        component for component in report.components if component.required and not component.healthy
    )
