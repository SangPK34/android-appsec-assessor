"""Reproducible Windows CLI for environment, device, and session operations."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .app_context import AppContext
from .capabilities import CapabilityDetector
from .device import DeviceSelectionStore
from .environment import collect_environment, required_failures, write_environment_report
from .errors import AndroidAssessorError
from .explorer import ExplorerConfig
from .logging_utils import configure_logging
from .models import EnvironmentReport
from .paths import ProjectPaths
from .report import ReportService
from .services.app_inspection_service import AppInspectionResult, AppInspectionService
from .services.cleanup_service import CleanupService
from .services.device_service import DeviceInspection, DeviceService
from .services.scan_service import ScanProfile, ScanResult, ScanService
from .services.scenario_service import ScenarioRequest
from .services.session_service import SessionService
from .services.validation_service import ValidationService
from .session import SessionRepository
from .storage import write_json_atomic

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="android-assessor")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("check", "Inspect the local portable environment."),
        ("self-test", "Check mandatory components and return a failing exit code if needed."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--json", action="store_true", dest="as_json")
        command.add_argument("--output", type=Path)

    devices = commands.add_parser("devices", help="List ADB devices without selecting one.")
    devices.add_argument("--json", action="store_true", dest="as_json")
    devices.add_argument("--show-serial", action="store_true")

    select_device = commands.add_parser(
        "select-device",
        help="Persist an explicit authorized device selection.",
    )
    select_device.add_argument("--serial", required=True)
    select_device.add_argument("--json", action="store_true", dest="as_json")

    inspect_device = commands.add_parser(
        "inspect-device",
        help="Inspect the selected device and detect capabilities without modifying it.",
    )
    inspect_device.add_argument("--serial")
    inspect_device.add_argument("--package")
    inspect_device.add_argument("--json", action="store_true", dest="as_json")
    inspect_device.add_argument("--show-serial", action="store_true")
    inspect_device.add_argument("--output", type=Path)

    inspect_app = commands.add_parser(
        "inspect-app",
        help="Create a session and collect APK/manifest metadata for one installed package.",
    )
    inspect_app.add_argument("--package", required=True)
    inspect_app.add_argument("--serial")
    inspect_app.add_argument("--json", action="store_true", dest="as_json")
    inspect_app.add_argument("--output", type=Path)

    scan = commands.add_parser(
        "scan",
        help="Run a quick or full assessment and generate a report.",
    )
    scan.add_argument("--package")
    scan.add_argument("--serial")
    scan.add_argument("--session", dest="session_id")
    scan.add_argument("--profile", choices=[item.value for item in ScanProfile], default="quick")
    scan.add_argument("--runtime-seconds", type=int, default=None)
    scan.add_argument(
        "--autonomous",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable bounded package-scoped UI exploration for a full assessment.",
    )
    scan.add_argument(
        "--auto",
        action="store_true",
        help=(
            "Run a full bounded assessment without UI prompts; enables autonomous "
            "exploration and scoped controlled-canary activation."
        ),
    )
    scan.add_argument("--max-runtime", type=int, default=None)
    scan.add_argument("--max-actions", type=int, default=100)
    scan.add_argument("--max-states", type=int, default=40)
    scan.add_argument("--plateau-seconds", type=int, default=8)
    scan.add_argument("--seed", type=int, default=1337)
    scan.add_argument(
        "--scenario-profile",
        type=Path,
        help="Tracked generic scenario profile used for deterministic activation.",
    )
    scan.add_argument(
        "--scenario",
        type=Path,
        help="Tracked scenario definition used for deterministic activation.",
    )
    scan.add_argument(
        "--scenario-vars",
        type=Path,
        help="Ignored local YAML overlay containing fixture-owned scenario values.",
    )
    scan.add_argument(
        "--controlled-canary",
        action="store_true",
        help=(
            "Opt in to bounded exact-canary form delivery during an autonomous "
            "Full Assessment; requires controlled_validation in scope."
        ),
    )
    scan.add_argument("--json", action="store_true", dest="as_json")
    scan.add_argument("--output", type=Path)

    report = commands.add_parser("report", help="Regenerate reports for one session.")
    report.add_argument("--session", required=True, dest="session_id")
    report.add_argument("--json", action="store_true", dest="as_json")

    validate = commands.add_parser(
        "validate",
        help="Run a supported controlled validation for one finding.",
    )
    validate.add_argument("--session", required=True, dest="session_id")
    validate.add_argument("--finding", required=True, dest="finding_id")
    validate.add_argument("--json", action="store_true", dest="as_json")

    session = commands.add_parser("session", help="Create, list, or inspect sessions.")
    session_commands = session.add_subparsers(dest="session_command", required=True)
    session_create = session_commands.add_parser(
        "create",
        help="Create a session and capture its initial read-only snapshot.",
    )
    session_create.add_argument("--package", required=True)
    session_create.add_argument("--serial")
    session_create.add_argument("--json", action="store_true", dest="as_json")
    session_create.add_argument("--show-serial", action="store_true")

    session_list = session_commands.add_parser("list", help="List existing sessions.")
    session_list.add_argument("--json", action="store_true", dest="as_json")
    session_list.add_argument("--show-serial", action="store_true")

    session_show = session_commands.add_parser("show", help="Show one session.")
    session_show.add_argument("--session", required=True, dest="session_id")
    session_show.add_argument("--json", action="store_true", dest="as_json")
    session_show.add_argument("--show-serial", action="store_true")

    cleanup = commands.add_parser(
        "cleanup",
        help="Run idempotent cleanup for one session.",
    )
    cleanup.add_argument("--session", required=True, dest="session_id")
    cleanup.add_argument("--json", action="store_true", dest="as_json")

    web = commands.add_parser("web", help="Run the local diagnostics web page.")
    web.add_argument("--host", default=None)
    web.add_argument("--port", type=int, default=None)
    return parser


def _print_report_table(report: EnvironmentReport) -> None:
    print(f"Project: {report.project_root}")
    print(f"Ready:   {'yes' if report.ready else 'no'}")
    print()
    print(f"{'Component':<30} {'Status':<10} {'Version':<24} Path")
    print("-" * 106)
    for component in report.components:
        print(
            f"{component.name:<30} {component.status.value:<10} "
            f"{(component.version or '-')[:23]:<24} {component.path or '-'}"
        )
        if component.error:
            print(f"  error: {component.error}")


def _write_output(payload: Any, output: Path | None, paths: ProjectPaths) -> None:
    if output is None:
        return
    target = output if output.is_absolute() else paths.root / output
    write_json_atomic(target, payload, root=paths.root)


def _run_check(args: argparse.Namespace, context: AppContext, strict: bool) -> int:
    report = collect_environment(context.paths, context.config)
    if args.output:
        target = args.output if args.output.is_absolute() else context.paths.root / args.output
        write_environment_report(report, target, context.paths)
    if args.as_json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        _print_report_table(report)
    failures = list(required_failures(report))
    if strict and failures:
        LOGGER.error("Mandatory components failed: %s", ", ".join(item.name for item in failures))
        return 1
    return 0


def _run_devices(args: argparse.Namespace, context: AppContext) -> int:
    devices = context.adb_client().list_devices()
    active_serial = DeviceSelectionStore(context.paths).read_serial()
    payload = []
    for device in devices:
        item = device.to_dict(show_serial=args.show_serial)
        item["selected"] = device.serial == active_serial
        payload.append(item)
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if not devices:
        print("No ADB devices detected.")
        return 0
    print(f"{'Sel':<4} {'Serial':<24} {'State':<16} {'Model':<24} Transport")
    print("-" * 86)
    for device in devices:
        serial = device.serial if args.show_serial else device.to_dict()["serial"]
        selected = "*" if device.serial == active_serial else ""
        print(
            f"{selected:<4} {serial:<24} {device.state:<16} "
            f"{device.model or '-':<24} {device.transport_id or '-'}"
        )
        if device.state == "unauthorized":
            print("     Unlock Android and accept the USB debugging RSA prompt.")
    return 0


def _run_select_device(args: argparse.Namespace, context: AppContext) -> int:
    device = context.device_selector().select(args.serial)
    payload = device.to_dict(show_serial=False)
    payload["selected"] = True
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Selected device: {payload['serial']} ({device.model or 'unknown model'})")
    return 0


def _device_service(context: AppContext) -> DeviceService:
    adb = context.adb_client()
    selector = context.device_selector(adb)
    detector = CapabilityDetector(adb, context.host_capability_paths())
    return DeviceService(adb, selector, detector)


def _print_device_inspection(inspection: DeviceInspection, *, show_serial: bool) -> None:
    device = inspection.device.to_dict(show_serial=show_serial)
    print(f"Device:         {device['serial']}")
    print(f"Model:          {device['model'] or '-'}")
    print(f"Android:        {device['android_version'] or '-'} (SDK {device['sdk'] or '-'})")
    print(f"Security patch: {device['security_patch'] or '-'}")
    print(f"Build:          {device['build_id'] or '-'}")
    print()
    print(f"{'Capability':<28} {'State':<14} Reason")
    print("-" * 100)
    for capability in inspection.capabilities.capabilities:
        print(f"{capability.name.value:<28} {capability.state.value:<14} {capability.reason}")


def _run_inspect_device(args: argparse.Namespace, context: AppContext) -> int:
    inspection = _device_service(context).inspect(serial=args.serial, package=args.package)
    payload = inspection.to_dict(show_serial=args.show_serial)
    _write_output(payload, args.output, context.paths)
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_device_inspection(inspection, show_serial=args.show_serial)
    return 0


def _print_app_inspection(inspection: AppInspectionResult) -> None:
    print(f"Session:   {inspection.session_id}")
    print(f"Package:   {inspection.package}")
    print(f"Device:    {inspection.serial_masked}")
    print(f"Status:    {inspection.status}")
    print(f"Version:   {inspection.metadata.version_name or '-'}")
    print(f"APK files: {len(inspection.apks)}")
    print(f"Evidence:  {len(inspection.evidence)}")
    print()
    print(f"{'Step':<24} Status")
    print("-" * 40)
    for step, status in inspection.steps.items():
        print(f"{step:<24} {status}")
    for limitation in inspection.limitations:
        print(f"  skipped: {limitation}")
    for error in inspection.errors:
        print(f"  error: {error}")


def _run_inspect_app(args: argparse.Namespace, context: AppContext) -> int:
    inspection = AppInspectionService(context).inspect(
        package=args.package,
        serial=args.serial,
    )
    payload = inspection.to_dict()
    _write_output(payload, args.output, context.paths)
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_app_inspection(inspection)
    return 0


def _print_scan(result: ScanResult) -> None:
    print(f"Session:  {result.session_id}")
    print(f"Report:   results/{result.session_id}/{result.report_path}")
    print(f"Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  {finding.rule_id:<12} {finding.status.value:<13} {finding.title}")
    for limitation in result.limitations:
        print(f"  skipped: {limitation}")


def _run_scan(args: argparse.Namespace, context: AppContext) -> int:
    if bool(args.package) == bool(args.session_id):
        raise AndroidAssessorError("Provide exactly one of --package or --session.")
    service = ScanService(context)
    auto_mode = bool(args.auto)
    if bool(args.scenario_profile) != bool(args.scenario):
        raise AndroidAssessorError(
            "Use --scenario-profile and --scenario together for deterministic activation."
        )
    if auto_mode and (args.scenario_profile is not None or args.scenario is not None):
        raise AndroidAssessorError("--auto cannot be combined with a deterministic scenario.")
    if auto_mode and args.autonomous is False:
        raise AndroidAssessorError("--auto cannot be combined with --no-autonomous.")
    scan_profile = ScanProfile.FULL.value if auto_mode else args.profile
    scenario_request = None
    if args.scenario_profile is not None:
        if scan_profile != ScanProfile.FULL.value:
            raise AndroidAssessorError("Deterministic scenarios require a Full Assessment.")
        if args.autonomous is True:
            raise AndroidAssessorError(
                "Deterministic scenarios and autonomous exploration are mutually exclusive."
            )
        scenario_request = ScenarioRequest(
            profile_path=context.paths.from_config(str(args.scenario_profile))
            or args.scenario_profile,
            scenario_path=context.paths.from_config(str(args.scenario)) or args.scenario,
            variables_path=(
                context.paths.from_config(str(args.scenario_vars))
                if args.scenario_vars is not None
                else None
            ),
        )
    if args.runtime_seconds is not None and args.max_runtime is not None:
        raise AndroidAssessorError("Use only one of --runtime-seconds or --max-runtime.")
    max_runtime = args.max_runtime if args.max_runtime is not None else args.runtime_seconds
    if max_runtime == 0 and (args.autonomous is True or auto_mode):
        raise AndroidAssessorError("--autonomous requires a runtime greater than zero.")
    autonomous = True if auto_mode else (
        False if max_runtime == 0 and args.autonomous is None else args.autonomous
    )
    if scenario_request is not None:
        autonomous = False
    controlled_canary = args.controlled_canary or auto_mode
    if controlled_canary and (
        scan_profile != ScanProfile.FULL.value
        or autonomous is False
        or max_runtime == 0
    ):
        raise AndroidAssessorError(
            "--controlled-canary requires an autonomous Full Assessment."
        )
    explorer_config = None
    if (
        scan_profile == ScanProfile.FULL.value
        and autonomous is not False
        and max_runtime != 0
    ):
        explorer_config = ExplorerConfig(
            max_runtime_seconds=(
                max_runtime
                if max_runtime is not None
                else ScanService.DEFAULT_AUTONOMOUS_RUNTIME_SECONDS
            ),
            max_actions=args.max_actions,
            max_states=args.max_states,
            plateau_seconds=args.plateau_seconds,
            seed=args.seed,
            per_action_timeout_seconds=8 if auto_mode else 3,
            max_observation_retries=2 if auto_mode else 1,
            max_action_failures=4 if auto_mode else 3,
        )
    if args.session_id:
        result = service.scan_session(
            args.session_id,
            profile=scan_profile,
            runtime_seconds=max_runtime,
            autonomous=autonomous,
            explorer_config=explorer_config,
            controlled_canary=controlled_canary,
            ipc_validation=auto_mode,
            micro_scenario=auto_mode,
            scenario_request=scenario_request,
        )
    else:
        result = service.scan(
            package=args.package,
            serial=args.serial,
            profile=scan_profile,
            runtime_seconds=max_runtime,
            autonomous=autonomous,
            explorer_config=explorer_config,
            controlled_canary=controlled_canary,
            ipc_validation=auto_mode,
            micro_scenario=auto_mode,
            scenario_request=scenario_request,
        )
    payload = result.to_dict()
    _write_output(payload, args.output, context.paths)
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_scan(result)
    return 0


def _run_report(args: argparse.Namespace, context: AppContext) -> int:
    payload = ReportService(context.paths).generate(args.session_id)
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Report: results/{args.session_id}/report.html")
    return 0


def _run_validate(args: argparse.Namespace, context: AppContext) -> int:
    finding = ValidationService(context).validate(args.session_id, args.finding_id)
    payload = finding.to_dict()
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        validation = finding.validation
        print(f"Finding:   {finding.finding_id}")
        print(f"Status:    {finding.status.value}")
        print(f"Validation: {validation.status.value if validation else 'none'}")
        if validation:
            print(f"Summary:   {validation.summary}")
    return 0


def _print_session(record: dict[str, Any]) -> None:
    print(f"Session:  {record['session_id']}")
    print(f"Status:   {record['status']}")
    print(f"Device:   {record['serial']}")
    print(f"Package:  {record['package']}")
    print(f"Created:  {record['created_at']}")
    print(f"Cleanup:  {record['cleanup_success']}")


def _run_session(args: argparse.Namespace, context: AppContext) -> int:
    repository = SessionRepository(context.paths)
    if args.session_command == "create":
        record = SessionService(context, repository).create(
            package=args.package,
            serial=args.serial,
        )
        payload = record.to_dict(show_serial=args.show_serial)
        if args.as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            _print_session(payload)
        return 0
    if args.session_command == "list":
        records = [record.to_dict(show_serial=args.show_serial) for record in repository.list()]
        if args.as_json:
            print(json.dumps(records, ensure_ascii=False, indent=2))
        elif not records:
            print("No sessions found.")
        else:
            print(f"{'Session':<24} {'Status':<18} {'Package':<36} Device")
            print("-" * 100)
            for record in records:
                print(
                    f"{record['session_id']:<24} {record['status']:<18} "
                    f"{record['package']:<36} {record['serial']}"
                )
        return 0
    if args.session_command == "show":
        payload = repository.load(args.session_id).to_dict(show_serial=args.show_serial)
        if args.as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            _print_session(payload)
        return 0
    raise AndroidAssessorError(f"Unknown session command: {args.session_command}")


def _run_cleanup(args: argparse.Namespace, context: AppContext) -> int:
    repository = SessionRepository(context.paths)
    result = CleanupService(context, repository).cleanup(args.session_id)
    try:
        ReportService(context.paths, repository).generate(result.session_id)
    except (AndroidAssessorError, OSError, ValueError) as exc:
        LOGGER.warning("Cleanup completed but report refresh failed: %s", exc)
    payload = result.to_dict()
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Session: {result.session_id}")
        print(f"Cleanup: {'success' if result.success else 'failed'}")
        for action in result.actions:
            suffix = f" - {action.error}" if action.error else ""
            print(f"  {action.action_type}: {action.status}{suffix}")
    return 0 if result.success else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = ProjectPaths.discover()
    configure_logging(paths, verbose=args.verbose)
    try:
        context = AppContext.create(paths)
        if args.command == "check":
            return _run_check(args, context, strict=False)
        if args.command == "self-test":
            return _run_check(args, context, strict=True)
        if args.command == "devices":
            return _run_devices(args, context)
        if args.command == "select-device":
            return _run_select_device(args, context)
        if args.command == "inspect-device":
            return _run_inspect_device(args, context)
        if args.command == "inspect-app":
            return _run_inspect_app(args, context)
        if args.command == "scan":
            return _run_scan(args, context)
        if args.command == "report":
            return _run_report(args, context)
        if args.command == "validate":
            return _run_validate(args, context)
        if args.command == "session":
            return _run_session(args, context)
        if args.command == "cleanup":
            return _run_cleanup(args, context)
        if args.command == "web":
            host = args.host or context.config.web.host
            port = args.port or context.config.web.port
            from .webapp import run_web

            return run_web(paths=paths, host=host, port=port)
        parser.error(f"Unknown command: {args.command}")
    except (AndroidAssessorError, OSError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
