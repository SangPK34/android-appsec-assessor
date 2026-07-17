"""Compact JSON and standalone HTML report generation."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .errors import AndroidAssessorError
from .evidence import EvidenceRepository, sha256_file
from .findings import FindingRepository
from .paths import ProjectPaths
from .redaction import redact_report_data
from .rule_catalog import merge_root_coverage
from .session import SessionRepository
from .storage import read_json_object, write_json_atomic, write_text_atomic

_VALIDATION_TYPES = {
    "natural_validation",
    "adb_assisted_validation",
    "root_assisted_validation",
    "instrumented_validation",
    "post_compromise_observation",
}
_PHYSICAL_STATUSES = {
    "NOT_REQUIRED",
    "BLOCKED_NO_DEVICE",
    "UNVERIFIED",
    "PASSED",
    "FAILED",
}
_EXPERIMENT_FIELDS = (
    "run_id",
    "environment_type",
    "fixture_or_physical",
    "device_model",
    "android_version",
    "package",
    "test_id",
    "expected_result",
    "actual_result",
    "status",
    "root_required",
    "root_used",
    "frida_required",
    "frida_used",
    "validation_type",
    "duration_ms",
    "false_positive",
    "false_negative",
    "cleanup_success",
    "physical_validation_status",
)


def _optional_json(path: Path, root: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return read_json_object(path, root=root)
    except (AndroidAssessorError, OSError, ValueError):
        return None


def _capability_available(device: dict[str, Any] | None, name: str) -> bool:
    if not device:
        return False
    capabilities = device.get("capabilities")
    values = capabilities.get("capabilities") if isinstance(capabilities, dict) else None
    if not isinstance(values, list):
        return False
    return any(
        isinstance(item, dict) and item.get("name") == name and item.get("available") is True
        for item in values
    )


def _capability_metadata(device: dict[str, Any] | None, name: str) -> dict[str, Any]:
    if not device:
        return {}
    capabilities = device.get("capabilities")
    values = capabilities.get("capabilities") if isinstance(capabilities, dict) else None
    if not isinstance(values, list):
        return {}
    for item in values:
        if isinstance(item, dict) and item.get("name") == name:
            metadata = item.get("metadata")
            return dict(metadata) if isinstance(metadata, dict) else {}
    return {}


def _fixture_or_physical(
    environment: dict[str, Any] | None,
    evidence: list[dict[str, Any]],
) -> str:
    marker = ""
    if environment:
        marker = str(
            environment.get("fixture_or_physical") or environment.get("environment_type") or ""
        ).casefold()
    if marker in {"fixture", "simulated"} or any(
        item.get("source") == "fixture" for item in evidence
    ):
        return "fixture"
    return "physical"


def _environment_type(
    record_serial: str,
    device: dict[str, Any] | None,
    provenance: str,
) -> str:
    if provenance == "fixture":
        return "simulated"
    info = device.get("device", {}) if isinstance(device, dict) else {}
    model = str(info.get("model", "")).casefold() if isinstance(info, dict) else ""
    if record_serial.startswith("emulator-") or "sdk_gphone" in model or "emulator" in model:
        return "emulator"
    return "physical_device"


def _capability_used_by_security_findings(
    findings: list[dict[str, Any]],
    capability_key: str,
) -> bool:
    return any(
        bool(item.get(capability_key))
        and str(item.get("status", "confirmed")) in {"confirmed", "potential"}
        and not bool((item.get("details") or {}).get("observation_only"))
        for item in findings
    )


def _is_runtime_check(finding: dict[str, Any]) -> bool:
    details = finding.get("details")
    return bool(isinstance(details, dict) and details.get("observation_only")) or str(
        finding.get("rule_id", "")
    ).startswith("ASL-RUNTIME-")


def _is_aggregate_alias(
    finding: dict[str, Any],
    rule_statuses: dict[str, str],
) -> bool:
    if str(finding.get("rule_id", "")) != "ASL-MVP-004":
        return False
    family = {
        "ASL-MANIFEST-EXPORTED-ACTIVITY",
        "ASL-MANIFEST-EXPORTED-SERVICE",
        "ASL-MANIFEST-EXPORTED-RECEIVER",
        "ASL-MANIFEST-EXPORTED-PROVIDER",
    }
    conclusive = {"pass", "potential", "confirmed"}
    return all(rule_statuses.get(rule_id) in conclusive for rule_id in family)


def _observation_status(finding: dict[str, Any]) -> str:
    details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
    explicit = str(details.get("observation_status", ""))
    if explicit in {"observed", "not_observed", "insufficient_activity", "skipped", "error"}:
        return explicit
    if str(finding.get("status")) == "error":
        return "error"
    if str(finding.get("status")) == "skipped":
        return "skipped"
    count = details.get("event_count", details.get("observation_count", 0))
    if isinstance(count, int) and count > 0:
        return "observed"
    if details.get("root_check_present") or details.get("root_check_executed"):
        return "observed"
    return "not_observed"


def _runtime_event_rows(
    findings: list[dict[str, Any]], evidence: list[dict[str, Any]], root: Path
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for item in evidence:
        if item.get("evidence_type") != "frida_events":
            continue
        path = root / str(item.get("relative_path", ""))
        if not path.is_file() or path.stat().st_size == 0:
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                value = json.loads(line)
                if isinstance(value, dict) and value.get("category") not in {None, "lifecycle"}:
                    events.append(value)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in events:
        key = (str(event.get("category", "unknown")), str(event.get("method", "event")))
        grouped.setdefault(key, []).append(event)
    rows: list[dict[str, Any]] = []
    for (category, method), values in sorted(grouped.items()):
        source_ids = [
            str(item.get("evidence_id"))
            for item in evidence
            if item.get("evidence_type") == "frida_events"
        ]
        finding_id = next(
            (
                str(item.get("finding_id"))
                for item in findings
                if str(item.get("rule_id")) == "CRYPTO-ECB" and category == "crypto"
            ),
            None,
        )
        rows.append(
            {
                "category": category,
                "method": method,
                "status": "observed",
                "event_count": len(values),
                "evidence_ids": source_ids,
                "finding_id": finding_id,
            }
        )
    return rows


def _root_coverage_aliases(
    coverage: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project newer analyzer rule IDs onto the stable root-focused catalog."""
    observed = {str(item.get("test_id")): item for item in coverage}
    findings_by_rule = {str(item.get("rule_id")): item for item in findings}
    aliases = {
        "ASL-ROOT-STORAGE": ("ASL-RUNTIME-STORAGE",),
        "ASL-ROOT-CRYPTO": ("CRYPTO-ECB", "CRYPTO-WEAK-ALGORITHM"),
        "ASL-ROOT-DETECTION": ("ASL-RUNTIME-ROOT",),
    }
    output = list(coverage)
    for alias, targets in aliases.items():
        if alias in observed:
            continue
        target = next(
            (findings_by_rule.get(rule_id) for rule_id in targets if rule_id in findings_by_rule),
            None,
        )
        if target is None:
            continue
        output.append(
            {
                "test_id": alias,
                "physical_validation_status": str(
                    target.get("device_validation_status", "UNVERIFIED")
                ),
                "finding_status": str(target.get("status", "inconclusive")),
            }
        )
    return output


def _validation_type(finding: dict[str, Any]) -> str:
    validation = finding.get("validation")
    if isinstance(validation, dict):
        value = str(validation.get("validation_type", ""))
        if value in _VALIDATION_TYPES:
            return value
    details = finding.get("details")
    if isinstance(details, dict):
        value = str(details.get("validation_type", ""))
        if value in _VALIDATION_TYPES:
            return value
    if finding.get("frida_used") is True or finding.get("analysis_type") == "instrumentation":
        return "instrumented_validation"
    if finding.get("root_used") is True or finding.get("root_required") is True:
        return "root_assisted_validation"
    return "adb_assisted_validation"


def _physical_status(finding: dict[str, Any], provenance: str) -> str:
    details = finding.get("details")
    value = (
        str(details.get("physical_validation_status", "UNVERIFIED"))
        if isinstance(details, dict)
        else "UNVERIFIED"
    )
    if value not in _PHYSICAL_STATUSES:
        value = "UNVERIFIED"
    if provenance == "fixture" and value in {"PASSED", "FAILED"}:
        return "UNVERIFIED"
    return value


def _normalize_findings(
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    *,
    root_available: bool,
    frida_available: bool,
    provenance: str,
    evidence_source: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_by_id = {
        str(item.get("evidence_id")): item for item in evidence if item.get("evidence_id")
    }
    normalized: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    for original in findings:
        finding = dict(original)
        details = finding.get("details")
        details = details if isinstance(details, dict) else {}
        validation_type = _validation_type(finding)
        frida_required = bool(
            details.get("frida_required")
            or validation_type == "instrumented_validation"
            or finding.get("frida_used") is True
        )
        physical_status = _physical_status(finding, provenance)
        evidence_sources = sorted(
            {
                str(evidence_by_id[item].get("source", "unknown"))
                for item in finding.get("evidence_ids", [])
                if item in evidence_by_id
            }
        )
        finding.update(
            {
                "root_available": root_available,
                "frida_required": frida_required,
                "frida_available": frida_available,
                "validation_type": validation_type,
                "device_validation_status": physical_status,
                "evidence_source": (
                    "none"
                    if not finding.get("evidence_ids")
                    else "fixture"
                    if provenance == "fixture"
                    else evidence_source or "physical_device"
                ),
                "evidence_sources": evidence_sources,
            }
        )
        normalized.append(finding)
        coverage.append(
            {
                "test_id": str(finding.get("rule_id", "unknown")),
                "available_without_root": not bool(finding.get("root_required")),
                "available_with_root": True,
                "requires_frida": frida_required,
                "implementation_status": str(details.get("implementation_status", "IMPLEMENTED")),
                "physical_validation_status": physical_status,
                "finding_status": str(finding.get("status", "inconclusive")),
            }
        )
    return normalized, coverage


def _aggregate_physical_status(coverage: list[dict[str, Any]]) -> str:
    statuses = {str(item["physical_validation_status"]) for item in coverage}
    if not statuses:
        return "UNVERIFIED"
    if "BLOCKED_NO_DEVICE" in statuses:
        return "BLOCKED_NO_DEVICE"
    if "FAILED" in statuses:
        return "FAILED"
    if statuses == {"NOT_REQUIRED"}:
        return "NOT_REQUIRED"
    if statuses <= {"PASSED", "NOT_REQUIRED"}:
        return "PASSED"
    return "UNVERIFIED"


def _csv_cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + value
    return value


def _experiment_csv(
    report: dict[str, Any],
    *,
    device_info: dict[str, Any],
) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=_EXPERIMENT_FIELDS, lineterminator="\n")
    writer.writeheader()
    for finding in report["findings"]:
        details = finding.get("details")
        details = details if isinstance(details, dict) else {}
        row = {
            "run_id": report["session"]["session_id"],
            "environment_type": report["experiment"]["environment_type"],
            "fixture_or_physical": report["experiment"]["fixture_or_physical"],
            "device_model": device_info.get("model", ""),
            "android_version": device_info.get("android_version", ""),
            "package": report["session"]["package"],
            "test_id": finding.get("rule_id", ""),
            "expected_result": details.get("expected_result", ""),
            "actual_result": finding.get("status", ""),
            "status": finding.get("status", ""),
            "root_required": finding.get("root_required", False),
            "root_used": finding.get("root_used", False),
            "frida_required": finding.get("frida_required", False),
            "frida_used": finding.get("frida_used", False),
            "validation_type": finding.get("validation_type", ""),
            "duration_ms": details.get("duration_ms", ""),
            "false_positive": details.get("false_positive", ""),
            "false_negative": details.get("false_negative", ""),
            "cleanup_success": report["cleanup"]["success"],
            "physical_validation_status": finding.get("device_validation_status", "UNVERIFIED"),
        }
        writer.writerow({name: _csv_cell(row[name]) for name in _EXPERIMENT_FIELDS})
    return buffer.getvalue()


class ReportService:
    def __init__(
        self,
        paths: ProjectPaths,
        sessions: SessionRepository | None = None,
    ) -> None:
        self.paths = paths
        self.sessions = sessions or SessionRepository(paths)
        self.findings = FindingRepository(paths, self.sessions)
        self.evidence = EvidenceRepository(paths, self.sessions)
        self.templates = Environment(
            loader=FileSystemLoader(paths.root / "templates"),
            autoescape=select_autoescape(("html", "xml")),
        )

    def generate(
        self,
        session_id: str,
        *,
        limitations: list[str] | None = None,
    ) -> dict[str, Any]:
        record = self.sessions.load(session_id)
        paths = self.sessions.paths_for(record.session_id)
        findings = [item.to_dict() for item in self.findings.list(record.session_id)]
        evidence = self.evidence.list(record.session_id)
        counts = {
            name: 0
            for name in ("confirmed", "potential", "pass", "inconclusive", "skipped", "error")
        }
        app = _optional_json(paths.app_json, self.paths.root)
        scan = _optional_json(paths.scan_json, self.paths.root)
        recorded_limitations = list(limitations or [])
        if app and isinstance(app.get("limitations"), list):
            recorded_limitations.extend(str(item) for item in app["limitations"])
        if scan and isinstance(scan.get("limitations"), list):
            recorded_limitations.extend(str(item) for item in scan["limitations"])
        device = _optional_json(paths.device_json, self.paths.root)
        environment = _optional_json(paths.environment_json, self.paths.root)
        provenance = _fixture_or_physical(environment, evidence)
        root_available = _capability_available(device, "ANDROID_ROOT")
        root_metadata = _capability_metadata(device, "ANDROID_ROOT")
        root_mode = str(root_metadata.get("root_mode") or ("su_root" if root_available else "none"))
        frida_state = _optional_json(paths.frida_dir / "state.json", self.paths.root)
        private_storage = _optional_json(
            paths.redacted_dir / "storage" / "private-storage.json", self.paths.root
        )
        frida_available = _capability_available(device, "FRIDA_CLIENT") and (
            _capability_available(device, "FRIDA_SERVER") or frida_state is not None
        )
        root_used_in_session = bool(
            private_storage
            or (frida_state and frida_state.get("server_started_by_framework") is True)
        )
        frida_used_in_session = bool(
            frida_state and frida_state.get("server_started_by_framework") is True
        )
        environment_type = _environment_type(record.serial, device, provenance)
        report_evidence_source = (
            "fixture"
            if provenance == "fixture"
            else "emulator"
            if environment_type == "emulator"
            else "physical_device"
        )
        usable_evidence = []
        for item in evidence:
            relative = item.get("relative_path")
            target = paths.root / str(relative) if relative else None
            if target is None or not target.is_file() or target.stat().st_size > 0:
                usable_evidence.append(item)
        evidence = usable_evidence
        findings, coverage = _normalize_findings(
            findings,
            evidence,
            root_available=root_available,
            frida_available=frida_available,
            provenance=provenance,
            evidence_source=report_evidence_source,
        )
        rule_statuses = {
            str(item.get("rule_id")): str(item.get("status")) for item in findings
        }
        suppressed_findings = [
            item for item in findings if _is_aggregate_alias(item, rule_statuses)
        ]
        security_rules = [
            item
            for item in findings
            if not _is_runtime_check(item) and item not in suppressed_findings
        ]
        runtime_checks = [item for item in findings if _is_runtime_check(item)]
        for finding in security_rules:
            status = str(finding.get("status"))
            if status in counts:
                counts[status] += 1
        coverage = merge_root_coverage(_root_coverage_aliases(coverage, findings))
        device_info = (
            device.get("device", {})
            if isinstance(device, dict) and isinstance(device.get("device"), dict)
            else {}
        )
        app_timings = app.get("phase_timings", {}) if isinstance(app, dict) else {}
        scan_timings = {
            **(app_timings if isinstance(app_timings, dict) else {}),
            **(scan.get("phase_timings", {}) if isinstance(scan, dict) else {}),
        }
        scan_steps = scan.get("dynamic_steps", {}) if isinstance(scan, dict) else {}
        app_steps = app.get("steps", {}) if isinstance(app, dict) else {}
        scan_profile = str(scan.get("profile", "quick")) if isinstance(scan, dict) else "quick"
        planned_modules = {
            "device_inspection": ("preflight", "Device and capability preflight."),
            "apk_acquisition": ("apk_acquisition", "Shared APK acquisition."),
            "manifest": ("manifest", "Shared manifest parsing."),
            "signature": ("signature", "APK signature verification."),
            "static_rules": ("rule_evaluation", "Static rule evaluation."),
            "logcat": ("logcat", "Bounded target-process logcat."),
            "private_storage": ("storage", "Bounded private-storage analysis."),
            "frida": ("frida_start", "Frida observer lifecycle."),
            "autonomous_exploration": (
                "exploration",
                "Bounded package-scoped UI exploration.",
            ),
            "runtime_observation": ("runtime_observation", "Runtime event observation."),
            "traffic": ("traffic", "Scoped traffic capture."),
            "report": ("report", "Report generation."),
        }
        modules: list[dict[str, Any]] = []
        module_evidence_prefixes = {
            "device_inspection": ("device_", "package_metadata"),
            "apk_acquisition": ("apk",),
            "manifest": ("manifest_", "apk_badging"),
            "signature": ("apk_signature",),
            "static_rules": ("manifest_", "apk_badging", "apk_signature"),
            "logcat": ("target_logcat",),
            "private_storage": ("private_storage_",),
            "frida": ("frida_",),
            "autonomous_exploration": (
                "autonomous_exploration_",
                "autonomous_interaction_",
            ),
            "runtime_observation": ("frida_events", "target_logcat"),
            "traffic": ("traffic_",),
            "report": ("report_", "experiment_results_csv"),
        }
        for module, (timing_key, description) in planned_modules.items():
            planned = scan_profile == "full" or module not in {
                "private_storage",
                "frida",
                "autonomous_exploration",
                "runtime_observation",
                "traffic",
            }
            app_step = {
                "apk_acquisition": "apk_pull",
                "manifest": "aapt2_manifest",
                "signature": "apksigner",
            }.get(module)
            executed = (
                (app_step is not None and app_steps.get(app_step) == "completed")
                or (timing_key in scan_timings)
                or (
                    module == "frida"
                    and scan_steps.get("frida_observation") not in {None, "skipped"}
                )
                or (
                    module == "autonomous_exploration"
                    and scan_steps.get("autonomous_exploration") not in {None, "skipped"}
                )
                or (module == "report")
            )
            skipped_step = {
                "traffic": "traffic_capture",
                "frida": "frida_observation",
                "autonomous_exploration": "autonomous_exploration",
                "private_storage": "private_storage",
                "logcat": "target_logcat",
            }.get(module, "")
            step_result = scan_steps.get(skipped_step)
            skipped = step_result == "skipped" or (
                app_step is not None and app_steps.get(app_step) in {"skipped", "error"}
            )
            failed = step_result in {"error", "start_failed", "stop_failed"}
            limitation_values = []
            if isinstance(app, dict) and isinstance(app.get("limitations"), list):
                limitation_values.extend(str(item) for item in app["limitations"])
            if isinstance(app, dict) and isinstance(app.get("errors"), list):
                limitation_values.extend(str(item) for item in app["errors"])
            if isinstance(scan, dict) and isinstance(scan.get("limitations"), list):
                limitation_values.extend(str(item) for item in scan["limitations"])
            module_terms = {
                "apk_acquisition": ("apk",),
                "manifest": ("manifest", "aapt2"),
                "signature": ("signature", "apksigner"),
                "logcat": ("logcat",),
                "private_storage": ("storage",),
                "frida": ("frida",),
                "autonomous_exploration": ("exploration",),
                "traffic": ("traffic", "proxy"),
            }
            evidence_count = (
                sum(
                    1
                    for item in evidence
                    if str(item.get("evidence_type", "")).startswith(
                        module_evidence_prefixes[module]
                    )
                )
                if executed
                else 0
            )
            skip_reason = (
                next(
                    (
                        item
                        for item in limitation_values
                        if any(
                            term in str(item).casefold()
                            for term in module_terms.get(module, (module.replace("_", " "),))
                        )
                    ),
                    None,
                )
                if skipped or failed
                else None
            )
            modules.append(
                {
                    "module": module,
                    "planned": planned,
                    "executed": bool(executed),
                    "result": (
                        "not_planned"
                        if not planned
                        else "error"
                        if failed
                        else "skipped"
                        if skipped
                        else "completed"
                        if executed
                        else "not_executed"
                    ),
                    "duration_ms": scan_timings.get(timing_key),
                    "evidence": evidence_count,
                    "event_item_count": 0,
                    "findings_produced": 0,
                    "skip_reason": skip_reason,
                    "description": description,
                }
            )
        security_findings = [
            item for item in security_rules if str(item.get("status")) in {"confirmed", "potential"}
        ]
        root_used_by_findings = _capability_used_by_security_findings(security_rules, "root_used")
        frida_used_by_findings = _capability_used_by_security_findings(security_rules, "frida_used")
        runtime_checks_payload = []
        for item in runtime_checks:
            observation_status = _observation_status(item)
            runtime_checks_payload.append(
                {
                    **item,
                    "finding_status": item.get("status"),
                    "status": observation_status,
                    "observation_status": observation_status,
                    "security_finding_produced": False,
                    "reason": (
                        "Runtime event observed; this row is not a vulnerability finding."
                        if observation_status == "observed"
                        else "No qualifying runtime event was observed in the bounded window."
                    ),
                }
            )
        observations = _runtime_event_rows(findings, evidence, paths.root)
        runtime_phases = []
        if isinstance(scan, dict) and isinstance(scan.get("runtime_phases"), list):
            for phase in scan["runtime_phases"]:
                if isinstance(phase, dict):
                    runtime_phases.append(
                        {
                            **phase,
                            "event_count": sum(
                                int(item.get("event_count", 0)) for item in observations
                            ),
                            "categories": sorted(
                                {str(item.get("category")) for item in observations}
                            ),
                        }
                    )
        runtime_checks_executed = len(runtime_checks_payload)
        security_rules_evaluated = len(security_rules)
        total_checks_executed = security_rules_evaluated + runtime_checks_executed
        wall_clock = scan.get("wall_clock_duration_ms") if isinstance(scan, dict) else None
        duration_keys = {
            "preflight",
            "apk_acquisition",
            "manifest",
            "signature",
            "rule_evaluation",
            "logcat",
            "storage",
            "frida_startup",
            "traffic_startup",
            "runtime_analysis",
            "report",
        }
        duration_keys.add("exploration" if "exploration" in scan_timings else "runtime_interaction")
        module_duration_sum = sum(
            float(value)
            for key, value in scan_timings.items()
            if key in duration_keys and isinstance(value, (int, float))
        )
        module_findings = {
            "static_rules": sum(
                1
                for item in security_findings
                if not bool(item.get("frida_used")) and not bool(item.get("root_used"))
            ),
            "frida": sum(1 for item in security_findings if bool(item.get("frida_used"))),
            "private_storage": sum(1 for item in security_findings if bool(item.get("root_used"))),
        }
        traffic_state = _optional_json(paths.traffic_dir / "state.json", self.paths.root) or {}
        for module in modules:
            module_name = str(module.get("module"))
            module["evidence"] = (
                sum(
                    1
                    for item in usable_evidence
                    if str(item.get("evidence_type", "")).startswith(
                        module_evidence_prefixes.get(module_name, ())
                    )
                )
                if module.get("executed")
                else 0
            )
            module["event_item_count"] = (
                sum(int(item.get("event_count", 0)) for item in observations)
                if module_name in {"frida", "runtime_observation"}
                else int(traffic_state.get("flow_count", 0))
                if module_name == "traffic"
                else len((private_storage or {}).get("observations", []))
                if module_name == "private_storage"
                else int(
                    ((scan or {}).get("autonomous_exploration") or {}).get("actions_executed", 0)
                )
                if module_name == "autonomous_exploration"
                else 0
            )
            module["findings_produced"] = module_findings.get(module_name, 0)
            if module_name == "traffic" and traffic_state.get("result") == "completed_no_data":
                module["result"] = "completed_no_data"
                module["skip_reason"] = "No request flows were captured in the scoped window."
        experiment = {
            "fixture_or_physical": provenance,
            "environment_type": environment_type,
            "eligible_for_empirical_metrics": provenance == "physical",
        }
        if provenance != "fixture":
            experiment["emulator_validation"] = (
                "VERIFIED" if environment_type == "emulator" else "UNVERIFIED"
            )
            experiment["physical_device_validation"] = "UNVERIFIED"
        payload: dict[str, Any] = {
            "schema_version": 2,
            "generated_at": datetime.now(UTC).isoformat(),
            "session": record.to_dict(show_serial=False),
            "device": device,
            "environment": environment,
            "app": app,
            "scan": scan,
            "traffic": _optional_json(paths.traffic_dir / "state.json", self.paths.root),
            "frida": _optional_json(paths.frida_dir / "state.json", self.paths.root),
            "private_storage": private_storage,
            "findings": security_rules,
            "all_findings": findings,
            "suppressed_findings": suppressed_findings,
            "runtime_checks": runtime_checks_payload,
            "evidence": usable_evidence,
            "summary": {
                "total": total_checks_executed,
                "security_rules_evaluated": security_rules_evaluated,
                "security_findings_total": len(security_findings),
                "runtime_checks_executed": runtime_checks_executed,
                "runtime_observations_total": len(observations),
                "total_checks_executed": total_checks_executed,
                **counts,
                "other": 0,
                "security_findings": len(security_findings),
                "runtime_observations": len(observations),
                "modules_executed": sum(1 for item in modules if item["executed"]),
                "modules_skipped": sum(1 for item in modules if item["result"] == "skipped"),
                "assessment_duration_ms": (
                    float(wall_clock)
                    if isinstance(wall_clock, (int, float))
                    else module_duration_sum
                ),
                "wall_clock_duration_ms": wall_clock,
                "sum_of_module_durations_ms": module_duration_sum,
                "parallel_phases": (
                    scan.get("parallel_phases", []) if isinstance(scan, dict) else []
                ),
            },
            "root_used": root_used_in_session,
            "root_available": root_available,
            "root_mode": root_mode,
            "root_probe_status": root_metadata.get("root_probe_status", "unknown"),
            "root_required": any(bool(item.get("root_required")) for item in findings),
            "root_used_in_session": root_used_in_session,
            "root_used_by_findings": root_used_by_findings,
            "frida_used": frida_used_in_session,
            "frida_used_in_session": frida_used_in_session,
            "frida_used_by_findings": frida_used_by_findings,
            "frida_available": frida_available,
            "frida_required": any(bool(item.get("frida_required")) for item in findings),
            "device_validation_status": _aggregate_physical_status(coverage),
            "evidence_source": "none" if not usable_evidence else report_evidence_source,
            "runtime_observations": observations,
            "runtime_phases": runtime_phases,
            "module_execution_coverage": modules,
            "module_timing": scan_timings,
            "root_vs_non_root_coverage": coverage,
            "experiment": experiment,
            "cleanup": {
                "status": record.status.value,
                "success": record.cleanup_success,
                "pending": record.pending_cleanup,
            },
            "report_state": (
                "final"
                if record.cleanup_success is True and not record.pending_cleanup
                else "preliminary"
            ),
            "limitations": list(dict.fromkeys(recorded_limitations)),
        }
        payload = redact_report_data(payload)
        csv_text = _experiment_csv(payload, device_info=device_info)
        write_text_atomic(
            paths.experiment_results_csv,
            csv_text,
            root=self.paths.root,
        )
        payload["report_artifacts"] = {
            "experiment_results_csv": {
                "relative_path": "experiment_results.csv",
                "sha256": sha256_file(paths.experiment_results_csv),
            }
        }
        html = self.templates.get_template("report.html.j2").render(report=payload)
        write_text_atomic(paths.report_html, html, root=self.paths.root)
        payload["report_artifacts"]["report_html"] = {
            "relative_path": "report.html",
            "sha256": sha256_file(paths.report_html),
        }
        write_json_atomic(paths.report_json, payload, root=self.paths.root)
        for target, evidence_type, description in (
            (paths.report_html, "report_html", "Standalone HTML assessment report."),
            (paths.report_json, "report_json", "Machine-readable assessment report."),
            (
                paths.experiment_results_csv,
                "experiment_results_csv",
                "Metrics-ready assessment rows with explicit fixture provenance.",
            ),
        ):
            self.evidence.register_file(
                record.session_id,
                target,
                evidence_type=evidence_type,
                source="report_generator",
                description=description,
                sensitive=True,
                redacted=True,
            )
        self.sessions.append_event(
            record.session_id,
            "report_generated",
            {"finding_count": len(findings)},
        )
        return payload
