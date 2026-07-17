"""Compact JSON and standalone HTML report generation."""

from __future__ import annotations

import csv
import io
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
        isinstance(item, dict)
        and item.get("name") == name
        and item.get("available") is True
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
            environment.get("fixture_or_physical")
            or environment.get("environment_type")
            or ""
        ).casefold()
    if marker in {"fixture", "simulated"} or any(
        item.get("source") == "fixture" for item in evidence
    ):
        return "fixture"
    return "physical"


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
    if (
        finding.get("frida_used") is True
        or finding.get("analysis_type") == "instrumentation"
    ):
        return "instrumented_validation"
    if finding.get("root_used") is True or finding.get("root_required") is True:
        return "root_assisted_validation"
    return "adb_assisted_validation"


def _physical_status(finding: dict[str, Any], provenance: str) -> str:
    details = finding.get("details")
    value = str(details.get("physical_validation_status", "UNVERIFIED")) if isinstance(
        details, dict
    ) else "UNVERIFIED"
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
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_by_id = {
        str(item.get("evidence_id")): item
        for item in evidence
        if item.get("evidence_id")
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
                    else "physical_device"
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
                "implementation_status": str(
                    details.get("implementation_status", "IMPLEMENTED")
                ),
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
            "physical_validation_status": finding.get(
                "device_validation_status", "UNVERIFIED"
            ),
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
        counts = {name: 0 for name in ("confirmed", "potential", "pass")}
        for finding in findings:
            status = str(finding["status"])
            if status in counts:
                counts[status] += 1
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
        root_mode = str(
            root_metadata.get("root_mode")
            or ("su_root" if root_available else "none")
        )
        frida_available = _capability_available(
            device, "FRIDA_CLIENT"
        ) and _capability_available(device, "FRIDA_SERVER")
        findings, coverage = _normalize_findings(
            findings,
            evidence,
            root_available=root_available,
            frida_available=frida_available,
            provenance=provenance,
        )
        coverage = merge_root_coverage(coverage)
        device_info = (
            device.get("device", {})
            if isinstance(device, dict) and isinstance(device.get("device"), dict)
            else {}
        )
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
            "private_storage": _optional_json(
                paths.redacted_dir / "storage" / "private-storage.json",
                self.paths.root,
            ),
            "findings": findings,
            "evidence": evidence,
            "summary": {
                "total": len(findings),
                **counts,
                "other": len(findings) - sum(counts.values()),
            },
            "root_used": any(bool(item.get("root_used")) for item in findings),
            "root_available": root_available,
            "root_mode": root_mode,
            "root_probe_status": root_metadata.get("root_probe_status", "unknown"),
            "root_required": any(bool(item.get("root_required")) for item in findings),
            "frida_used": any(bool(item.get("frida_used")) for item in findings),
            "frida_available": frida_available,
            "frida_required": any(bool(item.get("frida_required")) for item in findings),
            "device_validation_status": _aggregate_physical_status(coverage),
            "evidence_source": (
                "none"
                if not evidence
                else "fixture"
                if provenance == "fixture"
                else "physical_device"
            ),
            "root_vs_non_root_coverage": coverage,
            "experiment": {
                "fixture_or_physical": provenance,
                "environment_type": (
                    "simulated" if provenance == "fixture" else "physical_android"
                ),
                "eligible_for_empirical_metrics": provenance == "physical",
            },
            "cleanup": {
                "status": record.status.value,
                "success": record.cleanup_success,
                "pending": record.pending_cleanup,
            },
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
