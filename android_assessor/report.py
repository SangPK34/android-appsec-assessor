"""Compact JSON and standalone HTML report generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .errors import AndroidAssessorError
from .evidence import EvidenceRepository, sha256_file
from .findings import FindingRepository
from .paths import ProjectPaths
from .redaction import redact_report_data
from .session import SessionRepository
from .storage import read_json_object, write_json_atomic, write_text_atomic


def _optional_json(path: Path, root: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return read_json_object(path, root=root)
    except (AndroidAssessorError, OSError, ValueError):
        return None


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
        payload: dict[str, Any] = {
            "schema_version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "session": record.to_dict(show_serial=False),
            "device": _optional_json(paths.device_json, self.paths.root),
            "environment": _optional_json(paths.environment_json, self.paths.root),
            "app": app,
            "scan": scan,
            "traffic": _optional_json(paths.traffic_dir / "state.json", self.paths.root),
            "frida": _optional_json(paths.frida_dir / "state.json", self.paths.root),
            "findings": findings,
            "evidence": evidence,
            "summary": {
                "total": len(findings),
                **counts,
                "other": len(findings) - sum(counts.values()),
            },
            "root_used": any(bool(item.get("root_used")) for item in findings),
            "frida_used": any(bool(item.get("frida_used")) for item in findings),
            "cleanup": {
                "status": record.status.value,
                "success": record.cleanup_success,
                "pending": record.pending_cleanup,
            },
            "limitations": list(dict.fromkeys(recorded_limitations)),
        }
        payload = redact_report_data(payload)
        html = self.templates.get_template("report.html.j2").render(report=payload)
        write_text_atomic(paths.report_html, html, root=self.paths.root)
        payload["report_artifacts"] = {
            "report_html": {
                "relative_path": "report.html",
                "sha256": sha256_file(paths.report_html),
            }
        }
        write_json_atomic(paths.report_json, payload, root=self.paths.root)
        for target, evidence_type, description in (
            (paths.report_html, "report_html", "Standalone HTML assessment report."),
            (paths.report_json, "report_json", "Machine-readable assessment report."),
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
