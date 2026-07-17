"""Serializable finding records shared by CLI, web, validation, and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .errors import SessionError
from .paths import ProjectPaths
from .session import SessionRepository
from .storage import read_json_object, write_json_atomic


class FindingStatus(StrEnum):
    PASS = "pass"
    POTENTIAL = "potential"
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ValidationRecord:
    status: FindingStatus
    validation_type: str
    validated_at: str
    canary: str | None
    summary: str
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        value["evidence_ids"] = list(self.evidence_ids)
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ValidationRecord:
        return cls(
            status=FindingStatus(str(value["status"])),
            validation_type=str(value["validation_type"]),
            validated_at=str(value["validated_at"]),
            canary=str(value["canary"]) if value.get("canary") else None,
            summary=str(value["summary"]),
            evidence_ids=tuple(str(item) for item in value.get("evidence_ids", [])),
        )


@dataclass(frozen=True, slots=True)
class FindingRecord:
    finding_id: str
    rule_id: str
    title: str
    category: str
    description: str
    severity: str
    confidence: str
    status: FindingStatus
    analysis_type: str
    root_required: bool
    root_used: bool
    frida_used: bool
    validation_supported: bool
    validation: ValidationRecord | None
    evidence_ids: tuple[str, ...]
    remediation: str
    mappings: dict[str, Any]
    details: dict[str, Any]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        value["validation"] = self.validation.to_dict() if self.validation else None
        value["evidence_ids"] = list(self.evidence_ids)
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> FindingRecord:
        validation = value.get("validation")
        if validation is not None and not isinstance(validation, dict):
            raise SessionError("Finding validation has an invalid structure.")
        return cls(
            finding_id=str(value["finding_id"]),
            rule_id=str(value["rule_id"]),
            title=str(value["title"]),
            category=str(value["category"]),
            description=str(value["description"]),
            severity=str(value["severity"]),
            confidence=str(value["confidence"]),
            status=FindingStatus(str(value["status"])),
            analysis_type=str(value["analysis_type"]),
            root_required=bool(value.get("root_required", False)),
            root_used=bool(value.get("root_used", False)),
            frida_used=bool(value.get("frida_used", False)),
            validation_supported=bool(value.get("validation_supported", False)),
            validation=ValidationRecord.from_dict(validation) if validation else None,
            evidence_ids=tuple(str(item) for item in value.get("evidence_ids", [])),
            remediation=str(value["remediation"]),
            mappings=dict(value.get("mappings", {})),
            details=dict(value.get("details", {})),
            created_at=str(value["created_at"]),
            updated_at=str(value["updated_at"]),
        )


class FindingRepository:
    def __init__(self, paths: ProjectPaths, sessions: SessionRepository) -> None:
        self.paths = paths
        self.sessions = sessions

    def list(self, session_id: str) -> list[FindingRecord]:
        path = self.sessions.paths_for(session_id).findings_json
        payload = read_json_object(path, root=self.paths.root)
        values = payload.get("findings", [])
        if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
            raise SessionError("Finding file has an invalid structure.")
        return [FindingRecord.from_dict(item) for item in values]

    def save(self, session_id: str, findings: list[FindingRecord]) -> None:
        with self.sessions.state_lock(session_id):
            path = self.sessions.paths_for(session_id).findings_json
            write_json_atomic(
                path,
                {
                    "schema_version": 1,
                    "generated_at": datetime.now(UTC).isoformat(),
                    "findings": [finding.to_dict() for finding in findings],
                },
                root=self.paths.root,
            )

    def get(self, session_id: str, finding_id: str) -> FindingRecord:
        finding = next(
            (item for item in self.list(session_id) if item.finding_id == finding_id),
            None,
        )
        if finding is None:
            raise SessionError(f"Finding does not exist: {finding_id}")
        return finding

    def set_validation(
        self,
        session_id: str,
        finding_id: str,
        validation: ValidationRecord,
    ) -> FindingRecord:
        with self.sessions.state_lock(session_id):
            findings = self.list(session_id)
            updated: FindingRecord | None = None
            now = datetime.now(UTC).isoformat()
            output: list[FindingRecord] = []
            for finding in findings:
                if finding.finding_id != finding_id:
                    output.append(finding)
                    continue
                status = (
                    FindingStatus.CONFIRMED
                    if validation.status is FindingStatus.CONFIRMED
                    else finding.status
                )
                evidence = tuple(
                    dict.fromkeys((*finding.evidence_ids, *validation.evidence_ids))
                )
                updated = replace(
                    finding,
                    status=status,
                    validation=validation,
                    evidence_ids=evidence,
                    updated_at=now,
                )
                output.append(updated)
            if updated is None:
                raise SessionError(f"Finding does not exist: {finding_id}")
            self.save(session_id, output)
            return updated
