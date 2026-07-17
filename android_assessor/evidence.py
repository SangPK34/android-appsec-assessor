"""Evidence metadata and streaming SHA-256 registration."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .errors import SessionError
from .paths import ProjectPaths
from .session import SessionRepository
from .storage import read_json_object, require_under_root, write_json_atomic


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    if chunk_size < 4096:
        raise ValueError("Hash chunk size is too small.")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(chunk_size):
                digest.update(chunk)
    except OSError as exc:
        raise SessionError(f"Could not hash evidence file {path}: {exc}") from exc
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    evidence_type: str
    source: str
    timestamp: str
    sha256: str
    relative_path: str
    sensitive: bool
    redacted: bool
    description: str
    related_findings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["related_findings"] = list(self.related_findings)
        return value


class EvidenceRepository:
    def __init__(self, paths: ProjectPaths, sessions: SessionRepository) -> None:
        self.paths = paths
        self.sessions = sessions

    def list(self, session_id: str) -> list[dict[str, Any]]:
        index = self.sessions.paths_for(session_id).evidence_index
        payload = read_json_object(index, root=self.paths.root)
        evidence = payload.get("evidence", [])
        if not isinstance(evidence, list) or not all(isinstance(item, dict) for item in evidence):
            raise SessionError("Evidence index has an invalid structure.")
        return [dict(item) for item in evidence]

    def register_file(
        self,
        session_id: str,
        path: Path,
        *,
        evidence_type: str,
        source: str,
        description: str,
        sensitive: bool,
        redacted: bool,
        related_findings: tuple[str, ...] = (),
    ) -> EvidenceRecord:
        if not evidence_type or len(evidence_type) > 80:
            raise SessionError("Evidence type is invalid.")
        if not source or len(source) > 200:
            raise SessionError("Evidence source is invalid.")
        if not description or len(description) > 500:
            raise SessionError("Evidence description is invalid.")
        session_paths = self.sessions.paths_for(session_id)
        target = require_under_root(path, session_paths.root)
        if not target.is_file():
            raise SessionError(f"Evidence file does not exist: {target.name}")
        relative = target.relative_to(session_paths.root).as_posix()
        with self.sessions.state_lock(session_id):
            existing = self.list(session_id)
            previous = next(
                (item for item in existing if item.get("relative_path") == relative),
                None,
            )
            record = EvidenceRecord(
                evidence_id=(
                    str(previous["evidence_id"])
                    if previous and previous.get("evidence_id")
                    else f"ev-{uuid4().hex[:12]}"
                ),
                evidence_type=evidence_type,
                source=source,
                timestamp=datetime.now(UTC).isoformat(),
                sha256=sha256_file(target),
                relative_path=relative,
                sensitive=sensitive,
                redacted=redacted,
                description=description,
                related_findings=related_findings,
            )
            updated = [
                item for item in existing if item.get("relative_path") != relative
            ]
            updated.append(record.to_dict())
            write_json_atomic(
                session_paths.evidence_index,
                {"schema_version": 1, "evidence": updated},
                root=self.paths.root,
            )
            return record
