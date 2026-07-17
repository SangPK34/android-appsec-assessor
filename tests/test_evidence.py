from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from android_assessor.errors import SessionError
from android_assessor.evidence import EvidenceRepository, sha256_file
from android_assessor.paths import ProjectPaths
from android_assessor.session import SessionRepository


def test_evidence_registration_hashes_and_uses_relative_path(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "Android Lab có dấu")
    paths.ensure_layout()
    sessions = SessionRepository(paths)
    session = sessions.initialize(serial="ABC123", package="com.example.app")
    apk = sessions.paths_for(session.session_id).apk_dir / "000-base.apk"
    apk.write_bytes(b"APK-CONTENT")
    evidence = EvidenceRepository(paths, sessions)

    record = evidence.register_file(
        session.session_id,
        apk,
        evidence_type="apk",
        source="adb_pull",
        description="Base APK pulled from the selected lab device.",
        sensitive=True,
        redacted=False,
    )

    assert record.sha256 == sha256_file(apk)
    assert record.relative_path == "apk/000-base.apk"
    assert evidence.list(session.session_id)[0]["evidence_id"] == record.evidence_id


def test_evidence_registration_rejects_file_outside_session(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    sessions = SessionRepository(paths)
    session = sessions.initialize(serial="ABC123", package="com.example.app")
    outside = paths.logs_dir / "outside.txt"
    outside.write_text("not session evidence", encoding="utf-8")

    with pytest.raises(SessionError, match="outside project root"):
        EvidenceRepository(paths, sessions).register_file(
            session.session_id,
            outside,
            evidence_type="log",
            source="test",
            description="Outside file.",
            sensitive=False,
            redacted=False,
        )


def test_concurrent_evidence_registration_does_not_lose_records(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    sessions = SessionRepository(paths)
    session = sessions.initialize(serial="ABC123", package="com.example.app")
    evidence = EvidenceRepository(paths, sessions)
    files = []
    for index in range(12):
        path = sessions.paths_for(session.session_id).apk_dir / f"{index}.txt"
        path.write_text(str(index), encoding="utf-8")
        files.append(path)

    def register(path: Path) -> None:
        evidence.register_file(
            session.session_id,
            path,
            evidence_type="test",
            source="test",
            description="Concurrent evidence record.",
            sensitive=False,
            redacted=False,
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(register, files))

    records = evidence.list(session.session_id)
    assert len(records) == len(files)
    assert len({item["evidence_id"] for item in records}) == len(files)
