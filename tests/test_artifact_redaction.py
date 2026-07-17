from __future__ import annotations

import json
from pathlib import Path

from android_assessor.paths import ProjectPaths
from android_assessor.report import ReportService
from android_assessor.session import SessionRepository
from android_assessor.storage import write_json_atomic


def test_report_artifacts_are_redacted_before_being_classified_redacted(
    tmp_path: Path,
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    templates = paths.root / "templates"
    templates.mkdir()
    (templates / "report.html.j2").write_text(
        "<html><body>{{ report | tojson }}</body></html>",
        encoding="utf-8",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    repository.activate(
        record.session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURED_EMPTY",
            "http_proxy_error": None,
        },
        device={},
        environment={},
    )
    session_paths = repository.paths_for(record.session_id)
    secrets = (
        "report-bearer-secret",
        "manifest-api-secret",
        "person@example.com",
        "+84912345678",
    )
    write_json_atomic(
        session_paths.app_json,
        {
            "schema_version": 1,
            "package": record.package,
            "manifest": {"api_key": secrets[1]},
            "limitations": [
                f"Authorization: Bearer {secrets[0]}",
                f"Contact {secrets[2]} or {secrets[3]}",
            ],
        },
        root=paths.root,
    )

    ReportService(paths, repository).generate(record.session_id)

    html = session_paths.report_html.read_text(encoding="utf-8")
    report_json = session_paths.report_json.read_text(encoding="utf-8")
    for secret in secrets:
        assert secret not in html
        assert secret not in report_json
    parsed = json.loads(report_json)
    assert parsed["session"]["session_id"] == record.session_id
    evidence_index = json.loads(
        repository.paths_for(record.session_id).evidence_index.read_text(
            encoding="utf-8"
        )
    )
    report_evidence = [
        item
        for item in evidence_index["evidence"]
        if item["evidence_type"] in {"report_html", "report_json"}
    ]
    assert len(report_evidence) == 2
    assert all(item["redacted"] is True for item in report_evidence)
