from __future__ import annotations

import json
from pathlib import Path
from shutil import copyfile

from android_assessor.findings import FindingStatus
from android_assessor.paths import ProjectPaths
from android_assessor.rules import RuleEngine
from android_assessor.session import SessionRepository
from android_assessor.storage import write_json_atomic


def prepared_rule_session(tmp_path: Path) -> tuple[ProjectPaths, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    rules_dir = paths.root / "rules"
    rules_dir.mkdir()
    copyfile(Path(__file__).resolve().parent.parent / "rules" / "mvp.yaml", rules_dir / "mvp.yaml")
    repository = SessionRepository(paths)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    session_paths = repository.paths_for(record.session_id)
    write_json_atomic(
        session_paths.app_json,
        {
            "schema_version": 1,
            "package": record.package,
            "manifest": {
                "debuggable": False,
                "test_only": False,
                "uses_cleartext_traffic": False,
                "network_security_config": None,
                "components": [],
            },
        },
        root=paths.root,
    )
    return paths, repository, record.session_id


def write_traffic(
    paths: ProjectPaths,
    repository: SessionRepository,
    session_id: str,
    events: list[dict[str, object]],
) -> None:
    session_paths = repository.paths_for(session_id)
    event_path = session_paths.traffic_dir / "events.jsonl"
    event_path.write_text(
        "".join(json.dumps(item) + "\n" for item in events),
        encoding="utf-8",
    )
    write_json_atomic(
        session_paths.traffic_dir / "state.json",
        {"events_path": "traffic/events.jsonl"},
        root=paths.root,
    )


def test_unattributed_background_traffic_cannot_confirm_target_findings(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = prepared_rule_session(tmp_path)
    write_traffic(
        paths,
        repository,
        session_id,
        [
            {
                "event": "request",
                "flow_id": "background-http",
                "scheme": "http",
                "cleartext": True,
                "sensitive_query_keys": ["access_token"],
                "attribution": "unattributed",
            },
            {
                "event": "request",
                "flow_id": "background-https",
                "scheme": "https",
                "cleartext": False,
                "attribution": "unattributed",
            },
            {
                "event": "response",
                "flow_id": "background-https",
                "status_code": 200,
                "attribution": "unattributed",
            },
        ],
    )

    findings = {item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)}

    assert findings["ASL-MVP-002"].status is FindingStatus.PASS
    assert findings["ASL-MVP-003"].status is FindingStatus.INCONCLUSIVE
    assert findings["ASL-MVP-005"].status is FindingStatus.INCONCLUSIVE
    assert findings["ASL-MVP-002"].details["unattributed_request_count"] == 2


def test_validation_canary_attribution_can_confirm_cleartext(tmp_path: Path) -> None:
    paths, repository, session_id = prepared_rule_session(tmp_path)
    write_traffic(
        paths,
        repository,
        session_id,
        [
            {
                "event": "request",
                "flow_id": "canary-http",
                "scheme": "http",
                "cleartext": True,
                "sensitive_query_keys": [],
                "attribution": "validation_canary",
                "canary_sink_types": ["http_header", "http_body"],
            }
        ],
    )

    findings = {item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)}

    assert findings["ASL-MVP-002"].status is FindingStatus.CONFIRMED
    assert findings["ASL-MVP-003"].status is FindingStatus.CONFIRMED
    assert findings["ASL-MVP-003"].details["exact_canary_flow_count"] == 1
    assert findings["ASL-MVP-003"].details["traffic_canary_sink_types"] == [
        "http_body",
        "http_header",
    ]


def test_sensitive_name_without_exact_canary_is_only_potential(tmp_path: Path) -> None:
    paths, repository, session_id = prepared_rule_session(tmp_path)
    write_traffic(
        paths,
        repository,
        session_id,
        [
            {
                "event": "request",
                "flow_id": "target-token-shape",
                "scheme": "https",
                "cleartext": False,
                "sensitive_query_keys": ["access_token"],
                "attribution": "target",
            }
        ],
    )

    finding = next(
        item
        for item in RuleEngine(paths, repository).evaluate(session_id)
        if item.rule_id == "ASL-MVP-003"
    )

    assert finding.status is FindingStatus.POTENTIAL
    assert finding.status is not FindingStatus.CONFIRMED
    assert finding.details["exact_canary_flow_count"] == 0
    assert "exact session canary" in finding.details["missing_evidence"][0]
