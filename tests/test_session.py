from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from android_assessor.paths import ProjectPaths
from android_assessor.session import (
    CleanupActionStatus,
    CleanupActionType,
    SessionRepository,
    SessionStatus,
)


def repository_for(tmp_path: Path) -> SessionRepository:
    paths = ProjectPaths(tmp_path / "Android Lab có dấu")
    paths.ensure_layout()
    return SessionRepository(paths)


def test_session_creation_builds_reproducible_layout(tmp_path: Path) -> None:
    repository = repository_for(tmp_path)

    record = repository.initialize(serial="ABC123456", package="com.example.app")
    paths = repository.paths_for(record.session_id)

    assert record.status is SessionStatus.INITIALIZING
    assert paths.session_json.is_file()
    assert paths.app_json.is_file()
    assert paths.findings_json.is_file()
    assert paths.events_jsonl.is_file()
    assert paths.commands_jsonl.is_file()
    assert paths.evidence_index.is_file()
    assert (paths.root / "raw" / "README.txt").is_file()
    assert (paths.root / "traffic").is_dir()
    assert repository.load(record.session_id) == record
    assert record.to_dict(show_serial=False)["serial"] != "ABC123456"


def test_session_activation_and_cleanup_ledger_are_persisted(tmp_path: Path) -> None:
    repository = repository_for(tmp_path)
    record = repository.initialize(serial="ABC123", package="com.example.app")
    active = repository.activate(
        record.session_id,
        snapshot={
            "http_proxy": None,
            "http_proxy_state": "CAPTURED_EMPTY",
            "http_proxy_error": None,
        },
        device={"model": "Pixel 4 XL"},
        environment={"ready": True},
    )

    action = repository.record_cleanup_action(
        active.session_id,
        CleanupActionType.REMOVE_REVERSE,
        {"remote": "tcp:8080"},
    )
    updated = repository.update_cleanup_action(
        active.session_id,
        action.action_id,
        status=CleanupActionStatus.COMPLETED,
    )
    loaded = repository.load(active.session_id)

    assert active.status is SessionStatus.ACTIVE
    assert updated.attempts == 1
    assert loaded.status is SessionStatus.CLEANUP_REQUIRED
    assert loaded.cleanup_actions[0].status is CleanupActionStatus.COMPLETED


def test_event_log_redacts_secrets(tmp_path: Path) -> None:
    repository = repository_for(tmp_path)
    record = repository.initialize(serial="ABC123", package="com.example.app")

    repository.append_event(
        record.session_id,
        "test_event",
        {"authorization": "Bearer thesis-secret"},
    )

    events = repository.paths_for(record.session_id).events_jsonl.read_text(encoding="utf-8")
    assert "thesis-secret" not in events
    assert "<redacted>" in events
    for line in events.splitlines():
        json.loads(line)


def test_concurrent_cleanup_ledger_updates_are_not_lost(tmp_path: Path) -> None:
    repository = repository_for(tmp_path)
    record = repository.initialize(serial="ABC123", package="com.example.app")

    def add_action(index: int) -> None:
        repository.record_cleanup_action(
            record.session_id,
            CleanupActionType.REMOVE_REVERSE,
            {
                "reverse_remote": f"tcp:{8000 + index}",
                "reverse_local": f"tcp:{8000 + index}",
                "ownership_state": "owned",
            },
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add_action, range(16)))

    actions = repository.load(record.session_id).cleanup_actions
    assert len(actions) == 16
    assert len({action.action_id for action in actions}) == 16
