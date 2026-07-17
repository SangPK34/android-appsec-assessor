from __future__ import annotations

from types import SimpleNamespace

from hooks import mitm_capture


def test_mitm_event_is_redacted_before_first_write(tmp_path, monkeypatch) -> None:
    output = tmp_path / "redacted" / "traffic" / "events.jsonl"
    monkeypatch.setattr(
        mitm_capture.ctx,
        "options",
        SimpleNamespace(android_assessor_events=str(output)),
        raising=False,
    )
    secrets = (
        "fixture-bearer-secret",
        "fixture@example.invalid",
        "fixture-query-credential",
    )

    mitm_capture._write(
        {
            "event": "error",
            "error": (
                f"Authorization: Bearer {secrets[0]} "
                f"email={secrets[1]} credential={secrets[2]}"
            ),
            "custom_token": "fixture-custom-token",
        }
    )

    serialized = output.read_text(encoding="utf-8")
    assert all(secret not in serialized for secret in secrets)
    assert "fixture-custom-token" not in serialized
    assert "<redacted>" in serialized
