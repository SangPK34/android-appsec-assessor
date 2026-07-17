from __future__ import annotations

from types import SimpleNamespace

from mitmproxy import http

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


def _flow(host: str) -> SimpleNamespace:
    request = SimpleNamespace(
        pretty_url=f"https://{host}/path",
        pretty_host=host,
        method="GET",
        scheme="https",
        port=443,
        http_version="HTTP/2",
        headers=http.Headers(),
    )
    return SimpleNamespace(request=request, metadata={}, response=None, id="flow-1")


def test_mitm_blocks_hosts_outside_exact_scope_allowlist(monkeypatch) -> None:
    events: list[dict[str, object]] = []
    monkeypatch.setattr(
        mitm_capture.ctx,
        "options",
        SimpleNamespace(
            android_assessor_events="",
            android_assessor_canary="",
            android_assessor_allowed_hosts="10.0.2.2,api.lab.test",
        ),
        raising=False,
    )
    monkeypatch.setattr(mitm_capture, "_write", events.append)
    flow = _flow("external.example")

    mitm_capture.request(flow)  # type: ignore[arg-type]

    assert flow.response.status_code == 451
    assert events[0]["scope_allowed"] is False
    assert events[0]["blocked"] is True
    assert events[0]["attribution"] == "blocked_outside_scope"


def test_mitm_allows_exact_scoped_host(monkeypatch) -> None:
    events: list[dict[str, object]] = []
    monkeypatch.setattr(
        mitm_capture.ctx,
        "options",
        SimpleNamespace(
            android_assessor_events="",
            android_assessor_canary="",
            android_assessor_allowed_hosts="10.0.2.2",
        ),
        raising=False,
    )
    monkeypatch.setattr(mitm_capture, "_write", events.append)
    flow = _flow("10.0.2.2")

    mitm_capture.request(flow)  # type: ignore[arg-type]

    assert flow.response is None
    assert events[0]["scope_allowed"] is True
    assert events[0]["blocked"] is False
