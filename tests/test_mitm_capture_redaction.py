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
        raw_content=b"",
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


def test_mitm_attributes_exact_canary_in_query_header_and_bounded_body(
    monkeypatch,
) -> None:
    events: list[dict[str, object]] = []
    canary = "THESIS_CANARY_20260718T010203Z_abcdef123456"
    monkeypatch.setattr(
        mitm_capture.ctx,
        "options",
        SimpleNamespace(
            android_assessor_events="",
            android_assessor_canary=canary,
            android_assessor_allowed_hosts="10.0.2.2",
        ),
        raising=False,
    )
    monkeypatch.setattr(mitm_capture, "_write", events.append)
    flow = _flow("10.0.2.2")
    flow.request.port = 8888
    flow.request.scheme = "http"
    flow.request.pretty_url += f"?value={canary}"
    flow.request.headers = http.Headers(authorization=f"Bearer {canary}")
    flow.request.raw_content = f"value={canary}&kind=lab".encode()

    mitm_capture.request(flow)  # type: ignore[arg-type]

    event = events[0]
    assert event["attribution"] == "validation_canary"
    assert event["canary_sink_types"] == ["http_body", "http_header", "url_query"]
    assert event["canary_body_scan_status"] == "completed"
    assert canary not in str(event)


def test_mitm_rejects_canary_shape_and_skips_oversized_body(monkeypatch) -> None:
    events: list[dict[str, object]] = []
    canary = "THESIS_CANARY_20260718T010203Z_abcdef123456"
    monkeypatch.setattr(
        mitm_capture.ctx,
        "options",
        SimpleNamespace(
            android_assessor_events="",
            android_assessor_canary=canary,
            android_assessor_allowed_hosts="10.0.2.2",
        ),
        raising=False,
    )
    monkeypatch.setattr(mitm_capture, "_write", events.append)
    flow = _flow("10.0.2.2")
    flow.request.pretty_url += f"?value=x{canary}"
    flow.request.headers = http.Headers(x_lab=f"{canary}x")
    flow.request.raw_content = (
        canary.encode()
        + b"x"
        + b"0" * mitm_capture._MAX_CANARY_BODY_SCAN_BYTES
    )

    mitm_capture.request(flow)  # type: ignore[arg-type]

    event = events[0]
    assert event["attribution"] == "unattributed"
    assert event["canary_sink_types"] == []
    assert event["canary_body_scan_status"] == "skipped_size_limit"


def test_mitm_attributes_owned_fixture_value_by_fingerprint_without_leaking_raw(
    monkeypatch,
) -> None:
    events: list[dict[str, object]] = []
    secret = "fixture-owned-password"
    fingerprint = "b" * 64
    monkeypatch.setenv(
        "ANDROID_ASSESSOR_OWNED_VALUES",
        f'{{"{fingerprint}":"{secret}"}}',
    )
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
    flow.request.pretty_url += f"?password={secret}"
    flow.request.raw_content = f"username=fixture&password={secret}".encode()

    mitm_capture.request(flow)  # type: ignore[arg-type]

    event = events[0]
    assert event["attribution"] == "scenario_owned_value"
    assert event["owned_value_fingerprints"] == [fingerprint]
    assert event["owned_value_sink_types"] == {
        fingerprint: ["http_body", "url_query"]
    }
    assert secret not in str(event)


def test_mitm_maps_declared_scoped_local_backend_without_changing_attribution_host(
    monkeypatch,
) -> None:
    events: list[dict[str, object]] = []
    monkeypatch.setenv(
        "ANDROID_ASSESSOR_UPSTREAM_MAP",
        '{"10.0.2.2:8888":"127.0.0.1:8888"}',
    )
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
    flow.request.port = 8888
    flow.request.scheme = "http"

    mitm_capture.request(flow)  # type: ignore[arg-type]

    event = events[0]
    assert event["host"] == "10.0.2.2"
    assert event["backend_id"] == "10.0.2.2:8888"
    assert event["backend_scope"] == "scoped_local"
    assert flow.request.host == "127.0.0.1"
    assert flow.request.port == 8888
