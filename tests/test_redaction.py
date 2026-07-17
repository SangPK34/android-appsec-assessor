from __future__ import annotations

from android_assessor.redaction import (
    REDACTED,
    redact_arguments,
    redact_body_text,
    redact_data,
    redact_headers,
    redact_text,
    redact_url,
)


def test_redacts_common_http_secrets() -> None:
    value = (
        "Authorization: Bearer abc.def.ghi\n"
        "Cookie: session_id=secret-value\n"
        "GET /v1/object?api_key=topsecret&safe=yes"
    )

    redacted = redact_text(value)

    assert "abc.def.ghi" not in redacted
    assert "secret-value" not in redacted
    assert "topsecret" not in redacted
    assert REDACTED in redacted


def test_redacts_nested_sensitive_keys() -> None:
    value = {"user": {"email": "lab@example.com", "password": "canary"}, "safe": 3}

    redacted = redact_data(value)

    assert redacted["user"]["password"] == REDACTED
    assert redacted["user"]["email"] == REDACTED
    assert redacted["safe"] == 3


def test_redacts_explicit_sensitive_argument() -> None:
    result = redact_arguments(["--token", "exact-secret"], sensitive_values=["exact-secret"])

    assert result == ["--token", REDACTED]


def test_redacts_phone_without_hiding_tool_versions() -> None:
    value = "Call +84 912 345 678; fastboot version 37.0.0-13978923"

    redacted = redact_text(value)

    assert "+84 912 345 678" not in redacted
    assert "37.0.0-13978923" in redacted


def test_shared_redactor_handles_custom_headers_query_body_and_pii() -> None:
    headers = redact_headers(
        {
            "X-Lab-Credential": "custom-credential-value",
            "X-Custom-Token": "custom-token-value",
            "X-Contact": "lab.user@example.com +84 912 345 678",
        }
    )
    url = redact_url(
        "https://api.lab.local/item?credential=credential-query-value&safe=yes"
    )
    body = redact_body_text(
        'api_key="body-api-key" email=lab.user@example.com phone=+84912345678'
    )

    combined = f"{headers}\n{url}\n{body}"
    for secret in (
        "custom-credential-value",
        "custom-token-value",
        "credential-query-value",
        "body-api-key",
        "lab.user@example.com",
        "+84 912 345 678",
        "+84912345678",
    ):
        assert secret not in combined
    assert headers["X-Lab-Credential"] == REDACTED
