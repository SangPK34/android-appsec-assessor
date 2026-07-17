"""Bounded mitmproxy addon that records metadata without HTTP bodies."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from mitmproxy import ctx, http

from android_assessor.redaction import (
    redact_data,
    redact_headers,
    redact_url,
    sensitive_field_names,
    sensitive_query_names,
)


def load(loader: object) -> None:
    loader.add_option(  # type: ignore[attr-defined]
        "android_assessor_events",
        str,
        "",
        "AndroidSecurityLab JSONL event output path",
    )
    loader.add_option(  # type: ignore[attr-defined]
        "android_assessor_canary",
        str,
        "",
        "Unique controlled-validation canary used for conservative attribution",
    )


def _headers(headers: http.Headers) -> dict[str, str]:
    return redact_headers(headers.items(multi=True))


def _sensitive_header_names(headers: http.Headers) -> list[str]:
    return sensitive_field_names(name for name, _value in headers.items(multi=True))


def _sensitive_query_names(value: str) -> list[str]:
    return sensitive_query_names(value)


def _url(value: str) -> str:
    return redact_url(value)


def _attribution(value: str) -> str:
    canary = str(ctx.options.android_assessor_canary)
    if not canary:
        return "unattributed"
    try:
        if any(
            item == canary
            for _name, item in parse_qsl(urlsplit(value).query, keep_blank_values=True)
        ):
            return "validation_canary"
    except ValueError:
        pass
    return "unattributed"


def _write(payload: dict[str, object]) -> None:
    output = str(ctx.options.android_assessor_events)
    if not output:
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload["timestamp"] = datetime.now(UTC).isoformat()
    redacted_payload = redact_data(payload)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(redacted_payload, ensure_ascii=False) + "\n")


def request(flow: http.HTTPFlow) -> None:
    request_value = flow.request
    attribution = _attribution(request_value.pretty_url)
    flow.metadata["android_assessor_attribution"] = attribution
    _write(
        {
            "event": "request",
            "flow_id": flow.id,
            "method": request_value.method,
            "scheme": request_value.scheme,
            "host": request_value.pretty_host,
            "port": request_value.port,
            "url": _url(request_value.pretty_url),
            "sensitive_query_keys": _sensitive_query_names(request_value.pretty_url),
            "http_version": request_value.http_version,
            "headers": _headers(request_value.headers),
            "sensitive_headers_present": _sensitive_header_names(
                request_value.headers
            ),
            "cleartext": request_value.scheme.casefold() == "http",
            "attribution": attribution,
        }
    )


def response(flow: http.HTTPFlow) -> None:
    if flow.response is None:
        return
    _write(
        {
            "event": "response",
            "flow_id": flow.id,
            "status_code": flow.response.status_code,
            "content_type": flow.response.headers.get("content-type", "")[:300],
            "headers": _headers(flow.response.headers),
            "sensitive_headers_present": _sensitive_header_names(
                flow.response.headers
            ),
            "attribution": str(
                flow.metadata.get("android_assessor_attribution", "unattributed")
            ),
        }
    )


def error(flow: http.HTTPFlow) -> None:
    _write(
        {
            "event": "error",
            "flow_id": flow.id,
            "error": str(flow.error)[:1000],
        }
    )
