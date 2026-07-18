"""Bounded mitmproxy addon that records metadata without HTTP bodies."""

from __future__ import annotations

import json
import re
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

_MAX_CANARY_BODY_SCAN_BYTES = 64 * 1024
_MAX_CANARY_HEADER_VALUE_CHARS = 4096
_MAX_CANARY_HEADERS = 100


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
    loader.add_option(  # type: ignore[attr-defined]
        "android_assessor_allowed_hosts",
        str,
        "",
        "Comma-separated exact host allowlist for outbound capture",
    )


def _headers(headers: http.Headers) -> dict[str, str]:
    values = redact_headers(headers.items(multi=True))
    canary = str(getattr(ctx.options, "android_assessor_canary", ""))
    if not canary:
        return values
    return {
        name: value.replace(canary, "<session-canary-redacted>")
        for name, value in values.items()
    }


def _sensitive_header_names(headers: http.Headers) -> list[str]:
    return sensitive_field_names(name for name, _value in headers.items(multi=True))


def _sensitive_query_names(value: str) -> list[str]:
    return sensitive_query_names(value)


def _url(value: str) -> str:
    redacted = redact_url(value)
    canary = str(getattr(ctx.options, "android_assessor_canary", ""))
    return (
        redacted.replace(canary, "<session-canary-redacted>")
        if canary
        else redacted
    )


def _contains_exact_canary(value: str, canary: str) -> bool:
    if not canary:
        return False
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(canary)}(?![A-Za-z0-9_])",
            value,
        )
    )


def _request_canary_metadata(request_value: http.Request) -> tuple[list[str], str]:
    canary = str(ctx.options.android_assessor_canary)
    if not canary:
        return [], "not_configured"
    sinks: list[str] = []
    try:
        if any(
            item == canary
            for _name, item in parse_qsl(
                urlsplit(request_value.pretty_url).query,
                keep_blank_values=True,
            )
        ):
            sinks.append("url_query")
    except ValueError:
        pass
    for _name, value in list(request_value.headers.items(multi=True))[
        :_MAX_CANARY_HEADERS
    ]:
        if len(value) <= _MAX_CANARY_HEADER_VALUE_CHARS and _contains_exact_canary(
            value,
            canary,
        ):
            sinks.append("http_header")
            break
    raw_content = getattr(request_value, "raw_content", None)
    if raw_content is None:
        body_scan_status = "unavailable"
    elif len(raw_content) > _MAX_CANARY_BODY_SCAN_BYTES:
        body_scan_status = "skipped_size_limit"
    else:
        body_scan_status = "completed"
        body_text = bytes(raw_content).decode("utf-8", errors="ignore")
        if _contains_exact_canary(body_text, canary):
            sinks.append("http_body")
    return sorted(set(sinks)), body_scan_status


def _allowed_hosts() -> frozenset[str]:
    configured = str(getattr(ctx.options, "android_assessor_allowed_hosts", ""))
    return frozenset(
        host.strip().casefold().rstrip(".")
        for host in configured.split(",")
        if host.strip()
    )


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
    request_host = request_value.pretty_host.casefold().rstrip(".")
    scope_allowed = request_host in _allowed_hosts()
    canary_sink_types, body_scan_status = (
        _request_canary_metadata(request_value)
        if scope_allowed
        else ([], "blocked_outside_scope")
    )
    attribution = (
        "validation_canary"
        if canary_sink_types
        else "unattributed"
        if scope_allowed
        else "blocked_outside_scope"
    )
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
            "canary_sink_types": canary_sink_types,
            "canary_body_scan_status": body_scan_status,
            "scope_allowed": scope_allowed,
            "blocked": not scope_allowed,
        }
    )
    if not scope_allowed:
        flow.response = http.Response.make(
            451,
            b"",
            {"content-type": "text/plain; charset=utf-8"},
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
