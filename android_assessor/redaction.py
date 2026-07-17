"""Shared conservative redaction for artifacts, logs, commands, and reports."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "<redacted>"

_SENSITIVE_NAME_PATTERN = re.compile(
    r"(?i)(?:^|[-_.])(?:authorization|auth|bearer|token|key|secret|credential|"
    r"password|passwd|cookie|session)(?:$|[-_.])"
)
_SENSITIVE_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "credential",
    "credentials",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "session",
    "session_id",
}
_REPORT_IDENTIFIER_KEYS = {
    "session",
    "session_id",
    "finding_id",
    "evidence_id",
    "related_findings",
    "validation_type",
    "root_used_in_session",
    "frida_used_in_session",
}
_AUTH_PATTERN = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"
)
_BEARER_PATTERN = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+")
_COOKIE_PATTERN = re.compile(r"(?i)\b((?:set-)?cookie\s*[:=]\s*)[^\r\n]+")
_JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"
)
_EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
_PHONE_PATTERN = re.compile(r"(?<![\w.])\+?\d(?:[\d ()-]{7,}\d)(?![\w.])")
_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<prefix>[\"']?(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,80})[\"']?\s*[:=]\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&#}\]]+)"
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?P<prefix>[\"']?[A-Za-z0-9_.-]*(?:authorization|auth|bearer|token|key|"
    r"secret|credential|password|passwd|cookie|session)[A-Za-z0-9_.-]*"
    r"[\"']?\s*[:=]\s*)(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&#}\]]+)"
)


def is_sensitive_name(value: str) -> bool:
    normalized = value.strip().casefold()
    return normalized in _SENSITIVE_KEYS or bool(_SENSITIVE_NAME_PATTERN.search(normalized))


def is_sensitive_header_name(value: str) -> bool:
    normalized = value.strip().casefold()
    fragments = (
        "authorization",
        "auth",
        "bearer",
        "token",
        "key",
        "secret",
        "credential",
        "password",
        "passwd",
        "cookie",
        "session",
    )
    return any(fragment in normalized for fragment in fragments)


def redact_text(value: str) -> str:
    redacted = _AUTH_PATTERN.sub(rf"\1{REDACTED}", value)
    redacted = _BEARER_PATTERN.sub(rf"\1{REDACTED}", redacted)
    redacted = _COOKIE_PATTERN.sub(rf"\1{REDACTED}", redacted)
    redacted = _JWT_PATTERN.sub(REDACTED, redacted)

    def redact_secret_assignment(match: re.Match[str]) -> str:
        value_text = match.group("value")
        quote = value_text[0] if value_text[:1] in {"'", '"'} else ""
        replacement = f"{quote}{REDACTED}{quote}" if quote else REDACTED
        return match.group("prefix") + replacement

    redacted = _SECRET_ASSIGNMENT_PATTERN.sub(redact_secret_assignment, redacted)

    def redact_assignment(match: re.Match[str]) -> str:
        if not is_sensitive_name(match.group("key")):
            return match.group(0)
        value_text = match.group("value")
        quote = value_text[0] if value_text[:1] in {"'", '"'} else ""
        replacement = f"{quote}{REDACTED}{quote}" if quote else REDACTED
        return match.group("prefix") + replacement

    redacted = _ASSIGNMENT_PATTERN.sub(redact_assignment, redacted)
    redacted = _EMAIL_PATTERN.sub(REDACTED, redacted)

    def redact_phone(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        return REDACTED if 9 <= len(digits) <= 15 else match.group(0)

    return _PHONE_PATTERN.sub(redact_phone, redacted)


def redact_text_with_values(value: str, sensitive_values: Sequence[str] = ()) -> str:
    redacted = value
    for secret in sorted((item for item in sensitive_values if item), key=len, reverse=True):
        redacted = redacted.replace(secret, REDACTED)
    return redact_text(redacted)


def redact_headers(
    headers: Mapping[str, str] | Iterable[tuple[str, str]],
) -> dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else headers
    return {
        str(name): REDACTED
        if is_sensitive_header_name(str(name))
        else redact_text(str(value))[:1000]
        for name, value in items
    }


def sensitive_field_names(names: Iterable[str]) -> list[str]:
    return sorted(
        {name.casefold() for name in names if is_sensitive_header_name(name)}
    )


def sensitive_query_names(value: str) -> list[str]:
    try:
        return sorted(
            {
                name.casefold()
                for name, _item in parse_qsl(
                    urlsplit(value).query,
                    keep_blank_values=True,
                )
                if is_sensitive_name(name)
            }
        )
    except ValueError:
        return []


def redact_url(value: str) -> str:
    try:
        split = urlsplit(value)
        query = urlencode(
            [
                (name, REDACTED if is_sensitive_name(name) else redact_text(item))
                for name, item in parse_qsl(split.query, keep_blank_values=True)
            ]
        )
        return urlunsplit(
            (
                split.scheme,
                split.netloc,
                redact_text(split.path),
                query,
                "",
            )
        )
    except ValueError:
        return "<invalid-url>"


def redact_body_text(value: str) -> str:
    return redact_text(value)


def redact_data(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_name(str(key)) else redact_data(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [redact_data(item) for item in value]
    return value


def redact_report_data(value: Any, *, _key: str | None = None) -> Any:
    if isinstance(value, str):
        return value if _key in _REPORT_IDENTIFIER_KEYS else redact_text(value)
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if name not in _REPORT_IDENTIFIER_KEYS and is_sensitive_name(name):
                output[name] = REDACTED
            else:
                output[name] = redact_report_data(item, _key=name)
        return output
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [redact_report_data(item, _key=_key) for item in value]
    return value


def redact_arguments(
    arguments: Sequence[str],
    sensitive_values: Sequence[str] = (),
) -> list[str]:
    secrets = {value for value in sensitive_values if value}
    output: list[str] = []
    redact_next = False
    for argument in arguments:
        if argument in secrets or redact_next:
            output.append(REDACTED)
            redact_next = False
            continue
        output.append(redact_text(argument))
        if argument.startswith("-") and is_sensitive_name(argument.lstrip("-")):
            redact_next = "=" not in argument
    return output
