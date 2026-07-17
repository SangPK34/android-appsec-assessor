"""Bounded, read-only static inventory for pulled Android APK artifacts."""

from __future__ import annotations

import hashlib
import re
import struct
import zlib
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZipInfo

from .redaction import (
    REDACTED,
    is_sensitive_name,
    redact_text,
    redact_text_with_values,
)

_DEX_MAGIC = re.compile(rb"^dex\n\d{3}\x00$")
_DEX_HEADER_SIZE = 0x70
_DEX_ENDIAN_CONSTANT = 0x12345678
_DEX_REVERSE_ENDIAN_CONSTANT = 0x78563412
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
_ZIP_EOCD = struct.Struct("<4s4H2LH")
_ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3I5H2I")
_ZIP_MAX_COMMENT_BYTES = 0xFFFF
_CLASS_DESCRIPTOR = re.compile(r"^L[0-9A-Za-z_$/-]+;$")
_ROOT_DEX = re.compile(r"^classes(?:[2-9]|[1-9][0-9]+)?\.dex$")
_TEXT_SUFFIXES = frozenset(
    {
        ".cfg",
        ".conf",
        ".gradle",
        ".htm",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".key",
        ".kt",
        ".pem",
        ".properties",
        ".sh",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
_EMBEDDED_CODE_SUFFIXES = frozenset({".apk", ".dex", ".jar", ".so"})
_URL_PATTERN = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\x00<>\"'\\]+")
_PRIVATE_KEY_HEADER_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)
_ASSIGNED_SECRET_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<key_quote>[\"']?)"
    r"(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,80}"
    r"(?:authorization|auth|bearer|token|key|secret|credential|password|passwd|"
    r"cookie|session)[A-Za-z0-9_.-]{0,80})"
    r"(?P=key_quote)\s*[:=]\s*(?P<value_quote>[\"']?)"
    r"(?P<value>[^\s\"',;&#}\]]{6,512})(?P=value_quote)"
)
_KNOWN_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "high"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "low"),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\."
            r"[A-Za-z0-9_-]{6,}\b"
        ),
        "high",
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{12,})"),
        "high",
    ),
)
_PLACEHOLDER_TOKENS = frozenset(
    {
        "canary",
        "changeme",
        "dummy",
        "example",
        "fake",
        "fixture",
        "placeholder",
        "redacted",
        "sample",
        "test",
        "todo",
    }
)
_PLACEHOLDER_EXACT = frozenset(
    {
        "api_key",
        "apikey",
        "change_me",
        "client_secret",
        "password",
        "secret",
        "session_canary",
        "thesis_canary",
        "token",
    }
)
_PLACEHOLDER_PREFIXES = (
    "${",
    "{{",
    "<",
    "your_",
    "your-",
)
_LEGACY_PLACEHOLDER_TERMS = (
    "changeme",
    "session_canary",
    "thesis_canary",
)
_SENSITIVE_ASSIGNMENT_TOKENS = frozenset(
    {
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
    }
)
_SENSITIVE_ASSIGNMENT_ALIASES = frozenset(
    {
        "apikey",
        "accesstoken",
        "refreshtoken",
        "clientsecret",
        "clientcredential",
        "privatekey",
        "secretkey",
        "sessionid",
    }
)


class StaticApkAnalysisError(ValueError):
    """Raised when an APK or DEX structure cannot be inspected safely."""


class DexFormatError(StaticApkAnalysisError):
    """Raised for malformed or unsupported DEX structures."""


class _ArchivePreflightError(StaticApkAnalysisError):
    def __init__(
        self,
        category: str,
        *,
        limit_name: str | None = None,
        observed: int | None = None,
    ) -> None:
        super().__init__(category)
        self.category = category
        self.limit_name = limit_name
        self.observed = observed


def _is_class_descriptor(value: str) -> bool:
    return len(value) <= 1000 and bool(_CLASS_DESCRIPTOR.fullmatch(value))


def _is_type_descriptor(value: str, *, allow_void: bool = True) -> bool:
    if value in ({"V", "Z", "B", "S", "C", "I", "J", "F", "D"} if allow_void else {
        "Z",
        "B",
        "S",
        "C",
        "I",
        "J",
        "F",
        "D",
    }):
        return True
    dimensions = len(value) - len(value.lstrip("["))
    if dimensions:
        return dimensions <= 255 and _is_type_descriptor(
            value[dimensions:],
            allow_void=False,
        )
    return _is_class_descriptor(value)


def _is_reference_descriptor(value: str) -> bool:
    return _is_class_descriptor(value) or (
        value.startswith("[") and _is_type_descriptor(value, allow_void=False)
    )


@dataclass(frozen=True, slots=True)
class StaticApkPolicy:
    """Hard resource bounds for deterministic APK inspection."""

    max_apks: int = 32
    max_apk_file_bytes: int = 256 * 1024 * 1024
    max_archive_entries: int = 10_000
    max_central_directory_bytes: int = 16 * 1024 * 1024
    max_total_uncompressed_bytes: int = 128 * 1024 * 1024
    max_entry_uncompressed_bytes: int = 64 * 1024 * 1024
    max_dex_bytes: int = 64 * 1024 * 1024
    max_text_entry_bytes: int = 1024 * 1024
    max_compression_ratio: int = 200
    max_dex_files: int = 64
    max_dex_strings: int = 250_000
    max_method_references: int = 200_000
    max_dex_string_work_bytes: int = 64 * 1024 * 1024
    max_dex_parameter_references: int = 1_000_000
    max_dex_prototype_bytes: int = 16 * 1024 * 1024
    max_string_bytes: int = 4096
    max_resource_strings: int = 50_000
    max_secret_candidates: int = 500
    max_endpoints: int = 500
    max_dynamic_api_matches: int = 500
    max_policy_api_matches: int = 500
    max_embedded_code_entries: int = 500

    def __post_init__(self) -> None:
        numeric_values = asdict(self)
        if any(not isinstance(value, int) or value < 1 for value in numeric_values.values()):
            raise ValueError("Static APK analysis limits must be positive integers.")
        if self.max_string_bytes > self.max_text_entry_bytes:
            raise ValueError("Static string limit may not exceed the text-entry limit.")
        if self.max_text_entry_bytes > self.max_entry_uncompressed_bytes:
            raise ValueError("Text-entry limit may not exceed the general entry limit.")
        if self.max_dex_bytes > self.max_entry_uncompressed_bytes:
            raise ValueError("DEX limit may not exceed the general entry limit.")
        if self.max_dex_bytes > self.max_total_uncompressed_bytes:
            raise ValueError("DEX limit may not exceed the total uncompressed-byte limit.")


@dataclass(frozen=True, slots=True)
class StaticApkInput:
    path: Path
    source_id: str
    resource_strings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.source_id or len(self.source_id) > 240:
            raise ValueError("Static APK source identifier is invalid.")
        if any(value in self.source_id for value in ("\x00", "\r", "\n")):
            raise ValueError("Static APK source identifier contains control characters.")


@dataclass(frozen=True, slots=True)
class ApiPolicyEntry:
    policy_id: str
    class_descriptor: str
    method_name: str
    disposition: str
    rationale: str
    deprecated_since: int | None = None
    prototype: str | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9_.-]{1,79}", self.policy_id):
            raise ValueError("Static API policy identifier is invalid.")
        if not _is_class_descriptor(self.class_descriptor):
            raise ValueError("Static API policy class descriptor is invalid.")
        if not self.method_name or len(self.method_name) > 200:
            raise ValueError("Static API policy method name is invalid.")
        if self.disposition not in {"banned", "deprecated"}:
            raise ValueError("Static API policy disposition is invalid.")
        if not self.rationale or len(self.rationale) > 500:
            raise ValueError("Static API policy rationale is invalid.")
        if self.deprecated_since is not None and not 1 <= self.deprecated_since <= 10_000:
            raise ValueError("Static API deprecation level is invalid.")


DEFAULT_API_POLICY: tuple[ApiPolicyEntry, ...] = (
    ApiPolicyEntry(
        policy_id="ANDROID-WEBSETTINGS-SAVE-PASSWORD",
        class_descriptor="Landroid/webkit/WebSettings;",
        method_name="setSavePassword",
        disposition="deprecated",
        deprecated_since=18,
        rationale="Android deprecated WebView password saving in API level 18.",
    ),
    ApiPolicyEntry(
        policy_id="ANDROID-WEBSETTINGS-SAVE-FORM-DATA",
        class_descriptor="Landroid/webkit/WebSettings;",
        method_name="setSaveFormData",
        disposition="deprecated",
        deprecated_since=26,
        rationale="Android deprecated WebView form-data saving in API level 26.",
    ),
    ApiPolicyEntry(
        policy_id="ANDROID-ACTIVITYMANAGER-RUNNING-TASKS",
        class_descriptor="Landroid/app/ActivityManager;",
        method_name="getRunningTasks",
        disposition="deprecated",
        deprecated_since=21,
        rationale="Android deprecated unrestricted running-task inspection in API level 21.",
    ),
    ApiPolicyEntry(
        policy_id="JAVA-THREAD-STOP",
        class_descriptor="Ljava/lang/Thread;",
        method_name="stop",
        disposition="banned",
        rationale="The policy forbids asynchronous Thread.stop termination.",
    ),
)


@dataclass(frozen=True, slots=True)
class DexMethodReference:
    class_descriptor: str
    method_name: str
    prototype: str


@dataclass(frozen=True, slots=True)
class DexInventory:
    strings: tuple[str | None, ...]
    method_references: tuple[DexMethodReference, ...]
    oversized_strings: int


@dataclass(frozen=True, slots=True)
class SecretCandidate:
    kind: str
    confidence: str
    source_id: str
    location: str
    key_name: str | None
    value_sha256: str
    value_length: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EndpointCandidate:
    source_id: str
    location: str
    scheme: str
    host: str
    port: int | None
    redacted_url: str
    value_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ApiInventoryMatch:
    inventory_id: str
    category: str
    source_id: str
    dex_entry: str
    class_descriptor: str
    method_name: str
    prototype: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ApiPolicyMatch:
    policy_id: str
    disposition: str
    source_id: str
    dex_entry: str
    class_descriptor: str
    method_name: str
    prototype: str
    deprecated_since: int | None
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EmbeddedCodeEntry:
    source_id: str
    archive_entry: str
    kind: str
    size_bytes: int
    compressed_size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class StaticApkAnalysisResult:
    status: str
    sources: tuple[str, ...]
    secret_candidates: tuple[SecretCandidate, ...]
    endpoints: tuple[EndpointCandidate, ...]
    dynamic_loading_apis: tuple[ApiInventoryMatch, ...]
    api_policy_matches: tuple[ApiPolicyMatch, ...]
    embedded_code: tuple[EmbeddedCodeEntry, ...]
    limitations: tuple[str, ...]
    metrics: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": self.status,
            "sources": list(self.sources),
            "secret_candidates": [item.to_dict() for item in self.secret_candidates],
            "endpoints": [item.to_dict() for item in self.endpoints],
            "dynamic_loading_apis": [
                item.to_dict() for item in self.dynamic_loading_apis
            ],
            "api_policy_matches": [item.to_dict() for item in self.api_policy_matches],
            "embedded_code": [item.to_dict() for item in self.embedded_code],
            "limitations": list(self.limitations),
            "metrics": dict(self.metrics),
        }


@dataclass(slots=True)
class _Collector:
    policy: StaticApkPolicy
    api_policy: tuple[ApiPolicyEntry, ...]
    secrets: list[SecretCandidate] = field(default_factory=list)
    endpoints: list[EndpointCandidate] = field(default_factory=list)
    dynamic: list[ApiInventoryMatch] = field(default_factory=list)
    policy_matches: list[ApiPolicyMatch] = field(default_factory=list)
    embedded: list[EmbeddedCodeEntry] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    metrics: dict[str, int] = field(
        default_factory=lambda: {
            "apks_seen": 0,
            "apks_scanned": 0,
            "archive_entries_seen": 0,
            "archive_entries_scanned": 0,
            "central_directory_bytes": 0,
            "bytes_read": 0,
            "dex_files_scanned": 0,
            "dex_strings_scanned": 0,
            "dex_method_references": 0,
            "resource_strings_scanned": 0,
            "text_entries_scanned": 0,
        }
    )
    secret_keys: set[tuple[str, str, str]] = field(default_factory=set)
    endpoint_keys: set[tuple[str, str]] = field(default_factory=set)
    dynamic_keys: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    policy_keys: set[tuple[str, str, str, str]] = field(default_factory=set)
    embedded_keys: set[tuple[str, str]] = field(default_factory=set)
    source_sensitive_values: dict[str, list[str]] = field(default_factory=dict)
    total_declared_bytes: int = 0

    def limit(self, name: str) -> None:
        message = f"limit:{name}"
        if message not in self.limitations:
            self.limitations.append(message)

    def problem(self, source_id: str, category: str) -> None:
        message = f"{source_id}:{category}"
        if message not in self.limitations:
            self.limitations.append(message)


_DYNAMIC_API_PATTERNS: tuple[tuple[str, str, str, frozenset[str]], ...] = (
    (
        "DEX_CLASS_LOADER",
        "dex_loading",
        "Ldalvik/system/DexClassLoader;",
        frozenset({"<init>", "loadClass"}),
    ),
    (
        "IN_MEMORY_DEX_CLASS_LOADER",
        "dex_loading",
        "Ldalvik/system/InMemoryDexClassLoader;",
        frozenset({"<init>", "loadClass"}),
    ),
    (
        "PATH_CLASS_LOADER",
        "dex_loading",
        "Ldalvik/system/PathClassLoader;",
        frozenset({"<init>", "loadClass"}),
    ),
    (
        "DEX_FILE",
        "dex_loading",
        "Ldalvik/system/DexFile;",
        frozenset({"loadClass", "loadDex"}),
    ),
    (
        "CLASS_LOADER",
        "class_loading",
        "Ljava/lang/ClassLoader;",
        frozenset({"loadClass"}),
    ),
    (
        "CLASS_FOR_NAME",
        "reflection",
        "Ljava/lang/Class;",
        frozenset({"forName"}),
    ),
    (
        "REFLECTIVE_METHOD_INVOKE",
        "reflection",
        "Ljava/lang/reflect/Method;",
        frozenset({"invoke"}),
    ),
    (
        "SYSTEM_NATIVE_LOAD",
        "native_loading",
        "Ljava/lang/System;",
        frozenset({"load", "loadLibrary"}),
    ),
    (
        "RUNTIME_NATIVE_LOAD",
        "native_loading",
        "Ljava/lang/Runtime;",
        frozenset({"load", "loadLibrary"}),
    ),
)


def _uint32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise DexFormatError("DEX integer is outside the file bounds.")
    return struct.unpack_from("<I", data, offset)[0]


def _validate_table(
    data: bytes,
    *,
    name: str,
    size: int,
    offset: int,
    item_size: int,
    maximum: int,
) -> None:
    if size > maximum:
        raise DexFormatError(f"DEX {name} count exceeds the configured limit.")
    if size == 0:
        if offset != 0:
            raise DexFormatError(f"Empty DEX {name} table has a nonzero offset.")
        return
    if (
        offset < _DEX_HEADER_SIZE
        or offset % 4
        or offset + size * item_size > len(data)
    ):
        raise DexFormatError(f"DEX {name} table is outside the file bounds.")


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    decoded = 0
    for index in range(5):
        position = offset + index
        if position >= len(data):
            raise DexFormatError("DEX ULEB128 value is truncated.")
        value = data[position]
        decoded |= (value & 0x7F) << (index * 7)
        if not value & 0x80:
            if index == 4 and value > 0x0F:
                raise DexFormatError("DEX ULEB128 value overflows 32 bits.")
            return decoded, position + 1
    raise DexFormatError("DEX ULEB128 value is malformed.")


def _read_dex_string(
    data: bytes,
    offset: int,
    *,
    max_string_bytes: int,
) -> tuple[str | None, bool, int]:
    if offset < _DEX_HEADER_SIZE or offset >= len(data):
        raise DexFormatError("DEX string data offset is outside the file bounds.")
    declared_length, start = _read_uleb128(data, offset)
    search_end = min(len(data), start + max_string_bytes + 1)
    end = data.find(b"\x00", start, search_end)
    if end < 0:
        return None, True, max(0, search_end - start)
    raw = data[start:end]
    code_units: list[int] = []
    position = 0
    while position < len(raw):
        first = raw[position]
        if 0x01 <= first <= 0x7F:
            code_units.append(first)
            position += 1
            continue
        if 0xC0 <= first <= 0xDF and position + 1 < len(raw):
            second = raw[position + 1]
            if second & 0xC0 != 0x80:
                raise DexFormatError("DEX string contains malformed MUTF-8.")
            code_unit = ((first & 0x1F) << 6) | (second & 0x3F)
            if code_unit < 0x80 and code_unit != 0:
                raise DexFormatError("DEX string contains overlong MUTF-8.")
            code_units.append(code_unit)
            position += 2
            continue
        if 0xE0 <= first <= 0xEF and position + 2 < len(raw):
            second, third = raw[position + 1], raw[position + 2]
            if second & 0xC0 != 0x80 or third & 0xC0 != 0x80:
                raise DexFormatError("DEX string contains malformed MUTF-8.")
            code_unit = (
                ((first & 0x0F) << 12)
                | ((second & 0x3F) << 6)
                | (third & 0x3F)
            )
            if code_unit < 0x800:
                raise DexFormatError("DEX string contains overlong MUTF-8.")
            code_units.append(code_unit)
            position += 3
            continue
        raise DexFormatError("DEX string contains unsupported MUTF-8.")
    if len(code_units) != declared_length:
        raise DexFormatError("DEX string length metadata is inconsistent.")
    encoded_units = b"".join(struct.pack("<H", item) for item in code_units)
    decoded = encoded_units.decode("utf-16-le", errors="surrogatepass")
    return decoded, False, len(raw)


def parse_dex_inventory(
    data: bytes,
    *,
    policy: StaticApkPolicy | None = None,
) -> DexInventory:
    """Parse bounded DEX strings and exact method-id references in memory."""

    limits = policy or StaticApkPolicy()
    if len(data) < _DEX_HEADER_SIZE or len(data) > limits.max_dex_bytes:
        raise DexFormatError("DEX size is outside the configured bounds.")
    if not _DEX_MAGIC.fullmatch(data[:8]):
        raise DexFormatError("DEX magic is invalid or unsupported.")
    file_size = _uint32(data, 0x20)
    header_size = _uint32(data, 0x24)
    endian_tag = _uint32(data, 0x28)
    if file_size != len(data) or header_size != _DEX_HEADER_SIZE:
        raise DexFormatError("DEX header size metadata is inconsistent.")
    if endian_tag == _DEX_REVERSE_ENDIAN_CONSTANT:
        raise DexFormatError("Reverse-endian DEX files are unsupported.")
    if endian_tag != _DEX_ENDIAN_CONSTANT:
        raise DexFormatError("DEX endian tag is invalid.")

    string_count, string_offset = _uint32(data, 0x38), _uint32(data, 0x3C)
    type_count, type_offset = _uint32(data, 0x40), _uint32(data, 0x44)
    proto_count, proto_offset = _uint32(data, 0x48), _uint32(data, 0x4C)
    method_count, method_offset = _uint32(data, 0x58), _uint32(data, 0x5C)
    _validate_table(
        data,
        name="string-id",
        size=string_count,
        offset=string_offset,
        item_size=4,
        maximum=limits.max_dex_strings,
    )
    _validate_table(
        data,
        name="type-id",
        size=type_count,
        offset=type_offset,
        item_size=4,
        maximum=limits.max_dex_strings,
    )
    _validate_table(
        data,
        name="proto-id",
        size=proto_count,
        offset=proto_offset,
        item_size=12,
        maximum=limits.max_method_references,
    )
    _validate_table(
        data,
        name="method-id",
        size=method_count,
        offset=method_offset,
        item_size=8,
        maximum=limits.max_method_references,
    )

    strings: list[str | None] = []
    string_cache: dict[int, tuple[str | None, bool, int]] = {}
    string_work_bytes = 0
    oversized = 0
    for index in range(string_count):
        data_offset = _uint32(data, string_offset + index * 4)
        cached = string_cache.get(data_offset)
        if cached is None:
            cached = _read_dex_string(
                data,
                data_offset,
                max_string_bytes=limits.max_string_bytes,
            )
            string_work_bytes += cached[2]
            if string_work_bytes > limits.max_dex_string_work_bytes:
                raise DexFormatError("DEX string decode work exceeds the configured limit.")
            string_cache[data_offset] = cached
        value, was_oversized, _work_bytes = cached
        oversized += int(was_oversized)
        strings.append(value)

    types: list[str | None] = []
    for index in range(type_count):
        string_index = _uint32(data, type_offset + index * 4)
        if string_index >= string_count:
            raise DexFormatError("DEX type-id references an invalid string index.")
        descriptor = strings[string_index]
        if descriptor is not None and not _is_type_descriptor(descriptor):
            raise DexFormatError("DEX type-id descriptor is malformed.")
        types.append(descriptor)

    prototypes: list[str | None] = []
    parameter_cache: dict[int, tuple[tuple[str, ...], bool]] = {0: ((), False)}
    prototype_cache: dict[tuple[int, int], str | None] = {}
    decoded_parameter_references = 0
    prototype_bytes = 0
    for index in range(proto_count):
        base = proto_offset + index * 12
        shorty_index = _uint32(data, base)
        return_index = _uint32(data, base + 4)
        parameters_offset = _uint32(data, base + 8)
        if shorty_index >= string_count or return_index >= type_count:
            raise DexFormatError("DEX proto-id references an invalid index.")
        prototype_key = (return_index, parameters_offset)
        if prototype_key in prototype_cache:
            prototypes.append(prototype_cache[prototype_key])
            continue
        cached_parameters = parameter_cache.get(parameters_offset)
        if cached_parameters is None:
            if (
                parameters_offset < _DEX_HEADER_SIZE
                or parameters_offset % 4
                or parameters_offset + 4 > len(data)
            ):
                raise DexFormatError("DEX proto parameter list is outside file bounds.")
            parameter_count = _uint32(data, parameters_offset)
            if parameter_count > limits.max_method_references:
                raise DexFormatError("DEX proto parameter count exceeds the limit.")
            if (
                decoded_parameter_references + parameter_count
                > limits.max_dex_parameter_references
            ):
                raise DexFormatError(
                    "DEX aggregate parameter decode work exceeds the configured limit."
                )
            end = parameters_offset + 4 + parameter_count * 2
            if end > len(data):
                raise DexFormatError("DEX proto parameter list is truncated.")
            parameters: list[str] = []
            unresolved_parameters = False
            for position in range(parameter_count):
                type_index = struct.unpack_from(
                    "<H", data, parameters_offset + 4 + position * 2
                )[0]
                if type_index >= type_count:
                    raise DexFormatError("DEX proto parameter has an invalid type index.")
                value = types[type_index]
                if value == "V":
                    raise DexFormatError("DEX proto parameter may not have void type.")
                unresolved_parameters = unresolved_parameters or value is None
                if value is not None:
                    parameters.append(value)
            decoded_parameter_references += parameter_count
            cached_parameters = (tuple(parameters), unresolved_parameters)
            parameter_cache[parameters_offset] = cached_parameters
        parameters, unresolved_parameters = cached_parameters
        return_type = types[return_index]
        prototype = (
            None
            if unresolved_parameters or return_type is None
            else f"({''.join(parameters)}){return_type}"
        )
        if prototype is not None:
            prototype_bytes += len(prototype)
            if prototype_bytes > limits.max_dex_prototype_bytes:
                raise DexFormatError(
                    "DEX aggregate prototype decode work exceeds the configured limit."
                )
        prototype_cache[prototype_key] = prototype
        prototypes.append(prototype)

    methods: list[DexMethodReference] = []
    for index in range(method_count):
        base = method_offset + index * 8
        class_index, proto_index, name_index = struct.unpack_from("<HHI", data, base)
        if (
            class_index >= type_count
            or proto_index >= proto_count
            or name_index >= string_count
        ):
            raise DexFormatError("DEX method-id references an invalid index.")
        class_descriptor = types[class_index]
        method_name = strings[name_index]
        prototype = prototypes[proto_index]
        if class_descriptor is None or method_name is None or prototype is None:
            continue
        if not _is_reference_descriptor(class_descriptor):
            raise DexFormatError("DEX method class descriptor is malformed.")
        if not method_name or len(method_name) > 200:
            raise DexFormatError("DEX method name is malformed.")
        methods.append(
            DexMethodReference(
                class_descriptor=class_descriptor,
                method_name=method_name,
                prototype=prototype,
            )
        )
    return DexInventory(
        strings=tuple(strings),
        method_references=tuple(methods),
        oversized_strings=oversized,
    )


def _valid_archive_name(name: str) -> bool:
    if not name or len(name) > 500 or "\x00" in name or "\\" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _preflight_zip_archive(path: Path, policy: StaticApkPolicy) -> tuple[int, int]:
    """Validate a bounded, single-disk non-ZIP64 central directory before ZipFile."""

    file_size = path.stat().st_size
    tail_size = min(file_size, _ZIP_EOCD.size + _ZIP_MAX_COMMENT_BYTES)
    with path.open("rb") as handle:
        handle.seek(file_size - tail_size)
        tail = handle.read(tail_size)
        eocd_tail_offset = tail.rfind(_ZIP_EOCD_SIGNATURE)
        if eocd_tail_offset < 0 or eocd_tail_offset + _ZIP_EOCD.size > len(tail):
            raise _ArchivePreflightError("invalid_zip_eocd")
        eocd_offset = file_size - tail_size + eocd_tail_offset
        values = _ZIP_EOCD.unpack_from(tail, eocd_tail_offset)
        (
            _signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_size,
        ) = values
        if eocd_offset + _ZIP_EOCD.size + comment_size != file_size:
            raise _ArchivePreflightError("invalid_zip_eocd")
        locator_offset = eocd_offset - 20
        if locator_offset >= 0:
            handle.seek(locator_offset)
            if handle.read(4) == _ZIP64_LOCATOR_SIGNATURE:
                raise _ArchivePreflightError("zip64_unsupported")
        if (
            total_entries == 0xFFFF
            or disk_entries == 0xFFFF
            or central_size == 0xFFFFFFFF
            or central_offset == 0xFFFFFFFF
        ):
            raise _ArchivePreflightError("zip64_unsupported")
        if disk_number or central_disk or disk_entries != total_entries:
            raise _ArchivePreflightError("multidisk_zip_unsupported")
        if total_entries > policy.max_archive_entries:
            raise _ArchivePreflightError(
                "archive_entries",
                limit_name="archive_entries",
                observed=total_entries,
            )
        if central_size > policy.max_central_directory_bytes:
            raise _ArchivePreflightError(
                "central_directory_bytes",
                limit_name="central_directory_bytes",
                observed=central_size,
            )
        if (
            central_offset > eocd_offset
            or central_size > eocd_offset - central_offset
            or total_entries * _ZIP_CENTRAL_HEADER.size > central_size
        ):
            raise _ArchivePreflightError("invalid_central_directory")

        handle.seek(central_offset)
        remaining = central_size
        counted_entries = 0
        while remaining:
            if remaining < _ZIP_CENTRAL_HEADER.size:
                raise _ArchivePreflightError("invalid_central_directory")
            header = handle.read(_ZIP_CENTRAL_HEADER.size)
            if len(header) != _ZIP_CENTRAL_HEADER.size:
                raise _ArchivePreflightError("invalid_central_directory")
            fields = _ZIP_CENTRAL_HEADER.unpack(header)
            if fields[0] != _ZIP_CENTRAL_SIGNATURE or fields[13] != 0:
                raise _ArchivePreflightError("invalid_central_directory")
            variable_size = fields[10] + fields[11] + fields[12]
            record_size = _ZIP_CENTRAL_HEADER.size + variable_size
            if record_size > remaining:
                raise _ArchivePreflightError("invalid_central_directory")
            handle.seek(variable_size, 1)
            remaining -= record_size
            counted_entries += 1
            if counted_entries > policy.max_archive_entries:
                raise _ArchivePreflightError(
                    "archive_entries",
                    limit_name="archive_entries",
                    observed=counted_entries,
                )
        if counted_entries != total_entries:
            raise _ArchivePreflightError("central_directory_count_mismatch")
    return counted_entries, central_size


def _zip_entry_rejection(info: ZipInfo) -> str | None:
    if info.is_dir():
        return "directory"
    if not _valid_archive_name(info.filename):
        return "unsafe_name"
    if info.flag_bits & 0x1:
        return "encrypted"
    if info.file_size < 0 or info.compress_size < 0:
        return "invalid_metadata"
    return None


def _read_zip_entry(
    archive: ZipFile,
    info: ZipInfo,
    *,
    maximum: int,
    collector: _Collector,
) -> bytes | None:
    effective_maximum = min(maximum, collector.policy.max_entry_uncompressed_bytes)
    if info.file_size > effective_maximum:
        collector.limit("entry_uncompressed_bytes")
        return None
    ratio = info.file_size / max(1, info.compress_size)
    if ratio > collector.policy.max_compression_ratio:
        collector.limit("compression_ratio")
        return None
    if (
        collector.total_declared_bytes + info.file_size
        > collector.policy.max_total_uncompressed_bytes
    ):
        collector.limit("total_uncompressed_bytes")
        return None
    try:
        with archive.open(info, "r") as handle:
            value = handle.read(effective_maximum + 1)
    except (BadZipFile, EOFError, OSError, RuntimeError, ValueError, zlib.error):
        return None
    if len(value) != info.file_size or len(value) > effective_maximum:
        return None
    collector.total_declared_bytes += info.file_size
    collector.metrics["bytes_read"] += len(value)
    collector.metrics["archive_entries_scanned"] += 1
    return value


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("'\"").casefold()
    if len(normalized) < 6:
        return True
    tokens = set(re.findall(r"[a-z0-9]+", normalized))
    if normalized in _PLACEHOLDER_EXACT or tokens & _PLACEHOLDER_TOKENS:
        return True
    if any(term in normalized for term in _LEGACY_PLACEHOLDER_TERMS):
        return True
    if normalized.startswith(_PLACEHOLDER_PREFIXES) or normalized.endswith(("}", ">")):
        return True
    return len(set(normalized)) <= 2


def _is_sensitive_assignment_key(value: str) -> bool:
    camel_separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    tokens = {
        item.casefold()
        for item in re.findall(r"[A-Za-z0-9]+", camel_separated)
        if item
    }
    compact = re.sub(r"[^A-Za-z0-9]+", "", value).casefold()
    return bool(
        tokens & _SENSITIVE_ASSIGNMENT_TOKENS
        or compact in _SENSITIVE_ASSIGNMENT_ALIASES
    )


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _redact_known_secrets(value: str) -> str:
    redacted = redact_text(value)
    for _name, pattern, _confidence in _KNOWN_SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def _safe_source_id(
    value: str,
    *,
    sensitive_values: Sequence[str] = (),
) -> str:
    redacted = value
    for sensitive in sensitive_values:
        if sensitive:
            redacted = redacted.replace(sensitive, REDACTED)
    redacted = _redact_known_secrets(redacted)
    if redacted == value:
        return value
    return f"{REDACTED}:{_hash_value(value)[:16]}"


def _safe_metadata_text(
    value: str,
    *,
    sensitive_values: Sequence[str],
) -> str:
    return _redact_known_secrets(
        redact_text_with_values(value, sensitive_values)
    )


def _clean_secret_value(value: str) -> str:
    return value.strip().strip("'\"").rstrip(".,):]")


def _record_secret(
    collector: _Collector,
    *,
    kind: str,
    confidence: str,
    source_id: str,
    location: str,
    key_name: str | None,
    value: str,
) -> None:
    candidate = _clean_secret_value(value)
    if _is_placeholder(candidate):
        return
    digest = _hash_value(candidate)
    identity = (kind, source_id, digest)
    if identity in collector.secret_keys:
        return
    if len(collector.secrets) >= collector.policy.max_secret_candidates:
        collector.limit("secret_candidates")
        return
    collector.secret_keys.add(identity)
    source_values = collector.source_sensitive_values.setdefault(source_id, [])
    if candidate not in source_values:
        source_values.append(candidate)
    collector.secrets.append(
        SecretCandidate(
            kind=kind,
            confidence=confidence,
            source_id=source_id,
            location=location,
            key_name=key_name,
            value_sha256=digest,
            value_length=len(candidate),
        )
    )


def _redact_endpoint(value: str) -> tuple[str, str, int | None, str] | None:
    candidate = value.rstrip(".,;:)]}")
    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.casefold()
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if scheme not in {"http", "https", "ws", "wss"} or not host:
        return None
    normalized_host = host.casefold().rstrip(".")
    if not normalized_host or len(normalized_host) > 253:
        return None
    raw_host_authority = parsed.netloc.rsplit("@", 1)[-1]
    output_host = (
        REDACTED
        if _redact_known_secrets(raw_host_authority) != raw_host_authority
        else normalized_host
    )
    safe_host = f"[{output_host}]" if ":" in output_host else output_host
    authority = f"{safe_host}:{port}" if port is not None else safe_host
    path = "/".join(REDACTED if segment else "" for segment in parsed.path.split("/"))
    query = urlencode(
        [
            (f"parameter_{index + 1}", REDACTED)
            for index, _item in enumerate(
                parse_qsl(parsed.query, keep_blank_values=True)
            )
        ]
    )
    redacted = urlunsplit(
        (scheme, authority, path[:1000], query, "")
    )
    return scheme, output_host, port, redacted


def _record_endpoint(
    collector: _Collector,
    *,
    source_id: str,
    location: str,
    value: str,
) -> None:
    parsed = _redact_endpoint(value)
    if parsed is None:
        return
    digest = _hash_value(value.rstrip(".,;:)]}"))
    identity = (source_id, digest)
    if identity in collector.endpoint_keys:
        return
    if len(collector.endpoints) >= collector.policy.max_endpoints:
        collector.limit("endpoints")
        return
    scheme, host, port, redacted_url = parsed
    collector.endpoint_keys.add(identity)
    collector.endpoints.append(
        EndpointCandidate(
            source_id=source_id,
            location=location,
            scheme=scheme,
            host=host,
            port=port,
            redacted_url=redacted_url,
            value_sha256=digest,
        )
    )


def _scan_text(
    collector: _Collector,
    *,
    source_id: str,
    location: str,
    value: str,
) -> None:
    if len(value) > collector.policy.max_string_bytes:
        collector.limit("string_scan_bytes")
    bounded = value[: collector.policy.max_string_bytes]
    for match in _PRIVATE_KEY_HEADER_PATTERN.finditer(bounded):
        _record_secret(
            collector,
            kind="private_key_pem",
            confidence="high",
            source_id=source_id,
            location=location,
            key_name=None,
            value=match.group(0),
        )
    for pattern_name, pattern, confidence in _KNOWN_SECRET_PATTERNS:
        for match in pattern.finditer(bounded):
            secret = match.group(1) if pattern_name == "bearer_token" else match.group(0)
            _record_secret(
                collector,
                kind=pattern_name,
                confidence=confidence,
                source_id=source_id,
                location=location,
                key_name=None,
                value=secret,
            )
    for match in _ASSIGNED_SECRET_PATTERN.finditer(bounded):
        key = match.group("key")
        if not is_sensitive_name(key) and not _is_sensitive_assignment_key(key):
            continue
        _record_secret(
            collector,
            kind="named_assignment",
            confidence="medium",
            source_id=source_id,
            location=location,
            key_name=redact_text(key)[:100],
            value=match.group("value"),
        )
    for match in _URL_PATTERN.finditer(bounded):
        url = match.group(0)
        try:
            password = urlsplit(url.rstrip(".,;:)]}")).password
        except ValueError:
            password = None
        if password:
            _record_secret(
                collector,
                kind="basic_auth_password",
                confidence="high",
                source_id=source_id,
                location=location,
                key_name="url_password",
                value=password,
            )
        _record_endpoint(
            collector,
            source_id=source_id,
            location=location,
            value=url,
        )


def _record_method_reference(
    collector: _Collector,
    *,
    source_id: str,
    dex_entry: str,
    reference: DexMethodReference,
) -> None:
    for inventory_id, category, class_descriptor, methods in _DYNAMIC_API_PATTERNS:
        if (
            reference.class_descriptor == class_descriptor
            and reference.method_name in methods
        ):
            identity = (
                inventory_id,
                source_id,
                dex_entry,
                reference.method_name,
                reference.prototype,
            )
            if identity in collector.dynamic_keys:
                break
            if len(collector.dynamic) >= collector.policy.max_dynamic_api_matches:
                collector.limit("dynamic_api_matches")
                break
            collector.dynamic_keys.add(identity)
            collector.dynamic.append(
                ApiInventoryMatch(
                    inventory_id=inventory_id,
                    category=category,
                    source_id=source_id,
                    dex_entry=dex_entry,
                    class_descriptor=reference.class_descriptor,
                    method_name=reference.method_name,
                    prototype=reference.prototype,
                )
            )
            break
    for entry in collector.api_policy:
        if (
            reference.class_descriptor != entry.class_descriptor
            or reference.method_name != entry.method_name
            or (entry.prototype is not None and reference.prototype != entry.prototype)
        ):
            continue
        identity = (entry.policy_id, source_id, dex_entry, reference.prototype)
        if identity in collector.policy_keys:
            continue
        if len(collector.policy_matches) >= collector.policy.max_policy_api_matches:
            collector.limit("policy_api_matches")
            return
        collector.policy_keys.add(identity)
        collector.policy_matches.append(
            ApiPolicyMatch(
                policy_id=entry.policy_id,
                disposition=entry.disposition,
                source_id=source_id,
                dex_entry=dex_entry,
                class_descriptor=reference.class_descriptor,
                method_name=reference.method_name,
                prototype=reference.prototype,
                deprecated_since=entry.deprecated_since,
                rationale=entry.rationale,
            )
        )


def _record_embedded(
    collector: _Collector,
    *,
    source_id: str,
    info: ZipInfo,
) -> None:
    suffix = PurePosixPath(info.filename).suffix.casefold()
    if suffix not in _EMBEDDED_CODE_SUFFIXES:
        return
    if _ROOT_DEX.fullmatch(info.filename):
        return
    identity = (source_id, info.filename)
    if identity in collector.embedded_keys:
        return
    if len(collector.embedded) >= collector.policy.max_embedded_code_entries:
        collector.limit("embedded_code_entries")
        return
    collector.embedded_keys.add(identity)
    collector.embedded.append(
        EmbeddedCodeEntry(
            source_id=source_id,
            archive_entry=info.filename,
            kind=suffix.removeprefix("."),
            size_bytes=info.file_size,
            compressed_size_bytes=info.compress_size,
        )
    )


def _is_text_entry(name: str) -> bool:
    path = PurePosixPath(name)
    return path.suffix.casefold() in _TEXT_SUFFIXES and (
        name.startswith("assets/") or name.startswith("res/raw/")
    )


def _scan_archive(item: StaticApkInput, collector: _Collector) -> None:
    try:
        apk_size = item.path.stat().st_size
    except OSError:
        collector.problem(item.source_id, "invalid_apk_archive")
        return
    if apk_size < 1 or apk_size > collector.policy.max_apk_file_bytes:
        collector.limit("apk_file_bytes")
        return
    try:
        entry_count, central_size = _preflight_zip_archive(item.path, collector.policy)
    except _ArchivePreflightError as exc:
        if exc.limit_name is not None:
            collector.limit(exc.limit_name)
            if exc.limit_name == "archive_entries" and exc.observed is not None:
                collector.metrics["archive_entries_seen"] += exc.observed
            if exc.limit_name == "central_directory_bytes" and exc.observed is not None:
                collector.metrics["central_directory_bytes"] += exc.observed
        else:
            collector.problem(item.source_id, exc.category)
        return
    collector.metrics["archive_entries_seen"] += entry_count
    collector.metrics["central_directory_bytes"] += central_size
    try:
        with ZipFile(item.path, "r", allowZip64=False) as archive:
            infos = sorted(
                archive.infolist(),
                key=lambda value: (
                    0 if _ROOT_DEX.fullmatch(value.filename) else 1,
                    value.filename,
                    value.header_offset,
                ),
            )
            if len(infos) != entry_count:
                collector.problem(item.source_id, "central_directory_count_mismatch")
                return
            seen_names: set[str] = set()
            for info in infos:
                if info.filename in seen_names:
                    collector.problem(item.source_id, "duplicate_archive_entry")
                    continue
                seen_names.add(info.filename)
                planned_kind = (
                    "dex"
                    if _ROOT_DEX.fullmatch(info.filename)
                    else "text"
                    if _is_text_entry(info.filename)
                    else None
                )
                rejection = _zip_entry_rejection(info)
                if rejection is not None:
                    if planned_kind is not None:
                        collector.problem(
                            item.source_id,
                            f"{planned_kind}_entry_{rejection}",
                        )
                    continue
                _record_embedded(collector, source_id=item.source_id, info=info)
                if _ROOT_DEX.fullmatch(info.filename):
                    if collector.metrics["dex_files_scanned"] >= collector.policy.max_dex_files:
                        collector.limit("dex_files")
                        continue
                    data = _read_zip_entry(
                        archive,
                        info,
                        maximum=collector.policy.max_dex_bytes,
                        collector=collector,
                    )
                    if data is None:
                        collector.problem(item.source_id, "dex_read_failed")
                        continue
                    try:
                        inventory = parse_dex_inventory(data, policy=collector.policy)
                    except DexFormatError:
                        collector.problem(item.source_id, "malformed_dex")
                        continue
                    collector.metrics["dex_files_scanned"] += 1
                    collector.metrics["dex_strings_scanned"] += len(inventory.strings)
                    collector.metrics["dex_method_references"] += len(
                        inventory.method_references
                    )
                    if inventory.oversized_strings:
                        collector.problem(item.source_id, "oversized_dex_strings_skipped")
                    for index, value in enumerate(inventory.strings):
                        if value is not None:
                            _scan_text(
                                collector,
                                source_id=item.source_id,
                                location=f"{info.filename}:string:{index}",
                                value=value,
                            )
                    for reference in inventory.method_references:
                        _record_method_reference(
                            collector,
                            source_id=item.source_id,
                            dex_entry=info.filename,
                            reference=reference,
                        )
                elif _is_text_entry(info.filename):
                    data = _read_zip_entry(
                        archive,
                        info,
                        maximum=collector.policy.max_text_entry_bytes,
                        collector=collector,
                    )
                    if data is None:
                        collector.problem(item.source_id, "text_entry_read_failed")
                        continue
                    if data and data.count(b"\x00") * 100 > len(data):
                        collector.problem(item.source_id, "text_entry_binary_content")
                        continue
                    collector.metrics["text_entries_scanned"] += 1
                    text = data.decode("utf-8", errors="replace")
                    if "\ufffd" in text:
                        collector.problem(item.source_id, "text_entry_decode_replacement")
                    for index, line in enumerate(text.splitlines() or [text]):
                        _scan_text(
                            collector,
                            source_id=item.source_id,
                            location=f"{info.filename}:line:{index + 1}",
                            value=line,
                        )
    except (BadZipFile, LargeZipFile, OSError, ValueError):
        collector.problem(item.source_id, "invalid_apk_archive")
        return
    collector.metrics["apks_scanned"] += 1


def analyze_apks(
    apks: Sequence[StaticApkInput],
    *,
    policy: StaticApkPolicy | None = None,
    api_policy: Iterable[ApiPolicyEntry] = DEFAULT_API_POLICY,
) -> StaticApkAnalysisResult:
    """Inspect already-collected APKs without extracting or executing their content."""

    limits = policy or StaticApkPolicy()
    catalog = tuple(
        sorted(
            api_policy,
            key=lambda item: (
                item.policy_id,
                item.class_descriptor,
                item.method_name,
                item.prototype or "",
            ),
        )
    )
    if len({item.policy_id for item in catalog}) != len(catalog):
        raise ValueError("Static API policy identifiers must be unique.")
    collector = _Collector(policy=limits, api_policy=catalog)
    ordered = sorted(apks, key=lambda item: (item.source_id, item.path.name))
    if len({item.source_id for item in ordered}) != len(ordered):
        raise ValueError("Static APK source identifiers must be unique.")
    collector.metrics["apks_seen"] = len(ordered)
    if len(ordered) > limits.max_apks:
        collector.limit("apks")
        ordered = ordered[: limits.max_apks]
    for item in ordered:
        _scan_archive(item, collector)
        for index, value in enumerate(item.resource_strings[: limits.max_resource_strings]):
            collector.metrics["resource_strings_scanned"] += 1
            _scan_text(
                collector,
                source_id=item.source_id,
                location=f"resource_string:{index}",
                value=str(value),
            )
        if len(item.resource_strings) > limits.max_resource_strings:
            collector.limit("resource_strings")
    sensitive_values = tuple(
        dict.fromkeys(
            value
            for values in collector.source_sensitive_values.values()
            for value in values
            if value
        )
    )
    return StaticApkAnalysisResult(
        status="partial" if collector.limitations else "completed",
        sources=tuple(
            _safe_source_id(
                item.source_id,
                sensitive_values=collector.source_sensitive_values.get(
                    item.source_id,
                    (),
                ),
            )
            for item in ordered
        ),
        secret_candidates=tuple(
            replace(
                item,
                source_id=_safe_source_id(
                    item.source_id,
                    sensitive_values=sensitive_values,
                ),
                location=_safe_metadata_text(
                    item.location,
                    sensitive_values=sensitive_values,
                ),
                key_name=(
                    _safe_metadata_text(
                        item.key_name,
                        sensitive_values=sensitive_values,
                    )
                    if item.key_name is not None
                    else None
                ),
            )
            for item in collector.secrets
        ),
        endpoints=tuple(
            replace(
                item,
                source_id=_safe_source_id(
                    item.source_id,
                    sensitive_values=sensitive_values,
                ),
                location=_safe_metadata_text(
                    item.location,
                    sensitive_values=sensitive_values,
                ),
                host=_safe_metadata_text(
                    item.host,
                    sensitive_values=sensitive_values,
                ),
                redacted_url=_safe_metadata_text(
                    item.redacted_url,
                    sensitive_values=sensitive_values,
                ),
            )
            for item in collector.endpoints
        ),
        dynamic_loading_apis=tuple(
            replace(
                item,
                source_id=_safe_source_id(
                    item.source_id,
                    sensitive_values=sensitive_values,
                ),
                dex_entry=_safe_metadata_text(
                    item.dex_entry,
                    sensitive_values=sensitive_values,
                ),
                class_descriptor=_safe_metadata_text(
                    item.class_descriptor,
                    sensitive_values=sensitive_values,
                ),
                method_name=_safe_metadata_text(
                    item.method_name,
                    sensitive_values=sensitive_values,
                ),
                prototype=_safe_metadata_text(
                    item.prototype,
                    sensitive_values=sensitive_values,
                ),
            )
            for item in collector.dynamic
        ),
        api_policy_matches=tuple(
            replace(
                item,
                source_id=_safe_source_id(
                    item.source_id,
                    sensitive_values=sensitive_values,
                ),
                dex_entry=_safe_metadata_text(
                    item.dex_entry,
                    sensitive_values=sensitive_values,
                ),
                class_descriptor=_safe_metadata_text(
                    item.class_descriptor,
                    sensitive_values=sensitive_values,
                ),
                method_name=_safe_metadata_text(
                    item.method_name,
                    sensitive_values=sensitive_values,
                ),
                prototype=_safe_metadata_text(
                    item.prototype,
                    sensitive_values=sensitive_values,
                ),
                rationale=_safe_metadata_text(
                    item.rationale,
                    sensitive_values=sensitive_values,
                ),
            )
            for item in collector.policy_matches
        ),
        embedded_code=tuple(
            replace(
                item,
                source_id=_safe_source_id(
                    item.source_id,
                    sensitive_values=sensitive_values,
                ),
                archive_entry=_safe_metadata_text(
                    item.archive_entry,
                    sensitive_values=sensitive_values,
                ),
            )
            for item in collector.embedded
        ),
        limitations=tuple(
            _safe_metadata_text(item, sensitive_values=sensitive_values)
            for item in collector.limitations
        ),
        metrics=dict(collector.metrics),
    )
