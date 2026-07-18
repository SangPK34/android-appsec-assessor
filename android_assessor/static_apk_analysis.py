"""Bounded, read-only static inventory for pulled Android APK artifacts."""

from __future__ import annotations

import hashlib
import re
import struct
import time
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
    max_string_scan_chunk_bytes: int = 64 * 1024
    max_string_scan_file_bytes: int = 8 * 1024 * 1024
    max_string_scan_apk_bytes: int = 32 * 1024 * 1024
    max_string_scan_candidates: int = 1000
    max_string_scan_milliseconds: int = 5000
    max_resource_strings: int = 50_000
    max_secret_candidates: int = 500
    max_endpoints: int = 500
    max_dynamic_api_matches: int = 500
    max_policy_api_matches: int = 500
    max_embedded_code_entries: int = 500
    max_security_api_matches: int = 500
    max_dex_class_defs: int = 100_000
    max_dex_encoded_methods: int = 200_000
    max_dex_code_units: int = 8_000_000
    max_dex_invocations: int = 500_000
    min_pbe_iterations: int = 10_000
    max_static_behavior_candidates: int = 500

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
        if self.max_string_scan_chunk_bytes <= self.max_string_bytes:
            raise ValueError("String scan chunks must exceed the candidate string limit.")
        if self.max_string_scan_file_bytes < self.max_string_scan_chunk_bytes:
            raise ValueError("String scan file budget may not be smaller than a chunk.")
        if self.max_string_scan_apk_bytes < self.max_string_scan_file_bytes:
            raise ValueError("String scan APK budget may not be smaller than a file budget.")


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
        policy_id="ANDROID-WEBSETTINGS-PLUGIN-STATE",
        class_descriptor="Landroid/webkit/WebSettings;",
        method_name="setPluginState",
        prototype="(Landroid/webkit/WebSettings$PluginState;)V",
        disposition="deprecated",
        deprecated_since=18,
        rationale="Android deprecated WebView plugin-state configuration in API level 18.",
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
    oversized_string_regions: tuple[tuple[int, int], ...] = ()
    behavior_signals: tuple[_DexBehaviorSignal, ...] = ()
    behavior_limitations: tuple[str, ...] = ()
    behavior_metrics: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class _DexBehaviorSignal:
    rule_id: str
    confidence: str
    caller_class_descriptor: str
    caller_method_name: str
    caller_prototype: str
    indicators: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StaticBehaviorCandidate:
    rule_id: str
    confidence: str
    source_id: str
    dex_entry: str
    caller_class_descriptor: str
    caller_method_name: str
    caller_prototype: str
    indicators: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["indicators"] = list(self.indicators)
        return value


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
    security_api_candidates: tuple[ApiInventoryMatch, ...] = ()
    static_behavior_candidates: tuple[StaticBehaviorCandidate, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "status": self.status,
            "sources": list(self.sources),
            "secret_candidates": [item.to_dict() for item in self.secret_candidates],
            "endpoints": [item.to_dict() for item in self.endpoints],
            "dynamic_loading_apis": [
                item.to_dict() for item in self.dynamic_loading_apis
            ],
            "security_api_candidates": [
                item.to_dict() for item in self.security_api_candidates
            ],
            "static_behavior_candidates": [
                item.to_dict() for item in self.static_behavior_candidates
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
    security: list[ApiInventoryMatch] = field(default_factory=list)
    behavior: list[StaticBehaviorCandidate] = field(default_factory=list)
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
            "dex_class_defs_seen": 0,
            "dex_behavior_methods_scanned": 0,
            "dex_behavior_code_units_scanned": 0,
            "dex_behavior_invocations_scanned": 0,
            "static_behavior_candidates": 0,
            "resource_strings_scanned": 0,
            "text_entries_scanned": 0,
            "string_scan_bytes": 0,
            "string_scan_chunks": 0,
            "string_scan_timeouts": 0,
            "oversized_dex_strings_scanned": 0,
        }
    )
    secret_keys: set[tuple[str, str, str]] = field(default_factory=set)
    endpoint_keys: set[tuple[str, str]] = field(default_factory=set)
    dynamic_keys: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    security_keys: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    behavior_keys: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    policy_keys: set[tuple[str, str, str, str]] = field(default_factory=set)
    embedded_keys: set[tuple[str, str]] = field(default_factory=set)
    source_sensitive_values: dict[str, list[str]] = field(default_factory=dict)
    total_declared_bytes: int = 0
    string_scan_started: dict[str, float] = field(default_factory=dict)
    string_scan_source_bytes: dict[str, int] = field(default_factory=dict)
    string_scan_file_bytes: dict[tuple[str, str], int] = field(default_factory=dict)
    string_scan_timed_out: set[str] = field(default_factory=set)

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

# These exact DEX method references are bounded inventory candidates only. A
# method_id does not prove that a call is reachable, what arguments it receives,
# or how an implementation behaves. Runtime correlation must establish those
# properties before a candidate can support a security finding.
_SECURITY_API_PATTERNS: tuple[
    tuple[str, str, str, str, frozenset[str]], ...
] = (
    (
        "WEBVIEW_JAVASCRIPT_ENABLED",
        "webview",
        "Landroid/webkit/WebSettings;",
        "setJavaScriptEnabled",
        frozenset({"(Z)V"}),
    ),
    (
        "WEBVIEW_FILE_ACCESS",
        "webview",
        "Landroid/webkit/WebSettings;",
        "setAllowFileAccess",
        frozenset({"(Z)V"}),
    ),
    (
        "WEBVIEW_CONTENT_ACCESS",
        "webview",
        "Landroid/webkit/WebSettings;",
        "setAllowContentAccess",
        frozenset({"(Z)V"}),
    ),
    (
        "WEBVIEW_FILE_URL_ACCESS",
        "webview",
        "Landroid/webkit/WebSettings;",
        "setAllowFileAccessFromFileURLs",
        frozenset({"(Z)V"}),
    ),
    (
        "WEBVIEW_UNIVERSAL_FILE_URL_ACCESS",
        "webview",
        "Landroid/webkit/WebSettings;",
        "setAllowUniversalAccessFromFileURLs",
        frozenset({"(Z)V"}),
    ),
    (
        "WEBVIEW_MIXED_CONTENT_MODE",
        "webview",
        "Landroid/webkit/WebSettings;",
        "setMixedContentMode",
        frozenset({"(I)V"}),
    ),
    (
        "WEBVIEW_JAVASCRIPT_INTERFACE",
        "webview",
        "Landroid/webkit/WebView;",
        "addJavascriptInterface",
        frozenset({"(Ljava/lang/Object;Ljava/lang/String;)V"}),
    ),
    (
        "WEBVIEW_DEBUGGING",
        "webview",
        "Landroid/webkit/WebView;",
        "setWebContentsDebuggingEnabled",
        frozenset({"(Z)V"}),
    ),
    (
        "WEBVIEW_LOAD_URL",
        "webview",
        "Landroid/webkit/WebView;",
        "loadUrl",
        frozenset(
            {
                "(Ljava/lang/String;)V",
                "(Ljava/lang/String;Ljava/util/Map;)V",
            }
        ),
    ),
    (
        "WEBVIEW_LOAD_DATA",
        "webview",
        "Landroid/webkit/WebView;",
        "loadData",
        frozenset(
            {
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            }
        ),
    ),
    (
        "WEBVIEW_LOAD_DATA_BASE_URL",
        "webview",
        "Landroid/webkit/WebView;",
        "loadDataWithBaseURL",
        frozenset(
            {
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                "Ljava/lang/String;Ljava/lang/String;)V",
            }
        ),
    ),
    (
        "WEBVIEW_EVALUATE_JAVASCRIPT",
        "webview",
        "Landroid/webkit/WebView;",
        "evaluateJavascript",
        frozenset(
            {
                "(Ljava/lang/String;Landroid/webkit/ValueCallback;)V",
            }
        ),
    ),
    (
        "WEBVIEW_SSL_ERROR_PROCEED",
        "webview_tls",
        "Landroid/webkit/SslErrorHandler;",
        "proceed",
        frozenset({"()V"}),
    ),
    (
        "TLS_SSL_CONTEXT_INIT",
        "tls",
        "Ljavax/net/ssl/SSLContext;",
        "init",
        frozenset(
            {
                "([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;"
                "Ljava/security/SecureRandom;)V",
            }
        ),
    ),
    (
        "TLS_CHECK_SERVER_TRUSTED",
        "tls",
        "Ljavax/net/ssl/X509TrustManager;",
        "checkServerTrusted",
        frozenset(
            {
                "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
            }
        ),
    ),
    (
        "TLS_HOSTNAME_VERIFY",
        "tls",
        "Ljavax/net/ssl/HostnameVerifier;",
        "verify",
        frozenset({"(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z"}),
    ),
    (
        "TLS_SET_HOSTNAME_VERIFIER",
        "tls",
        "Ljavax/net/ssl/HttpsURLConnection;",
        "setHostnameVerifier",
        frozenset({"(Ljavax/net/ssl/HostnameVerifier;)V"}),
    ),
    (
        "TLS_SET_DEFAULT_HOSTNAME_VERIFIER",
        "tls",
        "Ljavax/net/ssl/HttpsURLConnection;",
        "setDefaultHostnameVerifier",
        frozenset({"(Ljavax/net/ssl/HostnameVerifier;)V"}),
    ),
    (
        "TLS_TRUST_MANAGER_FACTORY",
        "tls",
        "Ljavax/net/ssl/TrustManagerFactory;",
        "getTrustManagers",
        frozenset({"()[Ljavax/net/ssl/TrustManager;"}),
    ),
    (
        "TLS_OKHTTP_CERTIFICATE_PINNER",
        "tls_control",
        "Lokhttp3/CertificatePinner;",
        "check",
        frozenset(
            {
                "(Ljava/lang/String;Ljava/util/List;)V",
                "(Ljava/lang/String;[Ljava/security/cert/Certificate;)V",
            }
        ),
    ),
    (
        "CRYPTO_CIPHER_INSTANCE",
        "crypto",
        "Ljavax/crypto/Cipher;",
        "getInstance",
        frozenset(
            {
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/Cipher;",
                "(Ljava/lang/String;Ljava/security/Provider;)Ljavax/crypto/Cipher;",
            }
        ),
    ),
    (
        "CRYPTO_MESSAGE_DIGEST_INSTANCE",
        "crypto",
        "Ljava/security/MessageDigest;",
        "getInstance",
        frozenset(
            {
                "(Ljava/lang/String;)Ljava/security/MessageDigest;",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/MessageDigest;",
                "(Ljava/lang/String;Ljava/security/Provider;)Ljava/security/MessageDigest;",
            }
        ),
    ),
    (
        "CRYPTO_MAC_INSTANCE",
        "crypto",
        "Ljavax/crypto/Mac;",
        "getInstance",
        frozenset(
            {
                "(Ljava/lang/String;)Ljavax/crypto/Mac;",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/Mac;",
                "(Ljava/lang/String;Ljava/security/Provider;)Ljavax/crypto/Mac;",
            }
        ),
    ),
    (
        "CRYPTO_SECRET_KEY_SPEC",
        "crypto_material",
        "Ljavax/crypto/spec/SecretKeySpec;",
        "<init>",
        frozenset(
            {
                "([BLjava/lang/String;)V",
                "([BIILjava/lang/String;)V",
            }
        ),
    ),
    (
        "CRYPTO_IV_PARAMETER_SPEC",
        "crypto_material",
        "Ljavax/crypto/spec/IvParameterSpec;",
        "<init>",
        frozenset({"([B)V", "([BII)V"}),
    ),
    (
        "CRYPTO_PBE_PARAMETER_SPEC",
        "crypto_material",
        "Ljavax/crypto/spec/PBEParameterSpec;",
        "<init>",
        frozenset(
            {
                "([BI)V",
                "([BILjava/security/spec/AlgorithmParameterSpec;)V",
            }
        ),
    ),
    (
        "CRYPTO_PBE_KEY_SPEC",
        "crypto_material",
        "Ljavax/crypto/spec/PBEKeySpec;",
        "<init>",
        frozenset({"([C)V", "([C[BI)V", "([C[BII)V"}),
    ),
    (
        "CRYPTO_SECURE_RANDOM_SEED",
        "crypto_randomness",
        "Ljava/security/SecureRandom;",
        "setSeed",
        frozenset({"(J)V", "([B)V"}),
    ),
    (
        "CRYPTO_JAVA_RANDOM",
        "crypto_randomness",
        "Ljava/util/Random;",
        "<init>",
        frozenset({"()V", "(J)V"}),
    ),
    (
        "CRYPTO_JAVA_RANDOM",
        "crypto_randomness",
        "Ljava/util/Random;",
        "nextBytes",
        frozenset({"([B)V"}),
    ),
    (
        "PENDING_INTENT_ACTIVITY",
        "pending_intent",
        "Landroid/app/PendingIntent;",
        "getActivity",
        frozenset(
            {
                "(Landroid/content/Context;ILandroid/content/Intent;I)"
                "Landroid/app/PendingIntent;",
                "(Landroid/content/Context;ILandroid/content/Intent;I"
                "Landroid/os/Bundle;)Landroid/app/PendingIntent;",
            }
        ),
    ),
    (
        "PENDING_INTENT_ACTIVITIES",
        "pending_intent",
        "Landroid/app/PendingIntent;",
        "getActivities",
        frozenset(
            {
                "(Landroid/content/Context;I[Landroid/content/Intent;I)"
                "Landroid/app/PendingIntent;",
                "(Landroid/content/Context;I[Landroid/content/Intent;I"
                "Landroid/os/Bundle;)Landroid/app/PendingIntent;",
            }
        ),
    ),
    (
        "PENDING_INTENT_BROADCAST",
        "pending_intent",
        "Landroid/app/PendingIntent;",
        "getBroadcast",
        frozenset(
            {
                "(Landroid/content/Context;ILandroid/content/Intent;I)"
                "Landroid/app/PendingIntent;",
            }
        ),
    ),
    (
        "PENDING_INTENT_SERVICE",
        "pending_intent",
        "Landroid/app/PendingIntent;",
        "getService",
        frozenset(
            {
                "(Landroid/content/Context;ILandroid/content/Intent;I)"
                "Landroid/app/PendingIntent;",
            }
        ),
    ),
    (
        "PENDING_INTENT_FOREGROUND_SERVICE",
        "pending_intent",
        "Landroid/app/PendingIntent;",
        "getForegroundService",
        frozenset(
            {
                "(Landroid/content/Context;ILandroid/content/Intent;I)"
                "Landroid/app/PendingIntent;",
            }
        ),
    ),
)

_SECURITY_API_INDEX = {
    key: tuple(
        pattern
        for pattern in _SECURITY_API_PATTERNS
        if (pattern[2], pattern[3]) == key
    )
    for key in {
        (pattern[2], pattern[3]) for pattern in _SECURITY_API_PATTERNS
    }
}


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
) -> tuple[str | None, bool, int, int]:
    if offset < _DEX_HEADER_SIZE or offset >= len(data):
        raise DexFormatError("DEX string data offset is outside the file bounds.")
    declared_length, start = _read_uleb128(data, offset)
    search_end = min(len(data), start + max_string_bytes + 1)
    end = data.find(b"\x00", start, search_end)
    if end < 0:
        return None, True, max(0, search_end - start), start
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
    return decoded, False, len(raw), start


@dataclass(frozen=True, slots=True)
class _DexConstant:
    value: str | int | tuple[str, int]


@dataclass(frozen=True, slots=True)
class _DexInvocation:
    reference: DexMethodReference
    arguments: tuple[_DexConstant | None, ...]
    argument_generations: tuple[int, ...]
    invoke_kind: str


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _dex_payload_width(insns: memoryview, offset: int, signature: int) -> int | None:
    remaining = len(insns) - offset
    if signature == 0x0100:
        if remaining < 2:
            raise DexFormatError("DEX packed-switch payload is truncated.")
        return 4 + int(insns[offset + 1]) * 2
    if signature == 0x0200:
        if remaining < 2:
            raise DexFormatError("DEX sparse-switch payload is truncated.")
        return 2 + int(insns[offset + 1]) * 4
    if signature == 0x0300:
        if remaining < 4:
            raise DexFormatError("DEX array-data payload is truncated.")
        element_width = int(insns[offset + 1])
        element_count = int(insns[offset + 2]) | (int(insns[offset + 3]) << 16)
        if element_width not in {1, 2, 4, 8}:
            raise DexFormatError("DEX array-data element width is invalid.")
        return 4 + (element_width * element_count + 1) // 2
    return None


def _dex_instruction_width(insns: memoryview, offset: int) -> int | None:
    unit = int(insns[offset])
    opcode = unit & 0xFF
    if opcode == 0x00:
        if unit == 0:
            return 1
        return _dex_payload_width(insns, offset, unit)
    if opcode in {
        0x02,
        0x05,
        0x08,
        0x13,
        0x15,
        0x16,
        0x19,
        0x1A,
        0x1C,
        0x1F,
        0x20,
        0x22,
        0x23,
        0x29,
        0xFE,
        0xFF,
    } or 0x2D <= opcode <= 0x6D or 0x90 <= opcode <= 0xAF or 0xD0 <= opcode <= 0xE2:
        return 2
    if opcode in {
        0x03,
        0x06,
        0x09,
        0x14,
        0x17,
        0x1B,
        0x24,
        0x25,
        0x26,
        0x2A,
        0x2B,
        0x2C,
        0x6E,
        0x6F,
        0x70,
        0x71,
        0x72,
        0x74,
        0x75,
        0x76,
        0x77,
        0x78,
        0xFC,
        0xFD,
    }:
        return 3
    if opcode in {0xFA, 0xFB}:
        return 4
    if opcode == 0x18:
        return 5
    if (
        0x01 <= opcode <= 0x12
        or 0x1D <= opcode <= 0x1E
        or opcode in {0x21, 0x27, 0x28}
        or 0x7B <= opcode <= 0x8F
        or 0xB0 <= opcode <= 0xCF
    ):
        return 1
    return None


def _invoke_registers(insns: memoryview, offset: int, opcode: int) -> tuple[int, ...]:
    first = int(insns[offset])
    if 0x6E <= opcode <= 0x72:
        count = (first >> 12) & 0x0F
        if count > 5:
            raise DexFormatError("DEX invoke argument count is invalid.")
        packed = int(insns[offset + 2])
        registers = (
            packed & 0x0F,
            (packed >> 4) & 0x0F,
            (packed >> 8) & 0x0F,
            (packed >> 12) & 0x0F,
            (first >> 8) & 0x0F,
        )
        return registers[:count]
    count = (first >> 8) & 0xFF
    start = int(insns[offset + 2])
    return tuple(range(start, start + count))


def _scan_dex_invocations(
    data: bytes,
    *,
    code_offset: int,
    method_table: Sequence[DexMethodReference | None],
    string_count: int,
    invocation_budget: int,
) -> tuple[tuple[_DexInvocation, ...], int, bool, bool]:
    if code_offset < _DEX_HEADER_SIZE or code_offset % 4 or code_offset + 16 > len(data):
        raise DexFormatError("DEX code item is outside the file bounds.")
    registers_size, _ins_size, _outs_size, tries_size = struct.unpack_from(
        "<4H", data, code_offset
    )
    insns_size = _uint32(data, code_offset + 12)
    insns_offset = code_offset + 16
    insns_end = insns_offset + insns_size * 2
    if insns_end > len(data):
        raise DexFormatError("DEX code instructions are truncated.")
    if tries_size:
        tries_offset = insns_end + (2 if insns_size % 2 else 0)
        if tries_offset + tries_size * 8 > len(data):
            raise DexFormatError("DEX code exception table is truncated.")
    insns = memoryview(data)[insns_offset:insns_end].cast("H")
    constants: dict[int, _DexConstant] = {}
    register_generations: dict[int, int] = {}
    next_generation = 1
    flow_epoch = 0

    def validate_register(register: int, *, width: int = 1) -> None:
        if register < 0 or register + width > registers_size:
            raise DexFormatError("DEX instruction references an invalid register.")

    def register_generation(register: int) -> int:
        validate_register(register)
        return register_generations.get(
            register,
            -(flow_epoch * 0x10000 + register + 1),
        )

    def define_register(register: int, *, width: int = 1) -> None:
        nonlocal next_generation
        validate_register(register, width=width)
        for item in range(register, register + width):
            constants.pop(item, None)
            register_generations[item] = next_generation
            next_generation += 1

    def copy_register(destination: int, source: int) -> None:
        validate_register(destination)
        validate_register(source)
        if source in constants:
            constants[destination] = constants[source]
        else:
            constants.pop(destination, None)
        register_generations[destination] = register_generation(source)

    def clear_flow_state() -> None:
        nonlocal flow_epoch
        constants.clear()
        register_generations.clear()
        flow_epoch += 1

    invocations: list[_DexInvocation] = []
    offset = 0
    unsupported = False
    limited = False
    while offset < len(insns):
        first = int(insns[offset])
        opcode = first & 0xFF
        width = _dex_instruction_width(insns, offset)
        if width is None:
            unsupported = True
            break
        if width < 1 or offset + width > len(insns):
            raise DexFormatError("DEX instruction is truncated.")

        if opcode == 0x12:
            register = (first >> 8) & 0x0F
            define_register(register)
            constants[register] = _DexConstant(_sign_extend(first >> 12, 4))
        elif opcode == 0x13:
            destination = first >> 8
            define_register(destination)
            constants[destination] = _DexConstant(
                _sign_extend(int(insns[offset + 1]), 16)
            )
        elif opcode == 0x14:
            literal = int(insns[offset + 1]) | (int(insns[offset + 2]) << 16)
            destination = first >> 8
            define_register(destination)
            constants[destination] = _DexConstant(_sign_extend(literal, 32))
        elif opcode == 0x15:
            literal = int(insns[offset + 1]) << 16
            destination = first >> 8
            define_register(destination)
            constants[destination] = _DexConstant(_sign_extend(literal, 32))
        elif 0x16 <= opcode <= 0x19:
            define_register(first >> 8, width=2)
        elif opcode in {0x1A, 0x1B}:
            string_index = int(insns[offset + 1])
            if opcode == 0x1B:
                string_index |= int(insns[offset + 2]) << 16
            if string_index >= string_count:
                raise DexFormatError(
                    "DEX const-string references an invalid string index."
                )
            # String values are looked up by the caller because method-id parsing
            # deliberately does not retain a second unbounded string table here.
            destination = first >> 8
            define_register(destination)
            constants[destination] = _DexConstant(("string-index", string_index))
        elif opcode in {0x01, 0x07}:
            destination = (first >> 8) & 0x0F
            source = (first >> 12) & 0x0F
            copy_register(destination, source)
        elif opcode == 0x04:
            source = (first >> 12) & 0x0F
            validate_register(source, width=2)
            define_register((first >> 8) & 0x0F, width=2)
        elif opcode in {0x02, 0x08}:
            destination = first >> 8
            source = int(insns[offset + 1])
            copy_register(destination, source)
        elif opcode == 0x05:
            validate_register(int(insns[offset + 1]), width=2)
            define_register(first >> 8, width=2)
        elif opcode in {0x03, 0x09}:
            destination = int(insns[offset + 1])
            source = int(insns[offset + 2])
            copy_register(destination, source)
        elif opcode == 0x06:
            validate_register(int(insns[offset + 2]), width=2)
            define_register(int(insns[offset + 1]), width=2)
        elif 0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78:
            registers = _invoke_registers(insns, offset, opcode)
            if any(register >= registers_size for register in registers):
                raise DexFormatError("DEX invoke references an invalid register.")
            method_index = int(insns[offset + 1])
            if method_index >= len(method_table):
                raise DexFormatError("DEX invoke references an invalid method index.")
            reference = method_table[method_index]
            if reference is not None:
                if len(invocations) >= invocation_budget:
                    limited = True
                    break
                invocations.append(
                    _DexInvocation(
                        reference=reference,
                        arguments=tuple(constants.get(register) for register in registers),
                        argument_generations=tuple(
                            register_generation(register) for register in registers
                        ),
                        invoke_kind={
                            0x6E: "virtual",
                            0x6F: "super",
                            0x70: "direct",
                            0x71: "static",
                            0x72: "interface",
                            0x74: "virtual",
                            0x75: "super",
                            0x76: "direct",
                            0x77: "static",
                            0x78: "interface",
                        }[opcode],
                    )
                )
        elif opcode in {0x0A, 0x0C, 0x0D}:
            define_register(first >> 8)
        elif opcode == 0x0B:
            define_register(first >> 8, width=2)
        elif opcode in {0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C} or 0x32 <= opcode <= 0x3D:
            clear_flow_state()
        elif opcode in {0x21, 0x23, 0x20}:
            define_register((first >> 8) & 0x0F)
        elif 0x52 <= opcode <= 0x58:
            define_register(
                (first >> 8) & 0x0F,
                width=2 if opcode == 0x53 else 1,
            )
        elif opcode in {0x1C, 0x1F, 0x22, 0xFE, 0xFF}:
            define_register(first >> 8)
        elif 0x2D <= opcode <= 0x31:
            define_register(first >> 8)
        elif 0x44 <= opcode <= 0x4A:
            define_register(first >> 8, width=2 if opcode == 0x45 else 1)
        elif 0x60 <= opcode <= 0x66:
            define_register(first >> 8, width=2 if opcode == 0x61 else 1)
        elif 0x7B <= opcode <= 0x8F:
            define_register(
                (first >> 8) & 0x0F,
                width=(
                    2
                    if opcode
                    in {0x7D, 0x7E, 0x80, 0x81, 0x83, 0x86, 0x88, 0x89, 0x8B}
                    else 1
                ),
            )
        elif 0x90 <= opcode <= 0xAF:
            define_register(
                first >> 8,
                width=2 if 0x9B <= opcode <= 0xA5 or 0xAB <= opcode <= 0xAF else 1,
            )
        elif 0xB0 <= opcode <= 0xCF:
            define_register(
                (first >> 8) & 0x0F,
                width=2 if 0xBB <= opcode <= 0xC5 or 0xCB <= opcode <= 0xCF else 1,
            )
        elif 0xD0 <= opcode <= 0xD7:
            define_register((first >> 8) & 0x0F)
        elif 0xD8 <= opcode <= 0xE2:
            define_register(first >> 8)
        offset += width
    return tuple(invocations), offset, unsupported, limited


def _constant_value(
    value: _DexConstant | None,
    strings: Sequence[str | None],
) -> str | int | None:
    if value is None:
        return None
    raw = value.value
    if isinstance(raw, tuple):
        string_index = raw[1]
        if 0 <= string_index < len(strings):
            return strings[string_index]
        raise DexFormatError("DEX const-string references an invalid string index.")
    return raw


def _algorithm_family(value: str) -> str:
    algorithm = value.upper().strip().split("/", 1)[0]
    return re.sub(r"[^A-Z0-9]", "", algorithm)


def _weak_cipher_family(value: str) -> str | None:
    family = _algorithm_family(value)
    aliases = {
        "DES": "des",
        "DESEDE": "triple_des",
        "3DES": "triple_des",
        "TRIPLEDES": "triple_des",
        "RC2": "rc2",
        "RC4": "rc4",
        "ARC4": "rc4",
        "ARCFOUR": "rc4",
        "BLOWFISH": "blowfish",
    }
    if family in aliases:
        return aliases[family]
    if family.startswith("PBEWITH") and any(
        marker in family for marker in ("MD5", "SHA1", "DES", "RC2", "RC4")
    ):
        return "legacy_pbe"
    return None


def _weak_digest_family(value: str) -> str | None:
    family = re.sub(r"[^A-Z0-9]", "", value.upper().strip())
    if family in {"MD2", "MD4", "MD5", "HMACMD5"}:
        return "md5_family"
    if family in {"SHA", "SHA1", "HMACSHA1"}:
        return "sha1_family"
    return None


def _is_remote_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    scheme = urlsplit(value.strip()).scheme.lower()
    return scheme if scheme in {"http", "https", "ws", "wss"} else None


def _behavior_signals_for_method(
    caller: DexMethodReference,
    invocations: Sequence[_DexInvocation],
    strings: Sequence[str | None],
    *,
    min_pbe_iterations: int,
) -> tuple[_DexBehaviorSignal, ...]:
    detected: dict[str, tuple[str, set[str]]] = {}

    def record(rule_id: str, confidence: str, *indicators: str) -> None:
        current = detected.get(rule_id)
        if current is None:
            detected[rule_id] = (confidence, set(indicators))
            return
        old_confidence, old_indicators = current
        if old_confidence == "medium" and confidence == "high":
            old_confidence = "high"
        old_indicators.update(indicators)
        detected[rule_id] = (old_confidence, old_indicators)

    random_material_generations: set[int] = set()
    correlated_crypto_material: set[str] = set()
    javascript_enabled = False
    javascript_bridge = False
    remote_web_content: set[str] = set()

    for invocation in invocations:
        reference = invocation.reference
        arguments = tuple(
            _constant_value(item, strings) for item in invocation.arguments
        )
        class_name = reference.class_descriptor
        method_name = reference.method_name
        prototype = reference.prototype
        argument_generations = invocation.argument_generations

        if (
            class_name == "Ljavax/crypto/Cipher;"
            and method_name == "getInstance"
            and invocation.invoke_kind == "static"
            and prototype.startswith("(Ljava/lang/String;")
            and arguments
            and isinstance(arguments[0], str)
        ):
            transformation = arguments[0]
            normalized = transformation.upper().replace(" ", "")
            parts = normalized.split("/")
            family = _algorithm_family(transformation)
            if len(parts) >= 2 and parts[1] == "ECB":
                record(
                    "CRYPTO-ECB",
                    "high",
                    "cipher_mode:ecb",
                    f"cipher_family:{family.lower()}",
                )
            elif "/" not in normalized and family in {
                "AES",
                "ARIA",
                "BLOWFISH",
                "CAMELLIA",
                "CAST5",
                "DES",
                "DESEDE",
                "IDEA",
                "RC2",
                "SEED",
                "TRIPLEDES",
            }:
                record(
                    "CRYPTO-ECB",
                    "medium",
                    "cipher_mode:provider_default",
                    f"cipher_family:{family.lower()}",
                )
            weak_family = _weak_cipher_family(transformation)
            if weak_family is not None:
                record(
                    "CRYPTO-WEAK-ALGORITHM",
                    "high",
                    f"weak_cipher_family:{weak_family}",
                )

        if (
            class_name in {"Ljava/security/MessageDigest;", "Ljavax/crypto/Mac;"}
            and method_name == "getInstance"
            and invocation.invoke_kind == "static"
            and arguments
            and isinstance(arguments[0], str)
        ):
            weak_family = _weak_digest_family(arguments[0])
            if weak_family is not None:
                record(
                    "CRYPTO-WEAK-DIGEST",
                    "high",
                    f"weak_digest_family:{weak_family}",
                    (
                        "primitive:message_digest"
                        if class_name == "Ljava/security/MessageDigest;"
                        else "primitive:mac"
                    ),
                )

        iteration: object | None = None
        if (
            class_name == "Ljavax/crypto/spec/PBEParameterSpec;"
            and method_name == "<init>"
            and invocation.invoke_kind == "direct"
            and prototype in {
                "([BI)V",
                "([BILjava/security/spec/AlgorithmParameterSpec;)V",
            }
            and len(arguments) >= 3
        ):
            iteration = arguments[2]
        elif (
            class_name == "Ljavax/crypto/spec/PBEKeySpec;"
            and method_name == "<init>"
            and invocation.invoke_kind == "direct"
            and prototype in {"([C[BI)V", "([C[BII)V"}
            and len(arguments) >= 4
        ):
            iteration = arguments[3]
        if isinstance(iteration, int) and iteration < min_pbe_iterations:
            record(
                "CRYPTO-LOW-PBE-ITERATIONS",
                "high",
                "pbe_iterations:below_policy",
                f"policy_min_iterations:{min_pbe_iterations}",
            )

        if (
            class_name == "Ljava/util/Random;"
            and method_name == "nextBytes"
            and invocation.invoke_kind == "virtual"
            and len(argument_generations) >= 2
        ):
            random_material_generations.add(argument_generations[1])
        crypto_material_inputs = {
            "Ljavax/crypto/spec/SecretKeySpec;": (1, "secret_key"),
            "Ljavax/crypto/spec/IvParameterSpec;": (1, "initialization_vector"),
            "Ljavax/crypto/spec/PBEKeySpec;": (2, "pbe_salt"),
            "Ljavax/crypto/spec/PBEParameterSpec;": (1, "pbe_salt"),
        }
        material_input = crypto_material_inputs.get(class_name)
        if material_input is not None and invocation.invoke_kind == "direct":
            register_index, material_name = material_input
            if (
                len(argument_generations) > register_index
                and argument_generations[register_index]
                in random_material_generations
            ):
                correlated_crypto_material.add(material_name)

        if (
            class_name == "Landroid/webkit/WebSettings;"
            and invocation.invoke_kind == "virtual"
        ):
            unsafe_true = {
                "setAllowContentAccess": "content_access",
                "setAllowFileAccess": "file_access",
                "setAllowFileAccessFromFileURLs": "file_url_access",
                "setAllowUniversalAccessFromFileURLs": "universal_file_url_access",
                "setGeolocationEnabled": "geolocation",
                "setJavaScriptCanOpenWindowsAutomatically": "javascript_windows",
                "setJavaScriptEnabled": "javascript_enabled",
            }
            setting = unsafe_true.get(method_name)
            value = arguments[1] if len(arguments) >= 2 else None
            if setting is not None and value == 1:
                record(
                    "WEBVIEW-UNSAFE-SETTINGS",
                    "high",
                    f"unsafe_web_setting:{setting}",
                    "constant_value:true",
                )
                javascript_enabled = javascript_enabled or (
                    method_name == "setJavaScriptEnabled"
                )
            if method_name == "setMixedContentMode" and value == 0:
                record(
                    "WEBVIEW-UNSAFE-SETTINGS",
                    "high",
                    "unsafe_web_setting:mixed_content",
                    "constant_value:always_allow",
                )
            if method_name == "setSafeBrowsingEnabled" and value == 0:
                record(
                    "WEBVIEW-UNSAFE-SETTINGS",
                    "high",
                    "unsafe_web_setting:safe_browsing_disabled",
                    "constant_value:false",
                )
        if (
            class_name == "Landroid/webkit/WebView;"
            and method_name == "addJavascriptInterface"
            and invocation.invoke_kind == "virtual"
            and prototype == "(Ljava/lang/Object;Ljava/lang/String;)V"
        ):
            javascript_bridge = True
        if (
            class_name == "Landroid/webkit/WebView;"
            and method_name in {"loadUrl", "loadDataWithBaseURL"}
            and invocation.invoke_kind == "virtual"
        ):
            url_argument = arguments[1] if len(arguments) >= 2 else None
            remote_scheme = _is_remote_url(url_argument)
            if remote_scheme is not None:
                remote_web_content.add(remote_scheme)
        if (
            class_name == "Landroid/webkit/SslErrorHandler;"
            and method_name == "proceed"
            and prototype == "()V"
            and invocation.invoke_kind == "virtual"
        ):
            record(
                "WEBVIEW-SSL-ERROR-PROCEED",
                "high",
                "ssl_error_action:proceed",
            )

        dynamic_methods = {
            "Ldalvik/system/DexClassLoader;": {"<init>", "loadClass"},
            "Ldalvik/system/InMemoryDexClassLoader;": {"<init>", "loadClass"},
            "Ldalvik/system/DexFile;": {"loadClass", "loadDex"},
        }
        if (
            method_name in dynamic_methods.get(class_name, set())
            and (
                (method_name == "<init>" and invocation.invoke_kind == "direct")
                or (method_name == "loadDex" and invocation.invoke_kind == "static")
                or (method_name == "loadClass" and invocation.invoke_kind == "virtual")
            )
        ):
            record(
                "ASL-STATIC-DYNAMIC-CODE",
                "high" if method_name in {"<init>", "loadDex"} else "medium",
                "dynamic_code_api:actual_invoke",
                f"dynamic_code_operation:{method_name.lower().strip('<>')}",
            )
        if (
            class_name == "Ljava/io/ObjectInputStream;"
            and method_name == "readObject"
            and prototype == "()Ljava/lang/Object;"
            and invocation.invoke_kind == "virtual"
        ):
            record(
                "ASL-STATIC-DESERIALIZATION",
                "medium",
                "deserialization_api:object_input_stream_read_object",
            )

        storage_mode_index: int | None = None
        if class_name in {
            "Landroid/content/Context;",
            "Landroid/content/ContextWrapper;",
        }:
            if method_name in {"openFileOutput", "getSharedPreferences"}:
                storage_mode_index = 2
            elif method_name == "openOrCreateDatabase":
                storage_mode_index = 2
        if (
            storage_mode_index is not None
            and invocation.invoke_kind == "virtual"
            and len(arguments) > storage_mode_index
        ):
            storage_mode = arguments[storage_mode_index]
            if isinstance(storage_mode, int):
                if storage_mode & 0x01:
                    record(
                        "STORAGE-WORLD-READABLE",
                        "high",
                        "storage_mode:world_readable",
                        f"storage_api:{method_name}",
                    )
                if storage_mode & 0x02:
                    record(
                        "STORAGE-WORLD-WRITABLE",
                        "high",
                        "storage_mode:world_writable",
                        f"storage_api:{method_name}",
                    )

    if correlated_crypto_material:
        record(
            "CRYPTO-PREDICTABLE-RANDOM",
            "medium",
            "random_api:java_util_random_next_bytes",
            "correlation:same_register",
            *(f"crypto_material:{item}" for item in sorted(correlated_crypto_material)),
        )
    if javascript_enabled and javascript_bridge and remote_web_content:
        record(
            "WEBVIEW-JS-BRIDGE-REMOTE",
            "high",
            "webview:javascript_enabled",
            "webview:javascript_interface",
            "webview:remote_constant_content",
            *(f"remote_scheme:{item}" for item in sorted(remote_web_content)),
        )

    return tuple(
        _DexBehaviorSignal(
            rule_id=rule_id,
            confidence=confidence,
            caller_class_descriptor=caller.class_descriptor,
            caller_method_name=caller.method_name,
            caller_prototype=caller.prototype,
            indicators=tuple(sorted(indicators)),
        )
        for rule_id, (confidence, indicators) in sorted(detected.items())
    )


def _parse_dex_behavior(
    data: bytes,
    *,
    limits: StaticApkPolicy,
    strings: Sequence[str | None],
    types: Sequence[str | None],
    method_table: Sequence[DexMethodReference | None],
) -> tuple[
    tuple[_DexBehaviorSignal, ...],
    tuple[str, ...],
    tuple[tuple[str, int], ...],
]:
    class_count, class_offset = _uint32(data, 0x60), _uint32(data, 0x64)
    _validate_table(
        data,
        name="class-def",
        size=class_count,
        offset=class_offset,
        item_size=32,
        maximum=limits.max_dex_strings,
    )
    metrics = {
        "dex_class_defs_seen": class_count,
        "dex_behavior_methods_scanned": 0,
        "dex_behavior_code_units_scanned": 0,
        "dex_behavior_invocations_scanned": 0,
    }
    limitations: list[str] = []

    def limit(name: str) -> None:
        if name not in limitations:
            limitations.append(name)

    class_scan_count = min(class_count, limits.max_dex_class_defs)
    if class_count > class_scan_count:
        limit("dex_class_defs")
    encoded_methods_seen = 0
    encoded_members_seen = 0
    signals: list[_DexBehaviorSignal] = []
    signal_keys: set[tuple[str, str, str, str, tuple[str, ...]]] = set()

    for class_position in range(class_scan_count):
        class_base = class_offset + class_position * 32
        class_index = _uint32(data, class_base)
        class_data_offset = _uint32(data, class_base + 24)
        if class_index >= len(types):
            raise DexFormatError("DEX class definition has an invalid type index.")
        class_descriptor = types[class_index]
        if class_descriptor is not None and not _is_class_descriptor(class_descriptor):
            raise DexFormatError("DEX class definition descriptor is malformed.")
        if class_data_offset == 0:
            continue
        if class_data_offset < _DEX_HEADER_SIZE or class_data_offset >= len(data):
            raise DexFormatError("DEX class data is outside the file bounds.")
        cursor = class_data_offset
        counts: list[int] = []
        for _index in range(4):
            count, cursor = _read_uleb128(data, cursor)
            counts.append(count)
        static_fields, instance_fields, direct_methods, virtual_methods = counts
        class_members = static_fields + instance_fields + direct_methods + virtual_methods
        if (
            class_members > limits.max_dex_encoded_methods
            or encoded_members_seen + class_members > limits.max_dex_encoded_methods
        ):
            limit("dex_encoded_methods")
            continue
        encoded_members_seen += class_members

        for _field_position in range(static_fields + instance_fields):
            _field_index_diff, cursor = _read_uleb128(data, cursor)
            _access_flags, cursor = _read_uleb128(data, cursor)

        for method_list_size in (direct_methods, virtual_methods):
            method_index = 0
            for method_position in range(method_list_size):
                method_index_diff, cursor = _read_uleb128(data, cursor)
                _access_flags, cursor = _read_uleb128(data, cursor)
                code_offset, cursor = _read_uleb128(data, cursor)
                if method_position == 0:
                    method_index = method_index_diff
                else:
                    method_index += method_index_diff
                if method_index >= len(method_table):
                    raise DexFormatError("DEX encoded method has an invalid method index.")
                caller = method_table[method_index]
                if (
                    caller is not None
                    and class_descriptor is not None
                    and caller.class_descriptor != class_descriptor
                ):
                    raise DexFormatError("DEX encoded method belongs to the wrong class.")
                if code_offset == 0 or caller is None:
                    continue
                if encoded_methods_seen >= limits.max_dex_encoded_methods:
                    limit("dex_encoded_methods")
                    continue
                encoded_methods_seen += 1
                if code_offset + 16 > len(data):
                    raise DexFormatError("DEX code item is outside the file bounds.")
                insns_size = _uint32(data, code_offset + 12)
                remaining_code_units = (
                    limits.max_dex_code_units
                    - metrics["dex_behavior_code_units_scanned"]
                )
                if insns_size > remaining_code_units:
                    limit("dex_code_units")
                    continue
                remaining_invocations = (
                    limits.max_dex_invocations
                    - metrics["dex_behavior_invocations_scanned"]
                )
                if remaining_invocations <= 0:
                    limit("dex_invocations")
                    continue
                invocations, code_units, unsupported, invocation_limited = (
                    _scan_dex_invocations(
                        data,
                        code_offset=code_offset,
                        method_table=method_table,
                        string_count=len(strings),
                        invocation_budget=remaining_invocations,
                    )
                )
                metrics["dex_behavior_methods_scanned"] += 1
                metrics["dex_behavior_code_units_scanned"] += code_units
                metrics["dex_behavior_invocations_scanned"] += len(invocations)
                if unsupported:
                    limit("dex_behavior_unsupported_opcode")
                if invocation_limited:
                    limit("dex_invocations")
                for signal in _behavior_signals_for_method(
                    caller,
                    invocations,
                    strings,
                    min_pbe_iterations=limits.min_pbe_iterations,
                ):
                    key = (
                        signal.rule_id,
                        signal.caller_class_descriptor,
                        signal.caller_method_name,
                        signal.caller_prototype,
                        signal.indicators,
                    )
                    if key in signal_keys:
                        continue
                    if len(signals) >= limits.max_static_behavior_candidates:
                        limit("static_behavior_candidates")
                        continue
                    signal_keys.add(key)
                    signals.append(signal)

    return (
        tuple(signals),
        tuple(limitations),
        tuple(sorted(metrics.items())),
    )


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
    string_cache: dict[int, tuple[str | None, bool, int, int]] = {}
    string_work_bytes = 0
    oversized = 0
    oversized_regions: list[tuple[int, int]] = []
    oversized_offsets: set[int] = set()
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
        value, was_oversized, _work_bytes, data_start = cached
        oversized += int(was_oversized)
        if was_oversized and data_offset not in oversized_offsets:
            oversized_offsets.add(data_offset)
            oversized_regions.append((index, data_start))
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

    method_table: list[DexMethodReference | None] = []
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
            method_table.append(None)
            continue
        if not _is_reference_descriptor(class_descriptor):
            raise DexFormatError("DEX method class descriptor is malformed.")
        if not method_name or len(method_name) > 200:
            raise DexFormatError("DEX method name is malformed.")
        method_table.append(
            DexMethodReference(
                class_descriptor=class_descriptor,
                method_name=method_name,
                prototype=prototype,
            )
        )
    behavior_signals, behavior_limitations, behavior_metrics = _parse_dex_behavior(
        data,
        limits=limits,
        strings=strings,
        types=types,
        method_table=method_table,
    )
    return DexInventory(
        strings=tuple(strings),
        method_references=tuple(
            reference for reference in method_table if reference is not None
        ),
        oversized_strings=oversized,
        oversized_string_regions=tuple(oversized_regions),
        behavior_signals=behavior_signals,
        behavior_limitations=behavior_limitations,
        behavior_metrics=behavior_metrics,
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
    if len(candidate.encode("utf-8", errors="surrogatepass")) > (
        collector.policy.max_string_bytes
    ):
        collector.limit("string_candidate_bytes")
        return
    digest = _hash_value(candidate)
    identity = (kind, source_id, digest)
    if identity in collector.secret_keys:
        return
    if (
        len(collector.secrets) + len(collector.endpoints)
        >= collector.policy.max_string_scan_candidates
    ):
        collector.limit("string_scan_candidates")
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
    if len(value.encode("utf-8", errors="surrogatepass")) > (
        collector.policy.max_string_bytes
    ):
        collector.limit("string_candidate_bytes")
        return
    parsed = _redact_endpoint(value)
    if parsed is None:
        return
    digest = _hash_value(value.rstrip(".,;:)]}"))
    identity = (source_id, digest)
    if identity in collector.endpoint_keys:
        return
    if (
        len(collector.secrets) + len(collector.endpoints)
        >= collector.policy.max_string_scan_candidates
    ):
        collector.limit("string_scan_candidates")
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


def _string_scan_timed_out(collector: _Collector, source_id: str) -> bool:
    if source_id in collector.string_scan_timed_out:
        return True
    now = time.monotonic()
    started = collector.string_scan_started.get(source_id)
    if started is None:
        collector.string_scan_started[source_id] = now
        return False
    elapsed_ms = (now - started) * 1000
    if elapsed_ms < collector.policy.max_string_scan_milliseconds:
        return False
    collector.string_scan_timed_out.add(source_id)
    collector.metrics["string_scan_timeouts"] += 1
    collector.limit("string_scan_timeout")
    return True


def _claim_string_scan_bytes(
    collector: _Collector,
    *,
    source_id: str,
    file_key: str,
    requested: int,
) -> int:
    if requested <= 0 or _string_scan_timed_out(collector, source_id):
        return 0
    if (
        len(collector.secrets) + len(collector.endpoints)
        >= collector.policy.max_string_scan_candidates
    ):
        collector.limit("string_scan_candidates")
        return 0
    file_identity = (source_id, file_key)
    file_used = collector.string_scan_file_bytes.get(file_identity, 0)
    source_used = collector.string_scan_source_bytes.get(source_id, 0)
    file_remaining = collector.policy.max_string_scan_file_bytes - file_used
    source_remaining = collector.policy.max_string_scan_apk_bytes - source_used
    allowed = min(requested, max(0, file_remaining), max(0, source_remaining))
    if allowed < requested:
        if file_remaining <= source_remaining:
            collector.limit("string_scan_file_bytes")
        if source_remaining <= file_remaining:
            collector.limit("string_scan_apk_bytes")
    if allowed <= 0:
        return 0
    collector.string_scan_file_bytes[file_identity] = file_used + allowed
    collector.string_scan_source_bytes[source_id] = source_used + allowed
    collector.metrics["string_scan_bytes"] += allowed
    collector.metrics["string_scan_chunks"] += 1
    return allowed


def _accepted_scan_match(
    match: re.Match[str],
    *,
    text_length: int,
    final: bool,
) -> bool:
    if not final and match.end() >= text_length:
        return False
    return True


def _scan_text_window(
    collector: _Collector,
    *,
    source_id: str,
    location: str,
    bounded: str,
    final: bool,
) -> None:
    text_length = len(bounded)
    for match in _PRIVATE_KEY_HEADER_PATTERN.finditer(bounded):
        if not _accepted_scan_match(
            match,
            text_length=text_length,
            final=final,
        ):
            continue
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
            if not _accepted_scan_match(
                match,
                text_length=text_length,
                final=final,
            ):
                continue
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
        if not _accepted_scan_match(
            match,
            text_length=text_length,
            final=final,
        ):
            continue
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
        if not _accepted_scan_match(
            match,
            text_length=text_length,
            final=final,
        ):
            continue
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


def _scan_encoded_region(
    collector: _Collector,
    *,
    source_id: str,
    file_key: str,
    location: str,
    value: bytes | memoryview,
    complete: bool,
) -> None:
    chunk_size = collector.policy.max_string_scan_chunk_bytes
    overlap = min(collector.policy.max_string_bytes, chunk_size - 1)
    step = chunk_size - overlap
    total = len(value)
    offset = 0
    covered_end = 0
    multi_window = total > chunk_size or not complete
    while offset < total:
        desired_end = min(offset + chunk_size, total)
        new_bytes_requested = max(0, desired_end - covered_end)
        new_bytes_allowed = _claim_string_scan_bytes(
            collector,
            source_id=source_id,
            file_key=file_key,
            requested=new_bytes_requested,
        )
        if new_bytes_allowed <= 0:
            return
        window_end = covered_end + new_bytes_allowed
        raw_window = bytes(value[offset:window_end])
        reached_end = window_end >= total
        final = complete and reached_end
        bounded = raw_window.decode("utf-8", errors="replace")
        window_location = (
            f"{location}:offset:{offset}" if multi_window else location
        )
        _scan_text_window(
            collector,
            source_id=source_id,
            location=window_location,
            bounded=bounded,
            final=final,
        )
        covered_end = window_end
        if new_bytes_allowed < new_bytes_requested or reached_end:
            return
        offset = max(offset + step, covered_end - overlap)


def _bounded_dex_string_end(
    collector: _Collector,
    *,
    source_id: str,
    file_key: str,
    data: bytes,
    data_start: int,
) -> tuple[int, bool] | None:
    file_used = collector.string_scan_file_bytes.get((source_id, file_key), 0)
    source_used = collector.string_scan_source_bytes.get(source_id, 0)
    file_remaining = collector.policy.max_string_scan_file_bytes - file_used
    source_remaining = collector.policy.max_string_scan_apk_bytes - source_used
    available = min(max(0, file_remaining), max(0, source_remaining))
    if available <= 0:
        _claim_string_scan_bytes(
            collector,
            source_id=source_id,
            file_key=file_key,
            requested=1,
        )
        return None
    maximum = min(len(data), data_start + available)
    position = data_start
    while position < maximum:
        if _string_scan_timed_out(collector, source_id):
            return None
        chunk_end = min(
            position + collector.policy.max_string_scan_chunk_bytes,
            maximum,
        )
        terminator = data.find(b"\x00", position, chunk_end)
        if terminator >= 0:
            return terminator, True
        position = chunk_end
    if maximum < len(data):
        if file_remaining <= source_remaining:
            collector.limit("string_scan_file_bytes")
        if source_remaining <= file_remaining:
            collector.limit("string_scan_apk_bytes")
    else:
        collector.problem(source_id, "unterminated_dex_string")
    return maximum, False


def _scan_dex_oversized_region(
    collector: _Collector,
    *,
    source_id: str,
    dex_entry: str,
    string_index: int,
    data: bytes,
    data_start: int,
) -> None:
    bounded_end = _bounded_dex_string_end(
        collector,
        source_id=source_id,
        file_key=dex_entry,
        data=data,
        data_start=data_start,
    )
    if bounded_end is None:
        return
    end, complete = bounded_end
    if end <= data_start:
        return
    _scan_encoded_region(
        collector,
        source_id=source_id,
        file_key=dex_entry,
        location=f"{dex_entry}:string:{string_index}",
        value=memoryview(data)[data_start:end],
        complete=complete,
    )
    collector.metrics["oversized_dex_strings_scanned"] += 1


def _scan_text(
    collector: _Collector,
    *,
    source_id: str,
    location: str,
    value: str,
    file_key: str,
) -> None:
    encoded = value.encode("utf-8", errors="surrogatepass")
    _scan_encoded_region(
        collector,
        source_id=source_id,
        file_key=file_key,
        location=location,
        value=encoded,
        complete=True,
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
    for (
        inventory_id,
        category,
        class_descriptor,
        method_name,
        prototypes,
    ) in _SECURITY_API_INDEX.get(
        (reference.class_descriptor, reference.method_name),
        (),
    ):
        if (
            reference.class_descriptor != class_descriptor
            or reference.method_name != method_name
            or reference.prototype not in prototypes
        ):
            continue
        identity = (
            inventory_id,
            source_id,
            dex_entry,
            reference.method_name,
            reference.prototype,
        )
        if identity in collector.security_keys:
            break
        if len(collector.security) >= collector.policy.max_security_api_matches:
            collector.limit("security_api_matches")
            break
        collector.security_keys.add(identity)
        collector.security.append(
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


def _record_behavior_signal(
    collector: _Collector,
    *,
    source_id: str,
    dex_entry: str,
    signal: _DexBehaviorSignal,
) -> None:
    identity = (
        signal.rule_id,
        source_id,
        dex_entry,
        signal.caller_class_descriptor,
        f"{signal.caller_method_name}{signal.caller_prototype}",
    )
    if identity in collector.behavior_keys:
        return
    if len(collector.behavior) >= collector.policy.max_static_behavior_candidates:
        collector.limit("static_behavior_candidates")
        return
    collector.behavior_keys.add(identity)
    collector.behavior.append(
        StaticBehaviorCandidate(
            rule_id=signal.rule_id,
            confidence=signal.confidence,
            source_id=source_id,
            dex_entry=dex_entry,
            caller_class_descriptor=signal.caller_class_descriptor,
            caller_method_name=signal.caller_method_name,
            caller_prototype=signal.caller_prototype,
            indicators=signal.indicators,
        )
    )
    collector.metrics["static_behavior_candidates"] += 1


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
                    for metric_name, metric_value in inventory.behavior_metrics:
                        collector.metrics[metric_name] += metric_value
                    for limitation in inventory.behavior_limitations:
                        collector.limit(limitation)
                    for index, value in enumerate(inventory.strings):
                        if value is not None:
                            _scan_text(
                                collector,
                                source_id=item.source_id,
                                location=f"{info.filename}:string:{index}",
                                value=value,
                                file_key=info.filename,
                            )
                    for index, data_start in inventory.oversized_string_regions:
                        _scan_dex_oversized_region(
                            collector,
                            source_id=item.source_id,
                            dex_entry=info.filename,
                            string_index=index,
                            data=data,
                            data_start=data_start,
                        )
                    for reference in inventory.method_references:
                        _record_method_reference(
                            collector,
                            source_id=item.source_id,
                            dex_entry=info.filename,
                            reference=reference,
                        )
                    for signal in inventory.behavior_signals:
                        _record_behavior_signal(
                            collector,
                            source_id=item.source_id,
                            dex_entry=info.filename,
                            signal=signal,
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
                            file_key=info.filename,
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
                file_key="resource_strings",
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
        security_api_candidates=tuple(
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
            for item in sorted(
                collector.security,
                key=lambda value: (
                    value.source_id,
                    value.dex_entry,
                    value.inventory_id,
                    value.class_descriptor,
                    value.method_name,
                    value.prototype,
                ),
            )
        ),
        static_behavior_candidates=tuple(
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
                caller_class_descriptor=_safe_metadata_text(
                    item.caller_class_descriptor,
                    sensitive_values=sensitive_values,
                ),
                caller_method_name=_safe_metadata_text(
                    item.caller_method_name,
                    sensitive_values=sensitive_values,
                ),
                caller_prototype=_safe_metadata_text(
                    item.caller_prototype,
                    sensitive_values=sensitive_values,
                ),
                indicators=tuple(
                    _safe_metadata_text(
                        indicator,
                        sensitive_values=sensitive_values,
                    )
                    for indicator in item.indicators
                ),
            )
            for item in sorted(
                collector.behavior,
                key=lambda value: (
                    value.source_id,
                    value.dex_entry,
                    value.rule_id,
                    value.caller_class_descriptor,
                    value.caller_method_name,
                    value.caller_prototype,
                ),
            )
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
