from __future__ import annotations

import io
import json
import struct
from dataclasses import fields, replace
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

import pytest

import android_assessor.static_apk_analysis as static_analysis
from android_assessor.manifest import parse_aapt_strings
from android_assessor.static_apk_analysis import (
    ApiPolicyEntry,
    DexFormatError,
    StaticApkInput,
    StaticApkPolicy,
    analyze_apks,
    parse_dex_inventory,
)


def _uleb128(value: int) -> bytes:
    output = bytearray()
    while True:
        item = value & 0x7F
        value >>= 7
        output.append(item | (0x80 if value else 0))
        if not value:
            return bytes(output)


def _shorty(descriptor: str) -> str:
    return "L" if descriptor.startswith(("L", "[")) else descriptor[0]


def _mutf8(value: str) -> tuple[int, bytes]:
    utf16 = value.encode("utf-16-le", errors="surrogatepass")
    code_units = [
        struct.unpack_from("<H", utf16, offset)[0]
        for offset in range(0, len(utf16), 2)
    ]
    output = bytearray()
    for item in code_units:
        if 0x01 <= item <= 0x7F:
            output.append(item)
        elif item <= 0x7FF:
            output.extend((0xC0 | (item >> 6), 0x80 | (item & 0x3F)))
        else:
            output.extend(
                (
                    0xE0 | (item >> 12),
                    0x80 | ((item >> 6) & 0x3F),
                    0x80 | (item & 0x3F),
                )
            )
    return len(code_units), bytes(output)


def build_dex(
    *,
    extra_strings: tuple[str, ...] = (),
    methods: tuple[tuple[str, str, tuple[str, ...], str], ...] = (),
    method_bodies: tuple[tuple[int, int, tuple[int, ...]], ...] = (),
) -> bytes:
    strings: list[str] = []

    def add_string(value: str) -> int:
        if value not in strings:
            strings.append(value)
        return strings.index(value)

    for value in extra_strings:
        add_string(value)
    types: list[str] = []

    def add_type(value: str) -> int:
        add_string(value)
        if value not in types:
            types.append(value)
        return types.index(value)

    prototypes: list[tuple[tuple[str, ...], str]] = []
    for class_descriptor, method_name, parameters, return_type in methods:
        add_type(class_descriptor)
        add_string(method_name)
        add_type(return_type)
        for parameter in parameters:
            add_type(parameter)
        prototype = (parameters, return_type)
        if prototype not in prototypes:
            prototypes.append(prototype)
        add_string(_shorty(return_type) + "".join(_shorty(item) for item in parameters))

    cursor = 0x70
    string_ids_offset = cursor if strings else 0
    cursor += len(strings) * 4
    type_ids_offset = cursor if types else 0
    cursor += len(types) * 4
    proto_ids_offset = cursor if prototypes else 0
    cursor += len(prototypes) * 12
    method_ids_offset = cursor if methods else 0
    cursor += len(methods) * 8
    body_classes = sorted(
        {methods[method_index][0] for method_index, _registers, _insns in method_bodies}
    )
    class_defs_offset = cursor if body_classes else 0
    cursor += len(body_classes) * 32
    cursor = (cursor + 3) & ~3
    data_offset = cursor

    parameter_offsets: dict[tuple[str, ...], int] = {}
    type_list_data = bytearray()
    for parameters, _return_type in prototypes:
        if not parameters or parameters in parameter_offsets:
            continue
        while (cursor + len(type_list_data)) % 4:
            type_list_data.append(0)
        parameter_offsets[parameters] = cursor + len(type_list_data)
        type_list_data.extend(struct.pack("<I", len(parameters)))
        for parameter in parameters:
            type_list_data.extend(struct.pack("<H", types.index(parameter)))
    cursor += len(type_list_data)

    code_offsets: dict[int, int] = {}
    code_item_data = bytearray()
    for method_index, registers_size, insns in sorted(method_bodies):
        assert 0 <= method_index < len(methods)
        assert method_index not in code_offsets
        while (cursor + len(code_item_data)) % 4:
            code_item_data.append(0)
        code_offsets[method_index] = cursor + len(code_item_data)
        code_item_data.extend(
            struct.pack("<HHHHII", registers_size, 0, 5, 0, 0, len(insns))
        )
        code_item_data.extend(struct.pack(f"<{len(insns)}H", *insns))
    cursor += len(code_item_data)

    class_data_offsets: dict[str, int] = {}
    class_data = bytearray()
    for class_descriptor in body_classes:
        class_data_offsets[class_descriptor] = cursor + len(class_data)
        method_indexes = sorted(
            method_index
            for method_index, _registers, _insns in method_bodies
            if methods[method_index][0] == class_descriptor
        )
        class_data.extend(_uleb128(0))
        class_data.extend(_uleb128(0))
        class_data.extend(_uleb128(len(method_indexes)))
        class_data.extend(_uleb128(0))
        previous = 0
        for position, method_index in enumerate(method_indexes):
            class_data.extend(
                _uleb128(method_index if position == 0 else method_index - previous)
            )
            class_data.extend(_uleb128(0x09))
            class_data.extend(_uleb128(code_offsets[method_index]))
            previous = method_index
    cursor += len(class_data)

    string_offsets: list[int] = []
    string_data = bytearray()
    for value in strings:
        utf16_length, encoded = _mutf8(value)
        string_offsets.append(cursor + len(string_data))
        string_data.extend(_uleb128(utf16_length))
        string_data.extend(encoded)
        string_data.append(0)
    file_size = cursor + len(string_data)
    value = bytearray(file_size)
    value[:8] = b"dex\n035\x00"
    struct.pack_into("<I", value, 0x20, file_size)
    struct.pack_into("<I", value, 0x24, 0x70)
    struct.pack_into("<I", value, 0x28, 0x12345678)
    struct.pack_into("<II", value, 0x38, len(strings), string_ids_offset)
    struct.pack_into("<II", value, 0x40, len(types), type_ids_offset)
    struct.pack_into("<II", value, 0x48, len(prototypes), proto_ids_offset)
    struct.pack_into("<II", value, 0x58, len(methods), method_ids_offset)
    struct.pack_into("<II", value, 0x60, len(body_classes), class_defs_offset)
    if not (type_list_data or code_item_data or class_data or string_data):
        data_offset = 0x70
    struct.pack_into("<II", value, 0x68, file_size - data_offset, data_offset)

    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", value, string_ids_offset + index * 4, offset)
    for index, descriptor in enumerate(types):
        struct.pack_into("<I", value, type_ids_offset + index * 4, strings.index(descriptor))
    for index, (parameters, return_type) in enumerate(prototypes):
        base = proto_ids_offset + index * 12
        shorty = _shorty(return_type) + "".join(_shorty(item) for item in parameters)
        struct.pack_into(
            "<III",
            value,
            base,
            strings.index(shorty),
            types.index(return_type),
            parameter_offsets.get(parameters, 0),
        )
    for index, (class_descriptor, method_name, parameters, return_type) in enumerate(
        methods
    ):
        struct.pack_into(
            "<HHI",
            value,
            method_ids_offset + index * 8,
            types.index(class_descriptor),
            prototypes.index((parameters, return_type)),
            strings.index(method_name),
        )
    for index, class_descriptor in enumerate(body_classes):
        struct.pack_into(
            "<IIIIIIII",
            value,
            class_defs_offset + index * 32,
            types.index(class_descriptor),
            0x01,
            0xFFFFFFFF,
            0,
            0xFFFFFFFF,
            0,
            class_data_offsets[class_descriptor],
            0,
        )
    data_cursor = data_offset
    value[data_cursor : data_cursor + len(type_list_data)] = type_list_data
    data_cursor += len(type_list_data)
    value[data_cursor : data_cursor + len(code_item_data)] = code_item_data
    data_cursor += len(code_item_data)
    value[data_cursor : data_cursor + len(class_data)] = class_data
    value[cursor:] = string_data
    return bytes(value)


def _const_string(register: int, string_index: int) -> tuple[int, ...]:
    assert 0 <= register <= 0xFF
    assert 0 <= string_index <= 0xFFFF
    return (0x1A | (register << 8), string_index)


def _const_int(register: int, value: int) -> tuple[int, ...]:
    assert 0 <= register <= 0xFF
    assert -0x8000 <= value <= 0x7FFF
    return (0x13 | (register << 8), value & 0xFFFF)


def _invoke(
    method_index: int,
    registers: tuple[int, ...],
    *,
    static: bool = False,
    direct: bool = False,
) -> tuple[int, ...]:
    assert len(registers) <= 5
    assert all(0 <= register <= 0x0F for register in registers)
    padded = (*registers, 0, 0, 0, 0, 0)
    first = (
        (0x71 if static else 0x70 if direct else 0x6E)
        | (len(registers) << 12)
        | ((padded[4] if len(registers) == 5 else 0) << 8)
    )
    packed = padded[0] | (padded[1] << 4) | (padded[2] << 8) | (padded[3] << 12)
    return first, method_index, packed


def _first_code_offset(value: bytes) -> int:
    class_defs_offset = struct.unpack_from("<I", value, 0x64)[0]
    class_data_offset = struct.unpack_from("<I", value, class_defs_offset + 24)[0]
    cursor = class_data_offset

    def read_uleb() -> int:
        nonlocal cursor
        decoded = 0
        shift = 0
        while True:
            item = value[cursor]
            cursor += 1
            decoded |= (item & 0x7F) << shift
            if not item & 0x80:
                return decoded
            shift += 7

    counts = tuple(read_uleb() for _index in range(4))
    assert counts[:2] == (0, 0)
    assert counts[2] >= 1
    read_uleb()
    read_uleb()
    return read_uleb()


def write_apk(
    path: Path,
    dex: bytes,
    *,
    entries: dict[str, bytes] | None = None,
    compression: int = ZIP_STORED,
) -> None:
    with ZipFile(path, "w", compression=compression) as archive:
        archive.writestr("classes.dex", dex)
        for name, content in (entries or {}).items():
            archive.writestr(name, content)


def mutate_zip_entry(
    path: Path,
    name: str,
    *,
    set_flags: int = 0,
    corrupt_data: bool = False,
) -> None:
    value = bytearray(path.read_bytes())
    eocd = value.rfind(b"PK\x05\x06")
    assert eocd >= 0
    entry_count = struct.unpack_from("<H", value, eocd + 10)[0]
    central = struct.unpack_from("<I", value, eocd + 16)[0]
    for _index in range(entry_count):
        assert value[central : central + 4] == b"PK\x01\x02"
        filename_size, extra_size, comment_size = struct.unpack_from(
            "<HHH",
            value,
            central + 28,
        )
        filename = bytes(
            value[central + 46 : central + 46 + filename_size]
        ).decode("utf-8")
        if filename == name:
            local = struct.unpack_from("<I", value, central + 42)[0]
            assert value[local : local + 4] == b"PK\x03\x04"
            if set_flags:
                central_flags = struct.unpack_from("<H", value, central + 8)[0]
                local_flags = struct.unpack_from("<H", value, local + 6)[0]
                struct.pack_into("<H", value, central + 8, central_flags | set_flags)
                struct.pack_into("<H", value, local + 6, local_flags | set_flags)
            if corrupt_data:
                local_name_size, local_extra_size = struct.unpack_from(
                    "<HH",
                    value,
                    local + 26,
                )
                data_offset = local + 30 + local_name_size + local_extra_size
                value[data_offset] ^= 0x01
            path.write_bytes(value)
            return
        central += 46 + filename_size + extra_size + comment_size
    raise AssertionError(f"ZIP entry not found: {name}")


def test_parses_exact_dex_method_references() -> None:
    dex = build_dex(
        extra_strings=("emoji-😀",),
        methods=(
            (
                "Ldalvik/system/DexClassLoader;",
                "loadClass",
                ("Ljava/lang/String;",),
                "Ljava/lang/Class;",
            ),
        )
    )

    inventory = parse_dex_inventory(dex)

    assert inventory.method_references[0].class_descriptor == (
        "Ldalvik/system/DexClassLoader;"
    )
    assert inventory.method_references[0].method_name == "loadClass"
    assert inventory.method_references[0].prototype == (
        "(Ljava/lang/String;)Ljava/lang/Class;"
    )
    assert "emoji-😀" in inventory.strings


@pytest.mark.parametrize("mutation", ["magic", "file_size", "string_table", "method_ref"])
def test_rejects_malformed_dex_structures(mutation: str) -> None:
    value = bytearray(
        build_dex(
            methods=(("Ljava/lang/Thread;", "stop", (), "V"),),
        )
    )
    if mutation == "magic":
        value[:8] = b"not-dex!"
    elif mutation == "file_size":
        struct.pack_into("<I", value, 0x20, len(value) + 1)
    elif mutation == "string_table":
        struct.pack_into("<I", value, 0x3C, len(value) - 1)
    else:
        method_offset = struct.unpack_from("<I", value, 0x5C)[0]
        struct.pack_into("<H", value, method_offset, 65535)

    with pytest.raises(DexFormatError):
        parse_dex_inventory(bytes(value))


def test_inventory_redacts_secrets_endpoints_and_matches_exact_apis(
    tmp_path: Path,
) -> None:
    raw_secret = "REALPRODKEY_9x8y7z6w5v4u"
    query_secret = "query-token-9x8y7z6w"
    dex = build_dex(
        extra_strings=(
            f"api_key={raw_secret}",
            (
                "https://user:private-password@api.example.test/v1/items"
                f"?access_token={query_secret}&safe=yes"
            ),
        ),
        methods=(
            (
                "Ldalvik/system/DexClassLoader;",
                "<init>",
                (
                    "Ljava/lang/String;",
                    "Ljava/lang/String;",
                    "Ljava/lang/String;",
                    "Ljava/lang/ClassLoader;",
                ),
                "V",
            ),
            ("Landroid/webkit/WebSettings;", "setSavePassword", ("Z",), "V"),
        ),
    )
    apk = tmp_path / "base.apk"
    write_apk(
        apk,
        dex,
        entries={
            "assets/plugin.jar": b"nested archive is inventory only",
            "assets/settings.json": f'{{"client_secret":"{raw_secret}"}}'.encode(),
        },
    )

    result = analyze_apks((StaticApkInput(apk, "apk/base"),))
    serialized = json.dumps(result.to_dict())

    assert result.status == "completed"
    assert len(result.secret_candidates) == 3
    assert {item.value_length for item in result.secret_candidates} == {
        len(raw_secret),
        len(query_secret),
        len("private-password"),
    }
    assert "basic_auth_password" in {
        item.kind for item in result.secret_candidates
    }
    assert raw_secret not in serialized
    assert query_secret not in serialized
    assert "private-password" not in serialized
    assert result.endpoints[0].redacted_url == (
        "https://api.example.test/<redacted>/<redacted>"
        "?parameter_1=%3Credacted%3E&parameter_2=%3Credacted%3E"
    )
    assert [item.inventory_id for item in result.dynamic_loading_apis] == [
        "DEX_CLASS_LOADER"
    ]
    assert [item.policy_id for item in result.api_policy_matches] == [
        "ANDROID-WEBSETTINGS-SAVE-PASSWORD"
    ]
    assert result.embedded_code[0].archive_entry == "assets/plugin.jar"


def test_security_api_inventory_matches_exact_references_only(tmp_path: Path) -> None:
    apk = tmp_path / "security-api-inventory.apk"
    write_apk(
        apk,
        build_dex(
            extra_strings=("setAllowFileAccessFromFileURLs",),
            methods=(
                (
                    "Landroid/webkit/WebSettings;",
                    "setJavaScriptEnabled",
                    ("Z",),
                    "V",
                ),
                (
                    "Ljavax/net/ssl/SSLContext;",
                    "init",
                    (
                        "[Ljavax/net/ssl/KeyManager;",
                        "[Ljavax/net/ssl/TrustManager;",
                        "Ljava/security/SecureRandom;",
                    ),
                    "V",
                ),
                (
                    "Ljava/security/MessageDigest;",
                    "getInstance",
                    ("Ljava/lang/String;",),
                    "Ljava/security/MessageDigest;",
                ),
                (
                    "Landroid/app/PendingIntent;",
                    "getActivity",
                    (
                        "Landroid/content/Context;",
                        "I",
                        "Landroid/content/Intent;",
                        "I",
                    ),
                    "Landroid/app/PendingIntent;",
                ),
                # Same method name on another class is not an Android API match.
                ("Lcom/example/WebSettings;", "setJavaScriptEnabled", ("Z",), "V"),
                # Exact class/name with a wrong prototype is also not a match.
                (
                    "Landroid/webkit/WebSettings;",
                    "setJavaScriptEnabled",
                    ("I",),
                    "V",
                ),
                (
                    "Ljava/security/MessageDigest;",
                    "getInstance",
                    ("Ljava/lang/String;",),
                    "Ljava/lang/Object;",
                ),
            ),
        ),
    )

    result = analyze_apks((StaticApkInput(apk, "apk/security"),))
    serialized = result.to_dict()

    assert serialized["schema_version"] == 2
    assert [item.inventory_id for item in result.security_api_candidates] == [
        "CRYPTO_MESSAGE_DIGEST_INSTANCE",
        "PENDING_INTENT_ACTIVITY",
        "TLS_SSL_CONTEXT_INIT",
        "WEBVIEW_JAVASCRIPT_ENABLED",
    ]
    assert {item.category for item in result.security_api_candidates} == {
        "crypto",
        "pending_intent",
        "tls",
        "webview",
    }
    assert len(serialized["security_api_candidates"]) == 4


def test_static_behavior_candidates_require_actual_crypto_invokes(tmp_path: Path) -> None:
    methods = (
        ("Lfixture/SecurityFlow;", "inspect", (), "V"),
        (
            "Ljavax/crypto/Cipher;",
            "getInstance",
            ("Ljava/lang/String;",),
            "Ljavax/crypto/Cipher;",
        ),
        (
            "Ljava/security/MessageDigest;",
            "getInstance",
            ("Ljava/lang/String;",),
            "Ljava/security/MessageDigest;",
        ),
        (
            "Ljavax/crypto/spec/PBEKeySpec;",
            "<init>",
            ("[C", "[B", "I", "I"),
            "V",
        ),
        ("Ljava/util/Random;", "nextBytes", ("[B",), "V"),
        (
            "Ljavax/crypto/spec/SecretKeySpec;",
            "<init>",
            ("[B", "Ljava/lang/String;"),
            "V",
        ),
    )
    insns = (
        *_const_string(0, 0),
        *_invoke(1, (0,), static=True),
        *_const_string(1, 1),
        *_invoke(1, (1,), static=True),
        *_const_string(2, 2),
        *_invoke(2, (2,), static=True),
        *_const_int(3, 500),
        *_invoke(3, (4, 5, 6, 3, 7), direct=True),
        *_invoke(4, (8, 9)),
        *_invoke(5, (10, 9, 11), direct=True),
        0x0E,
    )
    apk = tmp_path / "crypto-behavior.apk"
    write_apk(
        apk,
        build_dex(
            extra_strings=("AES/ECB/PKCS5Padding", "DES/CBC/PKCS5Padding", "MD5"),
            methods=methods,
            method_bodies=((0, 12, insns),),
        ),
    )

    result = analyze_apks((StaticApkInput(apk, "apk/crypto-behavior"),))
    candidates = result.static_behavior_candidates

    assert {item.rule_id for item in candidates} == {
        "CRYPTO-ECB",
        "CRYPTO-LOW-PBE-ITERATIONS",
        "CRYPTO-PREDICTABLE-RANDOM",
        "CRYPTO-WEAK-ALGORITHM",
        "CRYPTO-WEAK-DIGEST",
    }
    assert {item.caller_method_name for item in candidates} == {"inspect"}
    serialized_candidates = json.dumps(
        result.to_dict()["static_behavior_candidates"]
    )
    assert set(result.to_dict()["static_behavior_candidates"][0]) == {
        "rule_id",
        "confidence",
        "source_id",
        "dex_entry",
        "caller_class_descriptor",
        "caller_method_name",
        "caller_prototype",
        "indicators",
    }
    assert "AES/ECB/PKCS5Padding" not in serialized_candidates
    assert "DES/CBC/PKCS5Padding" not in serialized_candidates
    assert result.metrics["dex_behavior_invocations_scanned"] == 6


def test_static_behavior_correlates_webview_calls_within_one_caller(
    tmp_path: Path,
) -> None:
    methods = (
        ("Lfixture/WebFlow;", "configure", (), "V"),
        (
            "Landroid/webkit/WebSettings;",
            "setJavaScriptEnabled",
            ("Z",),
            "V",
        ),
        (
            "Landroid/webkit/WebSettings;",
            "setAllowUniversalAccessFromFileURLs",
            ("Z",),
            "V",
        ),
        (
            "Landroid/webkit/WebSettings;",
            "setMixedContentMode",
            ("I",),
            "V",
        ),
        (
            "Landroid/webkit/WebView;",
            "addJavascriptInterface",
            ("Ljava/lang/Object;", "Ljava/lang/String;"),
            "V",
        ),
        (
            "Landroid/webkit/WebView;",
            "loadUrl",
            ("Ljava/lang/String;",),
            "V",
        ),
        ("Landroid/webkit/SslErrorHandler;", "proceed", (), "V"),
    )
    insns = (
        *_const_int(1, 1),
        *_invoke(1, (0, 1)),
        *_invoke(2, (0, 1)),
        *_const_int(2, 0),
        *_invoke(3, (0, 2)),
        *_invoke(4, (3, 4, 5)),
        *_const_string(6, 0),
        *_invoke(5, (3, 6)),
        *_invoke(6, (7,)),
        0x0E,
    )
    remote_url = "https://remote.example.test/content?token=never-serialize"
    apk = tmp_path / "web-behavior.apk"
    write_apk(
        apk,
        build_dex(
            extra_strings=(remote_url,),
            methods=methods,
            method_bodies=((0, 8, insns),),
        ),
    )

    result = analyze_apks((StaticApkInput(apk, "apk/web-behavior"),))
    candidates = result.static_behavior_candidates

    assert {item.rule_id for item in candidates} == {
        "WEBVIEW-JS-BRIDGE-REMOTE",
        "WEBVIEW-SSL-ERROR-PROCEED",
        "WEBVIEW-UNSAFE-SETTINGS",
    }
    candidate_json = json.dumps(result.to_dict()["static_behavior_candidates"])
    assert remote_url not in candidate_json
    bridge = next(
        item for item in candidates if item.rule_id == "WEBVIEW-JS-BRIDGE-REMOTE"
    )
    assert "remote_scheme:https" in bridge.indicators


def test_static_behavior_never_correlates_global_strings_or_separate_callers() -> None:
    methods = (
        ("Lfixture/SeparatedFlow;", "enableBridge", (), "V"),
        ("Lfixture/SeparatedFlow;", "loadRemote", (), "V"),
        (
            "Landroid/webkit/WebSettings;",
            "setJavaScriptEnabled",
            ("Z",),
            "V",
        ),
        (
            "Landroid/webkit/WebView;",
            "addJavascriptInterface",
            ("Ljava/lang/Object;", "Ljava/lang/String;"),
            "V",
        ),
        (
            "Landroid/webkit/WebView;",
            "loadUrl",
            ("Ljava/lang/String;",),
            "V",
        ),
        (
            "Ljavax/crypto/Cipher;",
            "getInstance",
            ("Ljava/lang/String;",),
            "Ljavax/crypto/Cipher;",
        ),
    )
    first_body = (
        *_const_int(1, 1),
        *_invoke(2, (0, 1)),
        *_invoke(3, (2, 3, 4)),
        0x0E,
    )
    second_body = (
        *_const_string(1, 0),
        *_invoke(4, (0, 1)),
        0x0E,
    )
    inventory = parse_dex_inventory(
        build_dex(
            extra_strings=("https://remote.example.test/", "AES/ECB/PKCS5Padding"),
            methods=methods,
            method_bodies=((0, 5, first_body), (1, 2, second_body)),
        )
    )

    assert "WEBVIEW-JS-BRIDGE-REMOTE" not in {
        item.rule_id for item in inventory.behavior_signals
    }
    assert "CRYPTO-ECB" not in {item.rule_id for item in inventory.behavior_signals}


@pytest.mark.parametrize(
    ("overwrite_name", "overwrite"),
    (
        ("12x-neg-int", (0x7B | (1 << 8) | (2 << 12),)),
        ("12x-binop-2addr", (0xB0 | (1 << 8) | (2 << 12),)),
        ("22c-instance-of", (0x20 | (1 << 8) | (2 << 12), 0)),
        ("22s-add-int-lit16", (0xD0 | (1 << 8) | (2 << 12), 0)),
        ("const-wide", (0x16 | (1 << 8), 0)),
        ("move-wide", (0x04 | (1 << 8),)),
        ("const-method-handle", (0xFE | (1 << 8), 0)),
        ("const-method-type", (0xFF | (1 << 8), 0)),
    ),
)
def test_static_behavior_kills_stale_constants_for_dex_destination_formats(
    overwrite_name: str,
    overwrite: tuple[int, ...],
) -> None:
    methods = (
        ("Lfixture/RegisterFlow;", "configure", (), "V"),
        (
            "Landroid/webkit/WebSettings;",
            "setJavaScriptEnabled",
            ("Z",),
            "V",
        ),
    )
    insns = (
        *_const_int(1, 1),
        *_const_int(2, 0),
        *overwrite,
        *_invoke(1, (0, 1)),
        0x0E,
    )

    inventory = parse_dex_inventory(
        build_dex(methods=methods, method_bodies=((0, 3, insns),))
    )

    assert overwrite_name
    assert "WEBVIEW-UNSAFE-SETTINGS" not in {
        item.rule_id for item in inventory.behavior_signals
    }


def test_predictable_random_requires_forward_unbroken_value_provenance() -> None:
    methods = (
        ("Lfixture/RandomFlow;", "positive", (), "V"),
        ("Lfixture/RandomFlow;", "reversed", (), "V"),
        ("Lfixture/RandomFlow;", "overwritten", (), "V"),
        ("Ljava/util/Random;", "nextBytes", ("[B",), "V"),
        (
            "Ljavax/crypto/spec/SecretKeySpec;",
            "<init>",
            ("[B", "Ljava/lang/String;"),
            "V",
        ),
    )
    random_call = _invoke(3, (0, 1))
    crypto_constructor = _invoke(4, (2, 1, 3), direct=True)
    positive = (*random_call, *crypto_constructor, 0x0E)
    reversed_calls = (*crypto_constructor, *random_call, 0x0E)
    overwrite_byte_array = 0x07 | (1 << 8) | (4 << 12)
    overwritten = (
        *random_call,
        overwrite_byte_array,
        *crypto_constructor,
        0x0E,
    )

    inventory = parse_dex_inventory(
        build_dex(
            methods=methods,
            method_bodies=(
                (0, 5, positive),
                (1, 5, reversed_calls),
                (2, 5, overwritten),
            ),
        )
    )
    predictable = [
        item
        for item in inventory.behavior_signals
        if item.rule_id == "CRYPTO-PREDICTABLE-RANDOM"
    ]

    assert [item.caller_method_name for item in predictable] == ["positive"]


def test_static_behavior_emits_generic_storage_loading_and_deserialization() -> None:
    methods = (
        ("Lfixture/GenericFlow;", "run", (), "V"),
        (
            "Landroid/content/Context;",
            "openFileOutput",
            ("Ljava/lang/String;", "I"),
            "Ljava/io/FileOutputStream;",
        ),
        (
            "Ldalvik/system/DexFile;",
            "loadDex",
            ("Ljava/lang/String;", "Ljava/lang/String;", "I"),
            "Ldalvik/system/DexFile;",
        ),
        (
            "Ljava/io/ObjectInputStream;",
            "readObject",
            (),
            "Ljava/lang/Object;",
        ),
    )
    insns = (
        *_const_int(2, 3),
        *_invoke(1, (0, 1, 2)),
        *_invoke(2, (3, 4, 5), static=True),
        *_invoke(3, (6,)),
        0x0E,
    )
    inventory = parse_dex_inventory(
        build_dex(methods=methods, method_bodies=((0, 7, insns),))
    )

    assert {item.rule_id for item in inventory.behavior_signals} == {
        "ASL-STATIC-DESERIALIZATION",
        "ASL-STATIC-DYNAMIC-CODE",
        "STORAGE-WORLD-READABLE",
        "STORAGE-WORLD-WRITABLE",
    }


def test_static_behavior_does_not_emit_loading_or_deserialization_for_uninvoked_refs() -> None:
    methods = (
        ("Lfixture/ReferenceOnly;", "run", (), "V"),
        (
            "Ldalvik/system/DexFile;",
            "loadDex",
            ("Ljava/lang/String;", "Ljava/lang/String;", "I"),
            "Ldalvik/system/DexFile;",
        ),
        (
            "Ljava/io/ObjectInputStream;",
            "readObject",
            (),
            "Ljava/lang/Object;",
        ),
    )
    inventory = parse_dex_inventory(
        build_dex(methods=methods, method_bodies=((0, 1, (0x0E,)),))
    )

    emitted = {item.rule_id for item in inventory.behavior_signals}
    assert "ASL-STATIC-DYNAMIC-CODE" not in emitted
    assert "ASL-STATIC-DESERIALIZATION" not in emitted


def test_static_behavior_is_bounded_and_rejects_malformed_code(tmp_path: Path) -> None:
    methods = (
        ("Lfixture/BoundedFlow;", "run", (), "V"),
        (
            "Ljavax/crypto/Cipher;",
            "getInstance",
            ("Ljava/lang/String;",),
            "Ljavax/crypto/Cipher;",
        ),
    )
    insns = (*_const_string(0, 0), *_invoke(1, (0,), static=True), 0x0E)
    dex = build_dex(
        extra_strings=("DES/ECB/PKCS5Padding",),
        methods=methods,
        method_bodies=((0, 1, insns),),
    )
    apk = tmp_path / "bounded-behavior.apk"
    write_apk(apk, dex)

    bounded = analyze_apks(
        (StaticApkInput(apk, "apk/bounded-behavior"),),
        policy=replace(StaticApkPolicy(), max_dex_code_units=1),
    )

    assert bounded.static_behavior_candidates == ()
    assert "limit:dex_code_units" in bounded.limitations
    assert bounded.metrics["dex_behavior_methods_scanned"] == 0

    candidate_bounded = analyze_apks(
        (StaticApkInput(apk, "apk/candidate-bounded"),),
        policy=replace(StaticApkPolicy(), max_static_behavior_candidates=1),
    )

    assert len(candidate_bounded.static_behavior_candidates) == 1
    assert "limit:static_behavior_candidates" in candidate_bounded.limitations

    malformed = bytearray(dex)
    code_offset = _first_code_offset(malformed)
    struct.pack_into("<I", malformed, code_offset + 12, len(malformed))
    with pytest.raises(DexFormatError, match="instructions are truncated"):
        parse_dex_inventory(bytes(malformed))

    bad_string_reference = bytearray(dex)
    code_offset = _first_code_offset(bad_string_reference)
    struct.pack_into("<H", bad_string_reference, code_offset + 18, 0xFFFF)
    with pytest.raises(DexFormatError, match="const-string references"):
        parse_dex_inventory(bytes(bad_string_reference))


def test_deprecated_webview_plugin_state_policy_requires_exact_prototype(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "plugin-state.apk"
    write_apk(
        apk,
        build_dex(
            methods=(
                (
                    "Landroid/webkit/WebSettings;",
                    "setPluginState",
                    ("Landroid/webkit/WebSettings$PluginState;",),
                    "V",
                ),
                (
                    "Landroid/webkit/WebSettings;",
                    "setPluginState",
                    ("I",),
                    "V",
                ),
            )
        ),
    )

    result = analyze_apks((StaticApkInput(apk, "apk/plugin-state"),))

    assert [item.policy_id for item in result.api_policy_matches] == [
        "ANDROID-WEBSETTINGS-PLUGIN-STATE"
    ]


@pytest.mark.parametrize(
    ("inventory_id", "category", "class_descriptor", "method_name", "prototype"),
    tuple(
        (
            inventory_id,
            category,
            class_descriptor,
            method_name,
            prototype,
        )
        for (
            inventory_id,
            category,
            class_descriptor,
            method_name,
            prototypes,
        ) in static_analysis._SECURITY_API_PATTERNS
        for prototype in sorted(prototypes)
    ),
)
def test_every_security_api_pattern_requires_an_exact_prototype(
    inventory_id: str,
    category: str,
    class_descriptor: str,
    method_name: str,
    prototype: str,
) -> None:
    collector = static_analysis._Collector(StaticApkPolicy(), ())
    static_analysis._record_method_reference(
        collector,
        source_id="fixture/source",
        dex_entry="classes.dex",
        reference=static_analysis.DexMethodReference(
            class_descriptor=class_descriptor,
            method_name=method_name,
            prototype=prototype,
        ),
    )
    rejected = static_analysis._Collector(StaticApkPolicy(), ())
    static_analysis._record_method_reference(
        rejected,
        source_id="fixture/source",
        dex_entry="classes.dex",
        reference=static_analysis.DexMethodReference(
            class_descriptor=class_descriptor,
            method_name=method_name,
            prototype=prototype + "invalid",
        ),
    )

    assert [(item.inventory_id, item.category) for item in collector.security] == [
        (inventory_id, category)
    ]
    assert rejected.security == []


def test_behavior_limits_are_appended_for_positional_policy_compatibility() -> None:
    names = [item.name for item in fields(StaticApkPolicy)]

    assert names.index("max_security_api_matches") < names.index("max_dex_class_defs")
    assert names[-1] == "max_static_behavior_candidates"


def test_security_api_inventory_is_deduplicated_ordered_and_bounded(
    tmp_path: Path,
) -> None:
    duplicate = (
        "Landroid/webkit/WebView;",
        "loadUrl",
        ("Ljava/lang/String;",),
        "V",
    )
    first = tmp_path / "first.apk"
    second = tmp_path / "second.apk"
    write_apk(first, build_dex(methods=(duplicate, duplicate)))
    write_apk(
        second,
        build_dex(
            methods=(
                (
                    "Ljavax/net/ssl/HostnameVerifier;",
                    "verify",
                    ("Ljava/lang/String;", "Ljavax/net/ssl/SSLSession;"),
                    "Z",
                ),
            ),
        ),
    )
    inputs = (
        StaticApkInput(second, "z/source"),
        StaticApkInput(first, "a/source"),
    )

    complete = analyze_apks(inputs)
    bounded = analyze_apks(
        inputs,
        policy=replace(StaticApkPolicy(), max_security_api_matches=1),
    )

    assert [
        (item.source_id, item.inventory_id)
        for item in complete.security_api_candidates
    ] == [
        ("a/source", "WEBVIEW_LOAD_URL"),
        ("z/source", "TLS_HOSTNAME_VERIFY"),
    ]
    assert len(bounded.security_api_candidates) == 1
    assert bounded.status == "partial"
    assert "limit:security_api_matches" in bounded.limitations


def test_placeholder_values_do_not_become_secret_candidates(tmp_path: Path) -> None:
    dex = build_dex(
        extra_strings=(
            "api_key=example-key",
            "client_secret=CHANGE_ME",
            "password=password",
            "access_token=THESIS_CANARY_123",
        )
    )
    apk = tmp_path / "placeholder.apk"
    write_apk(apk, dex)

    result = analyze_apks((StaticApkInput(apk, "apk/placeholder"),))

    assert result.secret_candidates == ()


def test_private_key_header_is_high_confidence_without_storing_key_material(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "private-key.apk"
    write_apk(
        apk,
        build_dex(),
        entries={
            "assets/signing.pem": (
                b"-----BEGIN PRIVATE KEY-----\n"
                b"opaque-private-key-material-must-not-be-serialized\n"
                b"-----END PRIVATE KEY-----\n"
            ),
        },
    )

    result = analyze_apks((StaticApkInput(apk, "apk/private-key"),))
    payload = json.dumps(result.to_dict())

    assert [(item.kind, item.confidence) for item in result.secret_candidates] == [
        ("private_key_pem", "high")
    ]
    assert "BEGIN PRIVATE KEY" not in payload
    assert "opaque-private-key-material" not in payload


def test_secret_assignment_matching_uses_identifier_boundaries(tmp_path: Path) -> None:
    apk = tmp_path / "assignment-boundaries.apk"
    write_apk(
        apk,
        build_dex(
            extra_strings=(
                "monkey=bananas-12345",
                "keyboard_layout=qwerty-layout-987",
                "hockey_score=visitors-12345",
                "turnkey_mode=enabled-value-42",
                "apiKey=production-value-98765",
            )
        ),
    )

    result = analyze_apks((StaticApkInput(apk, "apk/assignment-boundaries"),))

    assert len(result.secret_candidates) == 1
    assert result.secret_candidates[0].key_name == "apiKey"


def test_quoted_config_keys_are_detected_without_retaining_values(
    tmp_path: Path,
) -> None:
    json_secret = "JsonDeploySecret9x8y7z6w"
    single_quoted_secret = "SingleQuotedSecret8w7v6u5t"
    apk = tmp_path / "quoted-config.apk"
    write_apk(
        apk,
        build_dex(),
        entries={
            "assets/settings.json": (
                f'{{"client_secret":"{json_secret}"}}\n'
                f"{{'api_key': '{single_quoted_secret}'}}\n"
                '{"monkey":"bananas-12345"}\n'
                '{"client_secret":"CHANGE_ME"}\n'
            ).encode(),
        },
    )

    result = analyze_apks((StaticApkInput(apk, "apk/quoted-config"),))
    payload = json.dumps(result.to_dict())

    assert {
        (item.key_name, item.confidence, item.value_length)
        for item in result.secret_candidates
    } == {
        ("client_secret", "medium", len(json_secret)),
        ("api_key", "medium", len(single_quoted_secret)),
    }
    assert json_secret not in payload
    assert single_quoted_secret not in payload
    assert "bananas-12345" not in payload
    assert "CHANGE_ME" not in payload


def test_resource_strings_share_bounded_redacted_scanning(tmp_path: Path) -> None:
    apk = tmp_path / "resources.apk"
    write_apk(apk, build_dex())
    raw_secret = "resource-value-8z7y6x5w4v3u"

    result = analyze_apks(
        (
            StaticApkInput(
                apk,
                "apk/resources",
                resource_strings=(
                    f"client_secret={raw_secret}",
                    "https://resource.example.test/config?api_key=hidden-resource-value",
                ),
            ),
        )
    )

    payload = json.dumps(result.to_dict())
    assert result.metrics["resource_strings_scanned"] == 2
    assert result.secret_candidates[0].location == "resource_string:0"
    assert raw_secret not in payload
    assert "hidden-resource-value" not in payload


def test_nested_archives_are_inventory_only_and_entries_are_never_extracted(
    tmp_path: Path,
) -> None:
    nested = io.BytesIO()
    nested_secret = "NESTED_SECRET_MUST_NOT_BE_SCANNED"
    with ZipFile(nested, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("assets/config.txt", f"api_key={nested_secret}")
    apk = tmp_path / "nested.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", build_dex())
        archive.writestr("assets/plugin.jar", nested.getvalue())
        archive.writestr("../outside.txt", "api_key=path-traversal-secret")

    result = analyze_apks((StaticApkInput(apk, "apk/nested"),))

    assert result.secret_candidates == ()
    assert [item.archive_entry for item in result.embedded_code] == [
        "assets/plugin.jar"
    ]
    assert not (tmp_path.parent / "outside.txt").exists()
    assert nested_secret not in json.dumps(result.to_dict())


def test_crc_corrupt_scannable_text_entry_degrades_to_partial(tmp_path: Path) -> None:
    apk = tmp_path / "crc-corrupt.apk"
    write_apk(
        apk,
        build_dex(),
        entries={"assets/config.txt": b"ordinary configuration"},
    )
    mutate_zip_entry(apk, "assets/config.txt", corrupt_data=True)

    result = analyze_apks((StaticApkInput(apk, "apk/crc-corrupt"),))

    assert result.status == "partial"
    assert result.limitations == ("apk/crc-corrupt:text_entry_read_failed",)
    assert result.metrics["text_entries_scanned"] == 0


def test_encrypted_scannable_text_entry_degrades_to_partial(tmp_path: Path) -> None:
    apk = tmp_path / "encrypted-entry.apk"
    write_apk(
        apk,
        build_dex(),
        entries={"res/raw/protected.txt": b"ordinary configuration"},
    )
    mutate_zip_entry(apk, "res/raw/protected.txt", set_flags=0x1)

    result = analyze_apks((StaticApkInput(apk, "apk/encrypted-entry"),))

    assert result.status == "partial"
    assert result.limitations == ("apk/encrypted-entry:text_entry_encrypted",)
    assert result.metrics["text_entries_scanned"] == 0


def test_encrypted_root_dex_cannot_produce_a_completed_inventory(tmp_path: Path) -> None:
    apk = tmp_path / "encrypted-dex.apk"
    write_apk(apk, build_dex(extra_strings=("api_key=real-secret-value",)))
    mutate_zip_entry(apk, "classes.dex", set_flags=0x1)

    result = analyze_apks((StaticApkInput(apk, "apk/encrypted-dex"),))

    assert result.status == "partial"
    assert result.limitations == ("apk/encrypted-dex:dex_entry_encrypted",)
    assert result.metrics["dex_files_scanned"] == 0
    assert result.secret_candidates == ()


@pytest.mark.parametrize(
    ("entry_name", "content", "expected_problem"),
    [
        ("assets/../unsafe.txt", b"ordinary configuration", "text_entry_unsafe_name"),
        ("assets/binary.txt", b"\x00" * 20, "text_entry_binary_content"),
        ("res/raw/invalid.txt", b"invalid-utf8-\xff", "text_entry_decode_replacement"),
    ],
)
def test_unscannable_planned_text_entries_record_structured_limitations(
    tmp_path: Path,
    entry_name: str,
    content: bytes,
    expected_problem: str,
) -> None:
    apk = tmp_path / f"{expected_problem}.apk"
    write_apk(apk, build_dex(), entries={entry_name: content})

    result = analyze_apks((StaticApkInput(apk, "apk/unscannable"),))

    assert result.status == "partial"
    assert result.limitations == (f"apk/unscannable:{expected_problem}",)


def test_compression_and_total_byte_limits_are_structured(tmp_path: Path) -> None:
    apk = tmp_path / "bounded.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", build_dex(), compress_type=ZIP_STORED)
        archive.writestr(
            "assets/repeated.txt",
            b"A" * 50_000,
            compress_type=ZIP_DEFLATED,
        )
    policy = replace(StaticApkPolicy(), max_compression_ratio=2)

    result = analyze_apks((StaticApkInput(apk, "apk/bounded"),), policy=policy)

    assert result.status == "partial"
    assert "limit:compression_ratio" in result.limitations
    assert result.metrics["text_entries_scanned"] == 0


def test_archive_entry_limit_is_enforced_before_zipfile_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = tmp_path / "too-many-entries.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", build_dex())
        archive.writestr("assets/one.txt", "one")
        archive.writestr("assets/two.txt", "two")

    def fail_zipfile(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("ZipFile must not parse an archive over the entry bound")

    monkeypatch.setattr(static_analysis, "ZipFile", fail_zipfile)
    result = analyze_apks(
        (StaticApkInput(apk, "apk/entry-limit"),),
        policy=replace(StaticApkPolicy(), max_archive_entries=2),
    )

    assert result.status == "partial"
    assert result.metrics["archive_entries_seen"] == 3
    assert result.metrics["apks_scanned"] == 0
    assert result.limitations == ("limit:archive_entries",)


def test_spoofed_eocd_count_cannot_bypass_central_directory_entry_limit(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "spoofed-count.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", build_dex())
        archive.writestr("assets/one.txt", "one")
        archive.writestr("assets/two.txt", "two")
    value = bytearray(apk.read_bytes())
    eocd = value.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", value, eocd + 8, 1, 1)
    apk.write_bytes(value)

    result = analyze_apks(
        (StaticApkInput(apk, "apk/spoofed-count"),),
        policy=replace(StaticApkPolicy(), max_archive_entries=2),
    )

    assert result.status == "partial"
    assert result.limitations == ("limit:archive_entries",)
    assert result.metrics["apks_scanned"] == 0


def test_zip64_and_oversized_central_directories_are_rejected_preflight(
    tmp_path: Path,
) -> None:
    zip64 = tmp_path / "zip64-marker.apk"
    write_apk(zip64, build_dex())
    value = bytearray(zip64.read_bytes())
    eocd = value.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", value, eocd + 8, 0xFFFF, 0xFFFF)
    zip64.write_bytes(value)

    zip64_result = analyze_apks((StaticApkInput(zip64, "apk/zip64"),))

    assert zip64_result.status == "partial"
    assert zip64_result.limitations == ("apk/zip64:zip64_unsupported",)
    assert zip64_result.metrics["apks_scanned"] == 0

    oversized = tmp_path / "central-limit.apk"
    write_apk(oversized, build_dex())
    central_result = analyze_apks(
        (StaticApkInput(oversized, "apk/central-limit"),),
        policy=replace(StaticApkPolicy(), max_central_directory_bytes=1),
    )

    assert central_result.status == "partial"
    assert central_result.limitations == ("limit:central_directory_bytes",)
    assert central_result.metrics["apks_scanned"] == 0


def test_total_decompression_budget_stops_later_entries(tmp_path: Path) -> None:
    apk = tmp_path / "total-budget.apk"
    with ZipFile(apk, "w", compression=ZIP_STORED) as archive:
        archive.writestr("classes.dex", build_dex())
        archive.writestr("assets/config.txt", b"B" * 1024)
    policy = replace(
        StaticApkPolicy(),
        max_dex_bytes=1024,
        max_total_uncompressed_bytes=1024,
    )

    result = analyze_apks((StaticApkInput(apk, "apk/total-budget"),), policy=policy)

    assert "limit:total_uncompressed_bytes" in result.limitations
    assert result.metrics["dex_files_scanned"] == 1
    assert result.metrics["text_entries_scanned"] == 0


def test_apk_file_size_is_checked_before_zip_parsing(tmp_path: Path) -> None:
    apk = tmp_path / "oversized.apk"
    write_apk(apk, build_dex())
    policy = replace(StaticApkPolicy(), max_apk_file_bytes=32)

    result = analyze_apks((StaticApkInput(apk, "apk/oversized"),), policy=policy)

    assert result.metrics["archive_entries_seen"] == 0
    assert result.limitations == ("limit:apk_file_bytes",)


def test_malformed_dex_degrades_to_partial_without_scanning_strings(tmp_path: Path) -> None:
    apk = tmp_path / "malformed.apk"
    write_apk(apk, b"dex\n035\x00" + b"\x00" * 16)

    result = analyze_apks((StaticApkInput(apk, "apk/malformed"),))

    assert result.status == "partial"
    assert result.secret_candidates == ()
    assert result.dynamic_loading_apis == ()
    assert result.limitations == ("apk/malformed:malformed_dex",)


def test_dex_duplicate_string_offsets_are_decoded_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = bytearray(build_dex(extra_strings=("alpha-value", "bravo-value")))
    string_ids_offset = struct.unpack_from("<I", value, 0x3C)[0]
    first_offset = struct.unpack_from("<I", value, string_ids_offset)[0]
    struct.pack_into("<I", value, string_ids_offset + 4, first_offset)
    calls = 0
    original = static_analysis._read_dex_string

    def count_decode(*args: object, **kwargs: object) -> tuple[str | None, bool, int]:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(static_analysis, "_read_dex_string", count_decode)

    inventory = parse_dex_inventory(bytes(value))

    assert calls == 1
    assert inventory.strings == ("alpha-value", "alpha-value")


def test_shared_dex_parameter_lists_count_once_against_work_budget() -> None:
    dex = build_dex(
        methods=(
            ("Lcom/example/One;", "first", ("I",), "V"),
            ("Lcom/example/Two;", "second", ("I",), "I"),
        )
    )
    policy = replace(StaticApkPolicy(), max_dex_parameter_references=1)

    inventory = parse_dex_inventory(dex, policy=policy)

    assert {item.prototype for item in inventory.method_references} == {"(I)V", "(I)I"}


@pytest.mark.parametrize(
    ("policy", "match"),
    [
        (replace(StaticApkPolicy(), max_dex_string_work_bytes=1), "string decode work"),
        (
            replace(StaticApkPolicy(), max_dex_parameter_references=1),
            "parameter decode work",
        ),
        (replace(StaticApkPolicy(), max_dex_prototype_bytes=1), "prototype decode work"),
    ],
)
def test_dex_aggregate_decode_work_is_bounded(
    policy: StaticApkPolicy,
    match: str,
) -> None:
    dex = build_dex(
        extra_strings=("bounded-string",),
        methods=(("Lcom/example/Work;", "work", ("I", "I"), "V"),),
    )

    with pytest.raises(DexFormatError, match=match):
        parse_dex_inventory(dex, policy=policy)


def test_api_policy_is_exact_and_caller_driven(tmp_path: Path) -> None:
    apk = tmp_path / "policy.apk"
    write_apk(
        apk,
        build_dex(
            methods=(("Lcom/example/Legacy;", "open", ("I",), "V"),),
        ),
    )
    policy = (
        ApiPolicyEntry(
            "LAB-WRONG-PROTO",
            "Lcom/example/Legacy;",
            "open",
            "deprecated",
            "Fixture policy with a nonmatching prototype.",
            prototype="()V",
        ),
        ApiPolicyEntry(
            "LAB-EXACT-PROTO",
            "Lcom/example/Legacy;",
            "open",
            "banned",
            "Fixture policy with an exact prototype.",
            prototype="(I)V",
        ),
    )

    result = analyze_apks(
        (StaticApkInput(apk, "apk/policy"),),
        api_policy=policy,
    )

    assert [item.policy_id for item in result.api_policy_matches] == [
        "LAB-EXACT-PROTO"
    ]
    assert result.api_policy_matches[0].disposition == "banned"


def test_limits_and_order_are_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first.apk"
    second = tmp_path / "second.apk"
    write_apk(first, build_dex(extra_strings=("https://one.example.test/",)))
    write_apk(second, build_dex(extra_strings=("https://two.example.test/",)))
    policy = replace(StaticApkPolicy(), max_apks=1, max_endpoints=1)
    inputs = (
        StaticApkInput(second, "z/source"),
        StaticApkInput(first, "a/source"),
    )

    first_run = analyze_apks(inputs, policy=policy).to_dict()
    second_run = analyze_apks(inputs, policy=policy).to_dict()

    assert first_run == second_run
    assert first_run["sources"] == ["a/source"]
    assert first_run["endpoints"][0]["host"] == "one.example.test"
    assert "limit:apks" in first_run["limitations"]


def test_endpoint_metadata_never_retains_raw_path_query_or_known_secret(
    tmp_path: Path,
) -> None:
    aws_key = "AKIA1234567890ABCDEF"
    google_key = "AIza12345678901234567890123456789012345"
    endpoint = (
        f"https://api.example.test/private/{aws_key}"
        f"?opaque={google_key}&ordinary=visible-value"
    )
    apk = tmp_path / "endpoint-redaction.apk"
    write_apk(apk, build_dex(extra_strings=(endpoint,)))

    result = analyze_apks((StaticApkInput(apk, "apk/endpoint-redaction"),))
    payload = json.dumps(result.to_dict())

    assert aws_key not in payload
    assert google_key not in payload
    assert "private" not in result.endpoints[0].redacted_url
    assert "opaque" not in result.endpoints[0].redacted_url
    assert "ordinary" not in result.endpoints[0].redacted_url
    assert "visible-value" not in result.endpoints[0].redacted_url
    assert result.endpoints[0].redacted_url == (
        "https://api.example.test/<redacted>/<redacted>"
        "?parameter_1=%3Credacted%3E&parameter_2=%3Credacted%3E"
    )


def test_hostile_source_and_archive_names_cannot_leak_known_secrets(
    tmp_path: Path,
) -> None:
    aws_key = "AKIA1234567890ABCDEF"
    apk = tmp_path / "hostile-metadata.apk"
    write_apk(
        apk,
        build_dex(),
        entries={
            f"assets/{aws_key}.txt": b"https://metadata.example.test/value",
            f"assets/{aws_key}.jar": b"inventory only",
        },
    )

    result = analyze_apks(
        (StaticApkInput(apk, f"apk/{aws_key}"),)
    )
    payload = json.dumps(result.to_dict())

    assert aws_key not in payload
    assert result.sources[0].startswith("<redacted>:")
    assert result.endpoints[0].location == "assets/<redacted>.txt:line:1"
    assert result.embedded_code[0].archive_entry == "assets/<redacted>.jar"


def test_detected_arbitrary_secret_is_removed_from_all_candidate_metadata(
    tmp_path: Path,
) -> None:
    secret = "OpaqueDeploySecret9x8y7z6w"
    apk = tmp_path / "arbitrary-secret-location.apk"
    write_apk(
        apk,
        build_dex(),
        entries={f"assets/{secret}.txt": f"client_secret={secret}".encode()},
    )

    result = analyze_apks((StaticApkInput(apk, f"apk/{secret}"),))
    payload = json.dumps(result.to_dict())

    assert result.secret_candidates
    assert secret not in payload
    assert result.secret_candidates[0].source_id.startswith("<redacted>:")
    assert result.secret_candidates[0].location == "assets/<redacted>.txt:line:1"


def test_detected_secret_is_redacted_across_all_static_inventory_categories(
    tmp_path: Path,
) -> None:
    secret = "CrossCategorySecret9x8y7z6w"
    apk = tmp_path / "cross-category-secret.apk"
    write_apk(
        apk,
        build_dex(
            extra_strings=(f"client_secret={secret}",),
            methods=(
                (
                    "Ldalvik/system/DexClassLoader;",
                    "loadClass",
                    ("Ljava/lang/String;",),
                    "Ljava/lang/Class;",
                ),
                ("Landroid/webkit/WebSettings;", "setSavePassword", ("Z",), "V"),
                (
                    "Landroid/webkit/WebView;",
                    "loadUrl",
                    ("Ljava/lang/String;",),
                    "V",
                ),
            ),
        ),
        entries={
            f"assets/{secret}.txt": b"https://metadata.example.test/value",
            f"assets/{secret}.jar": b"inventory only",
        },
    )

    result = analyze_apks((StaticApkInput(apk, f"apk/{secret}"),))
    payload = json.dumps(result.to_dict())

    assert result.secret_candidates
    assert result.endpoints
    assert result.dynamic_loading_apis
    assert result.security_api_candidates
    assert result.api_policy_matches
    assert result.embedded_code
    assert secret not in payload
    assert result.sources[0].startswith("<redacted>:")
    assert result.endpoints[0].source_id.startswith("<redacted>:")
    assert result.endpoints[0].location == "assets/<redacted>.txt:line:1"
    assert result.dynamic_loading_apis[0].source_id.startswith("<redacted>:")
    assert result.security_api_candidates[0].source_id.startswith("<redacted>:")
    assert result.api_policy_matches[0].source_id.startswith("<redacted>:")
    assert result.embedded_code[0].source_id.startswith("<redacted>:")
    assert result.embedded_code[0].archive_entry == "assets/<redacted>.jar"


def test_public_google_identifier_requires_sensitive_context_for_finding_candidate(
    tmp_path: Path,
) -> None:
    identifier = "AIza12345678901234567890123456789012345"
    public_apk = tmp_path / "public-google-config.apk"
    contextual_apk = tmp_path / "contextual-google-config.apk"
    write_apk(public_apk, build_dex(extra_strings=(identifier,)))
    write_apk(
        contextual_apk,
        build_dex(extra_strings=(f"client_secret={identifier}",)),
    )

    public = analyze_apks((StaticApkInput(public_apk, "apk/public"),))
    contextual = analyze_apks((StaticApkInput(contextual_apk, "apk/contextual"),))

    assert [(item.kind, item.confidence) for item in public.secret_candidates] == [
        ("google_api_key", "low")
    ]
    assert any(
        item.kind == "named_assignment" and item.confidence == "medium"
        for item in contextual.secret_candidates
    )


def test_overlong_text_and_resource_strings_create_structured_limitation(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "truncated-input.apk"
    write_apk(
        apk,
        build_dex(),
        entries={"assets/minified.js": b"A" * 256},
    )
    policy = replace(StaticApkPolicy(), max_string_bytes=32)

    result = analyze_apks(
        (
            StaticApkInput(
                apk,
                "apk/truncated-input",
                resource_strings=("B" * 256,),
            ),
        ),
        policy=policy,
    )

    assert result.status == "completed"
    assert "limit:string_scan_bytes" not in result.limitations


def _large_region_policy(**overrides: int) -> StaticApkPolicy:
    values = {
        "max_string_bytes": 128,
        "max_string_scan_chunk_bytes": 256,
        "max_string_scan_file_bytes": 100_000,
        "max_string_scan_apk_bytes": 100_000,
        "max_string_scan_milliseconds": 5_000,
    }
    values.update(overrides)
    return replace(StaticApkPolicy(), **values)


@pytest.mark.parametrize("position", ("start", "middle", "boundary", "end"))
def test_oversized_dex_regions_are_scanned_in_overlapping_windows(
    tmp_path: Path,
    position: str,
) -> None:
    candidate = ";client_secret=REALPRODKEY_9x8y7z6w5v4u;"
    step = 256 - 128
    if position == "start":
        value = candidate + ("A" * 8_000)
    elif position == "middle":
        value = ("A" * 4_000) + candidate + ("B" * 4_000)
    elif position == "boundary":
        value = ("A" * (step - 5)) + candidate + ("B" * 4_000)
    else:
        value = ("A" * 8_000) + candidate
    apk = tmp_path / f"oversized-{position}.apk"
    write_apk(apk, build_dex(extra_strings=(value,)))

    result = analyze_apks(
        (StaticApkInput(apk, f"apk/oversized-{position}"),),
        policy=_large_region_policy(),
    )

    assert len(result.secret_candidates) == 1
    assert result.secret_candidates[0].kind == "named_assignment"
    assert "oversized_dex_strings_skipped" not in result.limitations
    assert result.metrics["oversized_dex_strings_scanned"] == 1


def test_large_resource_string_is_scanned_after_aapt_handoff(
    tmp_path: Path,
) -> None:
    candidate = ";client_secret=RESOURCESECRET_9x8y7w6v5u4t;"
    value = ("A" * 5_000) + candidate + ("B" * 5_000)
    parsed = parse_aapt_strings(f"String #0 : {value}\n")
    assert len(parsed[0]) == len(value)
    apk = tmp_path / "large-resource.apk"
    write_apk(apk, build_dex())

    result = analyze_apks(
        (StaticApkInput(apk, "apk/large-resource", resource_strings=parsed),),
        policy=_large_region_policy(),
    )

    assert len(result.secret_candidates) == 1
    assert result.secret_candidates[0].location.startswith(
        "resource_string:0:offset:"
    )


def test_large_text_region_endpoint_and_secret_are_redacted_and_deduplicated(
    tmp_path: Path,
) -> None:
    secret = "TEXTSECRET_9x8y7w6v5u4t"
    endpoint = "https://api.example.test/v1/items?access_token=token-9x8y7w6"
    value = ("A" * 5_000) + f';client_secret={secret};"{endpoint}"' + ("B" * 5_000)
    apk = tmp_path / "large-text.apk"
    write_apk(apk, build_dex(), entries={"assets/config.txt": value.encode()})

    result = analyze_apks(
        (StaticApkInput(apk, "apk/large-text"),),
        policy=_large_region_policy(),
    )
    serialized = json.dumps(result.to_dict())

    assert len(result.secret_candidates) == 2
    assert len(result.endpoints) == 1
    assert secret not in serialized
    assert endpoint not in serialized
    assert result.metrics["string_scan_chunks"] > 1


def test_large_binary_noise_does_not_create_string_candidates(tmp_path: Path) -> None:
    apk = tmp_path / "large-noise.apk"
    write_apk(
        apk,
        build_dex(),
        entries={"assets/noise.txt": b"\x00\xff" * 100_000},
    )

    result = analyze_apks(
        (StaticApkInput(apk, "apk/large-noise"),),
        policy=_large_region_policy(),
    )

    assert result.secret_candidates == ()
    assert result.endpoints == ()
    assert "apk/large-noise:text_entry_binary_content" in result.limitations


def test_large_region_budget_stops_without_false_pass(tmp_path: Path) -> None:
    value = ("A" * 2_000) + ";client_secret=TOO_FAR_9x8y7w6v5u4t;"
    apk = tmp_path / "budget.apk"
    write_apk(apk, build_dex(extra_strings=(value,)))

    result = analyze_apks(
        (StaticApkInput(apk, "apk/budget"),),
        policy=_large_region_policy(
            max_string_scan_file_bytes=512,
            max_string_scan_apk_bytes=512,
        ),
    )

    assert result.secret_candidates == ()
    assert "limit:string_scan_file_bytes" in result.limitations
    assert "limit:string_scan_apk_bytes" in result.limitations


def test_large_region_overlap_is_not_charged_twice_to_budget(tmp_path: Path) -> None:
    candidate = ";client_secret=WITHIN_UNIQUE_BUDGET_9x8y7w6v5u4t;"
    value = ("A" * 600) + candidate + ("B" * 2_000)
    apk = tmp_path / "overlap-budget.apk"
    write_apk(apk, build_dex(extra_strings=(value,)))

    result = analyze_apks(
        (StaticApkInput(apk, "apk/overlap-budget"),),
        policy=_large_region_policy(
            max_string_scan_file_bytes=1_000,
            max_string_scan_apk_bytes=1_000,
        ),
    )

    assert len(result.secret_candidates) == 1
    assert result.metrics["string_scan_bytes"] == 1_000
    assert "limit:string_scan_file_bytes" in result.limitations
    assert "limit:string_scan_apk_bytes" in result.limitations


def test_binary_noise_does_not_join_secret_fragments(tmp_path: Path) -> None:
    apk = tmp_path / "binary-separator.apk"
    write_apk(
        apk,
        build_dex(),
        entries={
            "assets/config.txt": (
                b"client_sec\xffret=NOT_A_CONTIGUOUS_SECRET_9x8y7w6v5u4t"
            )
        },
    )

    result = analyze_apks(
        (StaticApkInput(apk, "apk/binary-separator"),),
        policy=_large_region_policy(),
    )

    assert result.secret_candidates == ()


def test_large_region_timeout_is_structured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = ("A" * 8_000) + ";client_secret=AFTER_TIMEOUT_9x8y7w6v5u4t;"
    apk = tmp_path / "timeout.apk"
    write_apk(apk, build_dex(extra_strings=(value,)))
    clock = iter((0.0, 0.0, 10.0))
    monkeypatch.setattr(static_analysis.time, "monotonic", lambda: next(clock))

    result = analyze_apks(
        (StaticApkInput(apk, "apk/timeout"),),
        policy=_large_region_policy(max_string_scan_milliseconds=1),
    )

    assert result.secret_candidates == ()
    assert "limit:string_scan_timeout" in result.limitations
    assert result.metrics["string_scan_timeouts"] == 1


def test_oversized_string_does_not_hide_method_inventory(tmp_path: Path) -> None:
    value = ("A" * 8_000) + ";https://api.example.test/late;"
    apk = tmp_path / "large-methods.apk"
    write_apk(
        apk,
        build_dex(
            extra_strings=(value,),
            methods=(
                (
                    "Ldalvik/system/DexClassLoader;",
                    "loadClass",
                    ("Ljava/lang/String;",),
                    "Ljava/lang/Class;",
                ),
                ("Landroid/webkit/WebSettings;", "setSavePassword", ("Z",), "V"),
            ),
        ),
    )

    result = analyze_apks(
        (StaticApkInput(apk, "apk/large-methods"),),
        policy=_large_region_policy(),
    )

    assert {item.inventory_id for item in result.dynamic_loading_apis} == {
        "DEX_CLASS_LOADER"
    }
    assert {item.policy_id for item in result.api_policy_matches} == {
        "ANDROID-WEBSETTINGS-SAVE-PASSWORD"
    }


def test_resource_string_limit_never_false_passes_secret_after_sentinel(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "resource-limit.apk"
    write_apk(apk, build_dex())
    policy = replace(StaticApkPolicy(), max_resource_strings=2)

    result = analyze_apks(
        (
            StaticApkInput(
                apk,
                "apk/resource-limit",
                resource_strings=(
                    "first-benign-value",
                    "second-benign-value",
                    "client_secret=secret-after-analysis-bound",
                ),
            ),
        ),
        policy=policy,
    )

    assert result.status == "partial"
    assert result.secret_candidates == ()
    assert "limit:resource_strings" in result.limitations


def test_duplicate_policy_identifiers_are_rejected(tmp_path: Path) -> None:
    apk = tmp_path / "duplicate-policy.apk"
    write_apk(apk, build_dex())
    entry = ApiPolicyEntry(
        "LAB-DUPLICATE",
        "Lcom/example/Legacy;",
        "open",
        "banned",
        "Fixture duplicate policy.",
    )

    with pytest.raises(ValueError, match="unique"):
        analyze_apks(
            (StaticApkInput(apk, "apk/policy"),),
            api_policy=(entry, entry),
        )


def test_policy_bounds_validate_consistently() -> None:
    with pytest.raises(ValueError, match="positive"):
        StaticApkPolicy(max_apks=0)
    with pytest.raises(ValueError, match="text-entry"):
        StaticApkPolicy(max_text_entry_bytes=64, max_string_bytes=128)
