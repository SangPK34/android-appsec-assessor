from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor.errors import SessionError
from android_assessor.storage import read_json_object, write_json_atomic
from android_assessor.validation import (
    generate_session_canary,
    validate_android_apk_path,
    validate_managed_remote_path,
    validate_package_name,
    validate_reverse_endpoint,
    validate_session_canary,
    validate_session_id,
)


@pytest.mark.parametrize(
    "package",
    ("com.example.app", "vn.lab_app.target2"),
)
def test_accepts_android_package_names(package: str) -> None:
    assert validate_package_name(package) == package


@pytest.mark.parametrize(
    "package",
    ("", "example", "com..app", "com.example;id", "../com.example.app"),
)
def test_rejects_unsafe_android_package_names(package: str) -> None:
    with pytest.raises(SessionError):
        validate_package_name(package)


def test_validates_session_and_reverse_identifiers() -> None:
    assert validate_session_id("20260717-120102-a8f4c2") == "20260717-120102-a8f4c2"
    assert validate_reverse_endpoint("tcp:8080") == "tcp:8080"


def test_session_canary_is_unique_and_uses_the_exact_supported_format() -> None:
    first = generate_session_canary()
    second = generate_session_canary()

    assert validate_session_canary(first) == first
    assert validate_session_canary(second) == second
    assert first != second


@pytest.mark.parametrize(
    "canary",
    (
        "THESIS_CANARY_20260718T010203Z_deadbeef",
        "prefix_THESIS_CANARY_20260718T010203Z_deadbeefcafe",
        "THESIS_CANARY_20260718T010203Z_deadbeefcafe_suffix",
        "ASL_abcdef",
    ),
)
def test_rejects_non_exact_session_canaries(canary: str) -> None:
    with pytest.raises(SessionError):
        validate_session_canary(canary)


@pytest.mark.parametrize("endpoint", ("tcp:0", "tcp:70000", "localabstract:x", "tcp:8;id"))
def test_rejects_unmanaged_reverse_endpoints(endpoint: str) -> None:
    with pytest.raises(SessionError):
        validate_reverse_endpoint(endpoint)


def test_remote_cleanup_is_limited_to_framework_directory() -> None:
    managed = "/data/local/tmp/android-security-lab/session/file.bin"

    assert validate_managed_remote_path(managed) == managed
    with pytest.raises(SessionError):
        validate_managed_remote_path("/data/local/tmp/frida-server")
    with pytest.raises(SessionError):
        validate_managed_remote_path(
            "/data/local/tmp/android-security-lab/session/../../other"
        )


def test_android_apk_path_accepts_package_manager_paths_only() -> None:
    path = "/data/app/~~abc/com.example.app-AbC==/split_config.arm64_v8a.apk"

    assert validate_android_apk_path(path) == path
    for unsafe in (
        "relative/base.apk",
        "/data/app/../secret.apk",
        "/data/app/base.apk;id",
        "/data/app/base.zip",
    ):
        with pytest.raises(SessionError):
            validate_android_apk_path(unsafe)


def test_atomic_json_supports_unicode_and_rejects_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "lab có dấu"
    target = root / "state" / "data.json"

    write_json_atomic(target, {"value": "Cục Than"}, root=root)

    assert read_json_object(target, root=root) == {"value": "Cục Than"}
    with pytest.raises(SessionError):
        write_json_atomic(tmp_path / "outside.json", {}, root=root)
