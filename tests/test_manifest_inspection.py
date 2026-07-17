# ruff: noqa: E501
from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor import manifest as manifest_module
from android_assessor.errors import ApkInspectionError
from android_assessor.manifest import (
    Aapt2Inspector,
    inspect_manifest_tree,
    parse_aapt_xmltree,
)
from android_assessor.subprocess_utils import CommandResult

XMLTREE = """N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=2)
    A: package="com.example.lab" (Raw: "com.example.lab")
    E: uses-permission (line=3)
      A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.INTERNET" (Raw: "android.permission.INTERNET")
    E: permission (line=4)
      A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.lab.INTERNAL" (Raw: "com.example.lab.INTERNAL")
      A: http://schemas.android.com/apk/res/android:protectionLevel(0x01010009)=(type 0x10)0x2
    E: application (line=5)
      A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=(type 0x12)0xffffffff
      A: http://schemas.android.com/apk/res/android:testOnly(0x01010272)=(type 0x12)0x0
      A: http://schemas.android.com/apk/res/android:usesCleartextTraffic(0x010104ec)=(type 0x12)0xffffffff
      A: http://schemas.android.com/apk/res/android:networkSecurityConfig(0x01010527)=@0x7f130001
      A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=(type 0x12)0x0
      E: activity (line=10)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)=".DeepLinkActivity" (Raw: ".DeepLinkActivity")
        A: http://schemas.android.com/apk/res/android:exported(0x01010010)=(type 0x12)0xffffffff
        E: intent-filter (line=13)
          A: http://schemas.android.com/apk/res/android:autoVerify(0x010104ee)=(type 0x12)0xffffffff
          E: action (line=14)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.action.VIEW" (Raw: "android.intent.action.VIEW")
          E: category (line=15)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.category.BROWSABLE" (Raw: "android.intent.category.BROWSABLE")
          E: data (line=16)
            A: http://schemas.android.com/apk/res/android:scheme(0x01010027)="https" (Raw: "https")
            A: http://schemas.android.com/apk/res/android:host(0x01010028)="lab.example" (Raw: "lab.example")
            A: http://schemas.android.com/apk/res/android:pathPrefix(0x0101002b)="/open" (Raw: "/open")
      E: service (line=20)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="SyncService" (Raw: "SyncService")
        A: http://schemas.android.com/apk/res/android:permission(0x01010006)="com.example.lab.INTERNAL" (Raw: "com.example.lab.INTERNAL")
      E: provider (line=22)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.lab.DataProvider" (Raw: "com.example.lab.DataProvider")
        A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="com.example.lab.data" (Raw: "com.example.lab.data")
"""

BADGING = """package: name='com.example.lab' versionCode='42' versionName='4.2' compileSdkVersion='35'
sdkVersion:'23'
targetSdkVersion:'34'
application-label:'Lab App'
uses-permission: name='android.permission.INTERNET'
"""


def result(stdout: str) -> CommandResult:
    return CommandResult(
        arguments=(),
        exit_code=0,
        stdout=stdout,
        stderr="",
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=False,
    )


def test_manifest_parser_extracts_flags_components_permissions_and_deep_links() -> None:
    inspection = inspect_manifest_tree(parse_aapt_xmltree(XMLTREE), target_sdk=34)

    assert inspection.package == "com.example.lab"
    assert inspection.debuggable is True
    assert inspection.test_only is False
    assert inspection.uses_cleartext_traffic is True
    assert inspection.network_security_config == "@0x7f130001"
    assert inspection.allow_backup is False
    assert inspection.permissions[0].name == "android.permission.INTERNET"
    assert inspection.custom_permissions[0].name == "com.example.lab.INTERNAL"
    assert inspection.custom_permissions[0].protection_level == "2"
    assert [component.component_type for component in inspection.components] == [
        "activity",
        "service",
        "provider",
    ]
    activity = inspection.components[0]
    assert activity.name == "com.example.lab.DeepLinkActivity"
    assert activity.effective_exported is True
    assert activity.exported_source == "explicit"
    assert inspection.components[1].effective_exported is False
    assert inspection.components[1].permission == "com.example.lab.INTERNAL"
    assert inspection.components[2].authorities == "com.example.lab.data"
    assert inspection.deep_links[0].scheme == "https"
    assert inspection.deep_links[0].host == "lab.example"
    assert inspection.deep_links[0].path_prefix == "/open"
    assert inspection.deep_links[0].auto_verify is True


def test_legacy_intent_filter_export_is_labeled_as_inferred() -> None:
    without_explicit = XMLTREE.replace(
        "        A: http://schemas.android.com/apk/res/android:exported(0x01010010)=(type 0x12)0xffffffff\n",
        "",
    )

    inspection = inspect_manifest_tree(parse_aapt_xmltree(without_explicit), target_sdk=30)

    assert inspection.components[0].exported is None
    assert inspection.components[0].effective_exported is True
    assert inspection.components[0].exported_source == "legacy_intent_filter_default"


def test_manifest_parser_rejects_missing_manifest() -> None:
    with pytest.raises(ApkInspectionError, match="manifest element"):
        inspect_manifest_tree(parse_aapt_xmltree("E: resources\n"))


def test_aapt2_inspector_uses_fixed_commands_and_writes_raw_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "Lab With Spaces"
    executable = root / "tools" / "aapt2.exe"
    apk = root / "results" / "session" / "apk" / "000-base.apk"
    output_dir = apk.parent
    executable.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    executable.touch()
    apk.write_bytes(b"APK")
    calls: list[list[str]] = []

    def fake_run(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        calls.append([str(item) for item in arguments])
        return result(BADGING if "badging" in calls[-1] else XMLTREE)

    monkeypatch.setattr(manifest_module, "run_command", fake_run)

    inspection = Aapt2Inspector(executable).inspect(
        apk,
        output_dir=output_dir,
        project_root=root,
        target_sdk=34,
    )

    assert calls[0][1:3] == ["dump", "badging"]
    assert calls[1][1:5] == ["dump", "xmltree", "--file", "AndroidManifest.xml"]
    assert inspection.badging.label == "Lab App"
    assert inspection.badging_path.read_text(encoding="utf-8") == BADGING
    assert inspection.xmltree_path.read_text(encoding="utf-8") == XMLTREE
