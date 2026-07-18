# ruff: noqa: E501
from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor import manifest as manifest_module
from android_assessor.errors import ApkInspectionError
from android_assessor.manifest import (
    Aapt2Inspector,
    inspect_manifest_tree,
    parse_aapt_resource_xml_paths,
    parse_aapt_strings,
    parse_aapt_xmltree,
    redact_aapt_xmltree,
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
      A: http://schemas.android.com/apk/res/android:permission(0x01010006)="com.example.lab.INTERNAL" (Raw: "com.example.lab.INTERNAL")
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
          E: category (line=15)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.category.DEFAULT" (Raw: "android.intent.category.DEFAULT")
          E: data (line=16)
            A: http://schemas.android.com/apk/res/android:scheme(0x01010027)="https" (Raw: "https")
            A: http://schemas.android.com/apk/res/android:host(0x01010028)="lab.example" (Raw: "lab.example")
            A: http://schemas.android.com/apk/res/android:pathPrefix(0x0101002b)="/open" (Raw: "/open")
      E: service (line=20)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="SyncService" (Raw: "SyncService")
        A: http://schemas.android.com/apk/res/android:permission(0x01010006)="com.example.lab.INTERNAL" (Raw: "com.example.lab.INTERNAL")
        A: http://schemas.android.com/apk/res/android:directBootAware(0x01010505)=(type 0x12)0xffffffff
        A: http://schemas.android.com/apk/res/android:foregroundServiceType(0x01010599)="dataSync" (Raw: "dataSync")
      E: provider (line=22)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.lab.DataProvider" (Raw: "com.example.lab.DataProvider")
        A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="com.example.lab.data" (Raw: "com.example.lab.data")
        A: http://schemas.android.com/apk/res/android:multiprocess(0x01010013)=(type 0x12)0xffffffff
"""

BADGING = """package: name='com.example.lab' versionCode='42' versionName='4.2' compileSdkVersion='35'
sdkVersion:'23'
targetSdkVersion:'34'
application-label:'Lab App'
uses-permission: name='android.permission.INTERNET'
"""

FILE_PROVIDER_XMLTREE = """E: manifest (line=1)
  A: package="com.example.lab" (Raw: "com.example.lab")
  E: application (line=2)
    A: http://schemas.android.com/apk/res/android:permission(0x01010006)="com.example.lab.INTERNAL" (Raw: "com.example.lab.INTERNAL")
    E: provider (line=3)
      A: http://schemas.android.com/apk/res/android:name(0x01010003)="androidx.core.content.FileProvider" (Raw: "androidx.core.content.FileProvider")
      A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="com.example.lab.files" (Raw: "com.example.lab.files")
      A: http://schemas.android.com/apk/res/android:exported(0x01010010)=(type 0x12)0x0
      A: http://schemas.android.com/apk/res/android:grantUriPermissions(0x0101001b)=(type 0x12)0xffffffff
      E: meta-data (line=8)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.support.FILE_PROVIDER_PATHS" (Raw: "android.support.FILE_PROVIDER_PATHS")
        A: http://schemas.android.com/apk/res/android:resource(0x01010025)="@xml/share_paths" (Raw: "@xml/share_paths")
      E: path-permission (line=11)
        A: http://schemas.android.com/apk/res/android:pathPrefix(0x0101002b)="/shared" (Raw: "/shared")
        A: http://schemas.android.com/apk/res/android:readPermission(0x01010007)="com.example.lab.READ" (Raw: "com.example.lab.READ")
      E: grant-uri-permission (line=14)
        A: http://schemas.android.com/apk/res/android:pathPrefix(0x0101002b)="/shared/public" (Raw: "/shared/public")
"""

NUMERIC_FILE_PROVIDER_XMLTREE = FILE_PROVIDER_XMLTREE.replace(
    '="@xml/share_paths" (Raw: "@xml/share_paths")',
    "=(type 0x01)0x7f120001",
)

PATHS_XMLTREE = """E: paths (line=1)
  E: root-path (line=2)
    A: http://schemas.android.com/apk/res/android:name(0x01010003)="root" (Raw: "root")
    A: http://schemas.android.com/apk/res/android:path(0x0101002a)="." (Raw: ".")
  E: files-path (line=5)
    A: http://schemas.android.com/apk/res/android:name(0x01010003)="images" (Raw: "images")
    A: http://schemas.android.com/apk/res/android:path(0x0101002a)="images/" (Raw: "images/")
"""

RESOURCE_TABLE = """Package name=com.example.lab id=0x7f
  resource 0x7f120001 com.example.lab:xml/share_paths
    () (file) res/xml/share_paths.xml type=XML
"""

MERGED_DEEP_LINK_XMLTREE = """E: manifest (line=1)
  A: package="com.example.links" (Raw: "com.example.links")
  E: application (line=2)
    A: http://schemas.android.com/apk/res/android:permission(0x01010006)="com.example.links.OPEN" (Raw: "com.example.links.OPEN")
    E: activity (line=3)
      A: http://schemas.android.com/apk/res/android:name(0x01010003)=".LinkActivity" (Raw: ".LinkActivity")
      A: http://schemas.android.com/apk/res/android:exported(0x01010010)=(type 0x12)0xffffffff
      E: intent-filter (line=6)
        A: http://schemas.android.com/apk/res/android:autoVerify(0x010104ee)=(type 0x12)0xffffffff
        E: action (line=7)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.action.VIEW" (Raw: "android.intent.action.VIEW")
        E: category (line=9)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.category.BROWSABLE" (Raw: "android.intent.category.BROWSABLE")
        E: category (line=10)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.category.DEFAULT" (Raw: "android.intent.category.DEFAULT")
        E: data (line=11)
          A: http://schemas.android.com/apk/res/android:scheme(0x01010027)="https" (Raw: "https")
        E: data (line=13)
          A: http://schemas.android.com/apk/res/android:host(0x01010028)="links.example" (Raw: "links.example")
          A: http://schemas.android.com/apk/res/android:port(0x01010029)="443" (Raw: "443")
        E: data (line=16)
          A: http://schemas.android.com/apk/res/android:pathSuffix(0x0101055f)=".html" (Raw: ".html")
        E: data (line=18)
          A: http://schemas.android.com/apk/res/android:pathAdvancedPattern(0x01010560)="/[a-z]+" (Raw: "/[a-z]+")
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
    assert inspection.application_permission == "com.example.lab.INTERNAL"
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
    assert inspection.components[1].direct_boot_aware is True
    assert inspection.components[1].foreground_service_type == "dataSync"
    assert inspection.components[2].authorities == "com.example.lab.data"
    assert inspection.components[2].multiprocess is True
    assert inspection.deep_links[0].scheme == "https"
    assert inspection.deep_links[0].host == "lab.example"
    assert inspection.deep_links[0].path_prefix == "/open"
    assert inspection.deep_links[0].auto_verify is True


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("true", True),
        ("false", False),
        ("0xffffffff", True),
        ("0x0", False),
        ('(Raw: "true")', True),
        ('(raw: "false")', False),
        ("(type 0x12)0xffffffff", True),
        ("(type 0x12)0x0", False),
        ("type=0x12 data=0xffffffff", True),
        ("type=0x12 data=0x0", False),
    ),
)
def test_manifest_boolean_formats_are_normalized(
    value: str,
    expected: bool,
) -> None:
    output = f'''E: manifest
  A: package="com.example.boolean" (Raw: "com.example.boolean")
  E: application
    A: android:debuggable={value}
'''

    inspection = inspect_manifest_tree(parse_aapt_xmltree(output), target_sdk=34)

    assert inspection.debuggable is expected


@pytest.mark.parametrize(
    "value",
    (
        None,
        "maybe",
        "0x2",
        "(type 0x12)0x2",
        "type=0x12 data=0x2",
        "type=0x10 data=0xffffffff",
    ),
)
def test_absent_or_malformed_manifest_boolean_is_unknown(value: str | None) -> None:
    attribute = "" if value is None else f"    A: android:debuggable={value}\n"
    output = f'''E: manifest
  A: package="com.example.boolean" (Raw: "com.example.boolean")
  E: application
{attribute}'''

    inspection = inspect_manifest_tree(parse_aapt_xmltree(output), target_sdk=34)

    assert inspection.debuggable is None


def test_all_normalized_application_and_component_boolean_fields() -> None:
    output = '''E: manifest
  A: package="com.example.boolean" (Raw: "com.example.boolean")
  E: application
    A: android:enabled=true
    A: android:debuggable=(raw: "true")
    A: android:testOnly=0x0
    A: android:allowBackup=type=0x12 data=0xffffffff
    A: android:usesCleartextTraffic=false
    E: service
      A: android:name=".Worker" (Raw: ".Worker")
      A: android:exported=true
      A: android:enabled=0xffffffff
      A: android:directBootAware=(type 0x12)0xffffffff
      A: android:stopWithTask=(raw: "false")
      A: android:isolatedProcess=type=0x12 data=0xffffffff
    E: provider
      A: android:name=".Files" (Raw: ".Files")
      A: android:authorities="com.example.boolean.files" (Raw: "com.example.boolean.files")
      A: android:exported=false
      A: android:grantUriPermissions=0xffffffff
'''

    inspection = inspect_manifest_tree(parse_aapt_xmltree(output), target_sdk=34)

    assert inspection.application_enabled is True
    assert inspection.debuggable is True
    assert inspection.test_only is False
    assert inspection.allow_backup is True
    assert inspection.uses_cleartext_traffic is False
    service, provider = inspection.components
    assert service.exported is True
    assert service.enabled is True
    assert service.direct_boot_aware is True
    assert service.stop_with_task is False
    assert service.isolated_process is True
    assert provider.exported is False
    assert provider.grant_uri_permissions is True


@pytest.mark.parametrize(
    "component_type",
    ("activity", "activity-alias", "service", "receiver", "provider"),
)
def test_explicit_true_wins_for_every_component_type(component_type: str) -> None:
    alias_target = (
        '      A: android:targetActivity=".Target" (Raw: ".Target")\n'
        if component_type == "activity-alias"
        else ""
    )
    authorities = (
        '      A: android:authorities="com.example.boolean.provider" '
        '(Raw: "com.example.boolean.provider")\n'
        if component_type == "provider"
        else ""
    )
    output = f'''E: manifest
  A: package="com.example.boolean" (Raw: "com.example.boolean")
  E: application
    E: {component_type}
      A: android:name=".Entry" (Raw: ".Entry")
{alias_target}{authorities}      A: android:exported=true
'''

    component = inspect_manifest_tree(
        parse_aapt_xmltree(output),
        target_sdk=34,
    ).components[0]

    assert component.exported is True
    assert component.effective_exported is True
    assert component.exported_source == "explicit"


@pytest.mark.parametrize(
    ("component_type", "target_sdk", "expected", "source"),
    (
        ("activity", 30, True, "legacy_intent_filter_default"),
        ("activity-alias", 31, None, "missing_explicit_exported"),
        ("service", 30, True, "legacy_intent_filter_default"),
        ("receiver", 31, None, "missing_explicit_exported"),
        ("provider", 16, True, "legacy_provider_default"),
        ("provider", 17, False, "provider_default"),
    ),
)
def test_effective_exported_defaults_by_component_and_target_sdk(
    component_type: str,
    target_sdk: int,
    expected: bool | None,
    source: str,
) -> None:
    filter_xml = "" if component_type == "provider" else '''      E: intent-filter
        E: action
          A: android:name="com.example.boolean.OPEN" (Raw: "com.example.boolean.OPEN")
'''
    output = f'''E: manifest
  A: package="com.example.boolean" (Raw: "com.example.boolean")
  E: application
    E: {component_type}
      A: android:name=".Entry" (Raw: ".Entry")
{filter_xml}'''

    component = inspect_manifest_tree(
        parse_aapt_xmltree(output),
        target_sdk=target_sdk,
    ).components[0]

    assert component.effective_exported is expected
    assert component.exported_source == source


def test_manifest_parser_extracts_provider_policy_metadata() -> None:
    inspection = inspect_manifest_tree(
        parse_aapt_xmltree(FILE_PROVIDER_XMLTREE),
        target_sdk=34,
    )

    provider = inspection.components[0]
    assert provider.grant_uri_permissions is True
    assert provider.meta_data[0].name == "android.support.FILE_PROVIDER_PATHS"
    assert provider.meta_data[0].resource == "@xml/share_paths"
    assert provider.path_permissions[0].path_prefix == "/shared"
    assert provider.path_permissions[0].read_permission == "com.example.lab.READ"
    assert provider.uri_grant_patterns[0].path_prefix == "/shared/public"
    declaration = inspection.file_provider_paths[0]
    assert declaration.provider == "androidx.core.content.FileProvider"
    assert declaration.resource_reference == "@xml/share_paths"
    assert declaration.resolution_status == "unresolved"


def test_deep_link_data_elements_are_merged_with_component_provenance() -> None:
    inspection = inspect_manifest_tree(
        parse_aapt_xmltree(MERGED_DEEP_LINK_XMLTREE),
        target_sdk=34,
    )

    assert len(inspection.deep_links) == 2
    assert {item.host for item in inspection.deep_links} == {"links.example"}
    assert {item.port for item in inspection.deep_links} == {"443"}
    assert {item.path_suffix for item in inspection.deep_links} == {None, ".html"}
    assert {item.path_advanced_pattern for item in inspection.deep_links} == {
        None,
        "/[a-z]+",
    }
    assert all(item.scheme == "https" for item in inspection.deep_links)
    assert all(item.component_effective_exported is True for item in inspection.deep_links)
    assert all(
        item.component_permission == "com.example.links.OPEN"
        for item in inspection.deep_links
    )


def test_legacy_intent_filter_export_is_labeled_as_inferred() -> None:
    without_explicit = XMLTREE.replace(
        "        A: http://schemas.android.com/apk/res/android:exported(0x01010010)=(type 0x12)0xffffffff\n",
        "",
    )

    inspection = inspect_manifest_tree(parse_aapt_xmltree(without_explicit), target_sdk=30)

    assert inspection.components[0].exported is None
    assert inspection.components[0].effective_exported is True
    assert inspection.components[0].exported_source == "legacy_intent_filter_default"


def test_provider_export_default_is_unknown_without_target_sdk() -> None:
    inspection = inspect_manifest_tree(
        parse_aapt_xmltree(
            """E: manifest
  A: package=\"com.example.lab\" (Raw: \"com.example.lab\")
  E: application
    E: provider
      A: android:name=\".DataProvider\" (Raw: \".DataProvider\")
      A: android:authorities=\"com.example.lab.data\" (Raw: \"com.example.lab.data\")
"""
        ),
        target_sdk=None,
    )

    assert inspection.components[0].effective_exported is None
    assert inspection.components[0].exported_source == "unknown_provider_default"


@pytest.mark.parametrize(
    ("target_sdk", "expected_exported", "expected_source"),
    ((16, True, "legacy_provider_default"), (34, False, "provider_default")),
)
def test_aapt2_uses_badging_target_sdk_before_manifest_normalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_sdk: int,
    expected_exported: bool,
    expected_source: str,
) -> None:
    root = tmp_path / "Lab"
    executable = root / "tools" / "aapt2.exe"
    apk = root / "results" / "base.apk"
    executable.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    executable.touch()
    apk.write_bytes(b"APK")
    provider_manifest = """E: manifest
  A: package=\"com.example.lab\" (Raw: \"com.example.lab\")
  E: application
    E: provider
      A: android:name=\".DataProvider\" (Raw: \".DataProvider\")
      A: android:authorities=\"com.example.lab.data\" (Raw: \"com.example.lab.data\")
"""

    def fake_run(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        values = [str(item) for item in arguments]
        if "badging" in values:
            return result(BADGING.replace("targetSdkVersion:'34'", f"targetSdkVersion:'{target_sdk}'"))
        return result(provider_manifest)

    monkeypatch.setattr(manifest_module, "run_command", fake_run)

    inspection = Aapt2Inspector(executable).inspect(
        apk,
        output_dir=apk.parent / "manifest",
        project_root=root,
        target_sdk=None,
    )

    assert inspection.manifest.components[0].effective_exported is expected_exported
    assert inspection.manifest.components[0].exported_source == expected_source


def test_disabled_application_and_alias_permission_are_normalized() -> None:
    output = """E: manifest
  A: package=\"com.example.lab\" (Raw: \"com.example.lab\")
  E: application
    A: android:enabled=(type 0x12)0x0
    A: android:permission=\"com.example.lab.INTERNAL\" (Raw: \"com.example.lab.INTERNAL\")
    E: activity
      A: android:name=\".Target\" (Raw: \".Target\")
    E: activity-alias
      A: android:name=\".Alias\" (Raw: \".Alias\")
      A: android:targetActivity=\".Target\" (Raw: \".Target\")
      A: android:exported=(type 0x12)0xffffffff
      E: intent-filter
        E: action
          A: android:name=\"android.intent.action.VIEW\" (Raw: \"android.intent.action.VIEW\")
        E: category
          A: android:name=\"android.intent.category.BROWSABLE\" (Raw: \"android.intent.category.BROWSABLE\")
        E: category
          A: android:name=\"android.intent.category.DEFAULT\" (Raw: \"android.intent.category.DEFAULT\")
        E: data
          A: android:scheme=\"example\" (Raw: \"example\")
"""

    inspection = inspect_manifest_tree(parse_aapt_xmltree(output), target_sdk=34)

    assert inspection.application_enabled is False
    alias = next(item for item in inspection.components if item.component_type == "activity-alias")
    assert alias.permission is None
    assert alias.exported is True
    assert alias.effective_exported is False
    assert alias.exported_source == "application_disabled"
    assert inspection.deep_links[0].component_permission is None


def test_disabled_component_is_not_effectively_exported() -> None:
    output = '''E: manifest
  A: package="com.example.lab" (Raw: "com.example.lab")
  E: application
    E: receiver
      A: android:name=".DisabledReceiver" (Raw: ".DisabledReceiver")
      A: android:enabled=(raw: "false")
      A: android:exported=0xffffffff
'''

    component = inspect_manifest_tree(
        parse_aapt_xmltree(output),
        target_sdk=34,
    ).components[0]

    assert component.enabled is False
    assert component.exported is True
    assert component.effective_exported is False
    assert component.exported_source == "component_disabled"


def test_view_browsable_filter_without_default_is_not_normalized_as_deep_link() -> None:
    missing_default = XMLTREE.replace(
        "          E: category (line=15)\n"
        "            A: http://schemas.android.com/apk/res/android:name(0x01010003)=\"android.intent.category.DEFAULT\" (Raw: \"android.intent.category.DEFAULT\")\n",
        "",
    )

    inspection = inspect_manifest_tree(parse_aapt_xmltree(missing_default), target_sdk=34)

    assert inspection.deep_links == ()


def test_resource_table_parser_keeps_all_qualified_xml_variants() -> None:
    output = """resource 0x7f120001 com.example:xml/share_paths
    (default) (file) res/xml/share_paths.xml type=XML
    (v24) (file) res/xml-v24/share_paths.xml type=XML
"""

    mapping = parse_aapt_resource_xml_paths(output)

    assert mapping["0x7f120001"] == (
        "res/xml/share_paths.xml",
        "res/xml-v24/share_paths.xml",
    )
    assert mapping["@xml/share_paths"] == mapping["0x7f120001"]


def test_manifest_parser_rejects_missing_manifest() -> None:
    with pytest.raises(ApkInspectionError, match="manifest element"):
        inspect_manifest_tree(parse_aapt_xmltree("E: resources\n"))


def test_aapt_string_pool_parser_is_bounded_and_deduplicated() -> None:
    output = "\n".join(
        (
            "String pool of 4 unique strings:",
            "String #0 : client_secret=fixture-value-123456",
            "String #1 : https://api.example.test/v1",
            "String #2 : client_secret=fixture-value-123456",
            "String #3 : " + "x" * 5000,
        )
    )

    values = parse_aapt_strings(output)
    assert values[:2] == (
        "client_secret=fixture-value-123456",
        "https://api.example.test/v1",
    )
    assert len(values) == 3
    assert len(values[2]) == 4097


def test_aapt_string_pool_parser_retains_limit_sentinel() -> None:
    output = "\n".join(
        f"String #{index} : value-{index}" for index in range(50_002)
    )

    values = parse_aapt_strings(output)

    assert len(values) == 50_001
    assert values[-1] == "value-50000"


def test_aapt_xmltree_redaction_covers_unnamed_metadata_values() -> None:
    secret = "opaque-application-secret-9x8y7z6w"
    output = (
        "E: meta-data\n"
        "  A: android:name=\"com.example.CONFIG\" (Raw: \"com.example.CONFIG\")\n"
        f"  A: android:value=\"{secret}\" (Raw: \"{secret}\")\n"
    )

    redacted = redact_aapt_xmltree(output)

    assert secret not in redacted
    assert "android:value=<redacted>" in redacted


def test_aapt2_dump_strings_uses_fixed_bounded_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "Resource Strings"
    executable = root / "tools" / "aapt2.exe"
    apk = root / "results" / "session" / "apk" / "000-base.apk"
    executable.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    executable.touch()
    apk.write_bytes(b"APK")
    calls: list[list[str]] = []
    call_options: list[dict[str, object]] = []

    def fake_run(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        calls.append([str(item) for item in arguments])
        call_options.append(dict(_kwargs))
        return result("String #0 : https://resource.example.test/path\n")

    monkeypatch.setattr(manifest_module, "run_command", fake_run)

    values = Aapt2Inspector(executable).dump_strings(apk, project_root=root)

    assert calls == [
        [str(executable), "dump", "strings", str(apk)],
    ]
    assert call_options[0]["max_stdout_bytes"] == 20_000_000
    assert call_options[0]["max_stderr_bytes"] == 1_000_000
    assert values == ("https://resource.example.test/path",)


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


def test_aapt2_does_not_persist_unindexed_raw_manifest_when_normalization_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "Lab"
    executable = root / "tools" / "aapt2.exe"
    apk = root / "results" / "base.apk"
    output_dir = apk.parent / "manifest"
    executable.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    executable.touch()
    apk.write_bytes(b"APK")

    def fake_run(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        values = [str(item) for item in arguments]
        return result(BADGING if "badging" in values else "E: resources\n")

    monkeypatch.setattr(manifest_module, "run_command", fake_run)

    with pytest.raises(ApkInspectionError, match="manifest element"):
        Aapt2Inspector(executable).inspect(
            apk,
            output_dir=output_dir,
            project_root=root,
            target_sdk=34,
        )

    assert not (output_dir / "badging.txt").exists()
    assert not (output_dir / "manifest-xmltree.txt").exists()


def test_aapt2_resolves_numeric_file_provider_resource_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "Lab"
    executable = root / "tools" / "aapt2.exe"
    apk = root / "results" / "base.apk"
    output_dir = apk.parent / "manifest"
    executable.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    executable.touch()
    apk.write_bytes(b"APK")
    calls: list[list[str]] = []
    duplicate_metadata = """      E: meta-data (line=20)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.support.FILE_PROVIDER_PATHS" (Raw: "android.support.FILE_PROVIDER_PATHS")
        A: http://schemas.android.com/apk/res/android:resource(0x01010025)=(type 0x01)0x7f120001
"""
    manifest_output = NUMERIC_FILE_PROVIDER_XMLTREE.replace(
        "      E: path-permission (line=11)\n",
        duplicate_metadata + "      E: path-permission (line=11)\n",
    )

    def fake_run(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        values = [str(item) for item in arguments]
        calls.append(values)
        if "badging" in values:
            return result(BADGING)
        if "resources" in values:
            return result(RESOURCE_TABLE)
        if "AndroidManifest.xml" in values:
            return result(manifest_output)
        assert "res/xml/share_paths.xml" in values
        return result(PATHS_XMLTREE)

    monkeypatch.setattr(manifest_module, "run_command", fake_run)

    inspection = Aapt2Inspector(executable).inspect(
        apk,
        output_dir=output_dir,
        project_root=root,
        target_sdk=34,
    )

    assert sum("resources" in call for call in calls) == 1
    assert sum("res/xml/share_paths.xml" in call for call in calls) == 1
    assert len(inspection.manifest.file_provider_paths) == 1
    paths = inspection.manifest.file_provider_paths[0]
    assert paths.resource_path == "res/xml/share_paths.xml"
    assert paths.resolution_status == "resolved"
    assert [item.kind for item in paths.entries] == ["root-path", "files-path"]
    assert len(inspection.resource_xmltree_paths) == 1
    assert inspection.resource_xmltree_paths[0].read_text(encoding="utf-8") == PATHS_XMLTREE
    assert inspection.resource_table_path is not None
    assert inspection.resource_table_path.read_text(encoding="utf-8") == RESOURCE_TABLE


def test_aapt2_resolves_all_file_provider_resource_variants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "Lab"
    executable = root / "tools" / "aapt2.exe"
    apk = root / "results" / "base.apk"
    output_dir = apk.parent / "manifest"
    executable.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    executable.touch()
    apk.write_bytes(b"APK")
    resource_table = RESOURCE_TABLE.replace(
        "    () (file) res/xml/share_paths.xml type=XML",
        "    () (file) res/xml/share_paths.xml type=XML\n"
        "    (v24) (file) res/xml-v24/share_paths.xml type=XML",
    )
    narrow_paths = """E: paths
  E: files-path
    A: android:name=\"images\" (Raw: \"images\")
    A: android:path=\"images/\" (Raw: \"images/\")
"""

    def fake_run(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        values = [str(item) for item in arguments]
        if "badging" in values:
            return result(BADGING)
        if "resources" in values:
            return result(resource_table)
        if "AndroidManifest.xml" in values:
            return result(NUMERIC_FILE_PROVIDER_XMLTREE)
        if "res/xml-v24/share_paths.xml" in values:
            return result(PATHS_XMLTREE)
        return result(narrow_paths)

    monkeypatch.setattr(manifest_module, "run_command", fake_run)

    inspection = Aapt2Inspector(executable).inspect(
        apk,
        output_dir=output_dir,
        project_root=root,
        target_sdk=34,
    )

    assert [
        item.resource_path for item in inspection.manifest.file_provider_paths
    ] == ["res/xml/share_paths.xml", "res/xml-v24/share_paths.xml"]
    assert len(inspection.resource_xmltree_paths) == 2
    assert inspection.manifest.file_provider_paths[1].entries[0].kind == "root-path"


def test_file_provider_default_path_is_partial_when_resource_inventory_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "Lab"
    executable = root / "tools" / "aapt2.exe"
    apk = root / "results" / "base.apk"
    executable.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    executable.touch()
    apk.write_bytes(b"APK")

    def fake_run(
        _self: Aapt2Inspector,
        arguments: tuple[str, ...],
        _operation: str,
    ) -> str:
        if "badging" in arguments:
            return BADGING
        if "resources" in arguments:
            raise ApkInspectionError("bounded resource inventory unavailable")
        if "AndroidManifest.xml" in arguments:
            return FILE_PROVIDER_XMLTREE
        return PATHS_XMLTREE

    monkeypatch.setattr(Aapt2Inspector, "_run", fake_run)

    inspection = Aapt2Inspector(executable).inspect(
        apk,
        output_dir=apk.parent / "manifest",
        project_root=root,
        target_sdk=34,
    )

    paths = inspection.manifest.file_provider_paths[0]
    assert paths.resource_path == "res/xml/share_paths.xml"
    assert paths.resolution_status == "resolved_partial"
    assert paths.entries


def test_aapt2_bounds_file_provider_resource_dumps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "Lab"
    executable = root / "tools" / "aapt2.exe"
    apk = root / "results" / "base.apk"
    output_dir = apk.parent / "manifest"
    executable.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    executable.touch()
    apk.write_bytes(b"APK")
    providers = "\n".join(
        f"""    E: provider (line={index + 3})
      A: http://schemas.android.com/apk/res/android:name(0x01010003)=".Provider{index}" (Raw: ".Provider{index}")
      E: meta-data (line={index + 40})
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.support.FILE_PROVIDER_PATHS" (Raw: "android.support.FILE_PROVIDER_PATHS")
        A: http://schemas.android.com/apk/res/android:resource(0x01010025)="@xml/paths_{index}" (Raw: "@xml/paths_{index}")"""
        for index in range(18)
    )
    manifest_output = f"""E: manifest (line=1)
  A: package="com.example.lab" (Raw: "com.example.lab")
  E: application (line=2)
{providers}
"""
    resource_calls: list[list[str]] = []

    def fake_run(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        values = [str(item) for item in arguments]
        if "badging" in values:
            return result(BADGING)
        if "AndroidManifest.xml" in values:
            return result(manifest_output)
        resource_calls.append(values)
        return result(PATHS_XMLTREE)

    monkeypatch.setattr(manifest_module, "run_command", fake_run)

    inspection = Aapt2Inspector(executable).inspect(
        apk,
        output_dir=output_dir,
        project_root=root,
        target_sdk=34,
    )

    assert len(resource_calls) == 17
    assert len(inspection.resource_xmltree_paths) == 16
    assert [item.resolution_status for item in inspection.manifest.file_provider_paths].count(
        "limit_exceeded"
    ) == 2
