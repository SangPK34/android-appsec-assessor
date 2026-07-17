from __future__ import annotations

from copy import deepcopy

import pytest

from android_assessor.findings import FindingStatus
from android_assessor.manifest_analysis import ManifestSecurityAnalyzer
from tests.fakes import load_fixture


def _manifest(name: str) -> dict[str, object]:
    payload = load_fixture(f"manifests/{name}.json")
    manifest = payload["manifest"]
    assert isinstance(manifest, dict)
    return deepcopy(manifest)


def _results(manifest: dict[str, object]):
    return {
        item.test_id: item
        for item in ManifestSecurityAnalyzer.analyze(
            manifest,
            source="fixture",
            environment="simulated",
        )
    }


def test_secure_manifest_passes_bounded_metadata_checks() -> None:
    results = _results(_manifest("secure"))

    assert len(results) == 8
    assert all(item.finding_status is FindingStatus.PASS for item in results.values())
    assert all(item.finding_eligible is False for item in results.values())
    assert all(item.physical_validation_status == "UNVERIFIED" for item in results.values())


def test_allow_backup_is_potential_not_confirmed() -> None:
    result = _results(_manifest("exported"))["ASL-MANIFEST-ALLOW-BACKUP"]

    assert result.finding_status is FindingStatus.POTENTIAL
    assert "depends on Android version" in result.rationale


def test_application_signature_permission_protects_exported_components() -> None:
    results = _results(_manifest("exported"))

    assert results["ASL-MANIFEST-EXPORTED-ACTIVITY"].finding_status is FindingStatus.PASS
    assert results["ASL-MANIFEST-EXPORTED-SERVICE"].finding_status is FindingStatus.PASS
    assert results["ASL-MANIFEST-EXPORTED-RECEIVER"].finding_status is FindingStatus.PASS
    assert results["ASL-MANIFEST-EXPORTED-PROVIDER"].finding_status is FindingStatus.PASS


@pytest.mark.parametrize(
    ("component_type", "test_id"),
    (
        ("activity", "ASL-MANIFEST-EXPORTED-ACTIVITY"),
        ("service", "ASL-MANIFEST-EXPORTED-SERVICE"),
        ("receiver", "ASL-MANIFEST-EXPORTED-RECEIVER"),
        ("provider", "ASL-MANIFEST-EXPORTED-PROVIDER"),
    ),
)
def test_exported_component_without_permission_is_only_potential(
    component_type: str,
    test_id: str,
) -> None:
    manifest = _manifest("exported")
    manifest["application_permission"] = None
    matched = False
    for component in manifest["components"]:  # type: ignore[index]
        if component["component_type"] == component_type:
            matched = True
            component["permission"] = None
            component["read_permission"] = None
            component["write_permission"] = None
    if not matched:
        manifest["components"].append(  # type: ignore[union-attr]
            {
                "component_type": component_type,
                "name": f"com.example.rootedlab.Exported{component_type.title()}",
                "effective_exported": True,
                "enabled": True,
                "permission": None,
                "intent_filters": [],
            }
        )

    result = _results(manifest)[test_id]

    assert result.finding_status is FindingStatus.POTENTIAL
    assert result.finding_status is not FindingStatus.CONFIRMED


def test_weak_custom_permission_is_not_treated_as_strong() -> None:
    manifest = _manifest("exported")
    manifest["application_permission"] = None
    manifest["custom_permissions"] = [
        {
            "name": "com.example.rootedlab.INTERNAL",
            "protection_level": "dangerous",
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-RECEIVER"]

    assert result.finding_status is FindingStatus.POTENTIAL
    assert result.details["potentially_unprotected"][0]["boundary"] == ["weak"]


def test_service_inherits_application_signature_permission_with_provenance() -> None:
    manifest = _manifest("exported")
    manifest["components"].append(  # type: ignore[union-attr]
        {
            "component_type": "service",
            "name": "com.example.rootedlab.SyncService",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        }
    )

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-SERVICE"]

    assert result.finding_status is FindingStatus.PASS
    boundary = result.details["evaluated_components"][0]["effective_permissions"][0]
    assert boundary["operation"] == "invoke"
    assert boundary["permission"] == "com.example.rootedlab.INTERNAL"
    assert boundary["source"] == "application"
    assert boundary["classification"] == "signature"


def test_activity_alias_without_permission_does_not_inherit_application_permission() -> None:
    manifest = _manifest("exported")
    manifest["components"] = [
        {
            "component_type": "activity-alias",
            "name": "com.example.rootedlab.PublicAlias",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-ACTIVITY"]

    assert result.finding_status is FindingStatus.POTENTIAL
    boundary = result.details["potentially_unprotected"][0]["effective_permissions"][0]
    assert boundary["permission"] is None
    assert boundary["source"] == "missing"


def test_activity_alias_explicit_signature_permission_remains_protected() -> None:
    manifest = _manifest("exported")
    manifest["components"] = [
        {
            "component_type": "activity-alias",
            "name": "com.example.rootedlab.ProtectedAlias",
            "effective_exported": True,
            "enabled": True,
            "permission": "com.example.rootedlab.INTERNAL",
            "intent_filters": [],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-ACTIVITY"]

    assert result.finding_status is FindingStatus.PASS


def test_missing_custom_protection_level_defaults_to_weak_normal() -> None:
    manifest = _manifest("exported")
    manifest["application_permission"] = None
    manifest["custom_permissions"] = [
        {
            "name": "com.example.rootedlab.INTERNAL",
            "protection_level": None,
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-RECEIVER"]

    assert result.finding_status is FindingStatus.POTENTIAL
    boundary = result.details["potentially_unprotected"][0]["effective_permissions"][0]
    assert boundary["classification"] == "weak"
    assert boundary["protection"]["base"] == "normal"
    assert boundary["protection"]["defaulted"] is True
    custom_result = _results(manifest)["ASL-MANIFEST-CUSTOM-PERMISSION"]
    assert custom_result.finding_status is FindingStatus.POTENTIAL
    assert custom_result.details["weak_permissions"][0]["base"] == "normal"


@pytest.mark.parametrize("protection_level", ("signatureOrSystem", "3", "0x3"))
def test_signature_or_system_is_conservative_not_signature_pass(
    protection_level: str,
) -> None:
    manifest = _manifest("exported")
    manifest["application_permission"] = None
    manifest["custom_permissions"] = [
        {
            "name": "com.example.rootedlab.INTERNAL",
            "protection_level": protection_level,
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-RECEIVER"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE
    boundary = result.details["unknown_protection"][0]["effective_permissions"][0]
    assert boundary["classification"] == "legacy_restricted"
    assert boundary["protection"]["base"] == "signatureOrSystem"
    custom_result = _results(manifest)["ASL-MANIFEST-CUSTOM-PERMISSION"]
    assert custom_result.finding_status is FindingStatus.INCONCLUSIVE


def test_signature_custom_permission_passes_definition_policy() -> None:
    result = _results(_manifest("exported"))["ASL-MANIFEST-CUSTOM-PERMISSION"]

    assert result.finding_status is FindingStatus.PASS
    assert result.details["definitions"][0]["classification"] == "signature"


@pytest.mark.parametrize("custom_permissions", (None, "invalid", [{"name": 42}]))
def test_missing_or_malformed_custom_permission_inventory_is_inconclusive(
    custom_permissions: object,
) -> None:
    manifest = _manifest("secure")
    manifest["custom_permissions"] = custom_permissions

    result = _results(manifest)["ASL-MANIFEST-CUSTOM-PERMISSION"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_provider_effective_read_write_permissions_preserve_sources() -> None:
    manifest = _manifest("secure")
    manifest["application_permission"] = None
    manifest["custom_permissions"] = [
        {"name": "com.example.SIGNATURE", "protection_level": "signature"},
        {"name": "com.example.READ", "protection_level": "dangerous"},
    ]
    manifest["components"] = [
        {
            "component_type": "provider",
            "name": "com.example.Provider",
            "effective_exported": True,
            "enabled": True,
            "permission": "com.example.SIGNATURE",
            "read_permission": "com.example.READ",
            "write_permission": None,
            "path_permissions": [],
            "intent_filters": [],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-PROVIDER"]

    assert result.finding_status is FindingStatus.POTENTIAL
    boundaries = result.details["evaluated_components"][0]["effective_permissions"]
    assert [(item["operation"], item["source"]) for item in boundaries] == [
        ("read", "provider_read"),
        ("write", "component"),
    ]
    assert [item["classification"] for item in boundaries] == ["weak", "signature"]


def test_provider_path_permission_weak_override_is_evaluated() -> None:
    manifest = _manifest("secure")
    manifest["custom_permissions"] = [
        {"name": "com.example.SIGNATURE", "protection_level": "signature"},
        {"name": "com.example.PATH_READ", "protection_level": "dangerous"},
    ]
    manifest["components"] = [
        {
            "component_type": "provider",
            "name": "com.example.Provider",
            "effective_exported": True,
            "enabled": True,
            "permission": "com.example.SIGNATURE",
            "read_permission": None,
            "write_permission": None,
            "path_permissions": [
                {
                    "read_permission": "com.example.PATH_READ",
                    "path_prefix": "/shared",
                }
            ],
            "intent_filters": [],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-PROVIDER"]

    assert result.finding_status is FindingStatus.POTENTIAL
    boundaries = result.details["evaluated_components"][0]["effective_permissions"]
    path_read = next(item for item in boundaries if item["operation"] == "path_read")
    assert path_read["source"] == "path_permission_read"
    assert path_read["classification"] == "weak"
    assert path_read["matcher"] == {"path_prefix": "/shared"}


def test_malformed_application_permission_never_false_passes() -> None:
    manifest = _manifest("secure")
    manifest["application_permission"] = 123
    manifest["components"] = [
        {
            "component_type": "service",
            "name": "com.example.Service",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-SERVICE"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE
    boundary = result.details["unknown_protection"][0]["effective_permissions"][0]
    assert boundary["source"] == "malformed"
    assert boundary["classification"] == "malformed"


def test_broad_file_provider_path_is_potential() -> None:
    manifest = _manifest("secure")
    manifest["file_provider_paths"] = [
        {
            "provider": "com.example.Files",
            "authorities": "com.example.files",
            "grant_uri_permissions": True,
            "resource_reference": "@xml/paths",
            "resource_path": "res/xml/paths.xml",
            "resolution_status": "resolved",
            "entries": [{"kind": "root-path", "name": "root", "path": "tmp/"}],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-FILEPROVIDER-PATHS"]

    assert result.finding_status is FindingStatus.POTENTIAL
    assert result.details["broad_paths"][0]["kind"] == "root-path"


def test_broad_file_provider_path_without_external_reachability_is_not_finding() -> None:
    manifest = _manifest("secure")
    manifest["components"].append(  # type: ignore[union-attr]
        {
            "component_type": "provider",
            "name": "com.example.Files",
            "effective_exported": False,
            "enabled": True,
            "permission": None,
            "read_permission": None,
            "write_permission": None,
            "grant_uri_permissions": False,
            "uri_grant_patterns": [],
            "path_permissions": [],
            "intent_filters": [],
        }
    )
    manifest["file_provider_paths"] = [
        {
            "provider": "com.example.Files",
            "authorities": "com.example.files",
            "grant_uri_permissions": False,
            "resolution_status": "resolved",
            "entries": [{"kind": "root-path", "name": "root", "path": "."}],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-FILEPROVIDER-PATHS"]

    assert result.finding_status is FindingStatus.PASS
    assert result.details["broad_paths"] == []
    assert result.details["protected_broad_paths"][0]["access_state"] == "protected"
    assert result.details["protected_broad_paths"][0]["normalized_path"] == "."


def test_file_provider_grant_pattern_without_known_behavior_is_inconclusive() -> None:
    manifest = _manifest("secure")
    manifest["components"].append(  # type: ignore[union-attr]
        {
            "component_type": "provider",
            "name": "com.example.Files",
            "effective_exported": False,
            "enabled": True,
            "permission": None,
            "read_permission": None,
            "write_permission": None,
            "grant_uri_permissions": False,
            "uri_grant_patterns": [{"path_prefix": "/shared"}],
            "path_permissions": [],
            "intent_filters": [],
        }
    )
    manifest["file_provider_paths"] = [
        {
            "provider": "com.example.Files",
            "authorities": "com.example.files",
            "grant_uri_permissions": False,
            "resolution_status": "resolved",
            "entries": [{"kind": "root-path", "name": "root", "path": "/"}],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-FILEPROVIDER-PATHS"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE
    assert result.details["unknown_reachability"][0]["uri_grant_pattern_count"] == 1


def test_conflicting_file_provider_components_are_inconclusive() -> None:
    manifest = _manifest("secure")
    manifest["components"] = [
        {
            "component_type": "provider",
            "name": "com.example.Files",
            "effective_exported": False,
            "enabled": True,
            "permission": None,
            "read_permission": None,
            "write_permission": None,
            "grant_uri_permissions": False,
            "uri_grant_patterns": [],
            "path_permissions": [],
            "intent_filters": [],
            "source_apk": "base:0",
        },
        {
            "component_type": "provider",
            "name": "com.example.Files",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "read_permission": None,
            "write_permission": None,
            "grant_uri_permissions": True,
            "uri_grant_patterns": [],
            "path_permissions": [],
            "intent_filters": [],
            "source_apk": "split:1",
        },
    ]
    manifest["file_provider_paths"] = [
        {
            "provider": "com.example.Files",
            "authorities": "com.example.files",
            "grant_uri_permissions": True,
            "resolution_status": "resolved",
            "entries": [{"kind": "root-path", "name": "root", "path": "."}],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-FILEPROVIDER-PATHS"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE
    assert result.details["unknown_reachability"][0]["access_state"] == "unknown"
    assert result.details["unknown_reachability"][0]["reason"] == (
        "conflicting_provider_definitions"
    )


def test_file_provider_scoped_limitation_does_not_degrade_other_manifest_rules() -> None:
    manifest = _manifest("secure")
    manifest["file_provider_limitations"] = [
        "split_resource_variants_not_correlated"
    ]

    results = _results(manifest)

    assert results["ASL-MANIFEST-FILEPROVIDER-PATHS"].finding_status is (
        FindingStatus.INCONCLUSIVE
    )
    assert results["ASL-MANIFEST-EXPORTED-SERVICE"].finding_status is FindingStatus.PASS


def test_bounded_file_provider_path_passes_focused_policy() -> None:
    manifest = _manifest("secure")
    manifest["file_provider_paths"] = [
        {
            "provider": "com.example.Files",
            "authorities": "com.example.files",
            "grant_uri_permissions": True,
            "resource_reference": "@xml/paths",
            "resource_path": "res/xml/paths.xml",
            "resolution_status": "resolved",
            "entries": [
                {"kind": "files-path", "name": "images", "path": "images/"}
            ],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-FILEPROVIDER-PATHS"]

    assert result.finding_status is FindingStatus.PASS
    assert result.details["evaluated_configurations"] == 1


@pytest.mark.parametrize(
    "file_provider_paths",
    (
        "not-a-list",
        [{"provider": "com.example.Files", "resolution_status": "unresolved"}],
        [
            {
                "provider": "com.example.Files",
                "resolution_status": "resolved",
                "entries": [],
            }
        ],
    ),
)
def test_malformed_or_unresolved_file_provider_never_false_passes(
    file_provider_paths: object,
) -> None:
    manifest = _manifest("secure")
    manifest["file_provider_paths"] = file_provider_paths

    result = _results(manifest)["ASL-MANIFEST-FILEPROVIDER-PATHS"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_broad_unprotected_exported_deep_link_is_potential() -> None:
    manifest = _manifest("secure")
    manifest["deep_links"] = [
        {
            "component": "com.example.LinkActivity",
            "scheme": "example",
            "host": None,
            "path_prefix": "/apparently-narrow",
            "component_effective_exported": True,
            "component_permission": None,
            "auto_verify": False,
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-DEEP-LINK-EXPOSURE"]

    assert result.finding_status is FindingStatus.POTENTIAL
    exposed = result.details["potentially_exposed"][0]
    assert exposed["broad_match"] is True
    assert exposed["effective_permission"]["classification"] == "missing"


def test_deep_link_with_host_and_narrow_path_is_not_broad() -> None:
    manifest = _manifest("secure")
    manifest["deep_links"] = [
        {
            "component": "com.example.LinkActivity",
            "scheme": "example",
            "host": "open.example.test",
            "path_prefix": "/bounded",
            "component_effective_exported": True,
            "component_permission": None,
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-DEEP-LINK-EXPOSURE"]

    assert result.finding_status is FindingStatus.PASS
    assert result.details["evaluated_links"][0]["broad_match"] is False


def test_signature_protected_deep_link_passes_focused_policy() -> None:
    manifest = _manifest("exported")
    manifest["deep_links"] = [
        {
            "component": "com.example.rootedlab.LinkActivity",
            "scheme": "https",
            "host": "links.example",
            "component_effective_exported": True,
            "component_permission": "com.example.rootedlab.INTERNAL",
            "auto_verify": True,
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-DEEP-LINK-EXPOSURE"]

    assert result.finding_status is FindingStatus.PASS
    link = result.details["evaluated_links"][0]
    assert link["auto_verify_requested"] is True
    assert result.details["auto_verify_is_not_verification_proof"] is True


def test_external_deep_link_permission_is_inconclusive() -> None:
    manifest = _manifest("secure")
    manifest["deep_links"] = [
        {
            "component": "com.example.LinkActivity",
            "scheme": "https",
            "host": "links.example",
            "path": "/exact",
            "component_effective_exported": True,
            "component_permission": "android.permission.EXTERNAL_UNKNOWN",
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-DEEP-LINK-EXPOSURE"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE
    assert result.details["unknown"][0]["effective_permission"]["classification"] == (
        "external_unknown"
    )


@pytest.mark.parametrize(
    ("deep_links", "truncated"),
    (
        ("invalid", False),
        ([{"component": "missing-scheme"}], False),
        ([], True),
    ),
)
def test_malformed_or_truncated_deep_link_inventory_is_inconclusive(
    deep_links: object,
    truncated: bool,
) -> None:
    manifest = _manifest("secure")
    manifest["deep_links"] = deep_links
    manifest["deep_links_truncated"] = truncated

    result = _results(manifest)["ASL-MANIFEST-DEEP-LINK-EXPOSURE"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_unknown_platform_permission_is_inconclusive_not_pass_or_confirmed() -> None:
    manifest = _manifest("exported")
    manifest["application_permission"] = "android.permission.SOME_PLATFORM_PERMISSION"
    manifest["custom_permissions"] = []

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-PROVIDER"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE
    assert result.details["unknown_protection"]


def test_unknown_effective_export_is_inconclusive() -> None:
    manifest = _manifest("secure")
    manifest["components"] = [
        {
            "component_type": "receiver",
            "name": "com.example.rootedlab.UnknownReceiver",
            "effective_exported": None,
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-RECEIVER"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE
    assert result.details["unknown_export"] == [
        "com.example.rootedlab.UnknownReceiver"
    ]


def test_unknown_provider_default_is_inconclusive_not_pass() -> None:
    manifest = _manifest("secure")
    manifest["components"] = [
        {
            "component_type": "provider",
            "name": "com.example.UnknownProvider",
            "effective_exported": None,
            "exported_source": "unknown_provider_default",
            "enabled": True,
            "permission": None,
            "read_permission": None,
            "write_permission": None,
            "intent_filters": [],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-PROVIDER"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_disabled_application_suppresses_unreachable_component_and_deep_link() -> None:
    manifest = _manifest("secure")
    manifest["application_enabled"] = False
    manifest["components"] = [
        {
            "component_type": "service",
            "name": "com.example.DisabledService",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        }
    ]
    manifest["deep_links"] = [
        {
            "component": "com.example.DisabledActivity",
            "scheme": "example",
            "host": None,
            "component_effective_exported": True,
            "component_permission": None,
        }
    ]

    results = _results(manifest)

    assert results["ASL-MANIFEST-EXPORTED-SERVICE"].finding_status is FindingStatus.PASS
    assert results["ASL-MANIFEST-DEEP-LINK-EXPOSURE"].finding_status is FindingStatus.PASS


def test_conflicting_component_definitions_are_order_independent() -> None:
    manifest = _manifest("secure")
    definitions = [
        {
            "component_type": "service",
            "name": "com.example.ConflictingService",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        },
        {
            "component_type": "service",
            "name": "com.example.ConflictingService",
            "effective_exported": False,
            "enabled": False,
            "permission": None,
            "intent_filters": [],
        },
    ]

    statuses = []
    for rows in (definitions, list(reversed(definitions))):
        manifest["components"] = rows
        statuses.append(
            _results(manifest)["ASL-MANIFEST-EXPORTED-SERVICE"].finding_status
        )

    assert statuses == [FindingStatus.INCONCLUSIVE, FindingStatus.INCONCLUSIVE]


def test_conflicting_custom_permission_definitions_are_inconclusive() -> None:
    manifest = _manifest("secure")
    manifest["custom_permissions"] = [
        {"name": "com.example.CONFLICT", "protection_level": "signature"},
        {"name": "com.example.CONFLICT", "protection_level": "dangerous"},
    ]

    result = _results(manifest)["ASL-MANIFEST-CUSTOM-PERMISSION"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE
    assert result.details["malformed"][0]["reason"] == "duplicate_or_empty_name"


def test_launcher_activity_is_not_reported_as_unprotected_entry_point() -> None:
    manifest = _manifest("secure")
    manifest["components"] = [
        {
            "component_type": "activity",
            "name": "com.example.rootedlab.MainActivity",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [
                {
                    "actions": ["android.intent.action.MAIN"],
                    "categories": ["android.intent.category.LAUNCHER"],
                }
            ],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-ACTIVITY"]

    assert result.finding_status is FindingStatus.PASS


def test_missing_backup_flag_is_inconclusive() -> None:
    manifest = _manifest("secure")
    manifest.pop("allow_backup")

    result = _results(manifest)["ASL-MANIFEST-ALLOW-BACKUP"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    "components",
    (
        None,
        {"receiver": "not-a-list"},
        "not-a-list",
    ),
)
def test_malformed_component_inventory_never_false_passes(components: object) -> None:
    manifest = _manifest("secure")
    manifest["components"] = components

    results = _results(manifest)

    assert all(
        results[test_id].finding_status is FindingStatus.INCONCLUSIVE
        for test_id in (
            "ASL-MANIFEST-EXPORTED-ACTIVITY",
            "ASL-MANIFEST-EXPORTED-SERVICE",
            "ASL-MANIFEST-EXPORTED-RECEIVER",
            "ASL-MANIFEST-EXPORTED-PROVIDER",
        )
    )


def test_malformed_exported_value_is_inconclusive_not_pass() -> None:
    manifest = _manifest("secure")
    manifest["components"] = [
        {
            "component_type": "receiver",
            "name": "com.example.rootedlab.BadSchemaReceiver",
            "effective_exported": "true",
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        }
    ]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-RECEIVER"]

    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_manifest_fixture_provenance_cannot_be_labeled_physical() -> None:
    with pytest.raises(ValueError, match="simulated provenance"):
        ManifestSecurityAnalyzer.analyze(
            _manifest("secure"),
            source="fixture",
            environment="physical",
        )


def test_incomplete_split_manifest_coverage_never_false_passes() -> None:
    manifest = _manifest("secure")
    manifest["manifest_complete"] = False
    manifest["manifest_limitations"] = ["split:1:manifest_inspection_failed"]

    results = _results(manifest)

    for rule_id in (
        "ASL-MANIFEST-EXPORTED-ACTIVITY",
        "ASL-MANIFEST-EXPORTED-SERVICE",
        "ASL-MANIFEST-EXPORTED-RECEIVER",
        "ASL-MANIFEST-EXPORTED-PROVIDER",
        "ASL-MANIFEST-CUSTOM-PERMISSION",
        "ASL-MANIFEST-FILEPROVIDER-PATHS",
        "ASL-MANIFEST-DEEP-LINK-EXPOSURE",
    ):
        assert results[rule_id].finding_status is FindingStatus.INCONCLUSIVE
        assert results[rule_id].details["manifest_coverage_limitations"] == [
            "split:1:manifest_inspection_failed"
        ]


def test_incomplete_manifest_keeps_known_positive_candidate() -> None:
    manifest = _manifest("exported")
    manifest["application_permission"] = None
    manifest["components"].append(  # type: ignore[union-attr]
        {
            "component_type": "service",
            "name": "com.example.rootedlab.UnprotectedService",
            "effective_exported": True,
            "enabled": True,
            "permission": None,
            "intent_filters": [],
        }
    )
    manifest["manifest_complete"] = False
    manifest["manifest_limitations"] = ["split:2:manifest_inspection_failed"]

    result = _results(manifest)["ASL-MANIFEST-EXPORTED-SERVICE"]

    assert result.finding_status is FindingStatus.POTENTIAL
    assert result.details["manifest_coverage_limitations"]
