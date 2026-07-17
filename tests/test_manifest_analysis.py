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

    assert len(results) == 4
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
    assert results["ASL-MANIFEST-EXPORTED-RECEIVER"].finding_status is FindingStatus.PASS
    assert results["ASL-MANIFEST-EXPORTED-PROVIDER"].finding_status is FindingStatus.PASS


@pytest.mark.parametrize(
    ("component_type", "test_id"),
    (
        ("activity", "ASL-MANIFEST-EXPORTED-ACTIVITY"),
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
    for component in manifest["components"]:  # type: ignore[index]
        if component["component_type"] == component_type:
            component["permission"] = None
            component["read_permission"] = None
            component["write_permission"] = None

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
