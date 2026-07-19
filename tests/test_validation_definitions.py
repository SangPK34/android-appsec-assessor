from __future__ import annotations

import json

import pytest

from android_assessor.validation_definitions import (
    IMPLEMENTED_UNVERIFIED,
    UNVERIFIED_PHYSICAL,
    VALIDATION_DEFINITIONS,
    validation_by_id,
    validation_for_rule,
)

ALLOWED_TYPES = {
    "natural_validation",
    "adb_assisted_validation",
    "root_assisted_validation",
    "instrumented_validation",
    "post_compromise_observation",
}


def test_validation_registry_has_unique_complete_bounded_definitions() -> None:
    identifiers = [item.validation_id for item in VALIDATION_DEFINITIONS]

    assert len(identifiers) == len(set(identifiers)) == 8
    for definition in VALIDATION_DEFINITIONS:
        assert definition.validation_type in ALLOWED_TYPES
        assert definition.preconditions
        assert definition.required_capabilities
        assert definition.required_actions
        assert definition.expected_observable_effect
        assert definition.negative_case
        assert definition.evidence_requirements
        assert definition.cleanup_plan
        assert 1 <= definition.timeout_seconds <= 60
        assert definition.implementation_status == IMPLEMENTED_UNVERIFIED
        assert definition.physical_validation_status == UNVERIFIED_PHYSICAL


def test_existing_validations_are_registered_and_production_enabled() -> None:
    expected = {
        "ASL-NETWORK-CLEARTEXT": "cleartext_canary",
        "ASL-RUNTIME-SENSITIVE-SINK": "sensitive_logging_canary",
        "ASL-IPC-EXPORTED-COMPONENT": "exported_activity_canary",
        "STORAGE-WORLD-READABLE": "world_readable_storage_receiver_probe",
    }

    for rule_id, validation_id in expected.items():
        definition = validation_for_rule(rule_id)
        assert definition is not None
        assert definition.validation_id == validation_id
        assert definition.production_enabled is True


@pytest.mark.parametrize(
    "validation_id",
    (
        "shared_preferences_canary",
        "sqlite_canary",
        "crypto_boundary_canary",
        "root_detection_observation",
    ),
)
def test_root_focused_prepared_validations_remain_feature_gated(
    validation_id: str,
) -> None:
    definition = validation_by_id(validation_id)

    assert definition.production_enabled is False
    assert definition.rule_id is None
    assert definition.implementation_status == "IMPLEMENTED_UNVERIFIED"
    assert definition.physical_validation_status == "UNVERIFIED"


def test_validation_definitions_serialize_without_payload_or_secret_fields() -> None:
    serialized = json.dumps(
        [item.to_dict() for item in VALIDATION_DEFINITIONS],
        sort_keys=True,
    ).casefold()

    assert "payload" not in serialized
    assert "password" not in serialized
    assert "authorization" not in serialized
    assert "private_key" not in serialized


def test_unknown_validation_id_and_rule_are_not_enabled() -> None:
    assert validation_for_rule("ASL-NOT-REGISTERED") is None
    with pytest.raises(KeyError):
        validation_by_id("not-registered")
