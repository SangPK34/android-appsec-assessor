"""Bounded controlled-validation definitions and production feature gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

IMPLEMENTED_UNVERIFIED = "IMPLEMENTED_UNVERIFIED"
UNVERIFIED_PHYSICAL = "UNVERIFIED"


@dataclass(frozen=True, slots=True)
class ValidationDefinition:
    validation_id: str
    rule_id: str | None
    validation_type: str
    preconditions: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    required_actions: tuple[str, ...]
    expected_observable_effect: str
    negative_case: str
    evidence_requirements: tuple[str, ...]
    cleanup_plan: tuple[str, ...]
    timeout_seconds: int
    production_enabled: bool
    implementation_status: str = IMPLEMENTED_UNVERIFIED
    physical_validation_status: str = UNVERIFIED_PHYSICAL

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for name in (
            "preconditions",
            "required_capabilities",
            "required_actions",
            "evidence_requirements",
            "cleanup_plan",
        ):
            payload[name] = list(payload[name])
        return payload


VALIDATION_DEFINITIONS: tuple[ValidationDefinition, ...] = (
    ValidationDefinition(
        validation_id="cleartext_canary",
        rule_id="ASL-NETWORK-CLEARTEXT",
        validation_type="adb_assisted_validation",
        preconditions=("Active scoped session", "Allowlisted HTTP deep link"),
        required_capabilities=(
            "ADB_AUTHORIZED",
            "PROXY_CONFIGURATION",
            "MITMPROXY_AVAILABLE",
        ),
        required_actions=("controlled_validation", "traffic_capture"),
        expected_observable_effect=(
            "The exact session canary appears in attributed HTTP flow metadata."
        ),
        negative_case="Intent launch succeeds but no attributed cleartext canary flow appears.",
        evidence_requirements=("Redacted traffic event", "Canary attribution"),
        cleanup_plan=("Restore proxy snapshot", "Remove owned ADB reverse mapping"),
        timeout_seconds=30,
        production_enabled=True,
    ),
    ValidationDefinition(
        validation_id="sensitive_logging_canary",
        rule_id="ASL-RUNTIME-SENSITIVE-SINK",
        validation_type="adb_assisted_validation",
        preconditions=("Active scoped session", "Controlled canary delivery component"),
        required_capabilities=("ADB_AUTHORIZED", "LOGCAT_ACCESS"),
        required_actions=("controlled_validation",),
        expected_observable_effect="The exact canary appears in target-process logcat evidence.",
        negative_case="Canary delivery succeeds but target-process logcat lacks the canary.",
        evidence_requirements=("PID-attributed redacted logcat",),
        cleanup_plan=("No persistent mutation expected",),
        timeout_seconds=20,
        production_enabled=True,
    ),
    ValidationDefinition(
        validation_id="exported_activity_canary",
        rule_id="ASL-IPC-EXPORTED-COMPONENT",
        validation_type="adb_assisted_validation",
        preconditions=("Active scoped session", "Unprotected exported activity"),
        required_capabilities=("ADB_AUTHORIZED",),
        required_actions=("controlled_validation",),
        expected_observable_effect="Target-process evidence contains the exact delivered canary.",
        negative_case="Activity launches but ignores the canary and produces no defined effect.",
        evidence_requirements=("Bounded am output", "Observable target-process evidence"),
        cleanup_plan=("No persistent mutation expected",),
        timeout_seconds=20,
        production_enabled=True,
    ),
    ValidationDefinition(
        validation_id="world_readable_storage_receiver_probe",
        rule_id="STORAGE-WORLD-READABLE",
        validation_type="root_assisted_validation",
        preconditions=(
            "Active scoped session",
            "Static file-mode call-site in an exported receiver",
            "Root-assisted private-storage inventory",
        ),
        required_capabilities=("ADB_AUTHORIZED", "ANDROID_ROOT", "APP_DATA_READ"),
        required_actions=("controlled_validation", "root_storage_read"),
        expected_observable_effect=(
            "A bounded receiver broadcast is followed by private-storage metadata "
            "showing a world-readable package artifact."
        ),
        negative_case=(
            "The receiver broadcast completes and bounded private-storage inventory "
            "finds no world-readable package artifact."
        ),
        evidence_requirements=(
            "Bounded am broadcast output",
            "Redacted private-storage metadata",
        ),
        cleanup_plan=("No framework-owned persistent resource expected",),
        timeout_seconds=30,
        production_enabled=True,
    ),
    ValidationDefinition(
        validation_id="shared_preferences_canary",
        rule_id=None,
        validation_type="root_assisted_validation",
        preconditions=("Active scoped session", "Lab canary preference exists"),
        required_capabilities=("ANDROID_ROOT", "APP_DATA_READ"),
        required_actions=("root_storage_read", "controlled_validation"),
        expected_observable_effect="A bounded preference value matches the session canary.",
        negative_case="Preference metadata exists but no canary value is observable.",
        evidence_requirements=("Redacted preference artifact", "Artifact SHA-256"),
        cleanup_plan=("Restore canary preference from session backup if mutated",),
        timeout_seconds=30,
        production_enabled=False,
    ),
    ValidationDefinition(
        validation_id="sqlite_canary",
        rule_id=None,
        validation_type="root_assisted_validation",
        preconditions=("Active scoped session", "Lab canary database row exists"),
        required_capabilities=("ANDROID_ROOT", "APP_DATA_READ"),
        required_actions=("root_storage_read", "controlled_validation"),
        expected_observable_effect="A bounded query returns the exact session canary marker.",
        negative_case="Database metadata exists but the bounded canary query has no match.",
        evidence_requirements=("Redacted query result metadata", "Database SHA-256"),
        cleanup_plan=("Restore database backup if validation mutates a lab row",),
        timeout_seconds=30,
        production_enabled=False,
    ),
    ValidationDefinition(
        validation_id="crypto_boundary_canary",
        rule_id=None,
        validation_type="instrumented_validation",
        preconditions=("Active scoped session", "Observer handshake verified"),
        required_capabilities=("FRIDA_CLIENT", "FRIDA_SERVER"),
        required_actions=("frida_observe", "controlled_validation"),
        expected_observable_effect="A redacted crypto-boundary event reports canary_match=true.",
        negative_case="Crypto APIs execute without an attributed canary boundary event.",
        evidence_requirements=("Normalized Frida JSONL event", "Observer hook hash"),
        cleanup_plan=("Stop owned observer", "Stop only session-owned Frida Server"),
        timeout_seconds=30,
        production_enabled=False,
    ),
    ValidationDefinition(
        validation_id="root_detection_observation",
        rule_id=None,
        validation_type="instrumented_validation",
        preconditions=("Active scoped session", "Observer handshake verified"),
        required_capabilities=("ANDROID_ROOT", "FRIDA_CLIENT", "FRIDA_SERVER"),
        required_actions=("frida_observe", "controlled_validation"),
        expected_observable_effect=(
            "A normalized root-check event and app response are both observed."
        ),
        negative_case="A root-check API executes without a complete observable app response.",
        evidence_requirements=("Normalized root-check event", "App-response evidence"),
        cleanup_plan=("Stop owned observer", "Preserve pre-existing Frida Server"),
        timeout_seconds=30,
        production_enabled=False,
    ),
)


def validation_for_rule(rule_id: str) -> ValidationDefinition | None:
    return next(
        (definition for definition in VALIDATION_DEFINITIONS if definition.rule_id == rule_id),
        None,
    )


def validation_by_id(validation_id: str) -> ValidationDefinition:
    definition = next(
        (
            candidate
            for candidate in VALIDATION_DEFINITIONS
            if candidate.validation_id == validation_id
        ),
        None,
    )
    if definition is None:
        raise KeyError(validation_id)
    return definition
