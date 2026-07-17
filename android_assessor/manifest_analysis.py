"""Conservative manifest policy checks that never confirm exploitability statically."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .findings import FindingStatus


@dataclass(frozen=True, slots=True)
class ManifestPolicyResult:
    test_id: str
    finding_status: FindingStatus
    confidence: str
    validation_type: str
    rationale: str
    details: dict[str, Any]
    source: str
    environment: str
    finding_eligible: bool
    physical_validation_status: str = "UNVERIFIED"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["finding_status"] = self.finding_status.value
        return payload


def _protection_classification(
    permission: str | None,
    custom_permissions: dict[str, str | None],
) -> str:
    if not permission:
        return "missing"
    level = custom_permissions.get(permission)
    if level is None:
        return "unknown"
    normalized = str(level).strip().casefold()
    try:
        base = int(normalized, 0) & 0xF
    except ValueError:
        base = -1
    if base == 2 or "signature" in normalized:
        return "signature"
    if base in {0, 1} or normalized in {"normal", "dangerous"}:
        return "weak"
    return "unknown"


def _is_launcher(component: dict[str, Any]) -> bool:
    filters = component.get("intent_filters", [])
    if not isinstance(filters, list):
        return False
    return any(
        isinstance(item, dict)
        and "android.intent.action.MAIN" in item.get("actions", [])
        and "android.intent.category.LAUNCHER" in item.get("categories", [])
        for item in filters
    )


def _component_boundaries(
    component: dict[str, Any],
    application_permission: str | None,
) -> tuple[str | None, ...]:
    component_permission = component.get("permission")
    generic = (
        component_permission
        if isinstance(component_permission, str) and component_permission
        else application_permission
    )
    if component.get("component_type") == "provider":
        read_permission = component.get("read_permission")
        write_permission = component.get("write_permission")
        return (
            read_permission
            if isinstance(read_permission, str) and read_permission
            else generic,
            write_permission
            if isinstance(write_permission, str) and write_permission
            else generic,
        )
    return (generic,)


class ManifestSecurityAnalyzer:
    @staticmethod
    def analyze(
        manifest: dict[str, Any],
        *,
        source: str,
        environment: str,
    ) -> tuple[ManifestPolicyResult, ...]:
        if (source == "fixture") != (environment == "simulated"):
            raise ValueError("Manifest fixture requires simulated provenance.")
        simulated = source == "fixture" and environment == "simulated"
        allow_backup = manifest.get("allow_backup")
        if allow_backup is True:
            backup_status = FindingStatus.POTENTIAL
            backup_confidence = "medium"
            backup_rationale = (
                "Application backup is enabled; impact depends on Android version and data rules."
            )
        elif allow_backup is False:
            backup_status = FindingStatus.PASS
            backup_confidence = "high"
            backup_rationale = "Application backup is explicitly disabled."
        else:
            backup_status = FindingStatus.INCONCLUSIVE
            backup_confidence = "low"
            backup_rationale = "The effective application backup policy is unknown."
        results = [
            ManifestPolicyResult(
                test_id="ASL-MANIFEST-ALLOW-BACKUP",
                finding_status=backup_status,
                confidence=backup_confidence,
                validation_type="adb_assisted_validation",
                rationale=backup_rationale,
                details={"allow_backup": allow_backup},
                source=source,
                environment=environment,
                finding_eligible=not simulated,
            )
        ]

        custom_values = manifest.get("custom_permissions", [])
        custom_permissions = {
            str(item.get("name")): (
                str(item["protection_level"])
                if item.get("protection_level") is not None
                else None
            )
            for item in custom_values
            if isinstance(item, dict) and item.get("name")
        } if isinstance(custom_values, list) else {}
        application_permission = manifest.get("application_permission")
        if not isinstance(application_permission, str):
            application_permission = None
        components = manifest.get("components")
        components_valid = isinstance(components, list)
        values = components if components_valid else []
        for component_type, test_id in (
            ("activity", "ASL-MANIFEST-EXPORTED-ACTIVITY"),
            ("receiver", "ASL-MANIFEST-EXPORTED-RECEIVER"),
            ("provider", "ASL-MANIFEST-EXPORTED-PROVIDER"),
        ):
            if not components_valid:
                results.append(
                    ManifestPolicyResult(
                        test_id=test_id,
                        finding_status=FindingStatus.INCONCLUSIVE,
                        confidence="low",
                        validation_type="adb_assisted_validation",
                        rationale="The normalized component inventory is unavailable.",
                        details={"inventory_error": "components_not_a_list"},
                        source=source,
                        environment=environment,
                        finding_eligible=not simulated,
                    )
                )
                continue
            relevant = [
                item
                for item in values
                if isinstance(item, dict)
                and item.get("component_type") in {
                    component_type,
                    "activity-alias" if component_type == "activity" else component_type,
                }
                and item.get("enabled") is not False
                and not (component_type == "activity" and _is_launcher(item))
            ]
            exposed: list[dict[str, Any]] = []
            unknown_export: list[str] = []
            for component in relevant:
                exported = component.get("effective_exported")
                if exported is None:
                    unknown_export.append(str(component.get("name", "<unnamed>")))
                    continue
                if not isinstance(exported, bool):
                    unknown_export.append(str(component.get("name", "<unnamed>")))
                    continue
                if exported is not True:
                    continue
                boundaries = _component_boundaries(component, application_permission)
                classifications = tuple(
                    _protection_classification(permission, custom_permissions)
                    for permission in boundaries
                )
                exposed.append(
                    {
                        "name": str(component.get("name", "<unnamed>")),
                        "boundary": list(classifications),
                    }
                )
            unsafe = [
                item
                for item in exposed
                if any(value in {"missing", "weak"} for value in item["boundary"])
            ]
            unknown = [
                item
                for item in exposed
                if not any(value in {"missing", "weak"} for value in item["boundary"])
                and any(value == "unknown" for value in item["boundary"])
            ]
            if unsafe:
                status = FindingStatus.POTENTIAL
                confidence = "medium"
                rationale = "Exported component metadata lacks a strong permission boundary."
            elif unknown or unknown_export:
                status = FindingStatus.INCONCLUSIVE
                confidence = "low"
                rationale = "Export or permission protection could not be classified safely."
            else:
                status = FindingStatus.PASS
                confidence = "high"
                rationale = "No unprotected exported component was identified in this category."
            results.append(
                ManifestPolicyResult(
                    test_id=test_id,
                    finding_status=status,
                    confidence=confidence,
                    validation_type="adb_assisted_validation",
                    rationale=rationale,
                    details={
                        "potentially_unprotected": unsafe,
                        "unknown_protection": unknown,
                        "unknown_export": unknown_export,
                    },
                    source=source,
                    environment=environment,
                    finding_eligible=not simulated,
                )
            )
        return tuple(results)
