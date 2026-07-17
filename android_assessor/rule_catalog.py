"""Root-focused implementation coverage catalog for reports and thesis metrics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RootFocusedTestDefinition:
    test_id: str
    title: str
    available_without_root: bool
    available_with_root: bool
    requires_frida: bool
    implementation_status: str
    physical_validation_status: str = "UNVERIFIED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


ROOT_FOCUSED_TESTS: tuple[RootFocusedTestDefinition, ...] = (
    RootFocusedTestDefinition(
        "ASL-MVP-001",
        "Debuggable or test-only build",
        True,
        True,
        False,
        "IMPLEMENTED",
    ),
    RootFocusedTestDefinition(
        "ASL-MANIFEST-ALLOW-BACKUP",
        "Application backup policy",
        True,
        True,
        False,
        "IMPLEMENTED_UNVERIFIED",
    ),
    RootFocusedTestDefinition(
        "ASL-MVP-002",
        "Cleartext configuration and attributed runtime canary",
        True,
        True,
        False,
        "IMPLEMENTED",
    ),
    RootFocusedTestDefinition(
        "ASL-MVP-003",
        "Sensitive logging or URL token metadata",
        True,
        True,
        False,
        "IMPLEMENTED",
    ),
    RootFocusedTestDefinition(
        "ASL-MVP-004",
        "Exported Activity protection and controlled impact",
        True,
        True,
        False,
        "IMPLEMENTED",
    ),
    RootFocusedTestDefinition(
        "ASL-MANIFEST-EXPORTED-RECEIVER",
        "Exported Receiver protection metadata",
        True,
        True,
        False,
        "IMPLEMENTED_UNVERIFIED",
    ),
    RootFocusedTestDefinition(
        "ASL-MANIFEST-EXPORTED-PROVIDER",
        "Exported Provider protection metadata",
        True,
        True,
        False,
        "IMPLEMENTED_UNVERIFIED",
    ),
    RootFocusedTestDefinition(
        "ASL-ROOT-STORAGE",
        "Sensitive private-storage observations",
        False,
        True,
        False,
        "IMPLEMENTED_UNVERIFIED",
    ),
    RootFocusedTestDefinition(
        "ASL-ROOT-CRYPTO",
        "Runtime cryptographic boundary observations",
        False,
        True,
        True,
        "IMPLEMENTED_UNVERIFIED",
    ),
    RootFocusedTestDefinition(
        "ASL-MVP-005",
        "TLS and certificate trust behavior",
        True,
        True,
        False,
        "IMPLEMENTED",
    ),
    RootFocusedTestDefinition(
        "ASL-ROOT-DETECTION",
        "Root-detection execution and app response",
        False,
        True,
        True,
        "IMPLEMENTED_UNVERIFIED",
    ),
)


def merge_root_coverage(observed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(item.get("test_id")): item for item in observed}
    output: list[dict[str, Any]] = []
    catalog_ids: set[str] = set()
    for definition in ROOT_FOCUSED_TESTS:
        catalog_ids.add(definition.test_id)
        actual = by_id.get(definition.test_id)
        row = definition.to_dict()
        row["finding_status"] = (
            str(actual.get("finding_status", "skipped")) if actual else "skipped"
        )
        if actual:
            row["physical_validation_status"] = str(
                actual.get("physical_validation_status", "UNVERIFIED")
            )
        output.append(row)
    output.extend(
        item for item in observed if str(item.get("test_id")) not in catalog_ids
    )
    return output
