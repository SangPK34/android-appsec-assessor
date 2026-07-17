"""Normalized static/runtime root-detection control analysis."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from .findings import FindingStatus


class RootIndicatorType(StrEnum):
    SU_FILE = "su_file"
    ROOT_MANAGER_PACKAGE = "root_manager_package"
    BUILD_TAGS = "build_tags"
    SYSTEM_PROPERTY = "system_property"
    MOUNT_STATE = "mount_state"
    EXECUTABLE_LOOKUP = "executable_lookup"
    NATIVE_CHECK = "native_check"
    OTHER = "other"


class RootAppResponse(StrEnum):
    APP_BLOCKED = "app_blocked"
    WARNING_ONLY = "warning_only"
    NO_OBSERVABLE_EFFECT = "no_observable_effect"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RootDetectionEvent:
    check_id: str
    indicator_type: RootIndicatorType
    present: bool
    executed: bool
    detected: bool | None
    response: RootAppResponse
    bypass_instrumented: bool
    source: str
    environment: str

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        source: str,
        environment: str,
    ) -> RootDetectionEvent:
        check_id = str(value.get("check_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", check_id):
            raise ValueError("Root detection check ID is invalid.")
        try:
            indicator = RootIndicatorType(str(value.get("indicator_type", "other")))
            response = RootAppResponse(str(value.get("response", "unknown")))
        except ValueError as exc:
            raise ValueError("Root detection indicator or response is invalid.") from exc
        present = value.get("present")
        executed = value.get("executed")
        detected = value.get("detected")
        bypassed = value.get("bypass_instrumented", False)
        if not isinstance(present, bool) or not isinstance(executed, bool):
            raise ValueError("Root check present/executed fields must be boolean.")
        if detected is not None and not isinstance(detected, bool):
            raise ValueError("Root check detected field must be boolean or null.")
        if not isinstance(bypassed, bool):
            raise ValueError("Root bypass field must be boolean.")
        if bypassed and not executed:
            raise ValueError("An unexecuted root check cannot be instrumented as bypassed.")
        if (source == "fixture") != (environment == "simulated"):
            raise ValueError("Root-detection fixture requires simulated provenance.")
        return cls(
            check_id=check_id,
            indicator_type=indicator,
            present=present,
            executed=executed,
            detected=detected,
            response=response,
            bypass_instrumented=bypassed,
            source=source,
            environment=environment,
        )


@dataclass(frozen=True, slots=True)
class RootDetectionSummary:
    root_check_present: bool
    root_check_executed: bool
    root_detected: bool
    app_blocked: bool
    warning_only: bool
    no_observable_effect: bool


@dataclass(frozen=True, slots=True)
class RootDetectionResult:
    assessment: str
    finding_status: FindingStatus
    confidence: str
    validation_type: str
    summary: RootDetectionSummary
    indicator_types: tuple[str, ...]
    check_ids: tuple[str, ...]
    rationale: str
    finding_eligible: bool
    physical_validation_status: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["finding_status"] = self.finding_status.value
        return payload


class RootDetectionAnalyzer:
    @staticmethod
    def analyze(
        events: Iterable[RootDetectionEvent],
        *,
        expected_root_present: bool,
    ) -> RootDetectionResult:
        values = tuple(events)
        if len({(item.source, item.environment) for item in values}) > 1:
            raise ValueError("Root-detection analysis cannot mix evidence environments.")
        present = any(item.present for item in values)
        executed = any(item.executed for item in values)
        detected = any(item.detected is True for item in values)
        blocked = any(item.response is RootAppResponse.APP_BLOCKED for item in values)
        warning = any(item.response is RootAppResponse.WARNING_ONLY for item in values)
        no_effect = any(
            item.response is RootAppResponse.NO_OBSERVABLE_EFFECT for item in values
        )
        bypassed = any(item.bypass_instrumented for item in values)
        summary = RootDetectionSummary(
            root_check_present=present,
            root_check_executed=executed,
            root_detected=detected,
            app_blocked=blocked,
            warning_only=warning,
            no_observable_effect=no_effect,
        )
        if not present:
            assessment = "root_check_not_observed"
            status = FindingStatus.INCONCLUSIVE
            confidence = "low"
            validation_type = "instrumented_validation"
            rationale = "No static or runtime root-detection evidence was supplied."
        elif bypassed:
            assessment = "security_control_bypassed_in_lab"
            status = FindingStatus.POTENTIAL
            confidence = "medium"
            validation_type = "instrumented_validation"
            rationale = "A lab hook changed control behavior; this is not natural exploitability."
        elif not executed:
            assessment = "root_check_present"
            status = FindingStatus.PASS
            confidence = "medium"
            validation_type = "natural_validation"
            rationale = "A root check is present but runtime execution was not observed."
        elif detected and blocked:
            assessment = "security_control_effective"
            status = FindingStatus.PASS
            confidence = "high"
            validation_type = "instrumented_validation"
            rationale = "The executed check detected root and the app blocked access."
        elif detected and warning:
            assessment = "security_control_warning"
            status = FindingStatus.PASS
            confidence = "high"
            validation_type = "instrumented_validation"
            rationale = "The executed check detected root and displayed a warning."
        elif detected and no_effect:
            assessment = "security_control_no_effect"
            status = FindingStatus.POTENTIAL
            confidence = "high"
            validation_type = "instrumented_validation"
            rationale = "The app detected root but no observable enforcement followed."
        elif expected_root_present and all(
            item.detected is False for item in values if item.executed
        ):
            assessment = "security_control_weak"
            status = FindingStatus.POTENTIAL
            confidence = "medium"
            validation_type = "instrumented_validation"
            rationale = "Executed checks did not detect the simulated rooted condition."
        else:
            assessment = "root_check_inconclusive"
            status = FindingStatus.INCONCLUSIVE
            confidence = "low"
            validation_type = "instrumented_validation"
            rationale = "Check execution was observed without a complete app response."
        simulated = bool(values) and all(
            item.source == "fixture" and item.environment == "simulated"
            for item in values
        )
        return RootDetectionResult(
            assessment=assessment,
            finding_status=status,
            confidence=confidence,
            validation_type=validation_type,
            summary=summary,
            indicator_types=tuple(sorted({item.indicator_type.value for item in values})),
            check_ids=tuple(item.check_id for item in values),
            rationale=rationale,
            finding_eligible=bool(values) and not simulated,
            physical_validation_status="UNVERIFIED",
        )


def root_events_from_frida(
    events: Iterable[Any],
    *,
    source: str,
    environment: str,
) -> tuple[RootDetectionEvent, ...]:
    output: list[RootDetectionEvent] = []
    for index, event in enumerate(events, start=1):
        if getattr(event, "category", None) != "root_detection":
            continue
        arguments = getattr(event, "arguments_redacted", ())
        metadata = arguments[0] if arguments and isinstance(arguments[0], Mapping) else {}
        payload = {
            "check_id": str(metadata.get("check_id") or f"frida-root-{index}"),
            "indicator_type": str(metadata.get("indicator_type", "other")),
            "present": True,
            "executed": True,
            "detected": metadata.get("detected"),
            "response": str(metadata.get("response", "unknown")),
            "bypass_instrumented": bool(metadata.get("bypass_instrumented", False)),
        }
        output.append(
            RootDetectionEvent.from_mapping(
                payload,
                source=source,
                environment=environment,
            )
        )
    return tuple(output)


def load_root_detection_fixture(
    payload: Mapping[str, Any],
    scenario: str,
) -> tuple[RootDetectionEvent, ...]:
    if payload.get("source") != "fixture" or payload.get("environment") != "simulated":
        raise ValueError("Root-detection fixture requires fixture/simulated provenance.")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, Mapping) or not isinstance(scenarios.get(scenario), list):
        raise ValueError(f"Unknown root-detection fixture scenario: {scenario}")
    values = scenarios[scenario]
    if not all(isinstance(item, Mapping) for item in values):
        raise ValueError("Root-detection fixture events must be objects.")
    return tuple(
        RootDetectionEvent.from_mapping(
            item,
            source="fixture",
            environment="simulated",
        )
        for item in values
    )
