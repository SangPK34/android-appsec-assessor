from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from android_assessor.findings import FindingStatus
from android_assessor.frida_events import parse_frida_jsonl
from android_assessor.root_detection import (
    RootAppResponse,
    RootDetectionAnalyzer,
    RootDetectionEvent,
    RootIndicatorType,
    load_root_detection_fixture,
    root_events_from_frida,
)
from tests.fakes import FIXTURE_ROOT, load_fixture


@pytest.mark.parametrize(
    ("scenario", "assessment", "status"),
    (
        ("absent", "root_check_not_observed", FindingStatus.INCONCLUSIVE),
        ("present_not_executed", "root_check_present", FindingStatus.PASS),
        ("blocked", "security_control_effective", FindingStatus.PASS),
        ("warning", "security_control_warning", FindingStatus.PASS),
        ("no_effect", "security_control_no_effect", FindingStatus.POTENTIAL),
        ("not_detected", "security_control_weak", FindingStatus.POTENTIAL),
        ("bypassed", "security_control_bypassed_in_lab", FindingStatus.POTENTIAL),
    ),
)
def test_root_detection_fixture_state_matrix(
    scenario: str,
    assessment: str,
    status: FindingStatus,
) -> None:
    events = load_root_detection_fixture(
        load_fixture("root_detection/states.json"),
        scenario,
    )

    result = RootDetectionAnalyzer.analyze(events, expected_root_present=True)

    assert result.assessment == assessment
    assert result.finding_status is status
    assert result.finding_eligible is False
    assert result.physical_validation_status == "UNVERIFIED"


def test_root_detection_summary_distinguishes_execution_detection_and_response() -> None:
    events = load_root_detection_fixture(
        load_fixture("root_detection/states.json"),
        "blocked",
    )

    summary = RootDetectionAnalyzer.analyze(
        events,
        expected_root_present=True,
    ).summary

    assert summary.root_check_present is True
    assert summary.root_check_executed is True
    assert summary.root_detected is True
    assert summary.app_blocked is True
    assert summary.warning_only is False
    assert summary.no_observable_effect is False


def test_instrumented_bypass_is_never_labeled_natural_validation() -> None:
    events = load_root_detection_fixture(
        load_fixture("root_detection/states.json"),
        "bypassed",
    )

    result = RootDetectionAnalyzer.analyze(events, expected_root_present=True)

    assert result.validation_type == "instrumented_validation"
    assert "not natural exploitability" in result.rationale


def test_root_detection_is_not_a_vulnerability_by_default() -> None:
    events = load_root_detection_fixture(
        load_fixture("root_detection/states.json"),
        "warning",
    )

    result = RootDetectionAnalyzer.analyze(events, expected_root_present=True)

    assert result.finding_status is FindingStatus.PASS
    assert result.assessment == "security_control_warning"


def test_generic_frida_root_event_is_execution_observation_not_detection_claim() -> None:
    parsed = parse_frida_jsonl(
        (FIXTURE_ROOT / "frida" / "events.jsonl").read_text(encoding="utf-8"),
        expected_session_id="fixture-session",
        expected_package="com.example.rootedlab",
        source="fixture",
        environment="simulated",
    )

    events = root_events_from_frida(
        parsed.events,
        source="fixture",
        environment="simulated",
    )
    result = RootDetectionAnalyzer.analyze(events, expected_root_present=True)

    assert len(events) == 1
    assert events[0].indicator_type is RootIndicatorType.OTHER
    assert events[0].executed is True
    assert events[0].detected is None
    assert result.assessment == "root_check_inconclusive"
    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_specialized_frida_root_metadata_is_preserved_without_raw_indicator() -> None:
    payload = json.loads(
        (FIXTURE_ROOT / "frida" / "events.jsonl").read_text(encoding="utf-8").splitlines()[4]
    )
    payload["arguments_redacted"] = [
        {
            "check_id": "root-4242-1",
            "indicator_type": "su_file",
            "indicator_hash": "e" * 64,
            "detected": True,
            "response": "unknown",
            "bypass_instrumented": False,
        }
    ]

    parsed = parse_frida_jsonl(
        json.dumps(payload),
        expected_session_id="fixture-session",
        expected_package="com.example.rootedlab",
        source="fixture",
        environment="simulated",
    )
    events = root_events_from_frida(
        parsed.events,
        source="fixture",
        environment="simulated",
    )

    assert parsed.errors == ()
    assert events[0].indicator_type is RootIndicatorType.SU_FILE
    assert events[0].detected is True
    assert events[0].bypass_instrumented is False
    assert "/system/xbin/su" not in parsed.to_jsonl()


def test_root_observer_avoids_generic_call_attribution_and_duplicate_hooks() -> None:
    hook = Path(__file__).resolve().parent.parent / "hooks" / "basic_observer.js"
    source = hook.read_text(encoding="utf-8")

    assert source.count(
        "['android.webkit.WebView', 'setWebContentsDebuggingEnabled'"
    ) == 1
    assert "if (indicator !== null)" in source
    assert "if (relevant)" in source
    assert "key === 'ro.secure' && value === '0'" in source


@pytest.mark.parametrize(
    "change",
    (
        {"check_id": "bad id"},
        {"indicator_type": "made_up"},
        {"response": "crashed"},
        {"present": "yes"},
        {"detected": "yes"},
        {"executed": False, "bypass_instrumented": True},
    ),
)
def test_root_detection_model_rejects_invalid_events(change: dict[str, object]) -> None:
    payload: dict[str, object] = {
        "check_id": "root-check-1",
        "indicator_type": "su_file",
        "present": True,
        "executed": True,
        "detected": True,
        "response": "app_blocked",
        "bypass_instrumented": False,
    }
    payload.update(change)

    with pytest.raises(ValueError):
        RootDetectionEvent.from_mapping(
            payload,
            source="fixture",
            environment="simulated",
        )


def test_root_detection_analysis_rejects_mixed_environments() -> None:
    fixture = load_root_detection_fixture(
        load_fixture("root_detection/states.json"),
        "blocked",
    )[0]
    physical = replace(fixture, source="frida", environment="physical")

    with pytest.raises(ValueError, match="cannot mix"):
        RootDetectionAnalyzer.analyze(
            (fixture, physical),
            expected_root_present=True,
        )


def test_root_detection_response_enum_is_explicit() -> None:
    assert {item.value for item in RootAppResponse} == {
        "app_blocked",
        "warning_only",
        "no_observable_effect",
        "unknown",
    }
