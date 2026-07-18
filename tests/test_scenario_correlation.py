from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from android_assessor.scenario_correlation import correlate_scenario_events

SESSION = "20260719-100000-abcdef"
SCENARIO = "login-flow"
PACKAGE = "com.example.benchmark"
PID = 4242
CANARY_FP = "a" * 64
FIXTURE_FP = "b" * 64


def _summary() -> dict[str, Any]:
    return {
        "session_id": SESSION,
        "scenario_id": SCENARIO,
        "package": PACKAGE,
        "process": PACKAGE,
        "pid": PID,
        "canary_fingerprint": CANARY_FP,
        "owned_value_fingerprints": [FIXTURE_FP],
        "scoped_backend_ids": ["fixture-backend"],
        "evidence_ids": {
            "frida": "evidence-frida",
            "traffic": "evidence-traffic",
            "logcat": "evidence-logcat",
            "storage": "evidence-storage",
        },
        "steps": [
            {
                "step_id": "submit",
                "status": "completed",
                "started_at": "2026-07-19T10:00:00Z",
                "ended_at": "2026-07-19T10:00:05Z",
                "activated_writes": ["auth-state"],
            },
            {
                "step_id": "collect",
                "completed": True,
                "started_at": "2026-07-19T10:00:06Z",
                "completed_at": "2026-07-19T10:00:10Z",
            },
            {
                "step_id": "not-run",
                "outcome": "timeout_unknown",
                "completed": False,
                "started_at": "2026-07-19T10:00:11Z",
                "ended_at": "2026-07-19T10:00:12Z",
            },
        ],
    }


def _base_event(timestamp: str = "2026-07-19T10:00:02Z") -> dict[str, Any]:
    return {
        "session_id": SESSION,
        "scenario_id": SCENARIO,
        "package": PACKAGE,
        "process": PACKAGE,
        "pid": PID,
        "timestamp": timestamp,
    }


def _traffic() -> dict[str, Any]:
    return {
        **_base_event(),
        "event": "request",
        "owned_value_fingerprint": FIXTURE_FP,
        "exact_owned_value_match": True,
        "attribution": "scenario_owned_value",
        "backend_scope": "scoped_local",
        "backend_id": "fixture-backend",
    }


def _storage() -> dict[str, Any]:
    return {
        **_base_event("2026-07-19T10:00:08Z"),
        "step_id": "collect",
        "owned_value_fingerprint": FIXTURE_FP,
        "exact_owned_value_match": True,
        "package_owned": True,
        "plaintext": True,
        "baseline_delta": True,
        "activated_write_step_id": "submit",
        "write_activation": "auth-state",
        "storage_area": "shared_preferences",
    }


def test_correlates_four_observers_with_required_identity_fields() -> None:
    frida = {
        **_base_event(),
        "category": "crypto",
        "method": "Cipher.doFinal",
        "operation_completed": True,
        "algorithm": "DES",
    }
    traffic = _traffic()
    logcat = {
        **_base_event(),
        "canary_match": True,
        "exact_owned_value_match": True,
        "category": "sensitive_log",
    }
    storage = _storage()

    result = correlate_scenario_events(
        _summary(),
        frida_events=[frida],
        traffic_events=[traffic],
        logcat_events=[logcat],
        storage_events=[storage],
    )

    assert result.rejected == ()
    assert len(result.events) == 4
    required = {
        "session_id",
        "scenario_id",
        "step_id",
        "package",
        "process",
        "pid",
        "timestamp",
        "observer",
        "canary_fingerprint",
        "evidence_id",
        "eligible_for_confirmation",
        "rejection_reason",
    }
    assert all(required <= event.keys() for event in result.events)
    assert all(event["eligible_for_confirmation"] for event in result.events)
    assert {event["step_id"] for event in result.events} == {"submit", "collect"}
    assert {event["evidence_id"] for event in result.events} == {
        "evidence-frida",
        "evidence-traffic",
        "evidence-logcat",
        "evidence-storage",
    }


def test_completed_aliases_are_supported_but_false_completion_wins() -> None:
    summary = _summary()
    summary["steps"].append(
        {
            "step_id": "outcome-alias",
            "outcome": "completed",
            "started_at": "2026-07-19T10:00:20Z",
            "finished_at": "2026-07-19T10:00:21Z",
        }
    )
    accepted = {
        **_base_event("2026-07-19T10:00:20.500000Z"),
        "step_id": "outcome-alias",
        "evidence_id": "event-evidence",
    }
    incomplete = {
        **_base_event("2026-07-19T10:00:11.500000Z"),
        "step_id": "not-run",
        "evidence_id": "event-evidence",
    }

    result = correlate_scenario_events(summary, frida_events=[accepted, incomplete])

    assert [event["step_id"] for event in result.events] == ["outcome-alias"]
    assert result.rejected[0]["rejection_reason"] == "step_not_completed"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("session_id", "20260719-100000-fedcba", "wrong_session"),
        ("scenario_id", "other-flow", "wrong_scenario"),
        ("package", "com.example.other", "wrong_package"),
        ("pid", PID + 1, "wrong_pid"),
        ("process", f"{PACKAGE}:other", "wrong_process"),
        ("timestamp", "2026-07-19T10:01:00Z", "outside_completed_step_window"),
    ),
)
def test_wrong_identity_pid_or_window_is_rejected(
    field: str, value: Any, reason: str
) -> None:
    event = {**_base_event(), "evidence_id": "event-evidence", field: value}

    result = correlate_scenario_events(_summary(), frida_events=[event])

    assert result.events == ()
    assert result.rejected[0]["rejection_reason"] == reason


@pytest.mark.parametrize(
    ("change", "reason"),
    (
        ({"exact_owned_value_match": False}, "traffic_missing_exact_owned_value"),
        ({"attribution": "target"}, "traffic_without_owned_attribution"),
        ({"backend_scope": "internet"}, "traffic_backend_not_scoped_local"),
        ({"backend_id": "undeclared"}, "traffic_backend_not_declared"),
        ({"event": "response"}, "traffic_not_request"),
    ),
)
def test_traffic_requires_exact_owned_value_and_scoped_backend(
    change: dict[str, Any], reason: str
) -> None:
    event = {**_traffic(), **change}

    result = correlate_scenario_events(_summary(), traffic_events=[event])

    assert result.events == ()
    assert result.rejected[0]["eligible_for_confirmation"] is False
    assert result.rejected[0]["rejection_reason"] == reason


def test_traffic_with_unowned_fingerprint_is_rejected() -> None:
    event = {**_traffic(), "owned_value_fingerprint": "c" * 64}

    result = correlate_scenario_events(_summary(), traffic_events=[event])

    assert result.events == ()
    assert result.rejected[0]["rejection_reason"] == "unowned_value_fingerprint"


def test_addon_owned_fingerprint_list_and_scope_flag_are_accepted() -> None:
    event = _traffic()
    event.pop("owned_value_fingerprint")
    event.pop("exact_owned_value_match")
    event.pop("backend_scope")
    event["owned_value_fingerprints"] = [FIXTURE_FP]
    event["scope_allowed"] = True

    result = correlate_scenario_events(_summary(), traffic_events=[event])

    assert result.rejected == ()
    assert result.events[0]["canary_fingerprint"] == FIXTURE_FP
    assert result.events[0]["eligible_for_confirmation"] is True


@pytest.mark.parametrize(
    ("change", "reason"),
    (
        ({"baseline_delta": False}, "storage_without_baseline_delta"),
        ({"package_owned": False}, "storage_not_package_owned"),
        ({"plaintext": False}, "storage_not_plaintext"),
        ({"write_activation": "other-write"}, "storage_write_not_activated"),
        ({"activated_write_step_id": "not-run"}, "storage_write_step_not_completed"),
    ),
)
def test_storage_requires_activated_write_and_baseline_delta(
    change: dict[str, Any], reason: str
) -> None:
    event = {**_storage(), **change}

    result = correlate_scenario_events(_summary(), storage_events=[event])

    assert result.events == ()
    assert result.rejected[0]["rejection_reason"] == reason


def test_storage_observation_before_write_completion_is_rejected() -> None:
    summary = _summary()
    summary["steps"][0]["ended_at"] = "2026-07-19T10:00:09Z"

    result = correlate_scenario_events(summary, storage_events=[_storage()])

    assert result.events == ()
    assert result.rejected[0]["rejection_reason"] == "storage_observed_before_write_completed"


def test_ambiguous_window_without_explicit_step_is_rejected() -> None:
    summary = _summary()
    summary["steps"][1]["started_at"] = "2026-07-19T10:00:01Z"
    event = {**_base_event(), "evidence_id": "event-evidence"}

    result = correlate_scenario_events(summary, frida_events=[event])

    assert result.events == ()
    assert result.rejected[0]["rejection_reason"] == "ambiguous_step_window"


def test_missing_evidence_reference_is_rejected() -> None:
    summary = _summary()
    summary["evidence_ids"] = {}

    result = correlate_scenario_events(summary, frida_events=[_base_event()])

    assert result.events == ()
    assert result.rejected[0]["rejection_reason"] == "evidence_id is invalid"


def test_non_owned_log_event_is_correlated_but_not_confirmation_eligible() -> None:
    event = {
        **_base_event(),
        "evidence_id": "event-evidence",
        "category": "ordinary_log",
        "password": "must-never-survive",
    }

    result = correlate_scenario_events(_summary(), logcat_events=[event])

    assert result.rejected == ()
    assert result.events[0]["eligible_for_confirmation"] is False
    assert (
        result.events[0]["rejection_reason"]
        == "logcat_missing_exact_owned_value"
    )
    assert result.events[0]["canary_fingerprint"] is None
    assert "must-never-survive" not in str(result.to_dict())
    assert "password" not in result.events[0]["attributes"]


def test_frida_step_outcome_does_not_replace_completed_operation_evidence() -> None:
    event = {
        **_base_event(),
        "evidence_id": "event-evidence",
        "outcome": "completed",
        "method": "Cipher.getInstance",
    }

    result = correlate_scenario_events(_summary(), frida_events=[event])

    assert result.rejected == ()
    assert result.events[0]["eligible_for_confirmation"] is False
    assert result.events[0]["rejection_reason"] == "frida_event_not_confirmation_eligible"


def test_incomplete_frida_crypto_event_reports_operation_reason() -> None:
    event = {
        **_base_event(),
        "evidence_id": "event-evidence",
        "category": "crypto",
        "method": "cipher.do_final",
        "arguments_redacted": [{"operation_id": "crypto-1", "executed": False}],
    }

    result = correlate_scenario_events(_summary(), frida_events=[event])

    assert result.rejected == ()
    assert result.events[0]["eligible_for_confirmation"] is False
    assert result.events[0]["rejection_reason"] == "crypto_operation_not_completed"


def test_frida_redacted_executed_metadata_is_confirmation_eligible() -> None:
    event = {
        **_base_event(),
        "evidence_id": "event-evidence",
        "category": "crypto",
        "method": "cipher.do_final",
        "arguments_redacted": [
            {"operation_id": "crypto-1", "executed": True, "transformation": "AES/CBC"}
        ],
    }

    result = correlate_scenario_events(_summary(), frida_events=[event])

    assert result.rejected == ()
    assert result.events[0]["eligible_for_confirmation"] is True
    assert result.events[0]["attributes"]["operation_completed"] is True


def test_incomplete_scenario_cannot_produce_eligible_events() -> None:
    summary = _summary()
    summary["outcome"] = "partial"

    with pytest.raises(ValueError, match="scenario outcome"):
        correlate_scenario_events(summary, traffic_events=[_traffic()])


def test_runner_result_aliases_and_prefixed_fingerprint_are_supported() -> None:
    summary = _summary()
    summary.pop("pid")
    summary.pop("process")
    summary["verified_pids"] = [PID]
    prefixed = "hmac-sha256:" + ("c" * 64)
    summary["canary_fingerprint"] = None
    summary["owned_value_fingerprints"] = [prefixed]
    event = {
        **_base_event(),
        "owned_value_fingerprints": [prefixed],
        "exact_owned_value_match": True,
        "evidence_id": "event-evidence",
    }

    result = correlate_scenario_events(summary, logcat_events=[event])

    assert result.rejected == ()
    assert result.events[0]["process"] == PACKAGE
    assert result.events[0]["canary_fingerprint"] == prefixed


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("pid", 0, "positive integer"),
        ("canary_fingerprint", "short", "fingerprint"),
        ("steps", "not-a-list", "sequence"),
    ),
)
def test_invalid_summary_fails_closed(field: str, value: Any, message: str) -> None:
    summary = deepcopy(_summary())
    summary[field] = value

    with pytest.raises(ValueError, match=message):
        correlate_scenario_events(summary)
