"""Fail-closed correlation of scenario windows with already-redacted observations.

The correlator deliberately has no dependency on the scenario runner.  Its input is
plain mappings so persisted scenario summaries can be evaluated without re-running
device actions.  It never copies arbitrary source-event fields into its output.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .errors import SessionError
from .validation import validate_package_name

_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_FINGERPRINT = re.compile(r"^(?:(?:hmac-)?sha256:)?[a-f0-9]{64}$")
_OBSERVERS = ("frida", "traffic", "logcat", "storage")
_CONFIRMING_TRAFFIC_ATTRIBUTION = {"scenario_owned_value", "validation_canary"}


@dataclass(frozen=True, slots=True)
class ScenarioCorrelationResult:
    """Accepted normalized events and non-sensitive rejection diagnostics."""

    events: tuple[dict[str, Any], ...]
    rejected: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [dict(item) for item in self.events],
            "rejected": [dict(item) for item in self.rejected],
            "accepted_count": len(self.events),
            "rejected_count": len(self.rejected),
        }


@dataclass(frozen=True, slots=True)
class _StepWindow:
    step_id: str
    started_at: datetime
    ended_at: datetime
    pid: int | None
    process: str | None
    activated_writes: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ScenarioContext:
    session_id: str
    scenario_id: str
    package: str
    verified_pids: frozenset[int]
    process: str | None
    canary_fingerprint: str | None
    owned_fingerprints: frozenset[str]
    scoped_backend_ids: frozenset[str]
    evidence_ids: Mapping[str, str]
    steps: tuple[_StepWindow, ...]


class _RejectedEvent(ValueError):
    pass


def correlate_scenario_events(
    summary: Mapping[str, Any],
    *,
    frida_events: Sequence[Mapping[str, Any]] = (),
    traffic_events: Sequence[Mapping[str, Any]] = (),
    logcat_events: Sequence[Mapping[str, Any]] = (),
    storage_events: Sequence[Mapping[str, Any]] = (),
) -> ScenarioCorrelationResult:
    """Correlate observations to completed scenario steps.

    The accepted summary schema is intentionally small: scenario identity, a target
    PID/process, owned fingerprints, scoped backend IDs, optional observer evidence
    IDs, and ``steps`` with bounded timestamps.  A step is completed when its
    ``status`` or ``outcome`` is ``completed``, or when ``completed`` is true.  An
    explicit false ``completed`` value always wins.

    Traffic is accepted only for an exact owned-value match against a declared local
    backend.  Storage additionally requires a completed scenario-declared write and
    an observed post-write baseline delta in package-owned plaintext storage.
    """

    context = _parse_summary(summary)
    output: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    sources = (
        ("frida", frida_events),
        ("traffic", traffic_events),
        ("logcat", logcat_events),
        ("storage", storage_events),
    )
    for observer, events in sources:
        for index, event in enumerate(events):
            try:
                normalized = _correlate_event(context, observer, event)
            except (TypeError, ValueError) as exc:
                rejected.append(
                    {
                        "observer": observer,
                        "event_index": index,
                        "eligible_for_confirmation": False,
                        "rejection_reason": str(exc) or "invalid_event",
                    }
                )
            else:
                output.append(normalized)
    output.sort(key=lambda item: (str(item["timestamp"]), str(item["observer"])))
    return ScenarioCorrelationResult(tuple(output), tuple(rejected))


def _parse_summary(summary: Mapping[str, Any]) -> _ScenarioContext:
    if not isinstance(summary, Mapping):
        raise ValueError("scenario summary must be a mapping")
    outcome = summary.get("outcome")
    if outcome is not None and outcome != "completed":
        raise ValueError("scenario outcome is not completed")
    session_id = _safe_id(summary.get("session_id"), "session_id")
    scenario_id = _safe_id(summary.get("scenario_id"), "scenario_id")
    try:
        package = validate_package_name(str(summary.get("package", "")))
    except SessionError as exc:
        raise ValueError("scenario package is invalid") from exc
    explicit_pid = summary.get("pid")
    verified_pids = _pid_set(summary.get("verified_pids", ()), "verified_pids")
    if explicit_pid is not None:
        verified_pids.add(_positive_pid(explicit_pid, "scenario pid"))
    if not verified_pids:
        raise ValueError("scenario summary must contain a verified PID")
    default_pid = (
        _positive_pid(explicit_pid, "scenario pid")
        if explicit_pid is not None
        else next(iter(verified_pids))
        if len(verified_pids) == 1
        else None
    )
    process_value = summary.get("process")
    process = (
        _validated_process(process_value, package, "scenario process")
        if process_value is not None
        else None
    )
    canary_fingerprint = _optional_fingerprint(
        summary.get("canary_fingerprint"), "canary_fingerprint"
    )
    owned = _fingerprint_set(
        summary.get("owned_value_fingerprints", ()), "owned_value_fingerprints"
    )
    if canary_fingerprint is not None:
        owned.add(canary_fingerprint)
    backend_ids = _safe_id_set(summary.get("scoped_backend_ids", ()), "scoped_backend_ids")
    evidence_ids = _evidence_ids(summary.get("evidence_ids", {}))
    raw_steps = summary.get("steps")
    if not isinstance(raw_steps, Sequence) or isinstance(raw_steps, (str, bytes, bytearray)):
        raise ValueError("scenario steps must be a sequence")
    steps: list[_StepWindow] = []
    seen_steps: set[str] = set()
    for raw_step in raw_steps:
        if not isinstance(raw_step, Mapping) or not _step_completed(raw_step):
            continue
        step_id = _safe_id(raw_step.get("step_id", raw_step.get("id")), "step_id")
        if step_id in seen_steps:
            raise ValueError("completed scenario step IDs must be unique")
        seen_steps.add(step_id)
        started_at = _timestamp(raw_step.get("started_at"), "step started_at")
        ended_value = raw_step.get(
            "ended_at", raw_step.get("completed_at", raw_step.get("finished_at"))
        )
        ended_at = _timestamp(ended_value, "step ended_at")
        if ended_at < started_at:
            raise ValueError("completed step window ends before it starts")
        raw_step_pid = raw_step.get("pid", default_pid)
        step_pid = (
            _positive_pid(raw_step_pid, "step pid") if raw_step_pid is not None else None
        )
        if step_pid is not None and step_pid not in verified_pids:
            raise ValueError("step pid is not present in verified_pids")
        raw_step_process = raw_step.get("process", process)
        step_process = (
            _validated_process(raw_step_process, package, "step process")
            if raw_step_process is not None
            else None
        )
        activated_writes = _safe_id_set(
            raw_step.get("activated_writes", ()), "activated_writes"
        )
        steps.append(
            _StepWindow(
                step_id=step_id,
                started_at=started_at,
                ended_at=ended_at,
                pid=step_pid,
                process=step_process,
                activated_writes=frozenset(activated_writes),
            )
        )
    return _ScenarioContext(
        session_id=session_id,
        scenario_id=scenario_id,
        package=package,
        verified_pids=frozenset(verified_pids),
        process=process,
        canary_fingerprint=canary_fingerprint,
        owned_fingerprints=frozenset(owned),
        scoped_backend_ids=frozenset(backend_ids),
        evidence_ids=evidence_ids,
        steps=tuple(steps),
    )


def _correlate_event(
    context: _ScenarioContext,
    observer: str,
    event: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(event, Mapping):
        raise _RejectedEvent("event_not_mapping")
    claimed_observer = event.get("observer")
    if claimed_observer is not None and claimed_observer != observer:
        raise _RejectedEvent("observer_mismatch")
    if event.get("session_id") != context.session_id:
        raise _RejectedEvent("wrong_session")
    if event.get("scenario_id", context.scenario_id) != context.scenario_id:
        raise _RejectedEvent("wrong_scenario")
    if event.get("package") != context.package:
        raise _RejectedEvent("wrong_package")
    event_pid = _positive_pid(event.get("pid"), "event pid")
    timestamp = _timestamp(event.get("timestamp"), "event timestamp")
    step = _resolve_step(context, event, timestamp)
    if event_pid not in context.verified_pids:
        raise _RejectedEvent("wrong_pid")
    if step.pid is not None and event_pid != step.pid:
        raise _RejectedEvent("wrong_pid")
    expected_process = step.process or context.process
    process_value = event.get("process", expected_process or context.package)
    try:
        process = _validated_process(process_value, context.package, "event process")
    except ValueError as exc:
        raise _RejectedEvent("wrong_process") from exc
    if expected_process is not None and process != expected_process:
        raise _RejectedEvent("wrong_process")
    evidence_id = event.get("evidence_id", context.evidence_ids.get(observer))
    evidence_id = _safe_id(evidence_id, "evidence_id")
    fingerprint = _event_fingerprint(context, event)

    if observer == "traffic":
        _validate_traffic(context, event, fingerprint)
    elif observer == "storage":
        _validate_storage(context, event, timestamp, event_pid, fingerprint)
    elif observer == "logcat" and fingerprint is not None:
        if not _has_exact_owned_match(event):
            raise _RejectedEvent("logcat_match_not_exact")

    eligible = _eligible_for_confirmation(observer, event, fingerprint)
    return {
        "session_id": context.session_id,
        "scenario_id": context.scenario_id,
        "step_id": step.step_id,
        "package": context.package,
        "process": process,
        "pid": event_pid,
        "timestamp": _render_timestamp(timestamp),
        "observer": observer,
        "canary_fingerprint": fingerprint,
        "evidence_id": evidence_id,
        "eligible_for_confirmation": eligible,
        "rejection_reason": (
            None
            if eligible
            else _confirmation_ineligibility_reason(observer, event, fingerprint)
        ),
        "attributes": _safe_attributes(event, observer=observer),
    }


def _resolve_step(
    context: _ScenarioContext,
    event: Mapping[str, Any],
    timestamp: datetime,
) -> _StepWindow:
    claimed_step = event.get("step_id")
    if claimed_step is not None:
        candidates = [step for step in context.steps if step.step_id == claimed_step]
        if not candidates:
            raise _RejectedEvent("step_not_completed")
        step = candidates[0]
        if not step.started_at <= timestamp <= step.ended_at:
            raise _RejectedEvent("outside_step_window")
        return step
    candidates = [
        step for step in context.steps if step.started_at <= timestamp <= step.ended_at
    ]
    if not candidates:
        raise _RejectedEvent("outside_completed_step_window")
    if len(candidates) != 1:
        raise _RejectedEvent("ambiguous_step_window")
    return candidates[0]


def _event_fingerprint(
    context: _ScenarioContext, event: Mapping[str, Any]
) -> str | None:
    candidates = {
        value
        for value in (
            event.get("canary_fingerprint"),
            event.get("owned_value_fingerprint"),
        )
        if value is not None
    }
    plural = event.get("owned_value_fingerprints", ())
    if not isinstance(plural, Sequence) or isinstance(plural, (str, bytes, bytearray)):
        raise _RejectedEvent("owned_value_fingerprints_not_sequence")
    candidates.update(plural)
    fingerprints = {
        fingerprint
        for item in candidates
        if (fingerprint := _optional_fingerprint(item, "event fingerprint")) is not None
    }
    if fingerprints:
        if not fingerprints <= context.owned_fingerprints:
            raise _RejectedEvent("unowned_value_fingerprint")
        fingerprint = (
            context.canary_fingerprint
            if context.canary_fingerprint in fingerprints
            else sorted(fingerprints)[0]
        )
    elif event.get("canary_match") is True:
        fingerprint = context.canary_fingerprint
        if fingerprint is None:
            raise _RejectedEvent("canary_match_without_owned_fingerprint")
    else:
        fingerprint = None
    return fingerprint


def _validate_traffic(
    context: _ScenarioContext,
    event: Mapping[str, Any],
    fingerprint: str | None,
) -> None:
    if event.get("event") != "request":
        raise _RejectedEvent("traffic_not_request")
    if fingerprint is None or not _has_exact_owned_match(event):
        raise _RejectedEvent("traffic_missing_exact_owned_value")
    if event.get("attribution") not in _CONFIRMING_TRAFFIC_ATTRIBUTION:
        raise _RejectedEvent("traffic_without_owned_attribution")
    if (
        event.get("backend_scope") != "scoped_local"
        and event.get("scope_allowed") is not True
    ):
        raise _RejectedEvent("traffic_backend_not_scoped_local")
    backend_id = event.get("backend_id")
    if backend_id not in context.scoped_backend_ids:
        raise _RejectedEvent("traffic_backend_not_declared")


def _validate_storage(
    context: _ScenarioContext,
    event: Mapping[str, Any],
    timestamp: datetime,
    event_pid: int,
    fingerprint: str | None,
) -> None:
    if fingerprint is None or not _has_exact_owned_match(event):
        raise _RejectedEvent("storage_missing_exact_owned_value")
    if event.get("package_owned") is not True:
        raise _RejectedEvent("storage_not_package_owned")
    if event.get("plaintext") is not True:
        raise _RejectedEvent("storage_not_plaintext")
    if event.get("baseline_delta") is not True:
        raise _RejectedEvent("storage_without_baseline_delta")
    write_step_id = event.get("activated_write_step_id")
    activation = event.get("write_activation")
    write_steps = [step for step in context.steps if step.step_id == write_step_id]
    if not write_steps:
        raise _RejectedEvent("storage_write_step_not_completed")
    write_step = write_steps[0]
    if not isinstance(activation, str) or activation not in write_step.activated_writes:
        raise _RejectedEvent("storage_write_not_activated")
    if write_step.pid is not None and write_step.pid != event_pid:
        raise _RejectedEvent("storage_write_wrong_pid")
    if timestamp < write_step.ended_at:
        raise _RejectedEvent("storage_observed_before_write_completed")


def _eligible_for_confirmation(
    observer: str,
    event: Mapping[str, Any],
    fingerprint: str | None,
) -> bool:
    if observer in {"traffic", "storage"}:
        return True
    if observer == "logcat":
        return fingerprint is not None and _has_exact_owned_match(event)
    return _operation_completed(event, observer)


def _confirmation_ineligibility_reason(
    observer: str,
    event: Mapping[str, Any],
    fingerprint: str | None,
) -> str:
    """Explain why a correlated event is not evidence for confirmation."""

    if observer == "logcat":
        return "logcat_missing_exact_owned_value"
    if observer == "frida":
        category = event.get("category")
        if category == "crypto":
            return "crypto_operation_not_completed"
        if category == "logging":
            return (
                "logging_event_missing_exact_canary_or_owned_value"
                if fingerprint is None
                else "logging_sink_not_confirmation_eligible"
            )
        if category == "storage":
            return "storage_sink_missing_activated_plaintext_write"
        return "frida_event_not_confirmation_eligible"
    return "observer_not_confirmation_eligible"


def _safe_attributes(
    event: Mapping[str, Any], *, observer: str | None = None
) -> dict[str, Any]:
    """Keep only bounded, non-secret metadata useful to downstream rules."""

    allowed = {
        "algorithm",
        "attribution",
        "backend_id",
        "backend_scope",
        "baseline_delta",
        "canary_match",
        "category",
        "cleartext",
        "event",
        "exact_owned_value_match",
        "hook_id",
        "method",
        "operation_completed",
        "operation_kind",
        "outcome",
        "package_owned",
        "plaintext",
        "scope_allowed",
        "scheme",
        "storage_area",
        "transformation",
        "url_scheme",
        "write_activation",
    }
    attributes: dict[str, Any] = {}
    for key in sorted(allowed):
        value = event.get(key)
        if isinstance(value, bool) or value is None:
            if value is not None:
                attributes[key] = value
        elif isinstance(value, int) and not isinstance(value, bool):
            attributes[key] = value
        elif (
            isinstance(value, str)
            and len(value) <= 256
            and "\r" not in value
            and "\n" not in value
        ):
            attributes[key] = value
    if observer == "frida" and _operation_completed(event, observer):
        attributes["operation_completed"] = True
    return attributes


def _operation_completed(event: Mapping[str, Any], observer: str) -> bool:
    if event.get("operation_completed") is True:
        return True
    if observer != "frida" or event.get("category") != "crypto":
        return False
    arguments = event.get("arguments_redacted")
    if not isinstance(arguments, Sequence) or isinstance(
        arguments, (str, bytes, bytearray)
    ):
        return False
    return any(
        isinstance(argument, Mapping) and argument.get("executed") is True
        for argument in arguments
    )


def _step_completed(step: Mapping[str, Any]) -> bool:
    if step.get("completed") is False:
        return False
    statuses = [step.get("status"), step.get("outcome")]
    explicit = [value for value in statuses if value is not None]
    if explicit and any(value != "completed" for value in explicit):
        return False
    return step.get("completed") is True or "completed" in explicit


def _has_exact_owned_match(event: Mapping[str, Any]) -> bool:
    if event.get("exact_owned_value_match") is True:
        return True
    matches = event.get("owned_value_fingerprints")
    return (
        isinstance(matches, Sequence)
        and not isinstance(matches, (str, bytes, bytearray))
        and bool(matches)
    )


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a timezone-aware string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed


def _render_timestamp(value: datetime) -> str:
    rendered = value.isoformat()
    return rendered[:-6] + "Z" if rendered.endswith("+00:00") else rendered


def _positive_pid(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _pid_set(value: Any, name: str) -> set[int]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a sequence")
    return {_positive_pid(item, name) for item in value}


def _safe_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"{name} is invalid")
    return value


def _validated_process(value: Any, package: str, name: str) -> str:
    process = _safe_id(value, name)
    if process != package and not process.startswith(package + ":"):
        raise ValueError(f"{name} is outside the target package")
    return process


def _safe_id_set(value: Any, name: str) -> set[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a sequence")
    return {_safe_id(item, name) for item in value}


def _optional_fingerprint(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
        raise ValueError(f"{name} is invalid")
    return value


def _fingerprint_set(value: Any, name: str) -> set[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a sequence")
    return {
        fingerprint
        for item in value
        if (fingerprint := _optional_fingerprint(item, name)) is not None
    }


def _evidence_ids(value: Any) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError("evidence_ids must be a mapping")
    output: dict[str, str] = {}
    for observer, evidence_id in value.items():
        if observer not in _OBSERVERS:
            raise ValueError("evidence_ids contains an unsupported observer")
        output[str(observer)] = _safe_id(evidence_id, "evidence_id")
    return output
