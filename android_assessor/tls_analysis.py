"""Conservative TLS interception and certificate-trust behavior state model."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from .findings import FindingStatus


class TlsBehaviorState(StrEnum):
    MITM_ACCEPTED = "MITM_ACCEPTED"
    MITM_REJECTED = "MITM_REJECTED"
    PINNING_OBSERVED = "PINNING_OBSERVED"
    TRUST_MANAGER_OBSERVED = "TRUST_MANAGER_OBSERVED"
    NO_TRAFFIC = "NO_TRAFFIC"
    NETWORK_ERROR = "NETWORK_ERROR"
    UNATTRIBUTED_TRAFFIC = "UNATTRIBUTED_TRAFFIC"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class TlsEvidence:
    target_request_count: int = 0
    canary_request_count: int = 0
    canary_response_count: int = 0
    unattributed_request_count: int = 0
    explicit_certificate_rejection: bool = False
    pinning_observed: bool = False
    trust_manager_observed: bool = False
    network_error_observed: bool = False
    source: str = "unknown"
    environment: str = "unknown"

    def __post_init__(self) -> None:
        for value in (
            self.target_request_count,
            self.canary_request_count,
            self.canary_response_count,
            self.unattributed_request_count,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("TLS evidence counters must be non-negative integers.")
        if self.canary_response_count > self.canary_request_count:
            raise ValueError("TLS canary responses cannot exceed canary requests.")
        if self.canary_request_count > self.target_request_count:
            raise ValueError("TLS canary requests cannot exceed target requests.")
        if (self.source == "fixture") != (self.environment == "simulated"):
            raise ValueError("TLS fixture evidence requires simulated provenance.")


@dataclass(frozen=True, slots=True)
class TlsAnalysisResult:
    state: TlsBehaviorState
    finding_status: FindingStatus
    confidence: str
    validation_type: str
    rationale: str
    evidence: TlsEvidence
    finding_eligible: bool
    physical_validation_status: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload["finding_status"] = self.finding_status.value
        return payload


class TlsBehaviorAnalyzer:
    @staticmethod
    def analyze(evidence: TlsEvidence) -> TlsAnalysisResult:
        if evidence.canary_response_count > 0:
            state = TlsBehaviorState.MITM_ACCEPTED
            status = FindingStatus.CONFIRMED
            confidence = "high"
            rationale = "A uniquely attributed validation canary completed through MITM."
        elif evidence.canary_request_count > 0 and evidence.pinning_observed:
            state = TlsBehaviorState.PINNING_OBSERVED
            status = FindingStatus.PASS
            confidence = "medium"
            rationale = "Pinning behavior was observed for a target canary attempt."
        elif (
            evidence.canary_request_count > 0
            and evidence.explicit_certificate_rejection
        ):
            state = TlsBehaviorState.MITM_REJECTED
            status = FindingStatus.PASS
            confidence = "high"
            rationale = "An explicit certificate rejection followed a target canary attempt."
        elif evidence.target_request_count == 0 and evidence.unattributed_request_count > 0:
            state = TlsBehaviorState.UNATTRIBUTED_TRAFFIC
            status = FindingStatus.INCONCLUSIVE
            confidence = "high"
            rationale = "Only traffic without target attribution was captured."
        elif evidence.target_request_count == 0 and evidence.network_error_observed:
            state = TlsBehaviorState.NETWORK_ERROR
            status = FindingStatus.INCONCLUSIVE
            confidence = "low"
            rationale = "A network error occurred without a target-attributed TLS outcome."
        elif evidence.target_request_count == 0:
            state = TlsBehaviorState.NO_TRAFFIC
            status = FindingStatus.INCONCLUSIVE
            confidence = "high"
            rationale = "The target produced no attributed traffic."
        elif evidence.network_error_observed:
            state = TlsBehaviorState.NETWORK_ERROR
            status = FindingStatus.INCONCLUSIVE
            confidence = "low"
            rationale = "A generic network error cannot establish pinning or trust behavior."
        elif evidence.trust_manager_observed:
            state = TlsBehaviorState.TRUST_MANAGER_OBSERVED
            status = FindingStatus.INCONCLUSIVE
            confidence = "medium"
            rationale = "TrustManager execution alone does not establish MITM acceptance."
        else:
            state = TlsBehaviorState.INCONCLUSIVE
            status = FindingStatus.INCONCLUSIVE
            confidence = "low"
            rationale = "Target traffic lacked a uniquely attributed certificate outcome."
        simulated = evidence.source == "fixture" and evidence.environment == "simulated"
        return TlsAnalysisResult(
            state=state,
            finding_status=status,
            confidence=confidence,
            validation_type="instrumented_validation",
            rationale=rationale,
            evidence=evidence,
            finding_eligible=not simulated,
            physical_validation_status="UNVERIFIED",
        )

    @staticmethod
    def from_events(
        traffic_events: Iterable[Mapping[str, Any]],
        frida_events: Iterable[Mapping[str, Any]],
        *,
        source: str = "session",
        environment: str = "unknown",
    ) -> TlsAnalysisResult:
        traffic = tuple(traffic_events)
        frida = tuple(frida_events)
        target_requests = {
            str(item.get("flow_id"))
            for item in traffic
            if item.get("event") == "request"
            and item.get("scheme") == "https"
            and item.get("attribution") in {"target", "validation_canary"}
        }
        canary_requests = {
            str(item.get("flow_id"))
            for item in traffic
            if item.get("event") == "request"
            and item.get("scheme") == "https"
            and item.get("attribution") == "validation_canary"
        }
        canary_responses = {
            str(item.get("flow_id"))
            for item in traffic
            if item.get("event") == "response"
            and str(item.get("flow_id")) in canary_requests
            and item.get("attribution") == "validation_canary"
        }
        unattributed = sum(
            item.get("event") == "request"
            and item.get("scheme") == "https"
            and item.get("attribution", "unattributed") == "unattributed"
            for item in traffic
        )
        certificate_rejection = any(
            item.get("event") == "tls_error"
            and item.get("attribution") == "validation_canary"
            and item.get("error_kind") == "certificate_rejected"
            for item in traffic
        )
        network_error = any(
            item.get("event") in {"network_error", "tls_error"}
            and item.get("error_kind") in {"network", "unknown"}
            and item.get("attribution") in {"target", "validation_canary"}
            for item in traffic
        )
        pinning = any(
            item.get("category") == "tls"
            and (
                item.get("method") == "pinning.observed"
                or "pinning" in str(item.get("hook_id", "")).casefold()
            )
            for item in frida
        )
        trust_manager = any(
            item.get("category") == "tls"
            or item.get("event") in {"ssl_context_init", "trust_manager_observed"}
            for item in frida
        )
        return TlsBehaviorAnalyzer.analyze(
            TlsEvidence(
                target_request_count=len(target_requests),
                canary_request_count=len(canary_requests),
                canary_response_count=len(canary_responses),
                unattributed_request_count=unattributed,
                explicit_certificate_rejection=certificate_rejection,
                pinning_observed=pinning,
                trust_manager_observed=trust_manager,
                network_error_observed=network_error,
                source=source,
                environment=environment,
            )
        )


def load_tls_fixture(payload: Mapping[str, Any], scenario: str) -> TlsEvidence:
    if payload.get("source") != "fixture" or payload.get("environment") != "simulated":
        raise ValueError("TLS fixture requires fixture/simulated provenance.")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, Mapping) or not isinstance(scenarios.get(scenario), Mapping):
        raise ValueError(f"Unknown TLS fixture scenario: {scenario}")
    return TlsEvidence(
        **dict(scenarios[scenario]),
        source="fixture",
        environment="simulated",
    )
