"""Conservative TLS interception and certificate-trust behavior state model."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from .findings import FindingStatus

_TLS_CLASS_KEYS = (
    "class_name",
    "implementation_class",
    "implementation_class_name",
    "trust_manager_class",
    "verifier_class",
    "hostname_verifier_class",
)
_PLATFORM_TLS_CLASS_PREFIXES = (
    "javax.net.ssl.",
    "com.android.org.conscrypt.",
    "org.conscrypt.",
    "sun.security.ssl.",
)
_PLATFORM_HOSTNAME_VERIFIERS = frozenset(
    {
        "com.android.okhttp.internal.tls.okhostnameverifier",
        "com.squareup.okhttp.internal.tls.okhostnameverifier",
        "okhttp3.internal.tls.okhostnameverifier",
    }
)
_UNKNOWN_TLS_CLASSES = frozenset({"", "unknown", "<unknown>", "object"})


def _metadata_marks_custom(
    metadata: Mapping[str, Any],
    marker: str,
) -> bool:
    """Honor custom markers only when available class provenance supports them."""
    if metadata.get(marker) is not True:
        return False
    class_name = next(
        (
            str(metadata[key]).strip().casefold()
            for key in _TLS_CLASS_KEYS
            if isinstance(metadata.get(key), str)
        ),
        None,
    )
    # Existing observers may expose only a class hash. Preserve those explicit
    # markers while treating an explicit unknown/platform class conservatively.
    if class_name is None:
        return True
    if class_name in _UNKNOWN_TLS_CLASSES:
        return False
    if class_name.startswith(_PLATFORM_TLS_CLASS_PREFIXES):
        return False
    return class_name not in _PLATFORM_HOSTNAME_VERIFIERS


class TlsBehaviorState(StrEnum):
    MITM_ACCEPTED = "MITM_ACCEPTED"
    MITM_REJECTED = "MITM_REJECTED"
    PINNING_OBSERVED = "PINNING_OBSERVED"
    TRUST_MANAGER_OBSERVED = "TRUST_MANAGER_OBSERVED"
    CUSTOM_TRUST_CONFIGURED = "CUSTOM_TRUST_CONFIGURED"
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
    custom_trust_manager_observed: bool = False
    custom_hostname_verifier_observed: bool = False
    webview_ssl_proceed_observed: bool = False
    network_error_observed: bool = False
    trust_manager_accept_observed: bool = False
    trust_manager_reject_observed: bool = False
    hostname_verifier_accept_observed: bool = False
    hostname_verifier_reject_observed: bool = False
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
        elif (
            evidence.canary_request_count > 0
            and evidence.explicit_certificate_rejection
        ):
            state = TlsBehaviorState.MITM_REJECTED
            status = FindingStatus.PASS
            confidence = "high"
            rationale = "An explicit certificate rejection followed a target canary attempt."
        elif evidence.canary_request_count > 0 and evidence.pinning_observed:
            state = TlsBehaviorState.PINNING_OBSERVED
            status = FindingStatus.INCONCLUSIVE
            confidence = "medium"
            rationale = (
                "A certificate-pinning method ran for the target attempt, but no "
                "explicit accept or reject outcome was attributed."
            )
        elif (
            evidence.custom_trust_manager_observed
            or evidence.custom_hostname_verifier_observed
        ):
            state = TlsBehaviorState.CUSTOM_TRUST_CONFIGURED
            accepted = (
                evidence.trust_manager_accept_observed
                or evidence.hostname_verifier_accept_observed
            )
            rejected = (
                evidence.trust_manager_reject_observed
                or evidence.hostname_verifier_reject_observed
            )
            status = (
                FindingStatus.POTENTIAL
                if accepted or not rejected
                else FindingStatus.INCONCLUSIVE
            )
            confidence = "medium"
            rationale = (
                "A custom trust component accepted a runtime verification call, but no "
                "controlled invalid certificate or hostname was attributed."
                if accepted
                else (
                    "The observed custom trust component rejected its runtime verification "
                    "call; permissive certificate or hostname behavior was not shown."
                    if rejected
                    else "A custom trust component was installed at runtime, but permissive "
                    "certificate or hostname behavior was not deterministically proven."
                )
            )
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
            validation_type=(
                "instrumented_validation"
                if evidence.pinning_observed or evidence.trust_manager_observed
                else "adb_assisted_validation"
            ),
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
            item.get("method") in {
                "tls.check_server_trusted",
                "tls.trust_manager_observed",
            }
            or item.get("event") == "trust_manager_observed"
            for item in frida
        )
        metadata = [
            argument
            for item in frida
            for argument in item.get("arguments_redacted", [])
            if isinstance(argument, Mapping)
        ]
        custom_trust_manager = any(
            _metadata_marks_custom(item, "custom_trust_manager") for item in metadata
        )
        custom_hostname_verifier = any(
            _metadata_marks_custom(item, "custom_hostname_verifier") for item in metadata
        )
        webview_ssl_proceed = any(
            item.get("category") == "webview"
            and item.get("method") == "webview.ssl_error_proceed"
            for item in frida
        )
        trust_manager_accept = any(
            item.get("category") == "tls"
            and item.get("method") == "tls.check_server_trusted"
            and any(
                isinstance(argument, Mapping)
                and argument.get("decision") == "returned"
                and _metadata_marks_custom(argument, "custom_trust_manager")
                for argument in item.get("arguments_redacted", [])
            )
            for item in frida
        )
        trust_manager_reject = any(
            item.get("category") == "tls"
            and item.get("method") == "tls.check_server_trusted"
            and any(
                isinstance(argument, Mapping)
                and argument.get("decision") == "threw"
                and _metadata_marks_custom(argument, "custom_trust_manager")
                for argument in item.get("arguments_redacted", [])
            )
            for item in frida
        )
        hostname_verifier_accept = any(
            item.get("category") == "tls"
            and item.get("method") == "tls.hostname_verify"
            and any(
                isinstance(argument, Mapping)
                and argument.get("decision") == "accepted"
                and _metadata_marks_custom(argument, "custom_hostname_verifier")
                for argument in item.get("arguments_redacted", [])
            )
            for item in frida
        )
        hostname_verifier_reject = any(
            item.get("category") == "tls"
            and item.get("method") == "tls.hostname_verify"
            and any(
                isinstance(argument, Mapping)
                and argument.get("decision") == "rejected"
                and _metadata_marks_custom(argument, "custom_hostname_verifier")
                for argument in item.get("arguments_redacted", [])
            )
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
                custom_trust_manager_observed=custom_trust_manager,
                custom_hostname_verifier_observed=custom_hostname_verifier,
                webview_ssl_proceed_observed=webview_ssl_proceed,
                network_error_observed=network_error,
                trust_manager_accept_observed=trust_manager_accept,
                trust_manager_reject_observed=trust_manager_reject,
                hostname_verifier_accept_observed=hostname_verifier_accept,
                hostname_verifier_reject_observed=hostname_verifier_reject,
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
